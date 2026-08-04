//! Standalone production Chatwoot connector host.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_chatwoot::{
    ChatwootConnector, ChatwootConnectorError, ChatwootOperation, ChatwootWebhookDelivery,
    MAX_WEBHOOK_BODY_BYTES, ProfileStateChatwootReplayStore, event_from_channel_message,
};
use aip_connector_host::ConnectorHostEventPublisher;
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, ConnectorHostBootstrapError, PreparedConnectorHost,
    read_json_config, read_secret_utf8, shutdown_signal,
};
use aip_core::MessageBody;
use aip_runtime::EventLog;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use clap::Parser;
use serde_json::json;
use std::{path::PathBuf, process::ExitCode, sync::Arc};

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_OPERATION_CONFIG_BYTES: usize = 128 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aip-host-chatwoot", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Chatwoot base URL.
    #[arg(long, env = "AIP_CHATWOOT_BASE_URL")]
    base_url: String,
    /// Stable Chatwoot account id.
    #[arg(long, env = "AIP_CHATWOOT_ACCOUNT_ID")]
    account_id: String,
    /// Owner-only file containing the Chatwoot API token.
    #[arg(long, env = "AIP_CHATWOOT_API_TOKEN_FILE")]
    api_token_file: PathBuf,
    /// Owner-only webhook HMAC secret file. Omission creates an outbound-only host.
    #[arg(long, env = "AIP_CHATWOOT_WEBHOOK_SECRET_FILE")]
    webhook_secret_file: Option<PathBuf>,
    /// Maximum accepted Chatwoot response size in bytes.
    #[arg(long, env = "AIP_CHATWOOT_MAX_RESPONSE_BYTES")]
    max_response_bytes: Option<usize>,
    /// Optional JSON array of exact Chatwoot capability suffixes admitted for
    /// this product edition and account. Omission enables the full catalogue.
    #[arg(long, env = "AIP_CHATWOOT_OPERATIONS_FILE")]
    operations_file: Option<PathBuf>,
}

#[derive(Clone)]
struct WebhookState {
    connector: Arc<ChatwootConnector>,
    events: EventLog,
    publisher: ConnectorHostEventPublisher,
}

#[derive(Clone, Copy, Debug)]
struct WebhookRejection {
    status: StatusCode,
    code: &'static str,
}

impl IntoResponse for WebhookRejection {
    fn into_response(self) -> Response {
        webhook_error(self.status, self.code)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    let api_token = read_secret_utf8(&args.api_token_file, MAX_SECRET_BYTES)
        .map_err(|error| error.to_string())?;
    let mut connector = ChatwootConnector::with_api_token(
        &args.base_url,
        &args.account_id,
        ConnectorSecret::new(api_token.as_bytes()),
    )
    .map_err(|error| error.to_string())?;
    if let Some(limit) = args.max_response_bytes {
        connector = connector
            .with_max_response_bytes(limit)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.operations_file.as_ref() {
        let suffixes: Vec<String> = read_json_config(path, MAX_OPERATION_CONFIG_BYTES)
            .map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                ChatwootOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown Chatwoot operation suffix `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        connector = connector
            .with_allowed_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    let webhook_secret = args
        .webhook_secret_file
        .as_ref()
        .map(|path| read_secret_utf8(path, MAX_SECRET_BYTES))
        .transpose()
        .map_err(|error| error.to_string())?;
    if let Some(secret) = webhook_secret.as_ref() {
        // The admission manifest must expose the same signed ingress profile
        // that the final connector instance will serve. The replay backend is
        // replaced with shared runtime state immediately after preparation.
        connector = connector.with_webhook_secret(secret.as_bytes());
    }
    let host = PreparedConnectorHost::prepare(args.host.clone(), &connector)
        .await
        .map_err(|error| error.to_string())?;
    let stores = host.runtime_stores();
    let webhook_state = if let Some(secret) = webhook_secret.as_ref() {
        let replay = ProfileStateChatwootReplayStore::new(
            stores.profile_state.clone(),
            format!("instance:{}", args.host.instance_id),
        )?;
        connector = connector.with_webhook_security(secret.as_bytes(), Arc::new(replay));
        Some((Arc::new(connector.clone()), stores.events))
    } else {
        None
    };
    host.serve_with_router_factory(
        connector,
        move |publisher| match webhook_state {
            Some((connector, events)) => {
                let publisher = publisher.ok_or_else(|| {
                    ConnectorHostBootstrapError::Configuration(
                        "Chatwoot webhook ingress requires AIP_CONNECTOR_HOST_EVENT_ENDPOINT"
                            .to_owned(),
                    )
                })?;
                Ok(Router::new()
                    .route("/webhooks/chatwoot", post(chatwoot_webhook))
                    .layer(DefaultBodyLimit::max(MAX_WEBHOOK_BODY_BYTES))
                    .with_state(WebhookState {
                        connector,
                        events,
                        publisher,
                    }))
            }
            None => Ok(Router::new()),
        },
        shutdown_signal(),
    )
    .await
    .map_err(|error| error.to_string())
}

async fn chatwoot_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let delivery_id = match required_header(&headers, "x-chatwoot-delivery") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let timestamp = match required_header(&headers, "x-chatwoot-timestamp").and_then(|value| {
        value.parse::<i64>().map_err(|_| WebhookRejection {
            status: StatusCode::BAD_REQUEST,
            code: "webhook.invalid_timestamp",
        })
    }) {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let signature = match required_header(&headers, "x-chatwoot-signature") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let raw_body = match String::from_utf8(body.to_vec()) {
        Ok(value) => value,
        Err(_) => return webhook_error(StatusCode::BAD_REQUEST, "webhook.invalid_utf8"),
    };
    let envelopes = match state
        .connector
        .ingest_webhook_delivery(ChatwootWebhookDelivery {
            delivery_id,
            timestamp,
            signature,
            raw_body,
        })
        .await
    {
        Ok(envelopes) => envelopes,
        Err(ChatwootConnectorError::InvalidWebhook(_)) => {
            return webhook_error(StatusCode::UNAUTHORIZED, "webhook.authentication_failed");
        }
        Err(ChatwootConnectorError::ReplayStore(_)) => {
            return webhook_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook.storage_unavailable",
            );
        }
        Err(_) => return webhook_error(StatusCode::BAD_REQUEST, "webhook.invalid_delivery"),
    };
    let mut accepted = Vec::new();
    for envelope in envelopes {
        let MessageBody::ChannelMessage(message) = envelope.body else {
            return webhook_error(StatusCode::INTERNAL_SERVER_ERROR, "webhook.invalid_mapping");
        };
        let event = match event_from_channel_message(*message) {
            Ok(event) => event,
            Err(_) => {
                return webhook_error(StatusCode::INTERNAL_SERVER_ERROR, "webhook.invalid_mapping");
            }
        };
        match state.events.append_with_outcome(event).await {
            Ok(outcome) => accepted.push(outcome.into_event()),
            Err(_) => {
                return webhook_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "webhook.storage_unavailable",
                );
            }
        }
    }
    let publication = if accepted.is_empty() {
        None
    } else {
        match state
            .publisher
            .enqueue("chatwoot-webhooks", accepted.clone())
            .await
        {
            Ok(outcome) => Some(outcome.as_str()),
            Err(_) => {
                return webhook_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "webhook.storage_unavailable",
                );
            }
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "accepted_events": accepted.len(),
            "central_delivery": publication,
        })),
    )
        .into_response()
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, WebhookRejection> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(WebhookRejection {
            status: StatusCode::BAD_REQUEST,
            code: "webhook.missing_header",
        })
}

fn webhook_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": { "code": code } }))).into_response()
}
