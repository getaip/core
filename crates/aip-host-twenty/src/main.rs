//! Standalone production Twenty connector host.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_host::ConnectorHostEventPublisher;
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, ConnectorHostBootstrapError, PreparedConnectorHost,
    read_json_config, read_secret_utf8, shutdown_signal,
};
use aip_connector_twenty::{
    ProfileStateTwentyWebhookReplayStore, TwentyConnector, TwentyConnectorError,
    TwentyIdempotentIngestPolicy, TwentyOperation, TwentyWebhookDelivery,
};
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
const MAX_INGEST_POLICY_BYTES: usize = 1024 * 1024;
const MAX_WEBHOOK_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aip-host-twenty", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Twenty origin, without a path or credentials.
    #[arg(long, env = "AIP_TWENTY_BASE_URL")]
    base_url: String,
    /// Stable Twenty workspace/account identifier used for routing and manifests.
    #[arg(long, env = "AIP_TWENTY_WORKSPACE_ID")]
    workspace_id: String,
    /// Owner-only file containing a Twenty API key.
    #[arg(long, env = "AIP_TWENTY_API_TOKEN_FILE")]
    api_token_file: PathBuf,
    /// Owner-only Twenty webhook HMAC secret. Omission disables webhook ingress.
    #[arg(long, env = "AIP_TWENTY_WEBHOOK_SECRET_FILE")]
    webhook_secret_file: Option<PathBuf>,
    /// Explicitly permit plain HTTP to a trusted private-network Twenty origin.
    #[arg(long, env = "AIP_TWENTY_ALLOW_INSECURE_HTTP", default_value_t = false)]
    allow_insecure_http: bool,
    /// Maximum accepted Twenty response size in bytes.
    #[arg(long, env = "AIP_TWENTY_MAX_RESPONSE_BYTES")]
    max_response_bytes: Option<usize>,
    /// Optional JSON array of admitted capability suffixes. Omission enables all.
    #[arg(long, env = "AIP_TWENTY_OPERATIONS_FILE")]
    operations_file: Option<PathBuf>,
    /// Optional object-and-field allowlist for unattended idempotent ingestion.
    #[arg(long, env = "AIP_TWENTY_IDEMPOTENT_INGEST_POLICY_FILE")]
    idempotent_ingest_policy_file: Option<PathBuf>,
}

#[derive(Clone)]
struct WebhookState {
    connector: Arc<TwentyConnector>,
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
    let mut connector = TwentyConnector::with_api_token(
        &args.base_url,
        &args.workspace_id,
        ConnectorSecret::new(api_token.as_bytes()),
        args.allow_insecure_http,
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
                TwentyOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown Twenty operation suffix `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        connector = connector
            .with_allowed_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.idempotent_ingest_policy_file.as_ref() {
        let policy: TwentyIdempotentIngestPolicy =
            read_json_config(path, MAX_INGEST_POLICY_BYTES).map_err(|error| error.to_string())?;
        connector = connector
            .with_idempotent_ingest_policy(policy)
            .map_err(|error| error.to_string())?;
    }
    let webhook_secret = args
        .webhook_secret_file
        .as_ref()
        .map(|path| read_secret_utf8(path, MAX_SECRET_BYTES))
        .transpose()
        .map_err(|error| error.to_string())?;
    if let Some(secret) = webhook_secret.as_ref() {
        connector = connector
            .with_webhook_security(
                ConnectorSecret::new(secret.as_bytes()),
                Arc::new(aip_connector_twenty::InMemoryTwentyWebhookReplayStore::default()),
            )
            .map_err(|error| error.to_string())?;
    }
    let host = PreparedConnectorHost::prepare(args.host.clone(), &connector)
        .await
        .map_err(|error| error.to_string())?;
    let stores = host.runtime_stores();
    let webhook_state = if let Some(secret) = webhook_secret.as_ref() {
        let replay = ProfileStateTwentyWebhookReplayStore::new(
            stores.profile_state.clone(),
            format!("instance:{}", args.host.instance_id),
        )?;
        connector = connector
            .with_webhook_security(ConnectorSecret::new(secret.as_bytes()), Arc::new(replay))
            .map_err(|error| error.to_string())?;
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
                        "Twenty webhook ingress requires AIP_CONNECTOR_HOST_EVENT_ENDPOINT"
                            .to_owned(),
                    )
                })?;
                Ok(Router::new()
                    .route("/webhooks/twenty", post(twenty_webhook))
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

async fn twenty_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let timestamp = match required_header(&headers, "x-twenty-webhook-timestamp") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let signature = match required_header(&headers, "x-twenty-webhook-signature") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let nonce = match required_header(&headers, "x-twenty-webhook-nonce") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let event = match state
        .connector
        .ingest_webhook_delivery(TwentyWebhookDelivery {
            timestamp,
            signature,
            nonce,
            raw_body: body.to_vec(),
        })
        .await
    {
        Ok(event) => event,
        Err(TwentyConnectorError::ReplayStore(_)) => {
            return webhook_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook.storage_unavailable",
            );
        }
        Err(_) => {
            return webhook_error(StatusCode::UNAUTHORIZED, "webhook.authentication_failed");
        }
    };
    let accepted = match state.events.append_with_outcome(event).await {
        Ok(outcome) => outcome.into_event(),
        Err(_) => {
            return webhook_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook.storage_unavailable",
            );
        }
    };
    let publication = match state
        .publisher
        .enqueue("twenty-webhooks", vec![accepted])
        .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            return webhook_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook.storage_unavailable",
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "accepted_events": 1,
            "central_delivery": publication.as_str(),
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
