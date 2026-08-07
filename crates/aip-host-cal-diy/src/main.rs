//! Standalone production Cal.diy connector host.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_cal_diy::{
    CalDiyAuth, CalDiyConnector, CalDiyWebhookDelivery, CalDiyWebhookDestinationPolicy,
    ProfileStateCalDiyWebhookReplayStore, StaticCalDiyWebhookSecrets,
};
use aip_connector_host::ConnectorHostEventPublisher;
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, ConnectorHostBootstrapError, PreparedConnectorHost,
    read_secret_utf8, shutdown_signal,
};
use aip_core::MessageBody;
use aip_runtime::EventLog;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use clap::Parser;
use serde_json::json;
use std::{path::PathBuf, process::ExitCode, sync::Arc};
use time::OffsetDateTime;

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aip-host-cal-diy", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Cal.diy API base URL.
    #[arg(long, env = "AIP_CAL_DIY_BASE_URL")]
    cal_diy_base_url: String,
    /// Stable Cal.diy account boundary.
    #[arg(long, env = "AIP_CAL_DIY_ACCOUNT_ID")]
    cal_diy_account_id: String,
    /// Owner-controlled Bearer/API-key file.
    #[arg(long, env = "AIP_CAL_DIY_BEARER_TOKEN_FILE", conflicts_with_all = ["cal_diy_oauth_client_id", "cal_diy_oauth_client_secret_file"])]
    cal_diy_bearer_token_file: Option<PathBuf>,
    /// Public OAuth client id.
    #[arg(
        long,
        env = "AIP_CAL_DIY_OAUTH_CLIENT_ID",
        requires = "cal_diy_oauth_client_secret_file"
    )]
    cal_diy_oauth_client_id: Option<String>,
    /// Owner-controlled OAuth client-secret file.
    #[arg(
        long,
        env = "AIP_CAL_DIY_OAUTH_CLIENT_SECRET_FILE",
        requires = "cal_diy_oauth_client_id"
    )]
    cal_diy_oauth_client_secret_file: Option<PathBuf>,
    /// Maximum accepted provider response size.
    #[arg(long, env = "AIP_CAL_DIY_MAX_RESPONSE_BYTES")]
    cal_diy_max_response_bytes: Option<usize>,
    /// Webhook HMAC mapping formatted as `SUBSCRIPTION_ID=SECRET_FILE`.
    #[arg(
        long = "cal-diy-webhook-secret-file",
        env = "AIP_CAL_DIY_WEBHOOK_SECRET_FILES",
        value_delimiter = ','
    )]
    cal_diy_webhook_secret_files: Vec<String>,
    /// Deployment-owned HTTPS webhook destination prefix.
    #[arg(
        long = "cal-diy-webhook-subscriber-prefix",
        env = "AIP_CAL_DIY_WEBHOOK_SUBSCRIBER_PREFIXES",
        value_delimiter = ','
    )]
    cal_diy_webhook_subscriber_prefixes: Vec<String>,
}

#[derive(Clone)]
struct WebhookState {
    connector: Arc<CalDiyConnector>,
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
    let auth = cal_auth(&args)?;
    let mut connector =
        CalDiyConnector::with_auth(&args.cal_diy_base_url, &args.cal_diy_account_id, auth)
            .map_err(|error| error.to_string())?;
    if let Some(limit) = args.cal_diy_max_response_bytes {
        connector = connector
            .with_max_response_bytes(limit)
            .map_err(|error| error.to_string())?;
    }
    if !args.cal_diy_webhook_subscriber_prefixes.is_empty() {
        connector = connector.with_webhook_destination_policy(
            CalDiyWebhookDestinationPolicy::from_prefixes(
                args.cal_diy_webhook_subscriber_prefixes.clone(),
            )
            .map_err(|error| error.to_string())?,
        );
    }

    let webhook_secrets = if args.cal_diy_webhook_secret_files.is_empty() {
        None
    } else {
        Some(Arc::new(webhook_secrets(
            &args.cal_diy_webhook_secret_files,
        )?))
    };
    if let Some(secrets) = webhook_secrets.as_ref() {
        // Advertise signed ingress during admission. The process-local replay
        // store is replaced with the shared runtime store after preparation.
        connector = connector.with_webhook_security(
            secrets.clone(),
            Arc::new(aip_connector_cal_diy::InMemoryCalDiyWebhookReplayStore::default()),
        );
    }

    let host = PreparedConnectorHost::prepare(args.host.clone(), &connector)
        .await
        .map_err(|error| error.to_string())?;
    let stores = host.runtime_stores();
    connector = connector.with_profile_state_store(stores.profile_state.clone());

    let webhook_state = if let Some(secrets) = webhook_secrets {
        let replay = ProfileStateCalDiyWebhookReplayStore::new(
            stores.profile_state.clone(),
            format!("instance:{}", args.cal_diy_account_id),
        )?;
        connector = connector.with_webhook_security(secrets, Arc::new(replay));
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
                        "Cal.diy webhook ingress requires AIP_CONNECTOR_HOST_EVENT_ENDPOINT"
                            .to_owned(),
                    )
                })?;
                Ok(Router::new()
                    .route("/webhooks/cal-diy/{subscription_id}", post(cal_webhook))
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

fn cal_auth(args: &Args) -> Result<CalDiyAuth, String> {
    match (
        args.cal_diy_bearer_token_file.as_ref(),
        args.cal_diy_oauth_client_id.as_ref(),
        args.cal_diy_oauth_client_secret_file.as_ref(),
    ) {
        (Some(path), None, None) => {
            let secret = read_secret_utf8(path, MAX_SECRET_BYTES).map_err(|e| e.to_string())?;
            Ok(CalDiyAuth::Bearer(ConnectorSecret::new(
                secret.as_bytes(),
            )))
        }
        (None, Some(client_id), Some(path)) if !client_id.trim().is_empty() => {
            let secret = read_secret_utf8(path, MAX_SECRET_BYTES).map_err(|e| e.to_string())?;
            Ok(CalDiyAuth::OAuthClientCredentials {
                client_id: client_id.clone(),
                client_secret: ConnectorSecret::new(secret.as_bytes()),
            })
        }
        _ => Err(
            "Cal.diy requires either one Bearer-token file or one complete OAuth client-credential pair"
                .to_owned(),
        ),
    }
}

fn webhook_secrets(specs: &[String]) -> Result<StaticCalDiyWebhookSecrets, String> {
    let mut entries = Vec::with_capacity(specs.len());
    for spec in specs {
        let (secret_ref, path) = spec
            .split_once('=')
            .ok_or_else(|| "Cal.diy webhook secret mapping must be REF=FILE".to_owned())?;
        if secret_ref.trim().is_empty() || path.trim().is_empty() {
            return Err("Cal.diy webhook secret mapping must contain REF and FILE".to_owned());
        }
        let secret = read_secret_utf8(PathBuf::from(path.trim()).as_path(), MAX_SECRET_BYTES)
            .map_err(|error| error.to_string())?;
        entries.push((
            secret_ref.trim().to_owned(),
            ConnectorSecret::new(secret.as_bytes()),
        ));
    }
    StaticCalDiyWebhookSecrets::new(entries)
}

async fn cal_webhook(
    State(state): State<WebhookState>,
    Path(subscription_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let signature = match required_header(&headers, "x-cal-signature-256") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let webhook_version = match required_header(&headers, "x-cal-webhook-version") {
        Ok(value) => value,
        Err(rejection) => return rejection.into_response(),
    };
    let raw_body = match String::from_utf8(body.to_vec()) {
        Ok(value) => value,
        Err(_) => return webhook_error(StatusCode::BAD_REQUEST, "webhook.invalid_utf8"),
    };
    let delivery = CalDiyWebhookDelivery {
        subscription_id,
        signature,
        webhook_version: Some(webhook_version),
        raw_body,
        received_at: OffsetDateTime::now_utc().unix_timestamp(),
    };
    let envelopes = match state.connector.ingest_webhook_delivery(delivery).await {
        Ok(envelopes) => envelopes,
        Err(aip_connector_cal_diy::CalDiyWebhookError::InvalidSignature)
        | Err(aip_connector_cal_diy::CalDiyWebhookError::InvalidSignatureEncoding)
        | Err(aip_connector_cal_diy::CalDiyWebhookError::UnknownSubscription) => {
            return webhook_error(StatusCode::UNAUTHORIZED, "webhook.authentication_failed");
        }
        Err(aip_connector_cal_diy::CalDiyWebhookError::ReplayStore(_)) => {
            return webhook_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook.storage_unavailable",
            );
        }
        Err(_) => return webhook_error(StatusCode::BAD_REQUEST, "webhook.invalid_delivery"),
    };
    let mut accepted = Vec::new();
    for envelope in envelopes {
        let MessageBody::EventStream(stream) = envelope.body else {
            return webhook_error(StatusCode::INTERNAL_SERVER_ERROR, "webhook.invalid_mapping");
        };
        for event in stream.events {
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
    }
    let publication = if accepted.is_empty() {
        None
    } else {
        match state
            .publisher
            .enqueue("cal-diy-webhooks", accepted.clone())
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
