//! Standalone production WA Archive connector host.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, ConnectorHostBootstrapError, PreparedConnectorHost,
    read_json_config, read_secret_utf8, shutdown_signal,
};
use aip_connector_wa_archive::{
    WaArchiveChangeFeedWorker, WaArchiveConnector, WaArchiveControlOperation, WaArchiveOperation,
    WaArchiveQueryOperation,
};
use axum::Router;
use clap::Parser;
use std::{path::PathBuf, process::ExitCode, sync::Arc};

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_OPERATION_CONFIG_BYTES: usize = 128 * 1024;
const MAX_QUERY_OPERATION_CONFIG_BYTES: usize = 32 * 1024;
const MAX_CONTROL_OPERATION_CONFIG_BYTES: usize = 8 * 1024;
const MAX_MEDIA_ORIGIN_CONFIG_BYTES: usize = 128 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aip-host-wa-archive", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Base URL of the isolated WA Archive provider process.
    #[arg(long, env = "AIP_WA_ARCHIVE_BASE_URL")]
    base_url: String,
    /// Owner-only file containing the WA Archive API bearer token.
    #[arg(long, env = "AIP_WA_ARCHIVE_API_TOKEN_FILE")]
    api_token_file: PathBuf,
    /// Optional JSON array of exact provider operation kinds admitted for this account.
    #[arg(long, env = "AIP_WA_ARCHIVE_OPERATIONS_FILE")]
    operations_file: Option<PathBuf>,
    /// Optional JSON array of exact archive query kinds admitted for this account.
    #[arg(long, env = "AIP_WA_ARCHIVE_QUERY_OPERATIONS_FILE")]
    query_operations_file: Option<PathBuf>,
    /// Optional JSON array of exact operator-control kinds admitted for this account.
    #[arg(long, env = "AIP_WA_ARCHIVE_CONTROL_OPERATIONS_FILE")]
    control_operations_file: Option<PathBuf>,
    /// Exact source revision compiled into the WA Archive provider binary.
    #[arg(long, env = "AIP_WA_ARCHIVE_PROVIDER_SOURCE_REVISION")]
    provider_source_revision: String,
    /// Optional JSON array of exact HTTPS origins allowed for outgoing media retrieval.
    #[arg(long, env = "AIP_WA_ARCHIVE_MEDIA_ORIGINS_FILE")]
    media_origins_file: Option<PathBuf>,
    /// Maximum accepted provider JSON response size in bytes.
    #[arg(long, env = "AIP_WA_ARCHIVE_MAX_JSON_RESPONSE_BYTES")]
    max_json_response_bytes: Option<usize>,
    /// Maximum accepted allowlisted remote-media size in bytes.
    #[arg(long, env = "AIP_WA_ARCHIVE_MAX_MEDIA_BYTES")]
    max_media_bytes: Option<usize>,
    /// Disable provider change-feed publication for an explicitly outbound-only deployment.
    #[arg(
        long,
        env = "AIP_WA_ARCHIVE_DISABLE_CHANGE_FEED",
        default_value_t = false
    )]
    disable_change_feed: bool,
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
    let external_account_id = args
        .host
        .external_account_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            "AIP_CONNECTOR_HOST_EXTERNAL_ACCOUNT_ID is required for WA Archive".to_owned()
        })?
        .to_owned();
    if args.host.external_account_system.as_deref() != Some("wa_archive") {
        return Err("AIP_CONNECTOR_HOST_EXTERNAL_ACCOUNT_SYSTEM must be `wa_archive`".to_owned());
    }
    let api_token = read_secret_utf8(&args.api_token_file, MAX_SECRET_BYTES)
        .map_err(|error| error.to_string())?;
    let mut connector = WaArchiveConnector::new(
        &args.base_url,
        &external_account_id,
        ConnectorSecret::new(api_token.as_bytes()),
    )
    .map_err(|error| error.to_string())?
    .with_expected_provider_source_revision(&args.provider_source_revision)
    .map_err(|error| error.to_string())?;
    if let Some(path) = args.operations_file.as_ref() {
        let suffixes: Vec<String> = read_json_config(path, MAX_OPERATION_CONFIG_BYTES)
            .map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                WaArchiveOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown WA Archive operation `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        connector = connector
            .with_allowed_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.query_operations_file.as_ref() {
        let suffixes: Vec<String> = read_json_config(path, MAX_QUERY_OPERATION_CONFIG_BYTES)
            .map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                WaArchiveQueryOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown WA Archive query operation `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        connector = connector
            .with_allowed_query_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.control_operations_file.as_ref() {
        let suffixes: Vec<String> = read_json_config(path, MAX_CONTROL_OPERATION_CONFIG_BYTES)
            .map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                WaArchiveControlOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown WA Archive control operation `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        connector = connector
            .with_allowed_control_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.media_origins_file.as_ref() {
        let origins: Vec<String> = read_json_config(path, MAX_MEDIA_ORIGIN_CONFIG_BYTES)
            .map_err(|error| error.to_string())?;
        connector = connector
            .with_allowed_media_origins(origins)
            .map_err(|error| error.to_string())?;
    }
    if let Some(limit) = args.max_json_response_bytes {
        connector = connector
            .with_max_json_response_bytes(limit)
            .map_err(|error| error.to_string())?;
    }
    if let Some(limit) = args.max_media_bytes {
        connector = connector
            .with_max_media_bytes(limit)
            .map_err(|error| error.to_string())?;
    }
    connector
        .require_change_feed(!args.disable_change_feed)
        .await;
    let host = PreparedConnectorHost::prepare(args.host.clone(), &connector)
        .await
        .map_err(|error| error.to_string())?;
    let worker = WaArchiveChangeFeedWorker::new(
        Arc::new(connector.clone()),
        host.runtime_stores().profile_state,
    );
    let disable_change_feed = args.disable_change_feed;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    host.serve_with_router_factory(
        connector,
        move |publisher| {
            if disable_change_feed {
                return Ok(Router::new());
            }
            let publisher = publisher.ok_or_else(|| {
                ConnectorHostBootstrapError::Configuration(
                    "WA Archive change feed requires AIP_CONNECTOR_HOST_EVENT_ENDPOINT".to_owned(),
                )
            })?;
            tokio::spawn(worker.run(publisher, shutdown_receiver));
            Ok(Router::new())
        },
        async move {
            shutdown_signal().await;
            let _ = shutdown_sender.send(true);
        },
    )
    .await
    .map_err(|error| error.to_string())
}
