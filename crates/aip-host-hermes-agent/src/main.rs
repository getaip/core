//! Standalone production Hermes Agent connector host.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_hermes_agent::{
    HermesAgentConnector, HermesAgentEndpoint, HermesOperatorPolicy,
    RuntimeHermesDelegatedResultResolver,
};
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, PreparedConnectorHost, read_json_config, read_secret_utf8,
    shutdown_signal,
};
use clap::Parser;
use serde::Deserialize;
use std::{path::PathBuf, process::ExitCode};

const MAX_ENDPOINT_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_OPERATOR_POLICY_BYTES: usize = 512 * 1024;
const MAX_API_KEY_BYTES: usize = 16 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aip-host-hermes-agent", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Bounded JSON array of Hermes endpoint descriptors. API keys are file references.
    #[arg(long, env = "AIP_HERMES_ENDPOINTS_FILE")]
    endpoints_file: PathBuf,
    /// Optional validated Hermes operator-policy JSON. Omission keeps delegation disabled.
    #[arg(long, env = "AIP_HERMES_OPERATOR_POLICY_FILE")]
    operator_policy_file: Option<PathBuf>,
    /// Maximum accepted non-streaming Hermes response size in bytes.
    #[arg(long, env = "AIP_HERMES_MAX_JSON_RESPONSE_BYTES")]
    max_json_response_bytes: Option<usize>,
    /// Maximum accepted complete Hermes SSE response size in bytes.
    #[arg(long, env = "AIP_HERMES_MAX_STREAM_RESPONSE_BYTES")]
    max_stream_response_bytes: Option<usize>,
    /// Maximum accepted individual Hermes SSE frame size in bytes.
    #[arg(long, env = "AIP_HERMES_MAX_SSE_FRAME_BYTES")]
    max_sse_frame_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointConfig {
    id: String,
    base_url: String,
    #[serde(default)]
    api_key_file: Option<PathBuf>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
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
    let endpoint_configs: Vec<EndpointConfig> =
        read_json_config(&args.endpoints_file, MAX_ENDPOINT_CONFIG_BYTES)
            .map_err(|error| error.to_string())?;
    if endpoint_configs.is_empty() || endpoint_configs.len() > 1_000 {
        return Err("Hermes endpoint config must contain 1 to 1000 descriptors".to_owned());
    }
    let mut endpoints = Vec::with_capacity(endpoint_configs.len());
    for config in endpoint_configs {
        let tenant_id = config
            .tenant_id
            .unwrap_or_else(|| args.host.tenant_id.clone());
        if tenant_id != args.host.tenant_id {
            return Err(format!(
                "Hermes endpoint `{}` tenant does not match the connector instance tenant",
                config.id
            ));
        }
        let mut endpoint = HermesAgentEndpoint::new(&config.id, &config.base_url, None)
            .map_err(|error| error.to_string())?
            .with_tenant_id(tenant_id)
            .map_err(|error| error.to_string())?;
        if let Some(display_name) = config.display_name {
            endpoint = endpoint.with_display_name(display_name);
        }
        if let Some(path) = config.api_key_file {
            let secret =
                read_secret_utf8(&path, MAX_API_KEY_BYTES).map_err(|error| error.to_string())?;
            endpoint = endpoint
                .with_api_key_secret(ConnectorSecret::new(secret.as_bytes()))
                .map_err(|error| error.to_string())?;
        }
        endpoints.push(endpoint);
    }

    let mut connector = HermesAgentConnector::new(endpoints).map_err(|error| error.to_string())?;
    match (
        args.max_json_response_bytes,
        args.max_stream_response_bytes,
        args.max_sse_frame_bytes,
    ) {
        (None, None, None) => {}
        (Some(json), Some(stream), Some(frame)) => {
            connector = connector
                .with_response_limits(json, stream, frame)
                .map_err(|error| error.to_string())?;
        }
        _ => {
            return Err(
                "all three Hermes response limits must be configured together or omitted"
                    .to_owned(),
            );
        }
    }
    if let Some(path) = args.operator_policy_file.as_ref() {
        let policy: HermesOperatorPolicy =
            read_json_config(path, MAX_OPERATOR_POLICY_BYTES).map_err(|error| error.to_string())?;
        connector = connector
            .with_operator_policy(policy)
            .map_err(|error| error.to_string())?;
    }
    let host = PreparedConnectorHost::prepare(args.host, &connector)
        .await
        .map_err(|error| error.to_string())?;
    let stores = host.runtime_stores();
    connector = connector
        .with_profile_state_store(stores.profile_state.clone())
        .with_approval_store(stores.approvals.clone())
        .with_delegated_result_resolver(RuntimeHermesDelegatedResultResolver::from_stores(
            stores.action_queue,
            stores.lifecycle,
        ));
    host.serve(connector, shutdown_signal())
        .await
        .map_err(|error| error.to_string())
}
