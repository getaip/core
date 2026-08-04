//! Standalone production CrewAI connector host.
//!
//! The Rust process owns AIP identity, durable runtime state, registry leases,
//! and sidecar credentials. CrewAI itself remains in a separately versioned
//! Python artifact. One sidecar state volume must be mounted by exactly one
//! active replica; horizontal scaling uses independent connector instances.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_crewai::{CrewAiSidecarConnector, CrewDescriptor};
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, PreparedConnectorHost, read_json_config, read_secret_utf8,
    shutdown_signal,
};
use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

const MAX_CREW_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CREWS: usize = 1_000;

#[derive(Debug, Parser)]
#[command(name = "aip-host-crewai", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Base URL of the separately deployed immutable CrewAI sidecar.
    #[arg(long, env = "AIP_CREWAI_SIDECAR_URL")]
    sidecar_url: String,
    /// Owner-only file containing the sidecar bearer token.
    #[arg(long, env = "AIP_CREWAI_SIDECAR_TOKEN_FILE")]
    sidecar_token_file: PathBuf,
    /// Bounded JSON array of admitted CrewAI crew descriptors.
    #[arg(long, env = "AIP_CREWAI_CREWS_FILE")]
    crews_file: PathBuf,
    /// Maximum accepted sidecar response or complete event stream.
    #[arg(long, env = "AIP_CREWAI_MAX_RESPONSE_BYTES")]
    max_response_bytes: Option<usize>,
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
    let crews: Vec<CrewDescriptor> = read_json_config(&args.crews_file, MAX_CREW_CONFIG_BYTES)
        .map_err(|error| error.to_string())?;
    if crews.is_empty() || crews.len() > MAX_CREWS {
        return Err(format!(
            "CrewAI config must contain 1 to {MAX_CREWS} crew descriptors"
        ));
    }
    let token = read_secret_utf8(&args.sidecar_token_file, MAX_BEARER_TOKEN_BYTES)
        .map_err(|error| error.to_string())?;
    let mut connector = CrewAiSidecarConnector::new(&args.sidecar_url, crews)
        .map_err(|error| error.to_string())?
        .with_bearer_secret(ConnectorSecret::new(token.as_bytes()))
        .map_err(|error| error.to_string())?;
    if let Some(limit) = args.max_response_bytes {
        connector = connector
            .with_max_response_bytes(limit)
            .map_err(|error| error.to_string())?;
    }
    let host = PreparedConnectorHost::prepare(args.host, &connector)
        .await
        .map_err(|error| error.to_string())?;
    host.serve(connector, shutdown_signal())
        .await
        .map_err(|error| error.to_string())
}
