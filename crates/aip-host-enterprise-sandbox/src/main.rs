//! Standalone production process for the deterministic enterprise sandbox.

#![forbid(unsafe_code)]

use aip_connector_enterprise_sandbox::EnterpriseSandboxConnector;
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, PreparedConnectorHost, read_secret_utf8, shutdown_signal,
};
use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

const MAX_DATABASE_URL_BYTES: usize = 16 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aip-host-enterprise-sandbox", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Owner-controlled file containing the enterprise fixture PostgreSQL URL.
    #[arg(long, env = "AIP_ENTERPRISE_SANDBOX_DATABASE_URL_FILE")]
    provider_database_url_file: PathBuf,
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
    let database_url = read_secret_utf8(&args.provider_database_url_file, MAX_DATABASE_URL_BYTES)
        .map_err(|error| error.to_string())?;
    let connector = EnterpriseSandboxConnector::connect(database_url.as_str())
        .await
        .map_err(|error| error.to_string())?;
    let host = PreparedConnectorHost::prepare(args.host, &connector)
        .await
        .map_err(|error| error.to_string())?;
    host.serve(connector, shutdown_signal())
        .await
        .map_err(|error| error.to_string())
}
