//! Standalone production Dify connector host.

#![forbid(unsafe_code)]

use aip_connector::ConnectorSecret;
use aip_connector_dify::{
    DifyApp, DifyAppCredential, DifyConnector, DifyKnowledgeBase, DifyKnowledgeCredential,
    ProfileStateDifyTaskStore,
};
use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, PreparedConnectorHost, read_json_config, read_secret_utf8,
    shutdown_signal,
};
use clap::Parser;
use serde::Deserialize;
use std::{path::PathBuf, process::ExitCode, sync::Arc};

const MAX_APP_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_API_KEY_BYTES: usize = 16 * 1024;
const MAX_APPS: usize = 1_000;
const MAX_KNOWLEDGE_CREDENTIALS: usize = 1_000;

#[derive(Debug, Parser)]
#[command(name = "aip-host-dify", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Dify API base URL.
    #[arg(long, env = "AIP_DIFY_BASE_URL")]
    base_url: String,
    /// Owner-only file containing one Dify application API key.
    #[arg(long, env = "AIP_DIFY_API_KEY_FILE")]
    api_key_file: Option<PathBuf>,
    /// Bounded JSON array of Dify applications served by this instance. Each
    /// entry must name its own `api_key_file` unless the legacy global key is
    /// supplied for a set of applications that intentionally share a key.
    #[arg(long, env = "AIP_DIFY_APPS_FILE")]
    apps_file: Option<PathBuf>,
    /// Bounded JSON array of workspace-scoped Dify Knowledge API credentials.
    #[arg(long, env = "AIP_DIFY_KNOWLEDGE_FILE")]
    knowledge_file: Option<PathBuf>,
    /// Maximum accepted blocking response or complete event stream.
    #[arg(long, env = "AIP_DIFY_MAX_RESPONSE_BYTES")]
    max_response_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DifyAppConfig {
    id: String,
    name: String,
    mode: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    api_key_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DifyKnowledgeConfig {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    api_key_file: PathBuf,
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
    let configs: Vec<DifyAppConfig> = args
        .apps_file
        .as_ref()
        .map(|path| read_json_config(path, MAX_APP_CONFIG_BYTES))
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    let knowledge_configs: Vec<DifyKnowledgeConfig> = args
        .knowledge_file
        .as_ref()
        .map(|path| read_json_config(path, MAX_APP_CONFIG_BYTES))
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    if configs.len() > MAX_APPS {
        return Err(format!(
            "Dify app config must contain no more than {MAX_APPS} descriptors"
        ));
    }
    if knowledge_configs.len() > MAX_KNOWLEDGE_CREDENTIALS {
        return Err(format!(
            "Dify knowledge config must contain no more than {MAX_KNOWLEDGE_CREDENTIALS} descriptors"
        ));
    }
    if configs.is_empty() && knowledge_configs.is_empty() {
        return Err("at least one Dify app or knowledge credential is required".to_owned());
    }
    let global_key = args
        .api_key_file
        .as_ref()
        .map(|path| read_secret_utf8(path, MAX_API_KEY_BYTES))
        .transpose()
        .map_err(|error| error.to_string())?;
    let mut credentials = Vec::with_capacity(configs.len());
    for config in configs {
        if global_key.is_some() && config.api_key_file.is_some() {
            return Err(format!(
                "Dify app `{}` cannot combine a per-app key file with AIP_DIFY_API_KEY_FILE",
                config.id
            ));
        }
        let key = match (config.api_key_file.as_ref(), global_key.as_ref()) {
            (Some(path), None) => {
                read_secret_utf8(path, MAX_API_KEY_BYTES).map_err(|error| error.to_string())?
            }
            (None, Some(key)) => key.clone(),
            (None, None) => {
                return Err(format!(
                    "Dify app `{}` requires an owner-only api_key_file",
                    config.id
                ));
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "Dify app `{}` has an ambiguous API-key source",
                    config.id
                ));
            }
        };
        credentials.push(DifyAppCredential {
            app: DifyApp {
                id: config.id,
                name: config.name,
                mode: config.mode,
                description: config.description,
            },
            api_key: ConnectorSecret::new(key.as_bytes()),
        });
    }
    if global_key.is_some() && credentials.is_empty() {
        return Err(
            "AIP_DIFY_API_KEY_FILE requires at least one configured application".to_owned(),
        );
    }
    let mut knowledge_credentials = Vec::with_capacity(knowledge_configs.len());
    for config in knowledge_configs {
        let key = read_secret_utf8(&config.api_key_file, MAX_API_KEY_BYTES)
            .map_err(|error| error.to_string())?;
        knowledge_credentials.push(DifyKnowledgeCredential {
            knowledge: DifyKnowledgeBase {
                id: config.id,
                name: config.name,
                description: config.description,
            },
            api_key: ConnectorSecret::new(key.as_bytes()),
        });
    }
    let mut connector =
        DifyConnector::with_credentials(&args.base_url, credentials, knowledge_credentials)
            .map_err(|error| error.to_string())?;
    if let Some(limit) = args.max_response_bytes {
        connector = connector
            .with_max_response_bytes(limit)
            .map_err(|error| error.to_string())?;
    }
    let host = PreparedConnectorHost::prepare(args.host.clone(), &connector)
        .await
        .map_err(|error| error.to_string())?;
    let task_store = ProfileStateDifyTaskStore::new(
        host.runtime_stores().profile_state,
        format!("instance:{}", args.host.instance_id),
    )?;
    connector = connector.with_task_store(Arc::new(task_store));
    host.serve(connector, shutdown_signal())
        .await
        .map_err(|error| error.to_string())
}
