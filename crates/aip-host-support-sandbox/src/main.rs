//! Standalone production process for the deterministic support sandbox.

#![forbid(unsafe_code)]

use aip_connector_host_bootstrap::{
    ConnectorHostBootstrapArgs, PreparedConnectorHost, read_secret_utf8, shutdown_signal,
};
use aip_connector_support_sandbox::SupportSandboxConnector;
use aip_runtime::{
    ExecutionCheckpointObserver, ExecutionCheckpointRecord, ExecutionCheckpointStage,
};
use async_trait::async_trait;
use clap::Parser;
use serde::Deserialize;
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    future::pending,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_DATABASE_URL_BYTES: usize = 16 * 1024;
const MAX_CHECKPOINT_CONTROL_BYTES: u64 = 64 * 1024;
const CHECKPOINT_CONTROL_SCHEMA: &str = "aip.execution-crash-control/v1";
const CHECKPOINT_OBSERVATION_SCHEMA: &str = "aip.execution-crash-observation/v1";

#[derive(Debug, Parser)]
#[command(name = "aip-host-support-sandbox", version, about)]
struct Args {
    #[command(flatten)]
    host: ConnectorHostBootstrapArgs,
    /// Owner-controlled file containing the sandbox provider PostgreSQL URL.
    #[arg(long, env = "AIP_SUPPORT_SANDBOX_DATABASE_URL_FILE")]
    provider_database_url_file: PathBuf,
    /// Qualification-only control file selecting one process crash checkpoint.
    #[arg(
        long,
        env = "AIP_SUPPORT_SANDBOX_QUALIFICATION_CHECKPOINT_CONTROL_FILE",
        requires = "qualification_checkpoint_observed_file"
    )]
    qualification_checkpoint_control_file: Option<PathBuf>,
    /// Qualification-only atomic observation file written before the process blocks.
    #[arg(
        long,
        env = "AIP_SUPPORT_SANDBOX_QUALIFICATION_CHECKPOINT_OBSERVED_FILE",
        requires = "qualification_checkpoint_control_file"
    )]
    qualification_checkpoint_observed_file: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct FileCrashCheckpointObserver {
    control_file: PathBuf,
    observed_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrashCheckpointControl {
    schema_version: String,
    armed: bool,
    generation: String,
    action_id: String,
    stage: ExecutionCheckpointStage,
}

#[async_trait]
impl ExecutionCheckpointObserver for FileCrashCheckpointObserver {
    async fn observe(&self, checkpoint: ExecutionCheckpointRecord) {
        let control_file = self.control_file.clone();
        let control = tokio::task::spawn_blocking(move || load_control(&control_file))
            .await
            .ok()
            .and_then(Result::ok);
        let Some(control) = control else {
            return;
        };
        if !control.armed
            || checkpoint.stage != control.stage
            || checkpoint
                .action_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(control.action_id.as_str())
        {
            return;
        }
        let observed_file = self.observed_file.clone();
        let generation = control.generation;
        let written = tokio::task::spawn_blocking(move || {
            write_observation(&observed_file, &generation, &checkpoint)
        })
        .await
        .ok()
        .is_some_and(|result| result.is_ok());
        if written {
            // The fleet controller observes the durable marker and sends
            // SIGKILL. There is intentionally no release path inside the
            // process: continuing would invalidate the crash-window proof.
            pending::<()>().await;
        }
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
    let database_url = read_secret_utf8(&args.provider_database_url_file, MAX_DATABASE_URL_BYTES)
        .map_err(|error| error.to_string())?;
    let connector = SupportSandboxConnector::connect(database_url.as_str())
        .await
        .map_err(|error| error.to_string())?;
    let mut host = PreparedConnectorHost::prepare(args.host, &connector)
        .await
        .map_err(|error| error.to_string())?;
    if let (Some(control_file), Some(observed_file)) = (
        args.qualification_checkpoint_control_file,
        args.qualification_checkpoint_observed_file,
    ) {
        host = host.with_execution_checkpoint_observer(Arc::new(FileCrashCheckpointObserver {
            control_file,
            observed_file,
        }));
    }
    host.serve(connector, shutdown_signal())
        .await
        .map_err(|error| error.to_string())
}

fn load_control(path: &Path) -> Result<CrashCheckpointControl, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect crash checkpoint control: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("crash checkpoint control must be a regular non-symlink file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > MAX_CHECKPOINT_CONTROL_BYTES {
        return Err(format!(
            "crash checkpoint control must contain 1 to {MAX_CHECKPOINT_CONTROL_BYTES} bytes"
        ));
    }
    let control: CrashCheckpointControl = serde_json::from_slice(
        &fs::read(path)
            .map_err(|error| format!("failed to read crash checkpoint control: {error}"))?,
    )
    .map_err(|error| format!("crash checkpoint control is invalid JSON: {error}"))?;
    if control.schema_version != CHECKPOINT_CONTROL_SCHEMA {
        return Err("crash checkpoint control has an unsupported schema version".to_owned());
    }
    if control.generation.is_empty() || control.generation.len() > 128 {
        return Err("crash checkpoint generation must contain 1 to 128 bytes".to_owned());
    }
    if !control.action_id.starts_with("act_") || control.action_id.len() > 256 {
        return Err("crash checkpoint action id is invalid".to_owned());
    }
    Ok(control)
}

fn write_observation(
    path: &Path,
    generation: &str,
    checkpoint: &ExecutionCheckpointRecord,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "crash checkpoint observation path has no UTF-8 file name".to_owned())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_nanos();
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let payload = serde_json::to_vec(&json!({
        "schema_version": CHECKPOINT_OBSERVATION_SCHEMA,
        "generation": generation,
        "process_id": std::process::id(),
        "checkpoint": checkpoint,
    }))
    .map_err(|error| format!("failed to encode crash checkpoint observation: {error}"))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("failed to create crash checkpoint observation: {error}"))?;
    let publish = (|| -> Result<(), String> {
        file.write_all(&payload)
            .map_err(|error| format!("failed to write crash checkpoint observation: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync crash checkpoint observation: {error}"))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| format!("failed to publish crash checkpoint observation: {error}"))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync crash checkpoint directory: {error}"))?;
        Ok(())
    })();
    if publish.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish
}
