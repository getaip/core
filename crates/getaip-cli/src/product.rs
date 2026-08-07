use crate::{
    OutputFormat,
    adapters::{self, ClientKind, ClientScope, ConfigureClients},
    print_json, service,
};
use aip_connector_registry_postgres::{PostgresConnectorRegistry, RegistryPoolLimits};
use clap::Args;
use getaip_distribution::{
    AIP_PROTOCOL_VERSION, Artifact, GETAIP_SOFTWARE_VERSION, InstallError, InstallRoots, Installer,
    Platform, ReleaseClient, RollbackState, VerifiedInstallation, VerifiedManifest,
    atomic_write_json, default_trust_store, read_json_file, verify_signed_manifest,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Read, Seek, SeekFrom},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    time::Duration,
};

const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const SECRET_FILE_ENVIRONMENTS: &[&str] = &[
    "GETAIP_NATIVE_BEARER_TOKEN_FILE",
    "GETAIP_NATIVE_SIGNING_SEED_FILE",
    "GETAIP_NATS_PASSWORD_FILE",
    "GETAIP_NATS_SIGNING_SEED_FILE",
    "GETAIP_SERVER_CALLBACK_SIGNING_SEED_FILE",
    "GETAIP_SERVER_CONNECTOR_FLEET_SIGNING_SEED_FILE",
    "GETAIP_SERVER_CONNECTOR_REGISTRY_URL_FILE",
    "GETAIP_SERVER_MCP_INTROSPECTION_CLIENT_SECRET_FILE",
    "GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE",
    "GETAIP_SERVER_NATS_PASSWORD_FILE",
    "GETAIP_SERVER_POSTGRES_URL_FILE",
];

/// Arguments for secure native setup.
#[derive(Clone, Debug, Args)]
pub(crate) struct SetupArgs {
    /// Inspect and verify the plan without changing the filesystem.
    #[arg(long)]
    dry_run: bool,
    /// Stable human or JSON output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// Already downloaded signed manifest passed by the npm bootstrap.
    #[arg(long, value_name = "PATH", requires = "signature")]
    manifest: Option<PathBuf>,
    /// Detached signature for an already downloaded manifest.
    #[arg(long, value_name = "PATH", requires = "manifest")]
    signature: Option<PathBuf>,
    /// Exact local distribution archive used only by isolated release qualification.
    #[arg(
        long,
        value_name = "PATH",
        hide = true,
        requires_all = ["manifest", "signature", "test_root"]
    )]
    artifact: Option<PathBuf>,
    /// Configure Codex to launch the verified GetAIP MCP server.
    #[arg(long)]
    codex: bool,
    /// Configure Claude Code to launch the verified GetAIP MCP server.
    #[arg(long)]
    claude: bool,
    /// Configure Cursor to launch the verified GetAIP MCP server.
    #[arg(long)]
    cursor: bool,
    /// Configure Gemini CLI to launch the verified GetAIP MCP server.
    #[arg(long)]
    gemini: bool,
    /// Configure OpenCode to launch the verified GetAIP MCP server.
    #[arg(long)]
    opencode: bool,
    /// Mutate the selected clients' user-global configuration.
    #[arg(long, conflicts_with = "project")]
    global: bool,
    /// Mutate the selected clients' project-local configuration.
    #[arg(long, conflicts_with = "global")]
    project: bool,
    /// Explicit project root; defaults to the current directory with --project.
    #[arg(long, value_name = "ABSOLUTE_PATH", requires = "project")]
    project_root: Option<PathBuf>,
    /// Confirm the fully explicit non-interactive setup plan.
    #[arg(long)]
    yes: bool,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

/// Arguments for stable installation diagnostics.
#[derive(Clone, Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Stable human or JSON output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

/// Arguments for top-level product status.
#[derive(Clone, Debug, Args)]
pub(crate) struct StatusArgs {
    /// Stable human or JSON output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// Attempt an approved signed update check.
    #[arg(long)]
    check_updates: bool,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

/// Arguments for foreground server execution.
#[derive(Clone, Debug, Args)]
pub(crate) struct ServeArgs {
    /// HTTP bind address passed to the verified server.
    #[arg(long, value_name = "ADDRESS", conflicts_with = "mcp_stdio")]
    bind: Option<SocketAddr>,
    /// Run the server through MCP stdio instead of HTTP.
    #[arg(long, conflicts_with = "bind")]
    mcp_stdio: bool,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
    /// Additional server arguments forwarded exactly once after --.
    #[arg(last = true, allow_hyphen_values = true)]
    server_arguments: Vec<OsString>,
}

/// Arguments for signed native upgrade.
#[derive(Clone, Debug, Args)]
pub(crate) struct UpgradeArgs {
    /// Inspect and verify the upgrade without changing the filesystem.
    #[arg(long)]
    dry_run: bool,
    /// Stable human or JSON output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// Exact release version to fetch from the approved GitHub Release.
    #[arg(long, value_name = "SEMVER", conflicts_with = "manifest")]
    version: Option<String>,
    /// Already downloaded signed manifest for an offline or bootstrap handoff.
    #[arg(long, value_name = "PATH", requires = "signature")]
    manifest: Option<PathBuf>,
    /// Detached signature for an already downloaded manifest.
    #[arg(long, value_name = "PATH", requires = "manifest")]
    signature: Option<PathBuf>,
    /// Exact local distribution archive used only by isolated release qualification.
    #[arg(
        long,
        value_name = "PATH",
        hide = true,
        requires_all = ["manifest", "signature", "test_root"]
    )]
    artifact: Option<PathBuf>,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

/// Arguments for atomic rollback.
#[derive(Clone, Debug, Args)]
pub(crate) struct RollbackArgs {
    /// Inspect the rollback without changing the filesystem.
    #[arg(long)]
    dry_run: bool,
    /// Stable human or JSON output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

/// Arguments for reversible uninstall.
#[derive(Clone, Debug, Args)]
pub(crate) struct UninstallArgs {
    /// Inspect the uninstall without changing the filesystem.
    #[arg(long)]
    dry_run: bool,
    /// Also delete GetAIP-owned configuration, runtime state, cache, and logs.
    #[arg(long)]
    purge_user_data: bool,
    /// Stable human or JSON output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductConfig {
    schema: String,
    bind: SocketAddr,
    server_arguments: Vec<String>,
}

impl Default for ProductConfig {
    fn default() -> Self {
        Self {
            schema: "org.getaip.config.v1".to_owned(),
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            server_arguments: Vec::new(),
        }
    }
}

impl ProductConfig {
    fn validate(&self) -> Result<(), String> {
        if self.schema != "org.getaip.config.v1" {
            return Err(format!("unsupported GetAIP config schema {}", self.schema));
        }
        if !self.bind.ip().is_loopback() {
            return Err("default product configuration must bind to a loopback address".to_owned());
        }
        if self.server_arguments.iter().any(|argument| {
            let lower = argument.to_ascii_lowercase();
            lower.contains("token")
                || lower.contains("password")
                || lower.contains("secret")
                || lower.contains("seed")
        }) {
            return Err(
                "product configuration must reference secret files, not secret arguments"
                    .to_owned(),
            );
        }
        validate_string_forwarded_arguments(&self.server_arguments)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Serialize)]
struct DiagnosticCheck {
    id: &'static str,
    status: CheckStatus,
    explanation: String,
    remediation: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DoctorReport {
    schema: &'static str,
    overall: CheckStatus,
    platform: String,
    checks: Vec<DiagnosticCheck>,
}

#[derive(Clone, Debug, Serialize)]
struct StatusReport {
    schema: &'static str,
    platform: String,
    installed: bool,
    installation_status: &'static str,
    active_version: Option<String>,
    server_version: Option<String>,
    process_state: &'static str,
    readiness: &'static str,
    endpoint: Option<String>,
    configuration_source: Option<String>,
    connector_registry: &'static str,
    update: &'static str,
    rollback_version: Option<String>,
}

pub(crate) async fn setup(arguments: SetupArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let trust_store = default_trust_store().map_err(|error| error.to_string())?;
    let verified = match (
        arguments.manifest.as_deref(),
        arguments.signature.as_deref(),
    ) {
        (Some(manifest), Some(signature)) => {
            let manifest_bytes =
                read_bounded_regular_file(manifest, MAX_MANIFEST_BYTES, "distribution manifest")?;
            let signature_bytes =
                read_bounded_regular_file(signature, MAX_SIGNATURE_BYTES, "manifest signature")?;
            verify_signed_manifest(&manifest_bytes, &signature_bytes, &trust_store)
                .map_err(|error| error.to_string())?
        }
        (None, None) => ReleaseClient::new()
            .map_err(|error| error.to_string())?
            .fetch_signed_manifest(GETAIP_SOFTWARE_VERSION, &trust_store)
            .await
            .map_err(|error| error.to_string())?,
        _ => return Err("pass --manifest and --signature together".to_owned()),
    };
    validate_bootstrap_compatibility(&verified, platform)?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    validate_existing_config(&roots)?;
    let installer = Installer::new(roots.clone());
    let plan = installer
        .plan(&verified, platform)
        .map_err(|error| error.to_string())?;
    let server = roots
        .version_dir(&plan.target_version)
        .join("bin/getaip-server");
    let adapter_request = setup_adapter_request(&arguments, &server)?;
    let adapter_plan = match adapter_request.clone() {
        Some(request) => adapters::configure(&roots, request, true)?,
        None => Vec::new(),
    };
    if arguments.dry_run {
        return match arguments.output {
            OutputFormat::Json => print_json(&serde_json::json!({
                "schema": "org.getaip.cli.setup-plan.v1",
                "installation": plan,
                "client_adapters": adapter_plan,
            })),
            OutputFormat::Text => {
                println!(
                    "GetAIP {} setup plan: {:?} for {} ({})",
                    plan.target_version,
                    plan.action,
                    platform.asset_label(),
                    plan.distribution_sha256
                );
                for adapter in adapter_plan {
                    println!("client adapter: {adapter}");
                }
                println!("dry-run: no filesystem changes were made");
                Ok(())
            }
        };
    }

    let target = verified
        .manifest
        .target(platform)
        .map_err(|error| error.to_string())?;
    let archive_path = acquire_distribution_archive(
        &installer,
        &target.distribution_archive,
        arguments.artifact.as_deref(),
    )
    .await?;
    let outcome = installer
        .install_archive(&verified, platform, &archive_path)
        .map_err(|error| error.to_string())?;
    if let Err(error) = ensure_default_config(&installer) {
        revert_install_after_integration_failure(&installer, plan.current_version.as_deref());
        return Err(format!(
            "default configuration failed; installation activation was restored: {error}"
        ));
    }
    if let Err(error) = prepare_test_adapter_home(&arguments, adapter_request.as_ref()) {
        revert_install_after_integration_failure(&installer, plan.current_version.as_deref());
        return Err(format!(
            "client adapter boundary preparation failed; installation activation was restored: {error}"
        ));
    }
    let configured_clients = if let Some(request) = adapter_request {
        match adapters::configure(&roots, request, false) {
            Ok(configured) => configured,
            Err(error) => {
                revert_install_after_integration_failure(
                    &installer,
                    plan.current_version.as_deref(),
                );
                return Err(format!(
                    "client adapter configuration failed; installation activation was restored: {error}"
                ));
            }
        }
    } else {
        Vec::new()
    };
    match arguments.output {
        OutputFormat::Json => print_json(&serde_json::json!({
            "schema": "org.getaip.cli.setup-outcome.v1",
            "installation": outcome,
            "client_adapters": configured_clients,
        })),
        OutputFormat::Text => {
            println!(
                "GetAIP {} is active ({:?}; manifest {})",
                outcome.active_version, outcome.action, outcome.manifest_sha256
            );
            if let Some(previous) = outcome.rollback_version {
                println!("rollback retained: {previous}");
            }
            for adapter in configured_clients {
                println!("configured client adapter: {adapter}");
            }
            Ok(())
        }
    }
}

fn setup_adapter_request(
    arguments: &SetupArgs,
    server: &Path,
) -> Result<Option<ConfigureClients>, String> {
    let mut clients = Vec::new();
    for (selected, client) in [
        (arguments.codex, ClientKind::Codex),
        (arguments.claude, ClientKind::Claude),
        (arguments.cursor, ClientKind::Cursor),
        (arguments.gemini, ClientKind::Gemini),
        (arguments.opencode, ClientKind::OpenCode),
    ] {
        if selected {
            clients.push(client);
        }
    }
    if clients.is_empty() {
        if arguments.global || arguments.project || arguments.project_root.is_some() {
            return Err("select at least one client with --codex, --claude, --cursor, --gemini, or --opencode".to_owned());
        }
        let _ = arguments.yes;
        return Ok(None);
    }
    let scope = match (arguments.global, arguments.project) {
        (true, false) => ClientScope::Global,
        (false, true) => ClientScope::Project,
        _ => {
            return Err(
                "client adapters require exactly one scope: --global or --project".to_owned(),
            );
        }
    };
    let home = match arguments.test_root.as_deref() {
        Some(root) => root.join("client-home"),
        None => env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "cannot resolve current user home directory".to_owned())?,
    };
    let project_root = match arguments.project_root.as_deref() {
        Some(root) => root.to_path_buf(),
        None => env::current_dir().map_err(|error| error.to_string())?,
    };
    if !project_root.is_absolute() {
        return Err("--project-root must be absolute".to_owned());
    }
    Ok(Some(ConfigureClients {
        clients,
        scope,
        home,
        project_root,
        server: server.to_path_buf(),
    }))
}

fn prepare_test_adapter_home(
    arguments: &SetupArgs,
    request: Option<&ConfigureClients>,
) -> Result<(), String> {
    if arguments.test_root.is_some()
        && let Some(request) = request
    {
        fs::create_dir_all(&request.home).map_err(|error| error.to_string())?;
        let metadata = fs::symlink_metadata(&request.home).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("test adapter home must be a real directory".to_owned());
        }
    }
    Ok(())
}

fn revert_install_after_integration_failure(installer: &Installer, previous: Option<&str>) {
    let active = installer
        .verify_active_installation()
        .ok()
        .map(|installation| installation.active.version);
    if previous.is_some() && active.as_deref() != previous {
        let _ = installer.rollback(false);
    } else if previous.is_none() {
        let _ = installer.uninstall(false, false);
    }
}

pub(crate) async fn doctor(arguments: DoctorArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    let installer = Installer::new(roots.clone());
    let mut checks = vec![DiagnosticCheck {
        id: "platform.supported",
        status: CheckStatus::Pass,
        explanation: format!(
            "{} is in the qualified initial release matrix",
            platform.rust_target()
        ),
        remediation: None,
    }];

    let verified_installation = match installer.verify_active_installation() {
        Ok(installation) => {
            checks.push(DiagnosticCheck {
                id: "installation.integrity",
                status: CheckStatus::Pass,
                explanation: format!(
                    "GetAIP {} manifest signature, state, executable digests, and modes are valid",
                    installation.active.version
                ),
                remediation: None,
            });
            Some(installation)
        }
        Err(error) => {
            checks.push(DiagnosticCheck {
                id: "installation.integrity",
                status: CheckStatus::Fail,
                explanation: error.to_string(),
                remediation: Some(
                    "run getaip setup to install or repair the signed distribution".to_owned(),
                ),
            });
            None
        }
    };
    checks.push(check_version_compatibility(verified_installation.as_ref()));

    let configuration = match load_product_config(&roots) {
        Ok(Some(config)) => {
            checks.push(DiagnosticCheck {
                id: "configuration.readable",
                status: CheckStatus::Pass,
                explanation: "owned product configuration is readable and valid".to_owned(),
                remediation: None,
            });
            Some(config)
        }
        Ok(None) => {
            checks.push(DiagnosticCheck {
                id: "configuration.readable",
                status: CheckStatus::Warn,
                explanation: "product configuration has not been created".to_owned(),
                remediation: Some("run getaip setup".to_owned()),
            });
            None
        }
        Err(error) => {
            checks.push(DiagnosticCheck {
                id: "configuration.readable",
                status: CheckStatus::Fail,
                explanation: error,
                remediation: Some(
                    "repair the owned config file or restore its GetAIP backup".to_owned(),
                ),
            });
            None
        }
    };

    checks.push(check_secret_file_permissions());
    checks.push(check_service_configuration(
        platform,
        &roots,
        arguments.test_root.is_some(),
    ));
    if let Some(config) = configuration.as_ref() {
        let readiness = probe_readiness(config.bind).await;
        let port_available = TcpListener::bind(config.bind).is_ok();
        checks.push(if readiness {
            DiagnosticCheck {
                id: "server.readiness",
                status: CheckStatus::Pass,
                explanation: format!("server is ready on http://{}", config.bind),
                remediation: None,
            }
        } else {
            DiagnosticCheck {
                id: "server.readiness",
                status: CheckStatus::Warn,
                explanation: if port_available {
                    format!("server is stopped and port {} is available", config.bind)
                } else {
                    format!(
                        "port {} is occupied but GetAIP readiness did not pass",
                        config.bind
                    )
                },
                remediation: Some(
                    "run getaip serve or inspect the process using the configured port".to_owned(),
                ),
            }
        });
    }

    checks.push(check_optional_database_configuration(&roots));
    checks.push(check_connector_registry_configuration(&roots));
    checks.push(check_managed_clients(
        &roots,
        verified_installation.as_ref(),
    ));
    checks.push(check_update_availability(verified_installation.as_ref()));
    checks.push(check_rollback_state(
        &installer,
        verified_installation.as_ref(),
    ));
    let overall = if checks.iter().any(|check| check.status == CheckStatus::Fail) {
        CheckStatus::Fail
    } else if checks.iter().any(|check| check.status == CheckStatus::Warn) {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    let report = DoctorReport {
        schema: "org.getaip.cli.doctor.v1",
        overall,
        platform: platform.rust_target().to_owned(),
        checks,
    };
    match arguments.output {
        OutputFormat::Json => {
            print_json(&serde_json::to_value(report).map_err(|error| error.to_string())?)
        }
        OutputFormat::Text => {
            println!("GetAIP doctor: {:?}", report.overall);
            for check in report.checks {
                println!("[{:?}] {}: {}", check.status, check.id, check.explanation);
                if let Some(remediation) = check.remediation {
                    println!("  remediation: {remediation}");
                }
            }
            Ok(())
        }
    }
}

pub(crate) async fn status(arguments: StatusArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    let installer = Installer::new(roots.clone());
    let pointer = installer.read_active_optional().ok().flatten();
    let installation_result = installer.verify_active_installation();
    let installation_status = match &installation_result {
        Ok(_) => "verified",
        Err(getaip_distribution::InstallError::NotInstalled) => "not_installed",
        Err(_) => "invalid",
    };
    let installation = installation_result.ok();
    let configuration = load_product_config(&roots).ok().flatten();
    let readiness = match configuration.as_ref() {
        Some(config) if probe_readiness(config.bind).await => "ready",
        Some(config) if TcpListener::bind(config.bind).is_err() => "not_ready",
        Some(_) => "stopped",
        None => "not_configured",
    };
    let rollback_version = read_rollback_version(&roots);
    let connector_registry = probe_connector_registry(&roots).await;
    let report = StatusReport {
        schema: "org.getaip.cli.status.v1",
        platform: platform.rust_target().to_owned(),
        installed: pointer.is_some(),
        installation_status,
        active_version: pointer.map(|value| value.version),
        server_version: installation
            .as_ref()
            .map(|value| value.state.software_version.clone()),
        process_state: match readiness {
            "ready" => "running",
            "stopped" => "stopped",
            _ => "unknown",
        },
        readiness,
        endpoint: configuration
            .as_ref()
            .map(|config| format!("http://{}", config.bind)),
        configuration_source: configuration
            .as_ref()
            .map(|_| roots.configuration().display().to_string()),
        connector_registry,
        update: status_update_state(installation.as_ref(), arguments.check_updates),
        rollback_version,
    };
    match arguments.output {
        OutputFormat::Json => {
            print_json(&serde_json::to_value(report).map_err(|error| error.to_string())?)
        }
        OutputFormat::Text => {
            println!(
                "GetAIP: {} ({})",
                report.active_version.as_deref().unwrap_or("not installed"),
                report.installation_status
            );
            println!("server: {} / {}", report.process_state, report.readiness);
            if let Some(endpoint) = report.endpoint {
                println!("endpoint: {endpoint}");
            }
            if let Some(rollback) = report.rollback_version {
                println!("rollback: {rollback}");
            }
            println!("update: {}", report.update);
            Ok(())
        }
    }
}

pub(crate) async fn serve(arguments: ServeArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    let installer = Installer::new(roots.clone());
    let installation = installer
        .verify_active_installation()
        .map_err(|error| error.to_string())?;
    if installation.active.version != GETAIP_SOFTWARE_VERSION {
        return Err(format!(
            "getaip {} cannot run installed server {}; use the matching CLI",
            GETAIP_SOFTWARE_VERSION, installation.active.version
        ));
    }
    let config = load_product_config(&roots)?
        .ok_or_else(|| "GetAIP configuration is missing; run getaip setup".to_owned())?;
    let server = roots
        .version_dir(&installation.active.version)
        .join("bin/getaip-server");
    let pinned_server = pin_verified_server(&server, &installation, &roots.state.join("runtime"))?;
    verify_server_version(pinned_server.execution_path(), &installation)?;
    validate_forwarded_arguments(&arguments.server_arguments)?;

    let mut command = ProcessCommand::new(pinned_server.execution_path());
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if arguments.mcp_stdio {
        command.arg("--mcp-stdio");
    } else {
        command
            .arg("--bind")
            .arg(arguments.bind.unwrap_or(config.bind).to_string());
    }
    for argument in config.server_arguments {
        command.arg(argument);
    }
    for argument in arguments.server_arguments {
        command.arg(argument);
    }
    command.env("GETAIP_SERVER_STORAGE_DIR", roots.state.join("runtime"));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        Err(format!(
            "failed to execute verified server {}: {error}",
            server.display()
        ))
    }
    #[cfg(not(unix))]
    {
        Err("foreground execution is not qualified on this platform".to_owned())
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct PinnedExecutable {
    _file: fs::File,
    execution_path: PathBuf,
    cleanup_path: Option<PathBuf>,
}

#[cfg(unix)]
impl PinnedExecutable {
    fn execution_path(&self) -> &Path {
        &self.execution_path
    }
}

#[cfg(unix)]
impl Drop for PinnedExecutable {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup_path.as_deref() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn pin_verified_server(
    server: &Path,
    installation: &VerifiedInstallation,
    execution_root: &Path,
) -> Result<PinnedExecutable, String> {
    let target = installation
        .release
        .manifest
        .target(installation.state.platform)
        .map_err(|error| error.to_string())?;
    let expected = target
        .distribution_archive
        .files
        .iter()
        .find(|file| file.path == "bin/getaip-server")
        .ok_or_else(|| "signed distribution does not contain bin/getaip-server".to_owned())?;
    if !expected.executable {
        return Err("signed distribution does not mark getaip-server executable".to_owned());
    }
    pin_server_file(server, &expected.sha256, execution_root)
}

#[cfg(unix)]
fn pin_server_file(
    server: &Path,
    expected_sha256: &str,
    _execution_root: &Path,
) -> Result<PinnedExecutable, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(server)
        .map_err(|error| format!("cannot pin verified server {}: {error}", server.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o755 {
        return Err("pinned getaip-server is not a regular 0755 executable".to_owned());
    }
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest)
        .map_err(|error| format!("cannot hash pinned getaip-server: {error}"))?;
    let actual = hex::encode(digest.finalize());
    if actual != expected_sha256 {
        return Err(format!(
            "pinned getaip-server digest mismatch: expected {expected_sha256}, received {actual}"
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind pinned getaip-server: {error}"))?;
    #[cfg(target_os = "linux")]
    let (execution_path, cleanup_path) = {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        use std::os::fd::AsRawFd;

        let descriptor = file.as_raw_fd();
        let flags = fcntl(descriptor, FcntlArg::F_GETFD)
            .map(FdFlag::from_bits_truncate)
            .map_err(|error| format!("cannot inspect pinned server descriptor: {error}"))?;
        fcntl(
            descriptor,
            FcntlArg::F_SETFD(flags.difference(FdFlag::FD_CLOEXEC)),
        )
        .map_err(|error| format!("cannot retain pinned server descriptor: {error}"))?;
        (PathBuf::from(format!("/proc/self/fd/{descriptor}")), None)
    };
    #[cfg(target_os = "macos")]
    let (execution_path, cleanup_path) = {
        let execution_path = copy_to_private_execution_path(&mut file, _execution_root)?;
        (execution_path.clone(), Some(execution_path))
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (execution_path, cleanup_path) = {
        return Err("pinned execution is unsupported on this Unix platform".to_owned());
    };
    Ok(PinnedExecutable {
        _file: file,
        execution_path,
        cleanup_path,
    })
}

#[cfg(target_os = "macos")]
fn copy_to_private_execution_path(
    source: &mut fs::File,
    execution_root: &Path,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let directory = execution_root.join("executables");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("private execution root is not a real directory".to_owned());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    cleanup_stale_execution_files(&directory)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = directory.join(format!(
        "getaip-server-{}-{nonce}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&path)
        .map_err(|error| error.to_string())?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    if let Err(error) = io::copy(source, &mut destination)
        .and_then(|_| destination.sync_all())
        .and_then(|_| fs::set_permissions(&path, fs::Permissions::from_mode(0o500)))
    {
        let _ = fs::remove_file(&path);
        return Err(format!("cannot create private pinned executable: {error}"));
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn cleanup_stale_execution_files(directory: &Path) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("getaip-server-") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("unsafe file in private GetAIP execution directory".to_owned());
        }
        fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[derive(Debug)]
struct PinnedExecutable;

#[cfg(not(unix))]
impl PinnedExecutable {
    fn execution_path(&self) -> &Path {
        Path::new("")
    }
}

#[cfg(not(unix))]
fn pin_verified_server(
    _server: &Path,
    _installation: &VerifiedInstallation,
    _execution_root: &Path,
) -> Result<PinnedExecutable, String> {
    Err("foreground execution is not qualified on this platform".to_owned())
}

pub(crate) async fn upgrade(arguments: UpgradeArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    validate_existing_config(&roots)?;
    let installer = Installer::new(roots.clone());
    let installed = installer
        .verify_active_installation()
        .map_err(|error| error.to_string())?;
    let trust_store = default_trust_store().map_err(|error| error.to_string())?;
    let requested_version = arguments
        .version
        .as_deref()
        .unwrap_or(GETAIP_SOFTWARE_VERSION);
    let verified = match (
        arguments.manifest.as_deref(),
        arguments.signature.as_deref(),
    ) {
        (Some(manifest), Some(signature)) => {
            let manifest_bytes =
                read_bounded_regular_file(manifest, MAX_MANIFEST_BYTES, "distribution manifest")?;
            let signature_bytes =
                read_bounded_regular_file(signature, MAX_SIGNATURE_BYTES, "manifest signature")?;
            verify_signed_manifest(&manifest_bytes, &signature_bytes, &trust_store)
                .map_err(|error| error.to_string())?
        }
        (None, None) => ReleaseClient::new()
            .map_err(|error| error.to_string())?
            .fetch_signed_manifest(requested_version, &trust_store)
            .await
            .map_err(|error| error.to_string())?,
        _ => return Err("pass --manifest and --signature together".to_owned()),
    };
    validate_upgrade_compatibility(&verified, &installed, platform)?;
    let plan = installer
        .plan(&verified, platform)
        .map_err(|error| error.to_string())?;
    let target_server = roots
        .version_dir(&plan.target_version)
        .join("bin/getaip-server");
    let adapter_plan = adapters::refresh_owned(&roots, &target_server, true)?;
    let service_plan = service::refresh_if_managed(
        platform,
        &roots,
        arguments.test_root.is_some(),
        &target_server,
        true,
    )?;
    if arguments.dry_run {
        return match arguments.output {
            OutputFormat::Json => print_json(&serde_json::json!({
                "schema": "org.getaip.cli.upgrade-plan.v1",
                "installation": plan,
                "client_adapters": adapter_plan,
                "service": service_plan,
            })),
            OutputFormat::Text => {
                println!(
                    "GetAIP upgrade plan: {:?} {} -> {}",
                    plan.action,
                    plan.current_version.as_deref().unwrap_or("none"),
                    plan.target_version
                );
                for item in adapter_plan.into_iter().chain(service_plan) {
                    println!("integration: {item}");
                }
                println!("dry-run: no filesystem changes were made");
                Ok(())
            }
        };
    }
    let target = verified
        .manifest
        .target(platform)
        .map_err(|error| error.to_string())?;
    let archive_path = acquire_distribution_archive(
        &installer,
        &target.distribution_archive,
        arguments.artifact.as_deref(),
    )
    .await?;
    let outcome = installer
        .install_archive(&verified, platform, &archive_path)
        .map_err(|error| error.to_string())?;
    let configured_clients = match adapters::refresh_owned(&roots, &target_server, false) {
        Ok(configured) => configured,
        Err(error) => {
            let recovery = recover_previous_integrations(
                &installer,
                &roots,
                platform,
                arguments.test_root.is_some(),
                &installed.active.version,
            );
            return Err(format!(
                "client adapter refresh failed after upgrade: {error}; recovery: {recovery}"
            ));
        }
    };
    let refreshed_service = match service::refresh_if_managed(
        platform,
        &roots,
        arguments.test_root.is_some(),
        &target_server,
        false,
    ) {
        Ok(refreshed) => refreshed,
        Err(error) => {
            let recovery = recover_previous_integrations(
                &installer,
                &roots,
                platform,
                arguments.test_root.is_some(),
                &installed.active.version,
            );
            return Err(format!(
                "service refresh failed after upgrade: {error}; recovery: {recovery}"
            ));
        }
    };
    match arguments.output {
        OutputFormat::Json => print_json(&serde_json::json!({
            "schema": "org.getaip.cli.upgrade-outcome.v1",
            "installation": outcome,
            "client_adapters": configured_clients,
            "service": refreshed_service,
        })),
        OutputFormat::Text => {
            println!(
                "GetAIP {} is active; rollback retained: {}",
                outcome.active_version,
                outcome.rollback_version.as_deref().unwrap_or("none")
            );
            for item in configured_clients.into_iter().chain(refreshed_service) {
                println!("integration: {item}");
            }
            Ok(())
        }
    }
}

pub(crate) fn rollback(arguments: RollbackArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    let installer = Installer::new(roots.clone());
    let preview = installer
        .rollback(true)
        .map_err(|error| error.to_string())?;
    let target_version = preview
        .active_version
        .as_deref()
        .ok_or_else(|| "rollback preview did not identify a target version".to_owned())?;
    let target_server = roots.version_dir(target_version).join("bin/getaip-server");
    let adapter_plan = adapters::refresh_owned(&roots, &target_server, true)?;
    let service_plan = service::refresh_if_managed(
        platform,
        &roots,
        arguments.test_root.is_some(),
        &target_server,
        true,
    )?;
    if arguments.dry_run {
        return match arguments.output {
            OutputFormat::Json => print_json(&serde_json::json!({
                "schema": "org.getaip.cli.rollback-plan.v1",
                "installation": preview,
                "client_adapters": adapter_plan,
                "service": service_plan,
            })),
            OutputFormat::Text => {
                println!(
                    "GetAIP rollback dry-run: {} -> {}",
                    preview.previous_active_version.as_deref().unwrap_or("none"),
                    preview.active_version.as_deref().unwrap_or("none")
                );
                for item in adapter_plan.into_iter().chain(service_plan) {
                    println!("integration: {item}");
                }
                println!("dry-run: no filesystem changes were made");
                Ok(())
            }
        };
    }
    let outcome = installer
        .rollback(false)
        .map_err(|error| error.to_string())?;
    let previous_active = outcome
        .previous_active_version
        .clone()
        .ok_or_else(|| "rollback outcome omitted the previous active version".to_owned())?;
    let configured_clients = match adapters::refresh_owned(&roots, &target_server, false) {
        Ok(configured) => configured,
        Err(error) => {
            let recovery = recover_previous_integrations(
                &installer,
                &roots,
                platform,
                arguments.test_root.is_some(),
                &previous_active,
            );
            return Err(format!(
                "client adapter refresh failed after rollback: {error}; recovery: {recovery}"
            ));
        }
    };
    let refreshed_service = match service::refresh_if_managed(
        platform,
        &roots,
        arguments.test_root.is_some(),
        &target_server,
        false,
    ) {
        Ok(refreshed) => refreshed,
        Err(error) => {
            let recovery = recover_previous_integrations(
                &installer,
                &roots,
                platform,
                arguments.test_root.is_some(),
                &previous_active,
            );
            return Err(format!(
                "service refresh failed after rollback: {error}; recovery: {recovery}"
            ));
        }
    };
    match arguments.output {
        OutputFormat::Json => print_json(&serde_json::json!({
            "schema": "org.getaip.cli.rollback-outcome.v1",
            "installation": outcome,
            "client_adapters": configured_clients,
            "service": refreshed_service,
        })),
        OutputFormat::Text => {
            println!(
                "GetAIP rollback: {} -> {}",
                outcome.previous_active_version.as_deref().unwrap_or("none"),
                outcome.active_version.as_deref().unwrap_or("none")
            );
            for item in configured_clients.into_iter().chain(refreshed_service) {
                println!("integration: {item}");
            }
            Ok(())
        }
    }
}

pub(crate) fn uninstall(arguments: UninstallArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = resolve_roots(platform, arguments.test_root.as_deref())?;
    let installer = Installer::new(roots.clone());
    let client_plan = adapters::remove_owned(&roots, true)?;
    let service_plan =
        service::uninstall_if_managed(platform, &roots, arguments.test_root.is_some(), true)?;
    if arguments.dry_run {
        let outcome = installer
            .uninstall(true, arguments.purge_user_data)
            .map_err(|error| error.to_string())?;
        return match arguments.output {
            OutputFormat::Json => print_json(&serde_json::json!({
                "schema": "org.getaip.cli.uninstall-plan.v1",
                "installation": outcome,
                "client_adapters": client_plan,
                "service": service_plan,
            })),
            OutputFormat::Text => {
                println!("GetAIP uninstall dry-run");
                for item in client_plan.into_iter().chain(service_plan) {
                    println!("remove: {item}");
                }
                println!("dry-run: no filesystem changes were made");
                Ok(())
            }
        };
    }
    let removed_clients = adapters::remove_owned(&roots, false)?;
    let removed_service =
        service::uninstall_if_managed(platform, &roots, arguments.test_root.is_some(), false)?;
    let outcome = installer
        .uninstall(false, arguments.purge_user_data)
        .map_err(|error| error.to_string())?;
    match arguments.output {
        OutputFormat::Json => print_json(&serde_json::json!({
            "schema": "org.getaip.cli.uninstall-outcome.v1",
            "installation": outcome,
            "client_adapters": removed_clients,
            "service": removed_service,
        })),
        OutputFormat::Text => {
            println!(
                "GetAIP uninstalled{}; user data {}",
                if arguments.purge_user_data {
                    " with purge"
                } else {
                    ""
                },
                if outcome.user_data_preserved {
                    "preserved"
                } else {
                    "removed"
                }
            );
            for item in removed_clients.into_iter().chain(removed_service) {
                println!("removed: {item}");
            }
            Ok(())
        }
    }
}

async fn acquire_distribution_archive(
    installer: &Installer,
    artifact: &Artifact,
    qualification_artifact: Option<&Path>,
) -> Result<PathBuf, String> {
    if let Some(path) = qualification_artifact {
        return Ok(path.to_path_buf());
    }
    let downloads = installer
        .prepare_download_cache()
        .map_err(|error| error.to_string())?;
    let archive_path = downloads.join(&artifact.name);
    ReleaseClient::new()
        .map_err(|error| error.to_string())?
        .download_artifact(artifact, &archive_path)
        .await
        .map_err(|error| error.to_string())?;
    Ok(archive_path)
}

fn recover_previous_integrations(
    installer: &Installer,
    roots: &InstallRoots,
    platform: Platform,
    isolated: bool,
    previous_version: &str,
) -> String {
    let mut failures = Vec::new();
    if let Err(error) = installer.rollback(false) {
        failures.push(format!("activation rollback failed: {error}"));
    }
    let previous_server = roots
        .version_dir(previous_version)
        .join("bin/getaip-server");
    if let Err(error) = adapters::refresh_owned(roots, &previous_server, false) {
        failures.push(format!("client adapter restore failed: {error}"));
    }
    if let Err(error) =
        service::refresh_if_managed(platform, roots, isolated, &previous_server, false)
    {
        failures.push(format!("service restore failed: {error}"));
    }
    if failures.is_empty() {
        "previous verified release restored".to_owned()
    } else {
        failures.join("; ")
    }
}

pub(crate) fn resolve_roots(
    platform: Platform,
    test_root: Option<&Path>,
) -> Result<InstallRoots, String> {
    match test_root {
        Some(root) => InstallRoots::under_test_root(root),
        None => InstallRoots::for_current_user(platform),
    }
    .map_err(|error| error.to_string())
}

fn validate_existing_config(roots: &InstallRoots) -> Result<(), String> {
    if roots.configuration().exists() {
        let config: ProductConfig =
            read_json_file(&roots.configuration()).map_err(|error| error.to_string())?;
        config.validate()?;
    }
    Ok(())
}

fn ensure_default_config(installer: &Installer) -> Result<(), String> {
    let path = installer.roots().configuration();
    if path.exists() {
        let config: ProductConfig = read_json_file(&path).map_err(|error| error.to_string())?;
        return config.validate();
    }
    let config = ProductConfig::default();
    config.validate()?;
    atomic_write_json(&path, &config).map_err(|error| error.to_string())
}

fn load_product_config(roots: &InstallRoots) -> Result<Option<ProductConfig>, String> {
    let path = roots.configuration();
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let config: ProductConfig = read_json_file(&path).map_err(|error| error.to_string())?;
            config.validate()?;
            Ok(Some(config))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect GetAIP configuration: {error}")),
    }
}

async fn probe_readiness(bind: SocketAddr) -> bool {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    let url = format!("http://{bind}/ready");
    match client.get(url).send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

fn check_secret_file_permissions() -> DiagnosticCheck {
    let configured: Vec<_> = SECRET_FILE_ENVIRONMENTS
        .iter()
        .filter_map(|name| env::var_os(name).map(|path| (*name, PathBuf::from(path))))
        .collect();
    check_configured_secret_file_permissions(configured)
}

fn check_service_configuration(
    platform: Platform,
    roots: &InstallRoots,
    isolated: bool,
) -> DiagnosticCheck {
    match service::diagnostic_summary(platform, roots, isolated) {
        Ok(explanation) => DiagnosticCheck {
            id: "service.configuration",
            status: CheckStatus::Pass,
            explanation,
            remediation: None,
        },
        Err(error) => DiagnosticCheck {
            id: "service.configuration",
            status: CheckStatus::Fail,
            explanation: error,
            remediation: Some(
                "repair service.env and run getaip service install to refresh the owned definition"
                    .to_owned(),
            ),
        },
    }
}

fn check_configured_secret_file_permissions(
    configured: Vec<(&'static str, PathBuf)>,
) -> DiagnosticCheck {
    if configured.is_empty() {
        return DiagnosticCheck {
            id: "secrets.permissions",
            status: CheckStatus::Pass,
            explanation: "no optional secret-file environment variables are configured".to_owned(),
            remediation: None,
        };
    }
    let mut failures = Vec::new();
    for (name, path) in configured {
        match secret_file_is_private(&path) {
            Ok(true) => {}
            Ok(false) => failures.push(format!("{name} is not owner-only")),
            Err(error) => failures.push(format!("{name} cannot be inspected: {error}")),
        }
    }
    if failures.is_empty() {
        DiagnosticCheck {
            id: "secrets.permissions",
            status: CheckStatus::Pass,
            explanation: "configured secret files are regular and owner-only".to_owned(),
            remediation: None,
        }
    } else {
        DiagnosticCheck {
            id: "secrets.permissions",
            status: CheckStatus::Fail,
            explanation: failures.join("; "),
            remediation: Some(
                "use a regular owner-owned file with mode 0600; no secret value was read"
                    .to_owned(),
            ),
        }
    }
}

#[cfg(unix)]
pub(crate) fn secret_file_is_private(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    Ok(metadata.permissions().mode() & 0o077 == 0
        && metadata.uid() == nix::unistd::Uid::effective().as_raw())
}

fn check_optional_database_configuration(roots: &InstallRoots) -> DiagnosticCheck {
    let inline = env::var_os("GETAIP_SERVER_POSTGRES_URL");
    let file = env::var_os("GETAIP_SERVER_POSTGRES_URL_FILE");
    match (inline, file) {
        (Some(_), Some(_)) => DiagnosticCheck {
            id: "database.configuration",
            status: CheckStatus::Fail,
            explanation: "PostgreSQL URL and URL file are mutually exclusive".to_owned(),
            remediation: Some("configure exactly one PostgreSQL URL source".to_owned()),
        },
        (Some(value), None) => match value.into_string() {
            Ok(value) if !value.trim().is_empty() => DiagnosticCheck {
                id: "database.configuration",
                status: CheckStatus::Pass,
                explanation: "optional PostgreSQL runtime configuration is present".to_owned(),
                remediation: None,
            },
            Ok(_) => DiagnosticCheck {
                id: "database.configuration",
                status: CheckStatus::Fail,
                explanation: "PostgreSQL URL is empty".to_owned(),
                remediation: Some("configure a non-empty PostgreSQL URL".to_owned()),
            },
            Err(_) => DiagnosticCheck {
                id: "database.configuration",
                status: CheckStatus::Fail,
                explanation: "PostgreSQL URL is not valid UTF-8".to_owned(),
                remediation: Some("configure a valid PostgreSQL URL".to_owned()),
            },
        },
        (None, Some(_)) => DiagnosticCheck {
            id: "database.configuration",
            status: CheckStatus::Pass,
            explanation: "optional PostgreSQL runtime configuration is present".to_owned(),
            remediation: None,
        },
        (None, None) => match service::environment_file_reference(
            roots,
            "GETAIP_SERVER_POSTGRES_URL_FILE",
        ) {
            Ok(Some(_)) => DiagnosticCheck {
                id: "database.configuration",
                status: CheckStatus::Pass,
                explanation: "optional PostgreSQL service configuration is present".to_owned(),
                remediation: None,
            },
            Ok(None) => DiagnosticCheck {
                id: "database.configuration",
                status: CheckStatus::Warn,
                explanation:
                    "optional PostgreSQL runtime is not configured; local storage remains available"
                        .to_owned(),
                remediation: None,
            },
            Err(error) => DiagnosticCheck {
                id: "database.configuration",
                status: CheckStatus::Fail,
                explanation: error,
                remediation: Some("repair the reviewed service.env file".to_owned()),
            },
        },
    }
}

fn check_version_compatibility(installation: Option<&VerifiedInstallation>) -> DiagnosticCheck {
    let Some(installation) = installation else {
        return DiagnosticCheck {
            id: "versions.compatible",
            status: CheckStatus::Fail,
            explanation:
                "CLI/server compatibility cannot be established without a verified installation"
                    .to_owned(),
            remediation: Some(
                "run getaip setup to install or repair the signed distribution".to_owned(),
            ),
        };
    };
    let result = (|| {
        let release = &installation.release.manifest.release;
        let target = installation
            .release
            .manifest
            .target(installation.state.platform)
            .map_err(|error| error.to_string())?;
        let expected = GETAIP_SOFTWARE_VERSION;
        for (label, actual) in [
            ("active pointer", installation.active.version.as_str()),
            (
                "install state",
                installation.state.software_version.as_str(),
            ),
            ("signed release", release.version.as_str()),
            ("target CLI", target.cli_version.as_str()),
            ("target server", target.server_version.as_str()),
        ] {
            if actual != expected {
                return Err(format!(
                    "{label} version {actual} does not match GetAIP CLI {expected}"
                ));
            }
        }
        for (label, actual) in [
            (
                "install state",
                installation.state.aip_protocol_version.as_str(),
            ),
            ("signed release", release.aip_protocol_version.as_str()),
        ] {
            if actual != AIP_PROTOCOL_VERSION {
                return Err(format!(
                    "{label} AIP protocol version {actual} does not match {AIP_PROTOCOL_VERSION}"
                ));
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => DiagnosticCheck {
            id: "versions.compatible",
            status: CheckStatus::Pass,
            explanation: format!(
                "CLI and server are compatible at GetAIP {GETAIP_SOFTWARE_VERSION}; AIP protocol remains {AIP_PROTOCOL_VERSION}"
            ),
            remediation: None,
        },
        Err(error) => DiagnosticCheck {
            id: "versions.compatible",
            status: CheckStatus::Fail,
            explanation: error,
            remediation: Some(
                "run the matching signed GetAIP bootstrap or repair the installation".to_owned(),
            ),
        },
    }
}

fn check_connector_registry_configuration(roots: &InstallRoots) -> DiagnosticCheck {
    match connector_registry_url(roots) {
        Ok(Some(_)) => DiagnosticCheck {
            id: "connector_registry.configuration",
            status: CheckStatus::Pass,
            explanation: "optional connector-registry data-plane configuration is present"
                .to_owned(),
            remediation: None,
        },
        Ok(None) => DiagnosticCheck {
            id: "connector_registry.configuration",
            status: CheckStatus::Warn,
            explanation: "optional connector registry is not configured".to_owned(),
            remediation: None,
        },
        Err(error) => DiagnosticCheck {
            id: "connector_registry.configuration",
            status: CheckStatus::Fail,
            explanation: error,
            remediation: Some(
                "configure exactly one owner-only connector-registry URL source".to_owned(),
            ),
        },
    }
}

fn check_managed_clients(
    roots: &InstallRoots,
    installation: Option<&VerifiedInstallation>,
) -> DiagnosticCheck {
    let path = roots.managed_clients();
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let Some(installation) = installation else {
                return DiagnosticCheck {
                    id: "mcp.clients",
                    status: CheckStatus::Fail,
                    explanation:
                        "managed MCP clients cannot be verified without an active installation"
                            .to_owned(),
                    remediation: Some("repair the signed GetAIP installation".to_owned()),
                };
            };
            let server = roots
                .version_dir(&installation.active.version)
                .join("bin/getaip-server");
            match adapters::verify_managed(roots, &server) {
                Ok((entries, owned)) => DiagnosticCheck {
                    id: "mcp.clients",
                    status: CheckStatus::Pass,
                    explanation: format!(
                        "{entries} managed MCP client entries are valid; {owned} remain GetAIP-owned"
                    ),
                    remediation: None,
                },
                Err(error) => DiagnosticCheck {
                    id: "mcp.clients",
                    status: CheckStatus::Fail,
                    explanation: error,
                    remediation: Some(
                        "repair the affected client configuration or restore its GetAIP backup"
                            .to_owned(),
                    ),
                },
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => DiagnosticCheck {
            id: "mcp.clients",
            status: CheckStatus::Warn,
            explanation: "no MCP client has been configured by GetAIP".to_owned(),
            remediation: Some("run getaip setup with an explicit client adapter".to_owned()),
        },
        Err(error) => DiagnosticCheck {
            id: "mcp.clients",
            status: CheckStatus::Fail,
            explanation: format!("cannot inspect managed MCP clients: {error}"),
            remediation: None,
        },
    }
}

fn check_update_availability(installation: Option<&VerifiedInstallation>) -> DiagnosticCheck {
    let Some(installation) = installation else {
        return DiagnosticCheck {
            id: "lifecycle.update",
            status: CheckStatus::Warn,
            explanation: "update availability is not applicable until GetAIP is installed"
                .to_owned(),
            remediation: Some("run getaip setup".to_owned()),
        };
    };
    let installed = match Version::parse(&installation.active.version) {
        Ok(version) => version,
        Err(error) => {
            return DiagnosticCheck {
                id: "lifecycle.update",
                status: CheckStatus::Fail,
                explanation: format!("installed version is invalid: {error}"),
                remediation: Some("repair the signed GetAIP installation".to_owned()),
            };
        }
    };
    let bootstrap = match Version::parse(GETAIP_SOFTWARE_VERSION) {
        Ok(version) => version,
        Err(error) => {
            return DiagnosticCheck {
                id: "lifecycle.update",
                status: CheckStatus::Fail,
                explanation: format!("compiled CLI version is invalid: {error}"),
                remediation: Some("replace the CLI with an official signed release".to_owned()),
            };
        }
    };
    match classify_update_versions(&installed, &bootstrap) {
        "newer_signed_bootstrap_available" => DiagnosticCheck {
            id: "lifecycle.update",
            status: CheckStatus::Warn,
            explanation: format!(
                "signed bootstrap release {bootstrap} is newer than installed release {installed}"
            ),
            remediation: Some("run getaip upgrade with the matching signed release".to_owned()),
        },
        "current_for_signed_bootstrap" => DiagnosticCheck {
            id: "lifecycle.update",
            status: CheckStatus::Pass,
            explanation: format!(
                "installed release {installed} is current for this signed GetAIP CLI"
            ),
            remediation: None,
        },
        _ => DiagnosticCheck {
            id: "lifecycle.update",
            status: CheckStatus::Fail,
            explanation: format!(
                "installed release {installed} is newer than CLI release {bootstrap}"
            ),
            remediation: Some("use the CLI shipped with the active signed release".to_owned()),
        },
    }
}

fn classify_update_versions(installed: &Version, bootstrap: &Version) -> &'static str {
    if installed < bootstrap {
        "newer_signed_bootstrap_available"
    } else if installed == bootstrap {
        "current_for_signed_bootstrap"
    } else {
        "matching_cli_required"
    }
}

fn status_update_state(
    installation: Option<&VerifiedInstallation>,
    requested: bool,
) -> &'static str {
    if !requested {
        return "not_checked";
    }
    let Some(installation) = installation else {
        return "not_installed";
    };
    let Ok(installed) = Version::parse(&installation.active.version) else {
        return "invalid_installation_version";
    };
    let Ok(bootstrap) = Version::parse(GETAIP_SOFTWARE_VERSION) else {
        return "invalid_cli_version";
    };
    classify_update_versions(&installed, &bootstrap)
}

fn check_rollback_state(
    installer: &Installer,
    installation: Option<&VerifiedInstallation>,
) -> DiagnosticCheck {
    if installation.is_none() {
        return DiagnosticCheck {
            id: "lifecycle.rollback",
            status: CheckStatus::Warn,
            explanation: "rollback is unavailable until GetAIP is installed".to_owned(),
            remediation: Some("run getaip setup".to_owned()),
        };
    }
    match installer.rollback(true) {
        Ok(outcome) => DiagnosticCheck {
            id: "lifecycle.rollback",
            status: CheckStatus::Pass,
            explanation: format!(
                "signed rollback candidate {} was fully reverified",
                outcome.active_version.as_deref().unwrap_or("unknown")
            ),
            remediation: None,
        },
        Err(InstallError::RollbackUnavailable) => DiagnosticCheck {
            id: "lifecycle.rollback",
            status: CheckStatus::Warn,
            explanation: "this is the first installed version; no rollback candidate exists"
                .to_owned(),
            remediation: None,
        },
        Err(error) => DiagnosticCheck {
            id: "lifecycle.rollback",
            status: CheckStatus::Fail,
            explanation: format!("retained rollback candidate failed verification: {error}"),
            remediation: Some("run getaip setup to repair lifecycle metadata".to_owned()),
        },
    }
}

fn connector_registry_url(roots: &InstallRoots) -> Result<Option<String>, String> {
    let inline = env::var_os("GETAIP_SERVER_CONNECTOR_REGISTRY_URL");
    let file = match env::var_os("GETAIP_SERVER_CONNECTOR_REGISTRY_URL_FILE") {
        Some(path) => Some(PathBuf::from(path)),
        None if inline.is_none() => {
            service::environment_file_reference(roots, "GETAIP_SERVER_CONNECTOR_REGISTRY_URL_FILE")?
        }
        None => None,
    };
    match (inline, file) {
        (Some(_), Some(_)) => {
            Err("connector registry URL and URL file are mutually exclusive".to_owned())
        }
        (Some(value), None) => {
            let value = value
                .into_string()
                .map_err(|_| "connector registry URL is not valid UTF-8".to_owned())?;
            let value = value.trim();
            if value.is_empty() {
                return Err("connector registry URL is empty".to_owned());
            }
            Ok(Some(value.to_owned()))
        }
        (None, Some(path)) => {
            if !secret_file_is_private(&path)? {
                return Err(
                    "connector registry URL file must be regular, owner-owned, and mode 0600"
                        .to_owned(),
                );
            }
            let bytes = read_bounded_regular_file(
                &path,
                16 * 1024,
                "connector-registry PostgreSQL URL file",
            )?;
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| "connector registry URL file is not valid UTF-8".to_owned())?
                .trim();
            if value.is_empty() {
                return Err("connector registry URL file is empty".to_owned());
            }
            Ok(Some(value.to_owned()))
        }
        (None, None) => Ok(None),
    }
}

async fn probe_connector_registry(roots: &InstallRoots) -> &'static str {
    let url = match connector_registry_url(roots) {
        Ok(Some(url)) => url,
        Ok(None) => return "optional_not_configured",
        Err(_) => return "configured_invalid",
    };
    let limits = RegistryPoolLimits {
        control_max_connections: 1,
        data_max_connections: 1,
        acquire_timeout: Duration::from_secs(2),
    };
    match PostgresConnectorRegistry::connect_data_plane(&url, limits).await {
        Ok(_) => "reachable",
        Err(_) => "configured_unreachable",
    }
}

fn read_rollback_version(roots: &InstallRoots) -> Option<String> {
    read_json_file::<RollbackState>(&roots.rollback_state())
        .ok()
        .and_then(|state| {
            if state.validate().is_ok() {
                state.previous_version
            } else {
                None
            }
        })
}

fn verify_server_version(server: &Path, installation: &VerifiedInstallation) -> Result<(), String> {
    let output = ProcessCommand::new(server)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot execute verified server version probe: {error}"))?;
    if !output.status.success() {
        return Err("verified server version probe failed".to_owned());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "verified server version output is not UTF-8".to_owned())?;
    let expected = format!("getaip-server {}", installation.state.software_version);
    if stdout.trim() != expected {
        return Err(format!(
            "verified server reported an incompatible version; expected {expected}"
        ));
    }
    Ok(())
}

fn validate_forwarded_arguments(arguments: &[OsString]) -> Result<(), String> {
    for argument in arguments {
        let rendered = argument.to_string_lossy();
        if is_managed_server_argument(&rendered) {
            return Err(format!(
                "{} is managed by getaip serve and must not be repeated after --",
                rendered
            ));
        }
    }
    Ok(())
}

fn validate_string_forwarded_arguments(arguments: &[String]) -> Result<(), String> {
    if let Some(argument) = arguments
        .iter()
        .find(|argument| is_managed_server_argument(argument))
    {
        return Err(format!(
            "{argument} is managed by getaip serve and cannot be stored in config"
        ));
    }
    Ok(())
}

fn is_managed_server_argument(argument: &str) -> bool {
    ["--bind", "--mcp-stdio", "--storage-dir"]
        .iter()
        .any(|managed| argument == *managed || argument.starts_with(&format!("{managed}=")))
}

fn validate_bootstrap_compatibility(
    verified: &VerifiedManifest,
    platform: Platform,
) -> Result<(), String> {
    if verified.manifest.release.version != GETAIP_SOFTWARE_VERSION {
        return Err(format!(
            "native bootstrap {} refuses release {}; use the matching bootstrap",
            GETAIP_SOFTWARE_VERSION, verified.manifest.release.version
        ));
    }
    let current = Version::parse(GETAIP_SOFTWARE_VERSION)
        .map_err(|error| format!("compiled GetAIP version is invalid: {error}"))?;
    let minimum = Version::parse(&verified.manifest.release.minimum_cli_version)
        .map_err(|error| format!("manifest minimum CLI version is invalid: {error}"))?;
    if current < minimum {
        return Err(format!(
            "release requires getaip {minimum} or newer; current bootstrap is {current}"
        ));
    }
    verified
        .manifest
        .target(platform)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn validate_upgrade_compatibility(
    verified: &VerifiedManifest,
    installed: &VerifiedInstallation,
    platform: Platform,
) -> Result<(), String> {
    let target = Version::parse(&verified.manifest.release.version)
        .map_err(|error| format!("target GetAIP version is invalid: {error}"))?;
    let current = Version::parse(&installed.active.version)
        .map_err(|error| format!("installed GetAIP version is invalid: {error}"))?;
    validate_upgrade_direction(&target, &current)?;
    let bootstrap = Version::parse(GETAIP_SOFTWARE_VERSION)
        .map_err(|error| format!("compiled GetAIP version is invalid: {error}"))?;
    let minimum = Version::parse(&verified.manifest.release.minimum_cli_version)
        .map_err(|error| format!("manifest minimum CLI version is invalid: {error}"))?;
    if bootstrap < minimum {
        return Err(format!(
            "release requires getaip {minimum} or newer; current CLI is {bootstrap}"
        ));
    }
    verified
        .manifest
        .target(platform)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn validate_upgrade_direction(target: &Version, current: &Version) -> Result<(), String> {
    if target < current {
        return Err(format!(
            "refusing downgrade from {current} to {target}; use getaip rollback with retained signed evidence"
        ));
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot read {label} metadata: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    if metadata.len() > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .map_err(|error| format!("cannot open {label}: {error}"))?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if bytes.len() as u64 > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    #[test]
    #[cfg(unix)]
    fn pinned_executable_survives_path_replacement_and_rejects_symlink() {
        let temporary = tempdir().expect("tempdir");
        let server = temporary.path().join("getaip-server");
        fs::copy(std::env::current_exe().expect("test executable"), &server)
            .expect("copy executable");
        fs::set_permissions(&server, fs::Permissions::from_mode(0o755)).expect("permissions");
        let original = fs::read(&server).expect("read executable");
        let digest = hex::encode(Sha256::digest(&original));
        let pinned = pin_server_file(&server, &digest, temporary.path()).expect("pin executable");

        let moved = temporary.path().join("original-server");
        fs::rename(&server, &moved).expect("move original");
        fs::copy("/usr/bin/false", &server).expect("replace path");
        fs::set_permissions(&server, fs::Permissions::from_mode(0o755)).expect("permissions");
        let output = ProcessCommand::new(pinned.execution_path())
            .arg("--list")
            .output()
            .expect("execute pinned file descriptor");
        assert!(
            output.status.success(),
            "status {:?}, stderr {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8(output.stdout)
                .expect("UTF-8")
                .contains("pinned_executable_survives_path_replacement")
        );

        let link = temporary.path().join("server-link");
        symlink(&server, &link).expect("symlink");
        let error =
            pin_server_file(&link, &digest, temporary.path()).expect_err("symlink must fail");
        assert!(error.contains("cannot pin verified server"));
    }

    #[test]
    fn downgrade_is_rejected_outside_the_signed_rollback_flow() {
        let current = Version::parse("2.1.0").expect("current version");
        let target = Version::parse("2.0.0").expect("target version");
        let error = validate_upgrade_direction(&target, &current)
            .expect_err("ordinary upgrade must reject downgrade");
        assert!(error.contains("refusing downgrade from 2.1.0 to 2.0.0"));
        assert!(error.contains("getaip rollback"));
        assert!(validate_upgrade_direction(&current, &current).is_ok());
    }

    #[test]
    fn update_status_is_explicit_and_version_ordered() {
        let old = Version::parse("2.0.0").expect("old version");
        let current = Version::parse("2.1.0").expect("current version");
        let future = Version::parse("2.2.0").expect("future version");
        assert_eq!(
            classify_update_versions(&old, &current),
            "newer_signed_bootstrap_available"
        );
        assert_eq!(
            classify_update_versions(&current, &current),
            "current_for_signed_bootstrap"
        );
        assert_eq!(
            classify_update_versions(&future, &current),
            "matching_cli_required"
        );
        assert_eq!(status_update_state(None, false), "not_checked");
        assert_eq!(status_update_state(None, true), "not_installed");
    }

    #[test]
    fn diagnostic_secret_inventory_covers_server_credentials_not_public_material() {
        for required in [
            "GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE",
            "GETAIP_SERVER_NATS_PASSWORD_FILE",
            "GETAIP_SERVER_CALLBACK_SIGNING_SEED_FILE",
            "GETAIP_SERVER_CONNECTOR_FLEET_SIGNING_SEED_FILE",
            "GETAIP_SERVER_MCP_INTROSPECTION_CLIENT_SECRET_FILE",
            "GETAIP_SERVER_CONNECTOR_REGISTRY_URL_FILE",
            "GETAIP_SERVER_POSTGRES_URL_FILE",
        ] {
            assert!(SECRET_FILE_ENVIRONMENTS.contains(&required));
        }
        for public_material in [
            "GETAIP_NATIVE_TLS_CA_FILE",
            "GETAIP_SERVER_CONNECTOR_FLEET_TLS_CA_FILE",
            "GETAIP_SERVER_TRUSTED_IDENTITY_FILE",
            "GETAIP_SERVER_TRUSTED_SIGNER_FILE",
        ] {
            assert!(!SECRET_FILE_ENVIRONMENTS.contains(&public_material));
        }
    }

    #[test]
    #[cfg(unix)]
    fn diagnostics_never_include_secret_file_contents() {
        let temporary = tempdir().expect("tempdir");
        let secret = temporary.path().join("native-token");
        let sentinel = "GETAIP-SECRET-MUST-NOT-LEAK-2f91";
        fs::write(&secret, sentinel).expect("secret file");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("permissions");

        let check = check_configured_secret_file_permissions(vec![(
            "GETAIP_NATIVE_BEARER_TOKEN_FILE",
            secret,
        )]);
        assert_eq!(check.status, CheckStatus::Pass);
        let json = serde_json::to_string(&check).expect("diagnostic JSON");
        assert!(!json.contains(sentinel));
        assert!(!format!("{check:?}").contains(sentinel));
    }
}
