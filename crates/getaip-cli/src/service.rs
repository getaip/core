use clap::{Args, Subcommand};
use getaip_distribution::{
    InstallRoots, Installer, Platform, atomic_write_bytes, atomic_write_json, read_bounded_file,
    read_json_file, sha256_hex,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

const LAUNCHD_LABEL: &str = "org.getaip.server";
const SYSTEMD_UNIT: &str = "getaip-server.service";
const MANAGED_SERVICE_SCHEMA: &str = "org.getaip.managed-service.v1";
const MAX_SERVICE_ENVIRONMENT_BYTES: u64 = 64 * 1024;

type ServiceEnvironment = BTreeMap<String, String>;

/// Arguments for platform-native user service management.
#[derive(Clone, Debug, Args)]
pub(crate) struct ServiceArgs {
    /// Service lifecycle operation.
    #[command(subcommand)]
    command: ServiceCommand,
    /// Explicit isolated root used only for qualification and tests.
    #[arg(long, global = true, value_name = "ABSOLUTE_PATH", hide = true)]
    test_root: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum ServiceCommand {
    /// Create a user service definition without replacing a conflicting file.
    Install,
    /// Start the installed user service.
    Start,
    /// Stop the user service.
    Stop,
    /// Restart the user service.
    Restart,
    /// Print platform service-manager status.
    Status,
    /// Stop, unregister, and remove only the GetAIP-owned service definition.
    Uninstall,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    schema: String,
    bind: SocketAddr,
    server_arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedService {
    schema: String,
    platform: String,
    definition: PathBuf,
    definition_sha256: String,
}

pub(crate) fn run(arguments: ServiceArgs) -> Result<(), String> {
    let platform = Platform::detect().map_err(|error| error.to_string())?;
    let roots = super::product::resolve_roots(platform, arguments.test_root.as_deref())?;
    let isolated = arguments.test_root.is_some();
    match arguments.command {
        ServiceCommand::Install => install(platform, &roots, isolated),
        ServiceCommand::Uninstall => {
            let removed = uninstall_if_managed(platform, &roots, isolated, false)?;
            println!(
                "{}",
                removed
                    .first()
                    .map_or("GetAIP service was not installed", String::as_str)
            );
            Ok(())
        }
        command => manage(command, platform, &roots, isolated),
    }
}

/// Re-verifies the optional environment file and any owned service definition.
pub(crate) fn diagnostic_summary(
    platform: Platform,
    roots: &InstallRoots,
    isolated: bool,
) -> Result<String, String> {
    let environment = load_service_environment(roots)?;
    let Some(state) = load_managed_service(roots)? else {
        return Ok(format!(
            "no managed user service is installed; {} reviewed file reference(s) configured",
            environment.len()
        ));
    };
    let definition = definition_path(platform, roots, isolated)?;
    verify_managed_service(&state, platform, &definition)?;
    verify_owned_definition(&state)?;
    let (server, config) = verified_service_command(roots)?;
    let expected = render_definition(
        platform,
        &server,
        config.bind,
        &roots.state.join("runtime"),
        &environment,
    )?;
    if sha256_hex(expected.as_bytes()) != state.definition_sha256 {
        return Err(
            "managed service definition is stale relative to the active release, configuration, or service.env"
                .to_owned(),
        );
    }
    Ok(format!(
        "managed service definition and {} reviewed file reference(s) are valid",
        environment.len()
    ))
}

/// Resolves one reviewed service file reference without reading its contents.
pub(crate) fn environment_file_reference(
    roots: &InstallRoots,
    name: &str,
) -> Result<Option<PathBuf>, String> {
    if !valid_service_environment_name(name) {
        return Err("internal service environment lookup used an invalid name".to_owned());
    }
    Ok(load_service_environment(roots)?
        .get(name)
        .map(PathBuf::from))
}

/// Rewrites an already managed service to the currently active exact server.
pub(crate) fn refresh_if_managed(
    platform: Platform,
    roots: &InstallRoots,
    isolated: bool,
    server: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let Some(state) = load_managed_service(roots)? else {
        return Ok(Vec::new());
    };
    let definition = definition_path(platform, roots, isolated)?;
    verify_managed_service(&state, platform, &definition)?;
    let was_running = !isolated && manager_is_running(platform)?;
    if !dry_run {
        let metadata = fs::symlink_metadata(server).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("service server must be a verified regular file".to_owned());
        }
    }
    let config = load_service_config(roots)?;
    let environment = load_service_environment(roots)?;
    let document = render_definition(
        platform,
        server,
        config.bind,
        &roots.state.join("runtime"),
        &environment,
    )?;
    let summary = vec![format!(
        "refresh service definition {}",
        definition.display()
    )];
    if dry_run {
        verify_owned_definition(&state)?;
        return Ok(summary);
    }
    install_managed_definition(roots, platform, &definition, document.as_bytes())?;
    if !isolated {
        refresh_manager_definition(platform, &definition, was_running)?;
    }
    Ok(summary)
}

/// Removes only a definition whose path and digest match GetAIP ownership state.
pub(crate) fn uninstall_if_managed(
    platform: Platform,
    roots: &InstallRoots,
    isolated: bool,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let Some(state) = load_managed_service(roots)? else {
        return Ok(Vec::new());
    };
    let definition = definition_path(platform, roots, isolated)?;
    verify_managed_service(&state, platform, &definition)?;
    let original = verify_owned_definition(&state)?;
    let summary = vec![format!("remove managed service {}", definition.display())];
    if dry_run {
        return Ok(summary);
    }
    if !isolated {
        unregister_manager(platform)?;
    }
    remove_definition(&definition)?;
    if let Err(error) = remove_regular_file(&roots.managed_service()) {
        let _ = atomic_write_bytes(&definition, &original);
        return Err(format!(
            "failed to remove managed-service ownership state; definition restored: {error}"
        ));
    }
    if !isolated {
        reload_manager(platform)?;
    }
    Ok(summary)
}

fn install(platform: Platform, roots: &InstallRoots, isolated: bool) -> Result<(), String> {
    let definition = definition_path(platform, roots, isolated)?;
    let (server, config) = verified_service_command(roots)?;
    let environment = load_service_environment(roots)?;
    let document = render_definition(
        platform,
        &server,
        config.bind,
        &roots.state.join("runtime"),
        &environment,
    )?;
    install_managed_definition(roots, platform, &definition, document.as_bytes())?;
    if !isolated {
        register_manager(platform, &definition)?;
    }
    println!("installed GetAIP user service {}", definition.display());
    Ok(())
}

fn manage(
    command: ServiceCommand,
    platform: Platform,
    roots: &InstallRoots,
    isolated: bool,
) -> Result<(), String> {
    let definition = definition_path(platform, roots, isolated)?;
    let state = load_managed_service(roots)?
        .ok_or_else(|| "service is not installed; run getaip service install".to_owned())?;
    verify_managed_service(&state, platform, &definition)?;
    verify_owned_definition(&state)?;
    if isolated {
        println!("{}: managed definition installed", service_name(platform));
        return Ok(());
    }
    match command {
        ServiceCommand::Start => {
            start_manager(platform, &definition)?;
            println!("started {}", service_name(platform));
        }
        ServiceCommand::Stop => {
            stop_manager(platform)?;
            println!("stopped {}", service_name(platform));
        }
        ServiceCommand::Restart => {
            restart_manager(platform, &definition)?;
            println!("restarted {}", service_name(platform));
        }
        ServiceCommand::Status => status_manager(platform)?,
        ServiceCommand::Install | ServiceCommand::Uninstall => {
            return Err("invalid internal service dispatch".to_owned());
        }
    }
    Ok(())
}

fn verified_service_command(roots: &InstallRoots) -> Result<(PathBuf, ServiceConfig), String> {
    let installation = Installer::new(roots.clone())
        .verify_active_installation()
        .map_err(|error| error.to_string())?;
    let server = roots
        .version_dir(&installation.active.version)
        .join("bin/getaip-server");
    let config = load_service_config(roots)?;
    Ok((server, config))
}

fn load_service_config(roots: &InstallRoots) -> Result<ServiceConfig, String> {
    let config: ServiceConfig =
        read_json_file(&roots.configuration()).map_err(|error| error.to_string())?;
    if config.schema != "org.getaip.config.v1" {
        return Err(format!(
            "unsupported GetAIP config schema {}",
            config.schema
        ));
    }
    if !config.bind.ip().is_loopback() {
        return Err("user service configuration must use a loopback bind address".to_owned());
    }
    if !config.server_arguments.is_empty() {
        return Err(
            "service installation requires an empty server_arguments list; use a reviewed service environment file for advanced configuration"
                .to_owned(),
        );
    }
    Ok(config)
}

fn load_service_environment(roots: &InstallRoots) -> Result<ServiceEnvironment, String> {
    let path = roots.config.join("service.env");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ServiceEnvironment::new());
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect service environment file {}: {error}",
                path.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("service.env must be a regular non-symlink file".to_owned());
    }
    if metadata.len() > MAX_SERVICE_ENVIRONMENT_BYTES {
        return Err(format!(
            "service.env exceeds the {MAX_SERVICE_ENVIRONMENT_BYTES}-byte limit"
        ));
    }
    if !super::product::secret_file_is_private(&path)? {
        return Err("service.env must be owner-owned with mode 0600".to_owned());
    }
    let bytes = read_bounded_file(&path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_SERVICE_ENVIRONMENT_BYTES {
        return Err(format!(
            "service.env exceeds the {MAX_SERVICE_ENVIRONMENT_BYTES}-byte limit"
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "service.env must contain valid UTF-8".to_owned())?;
    let mut environment = ServiceEnvironment::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (raw_name, raw_value) = line.split_once('=').ok_or_else(|| {
            format!("service.env line {line_number} must use NAME=/absolute/path")
        })?;
        let name = raw_name.trim();
        let value = raw_value.trim();
        if !valid_service_environment_name(name) {
            return Err(format!(
                "service.env line {line_number} must name a GETAIP_SERVER_*_FILE variable"
            ));
        }
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(format!(
                "service.env line {line_number} contains an empty or unsafe file path"
            ));
        }
        let target = Path::new(value);
        if !target.is_absolute()
            || target
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(format!(
                "service.env line {line_number} file path must be absolute and normalized"
            ));
        }
        let target_metadata = fs::symlink_metadata(target).map_err(|error| {
            format!("service.env line {line_number} target cannot be inspected: {error}")
        })?;
        if target_metadata.file_type().is_symlink() || !target_metadata.is_file() {
            return Err(format!(
                "service.env line {line_number} target must be a regular non-symlink file"
            ));
        }
        if !super::product::secret_file_is_private(target)? {
            return Err(format!(
                "service.env line {line_number} target must be owner-owned with mode 0600"
            ));
        }
        if environment
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(format!(
                "service.env line {line_number} duplicates variable {name}"
            ));
        }
    }
    Ok(environment)
}

fn valid_service_environment_name(name: &str) -> bool {
    name.starts_with("GETAIP_SERVER_")
        && name.ends_with("_FILE")
        && name
            .bytes()
            .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == b'_')
}

fn definition_path(
    platform: Platform,
    roots: &InstallRoots,
    isolated: bool,
) -> Result<PathBuf, String> {
    if isolated {
        return Ok(match platform {
            Platform::DarwinArm64 | Platform::DarwinX64 => {
                roots.state.join("services/launchd/org.getaip.server.plist")
            }
            Platform::LinuxArm64 | Platform::LinuxX64 => {
                roots.state.join("services/systemd/getaip-server.service")
            }
        });
    }
    let home = home_directory()?;
    Ok(match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            home.join("Library/LaunchAgents/org.getaip.server.plist")
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            home.join(".config/systemd/user/getaip-server.service")
        }
    })
}

fn render_definition(
    platform: Platform,
    server: &Path,
    bind: SocketAddr,
    storage: &Path,
    environment: &ServiceEnvironment,
) -> Result<String, String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            render_launchd(server, bind, storage, environment)
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            render_systemd(server, bind, storage, environment)
        }
    }
}

fn install_managed_definition(
    roots: &InstallRoots,
    platform: Platform,
    path: &Path,
    contents: &[u8],
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("service definition has no parent: {}", path.display()))?;
    create_real_directory(parent)?;
    let prior_state = load_managed_service(roots)?;
    let original = match prior_state.as_ref() {
        Some(state) => {
            verify_managed_service(state, platform, path)?;
            Some(verify_owned_definition(state)?)
        }
        None => match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(format!(
                    "service definition {} already exists without GetAIP ownership state",
                    path.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        },
    };
    if original.as_deref() != Some(contents) {
        atomic_write_bytes(path, contents).map_err(|error| error.to_string())?;
    }
    let state = ManagedService {
        schema: MANAGED_SERVICE_SCHEMA.to_owned(),
        platform: platform.asset_label().to_owned(),
        definition: path.to_path_buf(),
        definition_sha256: sha256_hex(contents),
    };
    if let Err(error) = atomic_write_json(&roots.managed_service(), &state) {
        match original {
            Some(bytes) => {
                let _ = atomic_write_bytes(path, &bytes);
            }
            None => {
                let _ = remove_definition(path);
            }
        }
        return Err(format!(
            "failed to record managed-service ownership; definition restored: {error}"
        ));
    }
    Ok(())
}

fn load_managed_service(roots: &InstallRoots) -> Result<Option<ManagedService>, String> {
    match fs::symlink_metadata(roots.managed_service()) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("managed-service state must be a regular non-symlink file".to_owned());
            }
            let state: ManagedService =
                read_json_file(&roots.managed_service()).map_err(|error| error.to_string())?;
            if state.schema != MANAGED_SERVICE_SCHEMA {
                return Err(format!(
                    "unsupported managed-service schema {}",
                    state.schema
                ));
            }
            Ok(Some(state))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn verify_managed_service(
    state: &ManagedService,
    platform: Platform,
    expected_path: &Path,
) -> Result<(), String> {
    if state.platform != platform.asset_label() || state.definition != expected_path {
        return Err(
            "managed-service ownership state does not match this platform and path".to_owned(),
        );
    }
    Ok(())
}

fn verify_owned_definition(state: &ManagedService) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(&state.definition).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "managed service definition is unsafe: {}",
            state.definition.display()
        ));
    }
    let bytes = fs::read(&state.definition).map_err(|error| error.to_string())?;
    if sha256_hex(&bytes) != state.definition_sha256 {
        return Err(
            "managed service definition was changed by the user; refusing overwrite or removal"
                .to_owned(),
        );
    }
    Ok(bytes)
}

fn render_launchd(
    server: &Path,
    bind: SocketAddr,
    storage: &Path,
    environment: &ServiceEnvironment,
) -> Result<String, String> {
    let mut environment_xml = format!(
        "<key>GETAIP_SERVER_STORAGE_DIR</key><string>{}</string>",
        xml_escape(path_string(storage)?.as_str())
    );
    for (name, value) in environment {
        environment_xml.push_str(&format!(
            "\n    <key>{}</key><string>{}</string>",
            xml_escape(name),
            xml_escape(value)
        ));
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>--bind</string>\n    <string>{}</string>\n  </array>\n  <key>EnvironmentVariables</key>\n  <dict>\n    {}\n  </dict>\n  <key>RunAtLoad</key><false/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ThrottleInterval</key><integer>5</integer>\n  <key>ProcessType</key><string>Background</string>\n</dict>\n</plist>\n",
        LAUNCHD_LABEL,
        xml_escape(path_string(server)?.as_str()),
        xml_escape(&bind.to_string()),
        environment_xml
    ))
}

fn render_systemd(
    server: &Path,
    bind: SocketAddr,
    storage: &Path,
    environment: &ServiceEnvironment,
) -> Result<String, String> {
    let mut environment_lines = format!(
        "Environment=GETAIP_SERVER_STORAGE_DIR={}",
        systemd_escape_path(storage)?
    );
    for (name, value) in environment {
        environment_lines.push_str(&format!(
            "\nEnvironment={name}={}",
            systemd_escape_environment_value(value)?
        ));
    }
    Ok(format!(
        "[Unit]\nDescription=GetAIP server\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} --bind {}\n{}\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=default.target\n",
        systemd_escape_path(server)?,
        bind,
        environment_lines
    ))
}

fn register_manager(platform: Platform, definition: &Path) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            if !launchd_is_loaded()? {
                let domain = launchd_domain();
                let definition = path_string(definition)?;
                run_checked("launchctl", &["bootstrap", &domain, &definition])?;
            }
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            reload_manager(platform)?;
            run_checked("systemctl", &["--user", "enable", SYSTEMD_UNIT])?;
        }
    }
    Ok(())
}

fn unregister_manager(platform: Platform) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            if launchd_is_loaded()? {
                run_checked("launchctl", &["bootout", &launchd_service()])?;
            }
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            if command_success("systemctl", &["--user", "is-enabled", SYSTEMD_UNIT])? {
                run_checked("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT])?;
            }
        }
    }
    Ok(())
}

fn reload_manager(platform: Platform) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => Ok(()),
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            run_checked("systemctl", &["--user", "daemon-reload"])
        }
    }
}

fn manager_is_running(platform: Platform) -> Result<bool, String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => launchd_is_running(),
        Platform::LinuxArm64 | Platform::LinuxX64 => command_success(
            "systemctl",
            &["--user", "is-active", "--quiet", SYSTEMD_UNIT],
        ),
    }
}

fn start_manager(platform: Platform, definition: &Path) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            if !launchd_is_loaded()? {
                let definition = path_string(definition)?;
                run_checked("launchctl", &["bootstrap", &launchd_domain(), &definition])?;
            }
            run_checked("launchctl", &["kickstart", &launchd_service()])
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            run_checked("systemctl", &["--user", "start", SYSTEMD_UNIT])
        }
    }
}

fn stop_manager(platform: Platform) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            if launchd_is_loaded()? {
                run_checked("launchctl", &["bootout", &launchd_service()])?;
            }
            Ok(())
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            run_checked("systemctl", &["--user", "stop", SYSTEMD_UNIT])
        }
    }
}

fn restart_manager(platform: Platform, definition: &Path) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            if !launchd_is_loaded()? {
                let definition = path_string(definition)?;
                run_checked("launchctl", &["bootstrap", &launchd_domain(), &definition])?;
            }
            run_checked("launchctl", &["kickstart", "-k", &launchd_service()])
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            run_checked("systemctl", &["--user", "restart", SYSTEMD_UNIT])
        }
    }
}

fn refresh_manager_definition(
    platform: Platform,
    definition: &Path,
    was_running: bool,
) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            if launchd_is_loaded()? {
                run_checked("launchctl", &["bootout", &launchd_service()])?;
            }
            let definition = path_string(definition)?;
            run_checked("launchctl", &["bootstrap", &launchd_domain(), &definition])?;
            if was_running {
                run_checked("launchctl", &["kickstart", &launchd_service()])?;
            }
            Ok(())
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            reload_manager(platform)?;
            if was_running {
                restart_manager(platform, definition)?;
            }
            Ok(())
        }
    }
}

fn launchd_is_loaded() -> Result<bool, String> {
    command_success("launchctl", &["print", &launchd_service()])
}

fn launchd_is_running() -> Result<bool, String> {
    let output = Command::new("launchctl")
        .args(["print", &launchd_service()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("failed to execute launchctl: {error}"))?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(launchd_output_is_running(&output.stdout))
}

fn launchd_output_is_running(output: &[u8]) -> bool {
    String::from_utf8_lossy(output)
        .lines()
        .any(|line| line.trim() == "state = running")
}

fn status_manager(platform: Platform) -> Result<(), String> {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => {
            run_status("launchctl", &["print", &launchd_service()])
        }
        Platform::LinuxArm64 | Platform::LinuxX64 => {
            run_status("systemctl", &["--user", "status", SYSTEMD_UNIT])
        }
    }
}

fn launchd_domain() -> String {
    format!("gui/{}", nix::unistd::Uid::effective().as_raw())
}

fn launchd_service() -> String {
    format!("{}/{LAUNCHD_LABEL}", launchd_domain())
}

fn service_name(platform: Platform) -> &'static str {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => LAUNCHD_LABEL,
        Platform::LinuxArm64 | Platform::LinuxX64 => SYSTEMD_UNIT,
    }
}

fn remove_definition(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "refusing unsafe service definition {}",
            path.display()
        )),
        Ok(_) => fs::remove_file(path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn remove_regular_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(format!("refusing unsafe state file {}", path.display()))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn create_real_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("unsafe service directory {}", path.display()));
    }
    Ok(())
}

fn run_checked(program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to execute {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

fn command_success(program: &str, arguments: &[&str]) -> Result<bool, String> {
    Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|error| format!("failed to execute {program}: {error}"))
}

fn run_status(program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| format!("failed to execute {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

fn home_directory() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "cannot resolve current user home directory".to_owned())?;
    if !home.is_absolute() {
        return Err("current user home directory must be absolute".to_owned());
    }
    Ok(home)
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("service path is not UTF-8: {}", path.display()))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace(char::from(39_u8), "&apos;")
}

fn systemd_escape_path(path: &Path) -> Result<String, String> {
    let value = path_string(path)?;
    systemd_escape_environment_value(&value)
}

fn systemd_escape_environment_value(value: &str) -> Result<String, String> {
    if value.chars().any(char::is_control) {
        return Err("service environment value contains a control character".to_owned());
    }
    Ok(value
        .replace('\\', "\\x5c")
        .replace('%', "%%")
        .replace(' ', "\\x20")
        .replace('"', "\\x22"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn service_rendering_escapes_paths_without_a_shell() {
        let environment = ServiceEnvironment::from([(
            "GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE".to_owned(),
            "/opt/Get & AIP/secret%token".to_owned(),
        )]);
        let launchd = render_launchd(
            Path::new("/opt/Get & AIP/getaip-server"),
            SocketAddr::from(([127, 0, 0, 1], 18080)),
            Path::new("/opt/Get & AIP/state"),
            &environment,
        )
        .expect("launchd");
        assert!(launchd.contains("Get &amp; AIP"));
        assert!(launchd.contains("GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE"));
        assert!(launchd.contains("secret%token"));
        let systemd = render_systemd(
            Path::new("/home/a/Get AIP/getaip-server"),
            SocketAddr::from(([127, 0, 0, 1], 18080)),
            Path::new("/home/a/Get AIP/state"),
            &environment,
        )
        .expect("systemd");
        assert!(systemd.contains("Get\\x20AIP"));
        assert!(systemd.contains("secret%%token"));
        assert!(!systemd.contains("/bin/sh"));
        assert!(systemd.contains("NoNewPrivileges=true"));
    }

    #[test]
    #[cfg(unix)]
    fn service_environment_accepts_only_safe_file_references() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let secret = temporary.path().join("server token");
        let authority = temporary.path().join("trusted-identities.json");
        fs::write(&secret, b"secret").expect("secret");
        fs::write(&authority, b"{}").expect("authority");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("secret mode");
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).expect("authority mode");
        let environment_file = roots.config.join("service.env");
        fs::write(
            &environment_file,
            format!(
                "# file references only\nGETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE={}\nGETAIP_SERVER_TRUSTED_IDENTITY_FILE={}\n",
                secret.display(),
                authority.display()
            ),
        )
        .expect("environment file");
        fs::set_permissions(&environment_file, fs::Permissions::from_mode(0o600))
            .expect("environment mode");
        let environment = load_service_environment(&roots).expect("service environment");
        assert_eq!(environment.len(), 2);
        assert_eq!(
            environment.get("GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE"),
            Some(&secret.display().to_string())
        );
        assert_eq!(
            environment_file_reference(&roots, "GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE")
                .expect("file reference"),
            Some(secret.clone())
        );
        let diagnostic = diagnostic_summary(Platform::detect().expect("platform"), &roots, true)
            .expect("service diagnostic");
        assert!(diagnostic.contains("2 reviewed file reference(s)"));

        fs::set_permissions(&environment_file, fs::Permissions::from_mode(0o644))
            .expect("unsafe environment mode");
        let error = load_service_environment(&roots).expect_err("world-readable file must fail");
        assert!(error.contains("mode 0600"));

        fs::set_permissions(&environment_file, fs::Permissions::from_mode(0o600))
            .expect("restore environment mode");
        fs::write(
            &environment_file,
            "GETAIP_SERVER_NATIVE_BEARER_TOKEN=raw-secret\n",
        )
        .expect("unsafe raw secret");
        let error = load_service_environment(&roots).expect_err("raw secret must fail");
        assert!(error.contains("GETAIP_SERVER_*_FILE"));
    }

    #[test]
    fn launchd_state_parser_distinguishes_loaded_from_running() {
        assert!(launchd_output_is_running(
            b"org.getaip.server = {\n\tstate = running\n}\n"
        ));
        assert!(!launchd_output_is_running(
            b"org.getaip.server = {\n\tstate = exited\n}\n"
        ));
    }

    #[test]
    fn managed_definition_refuses_conflict_and_user_edit() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.state).expect("state");
        let definition = roots.state.join("services/systemd/getaip-server.service");
        fs::create_dir_all(definition.parent().expect("parent")).expect("service parent");
        fs::write(&definition, b"foreign").expect("foreign definition");
        let conflict =
            install_managed_definition(&roots, Platform::LinuxX64, &definition, b"managed")
                .expect_err("foreign definition must fail");
        assert!(conflict.contains("without GetAIP ownership"));
        fs::remove_file(&definition).expect("remove foreign");
        install_managed_definition(&roots, Platform::LinuxX64, &definition, b"managed")
            .expect("managed definition");
        fs::write(&definition, b"user edit").expect("user edit");
        let error =
            install_managed_definition(&roots, Platform::LinuxX64, &definition, b"new managed")
                .expect_err("edited managed definition must fail");
        assert!(error.contains("changed by the user"));
    }
}
