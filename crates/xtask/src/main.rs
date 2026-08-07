//! Workspace task runner.

#![forbid(unsafe_code)]

mod native_release;

use clap::{Parser, Subcommand};
use semver::Version;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

const SEMVER_TARGET_DIR: &str = "target/semver-checks";
const SEMVER_MIN_FREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const SOURCE_SNAPSHOT_PATH: &str = "SOURCE_SNAPSHOT.json";

/// Xtask CLI.
#[derive(Debug, Parser)]
#[command(name = "xtask", about = "AIP workspace automation")]
struct Cli {
    /// Task to run.
    #[command(subcommand)]
    command: Task,
}

/// Supported workspace tasks.
#[derive(Debug, Subcommand)]
enum Task {
    /// Run rustfmt.
    Fmt,
    /// Run clippy.
    Lint,
    /// Run tests.
    Test,
    /// Export JSON schemas into `schemas/aip`.
    Schema,
    /// Run the core conformance suite.
    Conformance,
    /// Run release blocking checks that do not require external services.
    ReleaseCheck,
    /// Verify that the core daemon and fleet infrastructure are product-neutral.
    CheckGetaipServerBoundary,
    /// Verify the exact private SDK closure and connector-repository boundary.
    CheckPrivateSdkBoundary,
    /// Write a deterministic, permission-aware inventory for the connector-repository transfer.
    ConnectorRepositoryInventory {
        /// JSON file receiving the transfer inventory.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Write the deterministic package and file inventory for a private SDK release.
    PrivateSdkInventory {
        /// JSON file receiving the private SDK release inventory.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Build deterministic native release artifacts and one target fragment.
    PackageNative {
        /// Exact Rust target from the supported release matrix.
        #[arg(long)]
        target: String,
        /// Reviewed native getaip executable.
        #[arg(long, value_name = "PATH")]
        cli: PathBuf,
        /// Reviewed native getaip-server executable.
        #[arg(long, value_name = "PATH")]
        server: PathBuf,
        /// New or empty artifact output directory.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Exact release source commit embedded in archive metadata.
        #[arg(long)]
        source_commit: String,
        /// Exact release source tree embedded in archive metadata.
        #[arg(long)]
        source_tree: String,
        /// Reproducible Unix timestamp used for every archive entry.
        #[arg(long)]
        source_date_epoch: u64,
    },
    /// Assemble and sign the exact four-target distribution manifest.
    AssembleNativeManifest {
        /// Directory containing target fragments and artifacts.
        #[arg(long, value_name = "PATH")]
        directory: PathBuf,
        /// Manifest output path.
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        /// Detached signature-envelope output path.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        /// External mode-0600 PKCS#8 Ed25519 private key.
        #[arg(long, value_name = "PATH")]
        signing_key: PathBuf,
        /// Trusted signing-key identifier.
        #[arg(long)]
        signing_key_id: String,
        /// Stable, release-candidate, or development.
        #[arg(long, default_value = "stable")]
        channel: String,
        /// Exact RFC 3339 publication timestamp.
        #[arg(long)]
        published_at: String,
        /// Optional previous installable GetAIP release.
        #[arg(long)]
        previous_version: Option<String>,
        /// Canonical Gitea source commit.
        #[arg(long)]
        gitea_commit: String,
        /// Canonical Gitea source tree.
        #[arg(long)]
        gitea_tree: String,
        /// Filtered GitHub snapshot commit.
        #[arg(long)]
        github_commit: String,
        /// Filtered GitHub snapshot tree.
        #[arg(long)]
        github_tree: String,
    },
    /// Verify signatures, checksums, archives, and exact release asset identity.
    VerifyNativeRelease {
        /// Directory containing the complete release candidate.
        #[arg(long, value_name = "PATH")]
        directory: PathBuf,
        /// Signed distribution manifest.
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        /// Detached signature envelope.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Task::Fmt => run("cargo", &["fmt", "--all"]),
        Task::Lint => run(
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        Task::Test => run("cargo", &["test", "--workspace", "--all-features"]),
        Task::Schema => run(
            "cargo",
            &[
                "run",
                "-q",
                "-p",
                "getaip-cli",
                "--",
                "schema",
                "export",
                "schemas/aip",
            ],
        ),
        Task::Conformance => run(
            "cargo",
            &["run", "-q", "-p", "getaip-cli", "--", "conformance", "run"],
        ),
        Task::ReleaseCheck => release_check(),
        Task::CheckGetaipServerBoundary => check_getaip_server_boundary(),
        Task::CheckPrivateSdkBoundary => check_private_sdk_boundary(),
        Task::ConnectorRepositoryInventory { output } => connector_repository_inventory(&output),
        Task::PrivateSdkInventory { output } => private_sdk_inventory(&output),
        Task::PackageNative {
            target,
            cli,
            server,
            output,
            source_commit,
            source_tree,
            source_date_epoch,
        } => native_release::package_native(
            &target,
            &cli,
            &server,
            &output,
            &source_commit,
            &source_tree,
            source_date_epoch,
        ),
        Task::AssembleNativeManifest {
            directory,
            manifest,
            signature,
            signing_key,
            signing_key_id,
            channel,
            published_at,
            previous_version,
            gitea_commit,
            gitea_tree,
            github_commit,
            github_tree,
        } => native_release::assemble_native_manifest(
            &directory,
            &manifest,
            &signature,
            &signing_key,
            &signing_key_id,
            &channel,
            &published_at,
            previous_version.as_deref(),
            &gitea_commit,
            &gitea_tree,
            &github_commit,
            &github_tree,
        ),
        Task::VerifyNativeRelease {
            directory,
            manifest,
            signature,
        } => native_release::verify_native_release(&directory, &manifest, &signature),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn release_check() -> Result<(), String> {
    run("cargo", &["fmt", "--all", "--check"])?;
    check_getaip_server_boundary()?;
    check_private_sdk_boundary()?;
    // Run isolated semver builds before the shared target accumulates the full
    // all-feature and no-default test matrices. Each package target is removed
    // immediately after comparison, keeping the release gate disk-bounded.
    if let Some(baseline_revision) = semver_baseline_revision()? {
        eprintln!("using semver baseline `{baseline_revision}`");
        run_semver_checks(&baseline_revision)?;
    } else {
        eprintln!("skipping semver-checks: no earlier stable release tag exists");
    }
    run(
        "cargo",
        &[
            "run",
            "-q",
            "-p",
            "getaip-cli",
            "--",
            "schema",
            "export",
            "schemas/aip",
        ],
    )?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        "cargo",
        &["nextest", "run", "--workspace", "--all-features"],
    )?;
    run("cargo", &["test", "--workspace", "--no-default-features"])?;
    run("cargo", &["deny", "check"])?;
    run("cargo", &["audit"])?;
    run("cargo-machete", &[])?;
    run(
        "cargo",
        &["check", "--manifest-path", "fuzz/Cargo.toml", "-q"],
    )?;
    run(
        "cargo",
        &["doc", "--workspace", "--all-features", "--no-deps"],
    )?;
    Ok(())
}

fn check_getaip_server_boundary() -> Result<(), String> {
    let output = ProcessCommand::new("cargo")
        .args(["metadata", "--format-version", "1", "--all-features"])
        .output()
        .map_err(|error| format!("failed to run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!("cargo metadata exited with {}", output.status));
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata returned invalid JSON: {error}"))?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata omitted packages".to_owned())?;
    let resolve_nodes = metadata
        .pointer("/resolve/nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata omitted resolve nodes".to_owned())?;
    let mut names_by_id = std::collections::BTreeMap::new();
    let mut ids_by_name = std::collections::BTreeMap::new();
    for package in packages {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "cargo package omitted id".to_owned())?;
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "cargo package omitted name".to_owned())?;
        names_by_id.insert(id.to_owned(), name.to_owned());
        ids_by_name.insert(name.to_owned(), id.to_owned());
    }
    check_facade_feature_boundary(packages)?;
    let mut dependencies_by_id = std::collections::BTreeMap::<String, Vec<String>>::new();
    for node in resolve_nodes {
        let id = node
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "cargo resolve node omitted id".to_owned())?;
        let dependencies = node
            .get("deps")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("cargo resolve node `{id}` omitted deps"))?
            .iter()
            .filter_map(|dependency| dependency.get("pkg").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect();
        dependencies_by_id.insert(id.to_owned(), dependencies);
    }

    let neutral_connectors = BTreeSet::from([
        "aip-connector",
        "aip-connector-registry",
        "aip-connector-admission",
        "aip-connector-orchestration",
        "aip-connector-registry-postgres",
        "aip-connector-remote",
        "aip-connector-host",
        "aip-connector-host-bootstrap",
        "aip-connector-control-plane",
    ]);
    for root in [
        "getaip-server",
        "aip-connector-registry",
        "aip-connector-admission",
        "aip-connector-orchestration",
        "aip-connector-registry-postgres",
        "aip-connector-remote",
        "aip-connector-host",
        "aip-connector-host-bootstrap",
        "aip-connector-control-plane",
    ] {
        let root_id = ids_by_name
            .get(root)
            .ok_or_else(|| format!("workspace package `{root}` is missing"))?;
        let mut queue = vec![(root_id.clone(), vec![root.to_owned()])];
        let mut seen = BTreeSet::new();
        while let Some((id, path)) = queue.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let name = names_by_id
                .get(&id)
                .ok_or_else(|| format!("resolve package `{id}` is missing"))?;
            if name.starts_with("aip-connector-") && !neutral_connectors.contains(name.as_str()) {
                return Err(format!(
                    "product connector dependency reached from `{root}`: {}",
                    path.join(" -> ")
                ));
            }
            for dependency in dependencies_by_id.get(&id).into_iter().flatten() {
                let mut dependency_path = path.clone();
                dependency_path.push(
                    names_by_id
                        .get(dependency)
                        .cloned()
                        .unwrap_or_else(|| dependency.clone()),
                );
                queue.push((dependency.clone(), dependency_path));
            }
        }
    }

    let product_hosts = [
        ("aip-host-support-sandbox", "aip-connector-support-sandbox"),
        (
            "aip-host-enterprise-sandbox",
            "aip-connector-enterprise-sandbox",
        ),
        ("aip-host-cal-diy", "aip-connector-cal-diy"),
        ("aip-host-hermes-agent", "aip-connector-hermes-agent"),
        ("aip-host-chatwoot", "aip-connector-chatwoot"),
        ("aip-host-dify", "aip-connector-dify"),
        ("aip-host-crewai", "aip-connector-crewai"),
        ("aip-host-twenty", "aip-connector-twenty"),
    ];
    for (host, allowed_product) in product_hosts {
        let root_id = ids_by_name
            .get(host)
            .ok_or_else(|| format!("workspace package `{host}` is missing"))?;
        let mut queue = vec![(root_id.clone(), vec![host.to_owned()])];
        let mut seen = BTreeSet::new();
        let mut found_product = false;
        while let Some((id, path)) = queue.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let name = names_by_id
                .get(&id)
                .ok_or_else(|| format!("resolve package `{id}` is missing"))?;
            if name.starts_with("aip-connector-") && !neutral_connectors.contains(name.as_str()) {
                if name != allowed_product {
                    return Err(format!(
                        "product host `{host}` reaches forbidden connector `{name}`: {}",
                        path.join(" -> ")
                    ));
                }
                found_product = true;
            }
            for dependency in dependencies_by_id.get(&id).into_iter().flatten() {
                let mut dependency_path = path.clone();
                dependency_path.push(
                    names_by_id
                        .get(dependency)
                        .cloned()
                        .unwrap_or_else(|| dependency.clone()),
                );
                queue.push((dependency.clone(), dependency_path));
            }
        }
        if !found_product {
            return Err(format!(
                "product host `{host}` does not depend on its exact connector `{allowed_product}`"
            ));
        }
    }

    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or_else(|| "cargo metadata omitted workspace_root".to_owned())?;
    let source_root = Path::new(workspace_root).join("crates/getaip-server");
    let markers = [
        "cal_diy",
        "cal-diy",
        "hermes",
        "chatwoot",
        "dify",
        "crewai",
        "support_sandbox",
        "support-sandbox",
        "enterprise_sandbox",
        "enterprise-sandbox",
    ];
    for file in recursive_files(&source_root)? {
        if !matches!(
            file.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "toml")
        ) {
            continue;
        }
        let content = fs::read_to_string(&file)
            .map_err(|error| format!("failed to read `{}`: {error}", file.display()))?;
        let lower = content.to_ascii_lowercase();
        if let Some(marker) = markers.iter().find(|marker| lower.contains(**marker)) {
            return Err(format!(
                "product marker `{marker}` found in core daemon source `{}`",
                file.display()
            ));
        }
    }
    let module_source_path = source_root.join("src/module.rs");
    let module_source = fs::read_to_string(&module_source_path).map_err(|error| {
        format!(
            "failed to read module boundary `{}`: {error}",
            module_source_path.display()
        )
    })?;
    for required_guard in [
        "pub const LOCAL_MODULE_HTTP_ROUTE_PREFIX: &str = \"/connectors/\";",
        "if !path.starts_with(LOCAL_MODULE_HTTP_ROUTE_PREFIX)",
        "aip.server.module.reserved_http_route",
    ] {
        if !module_source.contains(required_guard) {
            return Err(format!(
                "core daemon module boundary omitted reserved-route guard `{required_guard}`"
            ));
        }
    }
    eprintln!("getaip-server product boundary: PASS");
    Ok(())
}

fn check_private_sdk_boundary() -> Result<(), String> {
    const CONFIG_PATH: &str = "private-sdk-release.json";
    const MAX_CONFIG_BYTES: u64 = 64 * 1024;
    let metadata = cargo_metadata(false)?;
    let workspace_version = env!("CARGO_PKG_VERSION");
    let config_metadata = fs::metadata(CONFIG_PATH)
        .map_err(|error| format!("failed to inspect `{CONFIG_PATH}`: {error}"))?;
    if config_metadata.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "private SDK release policy is {} bytes; limit is {MAX_CONFIG_BYTES}",
            config_metadata.len()
        ));
    }
    let config: Value = serde_json::from_slice(
        &fs::read(CONFIG_PATH)
            .map_err(|error| format!("failed to read `{CONFIG_PATH}`: {error}"))?,
    )
    .map_err(|error| format!("`{CONFIG_PATH}` is invalid JSON: {error}"))?;
    require_json_string(&config, "schema_version", "aip.private-sdk-release/v1")?;
    require_json_string(&config, "registry", "getaip-private")?;
    require_json_string(
        &config,
        "target_connector_repository",
        "getaip/aip-connectors",
    )?;
    require_json_u64(&config, "minimum_verified_private_sdk_releases", 2)?;
    require_json_string(&config, "workspace_version", workspace_version)?;
    require_json_string(
        &config,
        "publication_mode",
        "disabled_until_registry_bootstrap",
    )?;

    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata omitted packages".to_owned())?;
    let workspace_members = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata omitted workspace_members".to_owned())?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let workspace_packages = packages
        .iter()
        .filter(|package| {
            package
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| workspace_members.contains(id))
        })
        .filter_map(|package| {
            package
                .get("name")
                .and_then(Value::as_str)
                .map(|name| (name.to_owned(), package))
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let sdk_order = required_unique_string_array(&config, "packages_in_publish_order")?;
    let required_sdk_paths = required_unique_string_array(&config, "private_sdk_required_paths")?;
    let connector_packages =
        required_unique_string_array(&config, "connector_repository_packages")?;
    let required_connector_paths =
        required_unique_string_array(&config, "connector_repository_required_paths")?;
    let sdk_positions = sdk_order
        .iter()
        .enumerate()
        .map(|(position, name)| (name.as_str(), position))
        .collect::<std::collections::BTreeMap<_, _>>();
    let product_markers = [
        "cal-diy",
        "chatwoot",
        "crewai",
        "dify",
        "hermes",
        "support-sandbox",
        "enterprise-sandbox",
    ];

    for (position, package_name) in sdk_order.iter().enumerate() {
        if product_markers
            .iter()
            .any(|marker| package_name.contains(marker))
        {
            return Err(format!(
                "product package `{package_name}` is forbidden in the private SDK closure"
            ));
        }
        let package = workspace_packages
            .get(package_name)
            .ok_or_else(|| format!("private SDK package `{package_name}` is missing"))?;
        if !package_has_library_target(package)? {
            return Err(format!(
                "private SDK package `{package_name}` has no library target"
            ));
        }
        let publish = package
            .get("publish")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("package `{package_name}` omitted publish policy"))?;
        if !publish.is_empty() {
            return Err(format!(
                "package `{package_name}` must remain non-publishable until the private registry bootstrap is verified"
            ));
        }
        for dependency in publish_workspace_dependencies(package, &workspace_packages)? {
            let dependency_position = sdk_positions.get(dependency.as_str()).ok_or_else(|| {
                format!(
                    "private SDK package `{package_name}` depends on workspace package `{dependency}` outside the verified closure"
                )
            })?;
            if *dependency_position >= position {
                return Err(format!(
                    "private SDK publish order places `{dependency}` after its dependent `{package_name}`"
                ));
            }
        }
    }

    let connector_set = connector_packages.iter().cloned().collect::<BTreeSet<_>>();
    if connector_set.len() != 12 {
        return Err(
            "connector repository policy must contain exactly six connectors and six hosts"
                .to_owned(),
        );
    }
    for package_name in &connector_packages {
        let package = workspace_packages
            .get(package_name)
            .ok_or_else(|| format!("connector repository package `{package_name}` is missing"))?;
        let publish = package
            .get("publish")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("package `{package_name}` omitted publish policy"))?;
        if !publish.is_empty() {
            return Err(format!(
                "connector repository package `{package_name}` must not publish from aip-core"
            ));
        }
        for dependency in all_workspace_dependencies(package, &workspace_packages)? {
            if !connector_set.contains(&dependency)
                && !sdk_positions.contains_key(dependency.as_str())
            {
                return Err(format!(
                    "connector repository package `{package_name}` depends on `{dependency}`, which is in neither the repository nor private SDK closure"
                ));
            }
        }
    }
    let (included_sdk_paths, omitted_sdk_paths) =
        validate_private_sdk_required_paths(&required_sdk_paths, 16 * 1024 * 1024)?;
    for path in &required_connector_paths {
        validate_repository_relative_file(Path::new(path), 16 * 1024 * 1024)?;
    }
    eprintln!(
        "private SDK boundary: PASS ({} SDK packages, {} SDK root files, {} code-only omissions, {} connector-repository packages, {} connector root files)",
        sdk_order.len(),
        included_sdk_paths.len(),
        omitted_sdk_paths.len(),
        connector_packages.len(),
        required_connector_paths.len()
    );
    Ok(())
}

fn connector_repository_inventory(output: &Path) -> Result<(), String> {
    const CONFIG_PATH: &str = "private-sdk-release.json";
    const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
    check_private_sdk_boundary()?;
    let config: Value = serde_json::from_slice(
        &fs::read(CONFIG_PATH)
            .map_err(|error| format!("failed to read `{CONFIG_PATH}`: {error}"))?,
    )
    .map_err(|error| format!("`{CONFIG_PATH}` is invalid JSON: {error}"))?;
    let connector_packages =
        required_unique_string_array(&config, "connector_repository_packages")?;
    let required_paths =
        required_unique_string_array(&config, "connector_repository_required_paths")?;
    let metadata = cargo_metadata(false)?;
    let workspace_root = metadata_workspace_root(&metadata)?;
    let roots = package_roots(&metadata, &connector_packages)?;
    for required in &required_paths {
        validate_repository_relative_file(Path::new(required), MAX_FILE_BYTES)?;
    }

    let paths = enumerate_inventory_paths(&workspace_root, &roots, &required_paths)?;
    let records = inventory_records(&workspace_root, paths, MAX_FILE_BYTES)?;
    let inventory_digest = inventory_digest(&records)?;
    let revision = git_stdout(&workspace_root, &["rev-parse", "HEAD"])?;
    let scoped_status = scoped_git_status(&workspace_root, &roots, &required_paths)?;
    let dependency_edges = package_dependency_edges(&metadata, &connector_packages)?;
    let inventory = serde_json::json!({
        "schema_version": "aip.connector-repository-inventory/v1",
        "workspace_version": env!("CARGO_PKG_VERSION"),
        "source_repository": "https://github.com/getaip/core",
        "source_revision": revision,
        "source_scope_dirty": !scoped_status.is_empty(),
        "target_repository": "getaip/aip-connectors",
        "packages": connector_packages,
        "package_roots": roots,
        "workspace_dependency_edges": dependency_edges,
        "file_count": records.len(),
        "files": records,
        "inventory_digest": inventory_digest
    });
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    let encoded = serde_json::to_vec_pretty(&inventory)
        .map_err(|error| format!("failed to encode transfer inventory: {error}"))?;
    write_atomic_file(output, &encoded)?;
    eprintln!(
        "connector repository inventory: PASS ({} files, {})",
        inventory["file_count"], inventory["inventory_digest"]
    );
    Ok(())
}

fn private_sdk_inventory(output: &Path) -> Result<(), String> {
    const CONFIG_PATH: &str = "private-sdk-release.json";
    const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
    check_private_sdk_boundary()?;
    let config: Value = serde_json::from_slice(
        &fs::read(CONFIG_PATH)
            .map_err(|error| format!("failed to read `{CONFIG_PATH}`: {error}"))?,
    )
    .map_err(|error| format!("`{CONFIG_PATH}` is invalid JSON: {error}"))?;
    let package_order = required_unique_string_array(&config, "packages_in_publish_order")?;
    let canonical_required_paths =
        required_unique_string_array(&config, "private_sdk_required_paths")?;
    let metadata = cargo_metadata(false)?;
    let workspace_root = metadata_workspace_root(&metadata)?;
    let roots = package_roots(&metadata, &package_order)?;
    let (required_paths, publication_omitted_required_paths) =
        validate_private_sdk_required_paths(&canonical_required_paths, MAX_FILE_BYTES)?;
    let paths = enumerate_inventory_paths(&workspace_root, &roots, &required_paths)?;
    let records = inventory_records(&workspace_root, paths, MAX_FILE_BYTES)?;
    let digest = inventory_digest(&records)?;
    let revision = git_stdout(&workspace_root, &["rev-parse", "HEAD"])?;
    let scoped_status = scoped_git_status(&workspace_root, &roots, &required_paths)?;
    let dependency_edges = package_dependency_edges(&metadata, &package_order)?;
    let inventory = serde_json::json!({
        "schema_version": "aip.private-sdk-inventory/v1",
        "workspace_version": env!("CARGO_PKG_VERSION"),
        "registry": "getaip-private",
        "source_repository": "https://github.com/getaip/core",
        "source_revision": revision,
        "source_scope_dirty": !scoped_status.is_empty(),
        "minimum_verified_releases_before_connector_transfer": 2,
        "packages_in_publish_order": package_order,
        "package_roots": roots,
        "canonical_required_root_paths": canonical_required_paths,
        "publication_omitted_required_paths": publication_omitted_required_paths,
        "workspace_dependency_edges": dependency_edges,
        "file_count": records.len(),
        "files": records,
        "inventory_digest": digest
    });
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    let encoded = serde_json::to_vec_pretty(&inventory)
        .map_err(|error| format!("failed to encode private SDK inventory: {error}"))?;
    write_atomic_file(output, &encoded)?;
    eprintln!(
        "private SDK inventory: PASS ({} packages, {} files, {})",
        inventory["packages_in_publish_order"]
            .as_array()
            .map_or(0, Vec::len),
        inventory["file_count"],
        inventory["inventory_digest"]
    );
    Ok(())
}

fn metadata_workspace_root(metadata: &Value) -> Result<PathBuf, String> {
    metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "cargo metadata omitted workspace_root".to_owned())
}

fn package_roots(metadata: &Value, package_names: &[String]) -> Result<BTreeSet<String>, String> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata omitted packages".to_owned())?;
    let workspace_root = metadata_workspace_root(metadata)?;
    let mut roots = BTreeSet::new();
    for package_name in package_names {
        let package = packages
            .iter()
            .find(|package| package.get("name").and_then(Value::as_str) == Some(package_name))
            .ok_or_else(|| format!("workspace package `{package_name}` is missing"))?;
        let manifest = PathBuf::from(required_object_string(package, "manifest_path")?);
        let root = manifest
            .parent()
            .ok_or_else(|| format!("package `{package_name}` manifest has no parent"))?
            .strip_prefix(&workspace_root)
            .map_err(|_| format!("package `{package_name}` is outside the workspace"))?;
        roots.insert(path_as_git_argument(root)?);
    }
    Ok(roots)
}

fn enumerate_inventory_paths(
    workspace_root: &Path,
    roots: &BTreeSet<String>,
    required_paths: &[String],
) -> Result<BTreeSet<String>, String> {
    let mut command = ProcessCommand::new("git");
    command.args(["ls-files", "-co", "--exclude-standard", "-z", "--"]);
    command.args(roots);
    command.current_dir(workspace_root);
    let listed = command
        .output()
        .map_err(|error| format!("failed to enumerate inventory files: {error}"))?;
    if !listed.status.success() {
        return Err(format!(
            "git file enumeration exited with {}",
            listed.status
        ));
    }
    let mut paths = listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .map(ToOwned::to_owned)
                .map_err(|_| "inventory path is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    paths.extend(required_paths.iter().cloned());
    if paths.is_empty() {
        return Err("release inventory is empty".to_owned());
    }
    Ok(paths)
}

fn inventory_records(
    workspace_root: &Path,
    paths: BTreeSet<String>,
    max_file_bytes: u64,
) -> Result<Vec<Value>, String> {
    let mut records = Vec::with_capacity(paths.len());
    for relative in paths {
        reject_generated_or_secret_path(&relative)?;
        let path = workspace_root.join(&relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect `{relative}`: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "release inventory input `{relative}` must be a regular non-symlink file"
            ));
        }
        if metadata.len() > max_file_bytes {
            return Err(format!(
                "release inventory input `{relative}` exceeds {max_file_bytes} bytes"
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("failed to read release input `{relative}`: {error}"))?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0_u32;
        records.push(serde_json::json!({
            "path": relative,
            "bytes": bytes.len(),
            "mode": format!("{mode:04o}"),
            "sha256": format!("{:x}", Sha256::digest(&bytes))
        }));
    }
    records.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .cmp(&right.get("path").and_then(Value::as_str))
    });
    Ok(records)
}

fn inventory_digest(records: &[Value]) -> Result<String, String> {
    let bytes = serde_json::to_vec(records)
        .map_err(|error| format!("failed to encode release inventory: {error}"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn scoped_git_status(
    workspace_root: &Path,
    roots: &BTreeSet<String>,
    required_paths: &[String],
) -> Result<String, String> {
    let mut scopes = roots.clone();
    scopes.extend(required_paths.iter().cloned());
    let mut args = vec!["status", "--porcelain=v1", "--"];
    args.extend(scopes.iter().map(String::as_str));
    git_stdout(workspace_root, &args)
}

fn package_dependency_edges(
    metadata: &Value,
    package_names: &[String],
) -> Result<Vec<Value>, String> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata omitted packages".to_owned())?;
    let selected = package_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut edges = Vec::new();
    for package_name in package_names {
        let package = packages
            .iter()
            .find(|package| package.get("name").and_then(Value::as_str) == Some(package_name))
            .ok_or_else(|| format!("workspace package `{package_name}` is missing"))?;
        let dependencies = package
            .get("dependencies")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("package `{package_name}` omitted dependencies"))?;
        for dependency in dependencies {
            if dependency.get("path").and_then(Value::as_str).is_none() {
                continue;
            }
            let dependency_name = required_object_string(dependency, "name")?;
            edges.push(serde_json::json!({
                "from": package_name,
                "to": dependency_name,
                "kind": dependency.get("kind").and_then(Value::as_str).unwrap_or("normal"),
                "inside_inventory": selected.contains(dependency_name)
            }));
        }
    }
    edges.sort_by(|left, right| {
        for field in ["from", "to", "kind"] {
            let ordering = left
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(right.get(field).and_then(Value::as_str).unwrap_or_default());
            if !ordering.is_eq() {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    });
    Ok(edges)
}

fn write_atomic_file(output: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("output path `{}` has no UTF-8 file name", output.display()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| {
            format!(
                "failed to create temporary inventory `{}`: {error}",
                temporary.display()
            )
        })?;
    let publish = (|| -> Result<(), String> {
        file.write_all(bytes).map_err(|error| {
            format!(
                "failed to write temporary inventory `{}`: {error}",
                temporary.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "failed to sync temporary inventory `{}`: {error}",
                temporary.display()
            )
        })?;
        drop(file);
        fs::rename(&temporary, output)
            .map_err(|error| format!("failed to publish `{}`: {error}", output.display()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!(
                    "failed to sync inventory directory `{}`: {error}",
                    parent.display()
                )
            })?;
        Ok(())
    })();
    if publish.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish
}

fn cargo_metadata(all_features: bool) -> Result<Value, String> {
    let mut command = ProcessCommand::new("cargo");
    command.args(["metadata", "--format-version", "1"]);
    if all_features {
        command.arg("--all-features");
    } else {
        command.arg("--no-deps");
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!("cargo metadata exited with {}", output.status));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata returned invalid JSON: {error}"))
}

fn require_json_string(value: &Value, field: &str, expected: &str) -> Result<(), String> {
    let actual = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("private SDK release policy omitted `{field}`"))?;
    if actual != expected {
        return Err(format!(
            "private SDK release policy `{field}` is `{actual}`, expected `{expected}`"
        ));
    }
    Ok(())
}

fn require_json_u64(value: &Value, field: &str, expected: u64) -> Result<(), String> {
    let actual = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("private SDK release policy omitted `{field}` integer"))?;
    if actual != expected {
        return Err(format!(
            "private SDK release policy `{field}` is `{actual}`, expected `{expected}`"
        ));
    }
    Ok(())
}

fn required_unique_string_array(value: &Value, field: &str) -> Result<Vec<String>, String> {
    let values = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("private SDK release policy omitted `{field}` array"))?;
    if values.is_empty() {
        return Err(format!("private SDK release policy `{field}` is empty"));
    }
    let mut result = Vec::with_capacity(values.len());
    let mut observed = BTreeSet::new();
    for value in values {
        let name = value
            .as_str()
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                format!("private SDK release policy `{field}` contains an invalid name")
            })?;
        if !observed.insert(name) {
            return Err(format!(
                "private SDK release policy `{field}` repeats `{name}`"
            ));
        }
        result.push(name.to_owned());
    }
    Ok(result)
}

fn code_only_snapshot_excludes_markdown() -> Result<bool, String> {
    let snapshot: Value = serde_json::from_slice(
        &fs::read(SOURCE_SNAPSHOT_PATH)
            .map_err(|error| format!("failed to read `{SOURCE_SNAPSHOT_PATH}`: {error}"))?,
    )
    .map_err(|error| format!("`{SOURCE_SNAPSHOT_PATH}` is invalid JSON: {error}"))?;
    if snapshot.get("mode").and_then(Value::as_str) != Some("code-only-single-root") {
        return Ok(false);
    }
    if snapshot.get("schema_version").and_then(Value::as_u64) != Some(2) {
        return Err(format!(
            "`{SOURCE_SNAPSHOT_PATH}` code-only mode requires schema version 2"
        ));
    }
    let excludes_markdown = snapshot
        .get("publication_boundary")
        .and_then(|boundary| boundary.get("excluded_markdown"))
        .and_then(Value::as_bool);
    if excludes_markdown != Some(true) {
        return Err(format!(
            "`{SOURCE_SNAPSHOT_PATH}` code-only mode must declare the Markdown exclusion"
        ));
    }
    Ok(true)
}

fn validate_private_sdk_required_paths(
    paths: &[String],
    max_bytes: u64,
) -> Result<(Vec<String>, Vec<String>), String> {
    let code_only_markdown_exclusion = code_only_snapshot_excludes_markdown()?;
    let mut included = Vec::with_capacity(paths.len());
    let mut omitted = Vec::new();
    for relative in paths {
        let path = Path::new(relative);
        match fs::symlink_metadata(path) {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && code_only_markdown_exclusion
                    && relative.to_ascii_lowercase().ends_with(".md") =>
            {
                omitted.push(relative.clone());
            }
            _ => {
                validate_repository_relative_file(path, max_bytes)?;
                included.push(relative.clone());
            }
        }
    }
    Ok((included, omitted))
}

fn validate_repository_relative_file(path: &Path, max_bytes: u64) -> Result<(), String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "connector repository path `{}` must stay inside the workspace",
            path.display()
        ));
    }
    let relative = path_as_git_argument(path)?;
    reject_generated_or_secret_path(&relative)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect connector path `{relative}`: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "connector repository path `{relative}` must be a regular non-symlink file"
        ));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!(
            "connector repository path `{relative}` must contain 1 to {max_bytes} bytes"
        ));
    }
    Ok(())
}

fn path_as_git_argument(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("path `{}` is empty or not UTF-8", path.display()))?;
    if value.contains(['\0', '\n', '\r']) {
        return Err(format!(
            "path `{value}` contains forbidden control characters"
        ));
    }
    Ok(value.replace('\\', "/"))
}

fn reject_generated_or_secret_path(path: &str) -> Result<(), String> {
    let components = Path::new(path)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if components.iter().any(|component| {
        matches!(
            *component,
            "target" | ".venv" | ".pytest_cache" | "__pycache__" | "node_modules"
        )
    }) {
        return Err(format!(
            "connector repository input `{path}` contains generated dependency state"
        ));
    }
    let file_name = components.last().copied().unwrap_or_default();
    if file_name == ".env"
        || file_name.starts_with(".env.")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
    {
        return Err(format!(
            "connector repository input `{path}` matches a forbidden credential-file pattern"
        ));
    }
    Ok(())
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("failed to run git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| format!("git {} returned non-UTF-8 output", args.join(" ")))
}

fn publish_workspace_dependencies(
    package: &Value,
    workspace_packages: &std::collections::BTreeMap<String, &Value>,
) -> Result<Vec<String>, String> {
    workspace_dependencies_matching(package, workspace_packages, |kind| kind != Some("dev"))
}

fn all_workspace_dependencies(
    package: &Value,
    workspace_packages: &BTreeMap<String, &Value>,
) -> Result<Vec<String>, String> {
    workspace_dependencies_matching(package, workspace_packages, |_| true)
}

fn workspace_dependencies_matching(
    package: &Value,
    workspace_packages: &BTreeMap<String, &Value>,
    include_kind: impl Fn(Option<&str>) -> bool,
) -> Result<Vec<String>, String> {
    let package_name = required_object_string(package, "name")?;
    let dependencies = package
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("package `{package_name}` omitted dependencies"))?;
    let mut result = BTreeSet::new();
    for dependency in dependencies {
        if !include_kind(dependency.get("kind").and_then(Value::as_str)) {
            continue;
        }
        let name = required_object_string(dependency, "name")?;
        if workspace_packages.contains_key(name) {
            result.insert(name.to_owned());
        }
    }
    Ok(result.into_iter().collect())
}

fn check_facade_feature_boundary(packages: &[Value]) -> Result<(), String> {
    let facade = packages
        .iter()
        .find(|package| package.get("name").and_then(Value::as_str) == Some("aip"))
        .ok_or_else(|| "workspace package `aip` is missing".to_owned())?;
    let features = facade
        .get("features")
        .and_then(Value::as_object)
        .ok_or_else(|| "workspace package `aip` omitted features".to_owned())?;
    let legacy_full = features
        .get("full")
        .and_then(Value::as_array)
        .ok_or_else(|| "facade feature `full` is missing".to_owned())?;
    if !legacy_full
        .iter()
        .any(|entry| entry.as_str() == Some("full-core"))
    {
        return Err("legacy facade feature `full` must include `full-core`".to_owned());
    }
    let neutral_connector_features = BTreeSet::from([
        "connector-host",
        "connector-registry",
        "connector-registry-postgres",
        "connector-remote",
    ]);
    let neutral_connector_dependencies = BTreeSet::from([
        "dep:aip-connector-host",
        "dep:aip-connector-registry",
        "dep:aip-connector-registry-postgres",
        "dep:aip-connector-remote",
    ]);
    let mut pending = vec!["full-core".to_owned()];
    let mut visited = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !visited.insert(feature.clone()) {
            continue;
        }
        let entries = features
            .get(&feature)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("facade feature `{feature}` is missing"))?;
        for entry in entries {
            let entry = entry
                .as_str()
                .ok_or_else(|| format!("facade feature `{feature}` contains a non-string"))?;
            let product_feature =
                entry.starts_with("connector-") && !neutral_connector_features.contains(entry);
            let product_dependency = entry.starts_with("dep:aip-connector-")
                && !neutral_connector_dependencies.contains(entry);
            if product_feature || product_dependency {
                return Err(format!(
                    "product connector feature `{entry}` is reachable from `full-core`"
                ));
            }
            if !entry.starts_with("dep:") && !entry.contains('/') && features.contains_key(entry) {
                pending.push(entry.to_owned());
            }
        }
    }
    Ok(())
}

fn recursive_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        let entries = fs::read_dir(&path)
            .map_err(|error| format!("failed to read `{}`: {error}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if file_type.is_symlink() {
                return Err(format!(
                    "symbolic link is not allowed under `{}`",
                    root.display()
                ));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn semver_baseline_revision() -> Result<Option<String>, String> {
    if let Ok(configured) = std::env::var("AIP_SEMVER_BASELINE_REV") {
        let configured = configured.trim();
        if configured.is_empty() {
            return Err("AIP_SEMVER_BASELINE_REV must not be empty".to_owned());
        }
        verify_git_revision(configured)?;
        return Ok(Some(configured.to_owned()));
    }

    let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("workspace version is not valid semver: {error}"))?;
    let output = ProcessCommand::new("git")
        .args(["tag", "--merged", "HEAD", "--list", "v[0-9]*"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("git tag exited with {}", output.status));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("git tag output was not valid UTF-8: {error}"))?;
    if let Some(tag) = select_semver_baseline(&current_version, stdout.lines()) {
        return Ok(Some(tag));
    }

    Ok(None)
}

fn release_version_from_tag(tag: &str) -> Option<Version> {
    let candidate = tag.strip_prefix('v')?;
    let version_end = candidate
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(candidate.len());
    Version::parse(&candidate[..version_end]).ok()
}

fn select_semver_baseline<'a>(
    current_version: &Version,
    tags: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    tags.into_iter()
        .filter_map(|tag| {
            release_version_from_tag(tag).map(|version| {
                let is_canonical = tag == format!("v{version}");
                (version, is_canonical, tag)
            })
        })
        .filter(|(version, _is_canonical, _tag)| version < current_version)
        .max_by(
            |(left_version, left_is_canonical, left_tag),
             (right_version, right_is_canonical, right_tag)| {
                left_version
                    .cmp(right_version)
                    .then_with(|| left_is_canonical.cmp(right_is_canonical))
                    .then_with(|| left_tag.cmp(right_tag))
            },
        )
        .map(|(_version, _is_canonical, tag)| tag.to_owned())
}

fn verify_git_revision(revision: &str) -> Result<(), String> {
    let revision_expression = format!("{revision}^{{commit}}");
    let status = ProcessCommand::new("git")
        .args(["rev-parse", "--verify", "--quiet", &revision_expression])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "semver baseline revision `{revision}` does not resolve to a commit"
        ))
    }
}

fn run_semver_checks(baseline_revision: &str) -> Result<(), String> {
    let packages = semver_package_names()?;
    let workspace_root = std::env::current_dir().map_err(|error| error.to_string())?;
    let semver_root = workspace_root.join(SEMVER_TARGET_DIR);
    for package in packages {
        if !path_exists_at_revision(&package.manifest_path, baseline_revision)? {
            eprintln!("skipping semver-checks for new package `{}`", package.name);
            continue;
        }

        let target_dir = semver_root.join(sanitize_path_component(&package.name));
        remove_dir_if_exists(&target_dir)?;
        ensure_min_free_space(&workspace_root, SEMVER_MIN_FREE_BYTES)?;

        eprintln!("running semver-checks for `{}`", package.name);
        let status = ProcessCommand::new("cargo")
            .args([
                "semver-checks",
                "-p",
                package.name.as_str(),
                "--baseline-rev",
                baseline_revision,
            ])
            .env("CARGO_TARGET_DIR", &target_dir)
            .status()
            .map_err(|error| error.to_string());

        let cleanup = remove_dir_if_exists(&target_dir);
        match (status, cleanup) {
            (Ok(exit_status), Ok(())) if exit_status.success() => {}
            (Ok(exit_status), Ok(())) => {
                return Err(format!(
                    "cargo semver-checks for `{}` exited with {exit_status}",
                    package.name
                ));
            }
            (Ok(exit_status), Err(cleanup_error)) if exit_status.success() => {
                return Err(cleanup_error);
            }
            (Ok(exit_status), Err(cleanup_error)) => {
                return Err(format!(
                    "cargo semver-checks for `{}` exited with {exit_status}; cleanup also failed: {cleanup_error}",
                    package.name
                ));
            }
            (Err(error), Ok(())) => return Err(error),
            (Err(error), Err(cleanup_error)) => {
                return Err(format!("{error}; cleanup also failed: {cleanup_error}"));
            }
        }
    }
    remove_dir_if_exists(&semver_root)?;
    Ok(())
}

#[derive(Debug)]
struct SemverPackage {
    name: String,
    manifest_path: String,
}

fn semver_package_names() -> Result<Vec<SemverPackage>, String> {
    let output = ProcessCommand::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("cargo metadata exited with {}", output.status));
    }

    let metadata: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!("failed to parse cargo metadata JSON for semver package discovery: {error}")
    })?;
    let workspace_root = std::env::current_dir().map_err(|error| error.to_string())?;
    let member_ids = metadata_array(&metadata, "workspace_members")?
        .iter()
        .map(required_string_value)
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut packages = Vec::new();
    for package in metadata_array(&metadata, "packages")? {
        let id = required_object_string(package, "id")?;
        if !member_ids.contains(id) || !package_has_library_target(package)? {
            continue;
        }
        let name = required_object_string(package, "name")?.to_owned();
        let manifest_path = required_object_string(package, "manifest_path")?;
        packages.push(SemverPackage {
            name,
            manifest_path: workspace_relative_path(&workspace_root, manifest_path),
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(packages)
}

fn metadata_array<'a>(metadata: &'a Value, field: &str) -> Result<&'a Vec<Value>, String> {
    metadata
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("cargo metadata response is missing `{field}` array"))
}

fn required_string_value(value: &Value) -> Result<String, String> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "cargo metadata array value is not a string".to_owned())
}

fn required_object_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("cargo metadata package is missing `{field}` string"))
}

fn package_has_library_target(package: &Value) -> Result<bool, String> {
    let targets = package
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata package is missing `targets` array".to_owned())?;
    for target in targets {
        let Some(kinds) = target.get("kind").and_then(Value::as_array) else {
            return Err("cargo metadata target is missing `kind` array".to_owned());
        };
        if kinds
            .iter()
            .filter_map(Value::as_str)
            .any(|kind| kind == "lib")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn workspace_relative_path(workspace_root: &Path, manifest_path: &str) -> String {
    let manifest_path = PathBuf::from(manifest_path);
    let relative_path = manifest_path
        .strip_prefix(workspace_root)
        .unwrap_or(manifest_path.as_path());
    relative_path.to_string_lossy().replace('\\', "/")
}

fn path_exists_at_revision(path: &str, revision: &str) -> Result<bool, String> {
    let object = format!("{revision}:{path}");
    let status = ProcessCommand::new("git")
        .args(["cat-file", "-e", &object])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    Ok(status.success())
}

fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn remove_dir_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove `{}`: {error}", path.display())),
    }
}

fn ensure_min_free_space(path: &Path, min_free_bytes: u64) -> Result<(), String> {
    let free_bytes = available_bytes(path)?;
    if free_bytes < min_free_bytes {
        return Err(format!(
            "insufficient free disk for semver-checks: {} available, {} required",
            human_bytes(free_bytes),
            human_bytes(min_free_bytes)
        ));
    }
    Ok(())
}

fn available_bytes(path: &Path) -> Result<u64, String> {
    let output = ProcessCommand::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("df exited with {}", output.status));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("df output was not valid UTF-8: {error}"))?;
    let data_line = stdout
        .lines()
        .nth(1)
        .ok_or_else(|| "df output did not include a data line".to_owned())?;
    let available_kib = data_line
        .split_whitespace()
        .nth(3)
        .ok_or_else(|| "df output did not include an available-space column".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("failed to parse df available-space column: {error}"))?;
    Ok(available_kib.saturating_mul(1024))
}

fn human_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1}GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    }
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = ProcessCommand::new(program)
        .args(args)
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{release_version_from_tag, select_semver_baseline};
    use semver::Version;

    #[test]
    fn release_tag_parser_accepts_descriptive_suffixes() {
        assert_eq!(
            release_version_from_tag("v0.6.0-aip-production-hardening"),
            Some(Version::new(0, 6, 0))
        );
        assert_eq!(release_version_from_tag("release-1.0.0"), None);
        assert_eq!(release_version_from_tag("v1.0"), None);
    }

    #[test]
    fn semver_baseline_is_the_latest_earlier_release() {
        let tags = [
            "v0.5.0-aip-native-lifecycle",
            "v1.0.0-preproduction",
            "v0.6.0-aip-production-hardening",
            "v1.0.0",
        ];
        assert_eq!(
            select_semver_baseline(&Version::new(1, 0, 0), tags),
            Some("v0.6.0-aip-production-hardening".to_owned())
        );
    }

    #[test]
    fn first_release_has_no_semver_baseline() {
        let tags = ["v0.1.0", "v0.2.0-plan"];
        assert_eq!(select_semver_baseline(&Version::new(0, 1, 0), tags), None);
    }

    #[test]
    fn canonical_release_wins_over_same_version_archive_tags() {
        let tags = [
            "v1.0.0-preproduction-a6ee5d0",
            "v1.0.0-rc1-5dd0595",
            "v1.0.0",
        ];
        assert_eq!(
            select_semver_baseline(&Version::new(1, 1, 0), tags),
            Some("v1.0.0".to_owned())
        );
    }
}
