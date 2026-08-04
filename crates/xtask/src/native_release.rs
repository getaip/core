//! Deterministic native release packaging and verification.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use getaip_distribution::{
    AIP_PROTOCOL_VERSION, Artifact, ArtifactFile, ArtifactKind, DEFAULT_RELEASE_ORIGIN,
    DISTRIBUTION_MANIFEST_SCHEMA_VERSION, DistributionManifest, GETAIP_SOFTWARE_VERSION, Platform,
    ReleaseChannel, ReleaseIdentity, SignatureEnvelope, SourceIdentity, TargetDistribution,
    default_release_network_policy, default_trust_store, extract_verified_archive, sha256_hex,
    verify_archive, verify_signed_manifest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};
use tar::{Archive, Builder, EntryType, Header};
use url::Url;

const MANIFEST_NAME: &str = "getaip-distribution-manifest.v1.json";
const SIGNATURE_NAME: &str = "getaip-distribution-manifest.v1.json.sig";
const CHECKSUMS_NAME: &str = "SHA256SUMS";
const PRODUCTION_MARKER_NAME: &str = "getaip-production-marker.v1.json";
const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseMetadata {
    schema_version: u32,
    getaip_version: String,
    aip_protocol_version: String,
    platform: Platform,
    rust_target: String,
    source_commit: String,
    source_tree: String,
    source_date_epoch: u64,
}

#[derive(Debug)]
struct ArchiveInput {
    relative_path: String,
    source: ArchiveSource,
    size: u64,
    sha256: String,
    executable: bool,
}

#[derive(Debug)]
enum ArchiveSource {
    File(PathBuf),
    Bytes(Vec<u8>),
}

/// Builds the four public native assets and signed-manifest fragment for one target.
pub fn package_native(
    rust_target: &str,
    cli_path: &Path,
    server_path: &Path,
    output: &Path,
    source_commit: &str,
    source_tree: &str,
    source_date_epoch: u64,
) -> Result<(), String> {
    let platform = platform_for_rust_target(rust_target)?;
    validate_git_object_id(source_commit, "source commit")?;
    validate_git_object_id(source_tree, "source tree")?;
    if source_date_epoch == 0 || source_date_epoch > u64::from(u32::MAX) {
        return Err("SOURCE_DATE_EPOCH must fit the reproducible gzip timestamp range".to_owned());
    }
    prepare_empty_output_directory(output)?;
    validate_release_binary(
        cli_path,
        "getaip",
        &format!("getaip {GETAIP_SOFTWARE_VERSION}"),
    )?;
    validate_release_binary(
        server_path,
        "getaip-server",
        &format!("getaip-server {GETAIP_SOFTWARE_VERSION}"),
    )?;

    let license = read_regular_bounded(&workspace_root()?.join("LICENSE"), MAX_METADATA_BYTES)?;
    let metadata = ReleaseMetadata {
        schema_version: 1,
        getaip_version: GETAIP_SOFTWARE_VERSION.to_owned(),
        aip_protocol_version: AIP_PROTOCOL_VERSION.to_owned(),
        platform,
        rust_target: rust_target.to_owned(),
        source_commit: source_commit.to_owned(),
        source_tree: source_tree.to_owned(),
        source_date_epoch,
    };
    let metadata_bytes = json_line(&metadata, "release metadata")?;
    let asset_label = platform.asset_label();

    let bootstrap_name = format!("getaip-{GETAIP_SOFTWARE_VERSION}-{asset_label}");
    let bootstrap_path = output.join(&bootstrap_name);
    copy_new_file(cli_path, &bootstrap_path, 0o755)?;
    let bootstrap = raw_artifact(&bootstrap_path, bootstrap_name)?;

    let cli_archive = build_archive_artifact(
        output,
        format!("getaip-{GETAIP_SOFTWARE_VERSION}-{asset_label}"),
        vec![
            archive_bytes("LICENSE", license.clone(), false),
            archive_bytes("RELEASE-METADATA.json", metadata_bytes.clone(), false),
            archive_file("bin/getaip", cli_path, true)?,
        ],
        source_date_epoch,
    )?;
    let server_archive = build_archive_artifact(
        output,
        format!("getaip-server-{GETAIP_SOFTWARE_VERSION}-{asset_label}"),
        vec![
            archive_bytes("LICENSE", license.clone(), false),
            archive_bytes("RELEASE-METADATA.json", metadata_bytes.clone(), false),
            archive_file("bin/getaip-server", server_path, true)?,
        ],
        source_date_epoch,
    )?;
    let distribution_archive = build_archive_artifact(
        output,
        format!("getaip-distribution-{GETAIP_SOFTWARE_VERSION}-{asset_label}"),
        vec![
            archive_bytes("LICENSE", license, false),
            archive_bytes("RELEASE-METADATA.json", metadata_bytes, false),
            archive_file("bin/getaip", cli_path, true)?,
            archive_file("bin/getaip-server", server_path, true)?,
        ],
        source_date_epoch,
    )?;

    let target = TargetDistribution {
        platform,
        rust_target: rust_target.to_owned(),
        minimum_platform_version: minimum_platform_version(platform).to_owned(),
        cli_version: GETAIP_SOFTWARE_VERSION.to_owned(),
        server_version: GETAIP_SOFTWARE_VERSION.to_owned(),
        bootstrap,
        cli_archive,
        server_archive,
        distribution_archive,
    };
    validate_target_fragment(&target)?;
    let fragment_path = output.join(fragment_name(platform));
    write_new_file(
        &fragment_path,
        &json_line(&target, "target fragment")?,
        0o644,
    )?;
    Ok(())
}

/// Combines four reviewed target fragments, signs exact manifest bytes, and writes checksums.
#[allow(clippy::too_many_arguments)]
pub fn assemble_native_manifest(
    directory: &Path,
    manifest_path: &Path,
    signature_path: &Path,
    signing_key_path: &Path,
    signing_key_id: &str,
    channel: &str,
    published_at: &str,
    previous_version: Option<&str>,
    gitea_commit: &str,
    gitea_tree: &str,
    github_commit: &str,
    github_tree: &str,
) -> Result<(), String> {
    validate_release_directory(directory)?;
    require_direct_child(manifest_path, directory, MANIFEST_NAME)?;
    require_direct_child(signature_path, directory, SIGNATURE_NAME)?;
    for (label, value) in [
        ("Gitea commit", gitea_commit),
        ("Gitea tree", gitea_tree),
        ("GitHub commit", github_commit),
        ("GitHub tree", github_tree),
    ] {
        validate_git_object_id(value, label)?;
    }
    let release_channel = parse_channel(channel)?;
    let targets = read_exact_target_fragments(directory)?;
    require_exact_target_assets(directory, &targets, false)?;
    verify_required_sboms(directory, &targets)?;

    let manifest = DistributionManifest {
        schema_version: DISTRIBUTION_MANIFEST_SCHEMA_VERSION,
        release: ReleaseIdentity {
            version: GETAIP_SOFTWARE_VERSION.to_owned(),
            aip_protocol_version: AIP_PROTOCOL_VERSION.to_owned(),
            channel: release_channel,
            published_at: published_at.to_owned(),
            minimum_cli_version: GETAIP_SOFTWARE_VERSION.to_owned(),
            source: SourceIdentity {
                gitea_commit: gitea_commit.to_owned(),
                gitea_tree: gitea_tree.to_owned(),
                github_commit: github_commit.to_owned(),
                github_tree: github_tree.to_owned(),
            },
        },
        signing_key_id: signing_key_id.to_owned(),
        network_policy: default_release_network_policy(),
        previous_version: previous_version.map(ToOwned::to_owned),
        targets,
    };
    manifest
        .validate()
        .map_err(|error| format!("distribution manifest is invalid: {error}"))?;
    let manifest_bytes = json_line(&manifest, "distribution manifest")?;
    let signing_key = read_signing_key(signing_key_path)?;
    let signature = signing_key.sign(&manifest_bytes);
    let envelope = SignatureEnvelope {
        schema_version: 1,
        key_id: signing_key_id.to_owned(),
        algorithm: "ed25519".to_owned(),
        signature: BASE64_STANDARD.encode(signature.to_bytes()),
    };
    let signature_bytes = json_line(&envelope, "signature envelope")?;
    let trust = default_trust_store()
        .map_err(|error| format!("failed to load the production release trust store: {error}"))?;
    verify_signed_manifest(&manifest_bytes, &signature_bytes, &trust).map_err(|error| {
        format!("external signing key does not produce a trusted release signature: {error}")
    })?;

    write_new_file(manifest_path, &manifest_bytes, 0o644)?;
    if let Err(error) = write_new_file(signature_path, &signature_bytes, 0o644) {
        let _ignored = fs::remove_file(manifest_path);
        return Err(error);
    }
    let checksums_path = directory.join(CHECKSUMS_NAME);
    let checksums = match build_checksums(directory, &manifest) {
        Ok(checksums) => checksums,
        Err(error) => {
            let _ignored = fs::remove_file(signature_path);
            let _ignored = fs::remove_file(manifest_path);
            return Err(error);
        }
    };
    if let Err(error) = write_new_file(&checksums_path, checksums.as_bytes(), 0o644) {
        let _ignored = fs::remove_file(signature_path);
        let _ignored = fs::remove_file(manifest_path);
        return Err(error);
    }
    Ok(())
}

/// Re-verifies the complete release candidate from only public trust material.
pub fn verify_native_release(
    directory: &Path,
    manifest_path: &Path,
    signature_path: &Path,
) -> Result<(), String> {
    validate_release_directory(directory)?;
    require_direct_child(manifest_path, directory, MANIFEST_NAME)?;
    require_direct_child(signature_path, directory, SIGNATURE_NAME)?;
    let manifest_bytes = read_regular_bounded(manifest_path, MAX_METADATA_BYTES)?;
    let signature_bytes = read_regular_bounded(signature_path, MAX_METADATA_BYTES)?;
    let trust = default_trust_store()
        .map_err(|error| format!("failed to load the production release trust store: {error}"))?;
    let verified = verify_signed_manifest(&manifest_bytes, &signature_bytes, &trust)
        .map_err(|error| format!("release manifest verification failed: {error}"))?;
    require_initial_matrix(&verified.manifest.targets)?;
    require_exact_target_assets(directory, &verified.manifest.targets, true)?;
    verify_required_sboms(directory, &verified.manifest.targets)?;

    for target in &verified.manifest.targets {
        verify_raw_artifact(directory, &target.bootstrap)?;
        for artifact in [
            &target.cli_archive,
            &target.server_archive,
            &target.distribution_archive,
        ] {
            verify_release_archive(
                directory,
                artifact,
                target,
                &verified.manifest.release.source,
            )?;
        }
    }
    verify_checksums(directory, &verified.manifest)?;
    let production_marker = directory.join(PRODUCTION_MARKER_NAME);
    if production_marker.exists() {
        verify_production_marker(directory, &production_marker, &verified.manifest)?;
    }
    verify_release_directory_allowlist(directory, &verified.manifest)?;
    Ok(())
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest directory has no workspace root".to_owned())
}

fn platform_for_rust_target(rust_target: &str) -> Result<Platform, String> {
    Platform::initial_release_matrix()
        .into_iter()
        .find(|platform| platform.rust_target() == rust_target)
        .ok_or_else(|| format!("unsupported native release target `{rust_target}`"))
}

const fn minimum_platform_version(platform: Platform) -> &'static str {
    match platform {
        Platform::DarwinArm64 | Platform::DarwinX64 => "macOS 13.0",
        Platform::LinuxArm64 | Platform::LinuxX64 => "Ubuntu 24.04 / glibc 2.39",
    }
}

fn validate_git_object_id(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must be a full lowercase 40-character Git object id"
        ))
    }
}

fn prepare_empty_output_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "artifact output `{}` must be a regular directory",
                    path.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|source| {
                format!(
                    "failed to create artifact output `{}`: {source}",
                    path.display()
                )
            })?;
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect artifact output `{}`: {error}",
                path.display()
            ));
        }
    }
    let mut entries = fs::read_dir(path).map_err(|error| {
        format!(
            "failed to read artifact output `{}`: {error}",
            path.display()
        )
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|error| {
            format!(
                "failed to read artifact output `{}`: {error}",
                path.display()
            )
        })?
        .is_some()
    {
        return Err(format!(
            "artifact output `{}` must be empty",
            path.display()
        ));
    }
    Ok(())
}

fn validate_release_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect release directory `{}`: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "release path `{}` must be a regular directory",
            path.display()
        ));
    }
    Ok(())
}

fn validate_release_binary(path: &Path, label: &str, expected_version: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect {label} binary `{}`: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "{label} binary `{}` must be a non-empty regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} binary exceeds the {MAX_INPUT_BYTES}-byte release limit"
        ));
    }
    if unix_mode(&metadata) & 0o111 == 0 {
        return Err(format!(
            "{label} binary `{}` is not executable",
            path.display()
        ));
    }
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|error| format!("failed to execute `{}` --version: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "`{}` --version exited with {}",
            path.display(),
            output.status
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("{label} --version output is not UTF-8"))?
        .trim();
    if stdout != expected_version {
        return Err(format!(
            "{label} --version returned `{stdout}`; expected `{expected_version}`"
        ));
    }
    Ok(())
}

fn archive_file(
    relative_path: &str,
    path: &Path,
    executable: bool,
) -> Result<ArchiveInput, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect archive input `{}`: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "archive input `{}` must be a non-empty regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!("archive input `{}` is too large", path.display()));
    }
    Ok(ArchiveInput {
        relative_path: relative_path.to_owned(),
        source: ArchiveSource::File(path.to_path_buf()),
        size: metadata.len(),
        sha256: sha256_file(path)?,
        executable,
    })
}

fn archive_bytes(relative_path: &str, bytes: Vec<u8>, executable: bool) -> ArchiveInput {
    ArchiveInput {
        relative_path: relative_path.to_owned(),
        size: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
        source: ArchiveSource::Bytes(bytes),
        executable,
    }
}

fn build_archive_artifact(
    output: &Path,
    root: String,
    mut inputs: Vec<ArchiveInput>,
    source_date_epoch: u64,
) -> Result<Artifact, String> {
    inputs.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut unique = BTreeSet::new();
    for input in &inputs {
        validate_relative_path(&input.relative_path)?;
        if !unique.insert(input.relative_path.as_str()) {
            return Err(format!("duplicate archive path `{}`", input.relative_path));
        }
    }
    let name = format!("{root}.tar.gz");
    let path = output.join(&name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("failed to create archive `{}`: {error}", path.display()))?;
    let gzip = GzBuilder::new()
        .mtime(source_date_epoch as u32)
        .write(file, Compression::best());
    let mut archive = Builder::new(gzip);
    archive.mode(tar::HeaderMode::Deterministic);
    for input in &inputs {
        append_archive_input(&mut archive, &root, input, source_date_epoch)?;
    }
    let gzip = archive
        .into_inner()
        .map_err(|error| format!("failed to finish tar archive `{name}`: {error}"))?;
    let file = gzip
        .finish()
        .map_err(|error| format!("failed to finish gzip archive `{name}`: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync archive `{name}`: {error}"))?;

    let artifact_files = inputs
        .into_iter()
        .map(|input| ArtifactFile {
            path: input.relative_path,
            sha256: input.sha256,
            executable: input.executable,
        })
        .collect();
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("failed to inspect archive `{name}`: {error}"))?;
    Ok(Artifact {
        name: name.clone(),
        kind: ArtifactKind::TarGz,
        url: release_url(&name)?,
        size: metadata.len(),
        sha256: sha256_file(&path)?,
        archive_root: Some(root),
        files: artifact_files,
    })
}

fn append_archive_input(
    archive: &mut Builder<flate2::write::GzEncoder<File>>,
    root: &str,
    input: &ArchiveInput,
    source_date_epoch: u64,
) -> Result<(), String> {
    let archive_path = format!("{root}/{}", input.relative_path);
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(input.size);
    header.set_mode(if input.executable { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(source_date_epoch);
    header
        .set_path(&archive_path)
        .map_err(|error| format!("failed to encode archive path `{archive_path}`: {error}"))?;
    header.set_cksum();
    match &input.source {
        ArchiveSource::File(path) => {
            let mut file = File::open(path).map_err(|error| {
                format!("failed to open archive input `{}`: {error}", path.display())
            })?;
            archive
                .append(&header, &mut file)
                .map_err(|error| format!("failed to append `{archive_path}`: {error}"))?;
        }
        ArchiveSource::Bytes(bytes) => archive
            .append(&header, bytes.as_slice())
            .map_err(|error| format!("failed to append `{archive_path}`: {error}"))?,
    }
    Ok(())
}

fn raw_artifact(path: &Path, name: String) -> Result<Artifact, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to inspect bootstrap `{}`: {error}", path.display()))?;
    Ok(Artifact {
        name: name.clone(),
        kind: ArtifactKind::RawExecutable,
        url: release_url(&name)?,
        size: metadata.len(),
        sha256: sha256_file(path)?,
        archive_root: None,
        files: Vec::new(),
    })
}

fn release_url(name: &str) -> Result<Url, String> {
    Url::parse(&format!(
        "{DEFAULT_RELEASE_ORIGIN}v{GETAIP_SOFTWARE_VERSION}/{name}"
    ))
    .map_err(|error| format!("failed to construct release URL: {error}"))
}

fn validate_target_fragment(target: &TargetDistribution) -> Result<(), String> {
    let manifest = DistributionManifest {
        schema_version: DISTRIBUTION_MANIFEST_SCHEMA_VERSION,
        release: ReleaseIdentity {
            version: GETAIP_SOFTWARE_VERSION.to_owned(),
            aip_protocol_version: AIP_PROTOCOL_VERSION.to_owned(),
            channel: ReleaseChannel::Development,
            published_at: "2026-01-01T00:00:00Z".to_owned(),
            minimum_cli_version: GETAIP_SOFTWARE_VERSION.to_owned(),
            source: SourceIdentity {
                gitea_commit: "0".repeat(40),
                gitea_tree: "1".repeat(40),
                github_commit: "2".repeat(40),
                github_tree: "3".repeat(40),
            },
        },
        signing_key_id: "fragment-validation".to_owned(),
        network_policy: default_release_network_policy(),
        previous_version: None,
        targets: vec![target.clone()],
    };
    manifest
        .validate()
        .map_err(|error| format!("target fragment is invalid: {error}"))
}

fn fragment_name(platform: Platform) -> String {
    format!("target-distribution-{}.json", platform.asset_label())
}

fn sbom_name(platform: Platform) -> String {
    format!(
        "getaip-sbom-{GETAIP_SOFTWARE_VERSION}-{}.spdx.json",
        platform.asset_label()
    )
}

fn parse_channel(value: &str) -> Result<ReleaseChannel, String> {
    match value {
        "stable" => Ok(ReleaseChannel::Stable),
        "release-candidate" => Ok(ReleaseChannel::ReleaseCandidate),
        "development" => Ok(ReleaseChannel::Development),
        _ => Err(format!("unsupported release channel `{value}`")),
    }
}

fn read_exact_target_fragments(directory: &Path) -> Result<Vec<TargetDistribution>, String> {
    let mut targets = Vec::new();
    let expected = Platform::initial_release_matrix()
        .into_iter()
        .map(fragment_name)
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("failed to list `{}`: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("failed to read release entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "release directory contains a non-UTF-8 filename".to_owned())?;
        if name.starts_with("target-distribution-") && name.ends_with(".json") {
            actual.insert(name);
        }
    }
    if actual != expected {
        return Err(format!(
            "target fragments differ from the exact four-target matrix: expected {expected:?}, found {actual:?}"
        ));
    }
    for platform in Platform::initial_release_matrix() {
        let path = directory.join(fragment_name(platform));
        let bytes = read_regular_bounded(&path, MAX_METADATA_BYTES)?;
        let target: TargetDistribution = serde_json::from_slice(&bytes)
            .map_err(|error| format!("target fragment `{}` is invalid: {error}", path.display()))?;
        if target.platform != platform {
            return Err(format!(
                "target fragment `{}` declares the wrong platform",
                path.display()
            ));
        }
        validate_target_fragment(&target)?;
        targets.push(target);
    }
    Ok(targets)
}

fn require_initial_matrix(targets: &[TargetDistribution]) -> Result<(), String> {
    let expected = Platform::initial_release_matrix()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual = targets
        .iter()
        .map(|target| target.platform)
        .collect::<BTreeSet<_>>();
    if targets.len() != expected.len() || actual != expected {
        return Err(
            "signed manifest does not contain the exact initial four-target matrix".to_owned(),
        );
    }
    Ok(())
}

fn require_exact_target_assets(
    directory: &Path,
    targets: &[TargetDistribution],
    verify_archives_now: bool,
) -> Result<(), String> {
    require_initial_matrix(targets)?;
    for target in targets {
        let raw = directory.join(&target.bootstrap.name);
        verify_raw_artifact(directory, &target.bootstrap)?;
        if !raw.exists() {
            return Err(format!("missing bootstrap `{}`", raw.display()));
        }
        for artifact in [
            &target.cli_archive,
            &target.server_archive,
            &target.distribution_archive,
        ] {
            let path = directory.join(&artifact.name);
            if verify_archives_now {
                verify_archive(&path, artifact).map_err(|error| {
                    format!("archive `{}` failed verification: {error}", artifact.name)
                })?;
            } else {
                verify_regular_digest(&path, artifact.size, &artifact.sha256)?;
            }
        }
    }
    Ok(())
}

fn verify_raw_artifact(directory: &Path, artifact: &Artifact) -> Result<(), String> {
    if artifact.kind != ArtifactKind::RawExecutable {
        return Err(format!(
            "bootstrap `{}` is not a raw executable",
            artifact.name
        ));
    }
    let path = directory.join(&artifact.name);
    verify_regular_digest(&path, artifact.size, &artifact.sha256)?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("failed to inspect bootstrap `{}`: {error}", path.display()))?;
    if unix_mode(&metadata) != 0o755 {
        return Err(format!(
            "bootstrap `{}` must have mode 0755",
            path.display()
        ));
    }
    Ok(())
}

fn verify_release_archive(
    directory: &Path,
    artifact: &Artifact,
    target: &TargetDistribution,
    source: &SourceIdentity,
) -> Result<(), String> {
    let path = directory.join(&artifact.name);
    verify_archive(&path, artifact)
        .map_err(|error| format!("archive `{}` failed verification: {error}", artifact.name))?;
    let temporary = tempfile::tempdir()
        .map_err(|error| format!("failed to create archive verification directory: {error}"))?;
    extract_verified_archive(&path, artifact, temporary.path()).map_err(|error| {
        format!(
            "archive `{}` failed strict extraction: {error}",
            artifact.name
        )
    })?;
    let metadata_path = temporary.path().join("RELEASE-METADATA.json");
    let metadata_bytes = read_regular_bounded(&metadata_path, MAX_METADATA_BYTES)?;
    let metadata: ReleaseMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
        format!(
            "archive `{}` release metadata is invalid: {error}",
            artifact.name
        )
    })?;
    if metadata.getaip_version != GETAIP_SOFTWARE_VERSION
        || metadata.aip_protocol_version != AIP_PROTOCOL_VERSION
        || metadata.platform != target.platform
        || metadata.rust_target != target.rust_target
        || metadata.source_commit != source.github_commit
        || metadata.source_tree != source.github_tree
    {
        return Err(format!(
            "archive `{}` release metadata identity differs from its target",
            artifact.name
        ));
    }
    inspect_deterministic_tar(&path, artifact, metadata.source_date_epoch)?;
    Ok(())
}

fn inspect_deterministic_tar(
    path: &Path,
    artifact: &Artifact,
    source_date_epoch: u64,
) -> Result<(), String> {
    let root = artifact
        .archive_root
        .as_deref()
        .ok_or_else(|| format!("archive `{}` has no root", artifact.name))?;
    let expected = artifact
        .files
        .iter()
        .map(|file| (format!("{root}/{}", file.path), file))
        .collect::<BTreeMap<_, _>>();
    let file = File::open(path)
        .map_err(|error| format!("failed to open archive `{}`: {error}", path.display()))?;
    let mut archive = Archive::new(GzDecoder::new(file));
    let mut actual_order = Vec::new();
    for entry in archive
        .entries()
        .map_err(|error| format!("failed to read archive `{}`: {error}", path.display()))?
    {
        let entry = entry.map_err(|error| format!("failed to read archive entry: {error}"))?;
        let header = entry.header();
        let entry_path = entry
            .path()
            .map_err(|error| format!("failed to read archive path: {error}"))?
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| "archive path is not UTF-8".to_owned())?;
        let expected_file = expected
            .get(&entry_path)
            .ok_or_else(|| format!("archive contains undeclared path `{entry_path}`"))?;
        if !header.entry_type().is_file()
            || header.uid().map_err(|error| error.to_string())? != 0
            || header.gid().map_err(|error| error.to_string())? != 0
            || header.mtime().map_err(|error| error.to_string())? != source_date_epoch
            || header.mode().map_err(|error| error.to_string())?
                != if expected_file.executable {
                    0o755
                } else {
                    0o644
                }
        {
            return Err(format!(
                "archive entry `{entry_path}` has non-deterministic metadata"
            ));
        }
        actual_order.push(entry_path);
    }
    let expected_order = expected.keys().cloned().collect::<Vec<_>>();
    if actual_order != expected_order {
        return Err(format!(
            "archive `{}` entries are not in deterministic path order",
            artifact.name
        ));
    }
    Ok(())
}

fn verify_required_sboms(directory: &Path, targets: &[TargetDistribution]) -> Result<(), String> {
    for target in targets {
        let name = sbom_name(target.platform);
        let path = directory.join(&name);
        let bytes = read_regular_bounded(&path, MAX_METADATA_BYTES)?;
        let sbom: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("SBOM `{name}` is invalid JSON: {error}"))?;
        let spdx_version = sbom
            .get("spdxVersion")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("SBOM `{name}` omits spdxVersion"))?;
        if !spdx_version.starts_with("SPDX-") {
            return Err(format!("SBOM `{name}` has an invalid SPDX version"));
        }
        if sbom
            .get("packages")
            .and_then(serde_json::Value::as_array)
            .is_none()
        {
            return Err(format!("SBOM `{name}` omits the SPDX packages array"));
        }
    }
    Ok(())
}

fn build_checksums(directory: &Path, manifest: &DistributionManifest) -> Result<String, String> {
    let names = public_release_names(manifest);
    let mut output = String::new();
    for name in names {
        let digest = sha256_file(&directory.join(&name))?;
        output.push_str(&format!("{digest}  {name}\n"));
    }
    Ok(output)
}

fn public_release_names(manifest: &DistributionManifest) -> BTreeSet<String> {
    let mut names = BTreeSet::from([MANIFEST_NAME.to_owned(), SIGNATURE_NAME.to_owned()]);
    for target in &manifest.targets {
        names.extend([
            target.bootstrap.name.clone(),
            target.cli_archive.name.clone(),
            target.server_archive.name.clone(),
            target.distribution_archive.name.clone(),
            sbom_name(target.platform),
        ]);
    }
    names
}

fn verify_checksums(directory: &Path, manifest: &DistributionManifest) -> Result<(), String> {
    let expected = build_checksums(directory, manifest)?;
    let actual = read_regular_bounded(&directory.join(CHECKSUMS_NAME), MAX_METADATA_BYTES)?;
    if actual != expected.as_bytes() {
        return Err("SHA256SUMS does not exactly match the signed release assets".to_owned());
    }
    Ok(())
}

fn verify_release_directory_allowlist(
    directory: &Path,
    manifest: &DistributionManifest,
) -> Result<(), String> {
    let mut allowed = public_release_names(manifest);
    allowed.insert(CHECKSUMS_NAME.to_owned());
    if directory.join(PRODUCTION_MARKER_NAME).exists() {
        allowed.insert(PRODUCTION_MARKER_NAME.to_owned());
    }
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("failed to list release directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("failed to read release entry: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("failed to inspect release entry: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "release entry `{}` is not a regular file",
                entry.path().display()
            ));
        }
        actual.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "release directory contains a non-UTF-8 filename".to_owned())?,
        );
    }
    if actual != allowed {
        return Err(format!(
            "release directory differs from its exact allowlist: {actual:?}"
        ));
    }
    Ok(())
}

fn verify_production_marker(
    directory: &Path,
    path: &Path,
    manifest: &DistributionManifest,
) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(&read_regular_bounded(path, MAX_METADATA_BYTES)?)
            .map_err(|error| format!("production marker is invalid JSON: {error}"))?;
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some("org.getaip.release.production-marker.v1")
        || value.get("status").and_then(serde_json::Value::as_str) != Some("production")
    {
        return Err("production marker has an invalid schema or status".to_owned());
    }
    for (pointer, expected) in [
        ("/release/version", manifest.release.version.as_str()),
        (
            "/release/aip_protocol_version",
            manifest.release.aip_protocol_version.as_str(),
        ),
        (
            "/source/gitea_commit",
            manifest.release.source.gitea_commit.as_str(),
        ),
        (
            "/source/gitea_tree",
            manifest.release.source.gitea_tree.as_str(),
        ),
        (
            "/source/github_commit",
            manifest.release.source.github_commit.as_str(),
        ),
        (
            "/source/github_tree",
            manifest.release.source.github_tree.as_str(),
        ),
    ] {
        if value.pointer(pointer).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(format!(
                "production marker identity mismatch at `{pointer}`"
            ));
        }
    }
    let expected_manifest = sha256_file(&directory.join(MANIFEST_NAME))?;
    let expected_signature = sha256_file(&directory.join(SIGNATURE_NAME))?;
    let expected_checksums = sha256_file(&directory.join(CHECKSUMS_NAME))?;
    for (pointer, expected) in [
        ("/native/manifest_sha256", expected_manifest.as_str()),
        (
            "/native/manifest_signature_sha256",
            expected_signature.as_str(),
        ),
        ("/native/checksums_sha256", expected_checksums.as_str()),
    ] {
        if value.pointer(pointer).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(format!("production marker digest mismatch at `{pointer}`"));
        }
    }
    let expected_assets = build_checksums(directory, manifest)?;
    let actual_assets = value
        .pointer("/native/assets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "production marker omits native assets".to_owned())?;
    let mut marker_checksums = String::new();
    for asset in actual_assets {
        let name = asset
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "production marker asset omits name".to_owned())?;
        let digest = asset
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "production marker asset omits digest".to_owned())?;
        marker_checksums.push_str(&format!("{digest}  {name}\n"));
    }
    if marker_checksums != expected_assets {
        return Err("production marker native assets differ from SHA256SUMS".to_owned());
    }
    for pointer in ["/npm", "/containers", "/qualification/native"] {
        if value
            .pointer(pointer)
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return Err(format!("production marker has no evidence at `{pointer}`"));
        }
    }
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect release signing key: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("release signing key must be a regular non-symlink file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err("release signing key has an invalid size".to_owned());
    }
    if unix_mode(&metadata) != 0o600 {
        return Err("release signing key must have mode 0600".to_owned());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read release signing key: {error}"))?;
    let pem = std::str::from_utf8(&bytes)
        .map_err(|_| "release signing key is not UTF-8 PKCS#8 PEM".to_owned())?;
    SigningKey::from_pkcs8_pem(pem)
        .map_err(|error| format!("release signing key is not valid Ed25519 PKCS#8 PEM: {error}"))
}

fn require_direct_child(path: &Path, directory: &Path, expected_name: &str) -> Result<(), String> {
    if path.parent() != Some(directory)
        || path.file_name().and_then(|value| value.to_str()) != Some(expected_name)
    {
        return Err(format!(
            "release metadata path must be exactly `{}`",
            directory.join(expected_name).display()
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || value.contains('\\')
        || value.contains("//")
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe archive path `{value}`"));
    }
    Ok(())
}

fn json_line<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_regular_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect `{}`: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "`{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > maximum {
        return Err(format!(
            "`{}` exceeds its {maximum}-byte limit",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("failed to read `{}`: {error}", path.display()))
}

fn copy_new_file(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    let mut input = File::open(source)
        .map_err(|error| format!("failed to open `{}`: {error}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("failed to create `{}`: {error}", destination.display()))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| format!("failed to copy `{}`: {error}", destination.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("failed to sync `{}`: {error}", destination.display()))?;
    set_mode(destination, mode)?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create `{}`: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write `{}`: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync `{}`: {error}", path.display()))?;
    set_mode(path, mode)
}

fn verify_regular_digest(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect `{}`: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "`{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() != expected_size {
        return Err(format!("`{}` has the wrong size", path.display()));
    }
    let actual = sha256_file(path)?;
    if actual != expected_sha256 {
        return Err(format!("`{}` has the wrong SHA-256 digest", path.display()));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("failed to open `{}` for hashing: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash `{}`: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("failed to set mode on `{}`: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("native GetAIP releases are supported only on Unix hosts".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn native_archives_are_reproducible() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir()?;
        let cli = temporary.path().join("getaip");
        let server = temporary.path().join("getaip-server");
        fs::write(
            &cli,
            format!("#!/bin/sh\nprintf 'getaip {GETAIP_SOFTWARE_VERSION}\\n'\n"),
        )?;
        fs::write(
            &server,
            format!("#!/bin/sh\nprintf 'getaip-server {GETAIP_SOFTWARE_VERSION}\\n'\n"),
        )?;
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&server, fs::Permissions::from_mode(0o755))?;
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        for output in [&first, &second] {
            package_native(
                "x86_64-unknown-linux-gnu",
                &cli,
                &server,
                output,
                &"a".repeat(40),
                &"b".repeat(40),
                1_700_000_000,
            )?;
        }
        let fragment: TargetDistribution =
            serde_json::from_slice(&fs::read(first.join("target-distribution-linux-x64.json"))?)?;
        for artifact in [
            fragment.cli_archive,
            fragment.server_archive,
            fragment.distribution_archive,
        ] {
            assert_eq!(
                fs::read(first.join(&artifact.name))?,
                fs::read(second.join(&artifact.name))?
            );
        }
        Ok(())
    }

    #[test]
    fn unsupported_target_is_rejected() {
        assert!(platform_for_rust_target("x86_64-pc-windows-msvc").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_external_key_assembles_a_complete_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let Some(signing_key) = std::env::var_os("GETAIP_TEST_SIGNING_KEY_PATH") else {
            return Ok(());
        };
        let temporary = tempfile::tempdir()?;
        let cli = temporary.path().join("getaip");
        let server = temporary.path().join("getaip-server");
        fs::write(
            &cli,
            format!("#!/bin/sh\nprintf 'getaip {GETAIP_SOFTWARE_VERSION}\\n'\n"),
        )?;
        fs::write(
            &server,
            format!("#!/bin/sh\nprintf 'getaip-server {GETAIP_SOFTWARE_VERSION}\\n'\n"),
        )?;
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&server, fs::Permissions::from_mode(0o755))?;

        let candidate = temporary.path().join("candidate");
        fs::create_dir(&candidate)?;
        for platform in Platform::initial_release_matrix() {
            let target_output = temporary.path().join(platform.asset_label());
            package_native(
                platform.rust_target(),
                &cli,
                &server,
                &target_output,
                &"a".repeat(40),
                &"b".repeat(40),
                1_700_000_000,
            )?;
            for entry in fs::read_dir(target_output)? {
                let entry = entry?;
                fs::copy(entry.path(), candidate.join(entry.file_name()))?;
            }
            fs::write(
                candidate.join(sbom_name(platform)),
                b"{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[]}\n",
            )?;
        }
        for platform in Platform::initial_release_matrix() {
            fs::set_permissions(
                candidate.join(format!(
                    "getaip-{GETAIP_SOFTWARE_VERSION}-{}",
                    platform.asset_label()
                )),
                fs::Permissions::from_mode(0o755),
            )?;
        }
        let manifest = candidate.join(MANIFEST_NAME);
        let signature = candidate.join(SIGNATURE_NAME);
        assemble_native_manifest(
            &candidate,
            &manifest,
            &signature,
            Path::new(&signing_key),
            "getaip-release-2026-01-5e8a972bae4003e8",
            "development",
            "2026-08-04T00:00:00Z",
            None,
            &"c".repeat(40),
            &"d".repeat(40),
            &"a".repeat(40),
            &"b".repeat(40),
        )?;
        for platform in Platform::initial_release_matrix() {
            fs::remove_file(candidate.join(fragment_name(platform)))?;
        }
        verify_native_release(&candidate, &manifest, &signature)?;
        Ok(())
    }
}
