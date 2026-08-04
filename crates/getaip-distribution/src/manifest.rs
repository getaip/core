use crate::{
    AIP_PROTOCOL_VERSION, DEFAULT_RELEASE_ORIGIN, DISTRIBUTION_MANIFEST_SCHEMA_VERSION,
    GITHUB_RELEASE_REDIRECT_HOST, Platform, RELEASE_NETWORK_POLICY_SCHEMA_VERSION,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const MAX_ARTIFACT_SIZE: u64 = 1024 * 1024 * 1024;
const TRUST_STORE_JSON: &str =
    include_str!("../../../release/getaip-distribution-trusted-keys.json");

/// Signed GetAIP distribution manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Release identity shared by every artifact.
    pub release: ReleaseIdentity,
    /// Key that must have signed the exact manifest bytes.
    pub signing_key_id: String,
    /// Signed network boundary needed to retrieve GitHub release assets.
    pub network_policy: ReleaseNetworkPolicy,
    /// Previous release eligible for automatic rollback.
    pub previous_version: Option<String>,
    /// Exact target distributions.
    pub targets: Vec<TargetDistribution>,
}

/// Signed, versioned network policy for GitHub release retrieval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseNetworkPolicy {
    /// Network-policy schema version.
    pub schema_version: u32,
    /// Maximum number of redirects from an exact approved release URL.
    pub maximum_redirects: u8,
    /// Exact HTTPS hosts that may receive the single redirect.
    pub redirect_hosts: Vec<String>,
}

/// Release identity bound into the distribution manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    /// GetAIP software version.
    pub version: String,
    /// AIP protocol version, which remains independent from software version.
    pub aip_protocol_version: String,
    /// Immutable release channel.
    pub channel: ReleaseChannel,
    /// RFC 3339 publication time.
    pub published_at: String,
    /// Minimum native CLI capable of interpreting this manifest.
    pub minimum_cli_version: String,
    /// Exact canonical and public source identities.
    pub source: SourceIdentity,
}

/// Allowed distribution release channel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseChannel {
    /// Public stable release.
    Stable,
    /// Reviewed release candidate.
    ReleaseCandidate,
    /// Non-production development fixture.
    Development,
}

/// Source identities for canonical Gitea and filtered GitHub publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Canonical Gitea commit.
    pub gitea_commit: String,
    /// Canonical Gitea tree.
    pub gitea_tree: String,
    /// Public code-only GitHub commit.
    pub github_commit: String,
    /// Public code-only GitHub tree.
    pub github_tree: String,
}

/// Complete distribution for one qualified platform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDistribution {
    /// Stable platform label.
    pub platform: Platform,
    /// Exact Rust target used to build the artifacts.
    pub rust_target: String,
    /// Minimum supported platform version.
    pub minimum_platform_version: String,
    /// Exact compatible CLI version.
    pub cli_version: String,
    /// Exact compatible server version.
    pub server_version: String,
    /// Raw native CLI used only for npm bootstrap handoff.
    pub bootstrap: Artifact,
    /// Standalone CLI archive.
    pub cli_archive: Artifact,
    /// Standalone server archive.
    pub server_archive: Artifact,
    /// Atomic CLI plus server installation archive.
    pub distribution_archive: Artifact,
}

/// Immutable release artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Exact release-asset filename.
    pub name: String,
    /// Artifact encoding and activation behavior.
    pub kind: ArtifactKind,
    /// Approved HTTPS release URL.
    pub url: Url,
    /// Exact byte size.
    pub size: u64,
    /// Lowercase hexadecimal SHA-256 digest.
    pub sha256: String,
    /// Single safe archive root for compressed artifacts.
    pub archive_root: Option<String>,
    /// Exact extracted file allowlist.
    pub files: Vec<ArtifactFile>,
}

/// Supported release artifact kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// Raw executable used by the npm bootstrap.
    RawExecutable,
    /// Gzip-compressed tar archive.
    TarGz,
}

/// One allowed file inside a release archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    /// Relative path below the archive root.
    pub path: String,
    /// Lowercase hexadecimal SHA-256 digest of the extracted file.
    pub sha256: String,
    /// Whether activation requires executable permissions.
    pub executable: bool,
}

/// Detached signature envelope. The signature covers exact manifest bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    /// Signature-envelope schema version.
    pub schema_version: u32,
    /// Trust-store key identifier.
    pub key_id: String,
    /// Signature algorithm, currently exactly `ed25519`.
    pub algorithm: String,
    /// Base64 Ed25519 signature.
    pub signature: String,
}

/// Checked-in public verification key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    /// Stable key identifier.
    pub key_id: String,
    /// Signature algorithm.
    pub algorithm: String,
    /// Base64 raw Ed25519 public key.
    pub public_key_base64: String,
    /// Whether releases must reject this key.
    pub revoked: bool,
}

/// Versioned GetAIP release trust store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustStore {
    keys: BTreeMap<String, TrustedKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStoreDocument {
    schema_version: u32,
    keys: Vec<TrustedKey>,
}

/// Manifest whose exact bytes and typed contents have both been verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifest {
    /// Parsed manifest.
    pub manifest: DistributionManifest,
    /// Digest of the exact signed bytes.
    pub manifest_sha256: String,
    /// Key that verified the detached signature.
    pub signing_key_id: String,
    /// Exact manifest bytes covered by the detached signature.
    pub signed_manifest_bytes: Vec<u8>,
    /// Exact detached-signature envelope bytes.
    pub signature_envelope_bytes: Vec<u8>,
}

impl TrustStore {
    /// Parses a versioned trust-store document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let document: TrustStoreDocument = serde_json::from_slice(bytes)?;
        if document.schema_version != 1 {
            return Err(ManifestError::UnsupportedTrustStoreSchema(
                document.schema_version,
            ));
        }
        let mut keys = BTreeMap::new();
        for key in document.keys {
            validate_safe_identifier(&key.key_id, "trust key id")?;
            if key.algorithm != "ed25519" {
                return Err(ManifestError::UnsupportedSignatureAlgorithm(key.algorithm));
            }
            decode_verifying_key(&key)?;
            if keys.insert(key.key_id.clone(), key).is_some() {
                return Err(ManifestError::DuplicateTrustKey);
            }
        }
        if keys.is_empty() {
            return Err(ManifestError::EmptyTrustStore);
        }
        Ok(Self { keys })
    }

    fn key(&self, key_id: &str) -> Result<&TrustedKey, ManifestError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| ManifestError::UntrustedKey(key_id.to_owned()))?;
        if key.revoked {
            return Err(ManifestError::RevokedKey(key_id.to_owned()));
        }
        Ok(key)
    }
}

/// Loads the checked-in production public trust set.
pub fn default_trust_store() -> Result<TrustStore, ManifestError> {
    TrustStore::from_json(TRUST_STORE_JSON.as_bytes())
}

/// Verifies a detached signature before parsing and validating a manifest.
pub fn verify_signed_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trust_store: &TrustStore,
) -> Result<VerifiedManifest, ManifestError> {
    let envelope: SignatureEnvelope = serde_json::from_slice(signature_bytes)?;
    if envelope.schema_version != 1 {
        return Err(ManifestError::UnsupportedSignatureSchema(
            envelope.schema_version,
        ));
    }
    if envelope.algorithm != "ed25519" {
        return Err(ManifestError::UnsupportedSignatureAlgorithm(
            envelope.algorithm,
        ));
    }
    let trusted_key = trust_store.key(&envelope.key_id)?;
    let verifying_key = decode_verifying_key(trusted_key)?;
    let decoded_signature = BASE64_STANDARD
        .decode(envelope.signature.as_bytes())
        .map_err(|error| ManifestError::InvalidSignatureEncoding(error.to_string()))?;
    let signature = Signature::try_from(decoded_signature.as_slice())
        .map_err(|error| ManifestError::InvalidSignatureEncoding(error.to_string()))?;
    verifying_key
        .verify_strict(manifest_bytes, &signature)
        .map_err(|_| ManifestError::SignatureVerificationFailed)?;

    let manifest: DistributionManifest = serde_json::from_slice(manifest_bytes)?;
    if manifest.signing_key_id != envelope.key_id {
        return Err(ManifestError::SigningKeyMismatch {
            manifest: manifest.signing_key_id,
            signature: envelope.key_id,
        });
    }
    manifest.validate()?;
    Ok(VerifiedManifest {
        manifest,
        manifest_sha256: sha256_hex(manifest_bytes),
        signing_key_id: trusted_key.key_id.clone(),
        signed_manifest_bytes: manifest_bytes.to_vec(),
        signature_envelope_bytes: signature_bytes.to_vec(),
    })
}

impl DistributionManifest {
    /// Validates release identity, target uniqueness, compatibility, and every artifact.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != DISTRIBUTION_MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedManifestSchema(
                self.schema_version,
            ));
        }
        let version = Version::parse(&self.release.version)
            .map_err(|error| ManifestError::InvalidVersion(error.to_string()))?;
        let minimum_cli_version = Version::parse(&self.release.minimum_cli_version)
            .map_err(|error| ManifestError::InvalidVersion(error.to_string()))?;
        if minimum_cli_version > version {
            return Err(ManifestError::MinimumCliExceedsRelease);
        }
        if self.release.aip_protocol_version != AIP_PROTOCOL_VERSION {
            return Err(ManifestError::ProtocolVersionChanged(
                self.release.aip_protocol_version.clone(),
            ));
        }
        OffsetDateTime::parse(&self.release.published_at, &Rfc3339)
            .map_err(|error| ManifestError::InvalidPublishedAt(error.to_string()))?;
        validate_git_identity(&self.release.source)?;
        validate_safe_identifier(&self.signing_key_id, "manifest signing key id")?;
        self.network_policy.validate()?;
        if let Some(previous) = self.previous_version.as_deref() {
            let previous = Version::parse(previous)
                .map_err(|error| ManifestError::InvalidVersion(error.to_string()))?;
            if previous >= version {
                return Err(ManifestError::InvalidPreviousVersion);
            }
        }
        if self.targets.is_empty() {
            return Err(ManifestError::NoTargets);
        }
        let mut platforms = BTreeSet::new();
        for target in &self.targets {
            if !platforms.insert(target.platform) {
                return Err(ManifestError::DuplicatePlatform(target.platform));
            }
            target.validate(&self.release.version)?;
        }
        Ok(())
    }

    /// Returns the exact distribution for a detected platform.
    pub fn target(&self, platform: Platform) -> Result<&TargetDistribution, ManifestError> {
        self.targets
            .iter()
            .find(|target| target.platform == platform)
            .ok_or(ManifestError::PlatformNotInManifest(platform))
    }
}

impl ReleaseNetworkPolicy {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != RELEASE_NETWORK_POLICY_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedNetworkPolicySchema(
                self.schema_version,
            ));
        }
        if self.maximum_redirects != 1 {
            return Err(ManifestError::InvalidMaximumRedirects(
                self.maximum_redirects,
            ));
        }
        if self.redirect_hosts.as_slice() != [GITHUB_RELEASE_REDIRECT_HOST] {
            return Err(ManifestError::UnapprovedRedirectHosts(
                self.redirect_hosts.clone(),
            ));
        }
        Ok(())
    }
}

/// Returns the only network policy understood by the first GetAIP release.
#[must_use]
pub fn default_release_network_policy() -> ReleaseNetworkPolicy {
    ReleaseNetworkPolicy {
        schema_version: RELEASE_NETWORK_POLICY_SCHEMA_VERSION,
        maximum_redirects: 1,
        redirect_hosts: vec![GITHUB_RELEASE_REDIRECT_HOST.to_owned()],
    }
}

impl TargetDistribution {
    fn validate(&self, version: &str) -> Result<(), ManifestError> {
        if self.rust_target != self.platform.rust_target() {
            return Err(ManifestError::RustTargetMismatch(self.platform));
        }
        if self.minimum_platform_version.trim().is_empty() {
            return Err(ManifestError::MissingMinimumPlatformVersion(self.platform));
        }
        if self.cli_version != version || self.server_version != version {
            return Err(ManifestError::IncompatibleComponentVersions(self.platform));
        }
        let asset = self.platform.asset_label();
        self.bootstrap.validate(
            version,
            &format!("getaip-{version}-{asset}"),
            ArtifactKind::RawExecutable,
            &[],
        )?;
        self.cli_archive.validate(
            version,
            &format!("getaip-{version}-{asset}.tar.gz"),
            ArtifactKind::TarGz,
            &["bin/getaip"],
        )?;
        self.server_archive.validate(
            version,
            &format!("getaip-server-{version}-{asset}.tar.gz"),
            ArtifactKind::TarGz,
            &["bin/getaip-server"],
        )?;
        self.distribution_archive.validate(
            version,
            &format!("getaip-distribution-{version}-{asset}.tar.gz"),
            ArtifactKind::TarGz,
            &["bin/getaip", "bin/getaip-server"],
        )
    }
}

impl Artifact {
    fn validate(
        &self,
        version: &str,
        expected_name: &str,
        expected_kind: ArtifactKind,
        required_files: &[&str],
    ) -> Result<(), ManifestError> {
        if self.name != expected_name {
            return Err(ManifestError::UnexpectedArtifactName {
                expected: expected_name.to_owned(),
                actual: self.name.clone(),
            });
        }
        if self.kind != expected_kind {
            return Err(ManifestError::UnexpectedArtifactKind(self.name.clone()));
        }
        validate_release_url(&self.url, version, &self.name)?;
        if self.size == 0 || self.size > MAX_ARTIFACT_SIZE {
            return Err(ManifestError::InvalidArtifactSize(self.name.clone()));
        }
        validate_sha256(&self.sha256, "artifact digest")?;
        match self.kind {
            ArtifactKind::RawExecutable => {
                if self.archive_root.is_some() || !self.files.is_empty() {
                    return Err(ManifestError::RawArtifactHasArchiveMetadata(
                        self.name.clone(),
                    ));
                }
            }
            ArtifactKind::TarGz => {
                let root = self
                    .archive_root
                    .as_deref()
                    .ok_or_else(|| ManifestError::MissingArchiveRoot(self.name.clone()))?;
                validate_safe_component(root, "archive root")?;
                if self.files.is_empty() {
                    return Err(ManifestError::EmptyArchiveAllowlist(self.name.clone()));
                }
                let mut paths = BTreeSet::new();
                for file in &self.files {
                    validate_relative_path(&file.path)?;
                    validate_sha256(&file.sha256, "archive file digest")?;
                    if !paths.insert(file.path.as_str()) {
                        return Err(ManifestError::DuplicateArchivePath(file.path.clone()));
                    }
                }
                for required in required_files {
                    let file = self
                        .files
                        .iter()
                        .find(|file| file.path == *required)
                        .ok_or_else(|| ManifestError::RequiredArchiveFileMissing {
                            artifact: self.name.clone(),
                            path: (*required).to_owned(),
                        })?;
                    if !file.executable {
                        return Err(ManifestError::RequiredExecutableNotMarked {
                            artifact: self.name.clone(),
                            path: (*required).to_owned(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

fn decode_verifying_key(key: &TrustedKey) -> Result<VerifyingKey, ManifestError> {
    let bytes = BASE64_STANDARD
        .decode(key.public_key_base64.as_bytes())
        .map_err(|error| ManifestError::InvalidPublicKey(error.to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ManifestError::InvalidPublicKey("expected 32 bytes".to_owned()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| ManifestError::InvalidPublicKey(error.to_string()))
}

fn validate_git_identity(source: &SourceIdentity) -> Result<(), ManifestError> {
    for (name, value) in [
        ("gitea commit", source.gitea_commit.as_str()),
        ("gitea tree", source.gitea_tree.as_str()),
        ("github commit", source.github_commit.as_str()),
        ("github tree", source.github_tree.as_str()),
    ] {
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ManifestError::InvalidGitIdentity(name.to_owned()));
        }
    }
    Ok(())
}

fn validate_release_url(url: &Url, version: &str, name: &str) -> Result<(), ManifestError> {
    let expected_prefix = format!("{DEFAULT_RELEASE_ORIGIN}v{version}/");
    if url.scheme() != "https"
        || !url.as_str().starts_with(&expected_prefix)
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path_segments().and_then(Iterator::last) != Some(name)
    {
        return Err(ManifestError::UnapprovedArtifactUrl(url.to_string()));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), ManifestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManifestError::InvalidSha256(label.to_owned()));
    }
    Ok(())
}

fn validate_safe_identifier(value: &str, label: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ManifestError::UnsafeIdentifier(label.to_owned()));
    }
    Ok(())
}

fn validate_safe_component(value: &str, label: &str) -> Result<(), ManifestError> {
    validate_safe_identifier(value, label)?;
    if value == "." || value == ".." {
        return Err(ManifestError::UnsafeIdentifier(label.to_owned()));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ManifestError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ManifestError::UnsafeArchivePath(value.to_owned()));
    }
    Ok(())
}

/// Lowercase SHA-256 digest of exact bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Signed distribution-manifest error.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// JSON parsing failed.
    #[error("distribution metadata JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Trust-store schema is unsupported.
    #[error("unsupported trust-store schema version {0}")]
    UnsupportedTrustStoreSchema(u32),
    /// Signature-envelope schema is unsupported.
    #[error("unsupported signature-envelope schema version {0}")]
    UnsupportedSignatureSchema(u32),
    /// Distribution-manifest schema is unsupported.
    #[error("unsupported distribution-manifest schema version {0}")]
    UnsupportedManifestSchema(u32),
    /// Signed release-network-policy schema is unsupported.
    #[error("unsupported release network-policy schema version {0}")]
    UnsupportedNetworkPolicySchema(u32),
    /// Signature algorithm is unsupported.
    #[error("unsupported release signature algorithm `{0}`")]
    UnsupportedSignatureAlgorithm(String),
    /// Trust store contains no key.
    #[error("release trust store must contain at least one key")]
    EmptyTrustStore,
    /// Trust store contains a duplicate key id.
    #[error("release trust store contains a duplicate key id")]
    DuplicateTrustKey,
    /// Key is not trusted.
    #[error("release signing key `{0}` is not trusted")]
    UntrustedKey(String),
    /// Key is revoked.
    #[error("release signing key `{0}` is revoked")]
    RevokedKey(String),
    /// Public key encoding is invalid.
    #[error("release public key is invalid: {0}")]
    InvalidPublicKey(String),
    /// Signature encoding is invalid.
    #[error("release signature encoding is invalid: {0}")]
    InvalidSignatureEncoding(String),
    /// Signature did not verify.
    #[error("release manifest signature verification failed")]
    SignatureVerificationFailed,
    /// Signed key differs from the manifest key id.
    #[error("manifest key `{manifest}` does not match signature key `{signature}`")]
    SigningKeyMismatch {
        /// Key id inside the manifest.
        manifest: String,
        /// Key id inside the signature envelope.
        signature: String,
    },
    /// Redirect bound is not exactly the reviewed first-release policy.
    #[error("release network policy allows {0} redirects; exactly one is required")]
    InvalidMaximumRedirects(u8),
    /// Redirect hosts differ from the reviewed GitHub release-asset host.
    #[error("release network policy contains unapproved redirect hosts: {0:?}")]
    UnapprovedRedirectHosts(Vec<String>),
    /// Semantic version is invalid.
    #[error("invalid GetAIP semantic version: {0}")]
    InvalidVersion(String),
    /// Manifest requires a CLI newer than its release.
    #[error("minimum CLI version exceeds the release version")]
    MinimumCliExceedsRelease,
    /// AIP protocol version changed unexpectedly.
    #[error("distribution manifest attempted to change AIP protocol version to `{0}`")]
    ProtocolVersionChanged(String),
    /// Publication time is invalid.
    #[error("manifest publication time is invalid: {0}")]
    InvalidPublishedAt(String),
    /// Git object id is malformed.
    #[error("manifest {0} is not a full lowercase Git object id")]
    InvalidGitIdentity(String),
    /// Rollback target is not older than the release.
    #[error("previous release version must be older than the current release")]
    InvalidPreviousVersion,
    /// No distribution target was declared.
    #[error("distribution manifest contains no target")]
    NoTargets,
    /// A target appears twice.
    #[error("distribution manifest contains duplicate platform {0:?}")]
    DuplicatePlatform(Platform),
    /// Current platform is absent.
    #[error("distribution manifest does not contain platform {0:?}")]
    PlatformNotInManifest(Platform),
    /// Rust target does not match the platform.
    #[error("Rust target does not match platform {0:?}")]
    RustTargetMismatch(Platform),
    /// Minimum platform version is missing.
    #[error("minimum platform version is missing for {0:?}")]
    MissingMinimumPlatformVersion(Platform),
    /// CLI and server versions are not exact matches.
    #[error("CLI and server versions are incompatible for {0:?}")]
    IncompatibleComponentVersions(Platform),
    /// Artifact filename differs from the contract.
    #[error("unexpected artifact name `{actual}`; expected `{expected}`")]
    UnexpectedArtifactName {
        /// Required name.
        expected: String,
        /// Supplied name.
        actual: String,
    },
    /// Artifact kind differs from the contract.
    #[error("unexpected artifact kind for `{0}`")]
    UnexpectedArtifactKind(String),
    /// URL is outside the approved release origin.
    #[error("artifact URL is not approved: {0}")]
    UnapprovedArtifactUrl(String),
    /// Artifact size is zero or exceeds the hard limit.
    #[error("artifact size is invalid for `{0}`")]
    InvalidArtifactSize(String),
    /// Digest is malformed.
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(String),
    /// Raw artifact contains archive-only metadata.
    #[error("raw artifact `{0}` contains archive metadata")]
    RawArtifactHasArchiveMetadata(String),
    /// Archive root is missing.
    #[error("archive `{0}` has no root directory")]
    MissingArchiveRoot(String),
    /// Archive allowlist is empty.
    #[error("archive `{0}` has an empty file allowlist")]
    EmptyArchiveAllowlist(String),
    /// Archive file path is unsafe.
    #[error("unsafe archive path `{0}`")]
    UnsafeArchivePath(String),
    /// Archive file path is duplicated.
    #[error("duplicate archive path `{0}`")]
    DuplicateArchivePath(String),
    /// Required archive file is absent.
    #[error("archive `{artifact}` is missing required file `{path}`")]
    RequiredArchiveFileMissing {
        /// Artifact name.
        artifact: String,
        /// Required relative path.
        path: String,
    },
    /// Required binary lacks the executable marker.
    #[error("archive `{artifact}` does not mark `{path}` executable")]
    RequiredExecutableNotMarked {
        /// Artifact name.
        artifact: String,
        /// Required relative path.
        path: String,
    },
    /// Identifier contains unsafe characters.
    #[error("{0} contains an unsafe identifier")]
    UnsafeIdentifier(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn artifact(name: &str, kind: ArtifactKind, files: Vec<ArtifactFile>) -> Artifact {
        Artifact {
            name: name.to_owned(),
            kind,
            url: Url::parse(&format!(
                "https://github.com/getaip/core/releases/download/v2.1.0/{name}"
            ))
            .expect("URL"),
            size: 128,
            sha256: "a".repeat(64),
            archive_root: (kind == ArtifactKind::TarGz)
                .then(|| name.trim_end_matches(".tar.gz").to_owned()),
            files,
        }
    }

    fn executable(path: &str) -> ArtifactFile {
        ArtifactFile {
            path: path.to_owned(),
            sha256: "b".repeat(64),
            executable: true,
        }
    }

    fn manifest() -> DistributionManifest {
        let platform = Platform::DarwinArm64;
        let asset = platform.asset_label();
        DistributionManifest {
            schema_version: 1,
            release: ReleaseIdentity {
                version: "2.1.0".to_owned(),
                aip_protocol_version: "1.0".to_owned(),
                channel: ReleaseChannel::Development,
                published_at: "2026-08-04T00:00:00Z".to_owned(),
                minimum_cli_version: "2.1.0".to_owned(),
                source: SourceIdentity {
                    gitea_commit: "a".repeat(40),
                    gitea_tree: "b".repeat(40),
                    github_commit: "c".repeat(40),
                    github_tree: "d".repeat(40),
                },
            },
            signing_key_id: "test-key".to_owned(),
            network_policy: default_release_network_policy(),
            previous_version: Some("2.0.0".to_owned()),
            targets: vec![TargetDistribution {
                platform,
                rust_target: platform.rust_target().to_owned(),
                minimum_platform_version: "14.0".to_owned(),
                cli_version: "2.1.0".to_owned(),
                server_version: "2.1.0".to_owned(),
                bootstrap: artifact(
                    &format!("getaip-2.1.0-{asset}"),
                    ArtifactKind::RawExecutable,
                    vec![],
                ),
                cli_archive: artifact(
                    &format!("getaip-2.1.0-{asset}.tar.gz"),
                    ArtifactKind::TarGz,
                    vec![executable("bin/getaip")],
                ),
                server_archive: artifact(
                    &format!("getaip-server-2.1.0-{asset}.tar.gz"),
                    ArtifactKind::TarGz,
                    vec![executable("bin/getaip-server")],
                ),
                distribution_archive: artifact(
                    &format!("getaip-distribution-2.1.0-{asset}.tar.gz"),
                    ArtifactKind::TarGz,
                    vec![executable("bin/getaip"), executable("bin/getaip-server")],
                ),
            }],
        }
    }

    fn signed_fixture() -> (Vec<u8>, Vec<u8>, TrustStore) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let manifest_bytes = serde_json::to_vec(&manifest()).expect("manifest JSON");
        let signature = signing_key.sign(&manifest_bytes);
        let signature_bytes = serde_json::to_vec(&SignatureEnvelope {
            schema_version: 1,
            key_id: "test-key".to_owned(),
            algorithm: "ed25519".to_owned(),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        })
        .expect("signature JSON");
        let trust = TrustStore::from_json(
            &serde_json::to_vec(&json!({
                "schema_version": 1,
                "keys": [{
                    "key_id": "test-key",
                    "algorithm": "ed25519",
                    "public_key_base64": BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
                    "revoked": false
                }]
            }))
            .expect("trust JSON"),
        )
        .expect("trust store");
        (manifest_bytes, signature_bytes, trust)
    }

    #[test]
    fn exact_signed_bytes_are_verified_before_use() {
        let (manifest_bytes, signature_bytes, trust) = signed_fixture();
        let verified = verify_signed_manifest(&manifest_bytes, &signature_bytes, &trust)
            .expect("verified manifest");
        assert_eq!(verified.manifest.release.version, "2.1.0");
        assert_eq!(verified.manifest_sha256, sha256_hex(&manifest_bytes));
    }

    #[test]
    fn published_json_schema_accepts_the_typed_manifest() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/getaip/distribution-manifest-v1.schema.json"
        ))
        .expect("distribution schema JSON");
        let validator = jsonschema::draft202012::new(&schema).expect("distribution schema");
        let instance = serde_json::to_value(manifest()).expect("manifest value");
        assert!(validator.is_valid(&instance));
        let mut rejected = instance;
        rejected["network_policy"]["redirect_hosts"] = json!(["attacker.invalid"]);
        assert!(!validator.is_valid(&rejected));
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let (mut manifest_bytes, signature_bytes, trust) = signed_fixture();
        let last = manifest_bytes.last_mut().expect("non-empty manifest");
        *last ^= 1;
        assert!(matches!(
            verify_signed_manifest(&manifest_bytes, &signature_bytes, &trust),
            Err(ManifestError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn arbitrary_artifact_origin_is_rejected() {
        let mut manifest = manifest();
        manifest.targets[0].distribution_archive.url =
            Url::parse("https://attacker.invalid/getaip.tar.gz").expect("URL");
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::UnapprovedArtifactUrl(_))
        ));
    }

    #[test]
    fn unapproved_redirect_policy_is_rejected() {
        let mut manifest = manifest();
        manifest.network_policy.redirect_hosts = vec!["attacker.invalid".to_owned()];
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::UnapprovedRedirectHosts(_))
        ));
        manifest.network_policy = default_release_network_policy();
        manifest.network_policy.maximum_redirects = 2;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidMaximumRedirects(2))
        ));
    }

    #[test]
    fn traversal_path_is_rejected() {
        let mut manifest = manifest();
        manifest.targets[0].distribution_archive.files[0].path = "../getaip".to_owned();
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::UnsafeArchivePath(_))
        ));
    }

    #[test]
    fn malformed_and_duplicate_platform_metadata_is_rejected() {
        let mut malformed = manifest();
        malformed.targets[0].rust_target = "x86_64-unknown-linux-gnu".to_owned();
        assert!(matches!(
            malformed.validate(),
            Err(ManifestError::RustTargetMismatch(Platform::DarwinArm64))
        ));

        let mut duplicate = manifest();
        duplicate.targets.push(duplicate.targets[0].clone());
        assert!(matches!(
            duplicate.validate(),
            Err(ManifestError::DuplicatePlatform(Platform::DarwinArm64))
        ));
    }
}
