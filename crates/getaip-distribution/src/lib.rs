//! Secure installation and release-distribution contracts for GetAIP.
//!
//! This crate is deliberately separate from the AIP protocol crates. It owns
//! software-release identity, signed distribution manifests, supported target
//! detection, and user-owned installation layout. It does not change AIP wire
//! semantics.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod archive;
mod download;
mod installer;
mod layout;
mod manifest;
mod platform;
mod state;
mod version;

pub use archive::{ArchiveError, ExtractedArchive, extract_verified_archive, verify_archive};
pub use download::{
    DownloadError, DownloadResult, ReleaseClient, manifest_signature_url, manifest_url,
    verify_downloaded_file,
};
pub use installer::{
    InstallAction, InstallError, InstallOutcome, InstallPlan, Installer, LifecycleAction,
    LifecycleOutcome, VerifiedInstallation,
};
pub use layout::{InstallRoots, LayoutError};
pub use manifest::{
    Artifact, ArtifactFile, ArtifactKind, DistributionManifest, ManifestError, ReleaseChannel,
    ReleaseIdentity, ReleaseNetworkPolicy, SignatureEnvelope, SourceIdentity, TargetDistribution,
    TrustStore, TrustedKey, VerifiedManifest, default_release_network_policy, default_trust_store,
    sha256_hex, verify_signed_manifest,
};
pub use platform::{Platform, PlatformError};
pub use state::{
    ActiveVersion, InstallState, RollbackState, StateError, atomic_write_bytes, atomic_write_json,
    read_bounded_file, read_json_file,
};
pub use version::{AIP_PROTOCOL_VERSION, BuildVersion, GETAIP_SOFTWARE_VERSION};

/// Current distribution-manifest schema version.
pub const DISTRIBUTION_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Canonical public release origin used by the first GetAIP distribution.
pub const DEFAULT_RELEASE_ORIGIN: &str = "https://github.com/getaip/core/releases/download/";

/// Exact GitHub-controlled host allowed for one release-asset redirect.
pub const GITHUB_RELEASE_REDIRECT_HOST: &str = "release-assets.githubusercontent.com";

/// Current signed release-network-policy schema.
pub const RELEASE_NETWORK_POLICY_SCHEMA_VERSION: u32 = 1;
