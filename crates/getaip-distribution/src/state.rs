use crate::{AIP_PROTOCOL_VERSION, Platform, SourceIdentity};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Atomic active-version pointer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveVersion {
    /// Pointer document schema.
    pub schema: String,
    /// Active GetAIP software version.
    pub version: String,
    /// Digest of the signed manifest that authorized this activation.
    pub manifest_sha256: String,
    /// RFC 3339 activation time.
    pub activated_at: String,
}

impl ActiveVersion {
    /// Constructs a versioned pointer for the current instant.
    pub fn new(version: String, manifest_sha256: String) -> Result<Self, StateError> {
        Ok(Self {
            schema: "org.getaip.install.active-version.v1".to_owned(),
            version,
            manifest_sha256,
            activated_at: now_rfc3339()?,
        })
    }

    /// Validates stable pointer fields.
    pub fn validate(&self) -> Result<(), StateError> {
        if self.schema != "org.getaip.install.active-version.v1" {
            return Err(StateError::UnsupportedSchema(self.schema.clone()));
        }
        semver::Version::parse(&self.version)
            .map_err(|error| StateError::InvalidState(error.to_string()))?;
        validate_digest(&self.manifest_sha256)?;
        parse_time(&self.activated_at)?;
        Ok(())
    }
}

/// Installer-owned record of the active verified distribution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallState {
    /// State document schema.
    pub schema: String,
    /// Active GetAIP software version.
    pub software_version: String,
    /// AIP wire version, independent from software version.
    pub aip_protocol_version: String,
    /// Qualified platform.
    pub platform: Platform,
    /// Signed manifest digest.
    pub manifest_sha256: String,
    /// Unified archive digest.
    pub distribution_sha256: String,
    /// Release signing key identifier.
    pub signing_key_id: String,
    /// Canonical and public source identities.
    pub source: SourceIdentity,
    /// RFC 3339 installation time.
    pub installed_at: String,
}

impl InstallState {
    /// Validates stable state fields before diagnostics or lifecycle operations.
    pub fn validate(&self) -> Result<(), StateError> {
        if self.schema != "org.getaip.install.state.v1" {
            return Err(StateError::UnsupportedSchema(self.schema.clone()));
        }
        semver::Version::parse(&self.software_version)
            .map_err(|error| StateError::InvalidState(error.to_string()))?;
        if self.aip_protocol_version != AIP_PROTOCOL_VERSION {
            return Err(StateError::InvalidState(
                "installation state changed the AIP protocol version".to_owned(),
            ));
        }
        validate_digest(&self.manifest_sha256)?;
        validate_digest(&self.distribution_sha256)?;
        if self.signing_key_id.trim().is_empty() {
            return Err(StateError::InvalidState(
                "installation state signing key is empty".to_owned(),
            ));
        }
        parse_time(&self.installed_at)?;
        Ok(())
    }
}

/// Previous known-good version eligible for one-step rollback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackState {
    /// Rollback document schema.
    pub schema: String,
    /// Version active after the last successful activation.
    pub current_version: String,
    /// Previous known-good version, if one exists locally.
    pub previous_version: Option<String>,
    /// RFC 3339 state update time.
    pub updated_at: String,
}

impl RollbackState {
    /// Validates the rollback relationship.
    pub fn validate(&self) -> Result<(), StateError> {
        if self.schema != "org.getaip.install.rollback.v1" {
            return Err(StateError::UnsupportedSchema(self.schema.clone()));
        }
        let current = semver::Version::parse(&self.current_version)
            .map_err(|error| StateError::InvalidState(error.to_string()))?;
        if let Some(previous) = self.previous_version.as_deref() {
            let previous = semver::Version::parse(previous)
                .map_err(|error| StateError::InvalidState(error.to_string()))?;
            if previous == current {
                return Err(StateError::InvalidState(
                    "rollback version equals the active version".to_owned(),
                ));
            }
        }
        parse_time(&self.updated_at)?;
        Ok(())
    }
}

/// Reads a bounded, regular, non-symlink JSON document.
pub fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T, StateError> {
    let bytes = read_bounded_file(path)?;
    serde_json::from_slice(&bytes).map_err(StateError::Json)
}

/// Reads one bounded regular non-symlink evidence document as exact bytes.
pub fn read_bounded_file(path: &Path) -> Result<Vec<u8>, StateError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| StateError::ReadMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StateError::NotRegularFile(path.to_path_buf()));
    }
    if metadata.len() > MAX_STATE_BYTES {
        return Err(StateError::DocumentTooLarge(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|source| StateError::Open {
            path: path.to_path_buf(),
            source,
        })?
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StateError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(StateError::DocumentTooLarge(path.to_path_buf()));
    }
    Ok(bytes)
}

/// Replaces one JSON document atomically in its existing filesystem directory.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), StateError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(StateError::Json)?;
    atomic_write_bytes(path, &bytes)
}

/// Replaces one bounded public evidence document atomically with private mode.
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let parent = path
        .parent()
        .ok_or_else(|| StateError::MissingParent(path.to_path_buf()))?;
    ensure_real_directory(parent)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(StateError::DocumentTooLarge(path.to_path_buf()));
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StateError::InvalidFileName(path.to_path_buf()))?;
    let temporary = parent.join(format!(".{name}.tmp-{}-{sequence}", process::id()));
    let result = write_then_rename(path, &temporary, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_then_rename(path: &Path, temporary: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(|source| StateError::Create {
            path: temporary.to_path_buf(),
            source,
        })?;
    set_owner_permissions(temporary)?;
    file.write_all(bytes).map_err(|source| StateError::Write {
        path: temporary.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| StateError::Sync {
        path: temporary.to_path_buf(),
        source,
    })?;
    fs::rename(temporary, path).map_err(|source| StateError::Rename {
        from: temporary.to_path_buf(),
        to: path.to_path_buf(),
        source,
    })?;
    File::open(
        path.parent()
            .ok_or_else(|| StateError::MissingParent(path.to_path_buf()))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|source| StateError::Sync {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| StateError::ReadMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StateError::NotRealDirectory(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn set_owner_permissions(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        StateError::Permissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn validate_digest(value: &str) -> Result<(), StateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateError::InvalidState(
            "state contains an invalid SHA-256 digest".to_owned(),
        ));
    }
    Ok(())
}

fn now_rfc3339() -> Result<String, StateError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| StateError::InvalidTime(error.to_string()))
}

fn parse_time(value: &str) -> Result<(), StateError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|error| StateError::InvalidTime(error.to_string()))
}

/// Persistent installation state error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum StateError {
    #[error("state JSON is invalid: {0}")]
    Json(serde_json::Error),
    #[error("failed to read metadata for {path}: {source}")]
    ReadMetadata { path: PathBuf, source: io::Error },
    #[error("state path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("state directory is not a real directory: {0}")]
    NotRealDirectory(PathBuf),
    #[error("state document exceeds the safety limit: {0}")]
    DocumentTooLarge(PathBuf),
    #[error("failed to open state document {path}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("failed to read state document {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to create state document {path}: {source}")]
    Create { path: PathBuf, source: io::Error },
    #[error("failed to write state document {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to sync state document {path}: {source}")]
    Sync { path: PathBuf, source: io::Error },
    #[error("failed to rename state document from {from} to {to}: {source}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("failed to set owner-only state permissions for {path}: {source}")]
    Permissions { path: PathBuf, source: io::Error },
    #[error("state path has no parent: {0}")]
    MissingParent(PathBuf),
    #[error("state path has an invalid file name: {0}")]
    InvalidFileName(PathBuf),
    #[error("unsupported state schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid installation state: {0}")]
    InvalidState(String),
    #[error("invalid state timestamp: {0}")]
    InvalidTime(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn active_pointer_round_trips_atomically() {
        let temporary = tempdir().expect("tempdir");
        let state_dir = temporary.path().join("state");
        fs::create_dir(&state_dir).expect("state dir");
        let path = state_dir.join("current");
        let pointer =
            ActiveVersion::new("2.1.0".to_owned(), "ab".repeat(32)).expect("active pointer");
        atomic_write_json(&path, &pointer).expect("write pointer");
        let loaded: ActiveVersion = read_json_file(&path).expect("read pointer");
        loaded.validate().expect("valid pointer");
        assert_eq!(pointer, loaded);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_state_document_is_rejected() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().expect("tempdir");
        let target = temporary.path().join("target");
        fs::write(&target, b"{}").expect("target");
        let link = temporary.path().join("link");
        symlink(&target, &link).expect("symlink");
        let error = read_json_file::<ActiveVersion>(&link).expect_err("symlink must fail");
        assert!(matches!(error, StateError::NotRegularFile(_)));
    }
}
