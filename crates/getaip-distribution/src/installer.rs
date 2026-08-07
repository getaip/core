use crate::{
    ActiveVersion, ArchiveError, ArtifactFile, InstallRoots, InstallState, ManifestError, Platform,
    RollbackState, StateError, TrustStore, VerifiedManifest, default_trust_store,
    extract_verified_archive, read_bounded_file, read_json_file, verify_archive,
    verify_signed_manifest,
};
use fs2::FileExt;
use semver::Version;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Pure installation decision made before any filesystem mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstallPlan {
    /// Stable machine-readable schema.
    pub schema: &'static str,
    /// Qualified platform.
    pub platform: Platform,
    /// Release to install.
    pub target_version: String,
    /// Currently active version, if readable.
    pub current_version: Option<String>,
    /// Exact signed archive URL.
    pub distribution_url: String,
    /// Exact signed archive digest.
    pub distribution_sha256: String,
    /// Planned lifecycle action.
    pub action: InstallAction,
}

/// Installer action class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallAction {
    /// No current version exists.
    Install,
    /// A different current version will be replaced atomically.
    Upgrade,
    /// The exact verified version is already active.
    Confirm,
    /// An existing inactive exact version will be activated.
    Reactivate,
    /// An existing corrupt immutable version will be repaired.
    Repair,
}

/// Successful installation result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstallOutcome {
    /// Stable machine-readable schema.
    pub schema: &'static str,
    /// Performed action.
    pub action: InstallAction,
    /// Active software version.
    pub active_version: String,
    /// Previous version retained for rollback.
    pub rollback_version: Option<String>,
    /// Exact signed manifest digest.
    pub manifest_sha256: String,
    /// Exact unified archive digest.
    pub distribution_sha256: String,
    /// Whether extraction was needed.
    pub extracted: bool,
}

/// Native lifecycle action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    /// Activate the retained previous verified version.
    Rollback,
    /// Remove installed executables while retaining user data.
    Uninstall,
    /// Remove installed executables and explicitly selected GetAIP user data.
    Purge,
}

/// Stable result for rollback and uninstall operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleOutcome {
    /// Stable machine-readable schema.
    pub schema: &'static str,
    /// Planned or performed lifecycle action.
    pub action: LifecycleAction,
    /// Whether this was a no-mutation preview.
    pub dry_run: bool,
    /// Version active before the action.
    pub previous_active_version: Option<String>,
    /// Version active after the action.
    pub active_version: Option<String>,
    /// Whether user configuration and logs were preserved.
    pub user_data_preserved: bool,
}

/// Secure versioned installer.
#[derive(Clone, Debug)]
pub struct Installer {
    roots: InstallRoots,
    trust_store: Option<TrustStore>,
}

/// Fully reverified local installation used by diagnostics and execution.
#[derive(Clone, Debug)]
pub struct VerifiedInstallation {
    /// Active pointer.
    pub active: ActiveVersion,
    /// Installer-owned state.
    pub state: InstallState,
    /// Reverified signed release manifest.
    pub release: VerifiedManifest,
}

impl Installer {
    /// Creates an installer for explicit separated roots.
    #[must_use]
    pub fn new(roots: InstallRoots) -> Self {
        Self {
            roots,
            trust_store: None,
        }
    }

    /// Overrides the checked-in trust set for isolated conformance tests.
    #[must_use]
    pub fn with_trust_store(mut self, trust_store: TrustStore) -> Self {
        self.trust_store = Some(trust_store);
        self
    }

    /// Returns the controlled installation roots.
    #[must_use]
    pub fn roots(&self) -> &InstallRoots {
        &self.roots
    }

    /// Creates only the controlled download cache after platform and manifest verification.
    pub fn prepare_download_cache(&self) -> Result<PathBuf, InstallError> {
        create_directory_boundary(&self.roots.cache)?;
        let downloads = self.roots.cache.join("downloads");
        create_directory_boundary(&downloads)?;
        Ok(downloads)
    }

    /// Computes the exact action without creating, deleting, or rewriting files.
    pub fn plan(
        &self,
        verified: &VerifiedManifest,
        platform: Platform,
    ) -> Result<InstallPlan, InstallError> {
        let target = verified.manifest.target(platform)?;
        let current = self.read_active_optional()?;
        let final_directory = self.roots.version_dir(&verified.manifest.release.version);
        let action = match current.as_ref() {
            Some(pointer) if pointer.version == verified.manifest.release.version => {
                if final_directory.exists()
                    && verify_version_directory(
                        &final_directory,
                        &target.distribution_archive.files,
                    )
                    .is_ok()
                {
                    InstallAction::Confirm
                } else {
                    InstallAction::Repair
                }
            }
            Some(_) => InstallAction::Upgrade,
            None if final_directory.exists()
                && verify_version_directory(
                    &final_directory,
                    &target.distribution_archive.files,
                )
                .is_ok() =>
            {
                InstallAction::Reactivate
            }
            None if final_directory.exists() => InstallAction::Repair,
            None => InstallAction::Install,
        };
        Ok(InstallPlan {
            schema: "org.getaip.install.plan.v1",
            platform,
            target_version: verified.manifest.release.version.clone(),
            current_version: current.map(|pointer| pointer.version),
            distribution_url: target.distribution_archive.url.to_string(),
            distribution_sha256: target.distribution_archive.sha256.clone(),
            action,
        })
    }

    /// Verifies, stages, and atomically activates one compatible CLI/server distribution.
    pub fn install_archive(
        &self,
        verified: &VerifiedManifest,
        platform: Platform,
        archive_path: &Path,
    ) -> Result<InstallOutcome, InstallError> {
        let plan = self.plan(verified, platform)?;
        let target = verified.manifest.target(platform)?;
        verify_archive(archive_path, &target.distribution_archive)?;
        prepare_roots(&self.roots)?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.roots.install_lock())
            .map_err(InstallError::OpenLock)?;
        lock_file
            .try_lock_exclusive()
            .map_err(|_| InstallError::InstallerBusy)?;

        let current = self.read_active_optional()?;
        let version = &verified.manifest.release.version;
        let final_directory = self.roots.version_dir(version);
        let final_is_valid = final_directory.exists()
            && verify_version_directory(&final_directory, &target.distribution_archive.files)
                .is_ok();
        let mut extracted = false;
        let mut quarantine = None;

        if !final_is_valid {
            let versions = final_directory
                .parent()
                .ok_or_else(|| InstallError::InvalidVersionPath(final_directory.clone()))?;
            ensure_real_directory(versions)?;
            let stage = unique_child(versions, ".stage", version);
            fs::create_dir(&stage).map_err(|source| InstallError::CreateStage {
                path: stage.clone(),
                source,
            })?;
            if let Err(error) =
                extract_verified_archive(archive_path, &target.distribution_archive, &stage)
            {
                let _ = fs::remove_dir_all(&stage);
                return Err(InstallError::Archive(error));
            }
            verify_version_directory(&stage, &target.distribution_archive.files)?;
            if final_directory.exists() {
                let backup = unique_child(versions, ".quarantine", version);
                fs::rename(&final_directory, &backup).map_err(|source| {
                    InstallError::QuarantineExisting {
                        from: final_directory.clone(),
                        to: backup.clone(),
                        source,
                    }
                })?;
                quarantine = Some(backup);
            }
            if let Err(source) = fs::rename(&stage, &final_directory) {
                if let Some(backup) = quarantine.as_ref() {
                    let _ = fs::rename(backup, &final_directory);
                }
                let _ = fs::remove_dir_all(&stage);
                return Err(InstallError::ActivateDirectory {
                    from: stage,
                    to: final_directory,
                    source,
                });
            }
            extracted = true;
        }

        verify_version_directory(&final_directory, &target.distribution_archive.files)?;
        let previous_version = if current
            .as_ref()
            .is_some_and(|pointer| pointer.version != *version)
        {
            current.as_ref().map(|pointer| pointer.version.clone())
        } else {
            self.read_rollback_optional()?
                .and_then(|state| state.previous_version)
        };
        let now = now_rfc3339()?;
        let install_state = InstallState {
            schema: "org.getaip.install.state.v1".to_owned(),
            software_version: version.clone(),
            aip_protocol_version: verified.manifest.release.aip_protocol_version.clone(),
            platform,
            manifest_sha256: verified.manifest_sha256.clone(),
            distribution_sha256: target.distribution_archive.sha256.clone(),
            signing_key_id: verified.signing_key_id.clone(),
            source: verified.manifest.release.source.clone(),
            installed_at: now.clone(),
        };
        install_state.validate()?;
        let rollback = RollbackState {
            schema: "org.getaip.install.rollback.v1".to_owned(),
            current_version: version.clone(),
            previous_version: previous_version.clone(),
            updated_at: now,
        };
        rollback.validate()?;
        let release_root = self.roots.state.join("releases");
        create_directory_boundary(&release_root)?;
        let release_state = self.roots.release_state_dir(version);
        create_directory_boundary(&release_state)?;
        crate::atomic_write_bytes(
            &release_state.join("release-manifest.json"),
            &verified.signed_manifest_bytes,
        )?;
        crate::atomic_write_bytes(
            &release_state.join("release-manifest.json.sig"),
            &verified.signature_envelope_bytes,
        )?;
        crate::atomic_write_json(&release_state.join("install-state.json"), &install_state)?;
        crate::atomic_write_bytes(
            &self.roots.release_manifest(),
            &verified.signed_manifest_bytes,
        )?;
        crate::atomic_write_bytes(
            &self.roots.release_manifest_signature(),
            &verified.signature_envelope_bytes,
        )?;
        crate::atomic_write_json(&self.roots.install_state(), &install_state)?;
        crate::atomic_write_json(&self.roots.rollback_state(), &rollback)?;
        let pointer = ActiveVersion::new(version.clone(), verified.manifest_sha256.clone())?;
        crate::atomic_write_json(&self.roots.current_pointer(), &pointer)?;

        if let Some(backup) = quarantine {
            fs::remove_dir_all(&backup).map_err(|source| InstallError::RemoveQuarantine {
                path: backup,
                source,
            })?;
        }
        FileExt::unlock(&lock_file).map_err(InstallError::Unlock)?;

        Ok(InstallOutcome {
            schema: "org.getaip.install.outcome.v1",
            action: plan.action,
            active_version: version.clone(),
            rollback_version: previous_version,
            manifest_sha256: verified.manifest_sha256.clone(),
            distribution_sha256: target.distribution_archive.sha256.clone(),
            extracted,
        })
    }

    /// Reads and validates the active pointer when installed.
    pub fn read_active_optional(&self) -> Result<Option<ActiveVersion>, InstallError> {
        let path = self.roots.current_pointer();
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let pointer: ActiveVersion = read_json_file(&path)?;
                pointer.validate()?;
                Ok(Some(pointer))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(InstallError::ReadPointerMetadata { path, source }),
        }
    }

    /// Reads and validates installer state when installed.
    pub fn read_install_state_optional(&self) -> Result<Option<InstallState>, InstallError> {
        let Some(active) = self.read_active_optional()? else {
            return Ok(None);
        };
        self.load_version_installation(&active.version)
            .map(|installation| Some(installation.state))
    }

    /// Re-verifies retained signature evidence, state identity, and every installed file.
    pub fn verify_active_installation(&self) -> Result<VerifiedInstallation, InstallError> {
        let active = self
            .read_active_optional()?
            .ok_or(InstallError::NotInstalled)?;
        let mut installation = self.load_version_installation(&active.version)?;
        if active.manifest_sha256 != installation.state.manifest_sha256
            || active.manifest_sha256 != installation.release.manifest_sha256
        {
            return Err(InstallError::InstallationIdentityMismatch);
        }
        installation.active = active;
        Ok(installation)
    }

    /// Previews or performs one atomic rollback to retained signed release evidence.
    pub fn rollback(&self, dry_run: bool) -> Result<LifecycleOutcome, InstallError> {
        let current = self.verify_active_installation()?;
        let rollback = self
            .read_rollback_optional()?
            .ok_or(InstallError::RollbackUnavailable)?;
        if rollback.current_version != current.active.version {
            return Err(InstallError::InstallationIdentityMismatch);
        }
        let previous = rollback
            .previous_version
            .as_deref()
            .ok_or(InstallError::RollbackUnavailable)?;
        let candidate = self.load_version_installation(previous)?;
        let outcome = LifecycleOutcome {
            schema: "org.getaip.install.lifecycle-outcome.v1",
            action: LifecycleAction::Rollback,
            dry_run,
            previous_active_version: Some(current.active.version.clone()),
            active_version: Some(candidate.active.version.clone()),
            user_data_preserved: true,
        };
        if dry_run {
            return Ok(outcome);
        }

        let lock_file = self.acquire_lock()?;
        let current = self.verify_active_installation()?;
        let rollback = self
            .read_rollback_optional()?
            .ok_or(InstallError::RollbackUnavailable)?;
        let previous = rollback
            .previous_version
            .as_deref()
            .ok_or(InstallError::RollbackUnavailable)?;
        let candidate = self.load_version_installation(previous)?;
        if rollback.current_version != current.active.version {
            return Err(InstallError::InstallationIdentityMismatch);
        }
        crate::atomic_write_bytes(
            &self.roots.release_manifest(),
            &candidate.release.signed_manifest_bytes,
        )?;
        crate::atomic_write_bytes(
            &self.roots.release_manifest_signature(),
            &candidate.release.signature_envelope_bytes,
        )?;
        crate::atomic_write_json(&self.roots.install_state(), &candidate.state)?;
        let new_rollback = RollbackState {
            schema: "org.getaip.install.rollback.v1".to_owned(),
            current_version: candidate.active.version.clone(),
            previous_version: Some(current.active.version),
            updated_at: now_rfc3339()?,
        };
        new_rollback.validate()?;
        crate::atomic_write_json(&self.roots.rollback_state(), &new_rollback)?;
        let pointer = ActiveVersion::new(
            candidate.active.version.clone(),
            candidate.release.manifest_sha256,
        )?;
        crate::atomic_write_json(&self.roots.current_pointer(), &pointer)?;
        FileExt::unlock(&lock_file).map_err(InstallError::Unlock)?;
        Ok(outcome)
    }

    /// Previews or removes only installer-owned artifacts.
    pub fn uninstall(
        &self,
        dry_run: bool,
        purge_user_data: bool,
    ) -> Result<LifecycleOutcome, InstallError> {
        let active = self.read_active_optional()?;
        let action = if purge_user_data {
            LifecycleAction::Purge
        } else {
            LifecycleAction::Uninstall
        };
        let outcome = LifecycleOutcome {
            schema: "org.getaip.install.lifecycle-outcome.v1",
            action,
            dry_run,
            previous_active_version: active.as_ref().map(|pointer| pointer.version.clone()),
            active_version: None,
            user_data_preserved: !purge_user_data,
        };
        if dry_run {
            return Ok(outcome);
        }
        if active.is_none() {
            remove_directory_if_present(&self.roots.data.join("versions"))?;
            remove_file_if_present(&self.roots.install_state())?;
            remove_file_if_present(&self.roots.rollback_state())?;
            remove_file_if_present(&self.roots.release_manifest())?;
            remove_file_if_present(&self.roots.release_manifest_signature())?;
            remove_directory_if_present(&self.roots.state.join("releases"))?;
            remove_directory_if_present(&self.roots.cache.join("downloads"))?;
            if purge_user_data {
                purge_roots(&self.roots)?;
            }
            return Ok(outcome);
        }
        let _ = self.verify_active_installation()?;
        let lock_file = self.acquire_lock()?;
        let _ = self.verify_active_installation()?;
        remove_file_if_present(&self.roots.current_pointer())?;
        remove_directory_if_present(&self.roots.data.join("versions"))?;
        remove_file_if_present(&self.roots.install_state())?;
        remove_file_if_present(&self.roots.rollback_state())?;
        remove_file_if_present(&self.roots.release_manifest())?;
        remove_file_if_present(&self.roots.release_manifest_signature())?;
        remove_directory_if_present(&self.roots.state.join("releases"))?;
        remove_directory_if_present(&self.roots.cache.join("downloads"))?;
        if purge_user_data {
            FileExt::unlock(&lock_file).map_err(InstallError::Unlock)?;
            purge_roots(&self.roots)?;
            return Ok(outcome);
        }
        FileExt::unlock(&lock_file).map_err(InstallError::Unlock)?;
        Ok(outcome)
    }

    fn read_rollback_optional(&self) -> Result<Option<RollbackState>, InstallError> {
        let path = self.roots.rollback_state();
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let state: RollbackState = read_json_file(&path)?;
                state.validate()?;
                Ok(Some(state))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(InstallError::ReadPointerMetadata { path, source }),
        }
    }

    fn acquire_lock(&self) -> Result<File, InstallError> {
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(self.roots.install_lock())
            .map_err(InstallError::OpenLock)?;
        lock_file
            .try_lock_exclusive()
            .map_err(|_| InstallError::InstallerBusy)?;
        Ok(lock_file)
    }

    fn load_version_installation(
        &self,
        version: &str,
    ) -> Result<VerifiedInstallation, InstallError> {
        Version::parse(version)
            .map_err(|error| InstallError::InvalidRetainedVersion(error.to_string()))?;
        let release_state = self.roots.release_state_dir(version);
        ensure_real_directory(&release_state)?;
        let manifest_bytes = read_bounded_file(&release_state.join("release-manifest.json"))?;
        let signature_bytes = read_bounded_file(&release_state.join("release-manifest.json.sig"))?;
        let default_trust;
        let trust = match self.trust_store.as_ref() {
            Some(trust) => trust,
            None => {
                default_trust = default_trust_store()?;
                &default_trust
            }
        };
        let release = verify_signed_manifest(&manifest_bytes, &signature_bytes, trust)?;
        let state: InstallState = read_json_file(&release_state.join("install-state.json"))?;
        state.validate()?;
        if state.software_version != version
            || release.manifest.release.version != version
            || state.manifest_sha256 != release.manifest_sha256
            || state.signing_key_id != release.signing_key_id
            || state.source != release.manifest.release.source
        {
            return Err(InstallError::InstallationIdentityMismatch);
        }
        let target = release.manifest.target(state.platform)?;
        if target.distribution_archive.sha256 != state.distribution_sha256 {
            return Err(InstallError::InstallationIdentityMismatch);
        }
        verify_version_directory(
            &self.roots.version_dir(version),
            &target.distribution_archive.files,
        )?;
        Ok(VerifiedInstallation {
            active: ActiveVersion {
                schema: "org.getaip.install.active-version.v1".to_owned(),
                version: version.to_owned(),
                manifest_sha256: release.manifest_sha256.clone(),
                activated_at: state.installed_at.clone(),
            },
            state,
            release,
        })
    }
}

fn purge_roots(roots: &InstallRoots) -> Result<(), InstallError> {
    let mut paths = BTreeSet::new();
    paths.insert(roots.data.clone());
    paths.insert(roots.config.clone());
    paths.insert(roots.state.clone());
    paths.insert(roots.cache.clone());
    paths.insert(roots.logs.clone());
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        remove_directory_if_present(&path)?;
    }
    Ok(())
}

fn prepare_roots(roots: &InstallRoots) -> Result<(), InstallError> {
    for root in [
        &roots.data,
        &roots.config,
        &roots.state,
        &roots.cache,
        &roots.logs,
    ] {
        create_directory_boundary(root)?;
    }
    create_directory_boundary(&roots.data.join("versions"))?;
    create_directory_boundary(&roots.cache.join("downloads"))?;
    Ok(())
}

fn create_directory_boundary(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(InstallError::UnsafeDirectory(path.to_path_buf()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent()
                && parent.exists()
            {
                ensure_real_directory(parent)?;
                ensure_user_owned_writable_directory(parent)?;
            }
            fs::create_dir_all(path).map_err(|source| InstallError::CreateDirectory {
                path: path.to_path_buf(),
                source,
            })?;
            ensure_real_directory(path)?;
        }
        Err(source) => {
            return Err(InstallError::DirectoryMetadata {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    ensure_user_owned_writable_directory(path)
}

#[cfg(unix)]
fn ensure_user_owned_writable_directory(path: &Path) -> Result<(), InstallError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata =
        fs::symlink_metadata(path).map_err(|source| InstallError::DirectoryMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    let owner = metadata.uid();
    let effective_user = nix::unistd::Uid::effective().as_raw();
    let mode = metadata.permissions().mode() & 0o777;
    if owner != effective_user || mode & 0o300 != 0o300 {
        return Err(InstallError::DirectoryNotUserWritable {
            path: path.to_path_buf(),
            owner,
            effective_user,
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_user_owned_writable_directory(_path: &Path) -> Result<(), InstallError> {
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), InstallError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| InstallError::DirectoryMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InstallError::UnsafeDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn unique_child(parent: &Path, prefix: &str, version: &str) -> PathBuf {
    let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    parent.join(format!("{prefix}-{version}-{}-{sequence}", process::id()))
}

fn verify_version_directory(directory: &Path, files: &[ArtifactFile]) -> Result<(), InstallError> {
    ensure_real_directory(directory)?;
    let expected_files: BTreeSet<_> = files.iter().map(|file| file.path.as_str()).collect();
    let expected_directories = expected_directory_paths(files);
    let mut seen = BTreeSet::new();
    verify_directory_recursive(
        directory,
        directory,
        &expected_files,
        &expected_directories,
        &mut seen,
    )?;
    let missing: Vec<_> = expected_files
        .iter()
        .filter(|path| !seen.contains(**path))
        .map(|path| (*path).to_owned())
        .collect();
    if !missing.is_empty() {
        return Err(InstallError::MissingInstalledFiles(missing));
    }
    for file in files {
        let path = directory.join(&file.path);
        let digest = sha256_file(&path)?;
        if digest != file.sha256 {
            return Err(InstallError::InstalledDigestMismatch {
                path,
                expected: file.sha256.clone(),
                actual: digest,
            });
        }
        verify_permissions(&path, file.executable)?;
    }
    Ok(())
}

fn expected_directory_paths(files: &[ArtifactFile]) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for file in files {
        let mut parent = Path::new(&file.path).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            if let Some(path) = path.to_str() {
                directories.insert(path.to_owned());
            }
            parent = path.parent();
        }
    }
    directories
}

fn verify_directory_recursive(
    root: &Path,
    current: &Path,
    expected_files: &BTreeSet<&str>,
    expected_directories: &BTreeSet<String>,
    seen: &mut BTreeSet<String>,
) -> Result<(), InstallError> {
    for entry in fs::read_dir(current).map_err(|source| InstallError::ReadDirectory {
        path: current.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| InstallError::ReadDirectory {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| InstallError::UnexpectedInstalledPath(path.clone()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| InstallError::UnexpectedInstalledPath(path.clone()))?
            .to_owned();
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| InstallError::DirectoryMetadata {
                path: path.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(InstallError::UnexpectedInstalledPath(path));
        }
        if metadata.is_dir() {
            if !expected_directories.contains(&relative) {
                return Err(InstallError::UnexpectedInstalledPath(path));
            }
            verify_directory_recursive(root, &path, expected_files, expected_directories, seen)?;
        } else if metadata.is_file() && expected_files.contains(relative.as_str()) {
            seen.insert(relative);
        } else {
            return Err(InstallError::UnexpectedInstalledPath(path));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, InstallError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| InstallError::DirectoryMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InstallError::UnexpectedInstalledPath(path.to_path_buf()));
    }
    let mut file = File::open(path).map_err(|source| InstallError::OpenInstalledFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| InstallError::ReadInstalledFile {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(unix)]
fn verify_permissions(path: &Path, executable: bool) -> Result<(), InstallError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| InstallError::DirectoryMetadata {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    let expected = if executable { 0o755 } else { 0o644 };
    if mode != expected {
        return Err(InstallError::InstalledPermissionMismatch {
            path: path.to_path_buf(),
            expected,
            actual: mode,
        });
    }
    Ok(())
}

fn now_rfc3339() -> Result<String, InstallError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| InstallError::Time(error.to_string()))
}

fn remove_file_if_present(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(InstallError::UnsafeRemovalTarget(path.to_path_buf()))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| InstallError::RemoveOwnedPath {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(InstallError::DirectoryMetadata {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_directory_if_present(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(InstallError::UnsafeRemovalTarget(path.to_path_buf()))
        }
        Ok(_) => fs::remove_dir_all(path).map_err(|source| InstallError::RemoveOwnedPath {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(InstallError::DirectoryMetadata {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Installer planning, verification, or activation error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum InstallError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("GetAIP is not installed; run getaip setup")]
    NotInstalled,
    #[error("installation pointer exists but install state is missing")]
    MissingInstallState,
    #[error("installation pointer, state, manifest, or artifact identity does not match")]
    InstallationIdentityMismatch,
    #[error("no retained verified rollback version is available")]
    RollbackUnavailable,
    #[error("retained rollback version is invalid: {0}")]
    InvalidRetainedVersion(String),
    #[error("another GetAIP installer or lifecycle operation is active")]
    InstallerBusy,
    #[error("failed to open installer lock: {0}")]
    OpenLock(io::Error),
    #[error("failed to unlock installer state: {0}")]
    Unlock(io::Error),
    #[error("unsafe installation directory: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("failed to read directory metadata for {path}: {source}")]
    DirectoryMetadata { path: PathBuf, source: io::Error },
    #[error("failed to create directory {path}: {source}")]
    CreateDirectory { path: PathBuf, source: io::Error },
    #[error(
        "installation directory {path} must be owned and writable by user {effective_user}; owner is {owner}, mode is {mode:o}"
    )]
    DirectoryNotUserWritable {
        path: PathBuf,
        owner: u32,
        effective_user: u32,
        mode: u32,
    },
    #[error("failed to create staging directory {path}: {source}")]
    CreateStage { path: PathBuf, source: io::Error },
    #[error("invalid version directory path: {0}")]
    InvalidVersionPath(PathBuf),
    #[error("failed to quarantine existing directory from {from} to {to}: {source}")]
    QuarantineExisting {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("failed to activate version directory from {from} to {to}: {source}")]
    ActivateDirectory {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("failed to remove repaired-version quarantine {path}: {source}")]
    RemoveQuarantine { path: PathBuf, source: io::Error },
    #[error("failed to read directory {path}: {source}")]
    ReadDirectory { path: PathBuf, source: io::Error },
    #[error("installed distribution contains unexpected path: {0}")]
    UnexpectedInstalledPath(PathBuf),
    #[error("installed distribution is missing files: {0:?}")]
    MissingInstalledFiles(Vec<String>),
    #[error("failed to open installed file {path}: {source}")]
    OpenInstalledFile { path: PathBuf, source: io::Error },
    #[error("failed to read installed file {path}: {source}")]
    ReadInstalledFile { path: PathBuf, source: io::Error },
    #[error("installed file {path} digest mismatch: expected {expected}, received {actual}")]
    InstalledDigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("installed file {path} mode mismatch: expected {expected:o}, received {actual:o}")]
    InstalledPermissionMismatch {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("failed to read installation pointer metadata for {path}: {source}")]
    ReadPointerMetadata { path: PathBuf, source: io::Error },
    #[error("failed to format installation timestamp: {0}")]
    Time(String),
    #[error("refusing to remove unsafe installer-owned target: {0}")]
    UnsafeRemovalTarget(PathBuf),
    #[error("failed to remove installer-owned path {path}: {source}")]
    RemoveOwnedPath { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Artifact, ArtifactKind, DistributionManifest, ReleaseChannel, ReleaseIdentity,
        SignatureEnvelope, SourceIdentity, TargetDistribution,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tar::{Builder, Header};
    use tempfile::tempdir;
    use url::Url;

    fn release_url(version: &str, name: &str) -> Url {
        Url::parse(&format!(
            "https://github.com/getaip/core/releases/download/v{version}/{name}"
        ))
        .expect("release URL")
    }

    fn fixture_trust() -> (SigningKey, TrustStore) {
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let trust = TrustStore::from_json(
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "keys": [{
                    "key_id": "fixture-key",
                    "algorithm": "ed25519",
                    "public_key_base64": BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
                    "revoked": false
                }]
            }))
            .expect("trust JSON"),
        )
        .expect("trust store");
        (signing_key, trust)
    }

    fn create_fixture(
        temp: &Path,
        platform: Platform,
        version: &str,
        payload: &str,
        signing_key: &SigningKey,
        trust: &TrustStore,
    ) -> (VerifiedManifest, PathBuf) {
        let root = format!("getaip-distribution-{version}");
        let cli = format!("fixture-cli-{payload}");
        let server = format!("fixture-server-{payload}");
        let archive_path = temp.join(format!("distribution-{version}.tar.gz"));
        let encoder = GzEncoder::new(
            File::create(&archive_path).expect("archive file"),
            Compression::default(),
        );
        let mut builder = Builder::new(encoder);
        for (name, contents) in [
            (format!("{root}/bin/getaip"), cli.as_bytes()),
            (format!("{root}/bin/getaip-server"), server.as_bytes()),
        ] {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, contents)
                .expect("append fixture");
        }
        builder.finish().expect("finish tar");
        let encoder = builder.into_inner().expect("gzip encoder");
        encoder.finish().expect("finish gzip");
        let archive_bytes = fs::read(&archive_path).expect("archive bytes");
        let asset = platform.asset_label();
        let distribution_name = format!("getaip-distribution-{version}-{asset}.tar.gz");
        let files = vec![
            ArtifactFile {
                path: "bin/getaip".to_owned(),
                sha256: hex::encode(Sha256::digest(cli.as_bytes())),
                executable: true,
            },
            ArtifactFile {
                path: "bin/getaip-server".to_owned(),
                sha256: hex::encode(Sha256::digest(server.as_bytes())),
                executable: true,
            },
        ];
        let archive = |name: String, files: Vec<ArtifactFile>| Artifact {
            url: release_url(version, &name),
            name,
            kind: ArtifactKind::TarGz,
            size: archive_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&archive_bytes)),
            archive_root: Some(root.clone()),
            files,
        };
        let raw_name = format!("getaip-{version}-{asset}");
        let target = TargetDistribution {
            platform,
            rust_target: platform.rust_target().to_owned(),
            minimum_platform_version: "qualified-fixture".to_owned(),
            cli_version: version.to_owned(),
            server_version: version.to_owned(),
            bootstrap: Artifact {
                url: release_url(version, &raw_name),
                name: raw_name,
                kind: ArtifactKind::RawExecutable,
                size: 1,
                sha256: "00".repeat(32),
                archive_root: None,
                files: Vec::new(),
            },
            cli_archive: archive(
                format!("getaip-{version}-{asset}.tar.gz"),
                vec![files[0].clone()],
            ),
            server_archive: archive(
                format!("getaip-server-{version}-{asset}.tar.gz"),
                vec![files[1].clone()],
            ),
            distribution_archive: archive(distribution_name, files),
        };
        let manifest = DistributionManifest {
            schema_version: 1,
            release: ReleaseIdentity {
                version: version.to_owned(),
                aip_protocol_version: "1.0".to_owned(),
                channel: ReleaseChannel::Development,
                published_at: "2026-08-04T00:00:00Z".to_owned(),
                minimum_cli_version: version.to_owned(),
                source: SourceIdentity {
                    gitea_commit: "11".repeat(20),
                    gitea_tree: "22".repeat(20),
                    github_commit: "33".repeat(20),
                    github_tree: "44".repeat(20),
                },
            },
            signing_key_id: "fixture-key".to_owned(),
            network_policy: crate::default_release_network_policy(),
            previous_version: (version != "2.1.0").then(|| "2.1.0".to_owned()),
            targets: vec![target],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
        let signature = signing_key.sign(&manifest_bytes);
        let signature_bytes = serde_json::to_vec(&SignatureEnvelope {
            schema_version: 1,
            key_id: "fixture-key".to_owned(),
            algorithm: "ed25519".to_owned(),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        })
        .expect("signature JSON");
        let verified = verify_signed_manifest(&manifest_bytes, &signature_bytes, trust)
            .expect("verified fixture manifest");
        (verified, archive_path)
    }

    #[test]
    fn install_is_atomic_idempotent_and_repairs_owned_version() {
        let temporary = tempdir().expect("tempdir");
        let platform = Platform::detect().expect("supported test platform");
        let (signing_key, trust) = fixture_trust();
        let (verified, archive_path) = create_fixture(
            temporary.path(),
            platform,
            "2.1.0",
            "v1",
            &signing_key,
            &trust,
        );
        let install_root = temporary.path().join("install");
        let roots = InstallRoots::under_test_root(&install_root).expect("roots");
        let installer = Installer::new(roots.clone()).with_trust_store(trust);

        let first = installer
            .install_archive(&verified, platform, &archive_path)
            .expect("first install");
        assert_eq!(first.action, InstallAction::Install);
        assert!(first.extracted);
        assert_eq!(
            fs::read(roots.version_dir("2.1.0").join("bin/getaip")).expect("installed CLI"),
            b"fixture-cli-v1"
        );

        let second = installer
            .install_archive(&verified, platform, &archive_path)
            .expect("idempotent install");
        assert_eq!(second.action, InstallAction::Confirm);
        assert!(!second.extracted);

        fs::write(roots.version_dir("2.1.0").join("bin/getaip"), b"corrupt")
            .expect("corrupt owned file");
        let repaired = installer
            .install_archive(&verified, platform, &archive_path)
            .expect("repair install");
        assert_eq!(repaired.action, InstallAction::Repair);
        assert!(repaired.extracted);
        assert_eq!(
            fs::read(roots.version_dir("2.1.0").join("bin/getaip")).expect("repaired CLI"),
            b"fixture-cli-v1"
        );
    }

    #[test]
    fn tampered_archive_fails_before_any_installation_mutation() {
        let temporary = tempdir().expect("tempdir");
        let platform = Platform::detect().expect("supported test platform");
        let (signing_key, trust) = fixture_trust();
        let (verified, archive_path) = create_fixture(
            temporary.path(),
            platform,
            "2.1.0",
            "v1",
            &signing_key,
            &trust,
        );
        OpenOptions::new()
            .append(true)
            .open(&archive_path)
            .expect("archive")
            .write_all(b"tamper")
            .expect("tamper archive");
        let install_root = temporary.path().join("install");
        let installer =
            Installer::new(InstallRoots::under_test_root(&install_root).expect("test roots"))
                .with_trust_store(trust);
        let error = installer
            .install_archive(&verified, platform, &archive_path)
            .expect_err("tamper must fail");
        assert!(matches!(
            error,
            InstallError::Archive(ArchiveError::ArchiveSizeMismatch { .. })
        ));
        assert!(!install_root.exists());
    }

    #[test]
    fn conflicting_installation_root_fails_before_activation() {
        let temporary = tempdir().expect("tempdir");
        let platform = Platform::detect().expect("supported test platform");
        let (signing_key, trust) = fixture_trust();
        let (verified, archive_path) = create_fixture(
            temporary.path(),
            platform,
            "2.1.0",
            "v1",
            &signing_key,
            &trust,
        );
        let install_root = temporary.path().join("conflicting-install");
        fs::create_dir(&install_root).expect("install boundary");
        fs::write(install_root.join("data"), b"not-a-directory").expect("conflicting data root");
        let roots = InstallRoots::under_test_root(&install_root).expect("roots");
        let installer = Installer::new(roots.clone()).with_trust_store(trust);

        let error = installer
            .install_archive(&verified, platform, &archive_path)
            .expect_err("conflicting installation boundary must fail");
        assert!(matches!(error, InstallError::ReadPointerMetadata { .. }));
        assert!(!roots.current_pointer().exists());
        assert!(!roots.state.exists());
        assert!(!roots.cache.exists());
    }

    #[test]
    #[cfg(unix)]
    fn insufficient_directory_permissions_fail_before_activation() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempdir().expect("tempdir");
        let platform = Platform::detect().expect("supported test platform");
        let (signing_key, trust) = fixture_trust();
        let (verified, archive_path) = create_fixture(
            temporary.path(),
            platform,
            "2.1.0",
            "v1",
            &signing_key,
            &trust,
        );
        let install_root = temporary.path().join("read-only-install");
        fs::create_dir(&install_root).expect("install boundary");
        fs::set_permissions(&install_root, fs::Permissions::from_mode(0o500))
            .expect("read-only boundary");
        let roots = InstallRoots::under_test_root(&install_root).expect("roots");
        let installer = Installer::new(roots.clone()).with_trust_store(trust);

        let result = installer.install_archive(&verified, platform, &archive_path);
        fs::set_permissions(&install_root, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        let error = result.expect_err("unwritable installation boundary must fail");
        assert!(matches!(
            error,
            InstallError::DirectoryNotUserWritable { .. }
        ));
        assert!(!roots.current_pointer().exists());
    }

    #[test]
    fn upgrade_rollback_and_uninstall_preserve_user_data_until_purge() {
        let temporary = tempdir().expect("tempdir");
        let platform = Platform::detect().expect("supported test platform");
        let (signing_key, trust) = fixture_trust();
        let (release_one, archive_one) = create_fixture(
            temporary.path(),
            platform,
            "2.1.0",
            "v1",
            &signing_key,
            &trust,
        );
        let (release_two, archive_two) = create_fixture(
            temporary.path(),
            platform,
            "2.2.0",
            "v2",
            &signing_key,
            &trust,
        );
        let roots =
            InstallRoots::under_test_root(&temporary.path().join("install")).expect("roots");
        let installer = Installer::new(roots.clone()).with_trust_store(trust);
        installer
            .install_archive(&release_one, platform, &archive_one)
            .expect("install v1");
        installer
            .install_archive(&release_two, platform, &archive_two)
            .expect("upgrade v2");
        let retained_manifest =
            fs::read(roots.release_manifest()).expect("retained manifest bytes");
        let retained_signature =
            fs::read(roots.release_manifest_signature()).expect("retained signature bytes");
        serde_json::from_slice::<serde_json::Value>(&retained_manifest)
            .expect("retained manifest JSON");
        serde_json::from_slice::<serde_json::Value>(&retained_signature)
            .expect("retained signature JSON");
        assert_eq!(
            installer
                .verify_active_installation()
                .expect("verified v2")
                .active
                .version,
            "2.2.0"
        );

        let preview = installer.rollback(true).expect("rollback preview");
        assert!(preview.dry_run);
        assert_eq!(
            installer
                .read_active_optional()
                .expect("pointer")
                .expect("active")
                .version,
            "2.2.0"
        );
        let rolled_back = installer.rollback(false).expect("rollback");
        assert_eq!(rolled_back.active_version.as_deref(), Some("2.1.0"));
        assert_eq!(
            fs::read(roots.version_dir("2.1.0").join("bin/getaip")).expect("rolled-back CLI"),
            b"fixture-cli-v1"
        );

        fs::write(roots.config.join("user-marker"), b"preserve").expect("user marker");
        let preview = installer.uninstall(true, false).expect("uninstall preview");
        assert!(preview.dry_run);
        assert!(roots.current_pointer().exists());
        let removed = installer.uninstall(false, false).expect("uninstall");
        assert!(removed.user_data_preserved);
        assert!(!roots.current_pointer().exists());
        assert_eq!(
            fs::read(roots.config.join("user-marker")).expect("preserved marker"),
            b"preserve"
        );
        installer.uninstall(false, true).expect("purge");
        assert!(!roots.config.exists());
    }
}
