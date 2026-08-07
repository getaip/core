use crate::{Artifact, ArtifactFile, ArtifactKind};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};
use tar::Archive;
use thiserror::Error;

const MAX_ARCHIVE_ENTRIES: usize = 256;
const MAX_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Result of extracting one strictly allowlisted release archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedArchive {
    /// Number of regular files written.
    pub file_count: usize,
    /// Total number of uncompressed file bytes written.
    pub uncompressed_bytes: u64,
}

/// Verifies the compressed archive size and SHA-256 digest without extracting it.
pub fn verify_archive(path: &Path, artifact: &Artifact) -> Result<(), ArchiveError> {
    if artifact.kind != ArtifactKind::TarGz {
        return Err(ArchiveError::WrongArtifactKind);
    }
    let metadata = fs::symlink_metadata(path).map_err(ArchiveError::ReadArchiveMetadata)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ArchiveError::ArchiveNotRegularFile(path.to_path_buf()));
    }
    if metadata.len() != artifact.size {
        return Err(ArchiveError::ArchiveSizeMismatch {
            expected: artifact.size,
            actual: metadata.len(),
        });
    }
    let actual = sha256_reader(File::open(path).map_err(ArchiveError::OpenArchive)?)?;
    if actual != artifact.sha256 {
        return Err(ArchiveError::ArchiveDigestMismatch {
            expected: artifact.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

/// Extracts an already verified archive into a new, empty staging directory.
///
/// Only regular files declared by the signed manifest and their exact parent
/// directories are accepted. Links, devices, duplicate paths, traversal, and
/// all undeclared content are rejected.
pub fn extract_verified_archive(
    archive_path: &Path,
    artifact: &Artifact,
    destination: &Path,
) -> Result<ExtractedArchive, ArchiveError> {
    verify_archive(archive_path, artifact)?;
    let root = artifact
        .archive_root
        .as_deref()
        .ok_or(ArchiveError::MissingArchiveRoot)?;
    ensure_new_empty_directory(destination)?;

    let extraction = (|| -> Result<ExtractedArchive, ArchiveError> {
        let allowed_files: BTreeMap<String, &ArtifactFile> = artifact
            .files
            .iter()
            .map(|file| (format!("{root}/{}", file.path), file))
            .collect();
        let mut allowed_directories = BTreeSet::from([root.to_owned()]);
        for path in allowed_files.keys() {
            let components: Vec<_> = Path::new(path).components().collect();
            for end in 1..components.len() {
                let directory = components[..end]
                    .iter()
                    .map(|component| match component {
                        Component::Normal(value) => value.to_string_lossy().into_owned(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                allowed_directories.insert(directory);
            }
        }

        let file = File::open(archive_path).map_err(ArchiveError::OpenArchive)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        let mut seen_paths = BTreeSet::new();
        let mut seen_files = BTreeSet::new();
        let mut entry_count = 0usize;
        let mut uncompressed_bytes = 0u64;

        for entry in archive.entries().map_err(ArchiveError::ReadArchive)? {
            entry_count = entry_count.saturating_add(1);
            if entry_count > MAX_ARCHIVE_ENTRIES {
                return cleanup_error(
                    destination,
                    ArchiveError::TooManyEntries(MAX_ARCHIVE_ENTRIES),
                );
            }
            let mut entry = entry.map_err(ArchiveError::ReadArchiveEntry)?;
            let entry_type = entry.header().entry_type();
            let raw_path = entry.path().map_err(ArchiveError::ReadEntryPath)?;
            let mut portable_path = path_to_portable_string(&raw_path)?;
            if entry_type.is_dir() {
                portable_path = portable_path.trim_end_matches('/').to_owned();
            }
            validate_exact_archive_path(&portable_path)?;
            if !seen_paths.insert(portable_path.clone()) {
                return cleanup_error(destination, ArchiveError::DuplicatePath(portable_path));
            }

            if entry_type.is_dir() {
                if !allowed_directories.contains(&portable_path) {
                    return cleanup_error(destination, ArchiveError::UnexpectedPath(portable_path));
                }
                continue;
            }
            if !entry_type.is_file() {
                return cleanup_error(
                    destination,
                    ArchiveError::UnsupportedEntryType(portable_path),
                );
            }
            let Some(expected) = allowed_files.get(&portable_path).copied() else {
                return cleanup_error(destination, ArchiveError::UnexpectedPath(portable_path));
            };
            let output_path = destination.join(&expected.path);
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).map_err(ArchiveError::CreateDestination)?;
                ensure_directory_is_not_symlink(parent)?;
            }

            let declared_size = entry.size();
            uncompressed_bytes = uncompressed_bytes
                .checked_add(declared_size)
                .ok_or(ArchiveError::ArchiveTooLarge)?;
            if uncompressed_bytes > MAX_UNCOMPRESSED_BYTES {
                return cleanup_error(destination, ArchiveError::ArchiveTooLarge);
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .map_err(|source| ArchiveError::CreateFile {
                    path: output_path.clone(),
                    source,
                })?;
            let actual_digest = copy_and_hash(&mut entry, &mut output, declared_size)?;
            output.sync_all().map_err(ArchiveError::SyncFile)?;
            set_manifest_permissions(&output_path, expected.executable)?;
            if actual_digest != expected.sha256 {
                return cleanup_error(
                    destination,
                    ArchiveError::FileDigestMismatch {
                        path: expected.path.clone(),
                        expected: expected.sha256.clone(),
                        actual: actual_digest,
                    },
                );
            }
            seen_files.insert(portable_path);
        }

        let missing: Vec<_> = allowed_files
            .keys()
            .filter(|path| !seen_files.contains(*path))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return cleanup_error(destination, ArchiveError::MissingFiles(missing));
        }

        Ok(ExtractedArchive {
            file_count: seen_files.len(),
            uncompressed_bytes,
        })
    })();
    if extraction.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    extraction
}

fn ensure_new_empty_directory(destination: &Path) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(destination).map_err(ArchiveError::DestinationMetadata)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArchiveError::DestinationNotDirectory(
            destination.to_path_buf(),
        ));
    }
    let mut entries = fs::read_dir(destination).map_err(ArchiveError::ReadDestination)?;
    if entries
        .next()
        .transpose()
        .map_err(ArchiveError::ReadDestination)?
        .is_some()
    {
        return Err(ArchiveError::DestinationNotEmpty(destination.to_path_buf()));
    }
    Ok(())
}

fn ensure_directory_is_not_symlink(path: &Path) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(path).map_err(ArchiveError::DestinationMetadata)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArchiveError::DestinationNotDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn validate_exact_archive_path(path: &str) -> Result<(), ArchiveError> {
    let parsed = Path::new(path);
    if path.is_empty()
        || parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.contains('\\')
        || path.contains("//")
    {
        return Err(ArchiveError::UnsafePath(path.to_owned()));
    }
    let normalized = parsed
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_string_lossy().into_owned(),
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .join("/");
    if normalized != path {
        return Err(ArchiveError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn path_to_portable_string(path: &Path) -> Result<String, ArchiveError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(ArchiveError::NonUtf8Path)
}

fn sha256_reader(mut reader: impl Read) -> Result<String, ArchiveError> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(ArchiveError::ReadArchiveBytes)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn copy_and_hash(
    reader: &mut impl Read,
    writer: &mut impl Write,
    declared_size: u64,
) -> Result<String, ArchiveError> {
    let mut digest = Sha256::new();
    let mut remaining = declared_size;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let capacity = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ArchiveError::ArchiveTooLarge)?;
        let read = reader
            .read(&mut buffer[..capacity])
            .map_err(ArchiveError::ReadArchiveEntry)?;
        if read == 0 {
            return Err(ArchiveError::TruncatedEntry);
        }
        writer
            .write_all(&buffer[..read])
            .map_err(ArchiveError::WriteFile)?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(unix)]
fn set_manifest_permissions(path: &Path, executable: bool) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(ArchiveError::SetPermissions)
}

fn cleanup_error<T>(destination: &Path, error: ArchiveError) -> Result<T, ArchiveError> {
    let _ = fs::remove_dir_all(destination);
    Err(error)
}

/// Secure archive verification or extraction error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ArchiveError {
    #[error("artifact is not a gzip-compressed tar archive")]
    WrongArtifactKind,
    #[error("archive root is missing")]
    MissingArchiveRoot,
    #[error("failed to read archive metadata: {0}")]
    ReadArchiveMetadata(io::Error),
    #[error("archive is not a regular file: {0}")]
    ArchiveNotRegularFile(PathBuf),
    #[error("archive size mismatch: expected {expected} bytes, received {actual}")]
    ArchiveSizeMismatch { expected: u64, actual: u64 },
    #[error("archive digest mismatch: expected {expected}, received {actual}")]
    ArchiveDigestMismatch { expected: String, actual: String },
    #[error("failed to open archive: {0}")]
    OpenArchive(io::Error),
    #[error("failed to read archive bytes: {0}")]
    ReadArchiveBytes(io::Error),
    #[error("failed to read gzip tar stream: {0}")]
    ReadArchive(io::Error),
    #[error("failed to read archive entry: {0}")]
    ReadArchiveEntry(io::Error),
    #[error("failed to read archive entry path: {0}")]
    ReadEntryPath(io::Error),
    #[error("archive path is not UTF-8")]
    NonUtf8Path,
    #[error("unsafe archive path: {0}")]
    UnsafePath(String),
    #[error("archive contains duplicate path: {0}")]
    DuplicatePath(String),
    #[error("archive contains undeclared path: {0}")]
    UnexpectedPath(String),
    #[error("archive contains unsupported entry type at: {0}")]
    UnsupportedEntryType(String),
    #[error("archive exceeds {0} entries")]
    TooManyEntries(usize),
    #[error("archive uncompressed content exceeds the safety limit")]
    ArchiveTooLarge,
    #[error("archive entry ended before its declared size")]
    TruncatedEntry,
    #[error("archive is missing declared files: {0:?}")]
    MissingFiles(Vec<String>),
    #[error("archive file {path} digest mismatch: expected {expected}, received {actual}")]
    FileDigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("failed to read staging destination metadata: {0}")]
    DestinationMetadata(io::Error),
    #[error("staging destination is not a real directory: {0}")]
    DestinationNotDirectory(PathBuf),
    #[error("staging destination is not empty: {0}")]
    DestinationNotEmpty(PathBuf),
    #[error("failed to read staging destination: {0}")]
    ReadDestination(io::Error),
    #[error("failed to create staging directory: {0}")]
    CreateDestination(io::Error),
    #[error("failed to create extracted file {path}: {source}")]
    CreateFile { path: PathBuf, source: io::Error },
    #[error("failed to write extracted file: {0}")]
    WriteFile(io::Error),
    #[error("failed to sync extracted file: {0}")]
    SyncFile(io::Error),
    #[error("failed to set extracted file permissions: {0}")]
    SetPermissions(io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, EntryType, Header};
    use tempfile::tempdir;
    use url::Url;

    fn fixture_archive(path: &Path, malicious_link: bool) -> Artifact {
        let cli = b"cli";
        let server = b"server";
        let file = File::create(path).expect("archive file");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        for (name, contents) in [
            ("getaip-distribution-2.1.0/bin/getaip", cli.as_slice()),
            (
                "getaip-distribution-2.1.0/bin/getaip-server",
                server.as_slice(),
            ),
        ] {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o777);
            header.set_cksum();
            builder
                .append_data(&mut header, name, contents)
                .expect("append file");
        }
        if malicious_link {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("../../outside").expect("link name");
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "getaip-distribution-2.1.0/bin/extra",
                    io::empty(),
                )
                .expect("append link");
        }
        builder.finish().expect("finish tar");
        let encoder = builder.into_inner().expect("encoder");
        encoder.finish().expect("finish gzip");
        let bytes = fs::read(path).expect("archive bytes");
        Artifact {
            name: "getaip-distribution-2.1.0-darwin-arm64.tar.gz".to_owned(),
            kind: ArtifactKind::TarGz,
            url: Url::parse("https://github.com/getaip/core/releases/download/v2.1.0/getaip-distribution-2.1.0-darwin-arm64.tar.gz").expect("url"),
            size: bytes.len() as u64,
            sha256: crate::sha256_hex(&bytes),
            archive_root: Some("getaip-distribution-2.1.0".to_owned()),
            files: vec![
                ArtifactFile { path: "bin/getaip".to_owned(), sha256: crate::sha256_hex(cli), executable: true },
                ArtifactFile { path: "bin/getaip-server".to_owned(), sha256: crate::sha256_hex(server), executable: true },
            ],
        }
    }

    fn rewrite_archive_with_raw_path(path: &Path, raw_path: &str) {
        assert!(
            raw_path.len() < 100,
            "fixture path must fit the tar name field"
        );
        let file = File::create(path).expect("traversal archive file");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let contents = b"escape";
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o755);
        header.as_mut_bytes()[..raw_path.len()].copy_from_slice(raw_path.as_bytes());
        header.set_cksum();
        builder
            .append(&header, contents.as_slice())
            .expect("append raw traversal entry");
        builder.finish().expect("finish traversal tar");
        let encoder = builder.into_inner().expect("traversal encoder");
        encoder.finish().expect("finish traversal gzip");
    }

    #[test]
    fn exact_allowlisted_archive_extracts_with_manifest_permissions() {
        let temp = tempdir().expect("tempdir");
        let archive_path = temp.path().join("archive.tar.gz");
        let artifact = fixture_archive(&archive_path, false);
        let destination = temp.path().join("stage");
        fs::create_dir(&destination).expect("stage");
        let result = extract_verified_archive(&archive_path, &artifact, &destination)
            .expect("secure extraction");
        assert_eq!(result.file_count, 2);
        assert_eq!(
            fs::read(destination.join("bin/getaip")).expect("cli"),
            b"cli"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(destination.join("bin/getaip"))
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
    }

    #[test]
    fn link_entry_is_rejected_before_activation() {
        let temp = tempdir().expect("tempdir");
        let archive_path = temp.path().join("archive.tar.gz");
        let artifact = fixture_archive(&archive_path, true);
        let destination = temp.path().join("stage");
        fs::create_dir(&destination).expect("stage");
        let error = extract_verified_archive(&archive_path, &artifact, &destination)
            .expect_err("link must fail");
        assert!(matches!(error, ArchiveError::UnsupportedEntryType(_)));
        assert!(!destination.exists());
    }

    #[test]
    fn traversal_entry_is_rejected_and_staging_is_removed() {
        let temp = tempdir().expect("tempdir");
        let archive_path = temp.path().join("archive.tar.gz");
        let mut artifact = fixture_archive(&archive_path, false);
        rewrite_archive_with_raw_path(&archive_path, "getaip-distribution-2.1.0/../../outside");
        let bytes = fs::read(&archive_path).expect("traversal archive bytes");
        artifact.size = bytes.len() as u64;
        artifact.sha256 = crate::sha256_hex(&bytes);
        let destination = temp.path().join("stage");
        fs::create_dir(&destination).expect("stage");

        let error = extract_verified_archive(&archive_path, &artifact, &destination)
            .expect_err("traversal must fail");
        assert!(matches!(error, ArchiveError::UnsafePath(_)));
        assert!(!destination.exists());
        assert!(!temp.path().join("outside").exists());
    }

    #[test]
    fn compressed_digest_mismatch_is_rejected() {
        let temp = tempdir().expect("tempdir");
        let archive_path = temp.path().join("archive.tar.gz");
        let mut artifact = fixture_archive(&archive_path, false);
        artifact.sha256 = "00".repeat(32);
        let error = verify_archive(&archive_path, &artifact).expect_err("digest must fail");
        assert!(matches!(error, ArchiveError::ArchiveDigestMismatch { .. }));
    }
}
