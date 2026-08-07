use crate::{
    Artifact, DEFAULT_RELEASE_ORIGIN, GETAIP_SOFTWARE_VERSION, GITHUB_RELEASE_REDIRECT_HOST,
    TrustStore, VerifiedManifest, verify_signed_manifest,
};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use thiserror::Error;

const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
static DOWNLOAD_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Result of an exact release-asset download or cache reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadResult {
    /// Verified local path.
    pub path: PathBuf,
    /// Number of verified bytes.
    pub size: u64,
    /// Exact lowercase SHA-256 digest.
    pub sha256: String,
    /// Whether an already verified local file was reused.
    pub reused: bool,
}

/// Strict release client with one GitHub release-asset redirect and bounded requests.
#[derive(Clone, Debug)]
pub struct ReleaseClient {
    client: Client,
}

impl ReleaseClient {
    /// Builds a release client with explicit connect and total timeouts.
    pub fn new() -> Result<Self, DownloadError> {
        let client = Client::builder()
            .redirect(Policy::custom(|attempt| {
                if attempt.previous().len() == 1 && approved_github_asset_redirect(attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .user_agent(format!("getaip/{GETAIP_SOFTWARE_VERSION}"))
            .build()
            .map_err(DownloadError::BuildClient)?;
        Ok(Self { client })
    }

    /// Fetches and verifies the current release manifest before parsing it.
    pub async fn fetch_signed_manifest(
        &self,
        version: &str,
        trust_store: &TrustStore,
    ) -> Result<VerifiedManifest, DownloadError> {
        let manifest_url = manifest_url(version)?;
        let signature_url = manifest_signature_url(version)?;
        let manifest_bytes = self
            .fetch_bounded_bytes(&manifest_url, MAX_MANIFEST_BYTES)
            .await?;
        let signature_bytes = self
            .fetch_bounded_bytes(&signature_url, MAX_SIGNATURE_BYTES)
            .await?;
        verify_signed_manifest(&manifest_bytes, &signature_bytes, trust_store)
            .map_err(DownloadError::Manifest)
    }

    /// Downloads one signed-manifest artifact to a controlled cache path.
    pub async fn download_artifact(
        &self,
        artifact: &Artifact,
        destination: &Path,
    ) -> Result<DownloadResult, DownloadError> {
        if let Ok(result) = verify_downloaded_file(destination, artifact.size, &artifact.sha256) {
            return Ok(DownloadResult {
                path: destination.to_path_buf(),
                size: result.0,
                sha256: result.1,
                reused: true,
            });
        }
        let parent = destination
            .parent()
            .ok_or_else(|| DownloadError::MissingParent(destination.to_path_buf()))?;
        ensure_real_directory(parent)?;
        let response = self
            .client
            .get(artifact.url.clone())
            .send()
            .await
            .map_err(DownloadError::Request)?;
        if response.status() != StatusCode::OK {
            return Err(DownloadError::UnexpectedStatus {
                url: artifact.url.clone(),
                status: response.status(),
            });
        }
        if let Some(length) = response.content_length()
            && length != artifact.size
        {
            return Err(DownloadError::ContentLengthMismatch {
                expected: artifact.size,
                actual: length,
            });
        }
        let sequence = DOWNLOAD_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let file_name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| DownloadError::InvalidFileName(destination.to_path_buf()))?;
        let temporary = parent.join(format!(".{file_name}.part-{}-{sequence}", process::id()));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| DownloadError::Create {
                path: temporary.clone(),
                source,
            })?;
        set_private_permissions(&temporary)?;

        let result = async {
            let mut stream = response.bytes_stream();
            let mut digest = Sha256::new();
            let mut received = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(DownloadError::ReadResponse)?;
                received = received
                    .checked_add(chunk.len() as u64)
                    .ok_or(DownloadError::DownloadTooLarge)?;
                if received > artifact.size {
                    return Err(DownloadError::DownloadTooLarge);
                }
                output
                    .write_all(&chunk)
                    .map_err(|source| DownloadError::Write {
                        path: temporary.clone(),
                        source,
                    })?;
                digest.update(&chunk);
            }
            if received != artifact.size {
                return Err(DownloadError::SizeMismatch {
                    expected: artifact.size,
                    actual: received,
                });
            }
            let actual = hex::encode(digest.finalize());
            if actual != artifact.sha256 {
                return Err(DownloadError::DigestMismatch {
                    expected: artifact.sha256.clone(),
                    actual,
                });
            }
            output.sync_all().map_err(|source| DownloadError::Sync {
                path: temporary.clone(),
                source,
            })?;
            replace_cache_file(&temporary, destination)?;
            Ok(DownloadResult {
                path: destination.to_path_buf(),
                size: received,
                sha256: artifact.sha256.clone(),
                reused: false,
            })
        }
        .await;
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    async fn fetch_bounded_bytes(&self, url: &Url, maximum: u64) -> Result<Vec<u8>, DownloadError> {
        validate_fixed_metadata_url(url)?;
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(DownloadError::Request)?;
        if response.status() != StatusCode::OK {
            return Err(DownloadError::UnexpectedStatus {
                url: url.clone(),
                status: response.status(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum)
        {
            return Err(DownloadError::DownloadTooLarge);
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(DownloadError::ReadResponse)?;
            if (bytes.len() as u64)
                .checked_add(chunk.len() as u64)
                .is_none_or(|length| length > maximum)
            {
                return Err(DownloadError::DownloadTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn approved_github_asset_redirect(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(GITHUB_RELEASE_REDIRECT_HOST)
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.fragment().is_none()
        && url.path().starts_with("/github-production-release-asset/")
        && url.query().is_some()
}

/// Exact current release-manifest URL.
pub fn manifest_url(version: &str) -> Result<Url, DownloadError> {
    release_metadata_url(version, "getaip-distribution-manifest.v1.json")
}

/// Exact current detached-signature URL.
pub fn manifest_signature_url(version: &str) -> Result<Url, DownloadError> {
    release_metadata_url(version, "getaip-distribution-manifest.v1.json.sig")
}

fn release_metadata_url(version: &str, name: &str) -> Result<Url, DownloadError> {
    semver::Version::parse(version)
        .map_err(|error| DownloadError::InvalidVersion(error.to_string()))?;
    let url = Url::parse(&format!("{DEFAULT_RELEASE_ORIGIN}v{version}/{name}"))
        .map_err(DownloadError::InvalidUrl)?;
    validate_fixed_metadata_url(&url)?;
    Ok(url)
}

fn validate_fixed_metadata_url(url: &Url) -> Result<(), DownloadError> {
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.as_str().starts_with(DEFAULT_RELEASE_ORIGIN)
    {
        return Err(DownloadError::UnapprovedUrl(url.clone()));
    }
    Ok(())
}

/// Verifies an already downloaded regular file by exact size and digest.
pub fn verify_downloaded_file(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(u64, String), DownloadError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DownloadError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DownloadError::NotRegularFile(path.to_path_buf()));
    }
    if metadata.len() != expected_size {
        return Err(DownloadError::SizeMismatch {
            expected: expected_size,
            actual: metadata.len(),
        });
    }
    let mut input = File::open(path).map_err(|source| DownloadError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|source| DownloadError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = hex::encode(digest.finalize());
    if actual != expected_sha256 {
        return Err(DownloadError::DigestMismatch {
            expected: expected_sha256.to_owned(),
            actual,
        });
    }
    Ok((metadata.len(), actual))
}

fn replace_cache_file(temporary: &Path, destination: &Path) -> Result<(), DownloadError> {
    if destination.exists() {
        let metadata =
            fs::symlink_metadata(destination).map_err(|source| DownloadError::Metadata {
                path: destination.to_path_buf(),
                source,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DownloadError::NotRegularFile(destination.to_path_buf()));
        }
        fs::remove_file(destination).map_err(|source| DownloadError::RemoveCached {
            path: destination.to_path_buf(),
            source,
        })?;
    }
    fs::rename(temporary, destination).map_err(|source| DownloadError::Rename {
        from: temporary.to_path_buf(),
        to: destination.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), DownloadError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DownloadError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DownloadError::UnsafeDirectory(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), DownloadError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        DownloadError::Permissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Strict release download error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum DownloadError {
    #[error("failed to build release HTTP client: {0}")]
    BuildClient(reqwest::Error),
    #[error("invalid release version: {0}")]
    InvalidVersion(String),
    #[error("invalid release URL: {0}")]
    InvalidUrl(url::ParseError),
    #[error("unapproved release URL: {0}")]
    UnapprovedUrl(Url),
    #[error("release request failed: {0}")]
    Request(reqwest::Error),
    #[error("release response from {url} returned HTTP {status}")]
    UnexpectedStatus { url: Url, status: StatusCode },
    #[error("release response stream failed: {0}")]
    ReadResponse(reqwest::Error),
    #[error("download exceeds the signed size or safety limit")]
    DownloadTooLarge,
    #[error("Content-Length mismatch: expected {expected}, received {actual}")]
    ContentLengthMismatch { expected: u64, actual: u64 },
    #[error("download size mismatch: expected {expected}, received {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("download digest mismatch: expected {expected}, received {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("failed to read metadata for {path}: {source}")]
    Metadata { path: PathBuf, source: io::Error },
    #[error("download path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("download directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("download path has no parent: {0}")]
    MissingParent(PathBuf),
    #[error("download path has an invalid file name: {0}")]
    InvalidFileName(PathBuf),
    #[error("failed to create download {path}: {source}")]
    Create { path: PathBuf, source: io::Error },
    #[error("failed to write download {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to sync download {path}: {source}")]
    Sync { path: PathBuf, source: io::Error },
    #[error("failed to open downloaded file {path}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("failed to read downloaded file {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to set private permissions on {path}: {source}")]
    Permissions { path: PathBuf, source: io::Error },
    #[error("failed to remove invalid cached file {path}: {source}")]
    RemoveCached { path: PathBuf, source: io::Error },
    #[error("failed to activate download from {from} to {to}: {source}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("signed release manifest is invalid: {0}")]
    Manifest(crate::ManifestError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn metadata_urls_are_exact_and_https() {
        assert_eq!(
            manifest_url("2.1.0").expect("manifest URL").as_str(),
            "https://github.com/getaip/core/releases/download/v2.1.0/getaip-distribution-manifest.v1.json"
        );
        assert_eq!(
            manifest_signature_url("2.1.0")
                .expect("signature URL")
                .as_str(),
            "https://github.com/getaip/core/releases/download/v2.1.0/getaip-distribution-manifest.v1.json.sig"
        );
    }

    #[test]
    fn only_the_exact_github_release_asset_redirect_is_approved() {
        let approved = Url::parse(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?token=3",
        )
        .expect("approved URL");
        assert!(approved_github_asset_redirect(&approved));
        for rejected in [
            "http://release-assets.githubusercontent.com/github-production-release-asset/1/2?token=3",
            "https://evil.example/github-production-release-asset/1/2?token=3",
            "https://release-assets.githubusercontent.com/other/1/2?token=3",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2",
        ] {
            assert!(!approved_github_asset_redirect(
                &Url::parse(rejected).expect("rejected URL")
            ));
        }
    }

    #[test]
    fn local_download_verification_rejects_symlink_and_tamper() {
        let temporary = tempdir().expect("tempdir");
        let file = temporary.path().join("asset");
        fs::write(&file, b"trusted").expect("asset");
        let digest = hex::encode(Sha256::digest(b"trusted"));
        assert!(verify_downloaded_file(&file, 7, &digest).is_ok());
        fs::write(&file, b"tamper!").expect("tamper");
        assert!(matches!(
            verify_downloaded_file(&file, 7, &digest),
            Err(DownloadError::DigestMismatch { .. })
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = temporary.path().join("link");
            symlink(&file, &link).expect("symlink");
            assert!(matches!(
                verify_downloaded_file(&link, 7, &digest),
                Err(DownloadError::NotRegularFile(_))
            ));
        }
    }

    #[tokio::test]
    async fn interrupted_download_removes_partial_file_before_returning() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture server");
        let address = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await.expect("read request");
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\npartial",
                )
                .await
                .expect("write truncated response");
            socket.shutdown().await.expect("close truncated response");
        });

        let temporary = tempdir().expect("tempdir");
        let cache = temporary.path().join("downloads");
        fs::create_dir(&cache).expect("cache");
        let destination = cache.join("getaip");
        let artifact = Artifact {
            name: "getaip-test".to_owned(),
            kind: crate::ArtifactKind::RawExecutable,
            url: Url::parse(&format!("http://{address}/getaip")).expect("fixture URL"),
            size: 16,
            sha256: hex::encode(Sha256::digest(b"complete-payload")),
            archive_root: None,
            files: Vec::new(),
        };

        let error = ReleaseClient::new()
            .expect("release client")
            .download_artifact(&artifact, &destination)
            .await
            .expect_err("truncated download must fail");
        assert!(matches!(
            error,
            DownloadError::ReadResponse(_) | DownloadError::SizeMismatch { .. }
        ));
        server.await.expect("fixture server");
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&cache).expect("cache entries").count(), 0);
    }
}
