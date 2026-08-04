//! Standalone, product-neutral lifecycle service for AIP connector hosts.
//!
//! This process exposes only signed registration, heartbeat, drain, and
//! offline operations. It connects with a restricted lifecycle database role;
//! catalog migration and connector admission remain separate operator actions.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use aip_connector_host::{
    ConnectorHostControlPlane, ConnectorHostControlPlaneHttpService,
    RegistryConnectorHostControlPlane,
};
use aip_connector_registry::ConnectorRegistryPoolSnapshot;
use aip_connector_registry_postgres::{
    CONNECTOR_REGISTRY_SCHEMA_VERSION, PostgresConnectorRegistry, RegistryPoolLimits,
};
use aip_core::{Principal, PrincipalId, PrincipalKind};
use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed};
use aip_gateway::CallbackSigner;
use aip_runtime::{ReplayBackend, ReplayStore, RuntimeError, RuntimeResult};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use serde::Serialize;
use std::{
    env,
    fs::{self, File},
    future::Future,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use zeroize::{Zeroize, Zeroizing};

const DATABASE_URL_FILE_ENV: &str = "AIP_CONNECTOR_CONTROL_DATABASE_URL_FILE";
const SIGNING_SEED_FILE_ENV: &str = "AIP_CONNECTOR_CONTROL_SIGNING_SEED_FILE";
const DEFAULT_PRINCIPAL_ID: &str = "service:aip-connector-control-plane";
const MAX_DATABASE_URL_BYTES: usize = 16 * 1024;
const MAX_SIGNING_SEED_BYTES: usize = 256;

/// Command-line configuration for the standalone connector control plane.
#[derive(Clone, Debug, Parser)]
#[command(
    name = "aip-connector-control-plane",
    about = "Least-privilege signed lifecycle service for AIP connector hosts"
)]
pub struct ConnectorControlPlaneArgs {
    /// Owner-only file containing the restricted lifecycle PostgreSQL URL.
    #[arg(long, value_name = "PATH")]
    pub database_url_file: Option<PathBuf>,
    /// Owner-only file containing a hex-encoded 32-byte Ed25519 signing seed.
    #[arg(long, value_name = "PATH")]
    pub signing_seed_file: Option<PathBuf>,
    /// Socket used behind the deployment's TLS termination boundary.
    #[arg(long, default_value = "127.0.0.1:8090")]
    pub bind: SocketAddr,
    /// Explicitly permit a non-loopback plaintext listener behind a trusted proxy network.
    #[arg(long, default_value_t = false)]
    pub allow_proxy_network_bind: bool,
    /// AIP service principal carried by signed control-plane responses.
    #[arg(long, default_value = DEFAULT_PRINCIPAL_ID)]
    pub principal_id: String,
    /// Connector-host lease lifetime granted by lifecycle operations.
    #[arg(long, default_value_t = 30_000)]
    pub lease_ttl_ms: u64,
    /// Maximum connections held by the restricted lifecycle pool.
    #[arg(long, default_value_t = 16)]
    pub max_connections: u32,
    /// Maximum wait for a lifecycle database connection.
    #[arg(long, default_value_t = 5_000)]
    pub acquire_timeout_ms: u64,
}

/// Startup or serving failure for the standalone connector control plane.
#[derive(Debug, Error)]
pub enum ConnectorControlPlaneError {
    /// Invalid or incomplete deployment configuration.
    #[error("configuration failed: {0}")]
    Configuration(String),
    /// Secret or listener file operation failed.
    #[error("I/O failed: {0}")]
    Io(String),
    /// Registry migration, permission, or connectivity check failed.
    #[error("connector registry failed: {0}")]
    Registry(String),
    /// HTTP listener failed.
    #[error("server failed: {0}")]
    Server(String),
}

#[derive(Clone)]
struct OperationsState {
    registry: Arc<PostgresConnectorRegistry>,
}

#[derive(Serialize)]
struct HealthDocument {
    status: &'static str,
    component: &'static str,
}

#[derive(Serialize)]
struct ReadinessDocument {
    status: &'static str,
    component: &'static str,
    schema_version: i64,
    catalog_revision: u64,
    pools: ConnectorRegistryPoolSnapshot,
}

#[derive(Clone)]
struct PostgresControlReplayBackend {
    registry: Arc<PostgresConnectorRegistry>,
}

#[async_trait]
impl ReplayBackend for PostgresControlReplayBackend {
    async fn claim(&self, message_id: &str, expires_at: OffsetDateTime) -> RuntimeResult<bool> {
        self.registry
            .claim_control_request(message_id, expires_at)
            .await
            .map_err(|error| RuntimeError::Storage(error.to_string()))
    }
}

/// Fully composed product-neutral connector lifecycle application.
pub struct ConnectorControlPlaneApplication {
    /// Requested listener address. Port zero is allowed for qualification tests.
    pub bind: SocketAddr,
    /// DID that connector hosts must trust for signed lifecycle responses.
    pub signer_did: String,
    router: Router,
    registry: Arc<PostgresConnectorRegistry>,
}

impl ConnectorControlPlaneApplication {
    /// Returns a clone of the bounded HTTP router for qualification tests.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Returns fixed-cardinality pool telemetry without database identities.
    #[must_use]
    pub fn pool_snapshot(&self) -> ConnectorRegistryPoolSnapshot {
        self.registry.pool_snapshot()
    }

    /// Serves until the supplied shutdown future resolves.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<SocketAddr, ConnectorControlPlaneError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind(self.bind)
            .await
            .map_err(|error| ConnectorControlPlaneError::Io(error.to_string()))?;
        let address = listener
            .local_addr()
            .map_err(|error| ConnectorControlPlaneError::Io(error.to_string()))?;
        axum::serve(listener, self.router.into_make_service())
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|error| ConnectorControlPlaneError::Server(error.to_string()))?;
        Ok(address)
    }
}

/// Builds the production composition without catalog-administration credentials.
pub async fn build_application(
    args: ConnectorControlPlaneArgs,
) -> Result<ConnectorControlPlaneApplication, ConnectorControlPlaneError> {
    validate_args(&args)?;
    let database_url_file = required_secret_path(
        args.database_url_file.as_deref(),
        DATABASE_URL_FILE_ENV,
        "database URL file",
    )?;
    let signing_seed_file = required_secret_path(
        args.signing_seed_file.as_deref(),
        SIGNING_SEED_FILE_ENV,
        "signing seed file",
    )?;
    let database_url_bytes = Zeroizing::new(read_owner_secret_file(
        &database_url_file,
        MAX_DATABASE_URL_BYTES,
    )?);
    let database_url = Zeroizing::new(
        String::from_utf8(database_url_bytes.to_vec())
            .map_err(|_| {
                ConnectorControlPlaneError::Configuration(
                    "database URL file must contain UTF-8".to_owned(),
                )
            })?
            .trim()
            .to_owned(),
    );
    if database_url.is_empty() {
        return Err(ConnectorControlPlaneError::Configuration(
            "database URL file must not be empty".to_owned(),
        ));
    }
    let pool_limits = RegistryPoolLimits {
        control_max_connections: 1,
        data_max_connections: args.max_connections,
        acquire_timeout: Duration::from_millis(args.acquire_timeout_ms),
    };
    let registry = Arc::new(
        PostgresConnectorRegistry::connect_data_plane(&database_url, pool_limits)
            .await
            .map_err(|error| ConnectorControlPlaneError::Registry(error.to_string()))?,
    );
    let pools = registry.pool_snapshot();
    if pools.control_max != 0 || pools.control_size != 0 {
        return Err(ConnectorControlPlaneError::Configuration(
            "connector lifecycle process must not retain catalog control credentials".to_owned(),
        ));
    }
    let seed_bytes = Zeroizing::new(read_owner_secret_file(
        &signing_seed_file,
        MAX_SIGNING_SEED_BYTES,
    )?);
    let seed_text = Zeroizing::new(String::from_utf8(seed_bytes.to_vec()).map_err(|_| {
        ConnectorControlPlaneError::Configuration(
            "signing seed file must contain UTF-8 hexadecimal text".to_owned(),
        )
    })?);
    let decoded = Zeroizing::new(hex::decode(seed_text.trim()).map_err(|_| {
        ConnectorControlPlaneError::Configuration(
            "signing seed must be exactly 64 hexadecimal characters".to_owned(),
        )
    })?);
    let mut seed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        ConnectorControlPlaneError::Configuration(
            "signing seed must encode exactly 32 bytes".to_owned(),
        )
    })?;
    let signing_key = signing_key_from_seed(seed);
    seed.zeroize();
    let principal_id = PrincipalId::parse(args.principal_id)
        .map_err(|error| ConnectorControlPlaneError::Configuration(error.to_string()))?;
    if !principal_id.as_str().starts_with("service:") {
        return Err(ConnectorControlPlaneError::Configuration(
            "connector control-plane principal must use the service: namespace".to_owned(),
        ));
    }
    let signer = CallbackSigner {
        principal: Principal::new(principal_id, PrincipalKind::Service),
        signing_key: Arc::new(signing_key),
    };
    let signer_did = did_key_from_verifying_key(&signer.signing_key.verifying_key());
    let control_plane: Arc<dyn ConnectorHostControlPlane> = Arc::new(
        RegistryConnectorHostControlPlane::new(registry.clone(), args.lease_ttl_ms)
            .map_err(|error| ConnectorControlPlaneError::Configuration(error.to_string()))?,
    );
    let replay = ReplayStore::new(Arc::new(PostgresControlReplayBackend {
        registry: registry.clone(),
    }));
    let lifecycle =
        ConnectorHostControlPlaneHttpService::new(control_plane, registry.clone(), replay, signer);
    let operations = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(OperationsState {
            registry: registry.clone(),
        });
    Ok(ConnectorControlPlaneApplication {
        bind: args.bind,
        signer_did,
        router: operations.merge(lifecycle.router()),
        registry,
    })
}

/// Parses configuration, composes the restricted service, and serves it.
pub async fn run() -> Result<(), ConnectorControlPlaneError> {
    let application = build_application(ConnectorControlPlaneArgs::parse()).await?;
    let bind = application.bind;
    let signer_did = application.signer_did.clone();
    let pools = application.pool_snapshot();
    let startup = serde_json::json!({
        "component": "aip-connector-control-plane",
        "status": "starting",
        "bind": bind.to_string(),
        "signer_did": signer_did,
        "schema_version": CONNECTOR_REGISTRY_SCHEMA_VERSION,
        "control_pool_max": pools.control_max,
        "lifecycle_pool_max": pools.data_max,
    });
    eprintln!("{startup}");
    application.serve_until(shutdown_signal()).await.map(|_| ())
}

fn validate_args(args: &ConnectorControlPlaneArgs) -> Result<(), ConnectorControlPlaneError> {
    if !args.bind.ip().is_loopback() && !args.allow_proxy_network_bind {
        return Err(ConnectorControlPlaneError::Configuration(
            "a non-loopback plaintext bind requires --allow-proxy-network-bind and external TLS termination"
                .to_owned(),
        ));
    }
    if !(1_000..=300_000).contains(&args.lease_ttl_ms) {
        return Err(ConnectorControlPlaneError::Configuration(
            "connector lease TTL must be between 1000 and 300000 milliseconds".to_owned(),
        ));
    }
    if args.max_connections == 0 || args.max_connections > 256 || args.acquire_timeout_ms == 0 {
        return Err(ConnectorControlPlaneError::Configuration(
            "database pool must contain 1 to 256 connections and acquire timeout must be greater than zero"
                .to_owned(),
        ));
    }
    if args.acquire_timeout_ms > 60_000 {
        return Err(ConnectorControlPlaneError::Configuration(
            "database acquire timeout must not exceed 60000 milliseconds".to_owned(),
        ));
    }
    Ok(())
}

fn required_secret_path(
    argument: Option<&Path>,
    environment_name: &str,
    label: &str,
) -> Result<PathBuf, ConnectorControlPlaneError> {
    argument
        .map(Path::to_path_buf)
        .or_else(|| {
            env::var_os(environment_name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .ok_or_else(|| {
            ConnectorControlPlaneError::Configuration(format!(
                "{label} is required via its command-line option or {environment_name}"
            ))
        })
}

fn read_owner_secret_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, ConnectorControlPlaneError> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|error| ConnectorControlPlaneError::Io(error.to_string()))?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(ConnectorControlPlaneError::Configuration(format!(
            "secret file `{}` must be a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if link_metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConnectorControlPlaneError::Configuration(format!(
                "secret file `{}` must not grant group or other permissions",
                path.display()
            )));
        }
    }
    let length = usize::try_from(link_metadata.len()).unwrap_or(usize::MAX);
    if length == 0 || length > max_bytes {
        return Err(ConnectorControlPlaneError::Configuration(format!(
            "secret file `{}` must contain 1 to {max_bytes} bytes",
            path.display()
        )));
    }
    let file =
        File::open(path).map_err(|error| ConnectorControlPlaneError::Io(error.to_string()))?;
    let mut bytes = Vec::with_capacity(length);
    file.take(
        u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|error| ConnectorControlPlaneError::Io(error.to_string()))?;
    if bytes.len() > max_bytes {
        bytes.zeroize();
        return Err(ConnectorControlPlaneError::Configuration(format!(
            "secret file `{}` exceeds {max_bytes} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

async fn health() -> Json<HealthDocument> {
    Json(HealthDocument {
        status: "ok",
        component: "aip-connector-control-plane",
    })
}

async fn ready(State(state): State<OperationsState>) -> Response {
    let schema = state.registry.installed_schema_version().await;
    let revision = state.registry.revision().await;
    match (schema, revision) {
        (Ok(schema_version), Ok(catalog_revision))
            if schema_version == CONNECTOR_REGISTRY_SCHEMA_VERSION =>
        {
            (
                StatusCode::OK,
                Json(ReadinessDocument {
                    status: "ready",
                    component: "aip-connector-control-plane",
                    schema_version,
                    catalog_revision: catalog_revision.0,
                    pools: state.registry.pool_snapshot(),
                }),
            )
                .into_response()
        }
        (schema, revision) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "component": "aip-connector-control-plane",
                "schema_ok": schema.is_ok(),
                "catalog_ok": revision.is_ok(),
            })),
        )
            .into_response(),
    }
}

async fn metrics(State(state): State<OperationsState>) -> Json<ConnectorRegistryPoolSnapshot> {
    Json(state.registry.pool_snapshot())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectorControlPlaneArgs, validate_args};
    use std::net::SocketAddr;

    fn args(bind: &str) -> ConnectorControlPlaneArgs {
        ConnectorControlPlaneArgs {
            database_url_file: None,
            signing_seed_file: None,
            bind: bind.parse::<SocketAddr>().expect("test bind"),
            allow_proxy_network_bind: false,
            principal_id: "service:test-control-plane".to_owned(),
            lease_ttl_ms: 30_000,
            max_connections: 4,
            acquire_timeout_ms: 5_000,
        }
    }

    #[test]
    fn non_loopback_plaintext_bind_requires_explicit_proxy_boundary() {
        assert!(validate_args(&args("127.0.0.1:8090")).is_ok());
        let mut exposed = args("0.0.0.0:8090");
        assert!(validate_args(&exposed).is_err());
        exposed.allow_proxy_network_bind = true;
        assert!(validate_args(&exposed).is_ok());
    }

    #[test]
    fn database_pool_bounds_fail_closed() {
        let mut unbounded = args("127.0.0.1:8090");
        unbounded.max_connections = 0;
        assert!(validate_args(&unbounded).is_err());
        unbounded.max_connections = 4;
        unbounded.acquire_timeout_ms = 60_001;
        assert!(validate_args(&unbounded).is_err());
    }
}
