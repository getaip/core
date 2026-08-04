//! Production bootstrap shared by every standalone AIP connector host.
//!
//! Product binaries use this crate for the security-sensitive process shell:
//! owner-controlled secret files, durable runtime storage, native AIP signing,
//! lifecycle control-plane authentication, bounded listener configuration,
//! readiness recovery, callbacks, and graceful draining. Product crates remain
//! responsible only for provider credentials, provider APIs, webhook
//! verification, and semantic error mapping.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use aip_auth::{CredentialHandle, VerifiedTenant};
use aip_connector::{Connector, ConnectorContext, FrozenConnector};
use aip_connector_host::{
    ConnectorHost, ConnectorHostCallbackConfig, ConnectorHostConfig, ConnectorHostError,
    ConnectorHostEventConfig, ConnectorHostEventPublisher, ConnectorHostLimits,
    CredentialRevisionCheck, CredentialRevisionPolicy, CredentialRevisionProvider,
    CredentialRevisionProviderError, HttpConnectorHostControlPlane,
    StaticCredentialRevisionProvider,
};
use aip_connector_registry::{
    ConnectorInstanceId, ConnectorReplicaId, ConnectorTopology, ConnectorTypeId, ConnectorVersionId,
};
use aip_core::{ExternalAccountRef, Principal, PrincipalId, PrincipalKind, TenantRef};
use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed, verifying_key_from_did_key};
use aip_gateway::{CallbackSigner, GatewayCallbackPolicy};
use aip_runtime::{ExecutionCheckpointObserver, Runtime, RuntimeStores};
use aip_storage_postgres::PostgresRuntimeStore;
use async_trait::async_trait;
use axum::Router;
use clap::Args;
use serde::de::DeserializeOwned;
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    future::Future,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use url::Url;
use zeroize::Zeroize;
use zeroize::Zeroizing;

const MAX_DATABASE_URL_BYTES: usize = 16 * 1024;
const MAX_SIGNING_SEED_BYTES: usize = 256;
const MAX_CREDENTIAL_REVISION_POLICY_BYTES: usize = 64 * 1024;

/// Common command-line contract implemented by every connector-host binary.
///
/// Secret values are deliberately absent. Database credentials and signing
/// material are read from bounded files after symlink and permission checks.
#[derive(Clone, Debug, Args)]
pub struct ConnectorHostBootstrapArgs {
    /// Listener address used behind the deployment ingress.
    #[arg(long, env = "AIP_CONNECTOR_HOST_BIND", default_value = "0.0.0.0:8081")]
    pub bind: SocketAddr,
    /// Externally reachable native AIP endpoint ending in `/aip/v1/messages`.
    #[arg(long, env = "AIP_CONNECTOR_HOST_PUBLIC_ENDPOINT")]
    pub public_endpoint: Url,
    /// Narrow lifecycle control-plane endpoint.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CONTROL_ENDPOINT")]
    pub control_plane_endpoint: Url,
    /// did:key used to verify lifecycle control-plane responses.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CONTROL_DID")]
    pub control_plane_did: Option<String>,
    /// Regular owner-controlled file containing the lifecycle control-plane did:key.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CONTROL_DID_FILE")]
    pub control_plane_did_file: Option<PathBuf>,
    /// Owner-controlled file containing the connector runtime PostgreSQL URL.
    #[arg(long, env = "AIP_CONNECTOR_HOST_DATABASE_URL_FILE")]
    pub database_url_file: PathBuf,
    /// Owner-controlled file containing a 32-byte Ed25519 seed in hexadecimal.
    #[arg(long, env = "AIP_CONNECTOR_HOST_SIGNING_SEED_FILE")]
    pub signing_seed_file: PathBuf,
    /// Admitted connector type id.
    #[arg(long, env = "AIP_CONNECTOR_HOST_TYPE_ID")]
    pub connector_type_id: ConnectorTypeId,
    /// Admitted immutable connector version id.
    #[arg(long, env = "AIP_CONNECTOR_HOST_VERSION_ID")]
    pub version_id: ConnectorVersionId,
    /// Logical connector instance id.
    #[arg(long, env = "AIP_CONNECTOR_HOST_INSTANCE_ID")]
    pub instance_id: ConnectorInstanceId,
    /// Pre-provisioned concrete replica id.
    #[arg(long, env = "AIP_CONNECTOR_HOST_REPLICA_ID")]
    pub replica_id: ConnectorReplicaId,
    /// Verified AIP tenant id owned by this instance.
    #[arg(long, env = "AIP_CONNECTOR_HOST_TENANT_ID")]
    pub tenant_id: String,
    /// Optional source system for the tenant reference.
    #[arg(long, env = "AIP_CONNECTOR_HOST_TENANT_SYSTEM")]
    pub tenant_system: Option<String>,
    /// Stable membership assertion for this connector instance.
    #[arg(long, env = "AIP_CONNECTOR_HOST_MEMBERSHIP_ID")]
    pub membership_id: String,
    /// Stable account id in the external product owned by this instance.
    #[arg(long, env = "AIP_CONNECTOR_HOST_EXTERNAL_ACCOUNT_ID")]
    pub external_account_id: Option<String>,
    /// External product/system name; required with `external-account-id`.
    #[arg(long, env = "AIP_CONNECTOR_HOST_EXTERNAL_ACCOUNT_SYSTEM")]
    pub external_account_system: Option<String>,
    /// Principal id used by the central `getaip-server` fleet gateway.
    #[arg(long, env = "AIP_CONNECTOR_HOST_GATEWAY_PRINCIPAL_ID")]
    pub gateway_principal_id: PrincipalId,
    /// did:key used to verify central gateway requests.
    #[arg(long, env = "AIP_CONNECTOR_HOST_GATEWAY_DID")]
    pub gateway_did: Option<String>,
    /// Regular owner-controlled file containing the central gateway did:key.
    #[arg(long, env = "AIP_CONNECTOR_HOST_GATEWAY_DID_FILE")]
    pub gateway_did_file: Option<PathBuf>,
    /// Optional PEM root certificate for private-PKI host, control, and callback TLS.
    #[arg(long, env = "AIP_CONNECTOR_HOST_TLS_CA_FILE")]
    pub tls_ca_certificate_file: Option<PathBuf>,
    /// Deployment trust domain shared by gateway and host.
    #[arg(long, env = "AIP_CONNECTOR_HOST_TRUST_DOMAIN")]
    pub trust_domain: String,
    /// Deployment region used for topology-aware routing.
    #[arg(long, env = "AIP_CONNECTOR_HOST_REGION", default_value = "global")]
    pub region: String,
    /// Independent failure zone within the deployment region.
    #[arg(long, env = "AIP_CONNECTOR_HOST_ZONE", default_value = "default")]
    pub zone: String,
    /// Operator-defined capacity class exposed by this replica.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_CAPACITY_CLASS",
        default_value = "standard"
    )]
    pub capacity_class: String,
    /// Exact immutable OCI digest for the running host artifact.
    #[arg(long, env = "AIP_CONNECTOR_HOST_ARTIFACT_DIGEST")]
    pub artifact_digest: String,
    /// Non-secret opaque reference to the deployment secret provider.
    #[arg(long, env = "AIP_CONNECTOR_HOST_SECRET_PROVIDER_REF")]
    pub secret_provider_ref: String,
    /// Monotonic non-secret instance configuration revision.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CONFIG_REVISION", default_value_t = 1)]
    pub config_revision: u64,
    /// Optional opaque provider credential handle id.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CREDENTIAL_ID")]
    pub credential_id: Option<String>,
    /// Credential-handle issuer; required with `credential-id`.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CREDENTIAL_ISSUER")]
    pub credential_issuer: Option<String>,
    /// Verified credential scope. Repeat for multiple scopes.
    #[arg(
        long = "credential-scope",
        env = "AIP_CONNECTOR_HOST_CREDENTIAL_SCOPES",
        value_delimiter = ','
    )]
    pub credential_scopes: Vec<String>,
    /// Opaque credential revision pinned to new route assignments.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CREDENTIAL_REVISION")]
    pub credential_revision_ref: Option<String>,
    /// Reloadable non-secret JSON policy for credential rotation and revocation.
    ///
    /// The file is read and validated immediately before each provider side
    /// effect. Replace it atomically to revoke a revision without restarting
    /// the host. Read or parse failures deny the action.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CREDENTIAL_POLICY_FILE")]
    pub credential_revision_policy_file: Option<PathBuf>,
    /// Fixed central stream callback endpoint.
    #[arg(long, env = "AIP_CONNECTOR_HOST_CALLBACK_ENDPOINT")]
    pub callback_endpoint: Option<Url>,
    /// Permit callback HTTP for an explicitly controlled development network.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_CALLBACK_ALLOW_HTTP",
        default_value_t = false
    )]
    pub callback_allow_http: bool,
    /// Permit private callback addresses for an explicitly controlled network.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_CALLBACK_ALLOW_PRIVATE",
        default_value_t = false
    )]
    pub callback_allow_private_networks: bool,
    /// Fixed central connector-event ingress endpoint.
    #[arg(long, env = "AIP_CONNECTOR_HOST_EVENT_ENDPOINT")]
    pub event_endpoint: Option<Url>,
    /// Permit event-ingress HTTP for an explicitly controlled network.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_EVENT_ALLOW_HTTP",
        default_value_t = false
    )]
    pub event_allow_http: bool,
    /// Permit a private event-ingress address for an explicitly controlled network.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_EVENT_ALLOW_PRIVATE",
        default_value_t = false
    )]
    pub event_allow_private_networks: bool,
    /// Permit plaintext host/control endpoints only on loopback.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_ALLOW_LOOPBACK_HTTP",
        default_value_t = false
    )]
    pub allow_insecure_loopback_http: bool,
    /// Maximum concurrent actions accepted by this replica.
    #[arg(long, env = "AIP_CONNECTOR_HOST_MAX_IN_FLIGHT", default_value_t = 32)]
    pub max_in_flight: u32,
    /// Registry lease lifetime in milliseconds.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_LEASE_TTL_MS",
        default_value_t = 30_000
    )]
    pub lease_ttl_ms: u64,
    /// Registry heartbeat interval in milliseconds.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_HEARTBEAT_MS",
        default_value_t = 10_000
    )]
    pub heartbeat_interval_ms: u64,
    /// Graceful drain deadline in milliseconds.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_DRAIN_TIMEOUT_MS",
        default_value_t = 30_000
    )]
    pub drain_timeout_ms: u64,
    /// Provider and storage readiness probe deadline in milliseconds.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_HEALTH_TIMEOUT_MS",
        default_value_t = 2_000
    )]
    pub health_probe_timeout_ms: u64,
    /// Lifecycle request deadline in milliseconds.
    #[arg(
        long,
        env = "AIP_CONNECTOR_HOST_CONTROL_TIMEOUT_MS",
        default_value_t = 5_000
    )]
    pub control_timeout_ms: u64,
}

/// Prepared, product-neutral process shell for one connector replica.
pub struct PreparedConnectorHost {
    bind: SocketAddr,
    config: ConnectorHostConfig,
    stores: RuntimeStores,
    control_plane: Arc<HttpConnectorHostControlPlane>,
    credential_revisions: Arc<dyn CredentialRevisionProvider>,
    callbacks: Option<ConnectorHostCallbackConfig>,
    events: Option<ConnectorHostEventConfig>,
    execution_checkpoint_observer: Option<Arc<dyn ExecutionCheckpointObserver>>,
}

impl std::fmt::Debug for PreparedConnectorHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedConnectorHost")
            .field("bind", &self.bind)
            .field("config", &self.config)
            .field("credential_revision_provider", &"configured")
            .field("callbacks", &self.callbacks)
            .field("events", &self.events)
            .field(
                "execution_checkpoint_observer",
                &self
                    .execution_checkpoint_observer
                    .as_ref()
                    .map(|_| "configured"),
            )
            .finish_non_exhaustive()
    }
}

/// Failure while building or serving the common connector-host shell.
#[derive(Debug, Error)]
pub enum ConnectorHostBootstrapError {
    /// Deployment arguments or secret-file metadata are invalid.
    #[error("connector-host bootstrap configuration failed: {0}")]
    Configuration(String),
    /// Durable runtime storage could not be opened or migrated.
    #[error("connector-host durable storage failed: {0}")]
    Storage(String),
    /// Product connector discovery failed before admission.
    #[error("connector-host product discovery failed: {0}")]
    Discovery(String),
    /// Common host construction or lifecycle failed.
    #[error(transparent)]
    Host(#[from] ConnectorHostError),
    /// Listener setup failed.
    #[error("connector-host listener failed: {0}")]
    Listener(String),
}

impl PreparedConnectorHost {
    /// Validates configuration, opens durable storage, and constructs signed
    /// control-plane identity without registering the replica.
    pub async fn prepare<C>(
        args: ConnectorHostBootstrapArgs,
        connector: &C,
    ) -> Result<Self, ConnectorHostBootstrapError>
    where
        C: Connector + ?Sized,
    {
        if args.allow_insecure_loopback_http && !args.bind.ip().is_loopback() {
            return Err(ConnectorHostBootstrapError::Configuration(
                "loopback HTTP exceptions require a loopback listener".to_owned(),
            ));
        }
        validate_text("tenant id", &args.tenant_id, 512)?;
        validate_text("membership id", &args.membership_id, 512)?;
        validate_text("trust domain", &args.trust_domain, 253)?;
        validate_text(
            "secret provider reference",
            &args.secret_provider_ref,
            2_048,
        )?;
        let external_account = match (
            args.external_account_id.as_deref(),
            args.external_account_system.as_deref(),
        ) {
            (Some(id), Some(system)) => {
                validate_text("external account id", id, 512)?;
                validate_text("external account system", system, 128)?;
                Some(ExternalAccountRef {
                    id: id.to_owned(),
                    system: system.to_owned(),
                })
            }
            (None, None) => None,
            _ => {
                return Err(ConnectorHostBootstrapError::Configuration(
                    "external account id and system must be configured together".to_owned(),
                ));
            }
        };
        let gateway_did = resolve_did(
            "central gateway",
            args.gateway_did.as_deref(),
            args.gateway_did_file.as_deref(),
        )?;
        let control_plane_did = resolve_did(
            "connector control plane",
            args.control_plane_did.as_deref(),
            args.control_plane_did_file.as_deref(),
        )?;
        verifying_key_from_did_key(&gateway_did)
            .map_err(|error| ConnectorHostBootstrapError::Configuration(error.to_string()))?;
        verifying_key_from_did_key(&control_plane_did)
            .map_err(|error| ConnectorHostBootstrapError::Configuration(error.to_string()))?;
        let tls_ca_certificate_pem = args
            .tls_ca_certificate_file
            .as_deref()
            .map(|path| read_public_file(path, 1024 * 1024, "TLS CA certificate"))
            .transpose()?;

        let seed_bytes = Zeroizing::new(read_bounded_secret(
            &args.signing_seed_file,
            MAX_SIGNING_SEED_BYTES,
        )?);
        let decoded_seed = Zeroizing::new(hex::decode(trim_ascii(&seed_bytes)).map_err(|_| {
            ConnectorHostBootstrapError::Configuration(
                "connector-host signing seed must be 64 hexadecimal characters".to_owned(),
            )
        })?);
        let mut seed: [u8; 32] = decoded_seed.as_slice().try_into().map_err(|_| {
            ConnectorHostBootstrapError::Configuration(
                "connector-host signing seed must encode exactly 32 bytes".to_owned(),
            )
        })?;
        let signing_key = Arc::new(signing_key_from_seed(seed));
        seed.zeroize();

        let context = ConnectorContext {
            tenant_id: Some(args.tenant_id.clone()),
            metadata: Default::default(),
        };
        let manifest = connector
            .discover(&context)
            .await
            .map_err(|error| ConnectorHostBootstrapError::Discovery(error.to_string()))?;
        let mut host_principal = manifest.agent;
        host_principal.trust_domain = Some(args.trust_domain.clone());
        host_principal.did = Some(did_key_from_verifying_key(&signing_key.verifying_key()));
        let host_signer = CallbackSigner {
            principal: host_principal,
            signing_key,
        };
        let callbacks = callback_config(
            &args,
            host_signer.clone(),
            tls_ca_certificate_pem.as_deref(),
        )?;
        let events = event_config(
            &args,
            host_signer.clone(),
            tls_ca_certificate_pem.as_deref(),
        )?;

        let credential = credential_handle(&args)?;
        let credential_revisions = credential_revision_provider(&args).await?;
        let tenant = VerifiedTenant {
            tenant: TenantRef {
                id: args.tenant_id.clone(),
                system: args.tenant_system.clone(),
            },
            membership_id: args.membership_id.clone(),
            roles: BTreeSet::new(),
            groups: BTreeSet::new(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        };
        let mut gateway_principal =
            Principal::new(args.gateway_principal_id.clone(), PrincipalKind::Service);
        gateway_principal.trust_domain = Some(args.trust_domain.clone());
        gateway_principal.did = Some(gateway_did.clone());
        let limits = ConnectorHostLimits {
            max_in_flight: args.max_in_flight,
            lease_ttl_ms: args.lease_ttl_ms,
            heartbeat_interval_ms: args.heartbeat_interval_ms,
            drain_timeout_ms: args.drain_timeout_ms,
            health_probe_timeout_ms: args.health_probe_timeout_ms,
            ..ConnectorHostLimits::default()
        };
        let config = ConnectorHostConfig {
            connector_type_id: args.connector_type_id,
            version_id: args.version_id,
            instance_id: args.instance_id,
            replica_id: args.replica_id,
            public_endpoint: args.public_endpoint,
            tenant,
            credential,
            external_account,
            credential_revision_ref: args.credential_revision_ref,
            config_revision: args.config_revision,
            secret_provider_ref: args.secret_provider_ref,
            artifact_digest: args.artifact_digest,
            host_signer: host_signer.clone(),
            gateway_principal,
            gateway_did,
            trust_domain: args.trust_domain,
            topology: ConnectorTopology {
                region: args.region,
                zone: args.zone,
                capacity_class: args.capacity_class,
            },
            allow_insecure_loopback_http: args.allow_insecure_loopback_http,
            limits,
        };

        let database_url = read_secret_utf8(&args.database_url_file, MAX_DATABASE_URL_BYTES)?;
        let store = PostgresRuntimeStore::connect(database_url.as_str())
            .await
            .map_err(|error| ConnectorHostBootstrapError::Storage(error.to_string()));
        let stores = store?.runtime_stores();

        let control_plane = Arc::new(HttpConnectorHostControlPlane::new_with_tls_ca(
            args.control_plane_endpoint,
            host_signer.clone(),
            control_plane_did,
            args.allow_insecure_loopback_http,
            args.control_timeout_ms,
            tls_ca_certificate_pem.as_deref(),
        )?);
        Ok(Self {
            bind: args.bind,
            config,
            stores,
            control_plane,
            credential_revisions,
            callbacks,
            events,
            execution_checkpoint_observer: None,
        })
    }

    /// Returns the complete durable stores so a product connector can bind its
    /// own durable projections to exactly the same backend before serving.
    #[must_use]
    pub fn runtime_stores(&self) -> RuntimeStores {
        self.stores.clone()
    }

    /// Installs a trusted process-local execution checkpoint observer.
    ///
    /// Normal product hosts do not need this extension. Fleet qualification
    /// uses it to stop a deterministic fixture at exact crash-window
    /// boundaries while retaining the standard production host construction.
    #[must_use]
    pub fn with_execution_checkpoint_observer(
        mut self,
        observer: Arc<dyn ExecutionCheckpointObserver>,
    ) -> Self {
        self.execution_checkpoint_observer = Some(observer);
        self
    }

    /// Builds, recovers, registers, serves, drains, and marks one replica
    /// offline around a caller-supplied shutdown future.
    pub async fn serve<C, F>(
        self,
        connector: C,
        shutdown: F,
    ) -> Result<(), ConnectorHostBootstrapError>
    where
        C: FrozenConnector + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.serve_with_router(connector, Router::new(), shutdown)
            .await
    }

    /// Serves the common host surface plus product-owned authenticated ingress.
    pub async fn serve_with_router<C, F>(
        self,
        connector: C,
        additional_routes: Router,
        shutdown: F,
    ) -> Result<(), ConnectorHostBootstrapError>
    where
        C: FrozenConnector + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.serve_with_router_factory(connector, |_| Ok(additional_routes), shutdown)
            .await
    }

    /// Builds product routes after the common host creates its signed event
    /// publisher and before the replica begins serving.
    pub async fn serve_with_router_factory<C, F, R>(
        self,
        connector: C,
        route_factory: R,
        shutdown: F,
    ) -> Result<(), ConnectorHostBootstrapError>
    where
        C: FrozenConnector + 'static,
        F: Future<Output = ()> + Send + 'static,
        R: FnOnce(
            Option<ConnectorHostEventPublisher>,
        ) -> Result<Router, ConnectorHostBootstrapError>,
    {
        let Self {
            bind,
            config,
            stores,
            control_plane,
            credential_revisions,
            callbacks,
            events,
            execution_checkpoint_observer,
        } = self;
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|error| ConnectorHostBootstrapError::Listener(error.to_string()))?;
        let runtime = Runtime::with_stores(stores);
        let runtime = match execution_checkpoint_observer {
            Some(observer) => runtime.with_execution_checkpoint_observer(observer),
            None => runtime,
        };
        let host = ConnectorHost::build_with_runtime_extensions(
            config,
            connector,
            control_plane,
            runtime,
            credential_revisions,
            callbacks,
        )
        .await?;
        let publisher = match events {
            Some(config) => Some(host.event_publisher(config).await?),
            None => None,
        };
        let additional_routes = route_factory(publisher)?;
        host.serve_with_router_until(listener, additional_routes, shutdown)
            .await?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct FileCredentialRevisionProvider {
    path: PathBuf,
}

impl FileCredentialRevisionProvider {
    async fn load(&self) -> Result<CredentialRevisionPolicy, CredentialRevisionProviderError> {
        let path = self.path.clone();
        let policy = tokio::task::spawn_blocking(move || {
            read_json_config::<CredentialRevisionPolicy>(
                &path,
                MAX_CREDENTIAL_REVISION_POLICY_BYTES,
            )
        })
        .await
        .map_err(|error| {
            CredentialRevisionProviderError::Unavailable(format!(
                "credential revision policy reader stopped unexpectedly: {error}"
            ))
        })?
        .map_err(|error| CredentialRevisionProviderError::Unavailable(error.to_string()))?;
        policy
            .validate()
            .map_err(|error| CredentialRevisionProviderError::Unavailable(error.to_string()))?;
        Ok(policy)
    }
}

#[async_trait]
impl CredentialRevisionProvider for FileCredentialRevisionProvider {
    async fn authorize(
        &self,
        check: &CredentialRevisionCheck,
    ) -> Result<(), CredentialRevisionProviderError> {
        let policy = self.load().await?;
        if policy.authorizes_revision(check.pinned_revision_ref.as_deref()) {
            Ok(())
        } else {
            Err(CredentialRevisionProviderError::Denied)
        }
    }
}

async fn credential_revision_provider(
    args: &ConnectorHostBootstrapArgs,
) -> Result<Arc<dyn CredentialRevisionProvider>, ConnectorHostBootstrapError> {
    if let Some(path) = args.credential_revision_policy_file.as_ref() {
        let provider = FileCredentialRevisionProvider { path: path.clone() };
        let initial_policy = provider.load().await.map_err(|error| {
            ConnectorHostBootstrapError::Configuration(format!(
                "credential revision policy is not usable at startup: {error}"
            ))
        })?;
        if !initial_policy.authorizes_revision(args.credential_revision_ref.as_deref()) {
            return Err(ConnectorHostBootstrapError::Configuration(
                "credential revision policy does not authorize the configured revision".to_owned(),
            ));
        }
        return Ok(Arc::new(provider));
    }

    let provider = StaticCredentialRevisionProvider::new(CredentialRevisionPolicy {
        current_revision_ref: args.credential_revision_ref.clone(),
        ..CredentialRevisionPolicy::default()
    })?;
    Ok(Arc::new(provider))
}

/// Waits for SIGTERM or Ctrl-C without installing product-specific handlers.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Reads a bounded owner-controlled UTF-8 secret and zeroizes it on drop.
pub fn read_secret_utf8(
    path: &Path,
    max_bytes: usize,
) -> Result<Zeroizing<String>, ConnectorHostBootstrapError> {
    let bytes = Zeroizing::new(read_bounded_secret(path, max_bytes)?);
    let value = std::str::from_utf8(trim_ascii(&bytes))
        .map_err(|_| {
            ConnectorHostBootstrapError::Configuration(format!(
                "secret file `{}` must contain UTF-8",
                path.display()
            ))
        })?
        .to_owned();
    if value.is_empty() {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "secret file `{}` is empty after trimming",
            path.display()
        )));
    }
    Ok(Zeroizing::new(value))
}

/// Reads and decodes a bounded, non-secret JSON configuration file.
pub fn read_json_config<T>(path: &Path, max_bytes: usize) -> Result<T, ConnectorHostBootstrapError>
where
    T: DeserializeOwned,
{
    let bytes = read_regular_file(path, max_bytes, "configuration", false)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ConnectorHostBootstrapError::Configuration(format!(
            "configuration file `{}` is invalid JSON: {error}",
            path.display()
        ))
    })
}

fn read_public_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, ConnectorHostBootstrapError> {
    read_regular_file(path, max_bytes, label, false)
}

fn resolve_did(
    label: &str,
    inline: Option<&str>,
    file: Option<&Path>,
) -> Result<String, ConnectorHostBootstrapError> {
    let did = match (inline, file) {
        (Some(_), Some(_)) => {
            return Err(ConnectorHostBootstrapError::Configuration(format!(
                "{label} DID must be configured inline or by file, not both"
            )));
        }
        (Some(value), None) => value.trim().to_owned(),
        (None, Some(path)) => read_secret_utf8(path, 512)?.to_string(),
        (None, None) => {
            return Err(ConnectorHostBootstrapError::Configuration(format!(
                "{label} DID is required"
            )));
        }
    };
    if did.is_empty() || did.len() > 512 {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} DID must contain 1 to 512 bytes"
        )));
    }
    Ok(did)
}

fn credential_handle(
    args: &ConnectorHostBootstrapArgs,
) -> Result<Option<CredentialHandle>, ConnectorHostBootstrapError> {
    match (
        args.credential_id.as_ref(),
        args.credential_issuer.as_ref(),
        args.credential_revision_ref.as_ref(),
    ) {
        (None, None, None) if args.credential_scopes.is_empty() => Ok(None),
        (Some(id), Some(issuer), Some(_)) => {
            let scopes = args
                .credential_scopes
                .iter()
                .map(|scope| scope.trim().to_owned())
                .collect::<BTreeSet<_>>();
            if scopes.is_empty() || scopes.contains("") {
                return Err(ConnectorHostBootstrapError::Configuration(
                    "credential handles require at least one non-empty verified scope".to_owned(),
                ));
            }
            CredentialHandle::new(id, issuer, scopes, Some(args.tenant_id.clone()), None)
                .map(Some)
                .map_err(|error| ConnectorHostBootstrapError::Configuration(error.to_string()))
        }
        _ => Err(ConnectorHostBootstrapError::Configuration(
            "credential id, issuer, revision, and scopes must be configured together".to_owned(),
        )),
    }
}

fn callback_config(
    args: &ConnectorHostBootstrapArgs,
    signer: CallbackSigner,
    tls_ca_certificate_pem: Option<&[u8]>,
) -> Result<Option<ConnectorHostCallbackConfig>, ConnectorHostBootstrapError> {
    let Some(target) = args.callback_endpoint.clone() else {
        if args.callback_allow_http || args.callback_allow_private_networks {
            return Err(ConnectorHostBootstrapError::Configuration(
                "callback network exceptions require a callback endpoint".to_owned(),
            ));
        }
        return Ok(None);
    };
    let host = target
        .host_str()
        .ok_or_else(|| {
            ConnectorHostBootstrapError::Configuration(
                "callback endpoint must contain a host".to_owned(),
            )
        })?
        .to_owned();
    Ok(Some(ConnectorHostCallbackConfig {
        target,
        policy: GatewayCallbackPolicy {
            allowed_hosts: HashSet::from([host]),
            allow_http: args.callback_allow_http,
            allow_private_networks: args.callback_allow_private_networks,
            tls_ca_certificate_pem: tls_ca_certificate_pem.map(ToOwned::to_owned),
            signer: Some(signer),
            ..GatewayCallbackPolicy::default()
        },
    }))
}

fn event_config(
    args: &ConnectorHostBootstrapArgs,
    signer: CallbackSigner,
    tls_ca_certificate_pem: Option<&[u8]>,
) -> Result<Option<ConnectorHostEventConfig>, ConnectorHostBootstrapError> {
    let Some(target) = args.event_endpoint.clone() else {
        if args.event_allow_http || args.event_allow_private_networks {
            return Err(ConnectorHostBootstrapError::Configuration(
                "event-ingress network exceptions require an event endpoint".to_owned(),
            ));
        }
        return Ok(None);
    };
    let host = target
        .host_str()
        .ok_or_else(|| {
            ConnectorHostBootstrapError::Configuration(
                "event endpoint must contain a host".to_owned(),
            )
        })?
        .to_owned();
    Ok(Some(ConnectorHostEventConfig {
        target,
        policy: GatewayCallbackPolicy {
            allowed_hosts: HashSet::from([host]),
            allow_http: args.event_allow_http,
            allow_private_networks: args.event_allow_private_networks,
            tls_ca_certificate_pem: tls_ca_certificate_pem.map(ToOwned::to_owned),
            signer: Some(signer),
            ..GatewayCallbackPolicy::default()
        },
    }))
}

fn validate_text(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ConnectorHostBootstrapError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} must contain 1 to {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn read_bounded_secret(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, ConnectorHostBootstrapError> {
    read_regular_file(path, max_bytes, "secret", true)
}

fn read_regular_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
    secret: bool,
) -> Result<Vec<u8>, ConnectorHostBootstrapError> {
    if max_bytes == 0 {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} file size bound must be greater than zero"
        )));
    }
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        ConnectorHostBootstrapError::Configuration(format!(
            "cannot inspect {label} file `{}`: {error}",
            path.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} path `{}` must be a regular non-symlink file",
            path.display()
        )));
    }
    let file = fs::File::open(path).map_err(|error| {
        ConnectorHostBootstrapError::Configuration(format!(
            "cannot open {label} file `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        ConnectorHostBootstrapError::Configuration(format!(
            "cannot inspect opened {label} file `{}`: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} path `{}` changed before it was opened",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
            return Err(ConnectorHostBootstrapError::Configuration(format!(
                "{label} path `{}` changed while it was being opened",
                path.display()
            )));
        }
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} file `{}` must contain 1 to {max_bytes} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        let forbidden = if secret { 0o077 } else { 0o022 };
        if mode & forbidden != 0 {
            return Err(ConnectorHostBootstrapError::Configuration(format!(
                "{label} file `{}` has unsafe group or world permissions",
                path.display(),
            )));
        }
    }
    let read_bound = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(read_bound)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ConnectorHostBootstrapError::Configuration(format!(
                "cannot read {label} file `{}`: {error}",
                path.display()
            ))
        })?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(ConnectorHostBootstrapError::Configuration(format!(
            "{label} file `{}` changed size during validation",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{FileCredentialRevisionProvider, read_json_config, read_secret_utf8};
    use aip_connector_host::{
        CredentialRevisionCheck, CredentialRevisionProvider, CredentialRevisionProviderError,
    };
    use aip_connector_registry::ConnectorInstanceId;
    use aip_core::CapabilityId;
    use serde::Deserialize;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct FixtureConfig {
        enabled: bool,
    }

    struct FixtureDirectory(PathBuf);

    impl FixtureDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aip-host-bootstrap-{}-{}",
                std::process::id(),
                aip_core::ActionId::new()
            ));
            fs::create_dir(&path).expect("fixture directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("fixture directory mode");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn secret_reader_requires_owner_only_regular_files() {
        let fixture = FixtureDirectory::new();
        let secret = fixture.path("secret");
        fs::write(&secret, b"protected-value\n").expect("secret file");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o640))
            .expect("group-readable mode");
        assert!(read_secret_utf8(&secret, 1024).is_err());

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("owner-only mode");
        assert_eq!(
            read_secret_utf8(&secret, 1024)
                .expect("owner-only secret")
                .as_str(),
            "protected-value"
        );

        let link = fixture.path("secret-link");
        symlink(&secret, &link).expect("secret symlink");
        assert!(read_secret_utf8(&link, 1024).is_err());
    }

    #[test]
    fn configuration_reader_is_bounded_and_rejects_writable_shared_files() {
        let fixture = FixtureDirectory::new();
        let config = fixture.path("config.json");
        fs::write(&config, br#"{"enabled":true}"#).expect("configuration file");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))
            .expect("read-only shared mode");
        assert_eq!(
            read_json_config::<FixtureConfig>(&config, 1024).expect("configuration"),
            FixtureConfig { enabled: true }
        );

        fs::set_permissions(&config, fs::Permissions::from_mode(0o664))
            .expect("group-writable mode");
        assert!(read_json_config::<FixtureConfig>(&config, 1024).is_err());
    }

    #[tokio::test]
    async fn file_credential_policy_reloads_and_fails_closed() {
        let fixture = FixtureDirectory::new();
        let policy = fixture.path("credential-policy.json");
        fs::write(
            &policy,
            br#"{"current_revision_ref":"revision-v1","accepted_previous_revisions":[],"revoked_revisions":[]}"#,
        )
        .expect("initial credential policy");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644))
            .expect("credential policy mode");
        let provider = FileCredentialRevisionProvider {
            path: policy.clone(),
        };
        let check = CredentialRevisionCheck {
            tenant_id: "tenant-acme".to_owned(),
            instance_id: ConnectorInstanceId::trusted("cinst_acme"),
            capability_id: CapabilityId::trusted("acme.execute"),
            pinned_revision_ref: Some("revision-v1".to_owned()),
        };
        provider
            .authorize(&check)
            .await
            .expect("initial revision authorized");

        fs::write(
            &policy,
            br#"{"current_revision_ref":"revision-v2","accepted_previous_revisions":[],"revoked_revisions":["revision-v1"]}"#,
        )
        .expect("revoked credential policy");
        assert_eq!(
            provider.authorize(&check).await,
            Err(CredentialRevisionProviderError::Denied)
        );

        fs::write(&policy, br#"{"current_revision_ref":"revision-v2""#)
            .expect("malformed credential policy");
        assert!(matches!(
            provider.authorize(&check).await,
            Err(CredentialRevisionProviderError::Unavailable(_))
        ));
    }
}
