//! Product-neutral command-line composition for the `getaip-server` binary.

use crate::{
    AipDaemon, AipDaemonConfig, AipDaemonDeployment, AipDaemonNatsConfig, DEFAULT_NATS_SERVICE,
    DEFAULT_NATS_VERSION, DaemonFleetServices, DaemonTrustResolvers, McpProtectedResourceConfig,
    NativeHttpAuthConfig, StartupError,
};
use aip_auth::{
    ApprovalAuthorityResolver, AuthorityMembership, CredentialHandle,
    DenyAllApprovalAuthorityResolver, DenyAllTrustedIdentityResolver, HttpTokenIntrospector,
    IntrospectionTokenVerifier, StaticApprovalAuthorityResolver, StaticTrustedIdentityResolver,
    TrustedIdentityBinding, TrustedIdentityResolver, VerifiedTenant,
};
use aip_connector_registry::RouteTopologyPreference;
use aip_connector_registry_postgres::{PostgresConnectorRegistry, RegistryPoolLimits};
use aip_connector_remote::{
    ConnectorEventIngressLimits, FairAdmissionScheduler, NativeAipHttpDispatcher,
    RegistryBoundEndpointPolicy, RemoteAdmissionLimits, RemoteConnectorHandler,
};
use aip_core::{CapabilityId, IdentityContext, Principal, PrincipalId, PrincipalKind};
use aip_discovery::CapabilityImplementationSupport;
use aip_gateway::{
    A2aCallbackCredentialKey, CallbackSigner, DelegationPeerSecurity, DelegationRoute,
    DelegationRouteBinding, GatewayCallbackPolicy, NativeAipHttpClient,
};
use aip_mcp_session::McpFrame;
use aip_runtime::RuntimeWorkBudgets;
use aip_transport_mcp_stdio::{McpStdioFrame, decode_frame, encode_frame};
use aip_transport_nats::NatsAuthentication;
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use url::Url;

/// Product-neutral AIP daemon command-line options.
#[derive(Debug, Parser)]
#[command(name = "getaip-server", version, about = "AIP core gateway daemon")]
pub struct CoreArgs {
    /// HTTP bind address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// External HTTPS origin advertised to A2A and capability-discovery clients.
    #[arg(long, value_name = "URL")]
    public_base_url: Option<String>,
    /// Stable principal id reported in the local AIP manifest.
    #[arg(long, default_value = "agent:getaip:server:local")]
    service_id: String,
    /// Optional trust domain reported in the local AIP manifest.
    #[arg(long)]
    trust_domain: Option<String>,
    /// Require Ed25519 signatures on incoming AIP envelopes.
    #[arg(long)]
    require_signed_envelopes: bool,
    /// Trusted native signer binding, formatted as DID=PRINCIPAL_ID.
    #[arg(long = "trusted-signer", value_name = "DID=PRINCIPAL_ID")]
    trusted_signers: Vec<String>,
    /// JSON directory of trusted native signer DID and principal bindings.
    #[arg(long = "trusted-signer-file", value_name = "PATH")]
    trusted_signer_file: Option<PathBuf>,
    /// Bearer token for ergonomic native HTTP lifecycle routes.
    #[arg(long = "native-bearer-token", value_name = "TOKEN")]
    native_bearer_token: Option<String>,
    /// Owner-only file containing the native HTTP bearer token.
    #[arg(long = "native-bearer-token-file", value_name = "FILE")]
    native_bearer_token_file: Option<PathBuf>,
    /// Principal established after native HTTP bearer authentication.
    #[arg(
        long = "native-principal",
        default_value = "service:getaip:server:http-edge"
    )]
    native_principal: String,
    /// Tenant bound to the native bearer identity for fleet discovery.
    #[arg(long = "native-tenant-id", value_name = "TENANT_ID")]
    native_tenant_id: Option<String>,
    /// Scope granted to the authenticated native HTTP principal.
    #[arg(long = "native-principal-scope", value_name = "SCOPE")]
    native_principal_scopes: Vec<String>,
    /// JSON authority directory used to verify approval decisions.
    #[arg(long = "approval-authority-file", value_name = "PATH")]
    approval_authority_file: Option<PathBuf>,
    /// JSON identity directory used to resolve authenticated principals.
    #[arg(long = "trusted-identity-file", value_name = "PATH")]
    trusted_identity_file: Option<PathBuf>,
    /// Permit unauthenticated native traffic for loopback-only development.
    #[arg(long)]
    allow_insecure_development: bool,
    /// Exact host allowed for outbound callback delivery.
    #[arg(long = "callback-allowed-host", value_name = "HOST")]
    callback_allowed_hosts: Vec<String>,
    /// Hex-encoded 32-byte Ed25519 seed used to sign native responses and callbacks.
    #[arg(
        long = "callback-signing-seed-hex",
        value_name = "HEX",
        conflicts_with = "callback_signing_seed_file"
    )]
    callback_signing_seed_hex: Option<String>,
    /// Owner-only file containing the response/callback Ed25519 signing seed.
    #[arg(
        long = "callback-signing-seed-file",
        value_name = "FILE",
        conflicts_with = "callback_signing_seed_hex"
    )]
    callback_signing_seed_file: Option<PathBuf>,
    /// Hex-encoded 32-byte AES key used to encrypt A2A push credentials at rest.
    #[arg(long = "a2a-push-encryption-key-hex", value_name = "HEX")]
    a2a_push_encryption_key_hex: Option<String>,
    /// Permit plaintext HTTP callback targets.
    #[arg(long)]
    callback_allow_http: bool,
    /// Permit private or loopback callback target addresses.
    #[arg(long)]
    callback_allow_private_networks: bool,
    /// Maximum callback deliveries executing concurrently.
    #[arg(long = "callback-max-in-flight", value_name = "COUNT")]
    callback_max_in_flight: Option<usize>,
    /// Maximum callback records leased by one recovery cycle.
    #[arg(long = "callback-recovery-batch", value_name = "COUNT")]
    callback_recovery_batch: Option<usize>,
    /// Maximum transaction reconciliations executing concurrently.
    #[arg(long = "reconciliation-max-in-flight", value_name = "COUNT")]
    reconciliation_max_in_flight: Option<usize>,
    /// Directory used for durable runtime state.
    #[arg(long, value_name = "DIR")]
    storage_dir: Option<PathBuf>,
    /// PostgreSQL URL used for clustered durable runtime state.
    #[arg(long, value_name = "URL", conflicts_with = "postgres_url_file")]
    postgres_url: Option<String>,
    /// Owner-only file containing the clustered runtime PostgreSQL URL.
    #[arg(long, value_name = "FILE", conflicts_with = "postgres_url")]
    postgres_url_file: Option<PathBuf>,
    /// PostgreSQL data-plane URL for the normalized connector-fleet registry.
    #[arg(
        long = "connector-registry-url",
        value_name = "URL",
        conflicts_with = "connector_registry_url_file"
    )]
    connector_registry_url: Option<String>,
    /// Owner-only file containing the connector-registry data-plane URL.
    #[arg(
        long = "connector-registry-url-file",
        value_name = "FILE",
        conflicts_with = "connector_registry_url"
    )]
    connector_registry_url_file: Option<PathBuf>,
    /// Maximum connector-registry data-plane connections.
    #[arg(long = "connector-registry-data-max-connections", value_name = "COUNT")]
    connector_registry_data_max_connections: Option<u32>,
    /// Maximum wait for a connector-registry connection.
    #[arg(
        long = "connector-registry-acquire-timeout-ms",
        value_name = "MILLISECONDS"
    )]
    connector_registry_acquire_timeout_ms: Option<u64>,
    /// Owner-only file containing a 32-byte Ed25519 seed as hexadecimal text.
    #[arg(long = "connector-fleet-signing-seed-file", value_name = "FILE")]
    connector_fleet_signing_seed_file: Option<PathBuf>,
    /// Public central endpoint used by connector hosts for streamed AIP chunks.
    #[arg(long = "connector-fleet-callback-url", value_name = "URL")]
    connector_fleet_callback_url: Option<String>,
    /// Exact connector-host DNS name or IP literal; repeat for multiple hosts.
    #[arg(long = "connector-fleet-allowed-host", value_name = "HOST")]
    connector_fleet_allowed_hosts: Vec<String>,
    /// Trust each endpoint admitted by the connector control plane as its host allowlist.
    #[arg(long = "connector-fleet-trust-registry-endpoints")]
    connector_fleet_trust_registry_endpoints: bool,
    /// Permit plaintext HTTP connector-host endpoints.
    #[arg(long = "connector-fleet-allow-http")]
    connector_fleet_allow_http: bool,
    /// Permit private or loopback connector-host addresses.
    #[arg(long = "connector-fleet-allow-private-networks")]
    connector_fleet_allow_private_networks: bool,
    /// Connector-host request timeout in milliseconds.
    #[arg(long = "connector-fleet-timeout-ms", value_name = "MILLISECONDS")]
    connector_fleet_timeout_ms: Option<u64>,
    /// Maximum accepted connector-host response size in bytes.
    #[arg(long = "connector-fleet-max-response-bytes", value_name = "BYTES")]
    connector_fleet_max_response_bytes: Option<usize>,
    /// Number of transport retries after the first connector-host request.
    #[arg(long = "connector-fleet-retry-budget", value_name = "COUNT")]
    connector_fleet_retry_budget: Option<u32>,
    /// Maximum number of cached connector-host HTTP connection pools.
    #[arg(long = "connector-fleet-max-cached-clients", value_name = "COUNT")]
    connector_fleet_max_cached_clients: Option<usize>,
    /// PEM root certificate used to verify connector-host private-PKI TLS.
    #[arg(long = "connector-fleet-tls-ca-file", value_name = "FILE")]
    connector_fleet_tls_ca_file: Option<PathBuf>,
    /// Region preferred for new connector route assignments.
    #[arg(long = "connector-fleet-region", value_name = "REGION")]
    connector_fleet_region: Option<String>,
    /// Zone preferred for new connector route assignments.
    #[arg(long = "connector-fleet-zone", value_name = "ZONE")]
    connector_fleet_zone: Option<String>,
    /// Capacity class required for new connector route assignments.
    #[arg(long = "connector-fleet-capacity-class", value_name = "CLASS")]
    connector_fleet_capacity_class: Option<String>,
    /// Forbid fallback to another region when preferred regional capacity is unavailable.
    #[arg(long = "connector-fleet-disable-cross-region-failover")]
    connector_fleet_disable_cross_region_failover: bool,
    /// Maximum connector actions executing through this daemon.
    #[arg(long = "connector-fleet-max-in-flight", value_name = "COUNT")]
    connector_fleet_max_in_flight: Option<usize>,
    /// Maximum connector actions executing for one verified tenant.
    #[arg(
        long = "connector-fleet-max-in-flight-per-tenant",
        value_name = "COUNT"
    )]
    connector_fleet_max_in_flight_per_tenant: Option<usize>,
    /// Maximum connector actions waiting for local dispatch.
    #[arg(long = "connector-fleet-max-queued", value_name = "COUNT")]
    connector_fleet_max_queued: Option<usize>,
    /// Maximum waiting connector actions for one verified tenant.
    #[arg(long = "connector-fleet-max-queued-per-tenant", value_name = "COUNT")]
    connector_fleet_max_queued_per_tenant: Option<usize>,
    /// Maximum canonical bytes represented by waiting connector actions.
    #[arg(long = "connector-fleet-max-queue-bytes", value_name = "BYTES")]
    connector_fleet_max_queue_bytes: Option<usize>,
    /// Maximum canonical size of one connector action.
    #[arg(long = "connector-fleet-max-request-bytes", value_name = "BYTES")]
    connector_fleet_max_request_bytes: Option<usize>,
    /// Maximum local connector-action queue age in milliseconds.
    #[arg(long = "connector-fleet-max-queue-age-ms", value_name = "MILLISECONDS")]
    connector_fleet_max_queue_age_ms: Option<u64>,
    /// Verified tenant scheduling weight, formatted as TENANT_ID=WEIGHT.
    #[arg(
        long = "connector-fleet-tenant-weight",
        value_name = "TENANT_ID=WEIGHT"
    )]
    connector_fleet_tenant_weights: Vec<String>,
    /// Maximum serialized connector-event envelope size in bytes.
    #[arg(long = "connector-event-max-envelope-bytes", value_name = "BYTES")]
    connector_event_max_envelope_bytes: Option<usize>,
    /// Maximum events accepted in one connector-event envelope.
    #[arg(long = "connector-event-max-events-per-envelope", value_name = "COUNT")]
    connector_event_max_events_per_envelope: Option<usize>,
    /// Maximum serialized size of one connector-originated event in bytes.
    #[arg(long = "connector-event-max-event-bytes", value_name = "BYTES")]
    connector_event_max_event_bytes: Option<usize>,
    /// Maximum serialized size of one connector stream chunk in bytes.
    #[arg(long = "connector-stream-max-chunk-bytes", value_name = "BYTES")]
    connector_stream_max_chunk_bytes: Option<usize>,
    /// Maximum concurrent connector-event storage operations.
    #[arg(long = "connector-event-max-in-flight", value_name = "COUNT")]
    connector_event_max_in_flight: Option<usize>,
    /// Maximum accepted age of a signed connector-event envelope in seconds.
    /// Historical `event.occurred_at` values are preserved independently.
    #[arg(long = "connector-event-max-age-seconds", value_name = "SECONDS")]
    connector_event_max_age_seconds: Option<u64>,
    /// Maximum accepted future clock skew for connector events in seconds.
    #[arg(
        long = "connector-event-max-future-skew-seconds",
        value_name = "SECONDS"
    )]
    connector_event_max_future_skew_seconds: Option<u64>,
    /// Maximum accepted age of a signed connector stream callback in seconds.
    #[arg(
        long = "connector-stream-callback-max-age-seconds",
        value_name = "SECONDS"
    )]
    connector_stream_callback_max_age_seconds: Option<u64>,
    /// NATS server URL.
    #[arg(long, value_name = "URL")]
    nats_url: Option<String>,
    /// NATS username. Requires `--nats-password-file`.
    #[arg(long, value_name = "USERNAME")]
    nats_username: Option<String>,
    /// Owner-only file containing the NATS password.
    #[arg(long, value_name = "FILE")]
    nats_password_file: Option<PathBuf>,
    /// NATS trust-domain subject segment.
    #[arg(long, value_name = "DOMAIN")]
    nats_trust_domain: Option<String>,
    /// NATS service subject segment.
    #[arg(long, value_name = "SERVICE")]
    nats_service: Option<String>,
    /// NATS version subject segment.
    #[arg(long, value_name = "VERSION")]
    nats_version: Option<String>,
    /// Optional NATS queue group.
    #[arg(long, value_name = "GROUP")]
    nats_queue_group: Option<String>,
    /// NATS request timeout in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    nats_request_timeout_ms: u64,
    /// Authenticated HTTP delegation route.
    #[arg(
        long = "delegation-http-route",
        value_name = "DELEGATE_ID=URL,PEER_ID,PEER_DID[,TRUST_DOMAIN]"
    )]
    delegation_http_routes: Vec<String>,
    /// Authenticated NATS delegation route.
    #[arg(
        long = "delegation-nats-route",
        value_name = "CAPABILITY_ID=SERVER_URL,SUBJECT,PEER_ID,PEER_DID[,TIMEOUT_MS[,TRUST_DOMAIN]]"
    )]
    delegation_nats_routes: Vec<String>,
    /// Print the daemon manifest and exit.
    #[arg(long)]
    print_manifest: bool,
    /// Serve the MCP compatibility profile over newline-delimited stdio.
    #[arg(long)]
    mcp_stdio: bool,
    /// Static bearer token required by MCP HTTP endpoints.
    #[arg(long = "mcp-bearer-token", value_name = "TOKEN")]
    mcp_bearer_token: Option<String>,
    /// Protected-resource identifier advertised for MCP HTTP.
    #[arg(long = "mcp-resource", value_name = "RESOURCE")]
    mcp_resource: Option<String>,
    /// OAuth authorization server issuer advertised for MCP HTTP.
    #[arg(long = "mcp-authorization-server", value_name = "ISSUER")]
    mcp_authorization_servers: Vec<String>,
    /// OAuth scope advertised as supported.
    #[arg(long = "mcp-scope", value_name = "SCOPE")]
    mcp_scopes: Vec<String>,
    /// OAuth scope required to establish an MCP HTTP session.
    #[arg(long = "mcp-required-scope", value_name = "SCOPE")]
    mcp_required_scopes: Vec<String>,
    /// RFC 7662 token introspection endpoint.
    #[arg(long = "mcp-introspection-url", value_name = "HTTPS_URL")]
    mcp_introspection_url: Option<String>,
    /// Trusted issuer represented by the introspection endpoint.
    #[arg(long = "mcp-introspection-issuer", value_name = "ISSUER")]
    mcp_introspection_issuer: Option<String>,
    /// OAuth client id for token introspection.
    #[arg(long = "mcp-introspection-client-id", value_name = "CLIENT_ID")]
    mcp_introspection_client_id: Option<String>,
    /// Owner-only file containing the introspection client secret.
    #[arg(long = "mcp-introspection-client-secret-file", value_name = "FILE")]
    mcp_introspection_client_secret_file: Option<PathBuf>,
    /// Permit an introspection endpoint on loopback HTTP.
    #[arg(long = "mcp-introspection-allow-loopback-http")]
    mcp_introspection_allow_loopback_http: bool,
    /// Human-readable protected-resource documentation URL.
    #[arg(long = "mcp-resource-documentation", value_name = "URL")]
    mcp_resource_documentation: Option<String>,
    /// Browser origin allowed to call MCP HTTP.
    #[arg(long = "mcp-allowed-origin", value_name = "ORIGIN")]
    mcp_allowed_origins: Vec<String>,
    /// Principal established after MCP transport authentication.
    #[arg(
        long = "mcp-principal",
        default_value = "service:getaip:server:mcp-edge"
    )]
    mcp_principal: String,
    /// Scope granted to the authenticated MCP principal.
    #[arg(long = "mcp-principal-scope", value_name = "SCOPE")]
    mcp_principal_scopes: Vec<String>,
}

/// Parses process configuration and runs the product-neutral daemon.
pub async fn run() -> Result<(), StartupError> {
    run_with_args(CoreArgs::parse()).await
}

async fn run_with_args(args: CoreArgs) -> Result<(), StartupError> {
    let service_id = PrincipalId::parse(&args.service_id).map_err(config_error)?;
    let trust_domain = args.trust_domain.as_deref().unwrap_or("local");
    let callback_policy = callback_policy_from_args(&args, &service_id)?;
    let mcp_protected_resource = mcp_protected_resource_config_from_args(&args);
    let mcp_token_verifier = mcp_token_verifier_from_args(&args, &mcp_protected_resource)?;
    let storage_dir = args.storage_dir.clone().or_else(|| {
        env::var("GETAIP_SERVER_STORAGE_DIR")
            .ok()
            .map(PathBuf::from)
    });
    let config = AipDaemonConfig {
        bind: args.bind,
        public_base_url: args
            .public_base_url
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_PUBLIC_BASE_URL").ok()),
        service_id,
        trust_domain: args.trust_domain.clone(),
        require_signed_envelopes: !env_flag("GETAIP_SERVER_ALLOW_UNSIGNED_ENVELOPES")
            || args.require_signed_envelopes
            || env_flag("GETAIP_SERVER_REQUIRE_SIGNED_ENVELOPES"),
        trusted_signers: trusted_signers_from_args(&args)?,
        native_http_auth: native_http_auth_from_args(&args)?,
        allow_insecure_development: args.allow_insecure_development
            || env_flag("GETAIP_SERVER_INSECURE_DEVELOPMENT"),
        callback_policy: callback_policy.clone(),
        storage_dir,
        nats: nats_config_from_args(&args, trust_domain.to_owned())?,
        delegation_routes: parse_delegation_routes(
            route_specs(
                args.delegation_http_routes.clone(),
                "GETAIP_SERVER_DELEGATION_HTTP_ROUTES",
            ),
            route_specs(
                args.delegation_nats_routes.clone(),
                "GETAIP_SERVER_DELEGATION_NATS_ROUTES",
            ),
            &callback_policy,
            trust_domain,
        )
        .await?,
        mcp_protected_resource,
        mcp_principal: authenticated_mcp_principal(&args)?,
    };
    let mut deployment = AipDaemonDeployment::default()
        .with_trust_resolvers(trust_resolvers_from_args(&args)?)
        .with_runtime_work_budgets(runtime_work_budgets_from_args(&args)?);
    let postgres_url = resolve_secret_text(
        args.postgres_url
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_POSTGRES_URL").ok()),
        args.postgres_url_file.clone().or_else(|| {
            env::var("GETAIP_SERVER_POSTGRES_URL_FILE")
                .ok()
                .map(PathBuf::from)
        }),
        "runtime PostgreSQL URL",
        16 * 1024,
    )?;
    if let Some(postgres_url) = postgres_url {
        deployment = deployment.with_postgres_url(postgres_url);
    }
    if let Some(fleet) = fleet_services_from_args(&args, &config.service_id, trust_domain).await? {
        deployment = deployment.with_fleet_services(fleet);
    }
    let daemon = AipDaemon::new_with_deployment(config.clone(), deployment)
        .await
        .map_err(StartupError::gateway)?;
    let daemon = match mcp_token_verifier {
        Some(verifier) => daemon.with_mcp_token_verifier(verifier),
        None => daemon,
    };
    if args.print_manifest {
        println!(
            "{}",
            serde_json::to_string_pretty(daemon.manifest()).map_err(|error| StartupError {
                code: "aip.server.render_manifest",
                message: error.to_string(),
            })?
        );
        return Ok(());
    }
    if args.mcp_stdio {
        return serve_mcp_stdio(daemon).await;
    }
    println!(
        "getaip-server listening on http://{} with service id {}",
        config.bind, config.service_id
    );
    daemon.serve(config.bind).await.map_err(StartupError::io)
}

fn config_error(error: impl std::fmt::Display) -> StartupError {
    StartupError {
        code: "aip.server.config",
        message: error.to_string(),
    }
}

fn principal_from_id(raw: &str) -> Result<Principal, StartupError> {
    let id = PrincipalId::parse(raw).map_err(config_error)?;
    let kind = match id.as_str().split(':').next() {
        Some("human") => PrincipalKind::Human,
        Some("service") => PrincipalKind::Service,
        Some("system") => PrincipalKind::System,
        Some("tenant") => PrincipalKind::Tenant,
        Some("customer") => PrincipalKind::Customer,
        Some("contact") => PrincipalKind::Contact,
        _ => PrincipalKind::Agent,
    };
    Ok(Principal::new(id, kind))
}

fn parse_trusted_signers(specs: Vec<String>) -> Result<Vec<(String, Principal)>, StartupError> {
    specs
        .into_iter()
        .map(|spec| {
            let (did, principal_id) = spec.split_once('=').ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("trusted signer `{spec}` must be formatted as DID=PRINCIPAL_ID"),
            })?;
            if !did.starts_with("did:key:z") {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: format!("trusted signer `{spec}` must use an Ed25519 did:key"),
                });
            }
            aip_crypto::verifying_key_from_did_key(did).map_err(config_error)?;
            Ok((did.to_owned(), principal_from_id(principal_id)?))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedSignerDirectoryEntry {
    signer_did: String,
    principal_id: String,
}

fn trusted_signers_from_args(args: &CoreArgs) -> Result<Vec<(String, Principal)>, StartupError> {
    let mut bindings = parse_trusted_signers(route_specs(
        args.trusted_signers.clone(),
        "GETAIP_SERVER_TRUSTED_SIGNERS",
    ))?;
    let signer_file = args.trusted_signer_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_TRUSTED_SIGNER_FILE")
            .ok()
            .map(PathBuf::from)
    });
    if let Some(path) = signer_file {
        let entries = serde_json::from_str::<Vec<TrustedSignerDirectoryEntry>>(
            &read_secure_configuration_file(&path, "trusted signer")?,
        )
        .map_err(|error| StartupError {
            code: "aip.server.config",
            message: format!("invalid trusted signer JSON: {error}"),
        })?;
        if entries.is_empty() {
            return Err(StartupError {
                code: "aip.server.config",
                message: "trusted signer file must contain at least one binding".to_owned(),
            });
        }
        for entry in entries {
            if !entry.signer_did.starts_with("did:key:z") {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: "trusted signer file entries must use Ed25519 did:key values"
                        .to_owned(),
                });
            }
            aip_crypto::verifying_key_from_did_key(&entry.signer_did).map_err(config_error)?;
            bindings.push((entry.signer_did, principal_from_id(&entry.principal_id)?));
        }
    }
    let mut dids = HashSet::new();
    if bindings.iter().any(|(did, _)| !dids.insert(did.clone())) {
        return Err(StartupError {
            code: "aip.server.config",
            message: "trusted signer DIDs must be unique across inline and file bindings"
                .to_owned(),
        });
    }
    Ok(bindings)
}

fn authenticated_mcp_principal(args: &CoreArgs) -> Result<Principal, StartupError> {
    let id = env::var("GETAIP_SERVER_MCP_PRINCIPAL").unwrap_or_else(|_| args.mcp_principal.clone());
    let mut principal = principal_from_id(&id)?;
    principal.auth_context = Some(serde_json::json!({
        "scopes": merged_env_list(
            args.mcp_principal_scopes.clone(),
            "GETAIP_SERVER_MCP_PRINCIPAL_SCOPES",
        )
    }));
    Ok(principal)
}

fn native_http_auth_from_args(
    args: &CoreArgs,
) -> Result<Option<NativeHttpAuthConfig>, StartupError> {
    let inline = args
        .native_bearer_token
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN").ok());
    let file = args.native_bearer_token_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE")
            .ok()
            .map(PathBuf::from)
    });
    // Use the common secret-text loader so a conventional trailing newline in
    // an owner-only Docker/Kubernetes secret is not treated as part of the
    // bearer token. Clients apply the same normalization before constructing
    // the Authorization header.
    let token = resolve_secret_text(inline, file, "native bearer token", 16 * 1024)?;
    let Some(token) = token else {
        return Ok(None);
    };
    let id = env::var("GETAIP_SERVER_NATIVE_PRINCIPAL")
        .unwrap_or_else(|_| args.native_principal.clone());
    let mut principal = principal_from_id(&id)?;
    principal.auth_context = Some(serde_json::json!({
        "scopes": merged_env_list(
            args.native_principal_scopes.clone(),
            "GETAIP_SERVER_NATIVE_PRINCIPAL_SCOPES",
        )
    }));
    let tenant_id = args
        .native_tenant_id
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_TENANT_ID").ok())
        .filter(|value| !value.trim().is_empty());
    let auth = NativeHttpAuthConfig::bearer(token, principal);
    Ok(Some(match tenant_id {
        Some(tenant_id) => auth.with_tenant(tenant_id),
        None => auth,
    }))
}

fn callback_policy_from_args(
    args: &CoreArgs,
    service_id: &PrincipalId,
) -> Result<GatewayCallbackPolicy, StartupError> {
    let allowed_hosts = merged_env_list(
        args.callback_allowed_hosts.clone(),
        "GETAIP_SERVER_CALLBACK_ALLOWED_HOSTS",
    )
    .into_iter()
    .map(|host| host.trim().to_ascii_lowercase())
    .filter(|host| !host.is_empty())
    .collect::<HashSet<_>>();
    let signer = resolve_secret_text(
        args.callback_signing_seed_hex
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_CALLBACK_SIGNING_SEED_HEX").ok()),
        args.callback_signing_seed_file.clone().or_else(|| {
            env::var("GETAIP_SERVER_CALLBACK_SIGNING_SEED_FILE")
                .ok()
                .map(PathBuf::from)
        }),
        "native response/callback signing seed",
        256,
    )?
    .map(|raw| {
        let seed = decode_32_byte_hex(&raw, "callback signing seed")?;
        Ok(CallbackSigner {
            principal: principal_from_id(service_id.as_str())?,
            signing_key: Arc::new(aip_crypto::signing_key_from_seed(seed)),
        })
    })
    .transpose()?;
    if !allowed_hosts.is_empty() && signer.is_none() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "callback allowlist requires a native response/callback signing seed"
                .to_owned(),
        });
    }
    let a2a_credential_key = args
        .a2a_push_encryption_key_hex
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_A2A_PUSH_ENCRYPTION_KEY_HEX").ok())
        .map(|raw| {
            decode_32_byte_hex(&raw, "A2A push encryption key").map(A2aCallbackCredentialKey::new)
        })
        .transpose()?;
    if a2a_credential_key.is_some() && signer.is_none() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "A2A push delivery requires a native response/callback signing seed"
                .to_owned(),
        });
    }
    Ok(GatewayCallbackPolicy {
        allowed_hosts,
        allow_http: args.callback_allow_http || env_flag("GETAIP_SERVER_CALLBACK_ALLOW_HTTP"),
        allow_private_networks: args.callback_allow_private_networks
            || env_flag("GETAIP_SERVER_CALLBACK_ALLOW_PRIVATE_NETWORKS"),
        request_timeout_ms: env_u64("GETAIP_SERVER_CALLBACK_TIMEOUT_MS")?.unwrap_or(5_000),
        max_response_bytes: env_usize("GETAIP_SERVER_CALLBACK_MAX_RESPONSE_BYTES")?
            .unwrap_or(4 * 1024 * 1024),
        tls_ca_certificate_pem: None,
        signer,
        a2a_credential_key,
    })
}

fn runtime_work_budgets_from_args(args: &CoreArgs) -> Result<RuntimeWorkBudgets, StartupError> {
    let defaults = RuntimeWorkBudgets::default();
    let budgets = RuntimeWorkBudgets {
        callback_max_in_flight: args
            .callback_max_in_flight
            .or(env_usize("GETAIP_SERVER_CALLBACK_MAX_IN_FLIGHT")?)
            .unwrap_or(defaults.callback_max_in_flight),
        callback_recovery_batch: args
            .callback_recovery_batch
            .or(env_usize("GETAIP_SERVER_CALLBACK_RECOVERY_BATCH")?)
            .unwrap_or(defaults.callback_recovery_batch),
        reconciliation_max_in_flight: args
            .reconciliation_max_in_flight
            .or(env_usize("GETAIP_SERVER_RECONCILIATION_MAX_IN_FLIGHT")?)
            .unwrap_or(defaults.reconciliation_max_in_flight),
    };
    if budgets.callback_max_in_flight == 0
        || budgets.callback_recovery_batch == 0
        || budgets.reconciliation_max_in_flight == 0
    {
        return Err(StartupError {
            code: "aip.server.config",
            message: "callback and reconciliation budgets must be greater than zero".to_owned(),
        });
    }
    Ok(budgets)
}

fn connector_event_limits_from_args(
    args: &CoreArgs,
) -> Result<(ConnectorEventIngressLimits, bool), StartupError> {
    const ENV_NAMES: [&str; 8] = [
        "GETAIP_SERVER_CONNECTOR_EVENT_MAX_ENVELOPE_BYTES",
        "GETAIP_SERVER_CONNECTOR_EVENT_MAX_EVENTS_PER_ENVELOPE",
        "GETAIP_SERVER_CONNECTOR_EVENT_MAX_EVENT_BYTES",
        "GETAIP_SERVER_CONNECTOR_EVENT_MAX_IN_FLIGHT",
        "GETAIP_SERVER_CONNECTOR_EVENT_MAX_AGE_SECONDS",
        "GETAIP_SERVER_CONNECTOR_EVENT_MAX_FUTURE_SKEW_SECONDS",
        "GETAIP_SERVER_CONNECTOR_STREAM_MAX_CHUNK_BYTES",
        "GETAIP_SERVER_CONNECTOR_STREAM_CALLBACK_MAX_AGE_SECONDS",
    ];
    let explicitly_configured = args.connector_event_max_envelope_bytes.is_some()
        || args.connector_event_max_events_per_envelope.is_some()
        || args.connector_event_max_event_bytes.is_some()
        || args.connector_stream_max_chunk_bytes.is_some()
        || args.connector_event_max_in_flight.is_some()
        || args.connector_event_max_age_seconds.is_some()
        || args.connector_event_max_future_skew_seconds.is_some()
        || args.connector_stream_callback_max_age_seconds.is_some()
        || ENV_NAMES.iter().any(|name| env::var_os(name).is_some());
    let defaults = ConnectorEventIngressLimits::default();
    let limits = ConnectorEventIngressLimits {
        max_envelope_bytes: args
            .connector_event_max_envelope_bytes
            .or(env_usize(ENV_NAMES[0])?)
            .unwrap_or(defaults.max_envelope_bytes),
        max_events_per_envelope: args
            .connector_event_max_events_per_envelope
            .or(env_usize(ENV_NAMES[1])?)
            .unwrap_or(defaults.max_events_per_envelope),
        max_event_bytes: args
            .connector_event_max_event_bytes
            .or(env_usize(ENV_NAMES[2])?)
            .unwrap_or(defaults.max_event_bytes),
        max_stream_chunk_bytes: args
            .connector_stream_max_chunk_bytes
            .or(env_usize(ENV_NAMES[6])?)
            .unwrap_or(defaults.max_stream_chunk_bytes),
        max_in_flight: args
            .connector_event_max_in_flight
            .or(env_usize(ENV_NAMES[3])?)
            .unwrap_or(defaults.max_in_flight),
        max_event_age: std::time::Duration::from_secs(
            args.connector_event_max_age_seconds
                .or(env_u64(ENV_NAMES[4])?)
                .unwrap_or(defaults.max_event_age.as_secs()),
        ),
        max_future_skew: std::time::Duration::from_secs(
            args.connector_event_max_future_skew_seconds
                .or(env_u64(ENV_NAMES[5])?)
                .unwrap_or(defaults.max_future_skew.as_secs()),
        ),
        max_stream_callback_age: std::time::Duration::from_secs(
            args.connector_stream_callback_max_age_seconds
                .or(env_u64(ENV_NAMES[7])?)
                .unwrap_or(defaults.max_stream_callback_age.as_secs()),
        ),
    };
    limits.validate().map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("connector event ingress limits are invalid: {error}"),
    })?;
    Ok((limits, explicitly_configured))
}

fn decode_32_byte_hex(raw: &str, label: &str) -> Result<[u8; 32], StartupError> {
    let bytes = hex::decode(raw.trim()).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("{label} is not valid hex: {error}"),
    })?;
    bytes.try_into().map_err(|_| StartupError {
        code: "aip.server.config",
        message: format!("{label} must contain exactly 32 bytes"),
    })
}

fn trust_resolvers_from_args(args: &CoreArgs) -> Result<DaemonTrustResolvers, StartupError> {
    let identity_file = args.trusted_identity_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_TRUSTED_IDENTITY_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let identity: Arc<dyn TrustedIdentityResolver> = match identity_file {
        Some(path) => Arc::new(StaticTrustedIdentityResolver::new(
            load_trusted_identity_bindings(&path)?,
        )),
        None => Arc::new(DenyAllTrustedIdentityResolver),
    };
    let authority_file = args.approval_authority_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_APPROVAL_AUTHORITY_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let approval: Arc<dyn ApprovalAuthorityResolver> = match authority_file {
        Some(path) => Arc::new(StaticApprovalAuthorityResolver::new(
            load_authority_memberships(&path)?,
        )),
        None => Arc::new(DenyAllApprovalAuthorityResolver),
    };
    Ok(DaemonTrustResolvers::new(identity, approval))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedIdentityDirectoryEntry {
    principal_id: PrincipalId,
    #[serde(default)]
    tenant: Option<VerifiedTenant>,
    #[serde(default)]
    credential: Option<CredentialHandle>,
    #[serde(default)]
    identity: Option<IdentityContext>,
    revision: u64,
    #[serde(default)]
    revoked: bool,
    #[serde(default, with = "time::serde::rfc3339::option")]
    expires_at: Option<time::OffsetDateTime>,
}

impl From<TrustedIdentityDirectoryEntry> for TrustedIdentityBinding {
    fn from(entry: TrustedIdentityDirectoryEntry) -> Self {
        Self {
            principal_id: entry.principal_id,
            tenant: entry.tenant,
            credential: entry.credential,
            identity: entry.identity,
            revision: entry.revision,
            revoked: entry.revoked,
            expires_at: entry.expires_at,
        }
    }
}

fn load_trusted_identity_bindings(
    path: &Path,
) -> Result<Vec<TrustedIdentityBinding>, StartupError> {
    let entries = serde_json::from_str::<Vec<TrustedIdentityDirectoryEntry>>(
        &read_secure_configuration_file(path, "trusted identity")?,
    )
    .map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("invalid trusted identity JSON: {error}"),
    })?;
    if entries.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "trusted identity file must contain at least one binding".to_owned(),
        });
    }
    let mut seen = HashSet::new();
    let mut bindings = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.revision == 0 || entry.revoked {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity binding for `{}` is revoked or has no revision",
                    entry.principal_id
                ),
            });
        }
        if entry
            .expires_at
            .is_some_and(|expires_at| expires_at <= time::OffsetDateTime::now_utc())
        {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity binding for `{}` is expired",
                    entry.principal_id
                ),
            });
        }
        if let Some(tenant) = &entry.tenant {
            tenant.validate().map_err(config_error)?;
        }
        if let Some(credential) = &entry.credential {
            credential
                .validate(&BTreeSet::new())
                .map_err(config_error)?;
        }
        if !seen.insert(entry.principal_id.clone()) {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity file contains duplicate principal `{}`",
                    entry.principal_id
                ),
            });
        }
        bindings.push(entry.into());
    }
    Ok(bindings)
}

fn load_authority_memberships(path: &Path) -> Result<Vec<AuthorityMembership>, StartupError> {
    let memberships = serde_json::from_str::<Vec<AuthorityMembership>>(
        &read_secure_configuration_file(path, "approval authority")?,
    )
    .map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("invalid approval authority JSON: {error}"),
    })?;
    if memberships.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "approval authority file must contain at least one membership".to_owned(),
        });
    }
    let mut seen = HashSet::new();
    for membership in &memberships {
        membership
            .validate_for(&membership.principal_id)
            .map_err(config_error)?;
        if membership.revision == 0 || !seen.insert(membership.principal_id.clone()) {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "approval authority membership for `{}` has no revision or is duplicated",
                    membership.principal_id
                ),
            });
        }
    }
    Ok(memberships)
}

fn read_secure_configuration_file(path: &Path, label: &str) -> Result<String, StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!(
            "failed to inspect {label} file `{}`: {error}",
            path.display()
        ),
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!(
                "{label} path `{}` must be a regular file and not a symbolic link",
                path.display()
            ),
        });
    }
    if metadata.len() > 1024 * 1024 {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!("{label} file `{}` exceeds 1 MiB", path.display()),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "{label} file `{}` must not be group- or world-writable",
                    path.display()
                ),
            });
        }
    }
    fs::read_to_string(path).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("failed to read {label} file `{}`: {error}", path.display()),
    })
}

fn read_secret_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!(
            "failed to inspect secret file `{}`: {error}",
            path.display()
        ),
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!("secret path `{}` must be a regular file", path.display()),
        });
    }
    if metadata.len() > max_bytes as u64 {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!("secret file `{}` exceeds {max_bytes} bytes", path.display()),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("secret file `{}` must use mode 0600", path.display()),
            });
        }
    }
    fs::read(path).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("failed to read secret file `{}`: {error}", path.display()),
    })
}

fn resolve_secret_text(
    inline: Option<String>,
    file: Option<PathBuf>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>, StartupError> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(StartupError {
            code: "aip.server.config",
            message: format!("configure {label} either inline or by file, not both"),
        }),
        (Some(value), None) => {
            let value = value.trim().to_owned();
            if value.is_empty() || value.len() > max_bytes {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: format!("{label} must contain 1 to {max_bytes} bytes"),
                });
            }
            Ok(Some(value))
        }
        (None, Some(path)) => {
            let bytes = read_secret_file(&path, max_bytes)?;
            let value = std::str::from_utf8(&bytes).map_err(|_| StartupError {
                code: "aip.server.config",
                message: format!("{label} file `{}` must contain UTF-8", path.display()),
            })?;
            let value = value.trim().to_owned();
            if value.is_empty() {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: format!("{label} file `{}` is empty", path.display()),
                });
            }
            Ok(Some(value))
        }
        (None, None) => Ok(None),
    }
}

async fn fleet_services_from_args(
    args: &CoreArgs,
    service_id: &PrincipalId,
    trust_domain: &str,
) -> Result<Option<DaemonFleetServices>, StartupError> {
    let (event_limits, event_limits_configured) = connector_event_limits_from_args(args)?;
    let registry_url = resolve_secret_text(
        args.connector_registry_url
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_CONNECTOR_REGISTRY_URL").ok()),
        args.connector_registry_url_file.clone().or_else(|| {
            env::var("GETAIP_SERVER_CONNECTOR_REGISTRY_URL_FILE")
                .ok()
                .map(PathBuf::from)
        }),
        "connector-registry PostgreSQL URL",
        16 * 1024,
    )?;
    let stream_callback_url = args
        .connector_fleet_callback_url
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_CONNECTOR_FLEET_CALLBACK_URL").ok());
    let pool_defaults = RegistryPoolLimits::default();
    let data_max_connections = args
        .connector_registry_data_max_connections
        .or(env_u32(
            "GETAIP_SERVER_CONNECTOR_REGISTRY_DATA_MAX_CONNECTIONS",
        )?)
        .unwrap_or(pool_defaults.data_max_connections);
    let acquire_timeout_ms = args
        .connector_registry_acquire_timeout_ms
        .or(env_u64(
            "GETAIP_SERVER_CONNECTOR_REGISTRY_ACQUIRE_TIMEOUT_MS",
        )?)
        .unwrap_or_else(|| {
            u64::try_from(pool_defaults.acquire_timeout.as_millis()).unwrap_or(u64::MAX)
        });
    let seed_file = args.connector_fleet_signing_seed_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_CONNECTOR_FLEET_SIGNING_SEED_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let allowed_hosts = merged_env_list(
        args.connector_fleet_allowed_hosts.clone(),
        "GETAIP_SERVER_CONNECTOR_FLEET_ALLOWED_HOSTS",
    )
    .into_iter()
    .map(|host| host.trim().to_ascii_lowercase())
    .filter(|host| !host.is_empty())
    .collect::<HashSet<_>>();
    let trust_registry_endpoints = args.connector_fleet_trust_registry_endpoints
        || env_flag("GETAIP_SERVER_CONNECTOR_FLEET_TRUST_REGISTRY_ENDPOINTS");
    let allow_http =
        args.connector_fleet_allow_http || env_flag("GETAIP_SERVER_CONNECTOR_FLEET_ALLOW_HTTP");
    let allow_private_networks = args.connector_fleet_allow_private_networks
        || env_flag("GETAIP_SERVER_CONNECTOR_FLEET_ALLOW_PRIVATE_NETWORKS");
    let request_timeout_ms = args
        .connector_fleet_timeout_ms
        .or(env_u64("GETAIP_SERVER_CONNECTOR_FLEET_TIMEOUT_MS")?)
        .unwrap_or(5_000);
    let max_response_bytes = args
        .connector_fleet_max_response_bytes
        .or(env_usize(
            "GETAIP_SERVER_CONNECTOR_FLEET_MAX_RESPONSE_BYTES",
        )?)
        .unwrap_or(4 * 1024 * 1024);
    let max_cached_clients = args
        .connector_fleet_max_cached_clients
        .or(env_usize(
            "GETAIP_SERVER_CONNECTOR_FLEET_MAX_CACHED_CLIENTS",
        )?)
        .unwrap_or(256);
    let tls_ca_certificate_pem = args
        .connector_fleet_tls_ca_file
        .clone()
        .or_else(|| {
            env::var("GETAIP_SERVER_CONNECTOR_FLEET_TLS_CA_FILE")
                .ok()
                .map(PathBuf::from)
        })
        .map(|path| {
            read_secure_configuration_file(&path, "connector fleet TLS CA").map(String::into_bytes)
        })
        .transpose()?;
    let topology = RouteTopologyPreference {
        region: args
            .connector_fleet_region
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_CONNECTOR_FLEET_REGION").ok())
            .filter(|value| !value.trim().is_empty()),
        zone: args
            .connector_fleet_zone
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_CONNECTOR_FLEET_ZONE").ok())
            .filter(|value| !value.trim().is_empty()),
        capacity_class: args
            .connector_fleet_capacity_class
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_CONNECTOR_FLEET_CAPACITY_CLASS").ok())
            .filter(|value| !value.trim().is_empty()),
        allow_cross_region: !(args.connector_fleet_disable_cross_region_failover
            || env_flag("GETAIP_SERVER_CONNECTOR_FLEET_DISABLE_CROSS_REGION_FAILOVER")),
    };
    let admission_defaults = RemoteAdmissionLimits::default();
    let max_in_flight = args
        .connector_fleet_max_in_flight
        .or(env_usize("GETAIP_SERVER_CONNECTOR_FLEET_MAX_IN_FLIGHT")?)
        .unwrap_or(admission_defaults.max_in_flight);
    let max_in_flight_per_tenant = args
        .connector_fleet_max_in_flight_per_tenant
        .or(env_usize(
            "GETAIP_SERVER_CONNECTOR_FLEET_MAX_IN_FLIGHT_PER_TENANT",
        )?)
        .unwrap_or(admission_defaults.max_in_flight_per_tenant);
    let max_queued = args
        .connector_fleet_max_queued
        .or(env_usize("GETAIP_SERVER_CONNECTOR_FLEET_MAX_QUEUED")?)
        .unwrap_or(admission_defaults.max_queued);
    let max_queued_per_tenant = args
        .connector_fleet_max_queued_per_tenant
        .or(env_usize(
            "GETAIP_SERVER_CONNECTOR_FLEET_MAX_QUEUED_PER_TENANT",
        )?)
        .unwrap_or(admission_defaults.max_queued_per_tenant);
    let max_queue_bytes = args
        .connector_fleet_max_queue_bytes
        .or(env_usize("GETAIP_SERVER_CONNECTOR_FLEET_MAX_QUEUE_BYTES")?)
        .unwrap_or(admission_defaults.max_queue_bytes);
    let max_request_bytes = args
        .connector_fleet_max_request_bytes
        .or(env_usize(
            "GETAIP_SERVER_CONNECTOR_FLEET_MAX_REQUEST_BYTES",
        )?)
        .unwrap_or(admission_defaults.max_request_bytes);
    let max_queue_age_ms = args
        .connector_fleet_max_queue_age_ms
        .or(env_u64("GETAIP_SERVER_CONNECTOR_FLEET_MAX_QUEUE_AGE_MS")?)
        .unwrap_or_else(|| {
            u64::try_from(admission_defaults.max_queue_age.as_millis()).unwrap_or(u64::MAX)
        });
    let tenant_weights = parse_tenant_weights(merged_env_list(
        args.connector_fleet_tenant_weights.clone(),
        "GETAIP_SERVER_CONNECTOR_FLEET_TENANT_WEIGHTS",
    ))?;
    let retry_budget = match args.connector_fleet_retry_budget {
        Some(value) => value,
        None => env_u64("GETAIP_SERVER_CONNECTOR_FLEET_RETRY_BUDGET")?
            .unwrap_or(2)
            .try_into()
            .map_err(|_| StartupError {
                code: "aip.server.config",
                message: "connector fleet retry budget exceeds u32".to_owned(),
            })?,
    };
    let Some(registry_url) = registry_url else {
        let partial = args.connector_registry_data_max_connections.is_some()
            || args.connector_registry_url_file.is_some()
            || args.connector_registry_acquire_timeout_ms.is_some()
            || seed_file.is_some()
            || stream_callback_url.is_some()
            || !allowed_hosts.is_empty()
            || trust_registry_endpoints
            || allow_http
            || allow_private_networks
            || args.connector_fleet_timeout_ms.is_some()
            || args.connector_fleet_max_response_bytes.is_some()
            || args.connector_fleet_retry_budget.is_some()
            || args.connector_fleet_max_cached_clients.is_some()
            || args.connector_fleet_tls_ca_file.is_some()
            || args.connector_fleet_region.is_some()
            || args.connector_fleet_zone.is_some()
            || args.connector_fleet_capacity_class.is_some()
            || args.connector_fleet_disable_cross_region_failover
            || args.connector_fleet_max_in_flight.is_some()
            || args.connector_fleet_max_in_flight_per_tenant.is_some()
            || args.connector_fleet_max_queued.is_some()
            || args.connector_fleet_max_queued_per_tenant.is_some()
            || args.connector_fleet_max_queue_bytes.is_some()
            || args.connector_fleet_max_request_bytes.is_some()
            || args.connector_fleet_max_queue_age_ms.is_some()
            || !tenant_weights.is_empty()
            || event_limits_configured;
        if partial {
            return Err(StartupError {
                code: "aip.server.config",
                message: "connector fleet options require --connector-registry-url".to_owned(),
            });
        }
        return Ok(None);
    };
    let seed_file = seed_file.ok_or_else(|| StartupError {
        code: "aip.server.config",
        message: "connector fleet mode requires an owner-only signing-seed file".to_owned(),
    })?;
    if !trust_registry_endpoints && allowed_hosts.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "connector fleet mode requires a host allowlist or registry endpoint trust"
                .to_owned(),
        });
    }
    if registry_url.trim().is_empty()
        || data_max_connections == 0
        || acquire_timeout_ms == 0
        || request_timeout_ms == 0
        || max_response_bytes == 0
        || max_cached_clients == 0
    {
        return Err(StartupError {
            code: "aip.server.config",
            message: "connector fleet URL and numeric bounds must be non-empty and non-zero"
                .to_owned(),
        });
    }
    let seed_text =
        String::from_utf8(read_secret_file(&seed_file, 256)?).map_err(|_| StartupError {
            code: "aip.server.config",
            message: "connector fleet signing seed must be UTF-8 hexadecimal text".to_owned(),
        })?;
    let signing_key = Arc::new(aip_crypto::signing_key_from_seed(decode_32_byte_hex(
        &seed_text,
        "connector fleet signing seed",
    )?));
    let mut principal = principal_from_id(service_id.as_str())?;
    principal.trust_domain = Some(trust_domain.to_owned());
    principal.did = Some(aip_crypto::did_key_from_verifying_key(
        &signing_key.verifying_key(),
    ));
    let signer = CallbackSigner {
        principal,
        signing_key,
    };
    let endpoint_policy = GatewayCallbackPolicy {
        allowed_hosts,
        allow_http,
        allow_private_networks,
        request_timeout_ms,
        max_response_bytes,
        tls_ca_certificate_pem,
        signer: Some(signer.clone()),
        a2a_credential_key: None,
    };
    let event_signer = signer.clone();
    let dispatcher = if trust_registry_endpoints {
        NativeAipHttpDispatcher::with_policy_provider(
            signer,
            Arc::new(RegistryBoundEndpointPolicy::new(endpoint_policy)),
            retry_budget,
        )
    } else {
        NativeAipHttpDispatcher::new(signer, endpoint_policy, retry_budget)
    }
    .with_client(NativeAipHttpClient::new(max_cached_clients));
    let dispatcher = match stream_callback_url {
        Some(target) => {
            let target = Url::parse(target.trim()).map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("connector fleet callback URL is invalid: {error}"),
            })?;
            if target.scheme() == "http" && !allow_http {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: "plaintext connector fleet callback URL requires --connector-fleet-allow-http"
                        .to_owned(),
                });
            }
            dispatcher
                .with_stream_callback_target(target)
                .map_err(|error| StartupError {
                    code: "aip.server.config",
                    message: error.to_string(),
                })?
        }
        None => dispatcher,
    };
    let streaming_enabled = dispatcher.stream_callbacks_enabled();
    let pool_limits = RegistryPoolLimits {
        control_max_connections: pool_defaults.control_max_connections,
        data_max_connections,
        acquire_timeout: std::time::Duration::from_millis(acquire_timeout_ms),
    };
    let registry = PostgresConnectorRegistry::connect_data_plane(registry_url.trim(), pool_limits)
        .await
        .map_err(|error| StartupError {
            code: "aip.server.connector_registry",
            message: error.to_string(),
        })?;
    let registry = Arc::new(registry);
    let admission = FairAdmissionScheduler::new(RemoteAdmissionLimits {
        max_in_flight,
        max_in_flight_per_tenant,
        max_queued,
        max_queued_per_tenant,
        max_queue_bytes,
        max_request_bytes,
        max_queue_age: std::time::Duration::from_millis(max_queue_age_ms),
        tenant_weights,
    })
    .map_err(|error| StartupError {
        code: "aip.server.config",
        message: error.to_string(),
    })?;
    let handler = Arc::new(
        RemoteConnectorHandler::new(
            registry.clone(),
            Arc::new(dispatcher),
            CapabilityImplementationSupport {
                invocation: true,
                cancellation: true,
                streaming: streaming_enabled,
                retry: true,
                transaction: true,
                reconciliation: true,
                compensation: true,
                approval: true,
                credentials: true,
            },
        )
        .with_admission_scheduler(admission.clone())
        .with_topology_preference(topology),
    );
    Ok(Some(
        DaemonFleetServices::new(registry.clone(), handler)
            .with_status_provider(registry.clone())
            .with_remote_admission(admission)
            .with_event_ingress(registry, event_signer, event_limits),
    ))
}

fn nats_config_from_args(
    args: &CoreArgs,
    fallback_trust_domain: String,
) -> Result<Option<AipDaemonNatsConfig>, StartupError> {
    let server_url = args
        .nats_url
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_NATS_URL").ok());
    let username = args
        .nats_username
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_NATS_USERNAME").ok());
    let password_file = args.nats_password_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_NATS_PASSWORD_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let Some(server_url) = server_url else {
        if username.is_some() || password_file.is_some() {
            return Err(StartupError {
                code: "aip.server.config",
                message: "NATS authentication requires a NATS server URL".to_owned(),
            });
        }
        return Ok(None);
    };
    let authentication = match (username, password_file) {
        (None, None) => None,
        (Some(username), Some(path)) => {
            let password =
                String::from_utf8(read_secret_file(&path, 16 * 1024)?).map_err(|_| {
                    StartupError {
                        code: "aip.server.config",
                        message: "NATS password file must contain valid UTF-8".to_owned(),
                    }
                })?;
            Some(NatsAuthentication::user_password(username, password).map_err(config_error)?)
        }
        _ => {
            return Err(StartupError {
                code: "aip.server.config",
                message: "NATS username and password file must be configured together".to_owned(),
            });
        }
    };
    Ok(Some(AipDaemonNatsConfig {
        server_url,
        authentication,
        trust_domain: args
            .nats_trust_domain
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_NATS_TRUST_DOMAIN").ok())
            .unwrap_or(fallback_trust_domain),
        service: args
            .nats_service
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_NATS_SERVICE").ok())
            .unwrap_or_else(|| DEFAULT_NATS_SERVICE.to_owned()),
        version: args
            .nats_version
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_NATS_VERSION").ok())
            .unwrap_or_else(|| DEFAULT_NATS_VERSION.to_owned()),
        queue_group: args
            .nats_queue_group
            .clone()
            .or_else(|| env::var("GETAIP_SERVER_NATS_QUEUE_GROUP").ok()),
        request_timeout_ms: env_u64("GETAIP_SERVER_NATS_REQUEST_TIMEOUT_MS")?
            .unwrap_or(args.nats_request_timeout_ms),
    }))
}

fn mcp_protected_resource_config_from_args(args: &CoreArgs) -> Option<McpProtectedResourceConfig> {
    let bearer_token = args
        .mcp_bearer_token
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_MCP_BEARER_TOKEN").ok());
    let authorization_servers = merged_env_list(
        args.mcp_authorization_servers.clone(),
        "GETAIP_SERVER_MCP_AUTHORIZATION_SERVERS",
    );
    let scopes = merged_env_list(args.mcp_scopes.clone(), "GETAIP_SERVER_MCP_SCOPES");
    let required_scopes = merged_env_list(
        args.mcp_required_scopes.clone(),
        "GETAIP_SERVER_MCP_REQUIRED_SCOPES",
    );
    let documentation = args
        .mcp_resource_documentation
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_MCP_RESOURCE_DOCUMENTATION").ok());
    let allowed_origins = merged_env_list(
        args.mcp_allowed_origins.clone(),
        "GETAIP_SERVER_MCP_ALLOWED_ORIGINS",
    );
    let resource = args
        .mcp_resource
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_MCP_RESOURCE").ok())
        .or_else(|| {
            (bearer_token.is_some()
                || !authorization_servers.is_empty()
                || !scopes.is_empty()
                || documentation.is_some())
            .then(|| format!("http://{}/mcp", args.bind))
        })?;
    let mut metadata =
        aip_transport_mcp_streamable_http::ProtectedResourceMetadata::bearer(resource);
    metadata.authorization_servers = authorization_servers;
    metadata.scopes_supported = scopes;
    metadata.resource_documentation = documentation;
    Some(McpProtectedResourceConfig {
        metadata,
        bearer_token,
        realm: Some("aip.server.mcp".to_owned()),
        required_scope: (!required_scopes.is_empty()).then(|| required_scopes.join(" ")),
        metadata_url: Some("/.well-known/oauth-protected-resource".to_owned()),
        allowed_origins,
        allow_loopback_origins: true,
    })
}

fn mcp_token_verifier_from_args(
    args: &CoreArgs,
    protected_resource: &Option<McpProtectedResourceConfig>,
) -> Result<Option<IntrospectionTokenVerifier<HttpTokenIntrospector>>, StartupError> {
    let url = args
        .mcp_introspection_url
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_MCP_INTROSPECTION_URL").ok());
    let issuer = args
        .mcp_introspection_issuer
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_MCP_INTROSPECTION_ISSUER").ok());
    let client_id = args
        .mcp_introspection_client_id
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_MCP_INTROSPECTION_CLIENT_ID").ok());
    let secret_file = args
        .mcp_introspection_client_secret_file
        .clone()
        .or_else(|| {
            env::var("GETAIP_SERVER_MCP_INTROSPECTION_CLIENT_SECRET_FILE")
                .ok()
                .map(PathBuf::from)
        });
    let configured = [
        url.is_some(),
        issuer.is_some(),
        client_id.is_some(),
        secret_file.is_some(),
    ];
    if configured.iter().all(|value| !value) {
        return Ok(None);
    }
    if !configured.iter().all(|value| *value) {
        return Err(StartupError {
            code: "aip.server.config",
            message: "MCP introspection requires URL, issuer, client id, and secret file"
                .to_owned(),
        });
    }
    let (Some(url), Some(issuer), Some(client_id), Some(secret_file)) =
        (url, issuer, client_id, secret_file)
    else {
        unreachable!("complete introspection configuration checked above")
    };
    let policy = protected_resource.as_ref().ok_or_else(|| StartupError {
        code: "aip.server.config",
        message: "MCP introspection requires a protected resource identifier".to_owned(),
    })?;
    if policy.bearer_token.is_some()
        || !policy
            .metadata
            .authorization_servers
            .iter()
            .any(|candidate| candidate == &issuer)
    {
        return Err(StartupError {
            code: "aip.server.config",
            message:
                "MCP introspection cannot use a static token and its issuer must be advertised"
                    .to_owned(),
        });
    }
    let secret = read_secret_file(&secret_file, 16 * 1024)?;
    let introspector = if args.mcp_introspection_allow_loopback_http
        || env_flag("GETAIP_SERVER_MCP_INTROSPECTION_ALLOW_LOOPBACK_HTTP")
    {
        HttpTokenIntrospector::new_with_loopback_http(url, issuer, client_id, secret)
    } else {
        HttpTokenIntrospector::new(url, issuer, client_id, secret)
    }
    .map_err(config_error)?;
    Ok(Some(IntrospectionTokenVerifier::new(introspector)))
}

async fn serve_mcp_stdio(daemon: AipDaemon) -> Result<(), StartupError> {
    const SESSION_ID: &str = "stdio";
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    let mut outgoing = daemon
        .open_mcp_stdio_peer(SESSION_ID)
        .await
        .map_err(|error| StartupError {
            code: "aip.server.mcp_stdio",
            message: error.to_string(),
        })?;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.map_err(StartupError::io)? else { break; };
                if line.trim().is_empty() { continue; }
                let frame = match decode_frame(line.as_bytes()) {
                    Ok(frame) => frame,
                    Err(error) => {
                        let response = aip_profile_mcp::JsonRpcResponse::error(
                            Value::Null,
                            aip_profile_mcp::JsonRpcError {
                                code: -32700,
                                message: error.to_string(),
                                data: Some(serde_json::json!({ "component": "aip.server.mcp_stdio" })),
                            },
                        );
                        write_stdio_frame(&mut stdout, McpStdioFrame::Response(response)).await?;
                        continue;
                    }
                };
                match frame {
                    McpStdioFrame::Request(request) => {
                        let response = daemon.mcp_server().handle_request(SESSION_ID, request).await;
                        write_stdio_frame(&mut stdout, McpStdioFrame::Response(response)).await?;
                    }
                    McpStdioFrame::Notification(notification) => {
                        if let Err(error) = daemon.mcp_server().handle_notification(SESSION_ID, notification).await {
                            eprintln!("getaip-server MCP stdio notification error: {error}");
                        }
                    }
                    McpStdioFrame::Response(response) => {
                        daemon.accept_mcp_stdio_response(SESSION_ID, response).await.map_err(|error| StartupError {
                            code: "aip.server.mcp_stdio",
                            message: error.to_string(),
                        })?;
                    }
                }
            }
            frame = outgoing.recv() => {
                let Some(frame) = frame else { break; };
                let frame = match frame {
                    McpFrame::Request(request) => McpStdioFrame::Request(request),
                    McpFrame::Notification(notification) => McpStdioFrame::Notification(notification),
                    McpFrame::Response(response) => McpStdioFrame::Response(response),
                };
                write_stdio_frame(&mut stdout, frame).await?;
            }
        }
    }
    Ok(())
}

async fn write_stdio_frame(
    stdout: &mut tokio::io::Stdout,
    frame: McpStdioFrame,
) -> Result<(), StartupError> {
    let encoded = encode_frame(&frame).map_err(|error| StartupError {
        code: "aip.server.mcp_stdio",
        message: error.to_string(),
    })?;
    stdout.write_all(&encoded).await.map_err(StartupError::io)?;
    stdout.flush().await.map_err(StartupError::io)
}

async fn parse_delegation_routes(
    http_specs: Vec<String>,
    nats_specs: Vec<String>,
    endpoint_policy: &GatewayCallbackPolicy,
    default_trust_domain: &str,
) -> Result<Vec<DelegationRoute>, StartupError> {
    if http_specs.is_empty() && nats_specs.is_empty() {
        return Ok(Vec::new());
    }
    let signer = endpoint_policy.signer.clone().ok_or_else(|| StartupError {
        code: "aip.server.config",
        message: "delegation routes require a native response/callback signing seed".to_owned(),
    })?;
    let mut routes = Vec::with_capacity(http_specs.len() + nats_specs.len());
    for spec in http_specs {
        let (delegate_id, fields) = spec.split_once('=').ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: format!(
                "HTTP delegation route `{spec}` must be DELEGATE_ID=URL,PEER_ID,PEER_DID[,TRUST_DOMAIN]"
            ),
        })?;
        let parts = fields.split(',').map(str::trim).collect::<Vec<_>>();
        if !(3..=4).contains(&parts.len()) || parts[..3].iter().any(|value| value.is_empty()) {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("HTTP delegation route `{spec}` has invalid fields"),
            });
        }
        let trust_domain = parts
            .get(3)
            .copied()
            .filter(|value| !value.is_empty())
            .unwrap_or(default_trust_domain);
        let security = DelegationPeerSecurity::new(
            trust_domain,
            signer.clone(),
            principal_from_id(parts[1])?,
            parts[2],
            endpoint_policy.clone(),
        )
        .map_err(config_error)?;
        security
            .endpoint_policy
            .validate_destination(parts[0])
            .await
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("HTTP delegation route `{spec}` is unsafe: {error}"),
            })?;
        routes.push(DelegationRoute::native_http_for_delegate(
            principal_from_id(delegate_id.trim())?.id,
            parts[0].to_owned(),
            security,
        ));
    }
    for spec in nats_specs {
        let (capability, fields) = spec.split_once('=').ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: format!(
                "NATS delegation route `{spec}` must be CAPABILITY_ID=SERVER_URL,SUBJECT,PEER_ID,PEER_DID[,TIMEOUT_MS[,TRUST_DOMAIN]]"
            ),
        })?;
        let parts = fields.split(',').map(str::trim).collect::<Vec<_>>();
        if !(4..=6).contains(&parts.len()) || parts[..4].iter().any(|value| value.is_empty()) {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` has invalid fields"),
            });
        }
        let timeout_ms = parts
            .get(4)
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u64>().map_err(config_error))
            .transpose()?
            .unwrap_or(30_000);
        let trust_domain = parts
            .get(5)
            .copied()
            .filter(|value| !value.is_empty())
            .unwrap_or(default_trust_domain);
        let security = DelegationPeerSecurity::new(
            trust_domain,
            signer.clone(),
            principal_from_id(parts[2])?,
            parts[3],
            endpoint_policy.clone(),
        )
        .map_err(config_error)?;
        security
            .endpoint_policy
            .validate_destination(parts[0])
            .await
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` is unsafe: {error}"),
            })?;
        routes.push(DelegationRoute {
            delegate_id: None,
            capability_id: Some(CapabilityId::parse(capability.trim()).map_err(config_error)?),
            binding: DelegationRouteBinding::NativeNats {
                server_url: parts[0].to_owned(),
                subject: parts[1].to_owned(),
                timeout_ms,
                security,
            },
        });
    }
    Ok(routes)
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn env_u64(name: &'static str) -> Result<Option<u64>, StartupError> {
    env::var(name)
        .ok()
        .map(|value| value.parse::<u64>().map_err(config_error))
        .transpose()
}

fn env_u32(name: &'static str) -> Result<Option<u32>, StartupError> {
    env::var(name)
        .ok()
        .map(|value| value.parse::<u32>().map_err(config_error))
        .transpose()
}

fn env_usize(name: &'static str) -> Result<Option<usize>, StartupError> {
    env::var(name)
        .ok()
        .map(|value| value.parse::<usize>().map_err(config_error))
        .transpose()
}

fn route_specs(mut values: Vec<String>, env_name: &str) -> Vec<String> {
    if let Ok(raw) = env::var(env_name) {
        values.extend(
            raw.split([';', '\n'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    values
}

fn merged_env_list(mut values: Vec<String>, env_name: &str) -> Vec<String> {
    if let Ok(raw) = env::var(env_name) {
        values.extend(
            raw.split([',', ';', '\n'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    values
}

fn parse_tenant_weights(values: Vec<String>) -> Result<BTreeMap<String, u32>, StartupError> {
    let mut weights = BTreeMap::new();
    for value in values {
        let (tenant_id, weight) = value.split_once('=').ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: "connector fleet tenant weights must use TENANT_ID=WEIGHT".to_owned(),
        })?;
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty() || tenant_id.len() > 256 {
            return Err(StartupError {
                code: "aip.server.config",
                message: "connector fleet tenant weight id must contain 1 to 256 bytes".to_owned(),
            });
        }
        let weight = weight.trim().parse::<u32>().map_err(config_error)?;
        if weight == 0 {
            return Err(StartupError {
                code: "aip.server.config",
                message: "connector fleet tenant weight must be greater than zero".to_owned(),
            });
        }
        if weights.insert(tenant_id.to_owned(), weight).is_some() {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("duplicate connector fleet tenant weight for `{tenant_id}`"),
            });
        }
    }
    Ok(weights)
}

#[cfg(all(test, unix))]
mod tests {
    use super::resolve_secret_text;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn secret_text_file_trims_conventional_line_endings() {
        let path = std::env::temp_dir().join(format!(
            "getaip-server-secret-text-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::write(&path, b"expected-token\r\n").expect("write secret fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict secret fixture");

        let loaded = resolve_secret_text(None, Some(path.clone()), "test bearer token", 16 * 1024);
        fs::remove_file(&path).expect("remove secret fixture");

        assert_eq!(
            loaded.expect("load secret"),
            Some("expected-token".to_owned())
        );
    }
}
