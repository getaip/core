//! Migration-compatible `getaip-server` daemon entrypoint.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used))]

mod modules;

use modules::{
    CalDiyModuleFactory, EnterpriseSandboxModuleFactory, HermesModuleFactory,
    SupportSandboxModuleFactory,
};

use aip_auth::{
    ApprovalAuthorityResolver, AuthError, AuthorityMembership, CredentialHandle,
    CredentialMaterial, CredentialProvider, DenyAllApprovalAuthorityResolver,
    DenyAllTrustedIdentityResolver, HttpTokenIntrospector, IntrospectionTokenVerifier,
    StaticApprovalAuthorityResolver, StaticTrustedIdentityResolver, TrustedIdentityBinding,
    TrustedIdentityResolver, VerifiedTenant,
};
use aip_connector::ConnectorSecret;
use aip_connector_cal_diy::{
    CalDiyAuth, CalDiyConnector, CalDiyTenantAccountBinding, CalDiyWebhookDestinationPolicy,
    CalDiyWebhookReplayStore, FileCalDiyWebhookReplayStore, InMemoryCalDiyWebhookReplayStore,
    StaticCalDiyWebhookSecrets,
};
use aip_connector_hermes_agent::{HermesAgentEndpoint, HermesOperatorPolicy};
use aip_connector_registry_postgres::PostgresConnectorRegistry;
use aip_connector_remote::{
    NativeAipHttpDispatcher, RegistryBoundEndpointPolicy, RemoteConnectorHandler,
};
use aip_core::{CapabilityId, IdentityContext, Principal, PrincipalId, PrincipalKind};
use aip_discovery::CapabilityImplementationSupport;
use aip_gateway::{
    A2aCallbackCredentialKey, CallbackSigner, DelegationPeerSecurity, DelegationRoute,
    DelegationRouteBinding, GatewayCallbackPolicy, NativeAipHttpClient,
};
use aip_mcp_session::McpFrame;
use aip_transport_mcp_stdio::{McpStdioFrame, decode_frame, encode_frame};
use aip_transport_nats::NatsAuthentication;
use async_trait::async_trait;
use clap::Parser;
use getaip_server::{
    AipDaemon, AipDaemonConfig, AipDaemonDeployment, AipDaemonNatsConfig, DEFAULT_NATS_SERVICE,
    DEFAULT_NATS_VERSION, DaemonFleetServices, DaemonTrustResolvers, McpProtectedResourceConfig,
    StartupError,
};
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

/// AIP daemon command-line options.
#[derive(Debug, Parser)]
#[command(name = "getaip-server", about = "AIP gateway daemon")]
struct Args {
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
    /// Hermes Agent endpoint exposed by this daemon, formatted as ID=URL.
    #[arg(long = "hermes-endpoint", value_name = "ID=URL")]
    hermes_endpoints: Vec<String>,
    /// Bearer token configured as API_SERVER_KEY on all Hermes endpoints.
    #[arg(long = "hermes-api-key", value_name = "TOKEN")]
    hermes_api_key: Option<String>,
    /// Permit Hermes operator principals to own first-class AIP delegations.
    #[arg(long = "hermes-operator-delegation-enabled")]
    hermes_operator_delegation_enabled: bool,
    /// Hermes model route used for governed operator runs.
    #[arg(long = "hermes-operator-model", value_name = "MODEL")]
    hermes_operator_model: Option<String>,
    /// File containing trusted system instructions for every operator run.
    #[arg(long = "hermes-operator-instructions-file", value_name = "PATH")]
    hermes_operator_instructions_file: Option<PathBuf>,
    /// Maximum wall-clock duration of an operator observation.
    #[arg(long = "hermes-operator-timeout-ms", value_name = "MILLISECONDS")]
    hermes_operator_timeout_ms: Option<u64>,
    /// Poll interval used for durable operator recovery.
    #[arg(long = "hermes-operator-poll-ms", value_name = "MILLISECONDS")]
    hermes_operator_poll_ms: Option<u64>,
    /// Maximum structured events accepted from one Hermes run.
    #[arg(long = "hermes-operator-max-events", value_name = "COUNT")]
    hermes_operator_max_events: Option<usize>,
    /// Maximum serialized AIP input supplied to one Hermes run.
    #[arg(long = "hermes-operator-max-input-bytes", value_name = "BYTES")]
    hermes_operator_max_input_bytes: Option<usize>,
    /// Maximum accepted AIP delegation-chain depth.
    #[arg(long = "hermes-operator-max-delegation-depth", value_name = "COUNT")]
    hermes_operator_max_delegation_depth: Option<usize>,
    /// TTL for exclusive run-start and approval-command claims.
    #[arg(long = "hermes-operator-claim-ttl-ms", value_name = "MILLISECONDS")]
    hermes_operator_claim_ttl_ms: Option<u64>,
    /// Time allowed to reconcile Hermes cancellation to a terminal status.
    #[arg(long = "hermes-operator-cancel-grace-ms", value_name = "MILLISECONDS")]
    hermes_operator_cancel_grace_ms: Option<u64>,
    /// Allowed delegated capability prefix; repeat for multiple prefixes.
    #[arg(long = "hermes-operator-capability-prefix", value_name = "PREFIX")]
    hermes_operator_capability_prefixes: Vec<String>,
    /// Delegated capability prefix exempt from the connector-level approval
    /// gate; repeat only for capabilities classified for unattended execution.
    #[arg(
        long = "hermes-operator-approval-exempt-capability-prefix",
        value_name = "PREFIX"
    )]
    hermes_operator_approval_exempt_capability_prefixes: Vec<String>,
    /// Allowed delegated scope prefix; repeat for multiple prefixes.
    #[arg(long = "hermes-operator-scope-prefix", value_name = "PREFIX")]
    hermes_operator_scope_prefixes: Vec<String>,
    /// Base URL of one self-hosted Cal.diy API deployment.
    #[arg(long = "cal-diy-base-url", value_name = "HTTPS_URL")]
    cal_diy_base_url: Option<String>,
    /// Stable deployment-local account id used to scope Cal.diy idempotency.
    #[arg(long = "cal-diy-account-id", value_name = "ACCOUNT_ID")]
    cal_diy_account_id: Option<String>,
    /// Trusted tenant-to-Cal-account binding, formatted as TENANT_ID=ACCOUNT_ID.
    #[arg(long = "cal-diy-tenant-account", value_name = "TENANT_ID=ACCOUNT_ID")]
    cal_diy_tenant_accounts: Vec<String>,
    /// Owner-only credential mapping, formatted as OPAQUE_HANDLE=MODE_0600_FILE.
    #[arg(long = "cal-diy-credential-file", value_name = "HANDLE=FILE")]
    cal_diy_credential_files: Vec<String>,
    /// Maximum Cal.diy response body accepted into memory.
    #[arg(long = "cal-diy-max-response-bytes", value_name = "BYTES")]
    cal_diy_max_response_bytes: Option<usize>,
    /// Mode-0600 file containing a Cal.diy API key or access token.
    #[arg(long = "cal-diy-bearer-token-file", value_name = "FILE")]
    cal_diy_bearer_token_file: Option<PathBuf>,
    /// Public Cal platform OAuth client id.
    #[arg(long = "cal-diy-oauth-client-id", value_name = "CLIENT_ID")]
    cal_diy_oauth_client_id: Option<String>,
    /// Mode-0600 file containing the Cal platform OAuth client secret.
    #[arg(long = "cal-diy-oauth-client-secret-file", value_name = "FILE")]
    cal_diy_oauth_client_secret_file: Option<PathBuf>,
    /// Signed webhook secret mapping, formatted as OPAQUE_REF=MODE_0600_FILE.
    #[arg(long = "cal-diy-webhook-secret-file", value_name = "REF=FILE")]
    cal_diy_webhook_secret_files: Vec<String>,
    /// Optional durable single-process webhook replay-observation file.
    #[arg(long = "cal-diy-webhook-replay-file", value_name = "FILE")]
    cal_diy_webhook_replay_file: Option<PathBuf>,
    /// Deployment-owned HTTPS ingress prefix allowed for Cal.diy webhooks.
    #[arg(
        long = "cal-diy-webhook-subscriber-prefix",
        value_name = "HTTPS_URL_PREFIX"
    )]
    cal_diy_webhook_subscriber_prefixes: Vec<String>,
    /// Require Ed25519 signatures on incoming AIP envelopes.
    #[arg(long)]
    require_signed_envelopes: bool,
    /// Trusted native signer binding, formatted as DID=PRINCIPAL_ID.
    #[arg(long = "trusted-signer", value_name = "DID=PRINCIPAL_ID")]
    trusted_signers: Vec<String>,
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
    /// Hex-encoded 32-byte Ed25519 seed used to sign callback envelopes.
    #[arg(long = "callback-signing-seed-hex", value_name = "HEX")]
    callback_signing_seed_hex: Option<String>,
    /// Hex-encoded 32-byte AES key used to encrypt A2A push credentials at rest.
    #[arg(long = "a2a-push-encryption-key-hex", value_name = "HEX")]
    a2a_push_encryption_key_hex: Option<String>,
    /// Permit plaintext HTTP callback targets.
    #[arg(long)]
    callback_allow_http: bool,
    /// Permit private or loopback callback target addresses.
    #[arg(long)]
    callback_allow_private_networks: bool,
    /// Directory used for durable runtime state.
    #[arg(long, value_name = "DIR")]
    storage_dir: Option<PathBuf>,
    /// PostgreSQL URL used for clustered durable runtime state.
    #[arg(long, value_name = "URL")]
    postgres_url: Option<String>,
    /// PostgreSQL URL for the normalized connector-fleet registry.
    #[arg(long = "connector-registry-url", value_name = "URL")]
    connector_registry_url: Option<String>,
    /// Owner-only file containing a 32-byte Ed25519 seed as hexadecimal text.
    #[arg(long = "connector-fleet-signing-seed-file", value_name = "FILE")]
    connector_fleet_signing_seed_file: Option<PathBuf>,
    /// Exact connector-host DNS name or IP literal; repeat for multiple hosts.
    #[arg(long = "connector-fleet-allowed-host", value_name = "HOST")]
    connector_fleet_allowed_hosts: Vec<String>,
    /// Trust each endpoint admitted by the connector control plane as its host allowlist.
    #[arg(long = "connector-fleet-trust-registry-endpoints")]
    connector_fleet_trust_registry_endpoints: bool,
    /// Permit plaintext HTTP connector-host endpoints.
    #[arg(long = "connector-fleet-allow-http")]
    connector_fleet_allow_http: bool,
    /// Permit private, loopback, link-local, or otherwise non-public connector-host addresses.
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
    /// PostgreSQL URL for the support sandbox business-data connector.
    #[arg(long = "support-sandbox-postgres-url", value_name = "URL")]
    support_sandbox_postgres_url: Option<String>,
    /// PostgreSQL URL for deterministic enterprise workflow capabilities.
    #[arg(long = "enterprise-sandbox-postgres-url", value_name = "URL")]
    enterprise_sandbox_postgres_url: Option<String>,
    /// NATS server URL. When set, getaip-server also serves native NATS request/reply.
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
    /// Optional NATS queue group for scaled daemon workers.
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
    /// Bearer token required by MCP Streamable HTTP endpoints.
    #[arg(long = "mcp-bearer-token", value_name = "TOKEN")]
    mcp_bearer_token: Option<String>,
    /// Protected-resource identifier advertised for MCP Streamable HTTP.
    #[arg(long = "mcp-resource", value_name = "RESOURCE")]
    mcp_resource: Option<String>,
    /// OAuth authorization server issuer advertised for MCP Streamable HTTP.
    #[arg(long = "mcp-authorization-server", value_name = "ISSUER")]
    mcp_authorization_servers: Vec<String>,
    /// OAuth scope advertised as supported by the MCP protected resource.
    #[arg(long = "mcp-scope", value_name = "SCOPE")]
    mcp_scopes: Vec<String>,
    /// OAuth scope required to establish any MCP HTTP session. Fine-grained
    /// operation scopes are enforced by individual AIP facade tools.
    #[arg(long = "mcp-required-scope", value_name = "SCOPE")]
    mcp_required_scopes: Vec<String>,
    /// RFC 7662 token introspection endpoint used by MCP HTTP authentication.
    #[arg(long = "mcp-introspection-url", value_name = "HTTPS_URL")]
    mcp_introspection_url: Option<String>,
    /// Trusted issuer represented by the configured introspection endpoint.
    #[arg(long = "mcp-introspection-issuer", value_name = "ISSUER")]
    mcp_introspection_issuer: Option<String>,
    /// OAuth client id used to authenticate token introspection requests.
    #[arg(long = "mcp-introspection-client-id", value_name = "CLIENT_ID")]
    mcp_introspection_client_id: Option<String>,
    /// Root-owned or mode-0600 file containing the introspection client secret.
    #[arg(long = "mcp-introspection-client-secret-file", value_name = "FILE")]
    mcp_introspection_client_secret_file: Option<PathBuf>,
    /// Permit an RFC 7662 endpoint on this process's loopback interface.
    #[arg(long = "mcp-introspection-allow-loopback-http")]
    mcp_introspection_allow_loopback_http: bool,
    /// Human-readable protected-resource documentation URL.
    #[arg(long = "mcp-resource-documentation", value_name = "URL")]
    mcp_resource_documentation: Option<String>,
    /// Browser origin allowed to call MCP Streamable HTTP.
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

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        match serde_json::to_string(&error) {
            Ok(rendered) => eprintln!("{rendered}"),
            Err(render_error) => {
                eprintln!("{{\"code\":\"aip.server.render_error\",\"message\":\"{render_error}\"}}")
            }
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<(), StartupError> {
    let args = Args::parse();
    let service_id = PrincipalId::parse(&args.service_id).map_err(|error| StartupError {
        code: "aip.server.config",
        message: error.to_string(),
    })?;
    let nats = nats_config_from_args(
        &args,
        args.trust_domain.as_deref().unwrap_or("local").to_owned(),
    )?;
    let mcp_protected_resource = mcp_protected_resource_config_from_args(&args);
    let mcp_token_verifier = mcp_token_verifier_from_args(&args, &mcp_protected_resource)?;
    let mcp_principal = authenticated_mcp_principal(&args)?;
    let native_http_auth = native_http_auth_from_args(&args)?;
    let trust_resolvers = trust_resolvers_from_args(&args)?;
    let callback_policy = callback_policy_from_args(&args, &service_id)?;
    let fleet_services = fleet_services_from_args(
        &args,
        &service_id,
        args.trust_domain.as_deref().unwrap_or("local"),
    )
    .await?;
    let allow_insecure_development =
        args.allow_insecure_development || env_flag("GETAIP_SERVER_INSECURE_DEVELOPMENT");
    let storage_dir = args.storage_dir.clone().or_else(|| {
        env::var("GETAIP_SERVER_STORAGE_DIR")
            .ok()
            .map(PathBuf::from)
    });
    let cal_diy_connector = cal_diy_connector_from_args(&args, storage_dir.as_deref())?;
    let hermes_operator_policy = hermes_operator_policy_from_args(&args)?;
    let hermes_endpoints = parse_hermes_endpoints(
        endpoint_specs(args.hermes_endpoints),
        args.hermes_api_key
            .clone()
            .or_else(|| env::var("AIP_HERMES_API_KEY").ok()),
    )?;
    let support_sandbox_postgres_url = args
        .support_sandbox_postgres_url
        .clone()
        .or_else(|| env::var("AIP_SUPPORT_SANDBOX_DATABASE_URL").ok());
    let enterprise_sandbox_postgres_url = args
        .enterprise_sandbox_postgres_url
        .clone()
        .or_else(|| env::var("AIP_ENTERPRISE_SANDBOX_DATABASE_URL").ok());
    let delegation_routes = parse_delegation_routes(
        route_specs(
            args.delegation_http_routes,
            "GETAIP_SERVER_DELEGATION_HTTP_ROUTES",
        ),
        route_specs(
            args.delegation_nats_routes,
            "GETAIP_SERVER_DELEGATION_NATS_ROUTES",
        ),
        &callback_policy,
        args.trust_domain.as_deref().unwrap_or("local"),
    )
    .await?;
    let trusted_signers = parse_trusted_signers(route_specs(
        args.trusted_signers,
        "GETAIP_SERVER_TRUSTED_SIGNERS",
    ))?;
    let config = AipDaemonConfig {
        bind: args.bind,
        public_base_url: args
            .public_base_url
            .or_else(|| env::var("GETAIP_SERVER_PUBLIC_BASE_URL").ok()),
        service_id,
        trust_domain: args.trust_domain,
        require_signed_envelopes: !env_flag("GETAIP_SERVER_ALLOW_UNSIGNED_ENVELOPES")
            || args.require_signed_envelopes
            || env_flag("GETAIP_SERVER_REQUIRE_SIGNED_ENVELOPES"),
        trusted_signers,
        native_http_auth,
        allow_insecure_development,
        callback_policy,
        storage_dir,
        nats,
        delegation_routes,
        mcp_protected_resource,
        mcp_principal,
    };
    let postgres_url = args
        .postgres_url
        .or_else(|| env::var("GETAIP_SERVER_POSTGRES_URL").ok());
    let mut deployment = AipDaemonDeployment::default().with_trust_resolvers(trust_resolvers);
    if let Some(postgres_url) = postgres_url {
        deployment = deployment.with_postgres_url(postgres_url);
    }
    if let Some(connector) = cal_diy_connector {
        deployment = deployment.with_module_factory(CalDiyModuleFactory::new(connector));
    }
    if !hermes_endpoints.is_empty() {
        deployment = deployment.with_module_factory(HermesModuleFactory::new(
            hermes_endpoints,
            hermes_operator_policy,
        ));
    }
    if let Some(database_url) = support_sandbox_postgres_url {
        deployment = deployment.with_module_factory(SupportSandboxModuleFactory::new(database_url));
    }
    if let Some(database_url) = enterprise_sandbox_postgres_url {
        deployment =
            deployment.with_module_factory(EnterpriseSandboxModuleFactory::new(database_url));
    }
    if let Some(services) = fleet_services {
        deployment = deployment.with_fleet_services(services);
    }
    let daemon = AipDaemon::new_with_deployment(config.clone(), deployment)
        .await
        .map_err(StartupError::gateway)?;
    let daemon = if let Some(verifier) = mcp_token_verifier {
        daemon.with_mcp_token_verifier(verifier)
    } else {
        daemon
    };
    if args.print_manifest {
        let rendered =
            serde_json::to_string_pretty(daemon.manifest()).map_err(|error| StartupError {
                code: "aip.server.render_manifest",
                message: error.to_string(),
            })?;
        println!("{rendered}");
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
            Ok((did.to_owned(), principal_from_id(principal_id)?))
        })
        .collect()
}

fn authenticated_mcp_principal(args: &Args) -> Result<Principal, StartupError> {
    let id = env::var("GETAIP_SERVER_MCP_PRINCIPAL").unwrap_or_else(|_| args.mcp_principal.clone());
    let mut principal = principal_from_id(&id)?;
    let scopes = merged_env_list(
        args.mcp_principal_scopes.clone(),
        "GETAIP_SERVER_MCP_PRINCIPAL_SCOPES",
    );
    principal.auth_context = Some(serde_json::json!({ "scopes": scopes }));
    Ok(principal)
}

fn trust_resolvers_from_args(args: &Args) -> Result<DaemonTrustResolvers, StartupError> {
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
    let content = read_secure_configuration_file(path, "trusted identity")?;
    parse_trusted_identity_bindings(&content)
}

fn parse_trusted_identity_bindings(
    content: &str,
) -> Result<Vec<TrustedIdentityBinding>, StartupError> {
    let entries =
        serde_json::from_str::<Vec<TrustedIdentityDirectoryEntry>>(content).map_err(|error| {
            StartupError {
                code: "aip.server.config",
                message: format!("invalid trusted identity JSON: {error}"),
            }
        })?;
    if entries.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "trusted identity file must contain at least one binding".to_owned(),
        });
    }
    let mut principals = HashSet::new();
    let mut bindings = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.revision == 0 {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity binding for `{}` must have a non-zero revision",
                    entry.principal_id
                ),
            });
        }
        if entry.revoked {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity binding for `{}` is revoked",
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
            tenant.validate().map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!(
                    "invalid trusted tenant binding for `{}`: {error}",
                    entry.principal_id
                ),
            })?;
        }
        if let Some(credential) = &entry.credential {
            credential
                .validate(&BTreeSet::new())
                .map_err(|error| StartupError {
                    code: "aip.server.config",
                    message: format!(
                        "invalid trusted credential binding for `{}`: {error}",
                        entry.principal_id
                    ),
                })?;
        }
        if !principals.insert(entry.principal_id.clone()) {
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
    let content = read_secure_configuration_file(path, "approval authority")?;
    parse_authority_memberships(&content)
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
                "{label} path `{}` must be a regular file and must not be a symbolic link",
                path.display()
            ),
        });
    }
    if metadata.len() > 1024 * 1024 {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!(
                "{label} file `{}` exceeds the 1 MiB configuration bound",
                path.display()
            ),
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

fn parse_authority_memberships(content: &str) -> Result<Vec<AuthorityMembership>, StartupError> {
    let memberships =
        serde_json::from_str::<Vec<AuthorityMembership>>(content).map_err(|error| {
            StartupError {
                code: "aip.server.config",
                message: format!("invalid approval authority JSON: {error}"),
            }
        })?;
    if memberships.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "approval authority file must contain at least one membership".to_owned(),
        });
    }
    let mut principals = HashSet::new();
    for membership in &memberships {
        membership
            .validate_for(&membership.principal_id)
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!(
                    "invalid approval authority membership for `{}`: {error}",
                    membership.principal_id
                ),
            })?;
        if membership.revision == 0 {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "approval authority membership for `{}` must have a non-zero revision",
                    membership.principal_id
                ),
            });
        }
        if !principals.insert(membership.principal_id.clone()) {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "approval authority file contains duplicate principal `{}`",
                    membership.principal_id
                ),
            });
        }
    }
    Ok(memberships)
}

fn native_http_auth_from_args(
    args: &Args,
) -> Result<Option<getaip_server::NativeHttpAuthConfig>, StartupError> {
    let inline_token = args
        .native_bearer_token
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN").ok());
    let token_file = args.native_bearer_token_file.clone().or_else(|| {
        env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE")
            .ok()
            .map(PathBuf::from)
    });
    if inline_token.is_some() && token_file.is_some() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "native bearer token and bearer-token file are mutually exclusive".to_owned(),
        });
    }
    let token = match (inline_token, token_file) {
        (Some(token), None) => Some(token),
        (None, Some(path)) => Some(
            String::from_utf8(read_secret_file(&path, 16 * 1024)?).map_err(|_| StartupError {
                code: "aip.server.config",
                message: "native bearer-token file must contain valid UTF-8".to_owned(),
            })?,
        ),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("conflicting native credentials were rejected"),
    };
    let Some(token) = token else {
        return Ok(None);
    };
    let id = env::var("GETAIP_SERVER_NATIVE_PRINCIPAL")
        .unwrap_or_else(|_| args.native_principal.clone());
    let mut principal = principal_from_id(&id)?;
    let scopes = merged_env_list(
        args.native_principal_scopes.clone(),
        "GETAIP_SERVER_NATIVE_PRINCIPAL_SCOPES",
    );
    principal.auth_context = Some(serde_json::json!({ "scopes": scopes }));
    let tenant_id = args
        .native_tenant_id
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_TENANT_ID").ok())
        .filter(|value| !value.trim().is_empty());
    let auth = getaip_server::NativeHttpAuthConfig::bearer(token, principal);
    Ok(Some(match tenant_id {
        Some(tenant_id) => auth.with_tenant(tenant_id),
        None => auth,
    }))
}

fn callback_policy_from_args(
    args: &Args,
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
    let seed_hex = args
        .callback_signing_seed_hex
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_CALLBACK_SIGNING_SEED_HEX").ok());
    let signer = seed_hex
        .map(|seed_hex| {
            let bytes = hex::decode(seed_hex.trim()).map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("callback signing seed is not valid hex: {error}"),
            })?;
            let seed: [u8; 32] = bytes.try_into().map_err(|_| StartupError {
                code: "aip.server.config",
                message: "callback signing seed must contain exactly 32 bytes".to_owned(),
            })?;
            Ok(CallbackSigner {
                principal: principal_from_id(service_id.as_str())?,
                signing_key: Arc::new(aip_crypto::signing_key_from_seed(seed)),
            })
        })
        .transpose()?;
    if !allowed_hosts.is_empty() && signer.is_none() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "callback allowlist requires GETAIP_SERVER_CALLBACK_SIGNING_SEED_HEX"
                .to_owned(),
        });
    }
    let a2a_credential_key = args
        .a2a_push_encryption_key_hex
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_A2A_PUSH_ENCRYPTION_KEY_HEX").ok())
        .map(|key_hex| {
            let bytes = hex::decode(key_hex.trim()).map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("A2A push encryption key is not valid hex: {error}"),
            })?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| StartupError {
                code: "aip.server.config",
                message: "A2A push encryption key must contain exactly 32 bytes".to_owned(),
            })?;
            Ok(A2aCallbackCredentialKey::new(key))
        })
        .transpose()?;
    if a2a_credential_key.is_some() && signer.is_none() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "A2A push delivery requires GETAIP_SERVER_CALLBACK_SIGNING_SEED_HEX"
                .to_owned(),
        });
    }
    Ok(GatewayCallbackPolicy {
        allowed_hosts,
        allow_http: args.callback_allow_http || env_flag("GETAIP_SERVER_CALLBACK_ALLOW_HTTP"),
        allow_private_networks: args.callback_allow_private_networks
            || env_flag("GETAIP_SERVER_CALLBACK_ALLOW_PRIVATE_NETWORKS"),
        request_timeout_ms: env::var("GETAIP_SERVER_CALLBACK_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5_000),
        max_response_bytes: env::var("GETAIP_SERVER_CALLBACK_MAX_RESPONSE_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(4 * 1024 * 1024),
        tls_ca_certificate_pem: None,
        signer,
        a2a_credential_key,
    })
}

async fn fleet_services_from_args(
    args: &Args,
    service_id: &PrincipalId,
    trust_domain: &str,
) -> Result<Option<DaemonFleetServices>, StartupError> {
    let registry_url = args
        .connector_registry_url
        .clone()
        .or_else(|| env::var("GETAIP_SERVER_CONNECTOR_REGISTRY_URL").ok());
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
    let retry_budget = match args.connector_fleet_retry_budget {
        Some(value) => value,
        None => env_u64("GETAIP_SERVER_CONNECTOR_FLEET_RETRY_BUDGET")?
            .unwrap_or(2)
            .try_into()
            .map_err(|_| StartupError {
                code: "aip.server.config",
                message: "GETAIP_SERVER_CONNECTOR_FLEET_RETRY_BUDGET exceeds u32".to_owned(),
            })?,
    };

    let Some(registry_url) = registry_url else {
        let fleet_option_present = seed_file.is_some()
            || !allowed_hosts.is_empty()
            || trust_registry_endpoints
            || allow_http
            || allow_private_networks
            || args.connector_fleet_timeout_ms.is_some()
            || args.connector_fleet_max_response_bytes.is_some()
            || args.connector_fleet_retry_budget.is_some()
            || args.connector_fleet_max_cached_clients.is_some()
            || env::var_os("GETAIP_SERVER_CONNECTOR_FLEET_TIMEOUT_MS").is_some()
            || env::var_os("GETAIP_SERVER_CONNECTOR_FLEET_MAX_RESPONSE_BYTES").is_some()
            || env::var_os("GETAIP_SERVER_CONNECTOR_FLEET_RETRY_BUDGET").is_some()
            || env::var_os("GETAIP_SERVER_CONNECTOR_FLEET_MAX_CACHED_CLIENTS").is_some();
        if fleet_option_present {
            return Err(StartupError {
                code: "aip.server.config",
                message: "connector fleet options require GETAIP_SERVER_CONNECTOR_REGISTRY_URL or --connector-registry-url"
                    .to_owned(),
            });
        }
        return Ok(None);
    };
    if registry_url.trim().is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "connector registry URL must not be empty".to_owned(),
        });
    }
    let seed_file = seed_file.ok_or_else(|| StartupError {
        code: "aip.server.config",
        message: "connector fleet mode requires GETAIP_SERVER_CONNECTOR_FLEET_SIGNING_SEED_FILE or --connector-fleet-signing-seed-file"
            .to_owned(),
    })?;
    if !trust_registry_endpoints && allowed_hosts.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "connector fleet mode requires an explicit host allowlist or --connector-fleet-trust-registry-endpoints"
                .to_owned(),
        });
    }
    if request_timeout_ms == 0 || max_response_bytes == 0 || max_cached_clients == 0 {
        return Err(StartupError {
            code: "aip.server.config",
            message: "connector fleet timeout, response bound, and client-cache bound must be greater than zero"
                .to_owned(),
        });
    }

    let seed_text =
        String::from_utf8(read_secret_file(&seed_file, 256)?).map_err(|_| StartupError {
            code: "aip.server.config",
            message: "connector fleet signing seed file must contain UTF-8 hexadecimal text"
                .to_owned(),
        })?;
    let seed_bytes = hex::decode(seed_text.trim()).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("connector fleet signing seed is not valid hex: {error}"),
    })?;
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| StartupError {
        code: "aip.server.config",
        message: "connector fleet signing seed must contain exactly 32 bytes".to_owned(),
    })?;
    let signing_key = Arc::new(aip_crypto::signing_key_from_seed(seed));
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
        tls_ca_certificate_pem: None,
        signer: Some(signer.clone()),
        a2a_credential_key: None,
    };
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
    let registry = Arc::new(
        PostgresConnectorRegistry::connect(registry_url.trim())
            .await
            .map_err(|error| StartupError {
                code: "aip.server.connector_registry",
                message: error.to_string(),
            })?,
    );
    let handler = Arc::new(RemoteConnectorHandler::new(
        registry.clone(),
        Arc::new(dispatcher),
        CapabilityImplementationSupport {
            invocation: true,
            cancellation: true,
            streaming: false,
            retry: true,
            transaction: true,
            reconciliation: true,
            compensation: true,
            approval: true,
            credentials: true,
        },
    ));
    Ok(Some(DaemonFleetServices::new(registry, handler)))
}

fn principal_from_id(raw: &str) -> Result<Principal, StartupError> {
    let id = PrincipalId::parse(raw.trim()).map_err(|error| StartupError {
        code: "aip.server.config",
        message: error.to_string(),
    })?;
    let kind = if raw.starts_with("human:") {
        PrincipalKind::Human
    } else if raw.starts_with("service:") {
        PrincipalKind::Service
    } else if raw.starts_with("system:") {
        PrincipalKind::System
    } else if raw.starts_with("tenant:") {
        PrincipalKind::Tenant
    } else {
        PrincipalKind::Agent
    };
    Ok(Principal::new(id, kind))
}

async fn serve_mcp_stdio(daemon: AipDaemon) -> Result<(), StartupError> {
    const SESSION_ID: &str = "stdio";
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
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
                let Some(line) = line.map_err(StartupError::io)? else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
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
                        if let Err(error) = daemon
                            .mcp_server()
                            .handle_notification(SESSION_ID, notification)
                            .await
                        {
                            eprintln!("getaip-server MCP stdio notification error: {error}");
                        }
                    }
                    McpStdioFrame::Response(response) => {
                        daemon
                            .accept_mcp_stdio_response(SESSION_ID, response)
                            .await
                            .map_err(|error| StartupError {
                                code: "aip.server.mcp_stdio",
                                message: error.to_string(),
                            })?;
                    }
                }
            }
            frame = outgoing.recv() => {
                let Some(frame) = frame else {
                    break;
                };
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

fn nats_config_from_args(
    args: &Args,
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
        (Some(username), Some(password_file)) => {
            let password = String::from_utf8(read_secret_file(&password_file, 16 * 1024)?)
                .map_err(|_| StartupError {
                    code: "aip.server.config",
                    message: "NATS password file must contain valid UTF-8".to_owned(),
                })?;
            Some(
                NatsAuthentication::user_password(username, password).map_err(|error| {
                    StartupError {
                        code: "aip.server.config",
                        message: error.to_string(),
                    }
                })?,
            )
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
        request_timeout_ms: env::var("GETAIP_SERVER_NATS_REQUEST_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(args.nats_request_timeout_ms),
    }))
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn endpoint_specs(mut cli_specs: Vec<String>) -> Vec<String> {
    if let Ok(raw) = env::var("AIP_HERMES_ENDPOINTS") {
        cli_specs.extend(
            raw.split([',', ';', '\n'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    cli_specs
}

fn route_specs(mut cli_specs: Vec<String>, env_name: &str) -> Vec<String> {
    if let Ok(raw) = env::var(env_name) {
        cli_specs.extend(
            raw.split([';', '\n'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    cli_specs
}

fn mcp_protected_resource_config_from_args(args: &Args) -> Option<McpProtectedResourceConfig> {
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
    let required_scope = (!required_scopes.is_empty()).then(|| required_scopes.join(" "));
    let mut metadata =
        aip_transport_mcp_streamable_http::ProtectedResourceMetadata::bearer(resource);
    metadata.authorization_servers = authorization_servers;
    metadata.scopes_supported = scopes;
    metadata.resource_documentation = documentation;
    Some(McpProtectedResourceConfig {
        metadata,
        bearer_token,
        realm: Some("aip.server.mcp".to_owned()),
        required_scope,
        metadata_url: Some("/.well-known/oauth-protected-resource".to_owned()),
        allowed_origins,
        allow_loopback_origins: true,
    })
}

fn mcp_token_verifier_from_args(
    args: &Args,
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
    if configured.iter().all(|configured| !configured) {
        return Ok(None);
    }
    if !configured.iter().all(|configured| *configured) {
        return Err(StartupError {
            code: "aip.server.config",
            message: "MCP introspection requires URL, issuer, client id, and client-secret file"
                .to_owned(),
        });
    }
    let (Some(url), Some(issuer), Some(client_id), Some(secret_file)) =
        (url, issuer, client_id, secret_file)
    else {
        return Err(StartupError {
            code: "aip.server.config",
            message: "MCP introspection configuration is incomplete".to_owned(),
        });
    };
    let policy = protected_resource.as_ref().ok_or_else(|| StartupError {
        code: "aip.server.config",
        message: "MCP introspection requires a protected resource identifier".to_owned(),
    })?;
    if policy.bearer_token.is_some() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "static MCP bearer token and OAuth introspection cannot be enabled together"
                .to_owned(),
        });
    }
    if !policy
        .metadata
        .authorization_servers
        .iter()
        .any(|candidate| candidate == &issuer)
    {
        return Err(StartupError {
            code: "aip.server.config",
            message: "MCP introspection issuer must be listed as an authorization server"
                .to_owned(),
        });
    }
    let secret = read_secret_file(&secret_file, 16 * 1024)?;
    let allow_loopback_http = args.mcp_introspection_allow_loopback_http
        || env_flag("GETAIP_SERVER_MCP_INTROSPECTION_ALLOW_LOOPBACK_HTTP");
    let introspector = if allow_loopback_http {
        HttpTokenIntrospector::new_with_loopback_http(url, issuer, client_id, secret)
    } else {
        HttpTokenIntrospector::new(url, issuer, client_id, secret)
    }
    .map_err(|error| StartupError {
        code: "aip.server.config",
        message: error.to_string(),
    })?;
    Ok(Some(IntrospectionTokenVerifier::new(introspector)))
}

fn read_secret_file(path: &std::path::Path, max_bytes: usize) -> Result<Vec<u8>, StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("cannot inspect secret file `{}`: {error}", path.display()),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!(
                "secret path `{}` must be a regular non-symlink file",
                path.display()
            ),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "secret file `{}` must not be accessible by group or other users",
                    path.display()
                ),
            });
        }
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!(
                "secret file `{}` size must be between 1 and {max_bytes} bytes",
                path.display()
            ),
        });
    }
    let mut secret = fs::read(path).map_err(|error| StartupError {
        code: "aip.server.config",
        message: format!("cannot read secret file `{}`: {error}", path.display()),
    })?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!("secret file `{}` contains no secret", path.display()),
        });
    }
    Ok(secret)
}

#[derive(Clone)]
struct FileCredentialProvider {
    paths: Arc<BTreeMap<String, PathBuf>>,
}

impl std::fmt::Debug for FileCredentialProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileCredentialProvider")
            .field("credential_count", &self.paths.len())
            .field("paths", &"[REDACTED]")
            .finish()
    }
}

impl FileCredentialProvider {
    fn from_specs(specs: Vec<String>) -> Result<Self, StartupError> {
        let mut paths = BTreeMap::new();
        for spec in specs {
            let (handle, path) = spec.split_once('=').ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: "Cal.diy credential mappings must be formatted as HANDLE=FILE".to_owned(),
            })?;
            let handle = handle.trim();
            let path = path.trim();
            if handle.is_empty()
                || handle.len() > 128
                || !handle.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
                })
                || path.is_empty()
            {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: "Cal.diy credential handles must be bounded route-safe identifiers and file paths must be non-empty"
                        .to_owned(),
                });
            }
            let path = PathBuf::from(path);
            let validated = CredentialMaterial::new(read_secret_file(&path, 16 * 1024)?);
            drop(validated);
            if paths.insert(handle.to_owned(), path).is_some() {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: format!("duplicate Cal.diy credential handle `{handle}`"),
                });
            }
        }
        if paths.is_empty() {
            return Err(StartupError {
                code: "aip.server.config",
                message: "Cal.diy credential routing requires at least one credential mapping"
                    .to_owned(),
            });
        }
        Ok(Self {
            paths: Arc::new(paths),
        })
    }
}

#[async_trait]
impl CredentialProvider for FileCredentialProvider {
    async fn resolve(&self, handle: &CredentialHandle) -> Result<CredentialMaterial, AuthError> {
        let path = self
            .paths
            .get(handle.id())
            .cloned()
            .ok_or_else(|| AuthError::Credential("opaque handle is unknown".to_owned()))?;
        let secret = tokio::task::spawn_blocking(move || read_secret_file(&path, 16 * 1024))
            .await
            .map_err(|_| AuthError::Credential("credential worker failed".to_owned()))?
            .map_err(|_| AuthError::Credential("credential file is unavailable".to_owned()))?;
        Ok(CredentialMaterial::new(secret))
    }
}

fn parse_cal_diy_tenant_accounts(
    specs: Vec<String>,
) -> Result<Vec<CalDiyTenantAccountBinding>, StartupError> {
    let mut tenants = BTreeSet::new();
    let mut bindings = Vec::with_capacity(specs.len());
    for spec in specs {
        let (tenant_id, account_id) = spec.split_once('=').ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: "Cal.diy tenant bindings must be formatted as TENANT_ID=ACCOUNT_ID".to_owned(),
        })?;
        let tenant_id = tenant_id.trim();
        let account_id = account_id.trim();
        if tenant_id.is_empty() || account_id.is_empty() {
            return Err(StartupError {
                code: "aip.server.config",
                message: "Cal.diy tenant and account ids must be non-empty".to_owned(),
            });
        }
        if !tenants.insert(tenant_id.to_owned()) {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("duplicate Cal.diy tenant binding `{tenant_id}`"),
            });
        }
        bindings.push(CalDiyTenantAccountBinding {
            tenant_id: tenant_id.to_owned(),
            account_id: account_id.to_owned(),
        });
    }
    Ok(bindings)
}

fn cal_diy_connector_from_args(
    args: &Args,
    storage_dir: Option<&std::path::Path>,
) -> Result<Option<CalDiyConnector>, StartupError> {
    let base_url = args
        .cal_diy_base_url
        .clone()
        .or_else(|| env::var("AIP_CAL_DIY_BASE_URL").ok());
    let account_id = args
        .cal_diy_account_id
        .clone()
        .or_else(|| env::var("AIP_CAL_DIY_ACCOUNT_ID").ok());
    let max_response_bytes = match args.cal_diy_max_response_bytes {
        Some(value) => Some(value),
        None => env::var("AIP_CAL_DIY_MAX_RESPONSE_BYTES")
            .ok()
            .map(|value| {
                value.parse::<usize>().map_err(|_| StartupError {
                    code: "aip.server.config",
                    message: "AIP_CAL_DIY_MAX_RESPONSE_BYTES must be a positive integer".to_owned(),
                })
            })
            .transpose()?,
    };
    let bearer_file = args.cal_diy_bearer_token_file.clone().or_else(|| {
        env::var("AIP_CAL_DIY_BEARER_TOKEN_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let oauth_client_id = args
        .cal_diy_oauth_client_id
        .clone()
        .or_else(|| env::var("AIP_CAL_DIY_OAUTH_CLIENT_ID").ok());
    let oauth_secret_file = args.cal_diy_oauth_client_secret_file.clone().or_else(|| {
        env::var("AIP_CAL_DIY_OAUTH_CLIENT_SECRET_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let webhook_specs = route_specs(
        args.cal_diy_webhook_secret_files.clone(),
        "AIP_CAL_DIY_WEBHOOK_SECRET_FILES",
    );
    let explicit_replay_file = args.cal_diy_webhook_replay_file.clone().or_else(|| {
        env::var("AIP_CAL_DIY_WEBHOOK_REPLAY_FILE")
            .ok()
            .map(PathBuf::from)
    });
    let webhook_subscriber_prefixes = route_specs(
        args.cal_diy_webhook_subscriber_prefixes.clone(),
        "AIP_CAL_DIY_WEBHOOK_SUBSCRIBER_PREFIXES",
    );
    let tenant_account_specs = route_specs(
        args.cal_diy_tenant_accounts.clone(),
        "AIP_CAL_DIY_TENANT_ACCOUNTS",
    );
    let credential_file_specs = route_specs(
        args.cal_diy_credential_files.clone(),
        "AIP_CAL_DIY_CREDENTIAL_FILES",
    );
    let configured = base_url.is_some()
        || account_id.is_some()
        || max_response_bytes.is_some()
        || bearer_file.is_some()
        || oauth_client_id.is_some()
        || oauth_secret_file.is_some()
        || !webhook_specs.is_empty()
        || !webhook_subscriber_prefixes.is_empty()
        || !tenant_account_specs.is_empty()
        || !credential_file_specs.is_empty()
        || explicit_replay_file.is_some();
    if !configured {
        return Ok(None);
    }
    if tenant_account_specs.is_empty() != credential_file_specs.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message:
                "Cal.diy tenant routing requires both tenant-account and credential-file mappings"
                    .to_owned(),
        });
    }
    let base_url = base_url
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: "Cal.diy connector requires --cal-diy-base-url".to_owned(),
        })?;
    let account_id = account_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: "Cal.diy connector requires --cal-diy-account-id".to_owned(),
        })?;
    if bearer_file.is_some() && (oauth_client_id.is_some() || oauth_secret_file.is_some()) {
        return Err(StartupError {
            code: "aip.server.config",
            message: "Cal.diy bearer and OAuth client credentials are mutually exclusive"
                .to_owned(),
        });
    }
    let auth = match (bearer_file, oauth_client_id, oauth_secret_file) {
        (Some(path), None, None) => {
            CalDiyAuth::Bearer(ConnectorSecret::new(read_secret_file(&path, 16 * 1024)?))
        }
        (None, Some(client_id), Some(path)) if !client_id.trim().is_empty() => {
            CalDiyAuth::OAuthClientCredentials {
                client_id,
                client_secret: ConnectorSecret::new(read_secret_file(&path, 16 * 1024)?),
            }
        }
        _ => {
            return Err(StartupError {
                code: "aip.server.config",
                message: "Cal.diy connector requires either a bearer-token file or both OAuth client id and client-secret file"
                    .to_owned(),
            });
        }
    };
    let mut connector =
        CalDiyConnector::with_auth(base_url, account_id, auth).map_err(|error| StartupError {
            code: "aip.server.config",
            message: error.to_string(),
        })?;
    if let Some(max_response_bytes) = max_response_bytes {
        connector = connector
            .with_max_response_bytes(max_response_bytes)
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: error.to_string(),
            })?;
    }
    if !tenant_account_specs.is_empty() {
        let identity_file = args.trusted_identity_file.clone().or_else(|| {
            env::var("GETAIP_SERVER_TRUSTED_IDENTITY_FILE")
                .ok()
                .map(PathBuf::from)
        });
        let identity_file = identity_file.ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: "Cal.diy tenant routing requires a trusted identity directory".to_owned(),
        })?;
        let bindings = parse_cal_diy_tenant_accounts(tenant_account_specs)?;
        let provider = FileCredentialProvider::from_specs(credential_file_specs)?;
        validate_cal_diy_identity_routes(
            &load_trusted_identity_bindings(&identity_file)?,
            &bindings,
            &provider,
        )?;
        connector = connector
            .with_tenant_credential_routing(bindings, Arc::new(provider))
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: error.to_string(),
            })?;
    }
    if !webhook_subscriber_prefixes.is_empty() {
        let policy = CalDiyWebhookDestinationPolicy::from_prefixes(webhook_subscriber_prefixes)
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: error.to_string(),
            })?;
        connector = connector.with_webhook_destination_policy(policy);
    }
    if explicit_replay_file.is_some() && webhook_specs.is_empty() {
        return Err(StartupError {
            code: "aip.server.config",
            message: "Cal.diy webhook replay storage requires at least one webhook secret mapping"
                .to_owned(),
        });
    }
    if !webhook_specs.is_empty() {
        let mut webhook_secrets = Vec::with_capacity(webhook_specs.len());
        for spec in webhook_specs {
            let (secret_ref, path) = spec.split_once('=').ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!(
                    "Cal.diy webhook secret mapping `{spec}` must be formatted as REF=FILE"
                ),
            })?;
            if secret_ref.trim().is_empty() || path.trim().is_empty() {
                return Err(StartupError {
                    code: "aip.server.config",
                    message: "Cal.diy webhook secret references and file paths must be non-empty"
                        .to_owned(),
                });
            }
            webhook_secrets.push((
                secret_ref.trim().to_owned(),
                ConnectorSecret::new(read_secret_file(
                    std::path::Path::new(path.trim()),
                    16 * 1024,
                )?),
            ));
        }
        let secrets =
            StaticCalDiyWebhookSecrets::new(webhook_secrets).map_err(|message| StartupError {
                code: "aip.server.config",
                message,
            })?;
        let replay_file = explicit_replay_file
            .or_else(|| storage_dir.map(|directory| directory.join("cal-diy-webhook-replay.json")));
        let replay: Arc<dyn CalDiyWebhookReplayStore> = match replay_file {
            Some(path) => Arc::new(FileCalDiyWebhookReplayStore::new(path)),
            None => Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
        };
        connector = connector.with_webhook_security(Arc::new(secrets), replay);
    }
    Ok(Some(connector))
}

fn validate_cal_diy_identity_routes(
    identities: &[TrustedIdentityBinding],
    bindings: &[CalDiyTenantAccountBinding],
    provider: &FileCredentialProvider,
) -> Result<(), StartupError> {
    let routed_accounts = bindings
        .iter()
        .map(|binding| (binding.tenant_id.as_str(), binding.account_id.as_str()))
        .collect::<BTreeMap<_, _>>();
    let routed_tenants = routed_accounts.keys().copied().collect::<BTreeSet<_>>();
    let mut covered_tenants = BTreeSet::new();
    for identity in identities {
        let Some(tenant) = &identity.tenant else {
            continue;
        };
        if !routed_tenants.contains(tenant.tenant.id.as_str()) {
            continue;
        }
        let credential = identity.credential.as_ref().ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: format!(
                "trusted identity `{}` has a routed Cal.diy tenant but no credential handle",
                identity.principal_id
            ),
        })?;
        if credential.issuer() != "cal_diy_deployment"
            || credential.tenant_id() != Some(tenant.tenant.id.as_str())
            || !provider.paths.contains_key(credential.id())
        {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity `{}` has an invalid Cal.diy credential binding",
                    identity.principal_id
                ),
            });
        }
        let expected_account = routed_accounts[tenant.tenant.id.as_str()];
        if !identity
            .identity
            .as_ref()
            .and_then(|context| context.external_account.as_ref())
            .is_some_and(|account| account.system == "cal_diy" && account.id == expected_account)
        {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!(
                    "trusted identity `{}` must bind the routed Cal.diy external account",
                    identity.principal_id
                ),
            });
        }
        covered_tenants.insert(tenant.tenant.id.as_str());
    }
    if let Some(missing) = routed_tenants.difference(&covered_tenants).next() {
        return Err(StartupError {
            code: "aip.server.config",
            message: format!(
                "Cal.diy tenant `{missing}` has no trusted identity and credential binding"
            ),
        });
    }
    Ok(())
}

fn merged_env_list(mut cli_values: Vec<String>, env_name: &str) -> Vec<String> {
    if let Ok(raw) = env::var(env_name) {
        cli_values.extend(
            raw.split([',', ';', '\n'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    cli_values
}

fn parse_hermes_endpoints(
    specs: Vec<String>,
    api_key: Option<String>,
) -> Result<Vec<HermesAgentEndpoint>, StartupError> {
    specs
        .into_iter()
        .map(|spec| {
            let (id, url) = spec.split_once('=').ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("Hermes endpoint `{spec}` must be formatted as ID=URL"),
            })?;
            HermesAgentEndpoint::new(id, url, api_key.clone()).map_err(|error| StartupError {
                code: "aip.server.config",
                message: error.to_string(),
            })
        })
        .collect()
}

fn hermes_operator_policy_from_args(args: &Args) -> Result<HermesOperatorPolicy, StartupError> {
    let mut policy = HermesOperatorPolicy {
        delegation_enabled: args.hermes_operator_delegation_enabled
            || env_flag("AIP_HERMES_OPERATOR_DELEGATION_ENABLED"),
        model: args
            .hermes_operator_model
            .clone()
            .or_else(|| env::var("AIP_HERMES_OPERATOR_MODEL").ok()),
        ..HermesOperatorPolicy::default()
    };

    let instructions_file = args.hermes_operator_instructions_file.clone().or_else(|| {
        env::var("AIP_HERMES_OPERATOR_INSTRUCTIONS_FILE")
            .ok()
            .map(PathBuf::from)
    });
    if let Some(path) = instructions_file {
        policy.system_instructions = fs::read_to_string(&path).map_err(|error| StartupError {
            code: "aip.server.config",
            message: format!(
                "failed to read Hermes operator instructions from `{}`: {error}",
                path.display()
            ),
        })?;
    } else if let Ok(instructions) = env::var("AIP_HERMES_OPERATOR_INSTRUCTIONS") {
        policy.system_instructions = instructions;
    }

    policy.timeout_ms = args
        .hermes_operator_timeout_ms
        .or(env_u64("AIP_HERMES_OPERATOR_TIMEOUT_MS")?)
        .unwrap_or(policy.timeout_ms);
    policy.poll_interval_ms = args
        .hermes_operator_poll_ms
        .or(env_u64("AIP_HERMES_OPERATOR_POLL_MS")?)
        .unwrap_or(policy.poll_interval_ms);
    policy.max_events = args
        .hermes_operator_max_events
        .or(env_usize("AIP_HERMES_OPERATOR_MAX_EVENTS")?)
        .unwrap_or(policy.max_events);
    policy.max_input_bytes = args
        .hermes_operator_max_input_bytes
        .or(env_usize("AIP_HERMES_OPERATOR_MAX_INPUT_BYTES")?)
        .unwrap_or(policy.max_input_bytes);
    policy.max_delegation_depth = args
        .hermes_operator_max_delegation_depth
        .or(env_usize("AIP_HERMES_OPERATOR_MAX_DELEGATION_DEPTH")?)
        .unwrap_or(policy.max_delegation_depth);
    policy.start_claim_ttl_ms = args
        .hermes_operator_claim_ttl_ms
        .or(env_u64("AIP_HERMES_OPERATOR_CLAIM_TTL_MS")?)
        .unwrap_or(policy.start_claim_ttl_ms);
    policy.cancel_grace_ms = args
        .hermes_operator_cancel_grace_ms
        .or(env_u64("AIP_HERMES_OPERATOR_CANCEL_GRACE_MS")?)
        .unwrap_or(policy.cancel_grace_ms);
    policy.allowed_capability_prefixes = merged_env_list(
        args.hermes_operator_capability_prefixes.clone(),
        "AIP_HERMES_OPERATOR_CAPABILITY_PREFIXES",
    );
    policy.delegation_approval_exempt_capability_prefixes = merged_env_list(
        args.hermes_operator_approval_exempt_capability_prefixes
            .clone(),
        "AIP_HERMES_OPERATOR_APPROVAL_EXEMPT_CAPABILITY_PREFIXES",
    );
    policy.allowed_scope_prefixes = merged_env_list(
        args.hermes_operator_scope_prefixes.clone(),
        "AIP_HERMES_OPERATOR_SCOPE_PREFIXES",
    );
    policy.validate().map_err(|error| StartupError {
        code: "aip.server.config",
        message: error.to_string(),
    })?;
    Ok(policy)
}

fn env_u64(name: &'static str) -> Result<Option<u64>, StartupError> {
    env::var(name)
        .ok()
        .map(|value| {
            value.parse::<u64>().map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("{name} must be an unsigned integer: {error}"),
            })
        })
        .transpose()
}

fn env_usize(name: &'static str) -> Result<Option<usize>, StartupError> {
    env::var(name)
        .ok()
        .map(|value| {
            value.parse::<usize>().map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("{name} must be an unsigned integer: {error}"),
            })
        })
        .transpose()
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
    let request_signer = endpoint_policy.signer.clone().ok_or_else(|| StartupError {
        code: "aip.server.config",
        message: "delegation routes require GETAIP_SERVER_CALLBACK_SIGNING_SEED_HEX".to_owned(),
    })?;
    let mut routes = Vec::with_capacity(http_specs.len() + nats_specs.len());
    for spec in http_specs {
        let (delegate_id, binding) = spec.split_once('=').ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: format!(
                "HTTP delegation route `{spec}` must be formatted as DELEGATE_ID=URL,PEER_ID,PEER_DID[,TRUST_DOMAIN]"
            ),
        })?;
        let mut parts = binding.split(',').map(str::trim);
        let endpoint = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("HTTP delegation route `{spec}` is missing URL"),
            })?;
        let expected_peer = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("HTTP delegation route `{spec}` is missing PEER_ID"),
            })?;
        let expected_peer_did =
            parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| StartupError {
                    code: "aip.server.config",
                    message: format!("HTTP delegation route `{spec}` is missing PEER_DID"),
                })?;
        let trust_domain = parts
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or(default_trust_domain);
        if parts.next().is_some() {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("HTTP delegation route `{spec}` has too many comma fields"),
            });
        }
        let delegate = principal_from_id(delegate_id.trim())?;
        let security = DelegationPeerSecurity::new(
            trust_domain,
            request_signer.clone(),
            principal_from_id(expected_peer)?,
            expected_peer_did,
            endpoint_policy.clone(),
        )
        .map_err(|error| StartupError {
            code: "aip.server.config",
            message: error.to_string(),
        })?;
        security
            .endpoint_policy
            .validate_destination(endpoint)
            .await
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("HTTP delegation route `{spec}` is unsafe: {error}"),
            })?;
        routes.push(DelegationRoute::native_http_for_delegate(
            delegate.id,
            endpoint.to_owned(),
            security,
        ));
    }
    for spec in nats_specs {
        let (capability_id, binding) = spec.split_once('=').ok_or_else(|| StartupError {
            code: "aip.server.config",
            message: format!(
                "NATS delegation route `{spec}` must be formatted as CAPABILITY_ID=SERVER_URL,SUBJECT,PEER_ID,PEER_DID[,TIMEOUT_MS[,TRUST_DOMAIN]]"
            ),
        })?;
        let mut parts = binding.split(',').map(str::trim);
        let server_url = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` is missing SERVER_URL"),
            })?;
        let subject = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` is missing SUBJECT"),
            })?;
        let expected_peer = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` is missing PEER_ID"),
            })?;
        let expected_peer_did =
            parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| StartupError {
                    code: "aip.server.config",
                    message: format!("NATS delegation route `{spec}` is missing PEER_DID"),
                })?;
        let timeout_ms = parts
            .next()
            .map(|value| {
                value.parse::<u64>().map_err(|error| StartupError {
                    code: "aip.server.config",
                    message: format!(
                        "NATS delegation route `{spec}` has invalid TIMEOUT_MS `{value}`: {error}"
                    ),
                })
            })
            .transpose()?
            .unwrap_or(30_000);
        let trust_domain = parts
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or(default_trust_domain);
        if parts.next().is_some() {
            return Err(StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` has too many comma fields"),
            });
        }
        let capability_id =
            CapabilityId::parse(capability_id.trim()).map_err(|error| StartupError {
                code: "aip.server.config",
                message: error.to_string(),
            })?;
        let security = DelegationPeerSecurity::new(
            trust_domain,
            request_signer.clone(),
            principal_from_id(expected_peer)?,
            expected_peer_did,
            endpoint_policy.clone(),
        )
        .map_err(|error| StartupError {
            code: "aip.server.config",
            message: error.to_string(),
        })?;
        security
            .endpoint_policy
            .validate_destination(server_url)
            .await
            .map_err(|error| StartupError {
                code: "aip.server.config",
                message: format!("NATS delegation route `{spec}` is unsafe: {error}"),
            })?;
        routes.push(DelegationRoute {
            delegate_id: None,
            capability_id: Some(capability_id),
            binding: DelegationRouteBinding::NativeNats {
                server_url: server_url.to_owned(),
                subject: subject.to_owned(),
                timeout_ms,
                security,
            },
        });
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::{
        Args, cal_diy_connector_from_args, fleet_services_from_args,
        mcp_protected_resource_config_from_args, native_http_auth_from_args, nats_config_from_args,
        parse_authority_memberships, parse_trusted_identity_bindings,
    };
    use aip_core::PrincipalId;
    use clap::Parser;
    use serde_json::{Value, json};

    fn membership(principal_id: &str, revision: u64, revoked: bool) -> Value {
        json!({
            "principal_id": principal_id,
            "tenant_id": null,
            "roles": ["operator_approver"],
            "groups": [],
            "tenant_policies": ["local.test.operator_approval"],
            "external_systems": [],
            "delegated_scopes": [],
            "revision": revision,
            "expires_at": null,
            "revoked": revoked
        })
    }

    fn identity(principal_id: &str, revision: u64, revoked: bool) -> Value {
        json!({
            "principal_id": principal_id,
            "revision": revision,
            "revoked": revoked,
            "expires_at": null
        })
    }

    #[tokio::test]
    async fn connector_fleet_cli_builds_a_signed_postgres_composition() {
        let Some(database_url) = std::env::var("AIP_POSTGRES_TEST_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            eprintln!(
                "AIP_POSTGRES_TEST_URL is not set; skipping live getaip-server fleet wiring test"
            );
            return;
        };
        let path = std::env::temp_dir().join(format!(
            "getaip-server-fleet-signing-seed-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::write(&path, "07".repeat(32)).expect("fleet seed fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only fleet seed fixture");
        }
        let args = Args::try_parse_from([
            "getaip-server",
            "--connector-registry-url",
            database_url.as_str(),
            "--connector-fleet-signing-seed-file",
            path.to_str().expect("UTF-8 fleet seed path"),
            "--connector-fleet-allowed-host",
            "connector.test",
            "--connector-fleet-max-cached-clients",
            "32",
        ])
        .expect("fleet arguments");
        let service_id = PrincipalId::trusted("service:test-fleet-getaip-server");
        let services = fleet_services_from_args(&args, &service_id, "test.example")
            .await
            .expect("fleet composition");
        assert!(services.is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn identity_directory_accepts_unique_active_bindings() {
        let content = json!([
            identity("service:booking-coordinator", 1, false),
            identity("agent:booking-supervisor", 9, false)
        ])
        .to_string();

        let parsed = parse_trusted_identity_bindings(&content).unwrap_or_default();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].revision, 9);
    }

    #[test]
    fn identity_directory_rejects_invalid_or_duplicate_bindings() {
        assert_identity_error(
            parse_trusted_identity_bindings("[]"),
            "at least one binding",
        );
        let duplicate = json!([
            identity("service:booking", 1, false),
            identity("service:booking", 2, false)
        ])
        .to_string();
        assert_identity_error(
            parse_trusted_identity_bindings(&duplicate),
            "duplicate principal",
        );
        let zero_revision = json!([identity("service:booking", 0, false)]).to_string();
        assert_identity_error(
            parse_trusted_identity_bindings(&zero_revision),
            "non-zero revision",
        );
        let revoked = json!([identity("service:booking", 1, true)]).to_string();
        assert_identity_error(parse_trusted_identity_bindings(&revoked), "revoked");
        let expired = json!([{
            "principal_id": "service:booking",
            "revision": 1,
            "revoked": false,
            "expires_at": "2000-01-01T00:00:00Z"
        }])
        .to_string();
        assert_identity_error(parse_trusted_identity_bindings(&expired), "expired");
    }

    #[test]
    fn authority_directory_accepts_unique_active_memberships() {
        let content = json!([
            membership("human:approver-one", 1, false),
            membership("human:approver-two", 7, false)
        ])
        .to_string();

        let parsed = parse_authority_memberships(&content).unwrap_or_default();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].revision, 7);
    }

    #[test]
    fn authority_directory_rejects_empty_and_duplicate_memberships() {
        assert_authority_error(parse_authority_memberships("[]"), "at least one membership");

        let duplicate = json!([
            membership("human:approver", 1, false),
            membership("human:approver", 2, false)
        ])
        .to_string();
        assert_authority_error(
            parse_authority_memberships(&duplicate),
            "duplicate principal",
        );
    }

    #[test]
    fn authority_directory_rejects_revoked_and_zero_revision_memberships() {
        let revoked = json!([membership("human:revoked", 1, true)]).to_string();
        assert_authority_error(parse_authority_memberships(&revoked), "revoked");

        let zero_revision = json!([membership("human:stale", 0, false)]).to_string();
        assert_authority_error(
            parse_authority_memberships(&zero_revision),
            "non-zero revision",
        );
    }

    #[test]
    fn mcp_supported_scopes_are_distinct_from_transport_required_scopes() {
        let args = Args::try_parse_from([
            "getaip-server",
            "--mcp-resource",
            "https://aip.example.test/mcp",
            "--mcp-scope",
            "mcp:connect",
            "--mcp-scope",
            "delegation:create",
            "--mcp-required-scope",
            "mcp:connect",
        ])
        .expect("arguments");

        let policy = mcp_protected_resource_config_from_args(&args).expect("MCP policy");

        assert_eq!(policy.required_scope.as_deref(), Some("mcp:connect"));
        assert_eq!(
            policy.metadata.scopes_supported,
            vec!["mcp:connect".to_owned(), "delegation:create".to_owned()]
        );
    }

    #[test]
    fn native_http_auth_reads_owner_only_token_file_and_rejects_conflicts() {
        let path = std::env::temp_dir().join(format!(
            "getaip-server-native-token-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::write(&path, b"native-file-secret\n").expect("native token fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only native token fixture");
        }
        let args = Args::try_parse_from([
            "getaip-server",
            "--native-bearer-token-file",
            path.to_str().expect("UTF-8 native token path"),
            "--native-principal",
            "service:cal-qualified-client",
            "--native-principal-scope",
            "action:write",
        ])
        .expect("native file arguments");
        let auth = native_http_auth_from_args(&args)
            .expect("native file authentication")
            .expect("configured native authentication");
        let diagnostics = format!("{auth:?}");
        assert!(!diagnostics.contains("native-file-secret"));

        let conflicting = Args::try_parse_from([
            "getaip-server",
            "--native-bearer-token",
            "inline-secret",
            "--native-bearer-token-file",
            path.to_str().expect("UTF-8 native token path"),
        ])
        .expect("conflicting arguments");
        let error = native_http_auth_from_args(&conflicting)
            .expect_err("conflicting native credentials must fail closed");
        assert!(error.message.contains("mutually exclusive"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cal_diy_cli_rejects_partial_or_conflicting_authentication() {
        let partial = Args::try_parse_from([
            "getaip-server",
            "--cal-diy-base-url",
            "http://127.0.0.1:5555/api",
            "--cal-diy-account-id",
            "primary",
        ])
        .expect("arguments");
        let message = cal_diy_connector_from_args(&partial, None)
            .err()
            .map(|error| error.message)
            .unwrap_or_default();
        assert!(message.contains("requires either a bearer-token file"));

        let conflicting = Args::try_parse_from([
            "getaip-server",
            "--cal-diy-base-url",
            "http://127.0.0.1:5555/api",
            "--cal-diy-account-id",
            "primary",
            "--cal-diy-bearer-token-file",
            "/not/read/before/conflict",
            "--cal-diy-oauth-client-id",
            "client-id",
            "--cal-diy-oauth-client-secret-file",
            "/not/read/before/conflict",
        ])
        .expect("arguments");
        let message = cal_diy_connector_from_args(&conflicting, None)
            .err()
            .map(|error| error.message)
            .unwrap_or_default();
        assert!(message.contains("mutually exclusive"));
    }

    #[test]
    fn cal_diy_cli_reads_owner_only_secret_file_without_debug_disclosure() {
        let path = std::env::temp_dir().join(format!(
            "getaip-server-cal-diy-secret-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::write(&path, b"cal-diy-cli-secret\n").expect("secret fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secret permissions");
        }
        let args = Args::try_parse_from([
            "getaip-server",
            "--cal-diy-base-url",
            "http://127.0.0.1:5555/api",
            "--cal-diy-account-id",
            "primary",
            "--cal-diy-bearer-token-file",
            path.to_str().expect("UTF-8 path"),
            "--cal-diy-max-response-bytes",
            "4096",
            "--cal-diy-webhook-subscriber-prefix",
            "https://aip.example.test/connectors/cal-diy/webhooks/",
        ])
        .expect("arguments");
        let connector = cal_diy_connector_from_args(&args, None)
            .expect("valid connector configuration")
            .expect("configured connector");
        let debug = format!("{connector:?}");
        assert!(!debug.contains("cal-diy-cli-secret"));
        assert!(debug.contains("configured_prefix_count: 1"));
        assert_eq!(
            connector
                .discover_manifest()
                .expect("connector manifest")
                .limits
                .as_ref()
                .and_then(|limits| limits.get("provider_max_response_bytes"))
                .and_then(Value::as_u64),
            Some(4096)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cal_diy_cli_builds_fail_closed_tenant_credential_routing() {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let bootstrap = std::env::temp_dir().join(format!("getaip-server-cal-bootstrap-{suffix}"));
        let tenant_secret = std::env::temp_dir().join(format!("getaip-server-cal-tenant-{suffix}"));
        let identities =
            std::env::temp_dir().join(format!("getaip-server-cal-identities-{suffix}.json"));
        std::fs::write(&bootstrap, b"bootstrap-secret\n").expect("bootstrap secret");
        std::fs::write(&tenant_secret, b"tenant-secret\n").expect("tenant secret");
        std::fs::write(
            &identities,
            serde_json::to_vec(&json!([{
                "principal_id": "service:cal-qualified-client",
                "tenant": {
                    "tenant": { "id": "tenant-qualified", "system": "test" },
                    "membership_id": "membership-qualified",
                    "roles": ["scheduler"],
                    "groups": [],
                    "verified_at": time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .expect("RFC3339 identity timestamp"),
                    "expires_at": null
                },
                "credential": {
                    "id": "credential:tenant-qualified",
                    "issuer": "cal_diy_deployment",
                    "scopes": ["*"],
                    "tenant_id": "tenant-qualified",
                    "expires_at": null
                },
                "identity": {
                    "tenant": { "id": "tenant-qualified", "system": "test" },
                    "external_account": { "id": "cal-account-qualified", "system": "cal_diy" },
                    "external_user": null,
                    "human_actor": null,
                    "service_account": null,
                    "acted_on_behalf_of": null,
                    "credential_ref": null,
                    "oauth": null
                },
                "revision": 1,
                "revoked": false,
                "expires_at": null
            }]))
            .expect("identity JSON"),
        )
        .expect("identity directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&bootstrap, &tenant_secret, &identities] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .expect("owner-only fixture");
            }
        }
        let tenant_account = "tenant-qualified=cal-account-qualified";
        let credential_file = format!(
            "credential:tenant-qualified={}",
            tenant_secret.to_str().expect("UTF-8 secret path")
        );
        let args = Args::try_parse_from([
            "getaip-server",
            "--cal-diy-base-url",
            "http://127.0.0.1:5555/api",
            "--cal-diy-account-id",
            "bootstrap",
            "--cal-diy-bearer-token-file",
            bootstrap.to_str().expect("UTF-8 bootstrap path"),
            "--trusted-identity-file",
            identities.to_str().expect("UTF-8 identity path"),
            "--cal-diy-tenant-account",
            tenant_account,
            "--cal-diy-credential-file",
            &credential_file,
        ])
        .expect("arguments");
        let connector = cal_diy_connector_from_args(&args, None)
            .expect("tenant-routed connector")
            .expect("configured connector");
        let manifest = connector.discover_manifest().expect("manifest");
        assert!(manifest.capabilities.iter().all(|capability| {
            capability
                .contract
                .as_ref()
                .and_then(|contract| contract.credentials.as_ref())
                .is_some_and(|policy| policy.required)
        }));
        let diagnostics = format!("{connector:?}");
        assert!(diagnostics.contains("tenant_count: 1"));
        assert!(!diagnostics.contains("tenant-secret"));
        assert!(!diagnostics.contains(tenant_secret.to_string_lossy().as_ref()));
        for path in [bootstrap, tenant_secret, identities] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn cal_diy_cli_rejects_partial_tenant_routing() {
        let args = Args::try_parse_from([
            "getaip-server",
            "--cal-diy-base-url",
            "http://127.0.0.1:5555/api",
            "--cal-diy-account-id",
            "bootstrap",
            "--cal-diy-bearer-token-file",
            "/not/read/before-routing-validation",
            "--cal-diy-tenant-account",
            "tenant-a=account-a",
        ])
        .expect("arguments");
        let message = cal_diy_connector_from_args(&args, None)
            .expect_err("partial tenant routing must fail")
            .message;
        assert!(message.contains("requires both tenant-account and credential-file"));
    }

    #[test]
    fn nats_cli_reads_owner_only_password_file_without_debug_disclosure() {
        let path = std::env::temp_dir().join(format!(
            "getaip-server-nats-secret-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::write(&path, b"nats-cli-secret\n").expect("secret fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secret permissions");
        }
        let args = Args::try_parse_from([
            "getaip-server",
            "--nats-url",
            "nats://127.0.0.1:4222",
            "--nats-username",
            "getaip-server",
            "--nats-password-file",
            path.to_str().expect("UTF-8 path"),
        ])
        .expect("arguments");
        let config = nats_config_from_args(&args, "local.test".to_owned())
            .expect("valid NATS configuration")
            .expect("configured NATS listener");

        assert!(config.authentication.is_some());
        assert!(!format!("{config:?}").contains("nats-cli-secret"));
        let _ = std::fs::remove_file(path);
    }

    fn assert_authority_error(
        result: Result<Vec<aip_auth::AuthorityMembership>, getaip_server::StartupError>,
        expected: &str,
    ) {
        let message = result.err().map(|error| error.message).unwrap_or_default();
        assert!(
            message.contains(expected),
            "expected authority error containing `{expected}`, got `{message}`"
        );
    }

    fn assert_identity_error(
        result: Result<Vec<aip_auth::TrustedIdentityBinding>, getaip_server::StartupError>,
        expected: &str,
    ) {
        let message = result.err().map(|error| error.message).unwrap_or_default();
        assert!(
            message.contains(expected),
            "expected identity error containing `{expected}`, got `{message}`"
        );
    }
}
