//! `getaip` command-line interface.
//!
//! The CLI intentionally speaks native AIP envelopes over HTTP. It is useful
//! for validating deployments without product-specific scripts or curl payloads.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod adapters;
mod product;
mod service;

use aip_conformance::CoreConformance;
use aip_connector_admission::{
    AdmissionJournal, AdmissionPackage, AdmissionTrustPolicy, EVIDENCE_STATEMENT_SCHEMA,
    EvidenceKind, EvidenceStatement, SignedAdmissionPackage, abandon_failed_package,
    apply_verified_package, revoke_applied_package, sign_admission_package, sign_evidence,
    verify_admission_package,
};
use aip_connector_orchestration::{
    DeploymentIntent, ObservedReplica, OrchestrationPlan, OrchestrationTrustPolicy,
    SignedOrchestrationPlan, orchestration_operation_ids, reconcile_verified_package,
    sign_orchestration_plan, verify_signed_orchestration_plan,
    verify_signed_orchestration_plan_against_observed,
};
use aip_connector_registry::{
    CapabilityBinding, ConnectorInstanceId, ConnectorRegistryAdmin, digest_json,
};
use aip_connector_registry_postgres::{
    CONNECTOR_REGISTRY_SCHEMA_VERSION, PostgresConnectorRegistry, RegistryPoolLimits,
};
use aip_core::{
    Action, ActionId, ActionMode, ActionTransaction, ApprovalDecision, ApprovalRequest,
    CapabilityId, Envelope, EventStreamRequest, IdentityContext, Manifest, ManifestRequest,
    MessageBody, MessageReference, MessageType, Principal, PrincipalId, PrincipalKind,
    ReceiptChain, TransactionId, TransactionMode,
};
use aip_crypto::{
    did_key_from_verifying_key, hash_receipt, hash_receipt_chain, sign_envelope,
    signing_key_from_seed, verify_envelope, verifying_key_from_did_key,
};
use aip_mcp_client::{
    McpClient, McpClientConfig, McpClientTransport, McpHttpClientTransport, McpStdioClientTransport,
};
use aip_schema::{SchemaName, SchemaRegistry};
use aip_transport::{RequestReplyTransport, TransportMessage};
use aip_transport_mcp_stdio::{McpStdioFrame, decode_frame, encode_frame};
use aip_transport_mcp_streamable_http::{McpHttpMessage, decode_json_rpc_value};
use aip_transport_nats::{NatsAuthentication, NatsSubject, NatsTransport, NatsTransportConfig};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;
use getaip_distribution::BuildVersion;
use reqwest::Url;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, OnceLock},
};
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroize;

/// AIP CLI.
#[derive(Debug, Parser)]
#[command(name = "getaip", version, about = "AIP developer and operator CLI")]
struct Cli {
    /// Bearer token used for native AIP HTTP endpoints.
    #[arg(
        long,
        global = true,
        value_name = "TOKEN",
        conflicts_with = "native_bearer_token_file"
    )]
    native_bearer_token: Option<String>,
    /// Owner-only file containing the native AIP HTTP bearer token.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        conflicts_with = "native_bearer_token"
    )]
    native_bearer_token_file: Option<PathBuf>,
    /// Owner-only file containing a hex-encoded native HTTP signing seed.
    #[arg(long, global = true, value_name = "PATH")]
    native_signing_seed_file: Option<PathBuf>,
    /// Principal carried by signed native HTTP envelopes.
    #[arg(
        long,
        global = true,
        value_name = "PRINCIPAL_ID",
        default_value = "agent:getaip:cli"
    )]
    native_principal_id: String,
    /// Trust domain carried by signed native HTTP envelopes.
    #[arg(long, global = true, value_name = "TRUST_DOMAIN")]
    native_trust_domain: Option<String>,
    /// PEM root certificate used to verify native private-PKI endpoints.
    #[arg(long, global = true, value_name = "PATH")]
    native_tls_ca_file: Option<PathBuf>,
    /// Pinned Ed25519 DID expected on native AIP response envelopes.
    #[arg(
        long,
        global = true,
        value_name = "DID",
        conflicts_with = "native_peer_did_file"
    )]
    native_peer_did: Option<String>,
    /// File containing the pinned Ed25519 DID expected on native responses.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        conflicts_with = "native_peer_did"
    )]
    native_peer_did_file: Option<PathBuf>,
    /// Hard limit for every native HTTP response body.
    #[arg(long, global = true, value_name = "BYTES", default_value_t = 4 * 1024 * 1024)]
    native_max_response_bytes: usize,
    /// Username used to authenticate native NATS connections.
    #[arg(long, global = true, value_name = "USERNAME")]
    nats_username: Option<String>,
    /// Owner-only file containing the native NATS password.
    #[arg(long, global = true, value_name = "PATH")]
    nats_password_file: Option<PathBuf>,
    /// Owner-only file containing a hex-encoded 32-byte Ed25519 signing seed.
    #[arg(long, global = true, value_name = "PATH")]
    nats_signing_seed_file: Option<PathBuf>,
    /// Command to execute.
    #[command(subcommand)]
    command: Command,
}

static NATIVE_BEARER_TOKEN: OnceLock<Option<String>> = OnceLock::new();
static NATIVE_HTTP_SECURITY: OnceLock<NativeHttpSecurity> = OnceLock::new();
static NATS_CLIENT_SECURITY: OnceLock<NatsClientSecurity> = OnceLock::new();
const CAPABILITY_CATALOG_QUERY_ID: &str = "cap:aip:server:connector-capabilities-query";

#[derive(Clone, Debug)]
struct NativeHttpSecurity {
    signing_seed_file: Option<PathBuf>,
    principal_id: String,
    trust_domain: Option<String>,
    tls_ca_file: Option<PathBuf>,
    expected_peer_did: Option<String>,
    max_response_bytes: usize,
}

impl NativeHttpSecurity {
    fn from_cli(cli: &Cli) -> Result<Self, String> {
        let inline_peer_did = cli
            .native_peer_did
            .clone()
            .or_else(|| non_empty_environment("GETAIP_NATIVE_PEER_DID"));
        let peer_did_file = cli
            .native_peer_did_file
            .clone()
            .or_else(|| environment_path("GETAIP_NATIVE_PEER_DID_FILE"));
        if inline_peer_did.is_some() && peer_did_file.is_some() {
            return Err(
                "native peer DID and GETAIP_NATIVE_PEER_DID_FILE are mutually exclusive".to_owned(),
            );
        }
        let expected_peer_did = match (inline_peer_did, peer_did_file) {
            (Some(value), None) => Some(value),
            (None, Some(path)) => Some(
                String::from_utf8(read_public_file(&path, 1_024, "native peer DID")?)
                    .map_err(|_| "native peer DID file must contain valid UTF-8".to_owned())?
                    .trim()
                    .to_owned(),
            ),
            (None, None) => None,
            (Some(_), Some(_)) => unreachable!("peer DID conflict checked above"),
        };
        let max_response_bytes = non_empty_environment("GETAIP_NATIVE_MAX_RESPONSE_BYTES")
            .map(|value| {
                value.parse::<usize>().map_err(|_| {
                    "GETAIP_NATIVE_MAX_RESPONSE_BYTES must be a positive integer".to_owned()
                })
            })
            .transpose()?
            .unwrap_or(cli.native_max_response_bytes);
        Ok(Self {
            signing_seed_file: cli
                .native_signing_seed_file
                .clone()
                .or_else(|| environment_path("GETAIP_NATIVE_SIGNING_SEED_FILE")),
            principal_id: non_empty_environment("GETAIP_NATIVE_PRINCIPAL_ID")
                .unwrap_or_else(|| cli.native_principal_id.clone()),
            trust_domain: cli
                .native_trust_domain
                .clone()
                .or_else(|| non_empty_environment("GETAIP_NATIVE_TRUST_DOMAIN")),
            tls_ca_file: cli
                .native_tls_ca_file
                .clone()
                .or_else(|| environment_path("GETAIP_NATIVE_TLS_CA_FILE")),
            expected_peer_did,
            max_response_bytes,
        })
    }

    fn principal(&self) -> Result<Principal, String> {
        principal_from_id(&self.principal_id)
    }

    fn validate(&self) -> Result<(), String> {
        let _ = self.principal()?;
        if self.max_response_bytes == 0 {
            return Err("native HTTP response limit must be greater than zero".to_owned());
        }
        if self.trust_domain.is_some() && self.signing_seed_file.is_none() {
            return Err("native HTTP trust domain requires a native signing-seed file".to_owned());
        }
        if self.signing_seed_file.is_some() && self.expected_peer_did.is_none() {
            return Err(
                "signed native HTTP requires --native-peer-did or --native-peer-did-file"
                    .to_owned(),
            );
        }
        if let Some(path) = self.signing_seed_file.as_deref() {
            let _ = read_ed25519_signing_key(path, "native HTTP")?;
        }
        if let Some(did) = self.expected_peer_did.as_deref() {
            verifying_key_from_did_key(did)
                .map_err(|error| format!("native peer DID is invalid: {error}"))?;
        }
        let _ = self.client()?;
        Ok(())
    }

    fn secure_envelope(&self, mut envelope: Envelope) -> Result<Envelope, String> {
        let Some(path) = self.signing_seed_file.as_deref() else {
            return Ok(envelope);
        };
        let signing_key = read_ed25519_signing_key(path, "native HTTP")?;
        let did = did_key_from_verifying_key(&signing_key.verifying_key());
        let mut principal = self.principal()?;
        principal.did = Some(did.clone());
        principal.trust_domain = self.trust_domain.clone();
        envelope.from = Some(principal);
        let security = envelope.security.get_or_insert_with(|| json!({}));
        let security = security
            .as_object_mut()
            .ok_or_else(|| "native envelope security metadata must be an object".to_owned())?;
        security.insert("did".to_owned(), json!(did));
        if let Some(trust_domain) = self.trust_domain.as_deref() {
            security.insert("trust_domain".to_owned(), json!(trust_domain));
        }
        security.remove("signature");
        let signature =
            sign_envelope(&envelope, &signing_key).map_err(|error| error.to_string())?;
        envelope
            .security
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "native envelope security metadata must be an object".to_owned())?
            .insert("signature".to_owned(), json!(signature));
        Ok(envelope)
    }

    fn client(&self) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if let Some(path) = self.tls_ca_file.as_deref() {
            let pem = read_public_file(path, 1024 * 1024, "native TLS CA")?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|error| format!("native TLS CA is invalid: {error}"))?;
            builder = builder.add_root_certificate(certificate);
        }
        builder
            .build()
            .map_err(|error| format!("native HTTP client failed: {error}"))
    }

    fn verify_response(&self, request: &Envelope, response: &Envelope) -> Result<(), String> {
        let Some(expected_did) = self.expected_peer_did.as_deref() else {
            return Ok(());
        };
        let metadata = response
            .security
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| "native peer response is not signed".to_owned())?;
        let response_did = metadata
            .get("did")
            .and_then(Value::as_str)
            .ok_or_else(|| "native peer response DID is missing".to_owned())?;
        if response_did != expected_did {
            return Err(format!(
                "native peer response DID `{response_did}` does not match the pinned peer"
            ));
        }
        let signature = metadata
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| "native peer response signature is missing".to_owned())?;
        let verifying_key = verifying_key_from_did_key(expected_did)
            .map_err(|error| format!("native peer DID is invalid: {error}"))?;
        verify_envelope(response, signature, &verifying_key)
            .map_err(|error| format!("native peer response signature is invalid: {error}"))?;
        let peer = response
            .from
            .as_ref()
            .ok_or_else(|| "native peer response sender is missing".to_owned())?;
        if peer.did.as_deref() != Some(expected_did) {
            return Err("native peer response sender is not bound to the pinned DID".to_owned());
        }
        if response.to != request.from {
            return Err(
                "native peer response recipient does not match the request sender".to_owned(),
            );
        }
        if response.session_id != request.session_id
            || response.correlation_id != request.correlation_id
        {
            return Err("native peer response context does not match the request".to_owned());
        }
        if !matches!(
            response.in_response_to.as_ref(),
            Some(MessageReference::Message(message_id)) if message_id == &request.message_id
        ) {
            return Err(
                "native peer response does not reference the exact request message".to_owned(),
            );
        }
        let now = OffsetDateTime::now_utc();
        let skew = time::Duration::minutes(5);
        if response.sent_at < now - skew || response.sent_at > now + skew {
            return Err(
                "native peer response timestamp is outside the accepted five-minute window"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct NatsClientSecurity {
    username: Option<String>,
    password_file: Option<PathBuf>,
    signing_seed_file: Option<PathBuf>,
}

impl NatsClientSecurity {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            username: cli
                .nats_username
                .clone()
                .or_else(|| non_empty_environment("GETAIP_NATS_USERNAME")),
            password_file: cli
                .nats_password_file
                .clone()
                .or_else(|| environment_path("GETAIP_NATS_PASSWORD_FILE")),
            signing_seed_file: cli
                .nats_signing_seed_file
                .clone()
                .or_else(|| environment_path("GETAIP_NATS_SIGNING_SEED_FILE")),
        }
    }

    fn authentication(&self) -> Result<Option<NatsAuthentication>, String> {
        match (&self.username, &self.password_file) {
            (None, None) => Ok(None),
            (Some(_), None) => Err(
                "NATS username requires --nats-password-file or GETAIP_NATS_PASSWORD_FILE"
                    .to_owned(),
            ),
            (None, Some(_)) => Err(
                "NATS password file requires --nats-username or GETAIP_NATS_USERNAME".to_owned(),
            ),
            (Some(username), Some(path)) => {
                let password = String::from_utf8(read_secret_file(path, 16 * 1024)?)
                    .map_err(|_| "NATS password file must contain valid UTF-8".to_owned())?;
                NatsAuthentication::user_password(username.clone(), password)
                    .map(Some)
                    .map_err(|error| error.to_string())
            }
        }
    }

    fn signing_key(&self) -> Result<Option<ed25519_dalek::SigningKey>, String> {
        let Some(path) = &self.signing_seed_file else {
            return Ok(None);
        };
        let encoded = String::from_utf8(read_secret_file(path, 1024)?)
            .map_err(|_| "NATS signing seed file must contain valid UTF-8".to_owned())?;
        let decoded = hex::decode(encoded.trim()).map_err(|_| {
            "NATS signing seed must be exactly 64 hexadecimal characters".to_owned()
        })?;
        let seed: [u8; 32] = decoded.try_into().map_err(|_| {
            "NATS signing seed must encode exactly 32 bytes (64 hexadecimal characters)".to_owned()
        })?;
        Ok(Some(signing_key_from_seed(seed)))
    }

    fn secure_envelope(&self, mut envelope: Envelope) -> Result<Envelope, String> {
        let Some(signing_key) = self.signing_key()? else {
            return Ok(envelope);
        };
        let did = did_key_from_verifying_key(&signing_key.verifying_key());
        let mut principal = cli_principal()?;
        principal.did = Some(did.clone());
        envelope.from = Some(principal);
        {
            let security = envelope.security.get_or_insert_with(|| json!({}));
            let security = security
                .as_object_mut()
                .ok_or_else(|| "envelope security metadata must be an object".to_owned())?;
            security.insert("did".to_owned(), json!(did));
            security.remove("signature");
        }
        let signature =
            sign_envelope(&envelope, &signing_key).map_err(|error| error.to_string())?;
        envelope
            .security
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "envelope security metadata must be an object".to_owned())?
            .insert("signature".to_owned(), json!(signature));
        Ok(envelope)
    }

    fn signer_did(&self) -> Result<String, String> {
        let signing_key = self.signing_key()?.ok_or_else(|| {
            "configure --nats-signing-seed-file or GETAIP_NATS_SIGNING_SEED_FILE".to_owned()
        })?;
        Ok(did_key_from_verifying_key(&signing_key.verifying_key()))
    }
}

/// Top-level CLI commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Print GetAIP software and AIP protocol version identity.
    Version {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
    /// Install one signed, compatible GetAIP distribution.
    Setup(product::SetupArgs),
    /// Diagnose installation, configuration, and runtime readiness.
    Doctor(product::DoctorArgs),
    /// Report top-level product installation and runtime status.
    Status(product::StatusArgs),
    /// Run the matching verified server in the foreground.
    Serve(product::ServeArgs),
    /// Install a newer explicitly signed GetAIP release.
    Upgrade(product::UpgradeArgs),
    /// Atomically activate the retained previous verified release.
    Rollback(product::RollbackArgs),
    /// Remove installer-owned artifacts and optionally GetAIP user data.
    Uninstall(product::UninstallArgs),
    /// Manage the optional user-owned GetAIP server service.
    Service(service::ServiceArgs),
    /// Schema commands.
    Schema {
        /// Schema subcommand.
        #[command(subcommand)]
        command: SchemaCommand,
    },
    /// Native NATS client security commands.
    Nats {
        /// NATS security subcommand.
        #[command(subcommand)]
        command: NatsCommand,
    },
    /// Manifest commands.
    Manifest {
        /// Manifest subcommand.
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Tenant-scoped capability catalog commands.
    Capability {
        /// Capability catalog subcommand.
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    /// Action commands.
    Action {
        /// Action subcommand.
        #[command(subcommand)]
        command: ActionCommand,
    },
    /// Approval lifecycle commands.
    Approval {
        /// Approval subcommand.
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Global native event stream commands.
    Events {
        /// Events subcommand.
        #[command(subcommand)]
        command: EventsCommand,
    },
    /// Session operational commands.
    Session {
        /// Session subcommand.
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Transaction read-model commands.
    Transaction {
        /// Transaction subcommand.
        #[command(subcommand)]
        command: TransactionCommand,
    },
    /// Audit read-model commands.
    Audit {
        /// Audit subcommand.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Resource read-model commands.
    Resource {
        /// Resource subcommand.
        #[command(subcommand)]
        command: ResourceCommand,
    },
    /// Conformance commands.
    Conformance {
        /// Conformance subcommand.
        #[command(subcommand)]
        command: ConformanceCommand,
    },
    /// MCP compatibility commands.
    Mcp {
        /// MCP subcommand.
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Connector commands.
    Connector {
        /// Connector subcommand.
        #[command(subcommand)]
        command: ConnectorCommand,
    },
    /// Receipt commands.
    Receipt {
        /// Receipt subcommand.
        #[command(subcommand)]
        command: ReceiptCommand,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize)]
struct VersionOutput {
    schema: &'static str,
    product: &'static str,
    #[serde(flatten)]
    version: BuildVersion,
}

/// Native NATS client security subcommands.
#[derive(Debug, Subcommand)]
enum NatsCommand {
    /// Derive the public did:key registered by a signed AIP deployment.
    SignerDid,
}

/// Schema subcommands.
#[derive(Debug, Subcommand)]
enum SchemaCommand {
    /// Export built-in schemas as JSON files.
    Export {
        /// Output directory.
        output: PathBuf,
    },
}

/// Manifest subcommands.
#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Fetch a manifest from a deployed AIP endpoint.
    Fetch {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
    },
    /// Fetch a manifest through native NATS request/reply.
    FetchNats {
        /// NATS server URL, for example `nats://127.0.0.1:14222`.
        server_url: String,
        /// AIP trust-domain subject segment.
        #[arg(long, default_value = "local")]
        trust_domain: String,
        /// AIP service subject segment.
        #[arg(long, default_value = "getaip-server")]
        service: String,
        /// AIP service version subject segment.
        #[arg(long, default_value = "v1")]
        version: String,
    },
    /// Validate a manifest JSON file.
    Validate {
        /// Path to manifest JSON.
        path: PathBuf,
    },
}

/// Tenant-scoped native capability catalog subcommands.
#[derive(Debug, Subcommand)]
enum CapabilityCommand {
    /// Query one bounded, revision-consistent capability page.
    List {
        /// Base URL, for example `https://aip.example`.
        url: String,
        /// Exact capability id filter.
        #[arg(long)]
        capability_id: Option<String>,
        /// Case-insensitive search across id, name, and description.
        #[arg(long)]
        text: Option<String>,
        /// Required implementation profile id.
        #[arg(long)]
        profile: Option<String>,
        /// Opaque cursor returned by the preceding page.
        #[arg(long)]
        cursor: Option<String>,
        /// Requested server-side page size.
        #[arg(long)]
        limit: Option<u32>,
        /// Query through a signed native AIP action instead of bearer-authenticated GET.
        #[arg(long)]
        signed_native: bool,
    },
}

/// Action subcommands.
#[derive(Debug, Subcommand)]
enum ActionCommand {
    /// Call an AIP capability through a deployed HTTP endpoint.
    Call {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Capability id to invoke.
        capability_id: String,
        /// JSON input object, or `@path` to read JSON from a file.
        #[arg(long, default_value = "{}")]
        input: String,
        /// Enterprise action options.
        #[command(flatten)]
        options: ActionOptions,
    },
    /// Call an AIP capability through native NATS request/reply.
    CallNats {
        /// NATS server URL, for example `nats://127.0.0.1:14222`.
        server_url: String,
        /// Capability id to invoke.
        capability_id: String,
        /// JSON input object, or `@path` to read JSON from a file.
        #[arg(long, default_value = "{}")]
        input: String,
        /// Enterprise action options.
        #[command(flatten)]
        options: ActionOptions,
        /// AIP trust-domain subject segment.
        #[arg(long, default_value = "local")]
        trust_domain: String,
        /// AIP service subject segment.
        #[arg(long, default_value = "getaip-server")]
        service: String,
        /// AIP service version subject segment.
        #[arg(long, default_value = "v1")]
        version: String,
    },
    /// List native action lifecycle views through HTTP.
    List {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Lifecycle state filter.
        #[arg(long)]
        state: Option<String>,
        /// Capability id filter.
        #[arg(long)]
        capability_id: Option<String>,
        /// Session id filter.
        #[arg(long)]
        session_id: Option<String>,
        /// Principal id filter.
        #[arg(long)]
        principal_id: Option<String>,
        /// Approval id filter.
        #[arg(long)]
        approval_id: Option<String>,
        /// Transaction id filter.
        #[arg(long)]
        transaction_id: Option<String>,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
        /// Include final results.
        #[arg(long)]
        include_results: bool,
        /// Include receipt chains.
        #[arg(long)]
        include_receipts: bool,
    },
    /// Read native action status through HTTP.
    Status {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Action id.
        action_id: String,
        /// Include final result.
        #[arg(long)]
        include_result: bool,
        /// Include receipt chain.
        #[arg(long)]
        include_receipts: bool,
        /// Include stream chunks.
        #[arg(long)]
        include_chunks: bool,
        /// Bounded wait in milliseconds.
        #[arg(long)]
        wait_ms: Option<u64>,
    },
    /// Read native final action result through HTTP.
    Result {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Action id.
        action_id: String,
        /// Bounded wait in milliseconds.
        #[arg(long)]
        wait_ms: Option<u64>,
        /// Include receipt chain.
        #[arg(long)]
        include_receipt: bool,
        /// Include terminal event hints.
        #[arg(long)]
        include_terminal_events: bool,
    },
    /// Read action-scoped native events/chunks through HTTP.
    Events {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Action id.
        action_id: String,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
        /// Event kind filters.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        /// Include chunks.
        #[arg(long)]
        include_chunks: bool,
        /// Request SSE follow mode from HTTP binding.
        #[arg(long)]
        follow: bool,
    },
    /// Cancel one native action through HTTP.
    Cancel {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Action id.
        action_id: String,
        /// Cancellation reason.
        #[arg(long)]
        reason: Option<String>,
    },
}

/// Global event stream subcommands.
#[derive(Debug, Subcommand)]
enum EventsCommand {
    /// Read global native events through HTTP.
    List {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
        /// Event kind filters.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        /// Request SSE follow mode from HTTP binding.
        #[arg(long)]
        follow: bool,
    },
}

/// Session operational subcommands.
#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// List native sessions.
    List {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Principal id filter.
        #[arg(long)]
        principal_id: Option<String>,
        /// Session state filter.
        #[arg(long)]
        status: Option<String>,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Read one native session.
    Get {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Session id.
        session_id: String,
    },
    /// Close one native session.
    Close {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Session id.
        session_id: String,
        /// Close reason.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Resume one native session after reconnect.
    Resume {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Session id.
        session_id: String,
        /// Optional resume token.
        #[arg(long)]
        resume_token: Option<String>,
        /// Last event cursor seen by the client.
        #[arg(long)]
        last_event_cursor: Option<String>,
    },
}

/// Approval subcommands.
#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// List approval lifecycle events through HTTP.
    List {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Starting event cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Maximum events to return.
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Event kind filter. Defaults to approval lifecycle events.
        #[arg(long = "kind")]
        kinds: Vec<String>,
    },
    /// List native approval records through HTTP.
    Records {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Approval status filter.
        #[arg(long)]
        status: Option<String>,
        /// Approver principal filter.
        #[arg(long)]
        approver: Option<String>,
        /// Requester principal filter.
        #[arg(long)]
        requester: Option<String>,
        /// Tenant id filter.
        #[arg(long)]
        tenant_id: Option<String>,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
        /// Include linked action status.
        #[arg(long)]
        include_action_status: bool,
        /// Include receipt chains.
        #[arg(long)]
        include_receipts: bool,
    },
    /// Read one native approval record through HTTP.
    Get {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Approval id.
        approval_id: String,
        /// Include linked action status.
        #[arg(long)]
        include_action_status: bool,
        /// Include receipt chain.
        #[arg(long)]
        include_receipts: bool,
    },
    /// Submit a first-class approval request through HTTP.
    Request {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// ApprovalRequest JSON, or `@path`.
        request: String,
    },
    /// Submit a first-class approval decision through HTTP.
    Decide {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// ApprovalDecision JSON, or `@path`.
        decision: String,
    },
    /// List approval lifecycle events through native NATS request/reply.
    ListNats {
        /// NATS server URL, for example `nats://127.0.0.1:14222`.
        server_url: String,
        /// Starting event cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Maximum events to return.
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Event kind filter. Defaults to approval lifecycle events.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        /// AIP trust-domain subject segment.
        #[arg(long, default_value = "local")]
        trust_domain: String,
        /// AIP service subject segment.
        #[arg(long, default_value = "getaip-server")]
        service: String,
        /// AIP service version subject segment.
        #[arg(long, default_value = "v1")]
        version: String,
    },
    /// Submit a first-class approval request through native NATS request/reply.
    RequestNats {
        /// NATS server URL, for example `nats://127.0.0.1:14222`.
        server_url: String,
        /// ApprovalRequest JSON, or `@path`.
        request: String,
        /// AIP trust-domain subject segment.
        #[arg(long, default_value = "local")]
        trust_domain: String,
        /// AIP service subject segment.
        #[arg(long, default_value = "getaip-server")]
        service: String,
        /// AIP service version subject segment.
        #[arg(long, default_value = "v1")]
        version: String,
    },
    /// Submit a first-class approval decision through native NATS request/reply.
    DecideNats {
        /// NATS server URL, for example `nats://127.0.0.1:14222`.
        server_url: String,
        /// ApprovalDecision JSON, or `@path`.
        decision: String,
        /// AIP trust-domain subject segment.
        #[arg(long, default_value = "local")]
        trust_domain: String,
        /// AIP service subject segment.
        #[arg(long, default_value = "getaip-server")]
        service: String,
        /// AIP service version subject segment.
        #[arg(long, default_value = "v1")]
        version: String,
    },
}

/// Transaction read-model subcommands.
#[derive(Debug, Subcommand)]
enum TransactionCommand {
    /// Read one transaction by transaction id, plan id, or action id.
    Get {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Transaction id selector.
        #[arg(long)]
        transaction_id: Option<String>,
        /// Plan id selector.
        #[arg(long)]
        plan_id: Option<String>,
        /// Action id selector.
        #[arg(long)]
        action_id: Option<String>,
        /// Include final result.
        #[arg(long)]
        include_result: bool,
        /// Include receipt chain.
        #[arg(long)]
        include_receipts: bool,
    },
}

/// Audit read-model subcommands.
#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Query native audit events.
    Events {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Action id filter.
        #[arg(long)]
        action_id: Option<String>,
        /// Session id filter.
        #[arg(long)]
        session_id: Option<String>,
        /// Principal id filter.
        #[arg(long)]
        principal_id: Option<String>,
        /// Transaction id filter.
        #[arg(long)]
        transaction_id: Option<String>,
        /// Inclusive RFC3339 lower timestamp bound.
        #[arg(long)]
        from: Option<String>,
        /// Inclusive RFC3339 upper timestamp bound.
        #[arg(long)]
        to: Option<String>,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
        /// Include related receipt chains.
        #[arg(long)]
        include_receipts: bool,
        /// Request an evidence export package; requires audit export authority.
        #[arg(long)]
        export: bool,
    },
}

/// Resource read-model subcommands.
#[derive(Debug, Subcommand)]
enum ResourceCommand {
    /// List native AIP resources.
    List {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Capability id filter.
        #[arg(long)]
        capability_id: Option<String>,
        /// Resource kind filter.
        #[arg(long)]
        kind: Option<String>,
        /// Page cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Page limit.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Read one native AIP resource.
    Read {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Resource id.
        resource_id: String,
        /// Optional version selector.
        #[arg(long)]
        version: Option<String>,
        /// Accept MIME/profile filters. Repeat or pass comma-separated values.
        #[arg(long = "accept")]
        accept: Vec<String>,
    },
}

/// Enterprise action flags shared by HTTP and NATS calls.
#[derive(Clone, Debug, Default, Args)]
struct ActionOptions {
    /// Stable action id used when retrying an interrupted operation.
    #[arg(long)]
    action_id: Option<String>,
    /// Idempotency key required by replay-sensitive capabilities.
    #[arg(long)]
    idempotency_key: Option<String>,
    /// Invocation mode.
    #[arg(long, value_enum)]
    mode: Option<CliActionMode>,
    /// Identity context JSON, or `@path`.
    #[arg(long)]
    identity: Option<String>,
    /// Approval decision JSON, or `@path`.
    #[arg(long)]
    approval: Option<String>,
    /// Transaction mode.
    #[arg(long, value_enum)]
    transaction_mode: Option<CliTransactionMode>,
    /// Transaction id.
    #[arg(long)]
    transaction_id: Option<String>,
    /// Durable plan id for plan/commit.
    #[arg(long)]
    plan_id: Option<String>,
    /// Action id being compensated.
    #[arg(long)]
    compensation_for: Option<String>,
}

/// CLI-facing action mode.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliActionMode {
    /// Synchronous action result.
    Sync,
    /// Queued asynchronous execution.
    Async,
    /// Streaming execution.
    Streaming,
}

impl From<CliActionMode> for ActionMode {
    fn from(value: CliActionMode) -> Self {
        match value {
            CliActionMode::Sync => Self::Sync,
            CliActionMode::Async => Self::Async,
            CliActionMode::Streaming => Self::Streaming,
        }
    }
}

/// CLI-facing transaction mode.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliTransactionMode {
    /// Execute normally.
    Execute,
    /// Validate without side effects.
    DryRun,
    /// Produce a durable plan.
    Plan,
    /// Commit a previous plan.
    Commit,
    /// Compensate a previous action.
    Compensate,
    /// Explicit rollback unsupported state.
    RollbackNotSupported,
}

impl From<CliTransactionMode> for TransactionMode {
    fn from(value: CliTransactionMode) -> Self {
        match value {
            CliTransactionMode::Execute => Self::Execute,
            CliTransactionMode::DryRun => Self::DryRun,
            CliTransactionMode::Plan => Self::Plan,
            CliTransactionMode::Commit => Self::Commit,
            CliTransactionMode::Compensate => Self::Compensate,
            CliTransactionMode::RollbackNotSupported => Self::RollbackNotSupported,
        }
    }
}

/// Conformance subcommands.
#[derive(Debug, Subcommand)]
enum ConformanceCommand {
    /// Run core conformance checks against an envelope file or built-in fixture.
    Run {
        /// Optional envelope JSON file.
        #[arg(long)]
        envelope: Option<PathBuf>,
    },
}

/// MCP compatibility subcommands.
#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Inspect an MCP peer and print its AIP manifest projection.
    Inspect {
        /// Streamable HTTP endpoint or AIP daemon base URL.
        #[arg(long)]
        url: Option<String>,
        /// Bearer token for protected MCP Streamable HTTP endpoints.
        #[arg(long)]
        bearer_token: Option<String>,
        /// MCP stdio server command.
        #[arg(long)]
        command: Option<String>,
        /// Argument passed to the stdio server command. Repeat for multiple args.
        #[arg(long = "arg")]
        args: Vec<String>,
    },
    /// Call an MCP tool through the outbound bridge.
    CallTool {
        /// Tool name.
        tool: String,
        /// JSON tool arguments, or `@path` to read JSON from a file.
        #[arg(long, default_value = "{}")]
        arguments: String,
        /// Streamable HTTP endpoint or AIP daemon base URL.
        #[arg(long)]
        url: Option<String>,
        /// Bearer token for protected MCP Streamable HTTP endpoints.
        #[arg(long)]
        bearer_token: Option<String>,
        /// MCP stdio server command.
        #[arg(long)]
        command: Option<String>,
        /// Argument passed to the stdio server command. Repeat for multiple args.
        #[arg(long = "arg")]
        args: Vec<String>,
    },
    /// Run outbound MCP client conformance against a peer.
    Conformance {
        /// Streamable HTTP endpoint or AIP daemon base URL.
        #[arg(long)]
        url: Option<String>,
        /// Bearer token for protected MCP Streamable HTTP endpoints.
        #[arg(long)]
        bearer_token: Option<String>,
        /// MCP stdio server command.
        #[arg(long)]
        command: Option<String>,
        /// Argument passed to the stdio server command. Repeat for multiple args.
        #[arg(long = "arg")]
        args: Vec<String>,
    },
    /// Serve an HTTP MCP endpoint as a stdio MCP server.
    ServeStdio {
        /// Streamable HTTP endpoint or AIP daemon base URL.
        #[arg(long)]
        url: String,
        /// Bearer token for protected MCP Streamable HTTP endpoints.
        #[arg(long)]
        bearer_token: Option<String>,
    },
    /// Bridge between MCP server transports.
    Bridge {
        /// Server transport exposed by the bridge.
        #[arg(long)]
        server: McpBridgeServer,
        /// HTTP bind address when `--server http` is selected.
        #[arg(long, default_value = "127.0.0.1:18090")]
        bind: SocketAddr,
        /// Streamable HTTP endpoint or AIP daemon base URL used when `--server stdio`.
        #[arg(long)]
        url: Option<String>,
        /// Bearer token for protected MCP Streamable HTTP endpoints.
        #[arg(long)]
        bearer_token: Option<String>,
        /// MCP stdio server command used when `--server http`.
        #[arg(long)]
        command: Option<String>,
        /// Argument passed to the stdio server command. Repeat for multiple args.
        #[arg(long = "arg")]
        args: Vec<String>,
    },
}

/// MCP bridge server mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum McpBridgeServer {
    /// Expose the upstream MCP endpoint over stdio.
    Stdio,
    /// Expose a stdio MCP subprocess over Streamable HTTP.
    Http,
}

/// Connector subcommands.
#[derive(Debug, Subcommand)]
enum ConnectorCommand {
    /// Verify that a deployed daemon exposes connector capabilities.
    Test {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Capability id that must be present. Can be passed multiple times.
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        /// Capability id that must be invoked successfully. Can be passed multiple times.
        #[arg(long = "invoke-capability")]
        invoke_capabilities: Vec<String>,
        /// JSON input object used for connector invocations, or `@path` to read JSON from a file.
        #[arg(long, default_value = "{}")]
        input: String,
        /// Expected action_result status for invoked capabilities.
        #[arg(long, default_value = "completed")]
        expect_status: String,
    },
    /// Install or verify immutable connector-registry migrations.
    RegistryMigrate {
        /// Owner-only file containing the PostgreSQL control-plane URL.
        #[arg(long, value_name = "PATH")]
        database_url_file: PathBuf,
        /// Maximum control-plane database connections during migration.
        #[arg(long, default_value_t = 4)]
        control_max_connections: u32,
        /// Maximum read connection count used while verifying the schema.
        #[arg(long, default_value_t = 1)]
        data_max_connections: u32,
        /// Maximum wait for a registry connection.
        #[arg(long, default_value_t = 5_000)]
        acquire_timeout_ms: u64,
    },
    /// Cryptographically verify and administer connector catalog packages.
    Registry {
        /// Registry operator subcommand.
        #[command(subcommand)]
        command: ConnectorRegistryCommand,
    },
    /// Build and verify signed plans for an external connector orchestrator.
    Orchestration {
        /// Orchestration operator subcommand.
        #[command(subcommand)]
        command: ConnectorOrchestrationCommand,
    },
}

/// Short-lived connector-orchestration operator commands.
#[derive(Debug, Subcommand)]
enum ConnectorOrchestrationCommand {
    /// Derive the next deterministic operation batch without signing or writing.
    Plan {
        /// Signed admission package that owns every target replica.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,
        /// Admission trust policy used to verify the package and its evidence.
        #[arg(long, value_name = "PATH")]
        admission_trust_policy: PathBuf,
        /// Deployment intent JSON.
        #[arg(long, value_name = "PATH")]
        intent: PathBuf,
        /// Bounded array of observations from the external platform.
        #[arg(long, value_name = "PATH")]
        observed: PathBuf,
        /// Executor trust roots and reconciliation bounds.
        #[arg(long, value_name = "PATH")]
        orchestration_policy: PathBuf,
    },
    /// Derive and sign one exact operation batch for an external executor.
    Sign {
        /// Signed admission package that owns every target replica.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,
        /// Admission trust policy used to verify the package and its evidence.
        #[arg(long, value_name = "PATH")]
        admission_trust_policy: PathBuf,
        /// Deployment intent JSON.
        #[arg(long, value_name = "PATH")]
        intent: PathBuf,
        /// Bounded array of observations from the external platform.
        #[arg(long, value_name = "PATH")]
        observed: PathBuf,
        /// Executor trust roots and reconciliation bounds.
        #[arg(long, value_name = "PATH")]
        orchestration_policy: PathBuf,
        /// Owner-only file containing a hex-encoded 32-byte Ed25519 seed.
        #[arg(long, value_name = "PATH")]
        signing_seed_file: PathBuf,
        /// Stable operator or deployment-controller identity.
        #[arg(long)]
        signer_identity: String,
    },
    /// Verify a signed operation batch exactly as an executor must verify it.
    Verify {
        /// Signed orchestration plan JSON.
        #[arg(long, value_name = "PATH")]
        plan: PathBuf,
        /// Fresh bounded platform observations used as the execution fence.
        #[arg(long, value_name = "PATH")]
        current_observed: PathBuf,
        /// Executor trust roots and hard limits.
        #[arg(long, value_name = "PATH")]
        orchestration_policy: PathBuf,
    },
}

/// Short-lived connector-registry operator commands.
#[derive(Debug, Subcommand)]
enum ConnectorRegistryCommand {
    /// Sign one canonical release evidence document with a policy key.
    SignEvidence {
        /// Mandatory evidence family.
        #[arg(long, value_enum)]
        kind: CliEvidenceKind,
        /// Exact immutable OCI or artifact digest evaluated by the evidence.
        #[arg(long)]
        artifact_digest: String,
        /// Canonical connector manifest digest evaluated by the evidence.
        #[arg(long)]
        manifest_digest: String,
        /// Complete JSON evidence document.
        #[arg(long, value_name = "PATH")]
        document: PathBuf,
        /// Owner-only file containing a hex-encoded 32-byte Ed25519 seed.
        #[arg(long, value_name = "PATH")]
        signing_seed_file: PathBuf,
        /// Stable build, scanner, or policy-evaluator identity.
        #[arg(long)]
        signer_identity: String,
        /// Evidence validity after issuance; bounded to 30 days.
        #[arg(long, default_value_t = 86_400)]
        valid_for_seconds: u64,
    },
    /// Sign one complete admission package with a release-authority key.
    SignPackage {
        /// Unsigned declarative admission package JSON.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,
        /// Owner-only file containing a hex-encoded 32-byte Ed25519 seed.
        #[arg(long, value_name = "PATH")]
        signing_seed_file: PathBuf,
        /// Stable release-authority identity.
        #[arg(long)]
        signer_identity: String,
    },
    /// Verify signatures, evidence, bounds, and catalog invariants without writing.
    Plan {
        /// Signed declarative admission package JSON.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,
        /// Deployment trust policy with separate package and evidence-role roots.
        #[arg(long, value_name = "PATH")]
        trust_policy: PathBuf,
    },
    /// Apply or safely resume one exact verified package.
    Apply {
        /// Signed declarative admission package JSON.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,
        /// Deployment trust policy with separate package and evidence-role roots.
        #[arg(long, value_name = "PATH")]
        trust_policy: PathBuf,
        /// Short-lived administrator database connection.
        #[command(flatten)]
        database: ConnectorRegistryDatabaseArgs,
    },
    /// Read one bounded, secret-free durable operator record.
    Status {
        /// Stable package id.
        #[arg(long)]
        package_id: String,
        /// Exact package revision; omitted selects the latest revision.
        #[arg(long)]
        revision: Option<u64>,
        /// Short-lived administrator database connection.
        #[command(flatten)]
        database: ConnectorRegistryDatabaseArgs,
    },
    /// Stop new traffic for an applied package and retain its audit record.
    Revoke {
        /// Stable package id.
        #[arg(long)]
        package_id: String,
        /// Exact applied package revision.
        #[arg(long)]
        revision: u64,
        /// Printable bounded operator reason retained in the audit record.
        #[arg(long)]
        reason: String,
        /// Short-lived administrator database connection.
        #[command(flatten)]
        database: ConnectorRegistryDatabaseArgs,
    },
    /// Terminalize one irrecoverable failed revision and retain its audit record.
    Abandon {
        /// Stable package id.
        #[arg(long)]
        package_id: String,
        /// Exact failed package revision.
        #[arg(long)]
        revision: u64,
        /// Printable bounded operator reason retained in the audit record.
        #[arg(long)]
        reason: String,
        /// Short-lived administrator database connection.
        #[command(flatten)]
        database: ConnectorRegistryDatabaseArgs,
    },
    /// Create or revision-update one tenant capability binding.
    SetBinding {
        /// Tenant that owns the connector instance and receives the capability.
        #[arg(long)]
        tenant_id: String,
        /// Capability exposed by the binding.
        #[arg(long)]
        capability_id: String,
        /// Logical connector instance selected by the binding.
        #[arg(long)]
        instance_id: String,
        /// Lower values are preferred when several bindings are enabled.
        #[arg(long)]
        priority: u32,
        /// Strictly monotonic binding policy revision.
        #[arg(long)]
        policy_revision: u64,
        /// Credential revision pinned into new route assignments.
        #[arg(long)]
        credential_revision_ref: Option<String>,
        /// Admission and quota policy used by this binding.
        #[arg(long)]
        quota_policy_ref: Option<String>,
        /// Desired routing state.
        #[arg(long, value_enum)]
        state: CliBindingState,
        /// Short-lived administrator database connection.
        #[command(flatten)]
        database: ConnectorRegistryDatabaseArgs,
    },
}

/// Desired tenant capability-binding state.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliBindingState {
    /// Allow this binding to receive new route assignments.
    Enabled,
    /// Retain the binding for audit but exclude it from new assignments.
    Disabled,
}

impl CliBindingState {
    const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Evidence family accepted by the release-signing CLI.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliEvidenceKind {
    /// Detached immutable-artifact signature evidence.
    OciSignature,
    /// Software bill of materials.
    Sbom,
    /// Build provenance.
    Provenance,
    /// AIP conformance result.
    Conformance,
    /// Vulnerability-policy result.
    Vulnerability,
    /// License-policy result.
    License,
    /// Revocation observation.
    Revocation,
}

impl From<CliEvidenceKind> for EvidenceKind {
    fn from(value: CliEvidenceKind) -> Self {
        match value {
            CliEvidenceKind::OciSignature => Self::OciSignature,
            CliEvidenceKind::Sbom => Self::Sbom,
            CliEvidenceKind::Provenance => Self::Provenance,
            CliEvidenceKind::Conformance => Self::Conformance,
            CliEvidenceKind::Vulnerability => Self::Vulnerability,
            CliEvidenceKind::License => Self::License,
            CliEvidenceKind::Revocation => Self::Revocation,
        }
    }
}

/// Bounded database settings shared by short-lived registry commands.
#[derive(Clone, Debug, Args)]
struct ConnectorRegistryDatabaseArgs {
    /// Owner-only file containing the PostgreSQL administrator URL.
    #[arg(long, value_name = "PATH")]
    database_url_file: PathBuf,
    /// Maximum administrator connections for this short-lived command.
    #[arg(long, default_value_t = 2)]
    control_max_connections: u32,
    /// Maximum read/data connections for validation and status.
    #[arg(long, default_value_t = 2)]
    data_max_connections: u32,
    /// Maximum connection acquisition time.
    #[arg(long, default_value_t = 5_000)]
    acquire_timeout_ms: u64,
}

/// Receipt subcommands.
#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    /// Verify a receipt hash chain JSON file.
    Verify {
        /// Path to receipt chain JSON.
        path: PathBuf,
    },
    /// Read a receipt chain from a deployed daemon.
    Get {
        /// Base URL, for example `http://127.0.0.1:18080`.
        url: String,
        /// Receipt chain id selector.
        #[arg(long)]
        chain_id: Option<String>,
        /// Individual receipt id selector.
        #[arg(long)]
        receipt_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    if let Command::Version { output } = &cli.command {
        return print_version(*output);
    }
    if let Command::Setup(arguments) = &cli.command {
        return product::setup(arguments.clone()).await;
    }
    if let Command::Doctor(arguments) = &cli.command {
        return product::doctor(arguments.clone()).await;
    }
    if let Command::Status(arguments) = &cli.command {
        return product::status(arguments.clone()).await;
    }
    if let Command::Serve(arguments) = &cli.command {
        return product::serve(arguments.clone()).await;
    }
    if let Command::Upgrade(arguments) = &cli.command {
        return product::upgrade(arguments.clone()).await;
    }
    if let Command::Rollback(arguments) = &cli.command {
        return product::rollback(arguments.clone());
    }
    if let Command::Uninstall(arguments) = &cli.command {
        return product::uninstall(arguments.clone());
    }
    if let Command::Service(arguments) = &cli.command {
        return service::run(arguments.clone());
    }
    let native_http_security = NativeHttpSecurity::from_cli(&cli)?;
    native_http_security.validate()?;
    NATIVE_HTTP_SECURITY
        .set(native_http_security)
        .map_err(|_| "native HTTP security was initialized more than once".to_owned())?;
    NATS_CLIENT_SECURITY
        .set(NatsClientSecurity::from_cli(&cli))
        .map_err(|_| "NATS client security was initialized more than once".to_owned())?;
    let inline_native_bearer = cli
        .native_bearer_token
        .or_else(|| env::var("GETAIP_NATIVE_BEARER_TOKEN").ok())
        .filter(|token| !token.trim().is_empty());
    let native_bearer_file = cli
        .native_bearer_token_file
        .or_else(|| environment_path("GETAIP_NATIVE_BEARER_TOKEN_FILE"));
    if inline_native_bearer.is_some() && native_bearer_file.is_some() {
        return Err(
            "native bearer token and GETAIP_NATIVE_BEARER_TOKEN_FILE are mutually exclusive"
                .to_owned(),
        );
    }
    let native_bearer = match (inline_native_bearer, native_bearer_file) {
        (Some(token), None) => Some(token),
        (None, Some(path)) => Some(
            String::from_utf8(read_secret_file(&path, 16 * 1024)?)
                .map_err(|_| "native bearer-token file must contain valid UTF-8".to_owned())?
                .trim()
                .to_owned(),
        ),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("credential conflict checked above"),
    };
    if native_bearer.as_ref().is_some_and(|token| token.is_empty()) {
        return Err("native bearer-token file must not be empty".to_owned());
    }
    NATIVE_BEARER_TOKEN
        .set(native_bearer)
        .map_err(|_| "native bearer token was initialized more than once".to_owned())?;
    match cli.command {
        Command::Version { .. } => unreachable!("version handled before security initialization"),
        Command::Setup(_) => unreachable!("setup handled before security initialization"),
        Command::Doctor(_) => unreachable!("doctor handled before security initialization"),
        Command::Status(_) => unreachable!("status handled before security initialization"),
        Command::Serve(_) => unreachable!("serve handled before security initialization"),
        Command::Upgrade(_) => unreachable!("upgrade handled before security initialization"),
        Command::Rollback(_) => unreachable!("rollback handled before security initialization"),
        Command::Uninstall(_) => unreachable!("uninstall handled before security initialization"),
        Command::Service(_) => unreachable!("service handled before security initialization"),
        Command::Schema {
            command: SchemaCommand::Export { output },
        } => export_schemas(output),
        Command::Nats {
            command: NatsCommand::SignerDid,
        } => print_nats_signer_did(),
        Command::Manifest {
            command: ManifestCommand::Fetch { url },
        } => {
            let manifest = fetch_manifest(&url).await?;
            print_json(&manifest)
        }
        Command::Manifest {
            command:
                ManifestCommand::FetchNats {
                    server_url,
                    trust_domain,
                    service,
                    version,
                },
        } => fetch_manifest_nats(&server_url, &trust_domain, &service, &version).await,
        Command::Manifest {
            command: ManifestCommand::Validate { path },
        } => validate_manifest(path),
        Command::Capability {
            command:
                CapabilityCommand::List {
                    url,
                    capability_id,
                    text,
                    profile,
                    cursor,
                    limit,
                    signed_native,
                },
        } => {
            if signed_native {
                list_capabilities_signed_native(&url, capability_id, text, profile, cursor, limit)
                    .await
            } else {
                get_http_json(
                    &url,
                    "/aip/v1/capabilities",
                    vec![
                        ("capability_id", capability_id),
                        ("text", text),
                        ("profile", profile),
                        ("cursor", cursor),
                        ("limit", limit.map(|value| value.to_string())),
                    ],
                )
                .await
            }
        }
        Command::Action {
            command:
                ActionCommand::Call {
                    url,
                    capability_id,
                    input,
                    options,
                },
        } => call_action(&url, &capability_id, &input, &options).await,
        Command::Action {
            command:
                ActionCommand::CallNats {
                    server_url,
                    capability_id,
                    input,
                    options,
                    trust_domain,
                    service,
                    version,
                },
        } => {
            call_action_nats(
                &server_url,
                &capability_id,
                &input,
                &options,
                &trust_domain,
                &service,
                &version,
            )
            .await
        }
        Command::Action {
            command:
                ActionCommand::List {
                    url,
                    state,
                    capability_id,
                    session_id,
                    principal_id,
                    approval_id,
                    transaction_id,
                    cursor,
                    limit,
                    include_results,
                    include_receipts,
                },
        } => {
            get_http_json(
                &url,
                "/aip/v1/actions",
                vec![
                    ("state", state),
                    ("capability_id", capability_id),
                    ("session_id", session_id),
                    ("principal_id", principal_id),
                    ("approval_id", approval_id),
                    ("transaction_id", transaction_id),
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                    (
                        "include_results",
                        include_results.then(|| "true".to_owned()),
                    ),
                    (
                        "include_receipts",
                        include_receipts.then(|| "true".to_owned()),
                    ),
                ],
            )
            .await
        }
        Command::Action {
            command:
                ActionCommand::Status {
                    url,
                    action_id,
                    include_result,
                    include_receipts,
                    include_chunks,
                    wait_ms,
                },
        } => {
            get_http_json(
                &url,
                &format!("/aip/v1/actions/{action_id}"),
                vec![
                    ("include_result", include_result.then(|| "true".to_owned())),
                    (
                        "include_receipts",
                        include_receipts.then(|| "true".to_owned()),
                    ),
                    ("include_chunks", include_chunks.then(|| "true".to_owned())),
                    ("wait_ms", wait_ms.map(|value| value.to_string())),
                ],
            )
            .await
        }
        Command::Action {
            command:
                ActionCommand::Result {
                    url,
                    action_id,
                    wait_ms,
                    include_receipt,
                    include_terminal_events,
                },
        } => {
            get_http_json(
                &url,
                &format!("/aip/v1/actions/{action_id}/result"),
                vec![
                    ("wait_ms", wait_ms.map(|value| value.to_string())),
                    (
                        "include_receipt",
                        include_receipt.then(|| "true".to_owned()),
                    ),
                    (
                        "include_terminal_events",
                        include_terminal_events.then(|| "true".to_owned()),
                    ),
                ],
            )
            .await
        }
        Command::Action {
            command:
                ActionCommand::Events {
                    url,
                    action_id,
                    cursor,
                    limit,
                    kinds,
                    include_chunks,
                    follow,
                },
        } => {
            get_http_json(
                &url,
                &format!("/aip/v1/actions/{action_id}/events"),
                vec![
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                    ("kinds", joined(kinds)),
                    ("include_chunks", include_chunks.then(|| "true".to_owned())),
                    ("follow", follow.then(|| "true".to_owned())),
                ],
            )
            .await
        }
        Command::Action {
            command:
                ActionCommand::Cancel {
                    url,
                    action_id,
                    reason,
                },
        } => {
            post_http_json(
                &url,
                &format!("/aip/v1/actions/{action_id}/cancel"),
                json!({ "reason": reason }),
            )
            .await
        }
        Command::Events {
            command:
                EventsCommand::List {
                    url,
                    cursor,
                    limit,
                    kinds,
                    follow,
                },
        } => {
            get_http_json(
                &url,
                "/aip/v1/events",
                vec![
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                    ("kinds", joined(kinds)),
                    ("follow", follow.then(|| "true".to_owned())),
                ],
            )
            .await
        }
        Command::Session {
            command:
                SessionCommand::List {
                    url,
                    principal_id,
                    status,
                    cursor,
                    limit,
                },
        } => {
            get_http_json(
                &url,
                "/aip/v1/sessions",
                vec![
                    ("principal_id", principal_id),
                    ("status", status),
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                ],
            )
            .await
        }
        Command::Session {
            command: SessionCommand::Get { url, session_id },
        } => get_http_json(&url, &format!("/aip/v1/sessions/{session_id}"), Vec::new()).await,
        Command::Session {
            command:
                SessionCommand::Close {
                    url,
                    session_id,
                    reason,
                },
        } => {
            post_http_json(
                &url,
                &format!("/aip/v1/sessions/{session_id}/close"),
                json!({ "reason": reason }),
            )
            .await
        }
        Command::Session {
            command:
                SessionCommand::Resume {
                    url,
                    session_id,
                    resume_token,
                    last_event_cursor,
                },
        } => {
            post_http_json(
                &url,
                &format!("/aip/v1/sessions/{session_id}/resume"),
                json!({
                    "resume_token": resume_token,
                    "last_event_cursor": last_event_cursor
                }),
            )
            .await
        }
        Command::Approval {
            command:
                ApprovalCommand::List {
                    url,
                    cursor,
                    limit,
                    kinds,
                },
        } => list_approvals(&url, cursor, limit, &kinds).await,
        Command::Approval {
            command:
                ApprovalCommand::Records {
                    url,
                    status,
                    approver,
                    requester,
                    tenant_id,
                    cursor,
                    limit,
                    include_action_status,
                    include_receipts,
                },
        } => {
            get_http_json(
                &url,
                "/aip/v1/approvals",
                vec![
                    ("status", status),
                    ("approver", approver),
                    ("requester", requester),
                    ("tenant_id", tenant_id),
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                    (
                        "include_action_status",
                        include_action_status.then(|| "true".to_owned()),
                    ),
                    (
                        "include_receipts",
                        include_receipts.then(|| "true".to_owned()),
                    ),
                ],
            )
            .await
        }
        Command::Approval {
            command:
                ApprovalCommand::Get {
                    url,
                    approval_id,
                    include_action_status,
                    include_receipts,
                },
        } => {
            get_http_json(
                &url,
                &format!("/aip/v1/approvals/{approval_id}"),
                vec![
                    (
                        "include_action_status",
                        include_action_status.then(|| "true".to_owned()),
                    ),
                    (
                        "include_receipts",
                        include_receipts.then(|| "true".to_owned()),
                    ),
                ],
            )
            .await
        }
        Command::Approval {
            command: ApprovalCommand::Request { url, request },
        } => submit_approval_request(&url, &request).await,
        Command::Approval {
            command: ApprovalCommand::Decide { url, decision },
        } => submit_approval_decision(&url, &decision).await,
        Command::Approval {
            command:
                ApprovalCommand::ListNats {
                    server_url,
                    cursor,
                    limit,
                    kinds,
                    trust_domain,
                    service,
                    version,
                },
        } => {
            list_approvals_nats(
                &server_url,
                cursor,
                limit,
                &kinds,
                &trust_domain,
                &service,
                &version,
            )
            .await
        }
        Command::Approval {
            command:
                ApprovalCommand::RequestNats {
                    server_url,
                    request,
                    trust_domain,
                    service,
                    version,
                },
        } => {
            submit_approval_request_nats(&server_url, &request, &trust_domain, &service, &version)
                .await
        }
        Command::Approval {
            command:
                ApprovalCommand::DecideNats {
                    server_url,
                    decision,
                    trust_domain,
                    service,
                    version,
                },
        } => {
            submit_approval_decision_nats(&server_url, &decision, &trust_domain, &service, &version)
                .await
        }
        Command::Transaction {
            command:
                TransactionCommand::Get {
                    url,
                    transaction_id,
                    plan_id,
                    action_id,
                    include_result,
                    include_receipts,
                },
        } => {
            let selectors = [
                transaction_id.as_ref(),
                plan_id.as_ref(),
                action_id.as_ref(),
            ]
            .into_iter()
            .filter(|value| value.is_some())
            .count();
            if selectors != 1 {
                return Err(
                    "pass exactly one of --transaction-id, --plan-id, or --action-id".to_owned(),
                );
            }
            let (path, params) = if let Some(transaction_id) = transaction_id {
                (
                    format!("/aip/v1/transactions/{transaction_id}"),
                    vec![
                        ("include_result", include_result.then(|| "true".to_owned())),
                        (
                            "include_receipts",
                            include_receipts.then(|| "true".to_owned()),
                        ),
                    ],
                )
            } else if let Some(plan_id) = plan_id {
                (
                    format!("/aip/v1/transactions/by-plan/{plan_id}"),
                    vec![
                        ("include_result", include_result.then(|| "true".to_owned())),
                        (
                            "include_receipts",
                            include_receipts.then(|| "true".to_owned()),
                        ),
                    ],
                )
            } else if let Some(action_id) = action_id {
                (
                    format!("/aip/v1/transactions/by-action/{action_id}"),
                    vec![
                        ("include_result", include_result.then(|| "true".to_owned())),
                        (
                            "include_receipts",
                            include_receipts.then(|| "true".to_owned()),
                        ),
                    ],
                )
            } else {
                return Err("pass exactly one transaction selector".to_owned());
            };
            get_http_json(&url, &path, params).await
        }
        Command::Audit {
            command:
                AuditCommand::Events {
                    url,
                    action_id,
                    session_id,
                    principal_id,
                    transaction_id,
                    from,
                    to,
                    cursor,
                    limit,
                    include_receipts,
                    export,
                },
        } => {
            get_http_json(
                &url,
                "/aip/v1/audit/events",
                vec![
                    ("action_id", action_id),
                    ("session_id", session_id),
                    ("principal_id", principal_id),
                    ("transaction_id", transaction_id),
                    ("from", from),
                    ("to", to),
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                    (
                        "include_receipts",
                        include_receipts.then(|| "true".to_owned()),
                    ),
                    ("export", export.then(|| "true".to_owned())),
                ],
            )
            .await
        }
        Command::Resource {
            command:
                ResourceCommand::List {
                    url,
                    capability_id,
                    kind,
                    cursor,
                    limit,
                },
        } => {
            get_http_json(
                &url,
                "/aip/v1/resources",
                vec![
                    ("capability_id", capability_id),
                    ("kind", kind),
                    ("cursor", cursor),
                    ("limit", limit.map(|value| value.to_string())),
                ],
            )
            .await
        }
        Command::Resource {
            command:
                ResourceCommand::Read {
                    url,
                    resource_id,
                    version,
                    accept,
                },
        } => {
            get_http_json(
                &url,
                &format!("/aip/v1/resources/{resource_id}"),
                vec![("version", version), ("accept", joined(accept))],
            )
            .await
        }
        Command::Conformance {
            command: ConformanceCommand::Run { envelope },
        } => run_conformance(envelope),
        Command::Mcp {
            command:
                McpCommand::Inspect {
                    url,
                    bearer_token,
                    command,
                    args,
                },
        } => {
            inspect_mcp(
                url.as_deref(),
                bearer_token.as_deref(),
                command.as_deref(),
                &args,
            )
            .await
        }
        Command::Mcp {
            command:
                McpCommand::CallTool {
                    tool,
                    arguments,
                    url,
                    bearer_token,
                    command,
                    args,
                },
        } => {
            call_mcp_tool(
                &tool,
                &arguments,
                url.as_deref(),
                bearer_token.as_deref(),
                command.as_deref(),
                &args,
            )
            .await
        }
        Command::Mcp {
            command:
                McpCommand::Conformance {
                    url,
                    bearer_token,
                    command,
                    args,
                },
        } => {
            mcp_conformance(
                url.as_deref(),
                bearer_token.as_deref(),
                command.as_deref(),
                &args,
            )
            .await
        }
        Command::Mcp {
            command: McpCommand::ServeStdio { url, bearer_token },
        } => serve_mcp_stdio_proxy(&url, bearer_token.as_deref()).await,
        Command::Mcp {
            command:
                McpCommand::Bridge {
                    server,
                    bind,
                    url,
                    bearer_token,
                    command,
                    args,
                },
        } => {
            mcp_bridge(
                server,
                bind,
                url.as_deref(),
                bearer_token.as_deref(),
                command.as_deref(),
                &args,
            )
            .await
        }
        Command::Connector {
            command:
                ConnectorCommand::Test {
                    url,
                    capabilities,
                    invoke_capabilities,
                    input,
                    expect_status,
                },
        } => {
            test_connector(
                &url,
                &capabilities,
                &invoke_capabilities,
                &input,
                &expect_status,
            )
            .await
        }
        Command::Connector {
            command:
                ConnectorCommand::RegistryMigrate {
                    database_url_file,
                    control_max_connections,
                    data_max_connections,
                    acquire_timeout_ms,
                },
        } => {
            migrate_connector_registry(
                &database_url_file,
                control_max_connections,
                data_max_connections,
                acquire_timeout_ms,
            )
            .await
        }
        Command::Connector {
            command: ConnectorCommand::Registry { command },
        } => match command {
            ConnectorRegistryCommand::SignEvidence {
                kind,
                artifact_digest,
                manifest_digest,
                document,
                signing_seed_file,
                signer_identity,
                valid_for_seconds,
            } => sign_connector_evidence(
                kind,
                &artifact_digest,
                &manifest_digest,
                &document,
                &signing_seed_file,
                &signer_identity,
                valid_for_seconds,
            ),
            ConnectorRegistryCommand::SignPackage {
                package,
                signing_seed_file,
                signer_identity,
            } => sign_connector_admission_package(&package, &signing_seed_file, &signer_identity),
            ConnectorRegistryCommand::Plan {
                package,
                trust_policy,
            } => plan_connector_admission(&package, &trust_policy),
            ConnectorRegistryCommand::Apply {
                package,
                trust_policy,
                database,
            } => apply_connector_admission(&package, &trust_policy, &database).await,
            ConnectorRegistryCommand::Status {
                package_id,
                revision,
                database,
            } => connector_admission_status(&package_id, revision, &database).await,
            ConnectorRegistryCommand::Revoke {
                package_id,
                revision,
                reason,
                database,
            } => revoke_connector_admission(&package_id, revision, &reason, &database).await,
            ConnectorRegistryCommand::Abandon {
                package_id,
                revision,
                reason,
                database,
            } => abandon_connector_admission(&package_id, revision, &reason, &database).await,
            ConnectorRegistryCommand::SetBinding {
                tenant_id,
                capability_id,
                instance_id,
                priority,
                policy_revision,
                credential_revision_ref,
                quota_policy_ref,
                state,
                database,
            } => {
                set_connector_binding(
                    &tenant_id,
                    &capability_id,
                    &instance_id,
                    priority,
                    policy_revision,
                    credential_revision_ref,
                    quota_policy_ref,
                    state,
                    &database,
                )
                .await
            }
        },
        Command::Connector {
            command: ConnectorCommand::Orchestration { command },
        } => match command {
            ConnectorOrchestrationCommand::Plan {
                package,
                admission_trust_policy,
                intent,
                observed,
                orchestration_policy,
            } => plan_connector_orchestration(
                &package,
                &admission_trust_policy,
                &intent,
                &observed,
                &orchestration_policy,
            ),
            ConnectorOrchestrationCommand::Sign {
                package,
                admission_trust_policy,
                intent,
                observed,
                orchestration_policy,
                signing_seed_file,
                signer_identity,
            } => sign_connector_orchestration(
                &package,
                &admission_trust_policy,
                &intent,
                &observed,
                &orchestration_policy,
                &signing_seed_file,
                &signer_identity,
            ),
            ConnectorOrchestrationCommand::Verify {
                plan,
                current_observed,
                orchestration_policy,
            } => verify_connector_orchestration(&plan, &current_observed, &orchestration_policy),
        },
        Command::Receipt {
            command: ReceiptCommand::Verify { path },
        } => verify_receipt_chain(path),
        Command::Receipt {
            command:
                ReceiptCommand::Get {
                    url,
                    chain_id,
                    receipt_id,
                },
        } => {
            let selectors = [chain_id.as_ref(), receipt_id.as_ref()]
                .into_iter()
                .filter(|value| value.is_some())
                .count();
            if selectors != 1 {
                return Err("pass exactly one of --chain-id or --receipt-id".to_owned());
            }
            if let Some(chain_id) = chain_id {
                get_http_json(&url, &format!("/aip/v1/receipts/{chain_id}"), Vec::new()).await
            } else if let Some(receipt_id) = receipt_id {
                get_http_json(
                    &url,
                    &format!("/aip/v1/receipts/by-receipt/{receipt_id}"),
                    Vec::new(),
                )
                .await
            } else {
                Err("pass exactly one of --chain-id or --receipt-id".to_owned())
            }
        }
    }
}

fn print_version(output: OutputFormat) -> Result<(), String> {
    let version = BuildVersion::current();
    match output {
        OutputFormat::Text => {
            let source = version.source_commit.as_deref().unwrap_or("unknown-source");
            let state = if version.release_build {
                "release"
            } else {
                "development"
            };
            println!(
                "getaip {} (AIP {}; {state}; {source})",
                version.software_version, version.aip_protocol_version
            );
            Ok(())
        }
        OutputFormat::Json => print_json(
            &serde_json::to_value(VersionOutput {
                schema: "org.getaip.cli.version.v1",
                product: "GetAIP",
                version,
            })
            .map_err(|error| error.to_string())?,
        ),
    }
}

fn export_schemas(output: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    for (file_name, schema) in SchemaRegistry::new().all() {
        let path = output.join(file_name);
        let data = serde_json::to_string_pretty(&schema).map_err(|error| error.to_string())?;
        fs::write(path, data).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn validate_manifest(path: PathBuf) -> Result<(), String> {
    let value = read_json_file(&path)?;
    SchemaRegistry::new()
        .validate_json(SchemaName::Manifest, &value)
        .map_err(|error| error.to_string())?;
    println!("manifest valid");
    Ok(())
}

async fn list_capabilities_signed_native(
    url: &str,
    capability_id: Option<String>,
    text: Option<String>,
    profile: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
) -> Result<(), String> {
    let mut input = serde_json::Map::new();
    for (key, value) in [
        ("capability_id", capability_id),
        ("text", text),
        ("profile", profile),
        ("cursor", cursor),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            input.insert(key.to_owned(), Value::String(value));
        }
    }
    if let Some(limit) = limit {
        input.insert("limit".to_owned(), json!(limit));
    }
    let response = call_action_envelope(
        url,
        CAPABILITY_CATALOG_QUERY_ID,
        Value::Object(input),
        &ActionOptions::default(),
    )
    .await?;
    let MessageBody::ActionResult(result) = response.body else {
        return Err("capability catalog action returned a non-action response".to_owned());
    };
    if result.status != aip_core::ActionResultStatus::Completed {
        return Err(format!(
            "capability catalog action returned terminal status {:?}",
            result.status
        ));
    }
    let output = result
        .output
        .ok_or_else(|| "capability catalog action returned no output".to_owned())?;
    print_json(&output)
}

async fn call_action(
    url: &str,
    capability_id: &str,
    input: &str,
    options: &ActionOptions,
) -> Result<(), String> {
    let input = parse_json_arg(input)?;
    let response = call_action_envelope(url, capability_id, input, options).await?;
    print_json(&response)
}

async fn call_action_envelope(
    url: &str,
    capability_id: &str,
    input: Value,
    options: &ActionOptions,
) -> Result<Envelope, String> {
    let capability_id = CapabilityId::parse(capability_id).map_err(|error| error.to_string())?;
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(build_action(
        capability_id,
        input,
        options,
    )?)));
    envelope.from = Some(cli_principal()?);
    post_envelope(url, envelope).await
}

async fn fetch_manifest_nats(
    server_url: &str,
    trust_domain: &str,
    service: &str,
    version: &str,
) -> Result<(), String> {
    let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
        profiles: Vec::new(),
        filter: None,
    }));
    let response = request_nats(
        server_url,
        nats_subject(trust_domain, service, version, MessageType::ManifestRequest),
        envelope,
    )
    .await?;
    print_json(&response)
}

async fn call_action_nats(
    server_url: &str,
    capability_id: &str,
    input: &str,
    options: &ActionOptions,
    trust_domain: &str,
    service: &str,
    version: &str,
) -> Result<(), String> {
    let input = parse_json_arg(input)?;
    let capability_id = CapabilityId::parse(capability_id).map_err(|error| error.to_string())?;
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(build_action(
        capability_id,
        input,
        options,
    )?)));
    envelope.from = Some(cli_principal()?);
    let response = request_nats(
        server_url,
        nats_subject(trust_domain, service, version, MessageType::Action),
        envelope,
    )
    .await?;
    print_json(&response)
}

async fn list_approvals(
    url: &str,
    cursor: Option<String>,
    limit: u32,
    kinds: &[String],
) -> Result<(), String> {
    let mut envelope = Envelope::new(MessageBody::EventStreamRequest(EventStreamRequest {
        cursor,
        limit: Some(limit),
        kinds: approval_event_kinds(kinds),
    }));
    envelope.from = Some(cli_principal()?);
    let response = post_envelope(url, envelope).await?;
    print_json(&response)
}

async fn list_approvals_nats(
    server_url: &str,
    cursor: Option<String>,
    limit: u32,
    kinds: &[String],
    trust_domain: &str,
    service: &str,
    version: &str,
) -> Result<(), String> {
    let mut envelope = Envelope::new(MessageBody::EventStreamRequest(EventStreamRequest {
        cursor,
        limit: Some(limit),
        kinds: approval_event_kinds(kinds),
    }));
    envelope.from = Some(cli_principal()?);
    let response = request_nats(
        server_url,
        nats_subject(
            trust_domain,
            service,
            version,
            MessageType::EventStreamRequest,
        ),
        envelope,
    )
    .await?;
    print_json(&response)
}

async fn submit_approval_request(url: &str, request: &str) -> Result<(), String> {
    let request = parse_typed_json_arg::<ApprovalRequest>(request)?;
    let mut envelope = Envelope::new(MessageBody::ApprovalRequest(Box::new(request)));
    envelope.from = Some(cli_principal()?);
    let response = post_envelope(url, envelope).await?;
    print_json(&response)
}

async fn submit_approval_decision(url: &str, decision: &str) -> Result<(), String> {
    let decision = parse_typed_json_arg::<ApprovalDecision>(decision)?;
    let mut envelope = Envelope::new(MessageBody::ApprovalDecision(Box::new(decision)));
    envelope.from = Some(cli_principal()?);
    let response = post_envelope(url, envelope).await?;
    print_json(&response)
}

async fn submit_approval_request_nats(
    server_url: &str,
    request: &str,
    trust_domain: &str,
    service: &str,
    version: &str,
) -> Result<(), String> {
    let request = parse_typed_json_arg::<ApprovalRequest>(request)?;
    let mut envelope = Envelope::new(MessageBody::ApprovalRequest(Box::new(request)));
    envelope.from = Some(cli_principal()?);
    let response = request_nats(
        server_url,
        nats_subject(trust_domain, service, version, MessageType::ApprovalRequest),
        envelope,
    )
    .await?;
    print_json(&response)
}

async fn submit_approval_decision_nats(
    server_url: &str,
    decision: &str,
    trust_domain: &str,
    service: &str,
    version: &str,
) -> Result<(), String> {
    let decision = parse_typed_json_arg::<ApprovalDecision>(decision)?;
    let mut envelope = Envelope::new(MessageBody::ApprovalDecision(Box::new(decision)));
    envelope.from = Some(cli_principal()?);
    let response = request_nats(
        server_url,
        nats_subject(
            trust_domain,
            service,
            version,
            MessageType::ApprovalDecision,
        ),
        envelope,
    )
    .await?;
    print_json(&response)
}

fn run_conformance(path: Option<PathBuf>) -> Result<(), String> {
    let suite = CoreConformance::new();
    let report = if let Some(path) = path {
        let envelope: Envelope =
            serde_json::from_value(read_json_file(&path)?).map_err(|error| error.to_string())?;
        suite.check_envelope(&envelope)
    } else {
        CoreConformance::check_message_body(&MessageBody::ManifestRequest(
            aip_core::ManifestRequest {
                profiles: Vec::new(),
                filter: None,
            },
        ))
    };
    print_json(&json!({
        "name": report.name,
        "passed": report.passed,
        "detail": report.detail
    }))
}

async fn inspect_mcp(
    url: Option<&str>,
    bearer_token: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<(), String> {
    let client = build_mcp_client("inspect", url, bearer_token, command, args)?;
    client
        .initialize()
        .await
        .map_err(|error| error.to_string())?;
    let manifest = client
        .refresh_manifest()
        .await
        .map_err(|error| error.to_string())?;
    print_json(&manifest)
}

async fn call_mcp_tool(
    tool: &str,
    arguments: &str,
    url: Option<&str>,
    bearer_token: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<(), String> {
    let arguments = parse_json_arg(arguments)?;
    let client = build_mcp_client("call-tool", url, bearer_token, command, args)?;
    client
        .initialize()
        .await
        .map_err(|error| error.to_string())?;
    let result = client
        .call_tool(tool, arguments)
        .await
        .map_err(|error| error.to_string())?;
    print_json(&result)
}

async fn mcp_conformance(
    url: Option<&str>,
    bearer_token: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<(), String> {
    let client = build_mcp_client("conformance", url, bearer_token, command, args)?;
    let report = aip_mcp_conformance::run_client_conformance(&client).await;
    print_json(&report)?;
    report.ensure_success().map_err(|error| error.to_string())
}

async fn serve_mcp_stdio_proxy(url: &str, bearer_token: Option<&str>) -> Result<(), String> {
    let endpoint = mcp_endpoint_url(url)?;
    let bearer_token = mcp_bearer_token(bearer_token);
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await.map_err(|error| error.to_string())? {
        if line.trim().is_empty() {
            continue;
        }
        let frame = decode_frame(line.as_bytes()).map_err(|error| error.to_string())?;
        let response = post_mcp_http_frame(&endpoint, bearer_token.as_deref(), frame).await?;
        if let Some(response) = response {
            let bytes = encode_frame(&McpStdioFrame::Response(response))
                .map_err(|error| error.to_string())?;
            stdout
                .write_all(&bytes)
                .await
                .map_err(|error| error.to_string())?;
            stdout.flush().await.map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

async fn mcp_bridge(
    server: McpBridgeServer,
    bind: SocketAddr,
    url: Option<&str>,
    bearer_token: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<(), String> {
    match server {
        McpBridgeServer::Stdio => {
            let url = url.ok_or_else(|| "`--server stdio` requires --url".to_owned())?;
            serve_mcp_stdio_proxy(url, bearer_token).await
        }
        McpBridgeServer::Http => {
            if url.is_some() {
                return Err("`--server http` uses --command, not --url".to_owned());
            }
            let command = command.ok_or_else(|| "`--server http` requires --command".to_owned())?;
            serve_mcp_http_bridge(bind, command, args).await
        }
    }
}

async fn serve_mcp_http_bridge(
    bind: SocketAddr,
    command: &str,
    args: &[String],
) -> Result<(), String> {
    let transport =
        Arc::new(McpStdioClientTransport::spawn(command, args).map_err(|error| error.to_string())?);
    let app = Router::new()
        .route("/mcp", post(handle_mcp_bridge_post))
        .route("/mcp/v1", post(handle_mcp_bridge_post))
        .with_state(transport);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    eprintln!("getaip MCP HTTP bridge listening on http://{bind}/mcp");
    axum::serve(listener, app)
        .await
        .map_err(|error| error.to_string())
}

async fn handle_mcp_bridge_post(
    State(transport): State<Arc<McpStdioClientTransport>>,
    _headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    match decode_json_rpc_value(payload) {
        Ok(McpHttpMessage::Request(request)) => match transport.request(request.clone()).await {
            Ok(response) => Json(response).into_response(),
            Err(error) => (
                StatusCode::BAD_GATEWAY,
                Json(aip_profile_mcp::JsonRpcResponse::error(
                    request.id,
                    aip_profile_mcp::JsonRpcError {
                        code: -32000,
                        message: error.to_string(),
                        data: Some(json!({ "component": "aip.cli.mcp_bridge" })),
                    },
                )),
            )
                .into_response(),
        },
        Ok(McpHttpMessage::Notification(notification)) => {
            match transport.notify(notification).await {
                Ok(()) => StatusCode::ACCEPTED.into_response(),
                Err(error) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "error": error.to_string() })),
                )
                    .into_response(),
            }
        }
        Ok(McpHttpMessage::Response(_response)) => StatusCode::ACCEPTED.into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn migrate_connector_registry(
    database_url_file: &Path,
    control_max_connections: u32,
    data_max_connections: u32,
    acquire_timeout_ms: u64,
) -> Result<(), String> {
    if control_max_connections == 0 || data_max_connections == 0 || acquire_timeout_ms == 0 {
        return Err("connector registry migration bounds must be greater than zero".to_owned());
    }
    let database_url = String::from_utf8(read_secret_file(database_url_file, 16 * 1024)?)
        .map_err(|_| "connector registry database URL file must contain UTF-8".to_owned())?;
    let database_url = database_url.trim();
    if database_url.is_empty() {
        return Err("connector registry database URL must not be empty".to_owned());
    }
    let registry = PostgresConnectorRegistry::connect_with_urls(
        database_url,
        database_url,
        RegistryPoolLimits {
            control_max_connections,
            data_max_connections,
            acquire_timeout: std::time::Duration::from_millis(acquire_timeout_ms),
        },
    )
    .await
    .map_err(|error| error.to_string())?;
    let installed = registry
        .installed_schema_version()
        .await
        .map_err(|error| error.to_string())?;
    if installed != CONNECTOR_REGISTRY_SCHEMA_VERSION {
        return Err(format!(
            "connector registry schema version {installed} does not match required version {CONNECTOR_REGISTRY_SCHEMA_VERSION}"
        ));
    }
    println!(
        "{}",
        json!({
            "status": "ok",
            "component": "aip-connector-registry-postgres",
            "schema_version": installed
        })
    );
    Ok(())
}

fn sign_connector_evidence(
    kind: CliEvidenceKind,
    artifact_digest: &str,
    manifest_digest: &str,
    document: &Path,
    signing_seed_file: &Path,
    signer_identity: &str,
    valid_for_seconds: u64,
) -> Result<(), String> {
    if !(60..=30 * 24 * 60 * 60).contains(&valid_for_seconds) {
        return Err("evidence validity must be between 60 seconds and 30 days".to_owned());
    }
    if signer_identity.trim().is_empty() || signer_identity.len() > 512 {
        return Err("evidence signer identity must contain 1 to 512 bytes".to_owned());
    }
    let kind = EvidenceKind::from(kind);
    let document = read_bounded_json::<Value>(document, 8 * 1024 * 1024)?;
    let issued_at = OffsetDateTime::now_utc();
    let statement = EvidenceStatement {
        schema_version: EVIDENCE_STATEMENT_SCHEMA.to_owned(),
        kind,
        artifact_digest: artifact_digest.to_owned(),
        manifest_digest: manifest_digest.to_owned(),
        document_digest: digest_json(&document).map_err(|error| error.to_string())?,
        signer_identity: signer_identity.to_owned(),
        issued_at,
        expires_at: issued_at
            + time::Duration::seconds(
                i64::try_from(valid_for_seconds)
                    .map_err(|_| "evidence validity exceeds i64".to_owned())?,
            ),
        outcome: kind.required_outcome(),
    };
    let signing_key = read_ed25519_signing_key(signing_seed_file, "evidence")?;
    let signed =
        sign_evidence(statement, document, &signing_key).map_err(|error| error.to_string())?;
    print_json(&signed)
}

fn sign_connector_admission_package(
    package: &Path,
    signing_seed_file: &Path,
    signer_identity: &str,
) -> Result<(), String> {
    if signer_identity.trim().is_empty() || signer_identity.len() > 512 {
        return Err("package signer identity must contain 1 to 512 bytes".to_owned());
    }
    let package = read_bounded_json::<AdmissionPackage>(package, 32 * 1024 * 1024)?;
    let signing_key = read_ed25519_signing_key(signing_seed_file, "admission package")?;
    let signed = sign_admission_package(package, signer_identity.to_owned(), &signing_key)
        .map_err(|error| error.to_string())?;
    print_json(&signed)
}

fn plan_connector_admission(package: &Path, trust_policy: &Path) -> Result<(), String> {
    let verified = verified_connector_admission(package, trust_policy)?;
    print_json(&json!({
        "status": "verified",
        "write_performed": false,
        "package_id": verified.package.package_id,
        "revision": verified.package.revision,
        "package_digest": verified.package_digest,
        "connector_type_id": verified.package.connector_type.id,
        "version_id": verified.connector_version.id,
        "version_status": verified.connector_version.status,
        "signer_identity": verified.signer_identity,
        "artifact_digest": verified.connector_version.attestation.artifact_digest,
        "instances": verified.package.instances.len(),
        "replicas": verified.package.replicas.len(),
        "bindings": verified.package.bindings.len(),
        "evidence_documents": verified.package.evidence.len(),
    }))
}

async fn apply_connector_admission(
    package: &Path,
    trust_policy: &Path,
    database: &ConnectorRegistryDatabaseArgs,
) -> Result<(), String> {
    let verified = verified_connector_admission(package, trust_policy)?;
    let registry = connect_registry_admin(database).await?;
    let operation = apply_verified_package(&registry, &verified)
        .await
        .map_err(|error| error.to_string())?;
    print_json(&operation)
}

async fn connector_admission_status(
    package_id: &str,
    revision: Option<u64>,
    database: &ConnectorRegistryDatabaseArgs,
) -> Result<(), String> {
    let registry = connect_registry_admin(database).await?;
    let operation = registry
        .admission_operation(package_id, revision)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "connector admission operation was not found".to_owned())?;
    print_json(&operation)
}

async fn revoke_connector_admission(
    package_id: &str,
    revision: u64,
    reason: &str,
    database: &ConnectorRegistryDatabaseArgs,
) -> Result<(), String> {
    let registry = connect_registry_admin(database).await?;
    let operation = revoke_applied_package(&registry, package_id, revision, reason)
        .await
        .map_err(|error| error.to_string())?;
    print_json(&operation)
}

async fn abandon_connector_admission(
    package_id: &str,
    revision: u64,
    reason: &str,
    database: &ConnectorRegistryDatabaseArgs,
) -> Result<(), String> {
    let registry = connect_registry_admin(database).await?;
    let operation = abandon_failed_package(&registry, package_id, revision, reason)
        .await
        .map_err(|error| error.to_string())?;
    print_json(&operation)
}

#[allow(clippy::too_many_arguments)]
async fn set_connector_binding(
    tenant_id: &str,
    capability_id: &str,
    instance_id: &str,
    priority: u32,
    policy_revision: u64,
    credential_revision_ref: Option<String>,
    quota_policy_ref: Option<String>,
    state: CliBindingState,
    database: &ConnectorRegistryDatabaseArgs,
) -> Result<(), String> {
    if tenant_id.trim().is_empty() || tenant_id.len() > 256 {
        return Err("tenant id must contain 1 to 256 bytes".to_owned());
    }
    if policy_revision == 0 {
        return Err("binding policy revision must be greater than zero".to_owned());
    }
    let capability_id = CapabilityId::parse(capability_id).map_err(|error| error.to_string())?;
    let instance_id = ConnectorInstanceId::parse(instance_id).map_err(|error| error.to_string())?;
    let binding = CapabilityBinding {
        tenant_id: tenant_id.to_owned(),
        capability_id,
        instance_id,
        priority,
        policy_revision,
        credential_revision_ref,
        quota_policy_ref,
        enabled: state.is_enabled(),
    };
    let registry = connect_registry_admin(database).await?;
    registry
        .put_binding(binding.clone())
        .await
        .map_err(|error| error.to_string())?;
    print_json(&binding)
}

fn verified_connector_admission(
    package: &Path,
    trust_policy: &Path,
) -> Result<aip_connector_admission::VerifiedAdmissionPackage, String> {
    let policy = read_bounded_json::<AdmissionTrustPolicy>(trust_policy, 1024 * 1024)?;
    let package = read_bounded_json::<SignedAdmissionPackage>(package, 32 * 1024 * 1024)?;
    verify_admission_package(package, &policy, OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())
}

fn plan_connector_orchestration(
    package: &Path,
    admission_trust_policy: &Path,
    intent: &Path,
    observed: &Path,
    orchestration_policy: &Path,
) -> Result<(), String> {
    let (plan, _) = connector_orchestration_plan(
        package,
        admission_trust_policy,
        intent,
        observed,
        orchestration_policy,
    )?;
    print_json(&plan)
}

fn sign_connector_orchestration(
    package: &Path,
    admission_trust_policy: &Path,
    intent: &Path,
    observed: &Path,
    orchestration_policy: &Path,
    signing_seed_file: &Path,
    signer_identity: &str,
) -> Result<(), String> {
    let (plan, policy) = connector_orchestration_plan(
        package,
        admission_trust_policy,
        intent,
        observed,
        orchestration_policy,
    )?;
    let signing_key = read_ed25519_signing_key(signing_seed_file, "orchestration")?;
    let signer_did = did_key_from_verifying_key(&signing_key.verifying_key());
    if !policy.trusted_signer_dids.contains(&signer_did) {
        return Err(format!(
            "orchestration signing DID `{signer_did}` is not trusted by the executor policy"
        ));
    }
    let signed =
        sign_orchestration_plan(plan, signer_did, signer_identity.to_owned(), &signing_key)
            .map_err(|error| error.to_string())?;
    verify_signed_orchestration_plan(
        signed.clone(),
        &policy.trusted_signer_dids,
        OffsetDateTime::now_utc(),
        &policy.limits,
    )
    .map_err(|error| error.to_string())?;
    print_json(&signed)
}

fn read_ed25519_signing_key(
    path: &Path,
    purpose: &str,
) -> Result<ed25519_dalek::SigningKey, String> {
    let mut encoded = read_secret_file(path, 1_024)?;
    let encoded_text = std::str::from_utf8(&encoded)
        .map_err(|_| format!("{purpose} signing seed must be UTF-8 hexadecimal text"))?;
    let mut decoded = hex::decode(encoded_text)
        .map_err(|_| format!("{purpose} signing seed must be hexadecimal"))?;
    encoded.zeroize();
    let mut seed: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("{purpose} signing seed must encode exactly 32 bytes"))?;
    decoded.zeroize();
    let signing_key = signing_key_from_seed(seed);
    seed.zeroize();
    Ok(signing_key)
}

fn verify_connector_orchestration(
    plan: &Path,
    current_observed: &Path,
    orchestration_policy: &Path,
) -> Result<(), String> {
    let policy = read_bounded_json::<OrchestrationTrustPolicy>(orchestration_policy, 1024 * 1024)?;
    let signed = read_bounded_json::<SignedOrchestrationPlan>(plan, 32 * 1024 * 1024)?;
    let current_observed =
        read_bounded_json::<Vec<ObservedReplica>>(current_observed, 32 * 1024 * 1024)?;
    let verified = verify_signed_orchestration_plan_against_observed(
        signed,
        &policy.trusted_signer_dids,
        current_observed,
        OffsetDateTime::now_utc(),
        &policy.limits,
    )
    .map_err(|error| error.to_string())?;
    let operation_ids =
        orchestration_operation_ids(&verified).map_err(|error| error.to_string())?;
    print_json(&json!({
        "status": "verified",
        "write_performed": false,
        "package_id": verified.intent.package_id,
        "package_revision": verified.intent.package_revision,
        "instance_id": verified.intent.instance_id,
        "generation": verified.intent.generation,
        "operations": verified.operations.len(),
        "operation_ids": operation_ids,
        "snapshot_fenced": true,
    }))
}

fn connector_orchestration_plan(
    package: &Path,
    admission_trust_policy: &Path,
    intent: &Path,
    observed: &Path,
    orchestration_policy: &Path,
) -> Result<(OrchestrationPlan, OrchestrationTrustPolicy), String> {
    let verified = verified_connector_admission(package, admission_trust_policy)?;
    let intent = read_bounded_json::<DeploymentIntent>(intent, 4 * 1024 * 1024)?;
    let observed = read_bounded_json::<Vec<ObservedReplica>>(observed, 32 * 1024 * 1024)?;
    let policy = read_bounded_json::<OrchestrationTrustPolicy>(orchestration_policy, 1024 * 1024)?;
    let plan = reconcile_verified_package(
        &verified,
        intent,
        observed,
        OffsetDateTime::now_utc(),
        &policy.limits,
    )
    .map_err(|error| error.to_string())?;
    Ok((plan, policy))
}

async fn connect_registry_admin(
    database: &ConnectorRegistryDatabaseArgs,
) -> Result<PostgresConnectorRegistry, String> {
    if database.control_max_connections == 0
        || database.data_max_connections == 0
        || database.acquire_timeout_ms == 0
    {
        return Err("connector registry database bounds must be greater than zero".to_owned());
    }
    let database_url = String::from_utf8(read_secret_file(&database.database_url_file, 16 * 1024)?)
        .map_err(|_| "connector registry database URL file must contain UTF-8".to_owned())?;
    let database_url = database_url.trim();
    if database_url.is_empty() {
        return Err("connector registry database URL must not be empty".to_owned());
    }
    PostgresConnectorRegistry::connect_with_urls(
        database_url,
        database_url,
        RegistryPoolLimits {
            control_max_connections: database.control_max_connections,
            data_max_connections: database.data_max_connections,
            acquire_timeout: std::time::Duration::from_millis(database.acquire_timeout_ms),
        },
    )
    .await
    .map_err(|error| error.to_string())
}

fn read_bounded_json<T>(path: &Path, max_bytes: usize) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect JSON file `{}`: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "JSON path `{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(format!(
            "JSON file `{}` size must be between 1 and {max_bytes} bytes",
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read JSON file `{}`: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot decode JSON file `{}`: {error}", path.display()))
}

async fn test_connector(
    url: &str,
    required_capabilities: &[String],
    invoke_capabilities: &[String],
    input: &str,
    expect_status: &str,
) -> Result<(), String> {
    let manifest = fetch_manifest(url).await?;
    let capability_ids = manifest
        .capabilities
        .iter()
        .map(|capability| capability.id.to_string())
        .collect::<Vec<_>>();
    let missing = required_capabilities
        .iter()
        .filter(|required| !capability_ids.contains(required))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!("missing capabilities: {}", missing.join(", ")));
    }
    let input = parse_json_arg(input)?;
    let mut invocations = Vec::new();
    for capability_id in invoke_capabilities {
        let response =
            call_action_envelope(url, capability_id, input.clone(), &ActionOptions::default())
                .await?;
        let status = action_result_status(&response.body)
            .ok_or_else(|| format!("capability `{capability_id}` did not return action_result"))?;
        if status != expect_status {
            return Err(format!(
                "capability `{capability_id}` returned status `{status}`, expected `{expect_status}`"
            ));
        }
        invocations.push(json!({
            "capability_id": capability_id,
            "status": status
        }));
    }
    print_json(&json!({
        "status": "ok",
        "agent": manifest.agent,
        "capability_count": capability_ids.len(),
        "capabilities": capability_ids,
        "invocations": invocations
    }))
}

fn verify_receipt_chain(path: PathBuf) -> Result<(), String> {
    let mut chain: ReceiptChain =
        serde_json::from_value(read_json_file(&path)?).map_err(|error| error.to_string())?;
    let mut previous_hash = None;
    for receipt in &mut chain.receipts {
        if receipt.previous_hash != previous_hash {
            return Err(format!("receipt `{}` previous hash mismatch", receipt.id));
        }
        let actual_hash = hash_receipt(receipt).map_err(|error| error.to_string())?;
        if receipt.hash.as_deref() != Some(actual_hash.as_str()) {
            return Err(format!("receipt `{}` hash mismatch", receipt.id));
        }
        previous_hash = receipt.hash.clone();
    }
    let root_hash = hash_receipt_chain(&chain).map_err(|error| error.to_string())?;
    if chain.root_hash.as_deref() != Some(root_hash.as_str()) {
        return Err("receipt chain root hash mismatch".to_owned());
    }
    print_json(&json!({
        "status": "ok",
        "chain_id": chain.chain_id,
        "receipt_count": chain.receipts.len(),
        "root_hash": root_hash
    }))
}

fn action_result_status(body: &MessageBody) -> Option<&'static str> {
    match body {
        MessageBody::ActionResult(result) => Some(match result.status {
            aip_core::ActionResultStatus::Completed => "completed",
            aip_core::ActionResultStatus::Failed => "failed",
            aip_core::ActionResultStatus::Cancelled => "cancelled",
            aip_core::ActionResultStatus::PendingApproval => "pending_approval",
            aip_core::ActionResultStatus::RequiresHuman => "requires_human",
        }),
        _ => None,
    }
}

async fn fetch_manifest(url: &str) -> Result<Manifest, String> {
    let url = endpoint_url(url, "/aip/v1/manifest")?;
    let response = native_http_request(native_http_client()?.get(url))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = read_bounded_response(response, native_response_limit()?).await?;
    if !status.is_success() {
        return Err(format!(
            "manifest fetch failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    serde_json::from_slice(&body).map_err(|error| error.to_string())
}

async fn get_http_json(
    base_url: &str,
    path: &str,
    params: Vec<(&'static str, Option<String>)>,
) -> Result<(), String> {
    let mut url = endpoint_url(base_url, path)?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in params {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                query.append_pair(key, &value);
            }
        }
    }
    let response = native_http_request(native_http_client()?.get(url))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = read_bounded_response(response, native_response_limit()?).await?;
    if !status.is_success() {
        return Err(format!(
            "AIP HTTP GET failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    let value = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| json!({ "body": String::from_utf8_lossy(&body) }));
    print_json(&value)
}

async fn post_http_json(base_url: &str, path: &str, body: Value) -> Result<(), String> {
    let url = endpoint_url(base_url, path)?;
    let response = native_http_request(native_http_client()?.post(url))
        .json(&body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = read_bounded_response(response, native_response_limit()?).await?;
    if !status.is_success() {
        return Err(format!(
            "AIP HTTP POST failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    let value = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| json!({ "body": String::from_utf8_lossy(&body) }));
    print_json(&value)
}

async fn post_envelope(url: &str, envelope: Envelope) -> Result<Envelope, String> {
    let url = endpoint_url(url, "/aip/v1/messages")?;
    let security = NATIVE_HTTP_SECURITY
        .get()
        .ok_or_else(|| "native HTTP security is not initialized".to_owned())?;
    let envelope = match NATIVE_HTTP_SECURITY.get() {
        Some(security) => security.secure_envelope(envelope)?,
        None => envelope,
    };
    let response = native_http_request(native_http_client()?.post(url))
        .json(&envelope)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = read_bounded_response(response, security.max_response_bytes).await?;
    let response = serde_json::from_slice::<Envelope>(&body).map_err(|error| {
        format!(
            "AIP response is not a valid envelope: {error}; HTTP {status}; body={}",
            String::from_utf8_lossy(&body)
        )
    })?;
    security.verify_response(&envelope, &response)?;
    if let MessageBody::Error(error) = &response.body {
        return Err(format!(
            "AIP peer error {}: {} (HTTP {status})",
            error.error.code, error.error.message
        ));
    }
    if !status.is_success() {
        return Err(format!(
            "AIP request failed with HTTP {status} without a protocol error"
        ));
    }
    Ok(response)
}

fn native_response_limit() -> Result<usize, String> {
    NATIVE_HTTP_SECURITY
        .get()
        .map(|security| security.max_response_bytes)
        .ok_or_else(|| "native HTTP security is not initialized".to_owned())
}

async fn read_bounded_response(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, String> {
    if max_response_bytes == 0 {
        return Err("HTTP response limit must be greater than zero".to_owned());
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(format!(
            "HTTP response exceeded the {max_response_bytes}-byte limit"
        ));
    }
    let initial_capacity = response
        .content_length()
        .unwrap_or(0)
        .min(max_response_bytes as u64) as usize;
    let mut body = Vec::with_capacity(initial_capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("HTTP response read failed: {error}"))?;
        if chunk.len() > max_response_bytes.saturating_sub(body.len()) {
            return Err(format!(
                "HTTP response exceeded the {max_response_bytes}-byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn native_http_request(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match NATIVE_BEARER_TOKEN.get().and_then(Option::as_deref) {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

fn native_http_client() -> Result<reqwest::Client, String> {
    NATIVE_HTTP_SECURITY
        .get()
        .map(NativeHttpSecurity::client)
        .unwrap_or_else(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| format!("native HTTP client failed: {error}"))
        })
}

async fn request_nats(
    server_url: &str,
    subject: NatsSubject,
    envelope: Envelope,
) -> Result<Envelope, String> {
    let security = NATS_CLIENT_SECURITY
        .get()
        .ok_or_else(|| "NATS client security is not initialized".to_owned())?;
    let mut config = NatsTransportConfig::new(server_url, subject);
    config.authentication = security.authentication()?;
    let envelope = security.secure_envelope(envelope)?;
    let transport = NatsTransport::connect(config)
        .await
        .map_err(|error| error.to_string())?;
    let response = transport
        .request(TransportMessage::new(envelope))
        .await
        .map_err(|error| error.to_string())?;
    successful_nats_response(response.envelope)
}

fn successful_nats_response(envelope: Envelope) -> Result<Envelope, String> {
    if let MessageBody::Error(error) = &envelope.body {
        return Err(format!(
            "AIP NATS peer error {}: {}",
            error.error.code, error.error.message
        ));
    }
    Ok(envelope)
}

fn print_nats_signer_did() -> Result<(), String> {
    let security = NATS_CLIENT_SECURITY
        .get()
        .ok_or_else(|| "NATS client security is not initialized".to_owned())?;
    print_json(&json!({
        "did": security.signer_did()?,
        "principal_id": cli_principal()?.id
    }))
}

fn non_empty_environment(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn environment_path(name: &str) -> Option<PathBuf> {
    non_empty_environment(name).map(PathBuf::from)
}

fn read_secret_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect secret file `{}`: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "secret path `{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "secret file `{}` must not be accessible by group or other users",
                path.display()
            ));
        }
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(format!(
            "secret file `{}` size must be between 1 and {max_bytes} bytes",
            path.display()
        ));
    }
    let mut secret =
        fs::read(path).map_err(|error| format!("cannot read `{}`: {error}", path.display()))?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.is_empty() {
        return Err(format!(
            "secret file `{}` contains no secret",
            path.display()
        ));
    }
    Ok(secret)
}

fn read_public_file(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} file `{}`: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} path `{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(format!(
            "{label} file `{}` must contain 1 to {max_bytes} bytes",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "{label} file `{}` must not be group- or world-writable",
                path.display()
            ));
        }
    }
    fs::read(path)
        .map_err(|error| format!("cannot read {label} file `{}`: {error}", path.display()))
}

async fn post_mcp_http_frame(
    endpoint: &str,
    bearer_token: Option<&str>,
    frame: McpStdioFrame,
) -> Result<Option<aip_profile_mcp::JsonRpcResponse>, String> {
    let value = match frame {
        McpStdioFrame::Request(request) => {
            serde_json::to_value(request).map_err(|error| error.to_string())?
        }
        McpStdioFrame::Notification(notification) => {
            serde_json::to_value(notification).map_err(|error| error.to_string())?
        }
        McpStdioFrame::Response(response) => {
            serde_json::to_value(response).map_err(|error| error.to_string())?
        }
    };
    let mut request = reqwest::Client::new().post(endpoint).json(&value);
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "MCP HTTP proxy request failed with HTTP {status}: {body}"
        ));
    }
    if body.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<aip_profile_mcp::JsonRpcResponse>(&body)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn nats_subject(
    trust_domain: &str,
    service: &str,
    version: &str,
    message_type: MessageType,
) -> NatsSubject {
    NatsSubject {
        trust_domain: trust_domain.to_owned(),
        service: service.to_owned(),
        version: version.to_owned(),
        message_type,
    }
}

fn endpoint_url(base: &str, path: &str) -> Result<Url, String> {
    Url::parse(base)
        .and_then(|url| url.join(path))
        .map_err(|error| error.to_string())
}

fn mcp_endpoint_url(base: &str) -> Result<String, String> {
    let url = Url::parse(base).map_err(|error| error.to_string())?;
    if url.path().ends_with("/mcp") || url.path().ends_with("/mcp/v1") {
        return Ok(url.to_string());
    }
    url.join("/mcp")
        .map(|url| url.to_string())
        .map_err(|error| error.to_string())
}

fn build_mcp_client(
    id_suffix: &str,
    url: Option<&str>,
    bearer_token: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<McpClient, String> {
    match (url, command) {
        (Some(url), None) => {
            let endpoint = mcp_endpoint_url(url)?;
            let mut transport =
                McpHttpClientTransport::new(&endpoint).map_err(|error| error.to_string())?;
            if let Some(token) = mcp_bearer_token(bearer_token) {
                transport = transport.with_bearer_token(token);
            }
            Ok(McpClient::new(
                McpClientConfig::new(format!("getaip-{id_suffix}-http")),
                std::sync::Arc::new(transport),
            ))
        }
        (None, Some(command)) => {
            let transport =
                McpStdioClientTransport::spawn(command, args).map_err(|error| error.to_string())?;
            Ok(McpClient::new(
                McpClientConfig::new(format!("getaip-{id_suffix}-stdio")),
                std::sync::Arc::new(transport),
            ))
        }
        (Some(_), Some(_)) => Err("pass either --url or --command, not both".to_owned()),
        (None, None) => Err("pass --url for Streamable HTTP or --command for stdio".to_owned()),
    }
}

fn mcp_bearer_token(cli_value: Option<&str>) -> Option<String> {
    cli_value
        .map(ToOwned::to_owned)
        .or_else(|| env::var("GETAIP_MCP_BEARER_TOKEN").ok())
}

fn approval_event_kinds(kinds: &[String]) -> Vec<String> {
    if !kinds.is_empty() {
        return kinds.to_vec();
    }
    [
        "aip.approval.requested",
        "aip.approval.granted",
        "aip.approval.denied",
        "aip.approval.expired",
        "aip.approval.revoked",
        "aip.action.resumed_result",
        "aip.action.approval_terminal",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

fn joined(values: Vec<String>) -> Option<String> {
    (!values.is_empty()).then(|| values.join(","))
}

fn build_action(
    capability_id: CapabilityId,
    input: Value,
    options: &ActionOptions,
) -> Result<Action, String> {
    let mut action = Action::new(capability_id, input);
    if let Some(action_id) = options.action_id.as_deref() {
        action.id = ActionId::parse(action_id).map_err(|error| error.to_string())?;
    }
    action.idempotency_key.clone_from(&options.idempotency_key);
    action.mode = options.mode.map(ActionMode::from);
    action.identity = options
        .identity
        .as_deref()
        .map(parse_json_arg)
        .transpose()?
        .map(serde_json::from_value::<IdentityContext>)
        .transpose()
        .map_err(|error| error.to_string())?;
    action.approval = options
        .approval
        .as_deref()
        .map(parse_json_arg)
        .transpose()?
        .map(serde_json::from_value::<ApprovalDecision>)
        .transpose()
        .map_err(|error| error.to_string())?;
    if let Some(mode) = options.transaction_mode {
        action.transaction = Some(ActionTransaction {
            mode: mode.into(),
            transaction_id: options
                .transaction_id
                .as_deref()
                .map(TransactionId::parse)
                .transpose()
                .map_err(|error| error.to_string())?,
            plan_id: options.plan_id.clone(),
            compensation_for: options
                .compensation_for
                .as_deref()
                .map(ActionId::parse)
                .transpose()
                .map_err(|error| error.to_string())?,
        });
    }
    Ok(action)
}

fn parse_json_arg(input: &str) -> Result<Value, String> {
    if let Some(path) = input.strip_prefix('@') {
        read_json_file(&PathBuf::from(path))
    } else {
        serde_json::from_str(input).map_err(|error| error.to_string())
    }
}

fn parse_typed_json_arg<T>(input: &str) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(parse_json_arg(input)?).map_err(|error| error.to_string())
}

fn read_json_file(path: &PathBuf) -> Result<Value, String> {
    let data = fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&data).map_err(|error| error.to_string())
}

fn cli_principal() -> Result<Principal, String> {
    NATIVE_HTTP_SECURITY
        .get()
        .map(NativeHttpSecurity::principal)
        .unwrap_or_else(|| principal_from_id("agent:getaip:cli"))
}

fn principal_from_id(raw: &str) -> Result<Principal, String> {
    let id = PrincipalId::parse(raw).map_err(|error| error.to_string())?;
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

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ActionOptions, NativeHttpSecurity, NatsClientSecurity, build_action, read_secret_file,
        successful_nats_response,
    };
    use aip_core::{
        ActionId, CapabilityId, CorrelationId, Envelope, ErrorBody, ManifestRequest, MessageBody,
        MessageReference, Principal, PrincipalId, PrincipalKind, ProtocolError, SessionId,
    };
    use aip_crypto::{
        did_key_from_verifying_key, sign_envelope, signing_key_from_seed, verify_envelope,
        verifying_key_from_did_key,
    };
    use serde_json::{Value, json};
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TestSecret(PathBuf);

    impl TestSecret {
        fn create(contents: &[u8]) -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("getaip-secret-{}-{suffix}", std::process::id()));
            fs::write(&path, contents).expect("write test secret");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("protect test secret");
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestSecret {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn action_builder_preserves_an_explicit_retry_identity() {
        let expected = ActionId::parse("act_operator_retry_0001").expect("valid action id");
        let options = ActionOptions {
            action_id: Some(expected.to_string()),
            idempotency_key: Some("provider-operation-0001".to_owned()),
            ..ActionOptions::default()
        };
        let action = build_action(
            CapabilityId::trusted("cap:test:write"),
            json!({"value": 1}),
            &options,
        )
        .expect("build exact retry action");
        assert_eq!(action.id, expected);
        assert_eq!(
            action.idempotency_key.as_deref(),
            Some("provider-operation-0001")
        );

        let invalid = ActionOptions {
            action_id: Some("not an AIP action id".to_owned()),
            ..ActionOptions::default()
        };
        assert!(
            build_action(CapabilityId::trusted("cap:test:write"), json!({}), &invalid).is_err()
        );
    }

    #[test]
    fn nats_security_signs_envelopes_as_the_cli_principal() {
        let seed = TestSecret::create(hex::encode([7_u8; 32]).as_bytes());
        let security = NatsClientSecurity {
            signing_seed_file: Some(seed.path().to_path_buf()),
            ..NatsClientSecurity::default()
        };
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));

        let signed = security
            .secure_envelope(envelope)
            .expect("sign native envelope");
        let signer = signed.from.as_ref().expect("signed sender");
        assert_eq!(signer.id.as_str(), "agent:getaip:cli");
        let metadata = signed
            .security
            .as_ref()
            .and_then(Value::as_object)
            .expect("security metadata");
        let did = metadata
            .get("did")
            .and_then(Value::as_str)
            .expect("signer did");
        let signature = metadata
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature");
        assert_eq!(signer.did.as_deref(), Some(did));
        let verifying_key = verifying_key_from_did_key(did).expect("decode signer did");
        verify_envelope(&signed, signature, &verifying_key).expect("verify native envelope");
    }

    #[test]
    fn native_http_security_binds_principal_did_and_trust_domain() {
        let seed = TestSecret::create(hex::encode([11_u8; 32]).as_bytes());
        let security = NativeHttpSecurity {
            signing_seed_file: Some(seed.path().to_path_buf()),
            principal_id: "service:getaip:cli:tenant-acme".to_owned(),
            trust_domain: Some("fleet.test".to_owned()),
            tls_ca_file: None,
            expected_peer_did: None,
            max_response_bytes: 4 * 1024 * 1024,
        };
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));

        let signed = security
            .secure_envelope(envelope)
            .expect("sign native HTTP envelope");
        let signer = signed.from.as_ref().expect("native HTTP signer");
        assert_eq!(signer.id.as_str(), "service:getaip:cli:tenant-acme");
        assert_eq!(signer.trust_domain.as_deref(), Some("fleet.test"));
        let metadata = signed
            .security
            .as_ref()
            .and_then(Value::as_object)
            .expect("native HTTP security metadata");
        let did = metadata
            .get("did")
            .and_then(Value::as_str)
            .expect("native HTTP signer did");
        let signature = metadata
            .get("signature")
            .and_then(Value::as_str)
            .expect("native HTTP signature");
        assert_eq!(signer.did.as_deref(), Some(did));
        assert_eq!(
            metadata.get("trust_domain").and_then(Value::as_str),
            Some("fleet.test")
        );
        let verifying_key = verifying_key_from_did_key(did).expect("decode native HTTP did");
        verify_envelope(&signed, signature, &verifying_key).expect("verify native HTTP envelope");
    }

    #[test]
    fn native_http_response_verification_pins_signer_and_exact_request() {
        let peer_key = signing_key_from_seed([12_u8; 32]);
        let peer_did = did_key_from_verifying_key(&peer_key.verifying_key());
        let security = NativeHttpSecurity {
            signing_seed_file: None,
            principal_id: "service:getaip:cli:test-client".to_owned(),
            trust_domain: None,
            tls_ca_file: None,
            expected_peer_did: Some(peer_did.clone()),
            max_response_bytes: 1024,
        };
        let client = Principal::new(
            PrincipalId::trusted("service:getaip:cli:test-client"),
            PrincipalKind::Service,
        );
        let mut request = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));
        request.from = Some(client.clone());
        request.session_id = Some(SessionId::new());
        request.correlation_id = Some(CorrelationId::new());

        let sign_response = |reference: MessageReference| {
            let mut peer = Principal::new(
                PrincipalId::trusted("service:getaip:server:test-peer"),
                PrincipalKind::Service,
            );
            peer.did = Some(peer_did.clone());
            let mut response = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
                profiles: Vec::new(),
                filter: None,
            }));
            response.from = Some(peer);
            response.to = Some(client.clone());
            response.session_id = request.session_id.clone();
            response.correlation_id = request.correlation_id.clone();
            response.in_response_to = Some(reference);
            response.security = Some(json!({ "did": peer_did }));
            let signature = sign_envelope(&response, &peer_key).expect("sign peer response");
            response
                .security
                .as_mut()
                .and_then(Value::as_object_mut)
                .expect("security object")
                .insert("signature".to_owned(), json!(signature));
            response
        };
        let valid = sign_response(MessageReference::Message(request.message_id.clone()));
        security
            .verify_response(&request, &valid)
            .expect("verify exact response");

        let wrong = sign_response(MessageReference::Message(aip_core::MessageId::new()));
        assert!(
            security
                .verify_response(&request, &wrong)
                .expect_err("wrong request reference must fail")
                .contains("exact request")
        );
    }

    #[test]
    fn nats_security_requires_complete_username_password_configuration() {
        let username_only = NatsClientSecurity {
            username: Some("getaip-server".to_owned()),
            ..NatsClientSecurity::default()
        };
        assert!(username_only.authentication().is_err());

        let password = TestSecret::create(b"secret");
        let password_only = NatsClientSecurity {
            password_file: Some(password.path().to_path_buf()),
            ..NatsClientSecurity::default()
        };
        assert!(password_only.authentication().is_err());
    }

    #[test]
    fn nats_peer_error_is_a_cli_failure() {
        let response = Envelope::new(MessageBody::Error(ErrorBody {
            error: ProtocolError::invalid_input("invalid native request"),
        }));
        let error = successful_nats_response(response).expect_err("reject peer error envelope");
        assert!(error.contains("action.invalid_input"));
        assert!(error.contains("invalid native request"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let secret = TestSecret::create(b"secret");
        fs::set_permissions(secret.path(), fs::Permissions::from_mode(0o640))
            .expect("weaken secret permissions");
        let error = read_secret_file(secret.path(), 1024).expect_err("reject weak permissions");
        assert!(error.contains("must not be accessible by group or other users"));
    }
}
