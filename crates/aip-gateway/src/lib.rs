//! AIP gateway composition layer.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_auth::{
    AuthError, AuthScheme, AuthenticatedPrincipal, CredentialHandle,
    DenyAllTrustedIdentityResolver, IdentityResolutionRequest, QueryAuthorizationRequest,
    QueryAuthorizationService, QueryObject, QueryOperation, ResolvedIdentity,
    TrustedIdentityResolver, VerifiedTenant,
};
use aip_connector::{
    CapabilityProviderConnector, Connector, ConnectorContext, FrozenConnector,
    FrozenConnectorHandler, OutboundConnector,
};
use aip_core::{
    Callback, CapabilityId, CorrelationId, CredentialRef, DelegationRequest, DelegationResult,
    Envelope, ErrorBody, ErrorCategory, HandshakeResponse, HandshakeStatus, IdentityContext,
    Manifest, MessageBody, MessageReference, Principal, PrincipalId, ProfileId, ProtocolError,
    SessionId,
};
use aip_crypto::{
    SessionCipher, did_key_from_verifying_key, sign_envelope, sign_value, verify_envelope,
    verifying_key_from_did_key,
};
use aip_discovery::{DiscoveryService, ManifestAdmissionPolicy};
use aip_runtime::{
    ActionHandler, CallbackDispatcher, DelegationRouter, MessageContext, Runtime, RuntimeError,
    RuntimeResult, runtime_error_to_protocol,
};
use aip_transport::TransportMessage;
use aip_transport_nats::{
    NatsSubject, NatsTransport, NatsTransportConfig, nats_headers_for_envelope,
};
use aip_transport_sse::SseTransport;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use lru::LruCache;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use url::Url;

/// Gateway error.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Runtime failed.
    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),
    /// Unsupported message type.
    #[error("unsupported message type")]
    UnsupportedMessage,
    /// Missing sender principal.
    #[error("missing sender principal")]
    MissingSender,
    /// Replayed message id.
    #[error("replayed message `{0}`")]
    Replay(String),
    /// No compatible profile was negotiated.
    #[error("no compatible profile")]
    NoCompatibleProfile,
    /// Signed envelope policy failed.
    #[error("invalid signed envelope: {0}")]
    Signature(String),
    /// Envelope context is not authorized for the requested protocol operation.
    #[error("policy violation: {}: {}", .0.code, .0.message)]
    Policy(Box<ProtocolError>),
}

/// Readiness state for one required gateway dependency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadinessComponent {
    /// Whether the dependency is ready to serve traffic.
    pub ready: bool,
    /// Operator-facing detail without credentials or user payloads.
    pub detail: String,
}

/// Aggregated gateway readiness report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GatewayReadiness {
    /// Whether every required dependency is ready.
    pub ready: bool,
    /// Durable storage readiness.
    pub storage: ReadinessComponent,
    /// Registered connector readiness keyed by connector id.
    pub connectors: HashMap<String, ReadinessComponent>,
}

/// Result alias for gateway operations.
pub type GatewayResult<T> = Result<T, GatewayError>;

/// Native callback profile handled by [`GatewayCallbackDispatcher`] over HTTP.
pub const NATIVE_HTTP_PROFILE: &str = "aip.native.http.v1";

/// Native callback profile handled by [`GatewayCallbackDispatcher`] over NATS.
pub const NATIVE_NATS_PROFILE: &str = "aip.native.nats.v1";

/// Native callback profile handled by [`GatewayCallbackDispatcher`] over SSE.
pub const NATIVE_SSE_PROFILE: &str = "aip.sse.stream.v1";

/// Remote delegation route owned by a gateway.
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationRoute {
    /// Optional delegate principal selector.
    pub delegate_id: Option<PrincipalId>,
    /// Optional child capability selector.
    pub capability_id: Option<CapabilityId>,
    /// Concrete peer binding used when this route matches.
    pub binding: DelegationRouteBinding,
}

impl DelegationRoute {
    /// Creates an authenticated route for a delegate principal over native HTTP.
    #[must_use]
    pub fn native_http_for_delegate(
        delegate_id: PrincipalId,
        endpoint: impl Into<String>,
        security: DelegationPeerSecurity,
    ) -> Self {
        Self {
            delegate_id: Some(delegate_id),
            capability_id: None,
            binding: DelegationRouteBinding::NativeHttp {
                endpoint: endpoint.into(),
                security,
            },
        }
    }

    /// Creates a route for a capability over native NATS request/reply.
    #[must_use]
    pub fn native_nats_for_capability(
        capability_id: CapabilityId,
        server_url: impl Into<String>,
        subject: impl Into<String>,
        security: DelegationPeerSecurity,
    ) -> Self {
        Self {
            delegate_id: None,
            capability_id: Some(capability_id),
            binding: DelegationRouteBinding::NativeNats {
                server_url: server_url.into(),
                subject: subject.into(),
                timeout_ms: 30_000,
                security,
            },
        }
    }

    fn matches(&self, request: &DelegationRequest) -> bool {
        self.delegate_id
            .as_ref()
            .is_none_or(|delegate_id| *delegate_id == request.delegate.id)
            && self
                .capability_id
                .as_ref()
                .is_none_or(|capability_id| *capability_id == request.child_action.capability_id)
    }
}

/// Remote peer binding for a delegation route.
#[derive(Clone, Debug, PartialEq)]
pub enum DelegationRouteBinding {
    /// Native HTTP JSON endpoint, usually `/aip/v1/messages`.
    NativeHttp {
        /// Absolute endpoint URL.
        endpoint: String,
        /// Mutual peer authentication and endpoint policy.
        security: DelegationPeerSecurity,
    },
    /// Native NATS request/reply subject.
    NativeNats {
        /// NATS server URL.
        server_url: String,
        /// Request subject.
        subject: String,
        /// Request timeout in milliseconds.
        timeout_ms: u64,
        /// Mutual peer authentication and endpoint policy.
        security: DelegationPeerSecurity,
    },
}

/// Authenticated remote-peer policy shared by native delegation transports.
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationPeerSecurity {
    /// Administrative trust domain for the route.
    pub trust_domain: String,
    /// Local identity used to sign outbound request envelopes.
    pub request_signer: CallbackSigner,
    /// Principal expected to sign the peer response.
    pub expected_peer: Principal,
    /// Exact `did:key` verifier expected on the peer response.
    pub expected_peer_did: String,
    /// Optional opaque credential handle retained for policy and audit context.
    pub credential: Option<CredentialHandle>,
    /// Number of transport retries after the initial attempt.
    pub retry_budget: u32,
    /// URL, timeout, redirect, DNS, and network policy for the endpoint.
    pub endpoint_policy: GatewayCallbackPolicy,
}

impl DelegationPeerSecurity {
    /// Creates a secure peer policy and validates non-secret configuration.
    pub fn new(
        trust_domain: impl Into<String>,
        request_signer: CallbackSigner,
        expected_peer: Principal,
        expected_peer_did: impl Into<String>,
        endpoint_policy: GatewayCallbackPolicy,
    ) -> RuntimeResult<Self> {
        let trust_domain = trust_domain.into();
        let expected_peer_did = expected_peer_did.into();
        if trust_domain.trim().is_empty() {
            return Err(RuntimeError::Authorization(
                "delegation trust domain must not be empty".to_owned(),
            ));
        }
        verifying_key_from_did_key(&expected_peer_did).map_err(|error| {
            RuntimeError::Authorization(format!("invalid delegation peer DID: {error}"))
        })?;
        Ok(Self {
            trust_domain,
            request_signer,
            expected_peer,
            expected_peer_did,
            credential: None,
            retry_budget: 2,
            endpoint_policy,
        })
    }
}

/// Pooled native AIP HTTP client for authenticated connector and delegation peers.
///
/// Every exchange revalidates the destination policy and pins the resolved
/// address before reusing a host-specific client. The cache is bounded so a
/// large fleet cannot create an unbounded number of connection pools.
#[derive(Clone)]
pub struct NativeAipHttpClient {
    clients: Arc<Mutex<LruCache<String, reqwest::Client>>>,
    max_cached_clients: usize,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    cache_evictions: Arc<AtomicU64>,
}

/// Fixed-cardinality telemetry for the native connector-host client cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NativeAipHttpClientCacheSnapshot {
    /// Connection pools currently retained by the cache.
    pub entries: usize,
    /// Configured hard entry ceiling.
    pub capacity: usize,
    /// Lookups served by an existing least-recently-used entry.
    pub hits: u64,
    /// Lookups that had to construct a new host-specific client.
    pub misses: u64,
    /// Least-recently-used entries removed at capacity.
    pub evictions: u64,
}

impl std::fmt::Debug for NativeAipHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAipHttpClient")
            .field("max_cached_clients", &self.max_cached_clients)
            .finish_non_exhaustive()
    }
}

impl Default for NativeAipHttpClient {
    fn default() -> Self {
        Self::new(256)
    }
}

impl NativeAipHttpClient {
    /// Creates a client with a bounded number of host-specific connection pools.
    #[must_use]
    pub fn new(max_cached_clients: usize) -> Self {
        let capacity = NonZeroUsize::new(max_cached_clients.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            clients: Arc::new(Mutex::new(LruCache::new(capacity))),
            max_cached_clients: capacity.get(),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            cache_evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns bounded cache telemetry without host names or addresses.
    pub async fn cache_snapshot(&self) -> NativeAipHttpClientCacheSnapshot {
        NativeAipHttpClientCacheSnapshot {
            entries: self.clients.lock().await.len(),
            capacity: self.max_cached_clients,
            hits: self.cache_hits.load(Ordering::Relaxed),
            misses: self.cache_misses.load(Ordering::Relaxed),
            evictions: self.cache_evictions.load(Ordering::Relaxed),
        }
    }

    /// Signs, sends, and verifies one native AIP request envelope.
    pub async fn exchange(
        &self,
        endpoint: &str,
        envelope: Envelope,
        security: &DelegationPeerSecurity,
    ) -> RuntimeResult<Envelope> {
        let (url, host, pinned_address) =
            validate_callback_url(&security.endpoint_policy, endpoint).await?;
        let client = self
            .client_for(&host, pinned_address, &security.endpoint_policy)
            .await?;
        let envelope = sign_peer_request(envelope, security)?;
        let attempts = security.retry_budget.saturating_add(1);
        let mut last_error = None;
        for attempt in 0..attempts {
            let response = client
                .post(url.clone())
                .header("AIP-Trust-Domain", &security.trust_domain)
                .header(
                    "Idempotency-Key",
                    match &envelope.body {
                        MessageBody::DelegationRequest(request) => request.delegation_id.as_str(),
                        MessageBody::Action(action) => action.id.as_str(),
                        _ => envelope.message_id.as_str(),
                    },
                )
                .json(&envelope)
                .send()
                .await;
            match response {
                Ok(response) => {
                    let status = response.status();
                    let max_response_bytes = security.endpoint_policy.max_response_bytes;
                    if response
                        .content_length()
                        .is_some_and(|length| length > max_response_bytes as u64)
                    {
                        return Err(RuntimeError::Handler(format!(
                            "native HTTP response exceeded {} bytes",
                            max_response_bytes
                        )));
                    }
                    let initial_capacity = response
                        .content_length()
                        .unwrap_or(0)
                        .min(max_response_bytes as u64)
                        as usize;
                    let mut bytes = Vec::with_capacity(initial_capacity);
                    let mut stream = response.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.map_err(|error| {
                            RuntimeError::Handler(format!(
                                "native HTTP response read failed: {error}"
                            ))
                        })?;
                        if chunk.len() > max_response_bytes.saturating_sub(bytes.len()) {
                            return Err(RuntimeError::Handler(format!(
                                "native HTTP response exceeded {max_response_bytes} bytes"
                            )));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    let body = serde_json::from_slice::<Envelope>(&bytes).map_err(|error| {
                        RuntimeError::Handler(format!(
                            "native HTTP response decode failed: {error}"
                        ))
                    })?;
                    verify_peer_response(&envelope, &body, security)?;
                    if !status.is_success() && !matches!(body.body, MessageBody::Error(_)) {
                        return Err(RuntimeError::Handler(format!(
                            "native HTTP peer returned status {status} without a protocol error"
                        )));
                    }
                    return Ok(body);
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                    if attempt + 1 < attempts {
                        tokio::time::sleep(Duration::from_millis(
                            50_u64.saturating_mul(1_u64 << attempt.min(6)),
                        ))
                        .await;
                    }
                }
            }
        }
        Err(RuntimeError::Handler(format!(
            "native HTTP request failed after {attempts} attempt(s): {}",
            last_error.unwrap_or_else(|| "unknown transport failure".to_owned())
        )))
    }

    async fn client_for(
        &self,
        host: &str,
        pinned_address: SocketAddr,
        policy: &GatewayCallbackPolicy,
    ) -> RuntimeResult<reqwest::Client> {
        let key = format!(
            "{host}|{pinned_address}|{}|{}",
            policy.request_timeout_ms.max(1),
            tls_ca_fingerprint(policy)
        );
        {
            let mut clients = self.clients.lock().await;
            if let Some(client) = clients.get(&key).cloned() {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(client);
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let client = apply_tls_policy(reqwest::Client::builder(), policy)?
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(policy.request_timeout_ms.max(1)))
            .resolve(host, pinned_address)
            .build()
            .map_err(|error| RuntimeError::Handler(format!("native client failed: {error}")))?;
        let mut clients = self.clients.lock().await;
        if let Some(existing) = clients.get(&key).cloned() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(existing);
        }
        if clients.len() >= self.max_cached_clients {
            self.cache_evictions.fetch_add(1, Ordering::Relaxed);
        }
        let _ = clients.put(key, client.clone());
        Ok(client)
    }
}

#[derive(Clone)]
struct GatewayDelegationRouter {
    routes: Arc<RwLock<Vec<DelegationRoute>>>,
    routers: Arc<RwLock<Vec<Arc<dyn DelegationRouter>>>>,
}

#[async_trait]
impl DelegationRouter for GatewayDelegationRouter {
    async fn can_route(&self, request: &DelegationRequest) -> bool {
        if self
            .routes
            .read()
            .await
            .iter()
            .any(|route| route.matches(request))
        {
            return true;
        }
        let routers = self.routers.read().await.clone();
        for router in routers {
            if router.can_route(request).await {
                return true;
            }
        }
        false
    }

    async fn route(
        &self,
        request: &DelegationRequest,
        context: &MessageContext,
    ) -> RuntimeResult<Option<DelegationResult>> {
        let route = self
            .routes
            .read()
            .await
            .iter()
            .find(|route| route.matches(request))
            .cloned();
        if let Some(route) = route {
            let envelope = delegation_request_envelope(request.clone(), context);
            let response = match route.binding {
                DelegationRouteBinding::NativeHttp { endpoint, security } => {
                    NativeAipHttpClient::default()
                        .exchange(&endpoint, envelope, &security)
                        .await?
                }
                DelegationRouteBinding::NativeNats {
                    server_url,
                    subject,
                    timeout_ms,
                    security,
                } => {
                    validate_callback_url(&security.endpoint_policy, &server_url).await?;
                    let envelope = sign_peer_request(envelope, &security)?;
                    let response =
                        request_native_nats(server_url, subject, timeout_ms, envelope.clone())
                            .await?;
                    verify_peer_response(&envelope, &response, &security)?;
                    response
                }
            };
            return match response.body {
                MessageBody::DelegationResult(result)
                    if result.delegation_id == request.delegation_id
                        && result.parent_action_id == request.parent_action_id
                        && result.child_action_id == request.child_action.id =>
                {
                    Ok(Some(*result))
                }
                MessageBody::DelegationResult(_) => Err(RuntimeError::Authorization(
                    "remote delegation response does not match the requested graph".to_owned(),
                )),
                MessageBody::Error(error) => Err(RuntimeError::Handler(format!(
                    "remote delegation failed: {}",
                    error.error.message
                ))),
                body => Err(RuntimeError::Handler(format!(
                    "remote delegation returned unexpected `{}`",
                    body.message_type().as_str()
                ))),
            };
        }

        let routers = self.routers.read().await.clone();
        for router in routers {
            if router.can_route(request).await {
                return router.route(request, context).await;
            }
        }
        Ok(None)
    }
}

/// Production callback dispatcher for native HTTP, NATS, and in-process SSE.
#[derive(Clone)]
pub struct CallbackSigner {
    /// Principal asserted by signed callback envelopes.
    pub principal: Principal,
    /// Ed25519 signing key whose DID must be trusted by the receiver.
    pub signing_key: Arc<SigningKey>,
}

impl CallbackSigner {
    /// Returns the transport principal cryptographically bound to this key.
    ///
    /// Callers that embed the callback recipient inside signed metadata must
    /// use this value, so the embedded principal and the eventual envelope
    /// sender cannot diverge when the DID is added during signing.
    #[must_use]
    pub fn bound_principal(&self) -> Principal {
        let mut principal = self.principal.clone();
        principal.did = Some(did_key_from_verifying_key(
            &self.signing_key.verifying_key(),
        ));
        principal
    }
}

impl std::fmt::Debug for CallbackSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallbackSigner")
            .field("principal", &self.principal)
            .field(
                "did",
                &did_key_from_verifying_key(&self.signing_key.verifying_key()),
            )
            .finish()
    }
}

impl PartialEq for CallbackSigner {
    fn eq(&self, other: &Self) -> bool {
        self.principal == other.principal
            && self.signing_key.verifying_key() == other.signing_key.verifying_key()
    }
}

impl Eq for CallbackSigner {}

/// Secret material used to encrypt A2A push credentials at rest.
///
/// The key is never serialized and its debug representation is redacted. A
/// production deployment must inject the same 32-byte key into every gateway
/// replica that can recover callback deliveries.
#[derive(Clone, PartialEq, Eq)]
pub struct A2aCallbackCredentialKey([u8; 32]);

impl A2aCallbackCredentialKey {
    /// Creates a credential-encryption key from 32 random bytes supplied by an operator KMS.
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Encrypts callback credentials with AES-256-GCM and caller-supplied associated data.
    pub fn seal(
        &self,
        aad: &str,
        credentials: &A2aCallbackCredentials,
    ) -> RuntimeResult<EncryptedA2aCallbackCredentials> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let plaintext = serde_json::to_vec(credentials).map_err(|error| {
            RuntimeError::Handler(format!("A2A credentials encode failed: {error}"))
        })?;
        let ciphertext = SessionCipher::from_key(self.0)
            .encrypt(nonce, aad.as_bytes(), &plaintext)
            .map_err(|error| {
                RuntimeError::Handler(format!("A2A credentials encryption failed: {error}"))
            })?;
        Ok(EncryptedA2aCallbackCredentials {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    /// Decrypts credentials previously returned by [`Self::seal`].
    pub fn open(
        &self,
        aad: &str,
        encrypted: &EncryptedA2aCallbackCredentials,
    ) -> RuntimeResult<A2aCallbackCredentials> {
        let nonce = URL_SAFE_NO_PAD
            .decode(&encrypted.nonce)
            .map_err(|_| RuntimeError::Authorization("invalid A2A credential nonce".to_owned()))?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| {
            RuntimeError::Authorization("invalid A2A credential nonce length".to_owned())
        })?;
        let ciphertext = URL_SAFE_NO_PAD.decode(&encrypted.ciphertext).map_err(|_| {
            RuntimeError::Authorization("invalid A2A credential ciphertext".to_owned())
        })?;
        let plaintext = SessionCipher::from_key(self.0)
            .decrypt(nonce, aad.as_bytes(), &ciphertext)
            .map_err(|_| {
                RuntimeError::Authorization("A2A credential decryption failed".to_owned())
            })?;
        serde_json::from_slice(&plaintext).map_err(|_| {
            RuntimeError::Authorization("invalid decrypted A2A credentials".to_owned())
        })
    }
}

impl std::fmt::Debug for A2aCallbackCredentialKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("A2aCallbackCredentialKey(<redacted>)")
    }
}

/// Decrypted credentials for one A2A push-notification configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aCallbackCredentials {
    /// Opaque callback verification token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// IANA HTTP authentication scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_scheme: Option<String>,
    /// Credentials rendered after the authentication scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_credentials: Option<String>,
}

/// AES-GCM ciphertext persisted in callback metadata instead of raw credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedA2aCallbackCredentials {
    /// Base64url-encoded 96-bit nonce.
    pub nonce: String,
    /// Base64url-encoded authenticated ciphertext.
    pub ciphertext: String,
}

/// Network and signing policy for callback delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayCallbackPolicy {
    /// Exact DNS names or IP literals allowed as callback destinations.
    pub allowed_hosts: HashSet<String>,
    /// Permit plaintext HTTP. Production deployments should leave this disabled.
    pub allow_http: bool,
    /// Permit loopback, private, link-local, and other non-public addresses.
    pub allow_private_networks: bool,
    /// End-to-end HTTP callback timeout.
    pub request_timeout_ms: u64,
    /// Maximum accepted native or callback response body size.
    pub max_response_bytes: usize,
    /// Optional private-PKI root certificate in PEM form.
    ///
    /// This augments, but never replaces, the built-in public roots. It is
    /// suitable for service-mesh and enterprise ingress certificates without
    /// disabling hostname or certificate verification.
    pub tls_ca_certificate_pem: Option<Vec<u8>>,
    /// Required signer for externally delivered callback envelopes.
    pub signer: Option<CallbackSigner>,
    /// Optional AES-256-GCM key for durable A2A push credentials.
    pub a2a_credential_key: Option<A2aCallbackCredentialKey>,
}

impl Default for GatewayCallbackPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: HashSet::new(),
            allow_http: false,
            allow_private_networks: false,
            request_timeout_ms: 5_000,
            max_response_bytes: 4 * 1024 * 1024,
            tls_ca_certificate_pem: None,
            signer: None,
            a2a_credential_key: None,
        }
    }
}

impl GatewayCallbackPolicy {
    /// Adds one bounded PEM-encoded root certificate for private PKI.
    pub fn with_tls_ca_certificate_pem(mut self, pem: Vec<u8>) -> RuntimeResult<Self> {
        validate_tls_ca_certificate(&pem)?;
        self.tls_ca_certificate_pem = Some(pem);
        Ok(self)
    }

    /// Validates an external callback destination against the configured SSRF policy.
    ///
    /// The check resolves DNS and rejects redirects, unlisted hosts, userinfo,
    /// fragments, non-HTTP schemes, and private address ranges unless they were
    /// explicitly enabled for a controlled deployment.
    pub async fn validate_destination(&self, target: &str) -> RuntimeResult<()> {
        validate_callback_url(self, target).await.map(|_| ())
    }
}

fn validate_tls_ca_certificate(pem: &[u8]) -> RuntimeResult<reqwest::Certificate> {
    if pem.is_empty() || pem.len() > 1024 * 1024 {
        return Err(RuntimeError::Authorization(
            "private-PKI root certificate must contain 1 byte to 1 MiB".to_owned(),
        ));
    }
    reqwest::Certificate::from_pem(pem).map_err(|error| {
        RuntimeError::Authorization(format!("private-PKI root certificate is invalid: {error}"))
    })
}

fn apply_tls_policy(
    builder: reqwest::ClientBuilder,
    policy: &GatewayCallbackPolicy,
) -> RuntimeResult<reqwest::ClientBuilder> {
    match policy.tls_ca_certificate_pem.as_deref() {
        Some(pem) => validate_tls_ca_certificate(pem)
            .map(|certificate| builder.add_root_certificate(certificate)),
        None => Ok(builder),
    }
}

fn tls_ca_fingerprint(policy: &GatewayCallbackPolicy) -> String {
    policy.tls_ca_certificate_pem.as_ref().map_or_else(
        || "public-roots".to_owned(),
        |pem| format!("{:x}", Sha256::digest(pem)),
    )
}

/// Callback dispatcher enforcing destination and signature policy.
#[derive(Clone)]
pub struct GatewayCallbackDispatcher {
    sse: SseTransport,
    policy: GatewayCallbackPolicy,
}

impl GatewayCallbackDispatcher {
    /// Creates a dispatcher using the supplied SSE transport for stream callbacks.
    #[must_use]
    pub fn new(sse: SseTransport) -> Self {
        Self {
            sse,
            policy: GatewayCallbackPolicy::default(),
        }
    }

    /// Creates a dispatcher with an explicit destination and signing policy.
    #[must_use]
    pub fn with_policy(sse: SseTransport, policy: GatewayCallbackPolicy) -> Self {
        Self { sse, policy }
    }

    /// Returns the SSE transport used by this dispatcher.
    #[must_use]
    pub fn sse_transport(&self) -> SseTransport {
        self.sse.clone()
    }
}

impl Default for GatewayCallbackDispatcher {
    fn default() -> Self {
        Self::new(SseTransport::new())
    }
}

#[async_trait]
impl CallbackDispatcher for GatewayCallbackDispatcher {
    async fn dispatch(&self, callback: &Callback, envelope: Envelope) -> RuntimeResult<()> {
        let profile = callback.profile.as_str();
        if profile == aip_profile_a2a::PROFILE_ID {
            post_secure_a2a_callback(&self.policy, callback, &envelope).await?;
            return Ok(());
        }
        if profile == NATIVE_HTTP_PROFILE
            || callback.target.starts_with("http://")
            || callback.target.starts_with("https://")
        {
            let envelope = self.signed_external_envelope(envelope)?;
            post_secure_callback(&self.policy, &callback.target, &envelope).await?;
            return Ok(());
        }
        if profile == NATIVE_NATS_PROFILE || callback.target.starts_with("nats://") {
            let envelope = self.signed_external_envelope(envelope)?;
            let (server_url, subject) = parse_nats_target(&callback.target)?;
            validate_callback_url(&self.policy, &server_url).await?;
            publish_native_nats(server_url, subject, envelope).await?;
            return Ok(());
        }
        if profile == NATIVE_SSE_PROFILE {
            let correlation_id = CorrelationId::parse(callback.target.clone())
                .map_err(|error| RuntimeError::Handler(error.to_string()))?;
            self.sse
                .publish_to(correlation_id, TransportMessage::new(envelope))
                .await
                .map_err(|error| RuntimeError::Handler(error.to_string()))?;
            return Ok(());
        }
        Err(RuntimeError::Handler(format!(
            "unsupported callback profile `{profile}`"
        )))
    }
}

impl GatewayCallbackDispatcher {
    fn signed_external_envelope(&self, envelope: Envelope) -> RuntimeResult<Envelope> {
        let signer = self.policy.signer.as_ref().ok_or_else(|| {
            RuntimeError::Authorization(
                "external callbacks require a configured Ed25519 signer".to_owned(),
            )
        })?;
        sign_native_envelope(envelope, signer)
    }
}

/// Signs a native envelope with an explicitly configured transport identity.
///
/// Existing non-secret security metadata is retained and covered by the
/// signature. Any caller-provided signature or DID is replaced.
pub fn sign_native_envelope(
    mut envelope: Envelope,
    signer: &CallbackSigner,
) -> RuntimeResult<Envelope> {
    let principal = signer.bound_principal();
    let did = principal
        .did
        .clone()
        .ok_or_else(|| RuntimeError::Handler("signer DID derivation failed".to_owned()))?;
    envelope.from = Some(principal);
    let security = envelope
        .security
        .get_or_insert_with(|| serde_json::json!({}));
    let security = security.as_object_mut().ok_or_else(|| {
        RuntimeError::Authorization("envelope security metadata must be an object".to_owned())
    })?;
    security.remove("signature");
    security.insert("did".to_owned(), serde_json::json!(did));
    let signature = sign_envelope(&envelope, &signer.signing_key)
        .map_err(|error| RuntimeError::Handler(error.to_string()))?;
    let security = envelope
        .security
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            RuntimeError::Authorization("envelope security metadata must be an object".to_owned())
        })?;
    security.insert("signature".to_owned(), serde_json::json!(signature));
    Ok(envelope)
}

/// Library-first gateway service used by `getaip-server`.
#[derive(Clone)]
pub struct Gateway {
    runtime: Runtime,
    local_manifest: Manifest,
    connectors: Arc<RwLock<HashMap<String, Arc<dyn Connector>>>>,
    delegation_routes: Arc<RwLock<Vec<DelegationRoute>>>,
    delegation_routers: Arc<RwLock<Vec<Arc<dyn DelegationRouter>>>>,
    trusted_signers: Arc<RwLock<HashMap<String, Principal>>>,
    remote_manifests: Arc<RwLock<HashMap<String, Manifest>>>,
    identity_resolver: Arc<dyn TrustedIdentityResolver>,
    query_authorization: QueryAuthorizationService,
    policy: GatewayPolicy,
}

/// Gateway-level protocol policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayPolicy {
    /// Reject actions without an envelope sender.
    pub require_action_sender: bool,
    /// Reject replayed message ids.
    pub reject_message_replay: bool,
    /// Retention window for replay claims and oldest accepted send timestamp.
    pub replay_window_ms: u64,
    /// Maximum accepted clock skew into the future.
    pub max_future_skew_ms: u64,
    /// Require Ed25519 envelope signatures in `security.signature`.
    pub require_signed_envelopes: bool,
    /// Permit `Envelope.from` to establish identity without transport proof.
    /// This is restricted to explicit local-development gateways.
    pub allow_unverified_payload_identity: bool,
    /// Accepted profiles. Empty means the local manifest profiles are used.
    pub accepted_profiles: Vec<ProfileId>,
    /// Resolve authenticated identity before executing an action whose
    /// capability is absent from the bounded local manifest. Fleet gateways
    /// enable this so tenant context is established before dynamic catalog
    /// lookup; standalone gateways leave it disabled.
    pub resolve_identity_for_unknown_actions: bool,
    /// Local capabilities that require deployment-owned identity resolution
    /// even when their contract does not request a downstream credential.
    pub identity_required_capabilities: BTreeSet<CapabilityId>,
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            require_action_sender: true,
            reject_message_replay: true,
            replay_window_ms: 300_000,
            max_future_skew_ms: 30_000,
            require_signed_envelopes: true,
            allow_unverified_payload_identity: false,
            accepted_profiles: Vec::new(),
            resolve_identity_for_unknown_actions: false,
            identity_required_capabilities: BTreeSet::new(),
        }
    }
}

impl Gateway {
    /// Creates a fail-closed gateway with a local manifest.
    ///
    /// Native envelopes accepted through [`Self::handle_envelope`] must be
    /// signed and bound to a trusted signer. Authenticated transports and
    /// profile hosts should use [`Self::handle_verified_envelope`].
    pub async fn new(local_manifest: Manifest) -> GatewayResult<Self> {
        Self::with_policy(local_manifest, GatewayPolicy::default()).await
    }

    /// Creates a fail-closed gateway with an atomically admitted handler set.
    pub async fn with_handlers(
        local_manifest: Manifest,
        handlers: HashMap<CapabilityId, Arc<dyn ActionHandler>>,
    ) -> GatewayResult<Self> {
        Self::with_policy_runtime_callback_and_handlers(
            local_manifest,
            GatewayPolicy::default(),
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
            handlers,
        )
        .await
    }

    /// Creates an explicitly insecure gateway for local examples and tests.
    ///
    /// This constructor trusts payload identity claims and accepts unsigned
    /// envelopes. It MUST NOT be used by a network-facing deployment.
    pub async fn local_development(local_manifest: Manifest) -> GatewayResult<Self> {
        Self::with_policy_runtime_and_callback_unchecked(
            local_manifest,
            GatewayPolicy {
                require_signed_envelopes: false,
                allow_unverified_payload_identity: true,
                ..GatewayPolicy::default()
            },
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
        )
        .await
    }

    /// Creates an unsigned loopback/test gateway with atomic handler admission.
    ///
    /// This keeps the insecure transport policy explicit while preserving the
    /// same manifest/implementation consistency guarantees as production.
    pub async fn local_development_with_handlers(
        local_manifest: Manifest,
        handlers: HashMap<CapabilityId, Arc<dyn ActionHandler>>,
    ) -> GatewayResult<Self> {
        Self::with_policy_runtime_callback_and_handlers(
            local_manifest,
            GatewayPolicy {
                require_signed_envelopes: false,
                allow_unverified_payload_identity: true,
                ..GatewayPolicy::default()
            },
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
            handlers,
        )
        .await
    }

    /// Creates a gateway with an explicit protocol policy.
    pub async fn with_policy(
        local_manifest: Manifest,
        policy: GatewayPolicy,
    ) -> GatewayResult<Self> {
        Self::with_policy_and_runtime(local_manifest, policy, Runtime::new()).await
    }

    /// Creates a gateway with an explicit protocol policy and caller-supplied runtime.
    pub async fn with_policy_and_runtime(
        local_manifest: Manifest,
        policy: GatewayPolicy,
        runtime: Runtime,
    ) -> GatewayResult<Self> {
        Self::with_policy_runtime_and_callback(
            local_manifest,
            policy,
            runtime,
            GatewayCallbackDispatcher::default(),
        )
        .await
    }

    /// Creates a gateway with explicit runtime and callback security policy.
    pub async fn with_policy_runtime_and_callback<D>(
        local_manifest: Manifest,
        policy: GatewayPolicy,
        runtime: Runtime,
        callback_dispatcher: D,
    ) -> GatewayResult<Self>
    where
        D: CallbackDispatcher + 'static,
    {
        Self::with_policy_runtime_callback_and_handlers(
            local_manifest,
            policy,
            runtime,
            callback_dispatcher,
            HashMap::new(),
        )
        .await
    }

    async fn with_policy_runtime_and_callback_unchecked<D>(
        local_manifest: Manifest,
        policy: GatewayPolicy,
        runtime: Runtime,
        callback_dispatcher: D,
    ) -> GatewayResult<Self>
    where
        D: CallbackDispatcher + 'static,
    {
        let delegation_routes = Arc::new(RwLock::new(Vec::new()));
        let delegation_routers = Arc::new(RwLock::new(Vec::new()));
        let runtime = runtime
            .with_callback_dispatcher(callback_dispatcher)
            .with_delegation_router(GatewayDelegationRouter {
                routes: delegation_routes.clone(),
                routers: delegation_routers.clone(),
            });
        runtime
            .discovery
            .write()
            .await
            .register_manifest("local", local_manifest.clone())
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        Ok(Self {
            runtime,
            local_manifest,
            connectors: Arc::new(RwLock::new(HashMap::new())),
            delegation_routes,
            delegation_routers,
            trusted_signers: Arc::default(),
            remote_manifests: Arc::default(),
            identity_resolver: Arc::new(DenyAllTrustedIdentityResolver),
            query_authorization: QueryAuthorizationService,
            policy,
        })
    }

    /// Creates a gateway by atomically admitting the local manifest and every
    /// callable implementation before the gateway can be observed.
    ///
    /// Network-facing deployments must use this constructor when the local
    /// manifest declares callable capabilities. The operation fails without
    /// publishing discovery state or handlers when any schema, binding,
    /// implementation claim, or projected identifier is invalid.
    pub async fn with_policy_runtime_callback_and_handlers<D>(
        local_manifest: Manifest,
        policy: GatewayPolicy,
        runtime: Runtime,
        callback_dispatcher: D,
        handlers: HashMap<CapabilityId, Arc<dyn ActionHandler>>,
    ) -> GatewayResult<Self>
    where
        D: CallbackDispatcher + 'static,
    {
        let delegation_routes = Arc::new(RwLock::new(Vec::new()));
        let delegation_routers = Arc::new(RwLock::new(Vec::new()));
        let runtime = runtime
            .with_callback_dispatcher(callback_dispatcher)
            .with_delegation_router(GatewayDelegationRouter {
                routes: delegation_routes.clone(),
                routers: delegation_routers.clone(),
            });
        runtime
            .admit_manifest_with_handlers("local", local_manifest.clone(), handlers)
            .await?;
        Ok(Self {
            runtime,
            local_manifest,
            connectors: Arc::new(RwLock::new(HashMap::new())),
            delegation_routes,
            delegation_routers,
            trusted_signers: Arc::default(),
            remote_manifests: Arc::default(),
            identity_resolver: Arc::new(DenyAllTrustedIdentityResolver),
            query_authorization: QueryAuthorizationService,
            policy,
        })
    }

    /// Returns the runtime used by the gateway.
    #[must_use]
    pub fn runtime(&self) -> Runtime {
        self.runtime.clone()
    }

    /// Installs the deployment-owned identity, tenant, and credential resolver.
    #[must_use]
    pub fn with_identity_resolver(mut self, resolver: Arc<dyn TrustedIdentityResolver>) -> Self {
        self.identity_resolver = resolver;
        self
    }

    /// Checks durable storage and every registered connector.
    pub async fn readiness(&self) -> GatewayReadiness {
        let storage = match self.runtime.storage_health.check().await {
            Ok(()) => ReadinessComponent {
                ready: true,
                detail: "storage read/write probe succeeded".to_owned(),
            },
            Err(error) => ReadinessComponent {
                ready: false,
                detail: error.to_string(),
            },
        };
        let connectors = self
            .connectors
            .read()
            .await
            .iter()
            .map(|(id, connector)| (id.clone(), connector.clone()))
            .collect::<Vec<_>>();
        let mut connector_readiness = HashMap::new();
        for (id, connector) in connectors {
            let component = match connector.health(&ConnectorContext::default()).await {
                Ok(health) => ReadinessComponent {
                    ready: health.ready,
                    detail: health.detail,
                },
                Err(error) => ReadinessComponent {
                    ready: false,
                    detail: error.to_string(),
                },
            };
            connector_readiness.insert(id, component);
        }
        let ready = storage.ready
            && connector_readiness
                .values()
                .all(|component| component.ready);
        metrics::gauge!("aip_gateway_ready").set(if ready { 1.0 } else { 0.0 });
        GatewayReadiness {
            ready,
            storage,
            connectors: connector_readiness,
        }
    }

    /// Registers a connector by id.
    pub async fn register_connector<C>(&self, connector: C)
    where
        C: Connector + 'static,
    {
        self.register_connector_arc(Arc::new(connector)).await;
    }

    /// Registers one type-erased connector for readiness composition.
    ///
    /// Daemon module admission rejects duplicate ids before this method is
    /// called, so the gateway retains its inexpensive map-based read path.
    pub async fn register_connector_arc(&self, connector: Arc<dyn Connector>) {
        self.connectors
            .write()
            .await
            .insert(connector.id().to_owned(), connector);
    }

    /// Registers an outbound connector and wires its capabilities into runtime routing.
    pub async fn register_outbound_connector<C>(&self, connector: C) -> GatewayResult<()>
    where
        C: Connector
            + CapabilityProviderConnector
            + OutboundConnector
            + ActionHandler
            + Clone
            + 'static,
    {
        let connector_id = connector.id().to_owned();
        let manifest = connector
            .discover(&ConnectorContext::default())
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        let connector = Arc::new(connector);
        let handlers = manifest
            .capabilities
            .iter()
            .filter(|capability| capability.kind != aip_core::CapabilityKind::Resource)
            .map(|capability| {
                (
                    capability.id.clone(),
                    connector.clone() as Arc<dyn ActionHandler>,
                )
            })
            .collect::<HashMap<_, _>>();
        self.runtime
            .admit_manifest_with_handlers(format!("connector:{connector_id}"), manifest, handlers)
            .await?;
        self.connectors
            .write()
            .await
            .insert(connector_id, connector as Arc<dyn Connector>);
        Ok(())
    }

    /// Registers a connector through the frozen typed SDK boundary.
    pub async fn register_frozen_connector<C>(&self, connector: C) -> GatewayResult<()>
    where
        C: FrozenConnector + CapabilityProviderConnector + Clone + 'static,
    {
        let connector_id = connector.id().to_owned();
        let manifest = connector
            .discover(&ConnectorContext::default())
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        let connector = Arc::new(connector);
        let handlers = manifest
            .capabilities
            .iter()
            .filter(|capability| capability.kind != aip_core::CapabilityKind::Resource)
            .map(|capability| {
                (
                    capability.id.clone(),
                    Arc::new(FrozenConnectorHandler::new(
                        connector.clone(),
                        capability.clone(),
                    )) as Arc<dyn ActionHandler>,
                )
            })
            .collect::<HashMap<_, _>>();
        self.runtime
            .admit_manifest_with_handlers(format!("connector:{connector_id}"), manifest, handlers)
            .await?;
        self.connectors
            .write()
            .await
            .insert(connector_id, connector as Arc<dyn Connector>);
        Ok(())
    }

    /// Registers a remote delegation route.
    pub async fn register_delegation_route(&self, route: DelegationRoute) {
        self.delegation_routes.write().await.push(route);
    }

    /// Registers a connector-owned delegation router.
    ///
    /// Static native HTTP and NATS routes retain precedence. A connector router
    /// is consulted only when no static route matches, which keeps deployment
    /// configuration authoritative while allowing governed operator connectors
    /// to own principals backed by a product-specific lifecycle.
    pub async fn register_delegation_router<R>(&self, router: R)
    where
        R: DelegationRouter + 'static,
    {
        self.register_delegation_router_arc(Arc::new(router)).await;
    }

    /// Registers one type-erased connector-owned delegation router.
    pub async fn register_delegation_router_arc(&self, router: Arc<dyn DelegationRouter>) {
        self.delegation_routers.write().await.push(router);
    }

    async fn can_route_delegation(&self, request: &DelegationRequest) -> bool {
        if self
            .delegation_routes
            .read()
            .await
            .iter()
            .any(|route| route.matches(request))
        {
            return true;
        }
        let routers = self.delegation_routers.read().await.clone();
        for router in routers {
            if router.can_route(request).await {
                return true;
            }
        }
        false
    }

    /// Registers a trusted DID-to-principal binding for signed native envelopes.
    ///
    /// Signature verification proves key possession. This registry supplies the
    /// independent trust decision that binds the key to an AIP principal.
    pub async fn register_trusted_signer(&self, did: impl Into<String>, principal: Principal) {
        self.trusted_signers
            .write()
            .await
            .insert(did.into(), principal);
    }

    /// Returns configured remote delegation routes.
    pub async fn delegation_routes(&self) -> Vec<DelegationRoute> {
        self.delegation_routes.read().await.clone()
    }

    /// Returns validated remote manifests that are not part of the local callable catalog.
    pub async fn remote_manifests(&self) -> Vec<Manifest> {
        let mut manifests = self
            .remote_manifests
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        manifests.sort_by(|left, right| left.agent.id.cmp(&right.agent.id));
        manifests
    }

    /// Handles a native AIP envelope and returns a native response envelope.
    ///
    /// The returned future is boxed because the native gateway dispatches every
    /// protocol message family from one public entrypoint. As the protocol grows,
    /// the unboxed state machine can become large enough to pressure default
    /// thread stacks in tests and embedders. Heap-boxing the dispatch future
    /// keeps the public API ergonomic (`gateway.handle_envelope(envelope).await`)
    /// while making stack usage independent from the largest message variant.
    pub fn handle_envelope(
        &self,
        envelope: Envelope,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<Envelope>> + Send + '_>> {
        Box::pin(self.handle_envelope_inner(envelope))
    }

    /// Handles an envelope received from an already authenticated in-process edge.
    ///
    /// This entrypoint is intended for stdio hosts and profile adapters that have
    /// authenticated their peer before constructing the AIP envelope. The
    /// authenticated actor replaces any payload-supplied sender metadata.
    pub fn handle_authenticated_envelope(
        &self,
        mut envelope: Envelope,
        actor: Principal,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<Envelope>> + Send + '_>> {
        envelope.from = Some(actor.clone());
        let authenticated = AuthenticatedPrincipal {
            scopes: principal_scope_set(&actor),
            issuer: "aip-gateway:authenticated-edge".to_owned(),
            audience: Some("aip-gateway".to_owned()),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_fingerprint: None,
            scheme: AuthScheme::DidProof,
            principal: actor,
        };
        Box::pin(self.handle_envelope_inner_with_actor(
            envelope,
            Some(authenticated),
            None,
            None,
            None,
            false,
        ))
    }

    /// Handles an envelope with transport-verified identity, tenant, and
    /// credential state. Network transports must use this entrypoint after
    /// token, certificate, DID, or peer authentication.
    pub fn handle_verified_envelope(
        &self,
        mut envelope: Envelope,
        actor: AuthenticatedPrincipal,
        tenant: Option<VerifiedTenant>,
        credential: Option<CredentialHandle>,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<Envelope>> + Send + '_>> {
        envelope.from = Some(actor.principal.clone());
        let resolved_identity = resolved_identity_context(tenant.as_ref(), credential.as_ref());
        Box::pin(self.handle_envelope_inner_with_actor(
            envelope,
            Some(actor),
            tenant,
            credential,
            resolved_identity,
            false,
        ))
    }

    /// Handles an envelope with a complete trusted identity resolution result.
    pub fn handle_resolved_envelope(
        &self,
        mut envelope: Envelope,
        resolved: ResolvedIdentity,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<Envelope>> + Send + '_>> {
        envelope.from = Some(resolved.actor.principal.clone());
        Box::pin(self.handle_envelope_inner_with_actor(
            envelope,
            Some(resolved.actor),
            resolved.tenant,
            resolved.credential,
            resolved.identity,
            false,
        ))
    }

    async fn handle_envelope_inner(&self, envelope: Envelope) -> GatewayResult<Envelope> {
        self.handle_envelope_inner_with_actor(envelope, None, None, None, None, true)
            .await
    }

    async fn handle_envelope_inner_with_actor(
        &self,
        envelope: Envelope,
        authenticated_actor: Option<AuthenticatedPrincipal>,
        mut verified_tenant: Option<VerifiedTenant>,
        mut credential: Option<CredentialHandle>,
        mut resolved_identity: Option<IdentityContext>,
        authenticate_envelope: bool,
    ) -> GatewayResult<Envelope> {
        metrics::counter!(
            "aip_envelopes_received_total",
            "message_type" => envelope.message_type.as_str().to_owned()
        )
        .increment(1);
        if matches!(&envelope.body, MessageBody::Action(_)) {
            metrics::counter!("aip_actions_total").increment(1);
        }
        let authenticated = if authenticate_envelope {
            self.enforce_envelope_policy(&envelope).await?
        } else {
            self.enforce_replay_policy(&envelope).await?;
            authenticated_actor
        };
        // A delegated child action crosses the same authorization and
        // connector boundary as a root action. Resolve both through the
        // deployment-owned identity directory before runtime dispatch so a
        // tenant-scoped remote capability is never selected from payload
        // claims and never loses its verified tenant partition in transit.
        let identity_action = match &envelope.body {
            MessageBody::Action(action) => Some(action.as_ref()),
            MessageBody::DelegationRequest(request) => Some(&request.child_action),
            _ => None,
        };
        if resolved_identity.is_none()
            && let (Some(authenticated), Some(action)) = (authenticated.as_ref(), identity_action)
            && let Some(resolved) = self.resolve_action_identity(authenticated, action).await?
        {
            verified_tenant = resolved.tenant;
            credential = resolved.credential;
            resolved_identity = resolved.identity;
        }
        if verified_tenant.is_none()
            && credential.is_none()
            && resolved_identity.is_none()
            && matches!(&envelope.body, MessageBody::Cancel(_))
            && let Some(authenticated) = authenticated.as_ref()
        {
            let resolved = self.resolve_operational_identity(authenticated).await?;
            verified_tenant = resolved.tenant;
            credential = resolved.credential;
            resolved_identity = resolved.identity;
        }
        let mut context = MessageContext::from_envelope(&envelope);
        context.actor = authenticated
            .as_ref()
            .map(|authenticated| authenticated.principal.clone());
        context.authenticated = authenticated;
        context.tenant = verified_tenant;
        context.credential = credential;
        context.resolved_identity = resolved_identity;
        self.enforce_query_policy(&envelope.body, &context)?;
        match envelope.body {
            MessageBody::Handshake(handshake) => {
                let responder = self.local_manifest.agent.clone();
                let authenticated_client = context.authenticated.as_ref().ok_or_else(|| {
                    GatewayError::Policy(Box::new(ProtocolError {
                        code: "auth.unverified_actor".to_owned(),
                        message: "handshake requires transport-established identity".to_owned(),
                        category: ErrorCategory::Auth,
                        retryable: Some(false),
                        retry_after_ms: None,
                        details: None,
                        source: Some(Box::new(serde_json::json!({
                            "component": "aip-gateway.handshake"
                        }))),
                    }))
                })?;
                if authenticated_client.principal.id != handshake.client.id
                    || authenticated_client.principal.kind != handshake.client.kind
                {
                    return Err(GatewayError::Policy(Box::new(ProtocolError {
                        code: "auth.claim_mismatch".to_owned(),
                        message: "handshake client does not match authenticated identity"
                            .to_owned(),
                        category: ErrorCategory::Auth,
                        retryable: Some(false),
                        retry_after_ms: None,
                        details: None,
                        source: Some(Box::new(serde_json::json!({
                            "component": "aip-gateway.handshake"
                        }))),
                    })));
                }
                let agreed_profiles = self.negotiate_profiles(&handshake.profiles);
                if agreed_profiles.is_empty() {
                    return Ok(self.response_envelope(
                        MessageBody::HandshakeResponse(Box::new(HandshakeResponse {
                            status: HandshakeStatus::Rejected,
                            session_id: None,
                            resume_token: None,
                            server: Some(responder),
                            agreed_profiles,
                            agreed_capabilities: Vec::new(),
                            heartbeat: None,
                            encryption: None,
                            billing: None,
                            redirect: None,
                            rejection_reason: Some(ProtocolError {
                                code: "handshake.no_compatible_profile".to_owned(),
                                message: "no requested profile is supported by this gateway"
                                    .to_owned(),
                                category: ErrorCategory::Permanent,
                                retryable: Some(false),
                                retry_after_ms: None,
                                details: None,
                                source: Some(Box::new(
                                    serde_json::json!({ "component": "aip-gateway" }),
                                )),
                            }),
                        })),
                        &context,
                    ));
                }
                let agreed_capabilities =
                    self.negotiate_capabilities(&handshake.requested_capabilities);
                let created_session = self
                    .runtime
                    .sessions
                    .create_secure(authenticated_client.principal.clone(), responder.clone())
                    .await?;
                let session = created_session.session;
                Ok(self.response_envelope(
                    MessageBody::HandshakeResponse(Box::new(HandshakeResponse {
                        status: HandshakeStatus::Accepted,
                        session_id: Some(session.id.clone()),
                        resume_token: Some(created_session.resume_token),
                        server: Some(responder),
                        agreed_profiles,
                        agreed_capabilities,
                        heartbeat: handshake.heartbeat,
                        encryption: None,
                        billing: handshake.billing,
                        redirect: None,
                        rejection_reason: None,
                    })),
                    &MessageContext {
                        session_id: Some(session.id),
                        ..context
                    },
                ))
            }
            MessageBody::ManifestRequest(request) => {
                let manifest =
                    Runtime::filter_manifest(&self.local_manifest, request.filter.as_ref());
                Ok(self.response_envelope(MessageBody::Manifest(manifest), &context))
            }
            MessageBody::Action(action) => {
                let principal = context.actor.clone().ok_or(GatewayError::MissingSender)?;
                let runtime = self.runtime.clone();
                let action_context = context.clone();
                let body = tokio::spawn(async move {
                    runtime
                        .submit_action(*action, &principal, action_context)
                        .await
                })
                .await
                .map_err(|error| {
                    RuntimeError::Handler(format!("runtime action task failed: {error}"))
                })??;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ActionStatusRequest(request) => {
                let body = self
                    .runtime
                    .action_status_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ActionStatus(status) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.lifecycle.action_status_received",
                        serde_json::to_value(status)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ActionResultRequest(request) => {
                let body = self
                    .runtime
                    .action_result_lookup_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ActionListRequest(request) => {
                let body = self
                    .runtime
                    .action_list_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ActionList(list) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.lifecycle.action_list_received",
                        serde_json::to_value(list)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ActionEventsRequest(request) => {
                let body = self
                    .runtime
                    .action_events_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ActionEvents(events) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.lifecycle.action_events_received",
                        serde_json::to_value(events)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::SessionRequest(request) => {
                let body = self
                    .runtime
                    .session_view_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::SessionListRequest(request) => {
                let body = self
                    .runtime
                    .session_list_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::SessionCloseRequest(request) => {
                let body = self
                    .runtime
                    .session_close_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::SessionResumeRequest(request) => {
                let body = self
                    .runtime
                    .session_resume_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::SessionView(view) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.session.view_received",
                        serde_json::to_value(view)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::SessionList(list) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.session.list_received",
                        serde_json::to_value(list)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::SessionResume(resume) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.session.resume_received",
                        serde_json::to_value(resume)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::DelegationRequest(request) => {
                let has_remote_route = self.can_route_delegation(&request).await;
                if !has_remote_route
                    && (request.delegate.id != self.local_manifest.agent.id
                        || request.delegate.kind != self.local_manifest.agent.kind)
                {
                    return Err(GatewayError::Policy(Box::new(ProtocolError {
                        code: "delegation.target_mismatch".to_owned(),
                        message: "delegation target is neither this gateway nor a registered peer"
                            .to_owned(),
                        category: ErrorCategory::Auth,
                        retryable: Some(false),
                        retry_after_ms: None,
                        details: None,
                        source: Some(Box::new(serde_json::json!({
                            "component": "aip-gateway.delegation"
                        }))),
                    })));
                }
                let principal = context.actor.clone().ok_or(GatewayError::MissingSender)?;
                let runtime = self.runtime.clone();
                let delegation_context = context.clone();
                let result = tokio::spawn(async move {
                    runtime
                        .process_delegation_request(*request, &principal, delegation_context)
                        .await
                })
                .await
                .map_err(|error| {
                    RuntimeError::Handler(format!("runtime delegation task failed: {error}"))
                })??;
                Ok(self
                    .response_envelope(MessageBody::DelegationResult(Box::new(result)), &context))
            }
            MessageBody::DelegationResult(result) => {
                let result = self
                    .runtime
                    .ingest_remote_delegation_result(*result, context.clone())
                    .await?;
                Ok(self
                    .response_envelope(MessageBody::DelegationResult(Box::new(result)), &context))
            }
            MessageBody::TransactionRequest(request) => {
                let principal = context.actor.clone().ok_or(GatewayError::MissingSender)?;
                let runtime = self.runtime.clone();
                let transaction_context = context.clone();
                let result = tokio::spawn(async move {
                    runtime
                        .process_transaction_request(*request, &principal, transaction_context)
                        .await
                })
                .await
                .map_err(|error| {
                    RuntimeError::Handler(format!("runtime transaction task failed: {error}"))
                })??;
                Ok(self
                    .response_envelope(MessageBody::TransactionResult(Box::new(result)), &context))
            }
            MessageBody::TransactionResult(result) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.transaction.result_received",
                        serde_json::to_value(result)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::TransactionQueryRequest(request) => {
                let body = self
                    .runtime
                    .transaction_query_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::TransactionView(view) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.transaction.view_received",
                        serde_json::to_value(view)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::Cancel(cancel) => {
                let body = self.runtime.handle_cancel(cancel, context.clone()).await?;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::Heartbeat(heartbeat) => {
                let ack = self
                    .runtime
                    .handle_heartbeat(heartbeat, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::HeartbeatAck(ack), &context))
            }
            MessageBody::HeartbeatAck(ack) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.heartbeat.ack",
                        serde_json::json!({
                            "sequence": ack.sequence,
                            "received_at": ack.received_at
                        }),
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::Escalation(escalation) => {
                let stream = self
                    .runtime
                    .record_escalation(*escalation, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::EscalationResolution(resolution) => {
                let stream = self
                    .runtime
                    .record_escalation_resolution(resolution, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ApprovalRequest(request) => {
                let stream = self
                    .runtime
                    .record_approval_request(*request, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ApprovalDecision(decision) => {
                let stream = self
                    .runtime
                    .record_approval_decision(*decision, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ApprovalQueryRequest(request) => {
                let body = self
                    .runtime
                    .approval_query_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ApprovalListRequest(request) => {
                let body = self
                    .runtime
                    .approval_list_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ApprovalRecordView(view) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.approval.view_received",
                        serde_json::to_value(view)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ApprovalList(list) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.approval.list_received",
                        serde_json::to_value(list)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::CallbackDeliveryQueryRequest(request) => {
                let body = self
                    .runtime
                    .callback_delivery_query_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::CallbackDeliveryListRequest(request) => {
                let body = self
                    .runtime
                    .callback_delivery_list_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::CallbackDeliveryRecord(record) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.callback.delivery_record_received",
                        serde_json::to_value(record)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::CallbackDeliveryList(list) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.callback.delivery_list_received",
                        serde_json::to_value(list)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::EventStreamRequest(request) => {
                let body = self
                    .runtime
                    .event_stream_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ChannelMessage(message) => {
                let stream = self
                    .runtime
                    .record_channel_message(*message, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::Conversation(update) => {
                let stream = self
                    .runtime
                    .record_conversation_update(*update, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ReceiptChain(chain) => {
                let chain = self
                    .runtime
                    .record_receipt_chain(chain, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::ReceiptChain(chain), &context))
            }
            MessageBody::ReceiptQueryRequest(request) => {
                let body = self
                    .runtime
                    .receipt_query_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::AuditEvent(audit) => {
                let audit = self
                    .runtime
                    .record_audit_event(*audit, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::AuditEvent(Box::new(audit)), &context))
            }
            MessageBody::AuditQueryRequest(request) => {
                let body = self
                    .runtime
                    .audit_query_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::AuditQueryResult(result) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.audit.query_result_received",
                        serde_json::to_value(result)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ResourceListRequest(request) => {
                let body = self
                    .runtime
                    .resource_list_response_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ResourceReadRequest(request) => {
                let body = self
                    .runtime
                    .resource_read_with_context(request, &context)
                    .await;
                Ok(self.response_envelope(body, &context))
            }
            MessageBody::ResourceList(list) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.resource.list_received",
                        serde_json::to_value(list)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ResourceReadResult(result) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.resource.read_result_received",
                        serde_json::to_value(result)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::BatchSettlement(settlement) => {
                let settlement = self
                    .runtime
                    .record_settlement(settlement, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::BatchSettlement(settlement), &context))
            }
            MessageBody::Ack(ack) => {
                let stream = self.runtime.record_ack(ack, context.clone()).await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::StreamChunk(chunk) => {
                let stream = self
                    .runtime
                    .ingest_stream_chunk(chunk, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::ActionResult(result) => {
                let stream = self
                    .runtime
                    .ingest_action_result(result, context.clone())
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::Error(error) => {
                let stream = self.runtime.record_error(error, context.clone()).await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::HandshakeResponse(response) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.handshake.response",
                        serde_json::to_value(response)
                            .map_err(|error| RuntimeError::Handler(error.to_string()))?,
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::Manifest(manifest) => {
                DiscoveryService::admit_manifest(
                    manifest.clone(),
                    &ManifestAdmissionPolicy::default(),
                    &HashMap::new(),
                )
                .map_err(RuntimeError::Admission)?;
                self.remote_manifests
                    .write()
                    .await
                    .insert(manifest.agent.id.to_string(), manifest.clone());
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.discovery.manifest_received",
                        serde_json::json!({
                            "agent": manifest.agent,
                            "capability_count": manifest.capabilities.len(),
                            "profiles": manifest.profiles
                        }),
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
            MessageBody::EventStream(stream) => {
                let stream = self
                    .runtime
                    .record_observation(
                        "aip.discovery.event_stream_received",
                        serde_json::json!({
                            "event_count": stream.events.len(),
                            "next_cursor": stream.next_cursor
                        }),
                        context.clone(),
                    )
                    .await?;
                Ok(self.response_envelope(MessageBody::EventStream(stream), &context))
            }
        }
    }

    async fn resolve_action_identity(
        &self,
        authenticated: &AuthenticatedPrincipal,
        action: &aip_core::Action,
    ) -> GatewayResult<Option<ResolvedIdentity>> {
        let capability = self
            .runtime
            .discovery
            .read()
            .await
            .capability(&action.capability_id)
            .cloned();
        let credential_policy = capability
            .as_ref()
            .and_then(|capability| capability.contract.as_ref())
            .and_then(|contract| contract.credentials.as_ref());
        let resolution_required = action.identity.is_some()
            || (capability.is_none() && self.policy.resolve_identity_for_unknown_actions)
            || self
                .policy
                .identity_required_capabilities
                .contains(&action.capability_id)
            || credential_policy.is_some_and(|policy| {
                policy.required
                    || !policy.accepted_issuers.is_empty()
                    || !policy.required_scopes.is_empty()
            });
        if !resolution_required {
            return Ok(None);
        }
        let accepted_credential_issuers = credential_policy
            .map(|policy| policy.accepted_issuers.iter().cloned().collect())
            .unwrap_or_default();
        let credential_required = credential_policy.is_some_and(|policy| policy.required);
        let required_credential_scopes = credential_policy
            .map(|policy| policy.required_scopes.iter().cloned().collect())
            .unwrap_or_default();
        let resolved = self
            .identity_resolver
            .resolve(IdentityResolutionRequest {
                actor: authenticated,
                claimed_identity: action.identity.as_ref(),
                accepted_credential_issuers: &accepted_credential_issuers,
                credential_required,
                required_credential_scopes: &required_credential_scopes,
            })
            .await
            .map_err(identity_resolution_error)?;
        Self::validate_resolved_identity(
            authenticated,
            resolved,
            &accepted_credential_issuers,
            credential_required,
            &required_credential_scopes,
        )
        .map(Some)
    }

    async fn resolve_operational_identity(
        &self,
        authenticated: &AuthenticatedPrincipal,
    ) -> GatewayResult<ResolvedIdentity> {
        let accepted_credential_issuers = BTreeSet::new();
        let required_credential_scopes = BTreeSet::new();
        let resolved = self
            .identity_resolver
            .resolve(IdentityResolutionRequest {
                actor: authenticated,
                claimed_identity: None,
                accepted_credential_issuers: &accepted_credential_issuers,
                credential_required: false,
                required_credential_scopes: &required_credential_scopes,
            })
            .await
            .map_err(identity_resolution_error)?;
        Self::validate_resolved_identity(
            authenticated,
            resolved,
            &accepted_credential_issuers,
            false,
            &required_credential_scopes,
        )
    }

    fn validate_resolved_identity(
        authenticated: &AuthenticatedPrincipal,
        mut resolved: ResolvedIdentity,
        accepted_credential_issuers: &BTreeSet<String>,
        credential_required: bool,
        required_credential_scopes: &BTreeSet<String>,
    ) -> GatewayResult<ResolvedIdentity> {
        resolved
            .actor
            .validate(&BTreeSet::new())
            .map_err(identity_resolution_error)?;
        if resolved.actor.principal.id != authenticated.principal.id
            || resolved.actor.principal.kind != authenticated.principal.kind
            || !resolved.actor.scopes.is_subset(&authenticated.scopes)
        {
            return Err(identity_resolution_error(AuthError::Resolution(
                "identity resolver attempted to replace the transport actor or elevate scopes"
                    .to_owned(),
            )));
        }
        resolved.actor = authenticated.clone();
        if let Some(tenant) = resolved.tenant.as_ref() {
            tenant.validate().map_err(identity_resolution_error)?;
        }
        if let Some(credential) = resolved.credential.as_ref() {
            credential
                .validate(required_credential_scopes)
                .map_err(identity_resolution_error)?;
            if !accepted_credential_issuers.is_empty()
                && !accepted_credential_issuers.contains(credential.issuer())
            {
                return Err(identity_resolution_error(AuthError::Credential(
                    "credential issuer is not accepted by the capability".to_owned(),
                )));
            }
        } else if credential_required {
            return Err(identity_resolution_error(AuthError::MissingCredential));
        }
        if let Some(credential_tenant) = resolved
            .credential
            .as_ref()
            .and_then(CredentialHandle::tenant_id)
        {
            let Some(tenant) = resolved.tenant.as_ref() else {
                return Err(identity_resolution_error(
                    AuthError::TenantMembershipRequired,
                ));
            };
            if tenant.tenant.id != credential_tenant {
                return Err(identity_resolution_error(AuthError::TenantMismatch {
                    requested: credential_tenant.to_owned(),
                    verified: tenant.tenant.id.clone(),
                }));
            }
        }
        let verified_tenant = resolved.tenant.as_ref().map(|tenant| tenant.tenant.clone());
        let verified_credential = resolved
            .credential
            .as_ref()
            .map(|credential| CredentialRef {
                id: credential.id().to_owned(),
                issuer: credential.issuer().to_owned(),
                scopes: credential.scopes().iter().cloned().collect(),
            });
        let had_identity = resolved.identity.is_some();
        let mut identity = resolved.identity.take().unwrap_or(IdentityContext {
            tenant: None,
            external_account: None,
            external_user: None,
            human_actor: None,
            service_account: None,
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        });
        if let Some(tenant) = verified_tenant {
            if let Some(identity_tenant) = identity.tenant.as_ref()
                && identity_tenant.id != tenant.id
            {
                return Err(identity_resolution_error(AuthError::TenantMismatch {
                    requested: identity_tenant.id.clone(),
                    verified: tenant.id,
                }));
            }
            // Project only the resolver-verified tenant value, including its
            // canonical system identifier. Wire claims never reach this path.
            identity.tenant = Some(tenant);
        }
        if let Some(credential) = verified_credential {
            if let Some(identity_credential) = identity.credential_ref.as_ref()
                && (identity_credential.id != credential.id
                    || identity_credential.issuer != credential.issuer
                    || identity_credential.scopes.iter().collect::<BTreeSet<_>>()
                        != credential.scopes.iter().collect::<BTreeSet<_>>())
            {
                return Err(identity_resolution_error(AuthError::Credential(
                    "resolved identity credential does not match the verified credential handle"
                        .to_owned(),
                )));
            }
            identity.credential_ref = Some(credential);
        }
        resolved.identity =
            (had_identity || identity.tenant.is_some() || identity.credential_ref.is_some())
                .then_some(identity);
        Ok(resolved)
    }

    fn response_envelope(&self, body: MessageBody, context: &MessageContext) -> Envelope {
        let mut response = Envelope::new(body);
        response.session_id.clone_from(&context.session_id);
        response.correlation_id.clone_from(&context.correlation_id);
        response.from = Some(self.local_manifest.agent.clone());
        response.to.clone_from(&context.actor);
        response
    }

    async fn enforce_envelope_policy(
        &self,
        envelope: &Envelope,
    ) -> GatewayResult<Option<AuthenticatedPrincipal>> {
        let authenticated = if self.policy.require_signed_envelopes {
            let did = verify_native_envelope_signature(envelope)?;
            let trusted = self
                .trusted_signers
                .read()
                .await
                .get(&did)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::Signature(format!("untrusted envelope signer `{did}`"))
                })?;
            if envelope
                .from
                .as_ref()
                .is_none_or(|sender| sender.id != trusted.id || sender.kind != trusted.kind)
            {
                return Err(GatewayError::Signature(
                    "signed envelope sender does not match its trusted DID binding".to_owned(),
                ));
            }
            Some(AuthenticatedPrincipal {
                scopes: principal_scope_set(&trusted),
                issuer: did,
                audience: Some("aip-gateway".to_owned()),
                authenticated_at: OffsetDateTime::now_utc(),
                expires_at: None,
                credential_fingerprint: trusted.did.clone(),
                scheme: AuthScheme::DidProof,
                principal: trusted,
            })
        } else if self.policy.allow_unverified_payload_identity {
            envelope
                .from
                .clone()
                .map(|principal| AuthenticatedPrincipal {
                    scopes: principal_scope_set(&principal),
                    issuer: "aip-gateway:local-development".to_owned(),
                    audience: Some("aip-gateway".to_owned()),
                    authenticated_at: OffsetDateTime::now_utc(),
                    expires_at: None,
                    credential_fingerprint: None,
                    scheme: AuthScheme::DidProof,
                    principal,
                })
        } else {
            None
        };
        self.enforce_replay_policy(envelope).await?;
        if self.policy.require_action_sender
            && matches!(envelope.body, MessageBody::Action(_))
            && authenticated.is_none()
        {
            return Err(GatewayError::MissingSender);
        }
        Ok(authenticated)
    }

    async fn enforce_replay_policy(&self, envelope: &Envelope) -> GatewayResult<()> {
        if self.policy.reject_message_replay {
            let now = time::OffsetDateTime::now_utc();
            let replay_window = time::Duration::milliseconds(
                self.policy.replay_window_ms.min(i64::MAX as u64) as i64,
            );
            let future_skew = time::Duration::milliseconds(
                self.policy.max_future_skew_ms.min(i64::MAX as u64) as i64,
            );
            if envelope.sent_at < now - replay_window || envelope.sent_at > now + future_skew {
                return Err(GatewayError::Replay(format!(
                    "{} outside accepted timestamp window",
                    envelope.message_id
                )));
            }
            let expires_at = envelope.sent_at + replay_window;
            if !self
                .runtime
                .replay
                .claim(envelope.message_id.as_str(), expires_at)
                .await?
            {
                return Err(GatewayError::Replay(envelope.message_id.to_string()));
            }
        }
        Ok(())
    }

    fn enforce_query_policy(
        &self,
        body: &MessageBody,
        context: &MessageContext,
    ) -> GatewayResult<()> {
        if requires_operational_sender(body) && context.actor.is_none() {
            return Err(GatewayError::MissingSender);
        }
        if let Some((object, operation)) = query_object_and_operation(body) {
            let authenticated = context.authenticated.as_ref().ok_or_else(|| {
                GatewayError::Policy(Box::new(ProtocolError {
                    code: "auth.unverified_actor".to_owned(),
                    message: "operational queries require transport-established identity"
                        .to_owned(),
                    category: ErrorCategory::Auth,
                    retryable: Some(false),
                    retry_after_ms: None,
                    details: None,
                    source: Some(Box::new(
                        serde_json::json!({ "component": "aip-gateway.query-authorization" }),
                    )),
                }))
            })?;
            let selected_principal = principal_selectors_for_body(body).first().copied();
            self.query_authorization
                .authorize(QueryAuthorizationRequest {
                    actor: authenticated,
                    tenant: context.tenant.as_ref(),
                    object,
                    operation,
                    owner: None,
                    selected_principal,
                    tenant_id: tenant_selector_for_body(body),
                    additional_scopes: BTreeSet::new(),
                    sensitive_fields: BTreeSet::new(),
                })
                .map_err(|error| {
                    let code = match (&error, object) {
                        (
                            AuthError::TenantMembershipRequired | AuthError::TenantSelectorRequired,
                            _,
                        ) => "auth.tenant_required",
                        (AuthError::TenantMismatch { .. }, _) => "auth.tenant_mismatch",
                        (_, QueryObject::Audit) => "audit.not_authorized",
                        _ => "auth.not_authorized",
                    };
                    GatewayError::Policy(Box::new(ProtocolError {
                        code: code.to_owned(),
                        message: error.to_string(),
                        category: ErrorCategory::Auth,
                        retryable: Some(false),
                        retry_after_ms: None,
                        details: Some(Box::new(serde_json::json!({
                            "object": object.scope_prefix(),
                            "operation": format!("{operation:?}")
                        }))),
                        source: Some(Box::new(
                            serde_json::json!({ "component": "aip-gateway.query-authorization" }),
                        )),
                    }))
                })?;
        }
        if let Some(request_session_id) = session_selector_for_body(body)
            && let Some(envelope_session_id) = context.session_id.as_ref()
            && request_session_id != envelope_session_id
        {
            return Err(GatewayError::Policy(Box::new(ProtocolError {
                code: "auth.session_mismatch".to_owned(),
                message: format!(
                    "request session `{request_session_id}` does not match envelope session `{envelope_session_id}`"
                ),
                category: ErrorCategory::Auth,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(serde_json::json!({
                    "request_session_id": request_session_id,
                    "envelope_session_id": envelope_session_id
                }))),
                source: Some(Box::new(serde_json::json!({ "component": "aip-gateway" }))),
            })));
        }
        Ok(())
    }

    fn negotiate_profiles(&self, requested: &[ProfileId]) -> Vec<ProfileId> {
        let supported = if self.policy.accepted_profiles.is_empty() {
            &self.local_manifest.profiles
        } else {
            &self.policy.accepted_profiles
        };
        requested
            .iter()
            .filter(|profile| supported.contains(profile))
            .cloned()
            .collect()
    }

    fn negotiate_capabilities(
        &self,
        requested: &[aip_core::CapabilityId],
    ) -> Vec<aip_core::CapabilityId> {
        if requested.is_empty() {
            return Vec::new();
        }
        let supported = self
            .local_manifest
            .capabilities
            .iter()
            .map(|capability| &capability.id)
            .collect::<HashSet<_>>();
        requested
            .iter()
            .filter(|capability_id| supported.contains(capability_id))
            .cloned()
            .collect()
    }

    /// Converts an error into an AIP error envelope.
    #[must_use]
    pub fn error_envelope(error: &GatewayError) -> Envelope {
        let protocol_error = match error {
            GatewayError::Runtime(runtime) => runtime_error_to_protocol(runtime),
            GatewayError::UnsupportedMessage => ProtocolError {
                code: "capability.unsupported".to_owned(),
                message: "message type is not handled by this gateway endpoint".to_owned(),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: None,
            },
            GatewayError::MissingSender => ProtocolError {
                code: "auth.not_authorized".to_owned(),
                message: "sender principal is required".to_owned(),
                category: ErrorCategory::Auth,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: None,
            },
            GatewayError::Replay(message_id) => ProtocolError {
                code: "replay.message_id".to_owned(),
                message: format!("message `{message_id}` was already processed"),
                category: ErrorCategory::Auth,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(serde_json::json!({ "component": "aip-gateway" }))),
            },
            GatewayError::NoCompatibleProfile => ProtocolError {
                code: "handshake.no_compatible_profile".to_owned(),
                message: "no compatible profile".to_owned(),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(serde_json::json!({ "component": "aip-gateway" }))),
            },
            GatewayError::Signature(reason) => ProtocolError {
                code: "auth.signature.invalid".to_owned(),
                message: reason.clone(),
                category: ErrorCategory::Auth,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(serde_json::json!({ "component": "aip-gateway" }))),
            },
            GatewayError::Policy(error) => (**error).clone(),
        };
        Envelope::new(MessageBody::Error(ErrorBody {
            error: protocol_error,
        }))
    }
}

fn delegation_request_envelope(request: DelegationRequest, context: &MessageContext) -> Envelope {
    let mut envelope = Envelope::new(MessageBody::DelegationRequest(Box::new(request.clone())));
    envelope.session_id.clone_from(&context.session_id);
    envelope.correlation_id = Some(context.correlation_id.clone().unwrap_or_default());
    envelope.from = Some(request.requested_by);
    envelope.to = Some(request.delegate);
    envelope
}

fn identity_resolution_error(error: AuthError) -> GatewayError {
    let code = match &error {
        AuthError::MissingCredential => "credential.required",
        AuthError::MissingScope(_) => "credential.scope_missing",
        AuthError::CredentialExpired => "credential.expired",
        AuthError::TenantMembershipRequired | AuthError::TenantSelectorRequired => {
            "auth.tenant_required"
        }
        AuthError::TenantMismatch { .. } => "auth.tenant_mismatch",
        AuthError::AuthenticationExpired => "auth.expired",
        AuthError::TenantMembershipExpired => "auth.tenant_membership_expired",
        AuthError::OwnershipDenied => "auth.not_authorized",
        AuthError::Resolution(_) | AuthError::Token(_) | AuthError::Credential(_) => {
            "auth.identity_resolution_failed"
        }
    };
    GatewayError::Policy(Box::new(ProtocolError {
        code: code.to_owned(),
        message: error.to_string(),
        category: ErrorCategory::Auth,
        retryable: Some(false),
        retry_after_ms: None,
        details: None,
        source: Some(Box::new(serde_json::json!({
            "component": "aip-gateway.identity-resolution"
        }))),
    }))
}

fn requires_operational_sender(body: &MessageBody) -> bool {
    matches!(
        body,
        MessageBody::Cancel(_)
            | MessageBody::ActionStatusRequest(_)
            | MessageBody::ActionResultRequest(_)
            | MessageBody::ActionListRequest(_)
            | MessageBody::ActionEventsRequest(_)
            | MessageBody::SessionRequest(_)
            | MessageBody::SessionListRequest(_)
            | MessageBody::SessionCloseRequest(_)
            | MessageBody::SessionResumeRequest(_)
            | MessageBody::ApprovalQueryRequest(_)
            | MessageBody::ApprovalListRequest(_)
            | MessageBody::CallbackDeliveryQueryRequest(_)
            | MessageBody::CallbackDeliveryListRequest(_)
            | MessageBody::TransactionQueryRequest(_)
            | MessageBody::ReceiptQueryRequest(_)
            | MessageBody::AuditQueryRequest(_)
            | MessageBody::ResourceListRequest(_)
            | MessageBody::ResourceReadRequest(_)
            | MessageBody::EventStreamRequest(_)
    )
}

fn session_selector_for_body(body: &MessageBody) -> Option<&SessionId> {
    match body {
        MessageBody::ActionListRequest(request) => request.session_id.as_ref(),
        MessageBody::SessionRequest(request) => Some(&request.session_id),
        MessageBody::SessionCloseRequest(request) => Some(&request.session_id),
        MessageBody::SessionResumeRequest(request) => Some(&request.session_id),
        MessageBody::AuditQueryRequest(request) => request.session_id.as_ref(),
        _ => None,
    }
}

fn tenant_selector_for_body(body: &MessageBody) -> Option<&str> {
    match body {
        MessageBody::ActionStatusRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ActionResultRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ActionListRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ActionEventsRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ApprovalQueryRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ApprovalListRequest(request) => request.tenant_id.as_deref(),
        MessageBody::CallbackDeliveryQueryRequest(request) => request.tenant_id.as_deref(),
        MessageBody::CallbackDeliveryListRequest(request) => request.tenant_id.as_deref(),
        MessageBody::TransactionQueryRequest(request) => request.tenant_id.as_deref(),
        MessageBody::AuditQueryRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ResourceListRequest(request) => request.tenant_id.as_deref(),
        MessageBody::ResourceReadRequest(request) => request.tenant_id.as_deref(),
        _ => None,
    }
}

fn query_object_and_operation(body: &MessageBody) -> Option<(QueryObject, QueryOperation)> {
    match body {
        MessageBody::ActionStatusRequest(_)
        | MessageBody::ActionResultRequest(_)
        | MessageBody::ActionListRequest(_)
        | MessageBody::ActionEventsRequest(_) => Some((QueryObject::Action, QueryOperation::Read)),
        MessageBody::SessionRequest(_) | MessageBody::SessionListRequest(_) => {
            Some((QueryObject::Session, QueryOperation::Read))
        }
        MessageBody::SessionCloseRequest(_) | MessageBody::SessionResumeRequest(_) => {
            Some((QueryObject::Session, QueryOperation::Write))
        }
        MessageBody::ApprovalQueryRequest(_) | MessageBody::ApprovalListRequest(_) => {
            Some((QueryObject::Approval, QueryOperation::Read))
        }
        MessageBody::CallbackDeliveryQueryRequest(_)
        | MessageBody::CallbackDeliveryListRequest(_) => {
            Some((QueryObject::Callback, QueryOperation::Read))
        }
        MessageBody::TransactionQueryRequest(_) => {
            Some((QueryObject::Transaction, QueryOperation::Read))
        }
        MessageBody::ReceiptQueryRequest(_) => Some((QueryObject::Receipt, QueryOperation::Read)),
        MessageBody::AuditQueryRequest(request) => Some((
            QueryObject::Audit,
            if request.export || request.include_receipts {
                QueryOperation::Export
            } else {
                QueryOperation::Read
            },
        )),
        MessageBody::ResourceListRequest(_) | MessageBody::ResourceReadRequest(_) => {
            Some((QueryObject::Resource, QueryOperation::Read))
        }
        MessageBody::EventStreamRequest(_) => Some((QueryObject::Event, QueryOperation::Read)),
        _ => None,
    }
}

fn resolved_identity_context(
    tenant: Option<&VerifiedTenant>,
    credential: Option<&CredentialHandle>,
) -> Option<IdentityContext> {
    if tenant.is_none() && credential.is_none() {
        return None;
    }
    Some(IdentityContext {
        tenant: tenant.map(|tenant| tenant.tenant.clone()),
        external_account: None,
        external_user: None,
        human_actor: None,
        service_account: None,
        acted_on_behalf_of: None,
        credential_ref: credential.map(|credential| CredentialRef {
            id: credential.id().to_owned(),
            issuer: credential.issuer().to_owned(),
            scopes: credential.scopes().iter().cloned().collect(),
        }),
        oauth: None,
    })
}

fn principal_scope_set(principal: &Principal) -> BTreeSet<String> {
    let Some(scopes) = principal
        .auth_context
        .as_ref()
        .and_then(|context| context.get("scopes"))
    else {
        return BTreeSet::new();
    };
    match scopes {
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        serde_json::Value::String(value) => BTreeSet::from([value.clone()]),
        _ => BTreeSet::new(),
    }
}

fn principal_selectors_for_body(body: &MessageBody) -> Vec<&PrincipalId> {
    let mut selectors = Vec::new();
    match body {
        MessageBody::ActionListRequest(request) => {
            if let Some(principal_id) = request.principal_id.as_ref() {
                selectors.push(principal_id);
            }
        }
        MessageBody::SessionListRequest(request) => {
            if let Some(principal_id) = request.principal_id.as_ref() {
                selectors.push(principal_id);
            }
        }
        MessageBody::ApprovalListRequest(request) => {
            if let Some(principal_id) = request.requester.as_ref() {
                selectors.push(principal_id);
            }
            if let Some(principal_id) = request.approver.as_ref() {
                selectors.push(principal_id);
            }
        }
        MessageBody::AuditQueryRequest(request) => {
            if let Some(principal_id) = request.principal_id.as_ref() {
                selectors.push(principal_id);
            }
        }
        _ => {}
    }
    selectors
}

fn sign_peer_request(
    mut envelope: Envelope,
    security: &DelegationPeerSecurity,
) -> RuntimeResult<Envelope> {
    let metadata = envelope
        .security
        .get_or_insert_with(|| serde_json::json!({}));
    let metadata = metadata.as_object_mut().ok_or_else(|| {
        RuntimeError::Authorization("native peer security metadata must be an object".to_owned())
    })?;
    metadata.insert(
        "trust_domain".to_owned(),
        serde_json::json!(security.trust_domain),
    );
    if let Some(credential) = &security.credential {
        metadata.insert(
            "credential_handle".to_owned(),
            serde_json::json!({
                "id": credential.id(),
                "issuer": credential.issuer()
            }),
        );
    }
    sign_native_envelope(envelope, &security.request_signer)
}

fn verify_peer_response(
    request: &Envelope,
    response: &Envelope,
    security: &DelegationPeerSecurity,
) -> RuntimeResult<()> {
    let response_did = response
        .security
        .as_ref()
        .and_then(|value| value.get("did"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            RuntimeError::Authorization("native peer response is not signed".to_owned())
        })?;
    if response_did != security.expected_peer_did {
        return Err(RuntimeError::Authorization(format!(
            "native peer response DID `{response_did}` does not match the bound peer"
        )));
    }
    let signature = response
        .security
        .as_ref()
        .and_then(|value| value.get("signature"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            RuntimeError::Authorization("native peer response signature is missing".to_owned())
        })?;
    let key = verifying_key_from_did_key(&security.expected_peer_did)
        .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    verify_envelope(response, signature, &key)
        .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    if response.from.as_ref().is_none_or(|peer| {
        peer.id != security.expected_peer.id || peer.kind != security.expected_peer.kind
    }) {
        return Err(RuntimeError::Authorization(
            "native peer response principal does not match the bound peer".to_owned(),
        ));
    }
    if response.to.as_ref().is_none_or(|recipient| {
        recipient.id != security.request_signer.principal.id
            || recipient.kind != security.request_signer.principal.kind
    }) {
        return Err(RuntimeError::Authorization(
            "native peer response recipient does not match the request signer".to_owned(),
        ));
    }
    if response.correlation_id != request.correlation_id {
        return Err(RuntimeError::Authorization(
            "native peer response correlation id does not match the request".to_owned(),
        ));
    }
    if !matches!(
        response.in_response_to.as_ref(),
        Some(MessageReference::Message(message_id)) if message_id == &request.message_id
    ) {
        return Err(RuntimeError::Authorization(
            "native peer response does not reference the exact request message".to_owned(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    let allowed_skew = time::Duration::minutes(5);
    if response.sent_at < now - allowed_skew || response.sent_at > now + allowed_skew {
        return Err(RuntimeError::Authorization(
            "native peer response timestamp is outside the accepted window".to_owned(),
        ));
    }
    Ok(())
}

async fn post_secure_callback(
    policy: &GatewayCallbackPolicy,
    target: &str,
    envelope: &Envelope,
) -> RuntimeResult<()> {
    let (url, host, pinned_address) = validate_callback_url(policy, target).await?;
    let client = apply_tls_policy(reqwest::Client::builder(), policy)?
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(policy.request_timeout_ms.max(1)))
        .resolve(&host, pinned_address)
        .build()
        .map_err(|error| RuntimeError::Handler(format!("callback client failed: {error}")))?;
    let mut request = client.post(url).json(envelope);
    if let Some(idempotency_key) = &envelope.idempotency_key {
        request = request.header("Idempotency-Key", idempotency_key);
    }
    let response = request
        .send()
        .await
        .map_err(|error| RuntimeError::Handler(format!("callback request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(RuntimeError::Handler(format!(
            "callback target returned status {}",
            response.status()
        )));
    }
    Ok(())
}

async fn post_secure_a2a_callback(
    policy: &GatewayCallbackPolicy,
    callback: &Callback,
    envelope: &Envelope,
) -> RuntimeResult<()> {
    let (url, host, pinned_address) = validate_callback_url(policy, &callback.target).await?;
    let metadata = callback
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("a2a"))
        .ok_or_else(|| RuntimeError::Handler("A2A callback metadata is missing".to_owned()))?;
    let payload = if let Some(payload) = metadata.get("payload") {
        payload.clone()
    } else {
        let MessageBody::ActionResult(result) = &envelope.body else {
            return Err(RuntimeError::Handler(
                "A2A callback requires an ActionResult or explicit StreamResponse payload"
                    .to_owned(),
            ));
        };
        let task_id = metadata
            .get("taskId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| result.action_id.as_str())
            .to_owned();
        let skill_id = metadata
            .get("skillId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        serde_json::json!({
            "task": aip_profile_a2a::task_from_result(task_id, skill_id, result)
        })
    };
    let credentials = match metadata.get("encryptedCredentials") {
        Some(value) => {
            let encrypted =
                serde_json::from_value::<EncryptedA2aCallbackCredentials>(value.clone()).map_err(
                    |_| RuntimeError::Authorization("invalid encrypted A2A credentials".to_owned()),
                )?;
            let aad = metadata
                .get("credentialAad")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    RuntimeError::Authorization("A2A credential AAD is missing".to_owned())
                })?;
            policy
                .a2a_credential_key
                .as_ref()
                .ok_or_else(|| {
                    RuntimeError::Authorization(
                        "A2A callback credentials require a configured decryption key".to_owned(),
                    )
                })?
                .open(aad, &encrypted)?
        }
        None => A2aCallbackCredentials::default(),
    };
    let signer = policy.signer.as_ref().ok_or_else(|| {
        RuntimeError::Authorization(
            "external A2A callbacks require a configured Ed25519 signer".to_owned(),
        )
    })?;
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| RuntimeError::Handler(format!("callback timestamp failed: {error}")))?;
    let signature_input = serde_json::json!({
        "messageId": envelope.message_id,
        "target": callback.target,
        "timestamp": timestamp,
        "payload": payload
    });
    let signature = sign_value(&signature_input, &signer.signing_key)
        .map_err(|error| RuntimeError::Handler(format!("A2A callback signing failed: {error}")))?;
    let did = did_key_from_verifying_key(&signer.signing_key.verifying_key());
    let client = apply_tls_policy(reqwest::Client::builder(), policy)?
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(policy.request_timeout_ms.max(1)))
        .resolve(&host, pinned_address)
        .build()
        .map_err(|error| RuntimeError::Handler(format!("A2A callback client failed: {error}")))?;
    let mut request = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/a2a+json")
        .header("AIP-Callback-DID", did)
        .header("AIP-Callback-Signature", signature)
        .header("AIP-Callback-Timestamp", timestamp)
        .header("AIP-Callback-Message-ID", envelope.message_id.as_str())
        .json(&payload);
    if let Some(token) = credentials.token.as_deref() {
        reject_callback_header_injection("A2A callback token", token)?;
        request = request.header("X-A2A-Notification-Token", token);
    }
    match (
        credentials.authentication_scheme.as_deref(),
        credentials.authentication_credentials.as_deref(),
    ) {
        (Some(scheme), Some(credentials)) => {
            validate_http_auth_scheme(scheme)?;
            reject_callback_header_injection("A2A callback credentials", credentials)?;
            request = request.header(
                reqwest::header::AUTHORIZATION,
                format!("{scheme} {credentials}"),
            );
        }
        (None, None) => {}
        _ => {
            return Err(RuntimeError::Authorization(
                "A2A callback authentication requires both scheme and credentials".to_owned(),
            ));
        }
    }
    let response = request
        .send()
        .await
        .map_err(|error| RuntimeError::Handler(format!("A2A callback request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(RuntimeError::Handler(format!(
            "A2A callback target returned status {}",
            response.status()
        )));
    }
    Ok(())
}

fn validate_http_auth_scheme(scheme: &str) -> RuntimeResult<()> {
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RuntimeError::Authorization(
            "invalid A2A HTTP authentication scheme".to_owned(),
        ));
    }
    Ok(())
}

fn reject_callback_header_injection(label: &str, value: &str) -> RuntimeResult<()> {
    if value.contains(['\r', '\n']) {
        return Err(RuntimeError::Authorization(format!(
            "{label} contains forbidden control characters"
        )));
    }
    Ok(())
}

async fn validate_callback_url(
    policy: &GatewayCallbackPolicy,
    target: &str,
) -> RuntimeResult<(Url, String, SocketAddr)> {
    let url = Url::parse(target)
        .map_err(|error| RuntimeError::Authorization(format!("invalid callback URL: {error}")))?;
    match url.scheme() {
        "https" | "nats" | "tls" => {}
        "http" if policy.allow_http => {}
        scheme => {
            return Err(RuntimeError::Authorization(format!(
                "callback URL scheme `{scheme}` is not allowed"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RuntimeError::Authorization(
            "callback URL credentials are forbidden".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| RuntimeError::Authorization("callback URL has no host".to_owned()))?;
    if !policy.allowed_hosts.contains(&host) {
        return Err(RuntimeError::Authorization(format!(
            "callback host `{host}` is not allowlisted"
        )));
    }
    let port = url
        .port()
        .or_else(|| match url.scheme() {
            "https" => Some(443),
            "http" => Some(80),
            "nats" | "tls" => Some(4222),
            _ => None,
        })
        .ok_or_else(|| RuntimeError::Authorization("callback URL has no usable port".to_owned()))?;
    let addresses = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| RuntimeError::Handler(format!("callback DNS lookup failed: {error}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(RuntimeError::Handler(
            "callback DNS lookup returned no addresses".to_owned(),
        ));
    }
    if !policy.allow_private_networks
        && addresses
            .iter()
            .any(|address| callback_ip_is_non_public(address.ip()))
    {
        return Err(RuntimeError::Authorization(format!(
            "callback host `{host}` resolves to a non-public address"
        )));
    }
    Ok((url, host, addresses[0]))
}

fn callback_ip_is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
    }
}

async fn request_native_nats(
    server_url: String,
    subject: String,
    timeout_ms: u64,
    envelope: Envelope,
) -> RuntimeResult<Envelope> {
    let message_type = envelope.message_type;
    let mut config = NatsTransportConfig::new(
        server_url,
        NatsSubject {
            trust_domain: "callback".to_owned(),
            service: "gateway".to_owned(),
            version: "v1".to_owned(),
            message_type,
        },
    );
    config.request_timeout_ms = timeout_ms;
    let transport = NatsTransport::connect(config)
        .await
        .map_err(|error| RuntimeError::Handler(format!("native NATS connect failed: {error}")))?;
    let response = transport
        .request_on(subject, TransportMessage::new(envelope))
        .await
        .map_err(|error| RuntimeError::Handler(format!("native NATS request failed: {error}")))?;
    Ok(response.envelope)
}

async fn publish_native_nats(
    server_url: String,
    subject: String,
    envelope: Envelope,
) -> RuntimeResult<()> {
    let message_type = envelope.message_type;
    let transport = NatsTransport::connect(NatsTransportConfig::new(
        server_url,
        NatsSubject {
            trust_domain: "callback".to_owned(),
            service: "gateway".to_owned(),
            version: "v1".to_owned(),
            message_type,
        },
    ))
    .await
    .map_err(|error| RuntimeError::Handler(format!("native NATS connect failed: {error}")))?;
    let headers = nats_headers_for_envelope(&envelope)
        .map_err(|error| RuntimeError::Handler(format!("native NATS headers failed: {error}")))?;
    let payload = serde_json::to_vec(&TransportMessage::new(envelope))
        .map_err(|error| RuntimeError::Handler(format!("native NATS encode failed: {error}")))?;
    transport
        .client()
        .publish_with_headers(subject, headers, payload.into())
        .await
        .map_err(|error| RuntimeError::Handler(format!("native NATS publish failed: {error}")))?;
    Ok(())
}

fn parse_nats_target(target: &str) -> RuntimeResult<(String, String)> {
    let rest = target.strip_prefix("nats://").ok_or_else(|| {
        RuntimeError::Handler("NATS callback target must start with `nats://`".to_owned())
    })?;
    let (authority, subject) = rest.split_once('/').ok_or_else(|| {
        RuntimeError::Handler("NATS callback target must include a subject path".to_owned())
    })?;
    if authority.trim().is_empty() || subject.trim().is_empty() {
        return Err(RuntimeError::Handler(
            "NATS callback target must include server and subject".to_owned(),
        ));
    }
    Ok((format!("nats://{authority}"), subject.replace('/', ".")))
}

/// Verifies a signed native AIP envelope and returns its `did:key` verifier.
///
/// This function proves key possession only. Callers must independently bind
/// the returned DID to an expected peer principal or trust-domain policy.
pub fn verify_native_envelope_signature(envelope: &Envelope) -> GatewayResult<String> {
    let security = envelope
        .security
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| GatewayError::Signature("missing security object".to_owned()))?;
    let signature = security
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| GatewayError::Signature("missing security.signature".to_owned()))?;
    let did = security
        .get("did")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            envelope
                .from
                .as_ref()
                .and_then(|principal| principal.did.as_deref())
        })
        .ok_or_else(|| GatewayError::Signature("missing did:key verifier".to_owned()))?;
    let key = verifying_key_from_did_key(did)
        .map_err(|error| GatewayError::Signature(error.to_string()))?;
    verify_envelope(envelope, signature, &key)
        .map_err(|error| GatewayError::Signature(error.to_string()))?;
    Ok(did.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        A2aCallbackCredentialKey, A2aCallbackCredentials, CallbackSigner, DelegationPeerSecurity,
        DelegationRoute, Gateway, GatewayCallbackDispatcher, GatewayCallbackPolicy, GatewayPolicy,
        NativeAipHttpClient, sign_native_envelope,
    };
    use aip_auth::{
        AuthError as IdentityAuthError, CredentialHandle, IdentityResolutionRequest,
        ResolvedIdentity, TrustedIdentityResolver,
    };
    use aip_auth::{AuthScheme, AuthenticatedPrincipal, VerifiedTenant};
    use aip_core::TenantRef;
    use aip_core::{
        AckStatus, Action, ActionId, ActionLifecycleState, ActionListRequest, ActionMode,
        ActionResult, ActionResultStatus, ActionStatusRequest, AuditQueryRequest, Callback, Cancel,
        CancelTarget, Capability, CapabilityId, CapabilityKind, DelegatedAuthorityGrant,
        DelegationId, DelegationRequest, DelegationStatus, Envelope, Handshake, Manifest,
        ManifestRequest, MessageBody, MessageReference, Principal, PrincipalId, PrincipalKind,
        ProfileId, ResourceListRequest, SessionId, SessionRequest,
    };
    use aip_runtime::{
        ActionHandler, CallbackDispatcher, DelegationRouter, EchoHandler, MessageContext, Runtime,
        RuntimeError, RuntimeResult,
    };
    use aip_transport::StreamingTransport;
    use aip_transport_sse::decode_sse;
    use axum::{
        Json, Router,
        body::{Body, Bytes},
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use futures_util::stream;
    use serde_json::json;
    use std::{
        collections::HashMap,
        convert::Infallible,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn native_http_client_cache_is_bounded_and_evicts_least_recently_used_entries() {
        let client = NativeAipHttpClient::new(2);
        let policy = GatewayCallbackPolicy::default();
        let first_address = "127.0.0.1:18001"
            .parse::<SocketAddr>()
            .expect("first address");
        let second_address = "127.0.0.1:18002"
            .parse::<SocketAddr>()
            .expect("second address");
        let third_address = "127.0.0.1:18003"
            .parse::<SocketAddr>()
            .expect("third address");

        client
            .client_for("first.test", first_address, &policy)
            .await
            .expect("first client");
        client
            .client_for("second.test", second_address, &policy)
            .await
            .expect("second client");
        client
            .client_for("first.test", first_address, &policy)
            .await
            .expect("touch first client");
        client
            .client_for("third.test", third_address, &policy)
            .await
            .expect("third client evicts second");
        let after_first_eviction = client.cache_snapshot().await;
        assert_eq!(after_first_eviction.entries, 2);
        assert_eq!(after_first_eviction.capacity, 2);
        assert_eq!(after_first_eviction.hits, 1);
        assert_eq!(after_first_eviction.misses, 3);
        assert_eq!(after_first_eviction.evictions, 1);

        client
            .client_for("second.test", second_address, &policy)
            .await
            .expect("evicted client is rebuilt");
        let final_snapshot = client.cache_snapshot().await;
        assert_eq!(final_snapshot.entries, 2);
        assert_eq!(final_snapshot.hits, 1);
        assert_eq!(final_snapshot.misses, 4);
        assert_eq!(final_snapshot.evictions, 2);
    }

    #[tokio::test]
    async fn native_http_client_rejects_fixed_and_streamed_oversized_responses() {
        async fn fixed() -> Response {
            (StatusCode::OK, "x".repeat(128)).into_response()
        }
        async fn streamed() -> Response {
            let chunks = stream::iter([
                Ok::<Bytes, Infallible>(Bytes::from(vec![b'x'; 24])),
                Ok::<Bytes, Infallible>(Bytes::from(vec![b'y'; 24])),
            ]);
            Response::new(Body::from_stream(chunks))
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let app = Router::new()
            .route("/fixed", post(fixed))
            .route("/streamed", post(streamed));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("oversized server");
        });

        let requester = Principal::new(
            PrincipalId::trusted("service:test:bounded-client"),
            PrincipalKind::Service,
        );
        let peer = Principal::new(
            PrincipalId::trusted("service:test:bounded-peer"),
            PrincipalKind::Service,
        );
        let requester_key = Arc::new(aip_crypto::signing_key_from_seed([91_u8; 32]));
        let peer_key = aip_crypto::signing_key_from_seed([92_u8; 32]);
        let mut endpoint_policy = GatewayCallbackPolicy::default();
        endpoint_policy.allowed_hosts.insert("127.0.0.1".to_owned());
        endpoint_policy.allow_http = true;
        endpoint_policy.allow_private_networks = true;
        endpoint_policy.max_response_bytes = 32;
        let security = DelegationPeerSecurity::new(
            "bounded.test",
            CallbackSigner {
                principal: requester,
                signing_key: requester_key,
            },
            peer,
            aip_crypto::did_key_from_verifying_key(&peer_key.verifying_key()),
            endpoint_policy,
        )
        .expect("peer security");
        let request = || {
            Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
                profiles: Vec::new(),
                filter: None,
            }))
        };
        let client = NativeAipHttpClient::new(2);
        for path in ["fixed", "streamed"] {
            let error = client
                .exchange(&format!("http://{address}/{path}"), request(), &security)
                .await
                .expect_err("oversized response must fail closed");
            assert!(
                error.to_string().contains("exceeded 32 bytes"),
                "unexpected {path} error: {error}"
            );
        }
        server.abort();
    }

    #[derive(Clone, Default)]
    struct A2aCallbackCapture(Arc<Mutex<Option<(HeaderMap, serde_json::Value)>>>);

    #[derive(Clone)]
    struct TestPeerState {
        gateway: Gateway,
        signer: CallbackSigner,
    }

    #[derive(Clone)]
    struct ConnectorDelegationRouter {
        delegate_id: PrincipalId,
        calls: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct ContextCapturingDelegationRouter {
        delegate_id: PrincipalId,
        observed: Arc<Mutex<Option<MessageContext>>>,
    }

    #[async_trait::async_trait]
    impl DelegationRouter for ConnectorDelegationRouter {
        async fn can_route(&self, request: &DelegationRequest) -> bool {
            request.delegate.id == self.delegate_id
        }

        async fn route(
            &self,
            request: &DelegationRequest,
            _context: &MessageContext,
        ) -> RuntimeResult<Option<aip_core::DelegationResult>> {
            if !self.can_route(request).await {
                return Ok(None);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(aip_core::DelegationResult {
                delegation_id: request.delegation_id.clone(),
                parent_action_id: request.parent_action_id.clone(),
                child_action_id: request.child_action.id.clone(),
                status: DelegationStatus::Completed,
                error: None,
                result: Some(ActionResult {
                    action_id: request.child_action.id.clone(),
                    status: ActionResultStatus::Completed,
                    output: Some(json!({ "connector_router": true })),
                    message: Vec::new(),
                    memory_update: None,
                    usage: None,
                    receipt: None,
                    error: None,
                }),
                receipt_chain: None,
                callback: None,
            }))
        }
    }

    #[async_trait::async_trait]
    impl DelegationRouter for ContextCapturingDelegationRouter {
        async fn can_route(&self, request: &DelegationRequest) -> bool {
            request.delegate.id == self.delegate_id
        }

        async fn route(
            &self,
            request: &DelegationRequest,
            context: &MessageContext,
        ) -> RuntimeResult<Option<aip_core::DelegationResult>> {
            if !self.can_route(request).await {
                return Ok(None);
            }
            *self.observed.lock().await = Some(context.clone());
            Ok(Some(aip_core::DelegationResult {
                delegation_id: request.delegation_id.clone(),
                parent_action_id: request.parent_action_id.clone(),
                child_action_id: request.child_action.id.clone(),
                status: DelegationStatus::Completed,
                error: None,
                result: Some(ActionResult {
                    action_id: request.child_action.id.clone(),
                    status: ActionResultStatus::Completed,
                    output: Some(json!({ "context_captured": true })),
                    message: Vec::new(),
                    memory_update: None,
                    usage: None,
                    receipt: None,
                    error: None,
                }),
                receipt_chain: None,
                callback: None,
            }))
        }
    }

    #[derive(Clone)]
    struct FixedIdentityResolver {
        resolved: ResolvedIdentity,
    }

    #[derive(Clone, Debug)]
    struct FullSupportEcho;

    #[async_trait::async_trait]
    impl ActionHandler for FullSupportEcho {
        fn implementation_support(&self) -> aip_discovery::CapabilityImplementationSupport {
            aip_discovery::CapabilityImplementationSupport {
                invocation: true,
                cancellation: true,
                streaming: true,
                retry: true,
                transaction: true,
                reconciliation: true,
                compensation: true,
                approval: true,
                credentials: true,
            }
        }

        async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
            EchoHandler.handle(action).await
        }
    }

    #[async_trait::async_trait]
    impl TrustedIdentityResolver for FixedIdentityResolver {
        async fn resolve(
            &self,
            _request: IdentityResolutionRequest<'_>,
        ) -> Result<ResolvedIdentity, IdentityAuthError> {
            Ok(self.resolved.clone())
        }
    }

    async fn capture_a2a_callback(
        State(capture): State<A2aCallbackCapture>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        *capture.0.lock().await = Some((headers, body));
        StatusCode::NO_CONTENT
    }

    fn authenticated_actor(mut principal: Principal, scopes: &[&str]) -> AuthenticatedPrincipal {
        // Transport-established claims replace payload-owned auth metadata.
        principal.auth_context = None;
        AuthenticatedPrincipal {
            principal,
            scheme: AuthScheme::DidProof,
            issuer: "test://gateway-authenticator".to_owned(),
            audience: Some("aip-gateway".to_owned()),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            authenticated_at: time::OffsetDateTime::now_utc(),
            expires_at: None,
            credential_fingerprint: Some("sha256:test-credential".to_owned()),
        }
    }

    fn verified_tenant(id: &str) -> VerifiedTenant {
        VerifiedTenant {
            tenant: TenantRef {
                id: id.to_owned(),
                system: Some("test-directory".to_owned()),
            },
            membership_id: format!("membership:{id}"),
            roles: Default::default(),
            groups: Default::default(),
            verified_at: time::OffsetDateTime::now_utc(),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn gateway_accepts_handshake() {
        let principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let response = gateway
            .handle_authenticated_envelope(
                Envelope::new(MessageBody::Handshake(Handshake {
                    client: principal.clone(),
                    purpose: "test".to_owned(),
                    requested_capabilities: Vec::new(),
                    profiles: vec![ProfileId::from("aip.native.http.v1")],
                    auth: None,
                    compliance_required: Vec::new(),
                    heartbeat: None,
                    encryption: None,
                    billing: None,
                })),
                principal,
            )
            .await
            .expect("response");
        assert!(matches!(response.body, MessageBody::HandshakeResponse(_)));
    }

    #[tokio::test]
    async fn gateway_rejects_action_without_sender() {
        let principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        let gateway = Gateway::with_policy(
            Manifest {
                manifest_version: "aip-manifest/v1".to_owned(),
                agent: principal,
                capabilities: Vec::new(),
                profiles: vec![ProfileId::from("aip.native.http.v1")],
                resources: Vec::new(),
                channels: Vec::new(),
                security: None,
                governance: None,
                limits: None,
                compatibility: None,
                extensions: None,
            },
            GatewayPolicy {
                require_signed_envelopes: false,
                ..GatewayPolicy::default()
            },
        )
        .await
        .expect("gateway");

        let error = gateway
            .handle_envelope(Envelope::new(MessageBody::Action(Box::new(Action::new(
                CapabilityId::trusted("cap:test:missing"),
                json!({}),
            )))))
            .await
            .expect_err("missing sender must be rejected");
        assert!(matches!(error, super::GatewayError::MissingSender));
    }

    #[tokio::test]
    async fn gateway_rejects_session_selector_mismatch() {
        let principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let mut envelope = Envelope::new(MessageBody::SessionRequest(SessionRequest {
            session_id: SessionId::new(),
        }));
        envelope.session_id = Some(SessionId::new());
        let error = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["session:read"]),
                None,
                None,
            )
            .await
            .expect_err("session mismatch must be rejected");
        match error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "auth.session_mismatch"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_rejects_query_tenant_mismatch() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context =
            Some(json!({ "tenant_id": "tenant-a", "scopes": ["action:read"] }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionStatusRequest(ActionStatusRequest {
            action_id: ActionId::new(),
            tenant_id: Some("tenant-b".to_owned()),
            include_result: false,
            include_receipts: false,
            include_chunks: false,
            wait_ms: None,
        }));
        let error = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("tenant mismatch must be rejected");
        match error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "auth.tenant_mismatch"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_requires_tenant_selector_for_tenant_scoped_queries() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context =
            Some(json!({ "tenant_id": "tenant-a", "scopes": ["action:read"] }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionStatusRequest(ActionStatusRequest {
            action_id: ActionId::new(),
            tenant_id: None,
            include_result: false,
            include_receipts: false,
            include_chunks: false,
            wait_ms: None,
        }));
        let error = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("missing tenant selector must be rejected");
        match error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "auth.tenant_required"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_allows_global_query_with_tenant_any_scope() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context = Some(json!({
            "tenant_id": "tenant-a",
            "scopes": ["action:read", "action:read:any"]
        }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionStatusRequest(ActionStatusRequest {
            action_id: ActionId::new(),
            tenant_id: None,
            include_result: false,
            include_receipts: false,
            include_chunks: false,
            wait_ms: None,
        }));
        let response = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["action:read", "action:read:any"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect("response");
        assert!(matches!(response.body, MessageBody::ActionStatus(_)));
    }

    #[tokio::test]
    async fn gateway_enforces_operational_query_scopes() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context =
            Some(json!({ "tenant_id": "tenant-a", "scopes": ["action:read"] }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");

        let audit = Envelope::new(MessageBody::AuditQueryRequest(AuditQueryRequest {
            tenant_id: Some("tenant-a".to_owned()),
            ..AuditQueryRequest::default()
        }));
        let audit_error = gateway
            .handle_verified_envelope(
                audit,
                authenticated_actor(principal.clone(), &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("audit query must require audit scope");
        match audit_error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "audit.not_authorized"),
            other => panic!("unexpected error: {other:?}"),
        }

        let resources = Envelope::new(MessageBody::ResourceListRequest(ResourceListRequest {
            tenant_id: Some("tenant-a".to_owned()),
            ..ResourceListRequest::default()
        }));
        let resource_error = gateway
            .handle_verified_envelope(
                resources,
                authenticated_actor(principal, &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("resource list must require resource scope");
        match resource_error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "auth.not_authorized"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_requires_audit_export_scope_for_evidence_queries() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:audit-reader").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context = Some(json!({
            "tenant_id": "tenant-a",
            "scopes": ["audit:read"]
        }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::AuditQueryRequest(AuditQueryRequest {
            tenant_id: Some("tenant-a".to_owned()),
            include_receipts: true,
            export: true,
            ..AuditQueryRequest::default()
        }));
        let error = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["audit:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("audit evidence export must require audit:export");
        match error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "audit.not_authorized"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_rejects_cross_principal_action_list_without_any_scope() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:alice").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context =
            Some(json!({ "tenant_id": "tenant-a", "scopes": ["action:read"] }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionListRequest(ActionListRequest {
            principal_id: Some(PrincipalId::parse("agent:bob").expect("principal")),
            ..ActionListRequest {
                state: None,
                capability_id: None,
                session_id: None,
                principal_id: None,
                approval_id: None,
                transaction_id: None,
                tenant_id: Some("tenant-a".to_owned()),
                cursor: None,
                limit: None,
                include_results: false,
                include_receipts: false,
            }
        }));
        let error = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("cross-principal selector must require any scope");
        match error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "auth.not_authorized"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_allows_cross_principal_action_list_with_any_scope() {
        let mut principal = Principal::new(
            PrincipalId::parse("agent:alice").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context = Some(json!({
            "tenant_id": "tenant-a",
            "scopes": ["action:read", "action:read:any"]
        }));
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionListRequest(ActionListRequest {
            principal_id: Some(PrincipalId::parse("agent:bob").expect("principal")),
            tenant_id: Some("tenant-a".to_owned()),
            ..ActionListRequest {
                state: None,
                capability_id: None,
                session_id: None,
                principal_id: None,
                approval_id: None,
                transaction_id: None,
                tenant_id: None,
                cursor: None,
                limit: None,
                include_results: false,
                include_receipts: false,
            }
        }));
        let response = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["action:read", "action:read:any"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect("response");
        assert!(matches!(response.body, MessageBody::ActionList(_)));
    }

    #[tokio::test]
    async fn gateway_allows_cross_principal_action_list_with_delegated_authority() {
        let owner_id = PrincipalId::parse("agent:owner").expect("principal");
        let mut principal = Principal::new(
            PrincipalId::parse("agent:delegate").expect("principal"),
            PrincipalKind::Agent,
        );
        principal.auth_context =
            Some(json!({ "tenant_id": "tenant-a", "scopes": ["action:read"] }));
        principal.delegated_authority.push(DelegatedAuthorityGrant {
            principal_id: owner_id.clone(),
            scopes: vec!["action:read".to_owned()],
            expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::minutes(5)),
            reason: Some("unit-test delegated gateway selector".to_owned()),
        });
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionListRequest(ActionListRequest {
            principal_id: Some(owner_id.clone()),
            tenant_id: Some("tenant-a".to_owned()),
            ..ActionListRequest {
                state: None,
                capability_id: None,
                session_id: None,
                principal_id: None,
                approval_id: None,
                transaction_id: None,
                tenant_id: None,
                cursor: None,
                limit: None,
                include_results: false,
                include_receipts: false,
            }
        }));
        let response = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal.clone(), &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect("delegated selector must be accepted");
        assert!(matches!(response.body, MessageBody::ActionList(_)));

        let mut expired = principal;
        expired.delegated_authority[0].expires_at =
            Some(time::OffsetDateTime::now_utc() - time::Duration::minutes(1));
        let expired_envelope = Envelope::new(MessageBody::ActionListRequest(ActionListRequest {
            principal_id: Some(owner_id),
            tenant_id: Some("tenant-a".to_owned()),
            ..ActionListRequest {
                state: None,
                capability_id: None,
                session_id: None,
                principal_id: None,
                approval_id: None,
                transaction_id: None,
                tenant_id: None,
                cursor: None,
                limit: None,
                include_results: false,
                include_receipts: false,
            }
        }));
        let error = gateway
            .handle_verified_envelope(
                expired_envelope,
                authenticated_actor(expired, &["action:read"]),
                Some(verified_tenant("tenant-a")),
                None,
            )
            .await
            .expect_err("expired delegated selector must be rejected");
        match error {
            super::GatewayError::Policy(error) => assert_eq!(error.code, "auth.not_authorized"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_routes_native_action_status_request() {
        let principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::ActionStatusRequest(ActionStatusRequest {
            action_id: ActionId::new(),
            tenant_id: None,
            include_result: true,
            include_receipts: false,
            include_chunks: false,
            wait_ms: None,
        }));
        let response = gateway
            .handle_verified_envelope(
                envelope,
                authenticated_actor(principal, &["action:read"]),
                None,
                None,
            )
            .await
            .expect("response");
        let MessageBody::ActionStatus(status) = response.body else {
            panic!("expected action status");
        };
        assert_eq!(status.state, ActionLifecycleState::Unknown);
    }

    #[tokio::test]
    async fn gateway_rejects_replayed_message_id() {
        let principal = Principal::new(
            PrincipalId::parse("agent:test").expect("principal"),
            PrincipalKind::Agent,
        );
        let gateway = Gateway::new(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        })
        .await
        .expect("gateway");
        let envelope = Envelope::new(MessageBody::Handshake(Handshake {
            client: principal.clone(),
            purpose: "test".to_owned(),
            requested_capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            auth: None,
            compliance_required: Vec::new(),
            heartbeat: None,
            encryption: None,
            billing: None,
        }));

        gateway
            .handle_authenticated_envelope(envelope.clone(), principal.clone())
            .await
            .expect("first request");
        let error = gateway
            .handle_authenticated_envelope(envelope, principal)
            .await
            .expect_err("replay must be rejected");
        assert!(matches!(error, super::GatewayError::Replay(_)));
    }

    #[tokio::test]
    async fn gateway_replay_claim_survives_durable_runtime_restart() {
        let root = std::env::temp_dir().join(format!(
            "aip-gateway-replay-{}-{}",
            std::process::id(),
            aip_core::ActionId::new()
        ));
        let principal = Principal::new(
            PrincipalId::trusted("agent:durable-replay"),
            PrincipalKind::Agent,
        );
        let manifest = manifest_for(principal.clone(), Vec::new());
        let policy = GatewayPolicy {
            require_signed_envelopes: false,
            ..GatewayPolicy::default()
        };
        let envelope = Envelope::new(MessageBody::Handshake(Handshake {
            client: principal.clone(),
            purpose: "durable replay proof".to_owned(),
            requested_capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            auth: None,
            compliance_required: Vec::new(),
            heartbeat: None,
            encryption: None,
            billing: None,
        }));
        let first = Gateway::with_policy_and_runtime(
            manifest.clone(),
            policy.clone(),
            Runtime::durable_local(root.clone())
                .await
                .expect("first runtime"),
        )
        .await
        .expect("first gateway");
        first
            .handle_authenticated_envelope(envelope.clone(), principal.clone())
            .await
            .expect("first delivery");
        drop(first);

        let second = Gateway::with_policy_and_runtime(
            manifest,
            policy,
            Runtime::durable_local(root.clone())
                .await
                .expect("second runtime"),
        )
        .await
        .expect("second gateway");
        let error = second
            .handle_authenticated_envelope(envelope, principal)
            .await
            .expect_err("replayed message must remain claimed after restart");
        assert!(matches!(error, super::GatewayError::Replay(_)));
        std::fs::remove_dir_all(root).expect("cleanup replay store");
    }

    #[tokio::test]
    async fn callback_policy_blocks_ssrf_and_only_allows_explicit_private_targets() {
        let mut policy = GatewayCallbackPolicy::default();
        policy.allowed_hosts.insert("127.0.0.1".to_owned());
        policy.allow_http = true;
        let private_error = policy
            .validate_destination("http://127.0.0.1:18080/callback")
            .await
            .expect_err("private callback target must be rejected by default");
        assert!(private_error.to_string().contains("non-public"));

        policy.allow_private_networks = true;
        policy
            .validate_destination("http://127.0.0.1:18080/callback")
            .await
            .expect("explicitly allowlisted development callback");
        let credentials_error = policy
            .validate_destination("http://user:secret@127.0.0.1:18080/callback")
            .await
            .expect_err("userinfo in callback URL must be rejected");
        assert!(
            credentials_error
                .to_string()
                .contains("credentials are forbidden")
        );
        let host_error = policy
            .validate_destination("http://localhost:18080/callback")
            .await
            .expect_err("non-allowlisted hostname must be rejected");
        assert!(host_error.to_string().contains("not allowlisted"));
    }

    #[test]
    fn external_callback_signing_covers_business_signature_fields() {
        let signing_key = std::sync::Arc::new(aip_crypto::signing_key_from_seed([9_u8; 32]));
        let signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:callback-signer"),
                PrincipalKind::Service,
            ),
            signing_key: signing_key.clone(),
        };
        let dispatcher = GatewayCallbackDispatcher::with_policy(
            aip_transport_sse::SseTransport::new(),
            GatewayCallbackPolicy {
                signer: Some(signer),
                ..GatewayCallbackPolicy::default()
            },
        );
        let envelope = Envelope::new(MessageBody::Action(Box::new(Action::new(
            CapabilityId::trusted("cap:test:signed-callback"),
            json!({ "payment": { "signature": "business-value" } }),
        ))));
        let signed = dispatcher
            .signed_external_envelope(envelope)
            .expect("signed callback envelope");
        let signature = signed
            .security
            .as_ref()
            .and_then(|security| security.get("signature"))
            .and_then(serde_json::Value::as_str)
            .expect("security signature")
            .to_owned();
        aip_crypto::verify_envelope(&signed, &signature, &signing_key.verifying_key())
            .expect("callback signature verification");

        let mut tampered = signed;
        let MessageBody::Action(action) = &mut tampered.body else {
            panic!("expected action");
        };
        action.input["payment"]["signature"] = json!("tampered");
        assert!(
            aip_crypto::verify_envelope(&tampered, &signature, &signing_key.verifying_key())
                .is_err(),
            "business signature fields must remain inside the signed payload"
        );
    }

    #[tokio::test]
    async fn a2a_callback_uses_stream_response_auth_encryption_and_payload_signature() {
        let capture = A2aCallbackCapture::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = Router::new()
            .route("/push", post(capture_a2a_callback))
            .with_state(capture.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("A2A callback receiver");
        });
        let signing_key = Arc::new(aip_crypto::signing_key_from_seed([9_u8; 32]));
        let credential_key = A2aCallbackCredentialKey::new([7_u8; 32]);
        let aad = "aip.a2a.push.v1|task-1|config-1|local";
        let encrypted = credential_key
            .seal(
                aad,
                &A2aCallbackCredentials {
                    token: Some("verification-token".to_owned()),
                    authentication_scheme: Some("Bearer".to_owned()),
                    authentication_credentials: Some("receiver-secret".to_owned()),
                },
            )
            .expect("encrypted callback credentials");
        let mut policy = GatewayCallbackPolicy::default();
        policy.allowed_hosts.insert("127.0.0.1".to_owned());
        policy.allow_http = true;
        policy.allow_private_networks = true;
        policy.signer = Some(CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:a2a-callback-signer"),
                PrincipalKind::Service,
            ),
            signing_key: signing_key.clone(),
        });
        policy.a2a_credential_key = Some(credential_key);
        let dispatcher =
            GatewayCallbackDispatcher::with_policy(aip_transport_sse::SseTransport::new(), policy);
        let action_id = ActionId::new();
        let envelope = Envelope::new(MessageBody::ActionResult(ActionResult {
            action_id: action_id.clone(),
            status: ActionResultStatus::Completed,
            output: Some(json!({ "answer": 42 })),
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        }));
        let callback = Callback {
            profile: ProfileId::from(aip_profile_a2a::PROFILE_ID),
            target: format!("http://{address}/push"),
            metadata: Some(json!({
                "a2a": {
                    "taskId": "task-1",
                    "contextId": "context-1",
                    "skillId": "answer",
                    "credentialAad": aad,
                    "encryptedCredentials": encrypted
                }
            })),
        };

        dispatcher
            .dispatch(&callback, envelope.clone())
            .await
            .expect("A2A callback delivery");
        let (headers, body) = capture.0.lock().await.clone().expect("captured callback");
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/a2a+json")
        );
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer receiver-secret")
        );
        assert_eq!(
            headers
                .get("x-a2a-notification-token")
                .and_then(|value| value.to_str().ok()),
            Some("verification-token")
        );
        assert_eq!(
            body.pointer("/task/status/state"),
            Some(&json!("TASK_STATE_COMPLETED"))
        );
        let timestamp = headers
            .get("aip-callback-timestamp")
            .and_then(|value| value.to_str().ok())
            .expect("callback timestamp");
        let signature = headers
            .get("aip-callback-signature")
            .and_then(|value| value.to_str().ok())
            .expect("callback signature");
        aip_crypto::verify_value(
            &json!({
                "messageId": envelope.message_id,
                "target": callback.target,
                "timestamp": timestamp,
                "payload": body
            }),
            signature,
            &signing_key.verifying_key(),
        )
        .expect("payload signature");
        server.abort();
    }

    #[tokio::test]
    async fn governed_action_identity_is_resolved_fail_closed_at_gateway() {
        let actor = Principal::new(
            PrincipalId::trusted("agent:identity-caller"),
            PrincipalKind::Agent,
        );
        let capability_id = CapabilityId::trusted("cap:test:resolved-identity");
        let mut capability =
            aip_testkit::enterprise_capability(capability_id.as_str(), "resolved identity");
        let contract = capability.contract.as_mut().expect("contract");
        contract.credentials = Some(aip_core::CredentialPolicy {
            required: true,
            accepted_issuers: vec!["vault:primary".to_owned()],
            required_scopes: vec!["records:write".to_owned()],
            allow_oauth_refresh: false,
        });
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::trusted("agent:identity-provider"),
                PrincipalKind::Agent,
            ),
            capabilities: vec![capability],
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        let unresolved_gateway = Gateway::with_policy_runtime_callback_and_handlers(
            manifest.clone(),
            GatewayPolicy::default(),
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
            HashMap::from([(
                capability_id.clone(),
                Arc::new(FullSupportEcho) as Arc<dyn ActionHandler>,
            )]),
        )
        .await
        .expect("unresolved gateway");
        let mut forged = Action::new(capability_id.clone(), json!({ "record": 1 }));
        forged.idempotency_key = Some("identity-resolution-test".to_owned());
        forged.identity = Some(aip_testkit::credential_identity(
            "tenant-a",
            "attacker:issuer",
            &["records:write"],
        ));
        let error = unresolved_gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::Action(Box::new(forged.clone()))),
                authenticated_actor(actor.clone(), &[]),
                None,
                None,
            )
            .await
            .expect_err("payload identity must not bypass the resolver");
        match error {
            super::GatewayError::Policy(error) => {
                assert_eq!(error.code, "auth.identity_resolution_failed")
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let tenant = verified_tenant("tenant-a");
        let credential = CredentialHandle::new(
            "credential:tenant-a",
            "vault:primary",
            std::collections::BTreeSet::from(["records:write".to_owned()]),
            Some("tenant-a".to_owned()),
            Some(time::OffsetDateTime::now_utc() + time::Duration::minutes(5)),
        )
        .expect("credential");
        let resolver = FixedIdentityResolver {
            resolved: ResolvedIdentity {
                actor: authenticated_actor(actor.clone(), &[]),
                tenant: Some(tenant),
                credential: Some(credential),
                // A resolver may return independently verified tenant and
                // credential handles without materializing the redundant AIP
                // identity projection. The gateway must synthesize it from
                // those trusted values and must never retain the forged wire
                // identity above.
                identity: None,
            },
        };
        let gateway = Gateway::with_policy_runtime_callback_and_handlers(
            manifest,
            GatewayPolicy::default(),
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
            HashMap::from([(
                capability_id.clone(),
                Arc::new(FullSupportEcho) as Arc<dyn ActionHandler>,
            )]),
        )
        .await
        .expect("gateway")
        .with_identity_resolver(Arc::new(resolver));
        let response = gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::Action(Box::new(forged))),
                authenticated_actor(actor.clone(), &[]),
                None,
                None,
            )
            .await
            .expect("resolved action");
        let MessageBody::ActionResult(result) = response.body else {
            panic!("expected action result");
        };
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result.output.as_ref().and_then(|value| value.get("echo")),
            Some(&json!({ "record": 1 }))
        );

        let mut queued = Action::new(capability_id, json!({ "record": 2 }));
        queued.mode = Some(ActionMode::Async);
        queued.idempotency_key = Some("identity-resolution-cancel-test".to_owned());
        queued.identity = Some(aip_testkit::credential_identity(
            "tenant-a",
            "vault:primary",
            &["records:write"],
        ));
        let queued_action_id = queued.id.clone();
        let queued_response = gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::Action(Box::new(queued))),
                authenticated_actor(actor.clone(), &["action:write"]),
                None,
                None,
            )
            .await
            .expect("queue tenant-bound action");
        let MessageBody::Ack(ack) = queued_response.body else {
            panic!("expected queued action acknowledgement");
        };
        assert_eq!(ack.status, AckStatus::Queued);

        let cancelled = gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::Cancel(Cancel {
                    target: CancelTarget::Action(queued_action_id.clone()),
                    reason: Some("operator requested".to_owned()),
                })),
                authenticated_actor(actor, &["action:write"]),
                None,
                None,
            )
            .await
            .expect("cancel tenant-bound action");
        let MessageBody::ActionResult(cancelled) = cancelled.body else {
            panic!("expected cancelled action result");
        };
        assert_eq!(cancelled.action_id, queued_action_id);
        assert_eq!(cancelled.status, ActionResultStatus::Cancelled);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gateway_routes_delegation_to_remote_http_peer() {
        let requester = Principal::new(
            PrincipalId::parse("agent:requester").expect("principal"),
            PrincipalKind::Agent,
        );
        let delegate = Principal::new(
            PrincipalId::parse("agent:delegate").expect("principal"),
            PrincipalKind::Agent,
        );
        let capability_id = CapabilityId::trusted("cap:test:remote-echo");
        let requester_key = Arc::new(aip_crypto::signing_key_from_seed([21_u8; 32]));
        let remote_key = Arc::new(aip_crypto::signing_key_from_seed([22_u8; 32]));
        let requester_signer = CallbackSigner {
            principal: requester.clone(),
            signing_key: requester_key.clone(),
        };
        let remote_signer = CallbackSigner {
            principal: delegate.clone(),
            signing_key: remote_key.clone(),
        };
        let remote_gateway = Gateway::with_policy_runtime_callback_and_handlers(
            manifest_for(delegate.clone(), vec![capability_id.clone()]),
            GatewayPolicy {
                require_signed_envelopes: true,
                allow_unverified_payload_identity: false,
                ..GatewayPolicy::default()
            },
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
            HashMap::from([(
                capability_id.clone(),
                Arc::new(EchoHandler) as Arc<dyn ActionHandler>,
            )]),
        )
        .await
        .expect("remote gateway");
        remote_gateway
            .register_trusted_signer(
                aip_crypto::did_key_from_verifying_key(&requester_key.verifying_key()),
                requester.clone(),
            )
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint = format!(
            "http://{}/aip/v1/messages",
            listener.local_addr().expect("addr")
        );
        let app = Router::new()
            .route("/aip/v1/messages", post(test_peer_envelope))
            .with_state(TestPeerState {
                gateway: remote_gateway,
                signer: remote_signer.clone(),
            });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test peer server");
        });

        let parent_gateway = Gateway::new(manifest_for(requester.clone(), Vec::new()))
            .await
            .expect("parent gateway");
        let mut endpoint_policy = GatewayCallbackPolicy::default();
        endpoint_policy.allowed_hosts.insert("127.0.0.1".to_owned());
        endpoint_policy.allow_http = true;
        endpoint_policy.allow_private_networks = true;
        endpoint_policy.request_timeout_ms = 5_000;
        let peer_security = DelegationPeerSecurity::new(
            "test.local",
            requester_signer,
            delegate.clone(),
            aip_crypto::did_key_from_verifying_key(&remote_key.verifying_key()),
            endpoint_policy,
        )
        .expect("peer security");
        parent_gateway
            .register_delegation_route(DelegationRoute::native_http_for_delegate(
                delegate.id.clone(),
                endpoint,
                peer_security,
            ))
            .await;

        let child_action = Action::new(capability_id, json!({ "remote": true }));
        let child_action_id = child_action.id.clone();
        let envelope = Envelope::new(MessageBody::DelegationRequest(Box::new(
            DelegationRequest {
                delegation_id: DelegationId::new(),
                parent_action_id: Action::new(CapabilityId::trusted("cap:test:parent"), json!({}))
                    .id,
                child_action,
                requested_by: requester.clone(),
                delegate: delegate.clone(),
                scope: "remote echo".to_owned(),
                callback: None,
                metadata: None,
            },
        )));
        let response = parent_gateway
            .handle_verified_envelope(envelope, authenticated_actor(requester, &[]), None, None)
            .await
            .expect("remote delegation response");
        server.abort();

        let MessageBody::DelegationResult(result) = response.body else {
            panic!("expected delegation result");
        };
        assert_eq!(
            result.status,
            DelegationStatus::Completed,
            "remote result: {result:#?}"
        );
        assert_eq!(result.child_action_id, child_action_id);
        assert_eq!(
            result
                .result
                .as_ref()
                .map(|action_result| action_result.status),
            Some(ActionResultStatus::Completed)
        );
        assert_eq!(
            result
                .result
                .as_ref()
                .and_then(|action_result| action_result.output.as_ref())
                .and_then(|output| output.pointer("/echo/remote")),
            Some(&json!(true))
        );
    }

    #[tokio::test]
    async fn gateway_routes_delegation_through_registered_connector_router() {
        let requester = Principal::new(
            PrincipalId::trusted("agent:connector-requester"),
            PrincipalKind::Agent,
        );
        let delegate = Principal::new(
            PrincipalId::trusted("agent:connector-operator"),
            PrincipalKind::Agent,
        );
        let gateway = Gateway::new(manifest_for(requester.clone(), Vec::new()))
            .await
            .expect("gateway");
        let calls = Arc::new(AtomicUsize::new(0));
        gateway
            .register_delegation_router(ConnectorDelegationRouter {
                delegate_id: delegate.id.clone(),
                calls: calls.clone(),
            })
            .await;
        let child_action = Action::new(
            CapabilityId::trusted("cap:test:connector-routed"),
            json!({ "payload": true }),
        );
        let child_action_id = child_action.id.clone();
        let response = gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::DelegationRequest(Box::new(
                    DelegationRequest {
                        delegation_id: DelegationId::new(),
                        parent_action_id: Action::new(
                            CapabilityId::trusted("cap:test:parent"),
                            json!({}),
                        )
                        .id,
                        child_action,
                        requested_by: requester.clone(),
                        delegate,
                        scope: "connector owned delegation".to_owned(),
                        callback: None,
                        metadata: None,
                    },
                ))),
                authenticated_actor(requester, &[]),
                None,
                None,
            )
            .await
            .expect("connector delegation response");
        let MessageBody::DelegationResult(result) = response.body else {
            panic!("expected delegation result");
        };
        assert_eq!(result.status, DelegationStatus::Completed);
        assert_eq!(result.child_action_id, child_action_id);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            result
                .result
                .as_ref()
                .and_then(|result| result.output.as_ref())
                .and_then(|output| output.get("connector_router")),
            Some(&json!(true))
        );
    }

    #[tokio::test]
    async fn gateway_resolves_delegated_child_identity_before_remote_dispatch() {
        let requester = Principal::new(
            PrincipalId::trusted("service:delegation-requester"),
            PrincipalKind::Service,
        );
        let delegate = Principal::new(
            PrincipalId::trusted("service:delegation-target"),
            PrincipalKind::Service,
        );
        let tenant = verified_tenant("tenant-acme");
        let resolver = FixedIdentityResolver {
            resolved: ResolvedIdentity {
                actor: authenticated_actor(requester.clone(), &[]),
                tenant: Some(tenant),
                credential: None,
                identity: None,
            },
        };
        let observed = Arc::new(Mutex::new(None));
        let gateway = Gateway::with_policy(
            manifest_for(delegate.clone(), Vec::new()),
            GatewayPolicy {
                resolve_identity_for_unknown_actions: true,
                ..GatewayPolicy::default()
            },
        )
        .await
        .expect("gateway")
        .with_identity_resolver(Arc::new(resolver));
        gateway
            .register_delegation_router(ContextCapturingDelegationRouter {
                delegate_id: delegate.id.clone(),
                observed: observed.clone(),
            })
            .await;

        let mut child_action = Action::new(
            CapabilityId::trusted("cap:test:tenant-scoped-external"),
            json!({ "payload": true }),
        );
        child_action.identity = Some(aip_testkit::credential_identity(
            "tenant-forged",
            "attacker:issuer",
            &["external:write"],
        ));
        let response = gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::DelegationRequest(Box::new(
                    DelegationRequest {
                        delegation_id: DelegationId::new(),
                        parent_action_id: ActionId::new(),
                        child_action,
                        requested_by: requester.clone(),
                        delegate,
                        scope: "tenant-scoped external execution".to_owned(),
                        callback: None,
                        metadata: None,
                    },
                ))),
                authenticated_actor(requester, &[]),
                None,
                None,
            )
            .await
            .expect("delegation response");
        let MessageBody::DelegationResult(result) = response.body else {
            panic!("expected delegation result");
        };
        assert_eq!(result.status, DelegationStatus::Completed);

        let observed = observed.lock().await.clone().expect("captured context");
        assert_eq!(
            observed
                .tenant
                .as_ref()
                .map(|tenant| tenant.tenant.id.as_str()),
            Some("tenant-acme")
        );
        assert_eq!(
            observed
                .resolved_identity
                .as_ref()
                .and_then(|identity| identity.tenant.as_ref())
                .map(|tenant| tenant.id.as_str()),
            Some("tenant-acme")
        );
        assert_ne!(
            observed
                .resolved_identity
                .as_ref()
                .and_then(|identity| identity.tenant.as_ref())
                .map(|tenant| tenant.id.as_str()),
            Some("tenant-forged")
        );
    }

    #[tokio::test]
    async fn gateway_callback_dispatcher_delivers_sse_envelopes() {
        let dispatcher = GatewayCallbackDispatcher::default();
        let correlation_id = aip_core::CorrelationId::new();
        dispatcher
            .sse_transport()
            .subscribe(&correlation_id)
            .await
            .expect("subscribe");
        let envelope = Envelope::new(MessageBody::Action(Box::new(Action::new(
            CapabilityId::trusted("cap:test:sse"),
            json!({}),
        ))));

        aip_runtime::CallbackDispatcher::dispatch(
            &dispatcher,
            &Callback {
                profile: ProfileId::from(super::NATIVE_SSE_PROFILE),
                target: correlation_id.to_string(),
                metadata: None,
            },
            envelope.clone(),
        )
        .await
        .expect("dispatch");

        let events = dispatcher
            .sse_transport()
            .events_since(&correlation_id, None)
            .await
            .expect("sse events");
        let delivered = decode_sse(&events[0]).expect("decode sse");
        assert_eq!(delivered.message_id, envelope.message_id);
    }

    async fn test_peer_envelope(
        State(state): State<TestPeerState>,
        Json(envelope): Json<Envelope>,
    ) -> (StatusCode, Json<Envelope>) {
        let request_message_id = envelope.message_id.clone();
        let correlation_id = envelope.correlation_id.clone();
        let recipient = envelope.from.clone();
        let gateway = state.gateway;
        let response = tokio::spawn(async move { gateway.handle_envelope(envelope).await }).await;
        let response = match response {
            Ok(response) => response,
            Err(error) => Err(super::GatewayError::Runtime(RuntimeError::Handler(
                format!("gateway task failed: {error}"),
            ))),
        };
        let (status, mut response) = match response {
            Ok(response) => (StatusCode::OK, response),
            Err(error) => (StatusCode::BAD_REQUEST, Gateway::error_envelope(&error)),
        };
        response.correlation_id = correlation_id;
        response.in_response_to = Some(MessageReference::Message(request_message_id));
        response.to = recipient;
        let signed = sign_native_envelope(response, &state.signer)
            .unwrap_or_else(|error| Gateway::error_envelope(&super::GatewayError::Runtime(error)));
        (status, Json(signed))
    }

    fn manifest_for(agent: Principal, capability_ids: Vec<CapabilityId>) -> Manifest {
        Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent,
            capabilities: capability_ids
                .into_iter()
                .map(|id| Capability {
                    id,
                    name: "test capability".to_owned(),
                    kind: CapabilityKind::Tool,
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    description: None,
                    risk: None,
                    stability: None,
                    cost: None,
                    auth: None,
                    bindings: Vec::new(),
                    requires_human_approval: None,
                    contract: None,
                })
                .collect(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        }
    }
}
