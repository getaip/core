//! Trusted identity, credential, token, and approval-authority boundaries.
//!
//! These types are runtime inputs. They are intentionally not AIP wire DTOs
//! and must be constructed only after a transport authenticator or deployment
//! identity provider has verified the corresponding claims.

use crate::{AuthError, AuthScheme};
use aip_core::{ApprovalId, IdentityContext, Principal, PrincipalId, TenantRef};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use time::OffsetDateTime;

const INTROSPECTION_RESPONSE_MAX_BYTES: usize = 1024 * 1024;

/// Deserializes timestamps written before trusted runtime identity records
/// adopted their canonical RFC 3339 representation.
///
/// Serialization is intentionally one-way: every newly persisted value uses
/// RFC 3339, while readers also accept the legacy `time` tuple representation
/// so an in-place upgrade does not make durable actions unreadable.
mod persisted_timestamp {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Representation {
        Rfc3339(String),
        Legacy(OffsetDateTime),
    }

    fn decode<E>(representation: Representation) -> Result<OffsetDateTime, E>
    where
        E: serde::de::Error,
    {
        match representation {
            Representation::Rfc3339(value) => {
                OffsetDateTime::parse(&value, &Rfc3339).map_err(E::custom)
            }
            Representation::Legacy(value) => Ok(value),
        }
    }

    pub(super) fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        time::serde::rfc3339::serialize(value, serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        decode(Representation::deserialize(deserializer)?)
    }

    pub(super) mod option {
        use super::{Representation, decode};
        use serde::{Deserialize, Deserializer, Serializer};
        use time::OffsetDateTime;

        pub(in super::super) fn serialize<S>(
            value: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            time::serde::rfc3339::option::serialize(value, serializer)
        }

        pub(in super::super) fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<Option<OffsetDateTime>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<Representation>::deserialize(deserializer)?
                .map(decode)
                .transpose()
        }
    }
}

/// A principal whose identity was established outside the AIP payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedPrincipal {
    /// Canonical AIP principal.
    pub principal: Principal,
    /// Authentication mechanism used at the transport edge.
    pub scheme: AuthScheme,
    /// Trusted issuer or trust domain.
    pub issuer: String,
    /// Verified token or credential audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Verified scopes.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub scopes: BTreeSet<String>,
    /// Time at which authentication was established.
    #[serde(with = "persisted_timestamp")]
    pub authenticated_at: OffsetDateTime,
    /// Time after which the authentication must not be used.
    #[serde(
        default,
        with = "persisted_timestamp::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
    /// Hash of the token id or certificate fingerprint retained for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint: Option<String>,
}

impl AuthenticatedPrincipal {
    /// Rejects expired authentication and missing required scopes.
    pub fn validate(&self, required_scopes: &BTreeSet<String>) -> Result<(), AuthError> {
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AuthError::AuthenticationExpired);
        }
        for scope in required_scopes {
            if !self.scopes.contains(scope) && !self.scopes.contains("*") {
                return Err(AuthError::MissingScope(scope.clone()));
            }
        }
        Ok(())
    }
}

/// Tenant membership verified by a trusted tenant resolver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTenant {
    /// Canonical tenant reference.
    pub tenant: TenantRef,
    /// Membership record or directory object id.
    pub membership_id: String,
    /// Tenant roles established by the resolver.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub roles: BTreeSet<String>,
    /// Tenant groups established by the resolver.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub groups: BTreeSet<String>,
    /// Time at which membership was verified.
    #[serde(with = "persisted_timestamp")]
    pub verified_at: OffsetDateTime,
    /// Membership expiration, if any.
    #[serde(
        default,
        with = "persisted_timestamp::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
}

impl VerifiedTenant {
    /// Returns an error when the membership is no longer valid.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AuthError::TenantMembershipExpired);
        }
        Ok(())
    }
}

/// Opaque reference to deployment-owned credential material.
///
/// The handle contains identifiers and verified scopes only. It cannot expose
/// a token, password, API key, or private key through debug output. Connectors
/// obtain short-lived material through [`CredentialProvider`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialHandle {
    id: String,
    issuer: String,
    scopes: BTreeSet<String>,
    tenant_id: Option<String>,
    #[serde(
        default,
        with = "persisted_timestamp::option",
        skip_serializing_if = "Option::is_none"
    )]
    expires_at: Option<OffsetDateTime>,
}

impl CredentialHandle {
    /// Creates a validated credential handle.
    pub fn new(
        id: impl Into<String>,
        issuer: impl Into<String>,
        scopes: BTreeSet<String>,
        tenant_id: Option<String>,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Self, AuthError> {
        let id = id.into();
        let issuer = issuer.into();
        if id.trim().is_empty() || issuer.trim().is_empty() {
            return Err(AuthError::Credential(
                "credential id and issuer must be non-empty".to_owned(),
            ));
        }
        Ok(Self {
            id,
            issuer,
            scopes,
            tenant_id,
            expires_at,
        })
    }

    /// Returns the opaque credential id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the verified credential issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the verified credential scopes.
    #[must_use]
    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    /// Returns the credential tenant partition.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Returns the time after which the credential must not be used.
    #[must_use]
    pub const fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }

    /// Validates expiry and required scope membership.
    pub fn validate(&self, required_scopes: &BTreeSet<String>) -> Result<(), AuthError> {
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AuthError::CredentialExpired);
        }
        for scope in required_scopes {
            if !self.scopes.contains(scope) && !self.scopes.contains("*") {
                return Err(AuthError::MissingScope(scope.clone()));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CredentialHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialHandle")
            .field("id", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("scopes", &self.scopes)
            .field("tenant_id", &self.tenant_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Short-lived secret material borrowed by a connector invocation.
///
/// The byte buffer is zeroed on drop and its debug representation is always
/// redacted. Callers must not persist or include the exposed bytes in errors.
pub struct CredentialMaterial {
    bytes: Vec<u8>,
}

impl CredentialMaterial {
    /// Creates material owned by the invocation boundary.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Exposes the secret only to the immediate connector invocation.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for CredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialMaterial([REDACTED])")
    }
}

impl Drop for CredentialMaterial {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Deployment credential provider used only at connector invocation time.
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Resolves a handle into short-lived secret material.
    async fn resolve(&self, handle: &CredentialHandle) -> Result<CredentialMaterial, AuthError>;
}

/// Bearer token wrapper whose content is never rendered and is zeroed on drop.
pub struct BearerToken {
    bytes: Vec<u8>,
}

impl BearerToken {
    /// Wraps an incoming bearer token.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, AuthError> {
        let bytes = value.into();
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(AuthError::Token(
                "bearer token length is outside the accepted range".to_owned(),
            ));
        }
        Ok(Self { bytes })
    }

    /// Exposes token bytes only to a verifier or introspection client.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

impl Drop for BearerToken {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Requirements applied to one bearer-token verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenVerificationRequest {
    /// Accepted issuers.
    pub accepted_issuers: BTreeSet<String>,
    /// Required audience or RFC 8707 resource indicator.
    pub audience: String,
    /// Required scopes.
    pub required_scopes: BTreeSet<String>,
    /// Current time supplied by the caller for deterministic tests.
    pub now: OffsetDateTime,
}

/// Verified token claims returned by a production verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    /// Token subject.
    pub subject: String,
    /// Token issuer.
    pub issuer: String,
    /// Audiences or resource indicators.
    pub audiences: BTreeSet<String>,
    /// Granted scopes.
    pub scopes: BTreeSet<String>,
    /// Expiration time.
    pub expires_at: OffsetDateTime,
    /// Optional tenant claim validated by the resolver.
    pub tenant_id: Option<String>,
    /// Non-reversible token identifier retained for replay/revocation audit.
    pub token_fingerprint: String,
}

/// Token verifier boundary for JWT validation or opaque-token introspection.
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    /// Verifies issuer, audience, scope, expiry, and revocation requirements.
    async fn verify(
        &self,
        token: &BearerToken,
        request: &TokenVerificationRequest,
    ) -> Result<VerifiedToken, AuthError>;
}

/// Raw result returned by a trusted OAuth token introspection endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenIntrospection {
    /// RFC 7662 active marker.
    pub active: bool,
    /// Subject.
    pub subject: Option<String>,
    /// Issuer.
    pub issuer: Option<String>,
    /// Audiences or resources.
    pub audiences: BTreeSet<String>,
    /// Granted scopes.
    pub scopes: BTreeSet<String>,
    /// Expiration time.
    pub expires_at: Option<OffsetDateTime>,
    /// Optional tenant claim.
    pub tenant_id: Option<String>,
    /// Stable non-secret token fingerprint.
    pub token_fingerprint: String,
}

/// Deployment-owned opaque-token introspection transport.
#[async_trait]
pub trait TokenIntrospector: Send + Sync {
    /// Calls the authorization server's authenticated introspection endpoint.
    async fn introspect(&self, token: &BearerToken) -> Result<TokenIntrospection, AuthError>;
}

struct IntrospectionClientSecret(Vec<u8>);

impl Drop for IntrospectionClientSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// RFC 7662 token introspector backed by an authenticated HTTPS endpoint.
///
/// Redirects are disabled, response bodies are bounded, client credentials are
/// redacted and zeroed, and token fingerprints are computed locally rather
/// than accepted from the authorization server.
#[derive(Clone)]
pub struct HttpTokenIntrospector {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    issuer: String,
    client_id: String,
    client_secret: Arc<IntrospectionClientSecret>,
}

impl fmt::Debug for HttpTokenIntrospector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTokenIntrospector")
            .field("endpoint", &self.endpoint)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

impl HttpTokenIntrospector {
    /// Creates an introspector that requires an HTTPS endpoint.
    pub fn new(
        endpoint: impl AsRef<str>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<Vec<u8>>,
    ) -> Result<Self, AuthError> {
        Self::build(endpoint, issuer, client_id, client_secret, false)
    }

    /// Creates an introspector that additionally permits HTTP on loopback.
    ///
    /// This constructor is restricted to local conformance and development
    /// deployments. Non-loopback HTTP endpoints remain rejected.
    pub fn new_with_loopback_http(
        endpoint: impl AsRef<str>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<Vec<u8>>,
    ) -> Result<Self, AuthError> {
        Self::build(endpoint, issuer, client_id, client_secret, true)
    }

    fn build(
        endpoint: impl AsRef<str>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<Vec<u8>>,
        allow_loopback_http: bool,
    ) -> Result<Self, AuthError> {
        let endpoint = reqwest::Url::parse(endpoint.as_ref())
            .map_err(|error| AuthError::Token(format!("invalid introspection URL: {error}")))?;
        validate_introspection_endpoint(&endpoint, allow_loopback_http)?;
        let issuer = issuer.into();
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        if issuer.trim().is_empty() || issuer.contains(['\r', '\n']) {
            return Err(AuthError::Token(
                "introspection issuer is empty or invalid".to_owned(),
            ));
        }
        if client_id.trim().is_empty()
            || client_id.len() > 1_024
            || client_id.contains(['\r', '\n'])
        {
            return Err(AuthError::Token(
                "introspection client id is empty or invalid".to_owned(),
            ));
        }
        if client_secret.is_empty() || client_secret.len() > 16 * 1024 {
            return Err(AuthError::Token(
                "introspection client secret length is invalid".to_owned(),
            ));
        }
        std::str::from_utf8(&client_secret).map_err(|_| {
            AuthError::Token("introspection client secret must be UTF-8".to_owned())
        })?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| {
                AuthError::Token(format!("could not build introspection client: {error}"))
            })?;
        Ok(Self {
            client,
            endpoint,
            issuer,
            client_id,
            client_secret: Arc::new(IntrospectionClientSecret(client_secret)),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IntrospectionAudience {
    One(String),
    Many(Vec<String>),
}

impl IntrospectionAudience {
    fn into_set(self) -> BTreeSet<String> {
        match self {
            Self::One(value) => BTreeSet::from([value]),
            Self::Many(values) => values.into_iter().collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct HttpIntrospectionResponse {
    active: bool,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<IntrospectionAudience>,
    #[serde(default)]
    resource: Option<IntrospectionAudience>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    tenant_id: Option<String>,
}

#[async_trait]
impl TokenIntrospector for HttpTokenIntrospector {
    async fn introspect(&self, token: &BearerToken) -> Result<TokenIntrospection, AuthError> {
        let token = std::str::from_utf8(token.expose())
            .map_err(|_| AuthError::Token("bearer token must be UTF-8".to_owned()))?;
        let client_secret = std::str::from_utf8(&self.client_secret.0)
            .map_err(|_| AuthError::Token("introspection client secret is invalid".to_owned()))?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .basic_auth(&self.client_id, Some(client_secret))
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .send()
            .await
            .map_err(|error| AuthError::Token(format!("token introspection failed: {error}")))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !status.is_success() {
            return Err(AuthError::Token(format!(
                "token introspection endpoint returned HTTP {status}"
            )));
        }
        if !content_type.starts_with("application/json") {
            return Err(AuthError::Token(
                "token introspection response is not application/json".to_owned(),
            ));
        }
        let body = read_bounded_introspection_body(response).await?;
        let decoded =
            serde_json::from_slice::<HttpIntrospectionResponse>(&body).map_err(|error| {
                AuthError::Token(format!("invalid introspection response: {error}"))
            })?;
        if let Some(response_issuer) = decoded.iss.as_deref()
            && response_issuer != self.issuer
        {
            return Err(AuthError::Token(
                "introspection response issuer does not match configuration".to_owned(),
            ));
        }
        let mut audiences = decoded
            .aud
            .map(IntrospectionAudience::into_set)
            .unwrap_or_default();
        if let Some(resources) = decoded.resource {
            audiences.extend(resources.into_set());
        }
        let expires_at = decoded
            .exp
            .map(OffsetDateTime::from_unix_timestamp)
            .transpose()
            .map_err(|error| {
                AuthError::Token(format!("invalid introspection expiration: {error}"))
            })?;
        Ok(TokenIntrospection {
            active: decoded.active,
            subject: decoded.sub,
            issuer: Some(self.issuer.clone()),
            audiences,
            scopes: decoded
                .scope
                .map(|scope| scope.split_whitespace().map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
            expires_at,
            tenant_id: decoded.tenant_id,
            token_fingerprint: format!("sha256:{:x}", Sha256::digest(token.as_bytes())),
        })
    }
}

async fn read_bounded_introspection_body(
    response: reqwest::Response,
) -> Result<Vec<u8>, AuthError> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| AuthError::Token(format!("introspection read failed: {error}")))?;
        if body.len().saturating_add(chunk.len()) > INTROSPECTION_RESPONSE_MAX_BYTES {
            return Err(AuthError::Token(format!(
                "introspection response exceeded {INTROSPECTION_RESPONSE_MAX_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_introspection_endpoint(
    endpoint: &reqwest::Url,
    allow_loopback_http: bool,
) -> Result<(), AuthError> {
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(AuthError::Token(
            "introspection URL must not contain credentials or a fragment".to_owned(),
        ));
    }
    if endpoint.scheme() == "https" {
        return Ok(());
    }
    let loopback = endpoint.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if endpoint.scheme() == "http" && allow_loopback_http && loopback {
        return Ok(());
    }
    Err(AuthError::Token(
        "introspection endpoint must use HTTPS; only explicit local development may use loopback HTTP"
            .to_owned(),
    ))
}

/// Strict verifier backed by RFC 7662-style token introspection.
#[derive(Clone, Debug)]
pub struct IntrospectionTokenVerifier<I> {
    introspector: I,
}

impl<I> IntrospectionTokenVerifier<I> {
    /// Creates a verifier from a deployment introspection client.
    #[must_use]
    pub fn new(introspector: I) -> Self {
        Self { introspector }
    }
}

#[async_trait]
impl<I> TokenVerifier for IntrospectionTokenVerifier<I>
where
    I: TokenIntrospector,
{
    async fn verify(
        &self,
        token: &BearerToken,
        request: &TokenVerificationRequest,
    ) -> Result<VerifiedToken, AuthError> {
        let claims = self.introspector.introspect(token).await?;
        if !claims.active {
            return Err(AuthError::Token("token is inactive or revoked".to_owned()));
        }
        let subject = claims
            .subject
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AuthError::Token("token subject is missing".to_owned()))?;
        let issuer = claims
            .issuer
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AuthError::Token("token issuer is missing".to_owned()))?;
        if !request.accepted_issuers.is_empty() && !request.accepted_issuers.contains(&issuer) {
            return Err(AuthError::Token("token issuer is not trusted".to_owned()));
        }
        if !claims.audiences.contains(&request.audience) {
            return Err(AuthError::Token(
                "token audience/resource does not match this server".to_owned(),
            ));
        }
        let expires_at = claims
            .expires_at
            .ok_or_else(|| AuthError::Token("token expiration is missing".to_owned()))?;
        if expires_at <= request.now {
            return Err(AuthError::Token("token has expired".to_owned()));
        }
        for scope in &request.required_scopes {
            if !claims.scopes.contains(scope) && !claims.scopes.contains("*") {
                return Err(AuthError::MissingScope(scope.clone()));
            }
        }
        Ok(VerifiedToken {
            subject,
            issuer,
            audiences: claims.audiences,
            scopes: claims.scopes,
            expires_at,
            tenant_id: claims.tenant_id,
            token_fingerprint: claims.token_fingerprint,
        })
    }
}

/// Request passed to a deployment identity and credential resolver.
pub struct IdentityResolutionRequest<'a> {
    /// Transport-authenticated principal.
    pub actor: &'a AuthenticatedPrincipal,
    /// Untrusted action identity claims, usable only as lookup hints.
    pub claimed_identity: Option<&'a IdentityContext>,
    /// Credential issuers accepted by the capability.
    pub accepted_credential_issuers: &'a BTreeSet<String>,
    /// Whether the capability requires a caller-bound credential.
    pub credential_required: bool,
    /// Credential scopes required by the capability.
    pub required_credential_scopes: &'a BTreeSet<String>,
}

/// Identity values established by trusted resolvers for one execution.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedIdentity {
    /// Authenticated actor.
    pub actor: AuthenticatedPrincipal,
    /// Verified tenant membership.
    pub tenant: Option<VerifiedTenant>,
    /// Opaque downstream credential handle.
    pub credential: Option<CredentialHandle>,
    /// Sanitized identity context retained for audit and provider mapping.
    pub identity: Option<IdentityContext>,
}

/// Async, tenant-aware identity and credential resolver.
#[async_trait]
pub trait TrustedIdentityResolver: Send + Sync {
    /// Resolves and independently verifies identity claims for one execution.
    async fn resolve(
        &self,
        request: IdentityResolutionRequest<'_>,
    ) -> Result<ResolvedIdentity, AuthError>;

    /// Returns the current directory revision for cache validation.
    ///
    /// Resolvers that cannot provide a cheap revocation-aware revision must
    /// return `None`; callers then bypass identity caching.
    async fn current_revision(
        &self,
        _actor: &AuthenticatedPrincipal,
    ) -> Result<Option<u64>, AuthError> {
        Ok(None)
    }
}

/// Fail-closed identity resolver used until a deployment provider is configured.
#[derive(Clone, Debug, Default)]
pub struct DenyAllTrustedIdentityResolver;

#[async_trait]
impl TrustedIdentityResolver for DenyAllTrustedIdentityResolver {
    async fn resolve(
        &self,
        _request: IdentityResolutionRequest<'_>,
    ) -> Result<ResolvedIdentity, AuthError> {
        Err(AuthError::Resolution(
            "no trusted identity resolver is configured".to_owned(),
        ))
    }
}

/// Server-owned identity directory entry.
#[derive(Clone, Debug, PartialEq)]
pub struct TrustedIdentityBinding {
    /// Authenticated transport principal to which this entry belongs.
    pub principal_id: PrincipalId,
    /// Verified tenant membership.
    pub tenant: Option<VerifiedTenant>,
    /// Opaque credential selected by the deployment.
    pub credential: Option<CredentialHandle>,
    /// Sanitized external identity mapping.
    pub identity: Option<IdentityContext>,
    /// Monotonic directory revision used for revocation-aware caching.
    pub revision: u64,
    /// Whether the entry has been revoked.
    pub revoked: bool,
    /// Optional directory entry expiration.
    pub expires_at: Option<OffsetDateTime>,
}

impl TrustedIdentityBinding {
    fn validate(&self, request: &IdentityResolutionRequest<'_>) -> Result<(), AuthError> {
        if self.principal_id != request.actor.principal.id {
            return Err(AuthError::Resolution(
                "identity directory principal mismatch".to_owned(),
            ));
        }
        if self.revoked {
            return Err(AuthError::Resolution(
                "identity directory entry is revoked".to_owned(),
            ));
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AuthError::Resolution(
                "identity directory entry has expired".to_owned(),
            ));
        }
        request.actor.validate(&BTreeSet::new())?;
        if let Some(tenant) = self.tenant.as_ref() {
            tenant.validate()?;
        }
        if let Some(credential) = self.credential.as_ref() {
            credential.validate(request.required_credential_scopes)?;
            if !request.accepted_credential_issuers.is_empty()
                && !request
                    .accepted_credential_issuers
                    .contains(credential.issuer())
            {
                return Err(AuthError::Credential(
                    "resolved credential issuer is not accepted".to_owned(),
                ));
            }
        } else if request.credential_required {
            return Err(AuthError::MissingCredential);
        }
        validate_identity_lookup_hint(
            request.claimed_identity,
            self.tenant.as_ref(),
            self.credential.as_ref(),
            self.identity.as_ref(),
        )
    }
}

/// Deterministic trusted identity directory for controlled deployments and
/// conformance tests.
#[derive(Clone, Debug, Default)]
pub struct StaticTrustedIdentityResolver {
    bindings: BTreeMap<PrincipalId, TrustedIdentityBinding>,
}

impl StaticTrustedIdentityResolver {
    /// Creates a directory from server-owned verified bindings.
    #[must_use]
    pub fn new(bindings: impl IntoIterator<Item = TrustedIdentityBinding>) -> Self {
        Self {
            bindings: bindings
                .into_iter()
                .map(|binding| (binding.principal_id.clone(), binding))
                .collect(),
        }
    }
}

#[async_trait]
impl TrustedIdentityResolver for StaticTrustedIdentityResolver {
    async fn resolve(
        &self,
        request: IdentityResolutionRequest<'_>,
    ) -> Result<ResolvedIdentity, AuthError> {
        let binding = self
            .bindings
            .get(&request.actor.principal.id)
            .ok_or_else(|| {
                AuthError::Resolution(
                    "authenticated principal is not in the identity directory".to_owned(),
                )
            })?;
        binding.validate(&request)?;
        Ok(ResolvedIdentity {
            actor: request.actor.clone(),
            tenant: binding.tenant.clone(),
            credential: binding.credential.clone(),
            identity: binding.identity.clone(),
        })
    }

    async fn current_revision(
        &self,
        actor: &AuthenticatedPrincipal,
    ) -> Result<Option<u64>, AuthError> {
        let binding = self.bindings.get(&actor.principal.id).ok_or_else(|| {
            AuthError::Resolution(
                "authenticated principal is not in the identity directory".to_owned(),
            )
        })?;
        if binding.revoked {
            return Err(AuthError::Resolution(
                "identity directory entry is revoked".to_owned(),
            ));
        }
        if binding
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AuthError::Resolution(
                "identity directory entry has expired".to_owned(),
            ));
        }
        Ok(Some(binding.revision))
    }
}

/// Bounds for a revocation-aware identity resolver cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityCachePolicy {
    /// Maximum number of actor/claim/credential-policy entries.
    pub max_entries: usize,
    /// Maximum cache lifetime, additionally bounded by actor, tenant, and
    /// credential expiration.
    pub ttl_ms: u64,
}

impl Default for IdentityCachePolicy {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            ttl_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug)]
struct CachedResolvedIdentity {
    value: ResolvedIdentity,
    revision: u64,
    expires_at: OffsetDateTime,
}

/// Bounded identity cache that checks the source directory revision before
/// every reuse. Resolvers without revision support are called directly.
#[derive(Clone)]
pub struct CachedTrustedIdentityResolver<R> {
    inner: Arc<R>,
    policy: IdentityCachePolicy,
    entries: Arc<Mutex<BTreeMap<String, CachedResolvedIdentity>>>,
}

impl<R> fmt::Debug for CachedTrustedIdentityResolver<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CachedTrustedIdentityResolver")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<R> CachedTrustedIdentityResolver<R> {
    /// Wraps one resolver with bounded revocation-aware caching.
    pub fn new(inner: R, policy: IdentityCachePolicy) -> Result<Self, AuthError> {
        if policy.max_entries == 0 || policy.ttl_ms == 0 {
            return Err(AuthError::Resolution(
                "identity cache bounds must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            inner: Arc::new(inner),
            policy,
            entries: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }
}

#[async_trait]
impl<R> TrustedIdentityResolver for CachedTrustedIdentityResolver<R>
where
    R: TrustedIdentityResolver + 'static,
{
    async fn resolve(
        &self,
        request: IdentityResolutionRequest<'_>,
    ) -> Result<ResolvedIdentity, AuthError> {
        let Some(revision) = self.inner.current_revision(request.actor).await? else {
            return self.inner.resolve(request).await;
        };
        let key = identity_cache_key(&request)?;
        let now = OffsetDateTime::now_utc();
        if let Some(cached) = self
            .entries
            .lock()
            .map_err(|_| AuthError::Resolution("identity cache lock poisoned".to_owned()))?
            .get(&key)
            .filter(|cached| cached.revision == revision && cached.expires_at > now)
            .cloned()
        {
            return Ok(cached.value);
        }
        let value = self.inner.resolve(request).await?;
        let mut expires_at = now
            + time::Duration::milliseconds(self.policy.ttl_ms.max(1).min(i64::MAX as u64) as i64);
        for candidate in [
            value.actor.expires_at,
            value.tenant.as_ref().and_then(|tenant| tenant.expires_at),
            value
                .credential
                .as_ref()
                .and_then(CredentialHandle::expires_at),
        ]
        .into_iter()
        .flatten()
        {
            expires_at = expires_at.min(candidate);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AuthError::Resolution("identity cache lock poisoned".to_owned()))?;
        entries.retain(|_, cached| cached.expires_at > now);
        while entries.len() >= self.policy.max_entries.max(1) {
            let Some(oldest) = entries.keys().next().cloned() else {
                break;
            };
            entries.remove(&oldest);
        }
        entries.insert(
            key,
            CachedResolvedIdentity {
                value: value.clone(),
                revision,
                expires_at,
            },
        );
        Ok(value)
    }

    async fn current_revision(
        &self,
        actor: &AuthenticatedPrincipal,
    ) -> Result<Option<u64>, AuthError> {
        self.inner.current_revision(actor).await
    }
}

fn identity_cache_key(request: &IdentityResolutionRequest<'_>) -> Result<String, AuthError> {
    let claims = serde_json::to_string(&request.claimed_identity)
        .map_err(|error| AuthError::Resolution(format!("identity cache key failed: {error}")))?;
    Ok(format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        request.actor.principal.id,
        claims,
        request
            .accepted_credential_issuers
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\u{1e}"),
        request
            .required_credential_scopes
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\u{1e}")
    ))
}

fn validate_identity_lookup_hint(
    claimed: Option<&IdentityContext>,
    tenant: Option<&VerifiedTenant>,
    credential: Option<&CredentialHandle>,
    identity: Option<&IdentityContext>,
) -> Result<(), AuthError> {
    let Some(claimed) = claimed else {
        return Ok(());
    };
    if claimed.tenant.as_ref().map(|tenant| tenant.id.as_str())
        != tenant.map(|tenant| tenant.tenant.id.as_str())
    {
        return Err(AuthError::TenantMismatch {
            requested: claimed
                .tenant
                .as_ref()
                .map(|tenant| tenant.id.clone())
                .unwrap_or_else(|| "<none>".to_owned()),
            verified: tenant
                .map(|tenant| tenant.tenant.id.clone())
                .unwrap_or_else(|| "<none>".to_owned()),
        });
    }
    if let Some(claimed_credential) = claimed.credential_ref.as_ref() {
        let Some(credential) = credential else {
            return Err(AuthError::MissingCredential);
        };
        if claimed_credential.id != credential.id()
            || claimed_credential.issuer != credential.issuer()
        {
            return Err(AuthError::Credential(
                "credential lookup hint does not match the trusted directory".to_owned(),
            ));
        }
    }
    if let Some(identity) = identity
        && (claimed
            .external_account
            .as_ref()
            .is_some_and(|account| identity.external_account.as_ref() != Some(account))
            || claimed
                .external_user
                .as_ref()
                .is_some_and(|user| identity.external_user.as_ref() != Some(user))
            || claimed.human_actor.as_ref().is_some_and(|actor| {
                identity.human_actor.as_ref().map(|trusted| &trusted.id) != Some(&actor.id)
            })
            || claimed.acted_on_behalf_of.as_ref().is_some_and(|actor| {
                identity
                    .acted_on_behalf_of
                    .as_ref()
                    .map(|trusted| &trusted.id)
                    != Some(&actor.id)
            }))
    {
        return Err(AuthError::Resolution(
            "identity lookup hint does not match the trusted directory".to_owned(),
        ));
    }
    Ok(())
}

/// One delegated approval scope established by an authority resolver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedAuthorityScope {
    /// Scope label.
    pub scope: String,
    /// Expiration time.
    #[serde(with = "persisted_timestamp")]
    pub expires_at: OffsetDateTime,
    /// Optional maximum risk rank accepted by the grant.
    pub max_risk_rank: Option<u8>,
    /// Optional maximum governed numeric value accepted by the grant.
    pub max_value: Option<u64>,
    /// Revocation marker.
    pub revoked: bool,
}

/// Trusted authority memberships for an approval actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityMembership {
    /// Approver principal.
    pub principal_id: PrincipalId,
    /// Verified tenant id.
    pub tenant_id: Option<String>,
    /// Verified roles.
    pub roles: BTreeSet<String>,
    /// Verified groups.
    pub groups: BTreeSet<String>,
    /// Verified tenant policy ids.
    pub tenant_policies: BTreeSet<String>,
    /// Verified external approval systems.
    pub external_systems: BTreeSet<String>,
    /// Delegated scopes.
    pub delegated_scopes: Vec<DelegatedAuthorityScope>,
    /// Membership revision used for revocation-aware caches.
    pub revision: u64,
    /// Time after which this resolution must be refreshed.
    #[serde(
        default,
        with = "persisted_timestamp::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
    /// Whether the membership has been revoked.
    pub revoked: bool,
}

impl AuthorityMembership {
    /// Validates the membership's principal, expiry, and revocation state.
    pub fn validate_for(&self, principal_id: &PrincipalId) -> Result<(), AuthError> {
        if &self.principal_id != principal_id {
            return Err(AuthError::Resolution(
                "authority membership principal mismatch".to_owned(),
            ));
        }
        if self.revoked {
            return Err(AuthError::Resolution(
                "authority membership is revoked".to_owned(),
            ));
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AuthError::Resolution(
                "authority membership has expired".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Trusted approval authority resolver.
#[async_trait]
pub trait ApprovalAuthorityResolver: Send + Sync {
    /// Resolves current tenant, role, group, external, and delegated authority.
    async fn resolve(
        &self,
        approval_id: &ApprovalId,
        actor: &AuthenticatedPrincipal,
        tenant_id: Option<&str>,
    ) -> Result<AuthorityMembership, AuthError>;

    /// Returns the current authority-directory revision for cache validation.
    ///
    /// Resolvers that cannot provide a cheap revocation-aware revision MUST
    /// return `None`; callers then bypass cached authority decisions.
    async fn current_revision(
        &self,
        _actor: &AuthenticatedPrincipal,
        _tenant_id: Option<&str>,
    ) -> Result<Option<u64>, AuthError> {
        Ok(None)
    }
}

/// Fail-closed authority resolver used when no policy backend is configured.
#[derive(Clone, Debug, Default)]
pub struct DenyAllApprovalAuthorityResolver;

#[async_trait]
impl ApprovalAuthorityResolver for DenyAllApprovalAuthorityResolver {
    async fn resolve(
        &self,
        _approval_id: &ApprovalId,
        _actor: &AuthenticatedPrincipal,
        _tenant_id: Option<&str>,
    ) -> Result<AuthorityMembership, AuthError> {
        Err(AuthError::Resolution(
            "no approval authority resolver is configured".to_owned(),
        ))
    }
}

/// Deterministic authority directory for conformance and embedded deployments.
#[derive(Clone, Debug, Default)]
pub struct StaticApprovalAuthorityResolver {
    memberships: BTreeMap<PrincipalId, AuthorityMembership>,
}

impl StaticApprovalAuthorityResolver {
    /// Creates a directory from verified memberships.
    #[must_use]
    pub fn new(memberships: impl IntoIterator<Item = AuthorityMembership>) -> Self {
        Self {
            memberships: memberships
                .into_iter()
                .map(|membership| (membership.principal_id.clone(), membership))
                .collect(),
        }
    }
}

#[async_trait]
impl ApprovalAuthorityResolver for StaticApprovalAuthorityResolver {
    async fn resolve(
        &self,
        _approval_id: &ApprovalId,
        actor: &AuthenticatedPrincipal,
        tenant_id: Option<&str>,
    ) -> Result<AuthorityMembership, AuthError> {
        let membership = self
            .memberships
            .get(&actor.principal.id)
            .cloned()
            .ok_or_else(|| {
                AuthError::Resolution("approver is not in the authority directory".to_owned())
            })?;
        membership.validate_for(&actor.principal.id)?;
        if let Some(tenant_id) = tenant_id
            && membership.tenant_id.as_deref() != Some(tenant_id)
        {
            return Err(AuthError::Resolution(
                "approver does not belong to the approval tenant".to_owned(),
            ));
        }
        Ok(membership)
    }

    async fn current_revision(
        &self,
        actor: &AuthenticatedPrincipal,
        tenant_id: Option<&str>,
    ) -> Result<Option<u64>, AuthError> {
        let membership = self.memberships.get(&actor.principal.id).ok_or_else(|| {
            AuthError::Resolution("approver is not in the authority directory".to_owned())
        })?;
        membership.validate_for(&actor.principal.id)?;
        if tenant_id.is_some_and(|tenant_id| membership.tenant_id.as_deref() != Some(tenant_id)) {
            return Err(AuthError::Resolution(
                "approver does not belong to the approval tenant".to_owned(),
            ));
        }
        Ok(Some(membership.revision))
    }
}

/// Bounds for a revocation-aware approval authority cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityCachePolicy {
    /// Maximum number of approval/principal/tenant entries.
    pub max_entries: usize,
    /// Maximum cache lifetime, additionally bounded by membership expiry.
    pub ttl_ms: u64,
}

impl Default for AuthorityCachePolicy {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            ttl_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AuthorityCacheKey {
    approval_id: ApprovalId,
    principal_id: PrincipalId,
    tenant_id: Option<String>,
}

#[derive(Clone, Debug)]
struct CachedAuthority {
    membership: AuthorityMembership,
    cached_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

/// Bounded approval resolver cache with expiry and revision validation.
///
/// A cached decision is never used unless the wrapped resolver reports the
/// same current revision. This makes revocation propagation independent of the
/// configured TTL. Resolvers without revision support remain correct by
/// bypassing the cache.
#[derive(Clone)]
pub struct CachedApprovalAuthorityResolver<R> {
    inner: Arc<R>,
    policy: AuthorityCachePolicy,
    entries: Arc<Mutex<BTreeMap<AuthorityCacheKey, CachedAuthority>>>,
}

impl<R> fmt::Debug for CachedApprovalAuthorityResolver<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CachedApprovalAuthorityResolver")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<R> CachedApprovalAuthorityResolver<R> {
    /// Creates a cache around a deployment resolver.
    pub fn new(inner: R, policy: AuthorityCachePolicy) -> Result<Self, AuthError> {
        if policy.max_entries == 0 || policy.ttl_ms == 0 {
            return Err(AuthError::Resolution(
                "authority cache bounds must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            inner: Arc::new(inner),
            policy,
            entries: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Evicts every cached decision for a principal.
    pub fn invalidate_principal(&self, principal_id: &PrincipalId) -> Result<usize, AuthError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AuthError::Resolution("authority cache lock was poisoned".to_owned()))?;
        let before = entries.len();
        entries.retain(|key, _| &key.principal_id != principal_id);
        Ok(before.saturating_sub(entries.len()))
    }

    fn insert(
        &self,
        key: AuthorityCacheKey,
        membership: AuthorityMembership,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let ttl_expiry =
            now + time::Duration::milliseconds(self.policy.ttl_ms.min(i64::MAX as u64) as i64);
        let expires_at = membership
            .expires_at
            .map_or(ttl_expiry, |expiry| expiry.min(ttl_expiry));
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AuthError::Resolution("authority cache lock was poisoned".to_owned()))?;
        entries.retain(|_, entry| entry.expires_at > now);
        while entries.len() >= self.policy.max_entries {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else {
                break;
            };
            entries.remove(&oldest);
        }
        entries.insert(
            key,
            CachedAuthority {
                membership,
                cached_at: now,
                expires_at,
            },
        );
        Ok(())
    }
}

#[async_trait]
impl<R> ApprovalAuthorityResolver for CachedApprovalAuthorityResolver<R>
where
    R: ApprovalAuthorityResolver + 'static,
{
    async fn resolve(
        &self,
        approval_id: &ApprovalId,
        actor: &AuthenticatedPrincipal,
        tenant_id: Option<&str>,
    ) -> Result<AuthorityMembership, AuthError> {
        actor.validate(&BTreeSet::new())?;
        let key = AuthorityCacheKey {
            approval_id: approval_id.clone(),
            principal_id: actor.principal.id.clone(),
            tenant_id: tenant_id.map(ToOwned::to_owned),
        };
        let now = OffsetDateTime::now_utc();
        let cached = self
            .entries
            .lock()
            .map_err(|_| AuthError::Resolution("authority cache lock was poisoned".to_owned()))?
            .get(&key)
            .filter(|entry| entry.expires_at > now)
            .cloned();
        if let Some(cached) = cached
            && self.inner.current_revision(actor, tenant_id).await?
                == Some(cached.membership.revision)
        {
            cached.membership.validate_for(&actor.principal.id)?;
            return Ok(cached.membership);
        }
        let membership = self.inner.resolve(approval_id, actor, tenant_id).await?;
        membership.validate_for(&actor.principal.id)?;
        self.insert(key, membership.clone(), now)?;
        Ok(membership)
    }

    async fn current_revision(
        &self,
        actor: &AuthenticatedPrincipal,
        tenant_id: Option<&str>,
    ) -> Result<Option<u64>, AuthError> {
        self.inner.current_revision(actor, tenant_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalAuthorityResolver, AuthenticatedPrincipal, AuthorityCachePolicy,
        AuthorityMembership, BearerToken, CachedApprovalAuthorityResolver,
        CachedTrustedIdentityResolver, CredentialHandle, HttpTokenIntrospector,
        IdentityCachePolicy, IdentityResolutionRequest, IntrospectionTokenVerifier,
        ResolvedIdentity, TokenIntrospection, TokenIntrospector, TokenVerificationRequest,
        TokenVerifier, TrustedIdentityBinding, TrustedIdentityResolver, VerifiedTenant,
        validate_identity_lookup_hint,
    };
    use crate::{AuthError, AuthScheme};
    use aip_core::{
        ApprovalId, ExternalAccountRef, IdentityContext, Principal, PrincipalId, PrincipalKind,
        TenantRef,
    };
    use async_trait::async_trait;
    use axum::{Json, Router, body::Bytes, http::HeaderMap, routing::post};
    use serde_json::json;
    use std::{
        collections::BTreeSet,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use time::{Duration, OffsetDateTime};

    #[derive(Clone)]
    struct Introspector(TokenIntrospection);

    #[derive(Clone)]
    struct MutableAuthorityResolver {
        membership: Arc<Mutex<AuthorityMembership>>,
        resolves: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct MutableIdentityResolver {
        binding: Arc<Mutex<TrustedIdentityBinding>>,
        resolves: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl TrustedIdentityResolver for MutableIdentityResolver {
        async fn resolve(
            &self,
            request: IdentityResolutionRequest<'_>,
        ) -> Result<ResolvedIdentity, AuthError> {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            let binding = self
                .binding
                .lock()
                .map_err(|_| AuthError::Resolution("test lock poisoned".to_owned()))?
                .clone();
            binding.validate(&request)?;
            Ok(ResolvedIdentity {
                actor: request.actor.clone(),
                tenant: binding.tenant,
                credential: binding.credential,
                identity: binding.identity,
            })
        }

        async fn current_revision(
            &self,
            _actor: &AuthenticatedPrincipal,
        ) -> Result<Option<u64>, AuthError> {
            Ok(Some(
                self.binding
                    .lock()
                    .map_err(|_| AuthError::Resolution("test lock poisoned".to_owned()))?
                    .revision,
            ))
        }
    }

    #[async_trait]
    impl ApprovalAuthorityResolver for MutableAuthorityResolver {
        async fn resolve(
            &self,
            _approval_id: &ApprovalId,
            actor: &AuthenticatedPrincipal,
            _tenant_id: Option<&str>,
        ) -> Result<AuthorityMembership, AuthError> {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            let membership = self
                .membership
                .lock()
                .map_err(|_| AuthError::Resolution("test lock poisoned".to_owned()))?
                .clone();
            membership.validate_for(&actor.principal.id)?;
            Ok(membership)
        }

        async fn current_revision(
            &self,
            _actor: &AuthenticatedPrincipal,
            _tenant_id: Option<&str>,
        ) -> Result<Option<u64>, AuthError> {
            Ok(Some(
                self.membership
                    .lock()
                    .map_err(|_| AuthError::Resolution("test lock poisoned".to_owned()))?
                    .revision,
            ))
        }
    }

    #[async_trait]
    impl TokenIntrospector for Introspector {
        async fn introspect(&self, _token: &BearerToken) -> Result<TokenIntrospection, AuthError> {
            Ok(self.0.clone())
        }
    }

    fn claims(now: OffsetDateTime) -> TokenIntrospection {
        TokenIntrospection {
            active: true,
            subject: Some("principal:operator".to_owned()),
            issuer: Some("https://issuer.example".to_owned()),
            audiences: BTreeSet::from(["https://aip.example".to_owned()]),
            scopes: BTreeSet::from(["action:write".to_owned()]),
            expires_at: Some(now + Duration::minutes(5)),
            tenant_id: Some("tenant-a".to_owned()),
            token_fingerprint: "sha256:test".to_owned(),
        }
    }

    async fn introspection_endpoint(headers: HeaderMap, body: Bytes) -> Json<serde_json::Value> {
        assert!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Basic "))
        );
        let body = std::str::from_utf8(&body).expect("form body");
        assert!(body.contains("token=opaque-token"));
        Json(json!({
            "active": true,
            "sub": "service:introspection-user",
            "iss": "https://issuer.example",
            "aud": ["https://aip.example/mcp"],
            "scope": "action:read action:write",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 300,
            "tenant_id": "tenant-a"
        }))
    }

    #[tokio::test]
    async fn http_introspector_authenticates_bounds_and_verifies_claims() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("introspection listener");
        let address = listener.local_addr().expect("introspection address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/introspect", post(introspection_endpoint)),
            )
            .await
            .expect("introspection server");
        });
        let introspector = HttpTokenIntrospector::new_with_loopback_http(
            format!("http://{address}/introspect"),
            "https://issuer.example",
            "getaip-server",
            b"introspection-secret".to_vec(),
        )
        .expect("HTTP introspector");
        assert!(!format!("{introspector:?}").contains("introspection-secret"));
        let verifier = IntrospectionTokenVerifier::new(introspector);
        let verified = verifier
            .verify(
                &BearerToken::new(b"opaque-token".to_vec()).expect("token"),
                &TokenVerificationRequest {
                    accepted_issuers: BTreeSet::from(["https://issuer.example".to_owned()]),
                    audience: "https://aip.example/mcp".to_owned(),
                    required_scopes: BTreeSet::from(["action:write".to_owned()]),
                    now: OffsetDateTime::now_utc(),
                },
            )
            .await
            .expect("verified HTTP token");
        assert_eq!(verified.subject, "service:introspection-user");
        assert_eq!(verified.tenant_id.as_deref(), Some("tenant-a"));
        assert!(verified.token_fingerprint.starts_with("sha256:"));
        assert!(!verified.token_fingerprint.contains("opaque-token"));
        server.abort();
    }

    #[test]
    fn http_introspector_rejects_non_tls_non_loopback_endpoint() {
        let error = HttpTokenIntrospector::new_with_loopback_http(
            "http://192.0.2.10/introspect",
            "https://issuer.example",
            "getaip-server",
            b"secret".to_vec(),
        )
        .expect_err("non-loopback HTTP must be rejected");
        assert!(error.to_string().contains("HTTPS"));
    }

    #[tokio::test]
    async fn introspection_verifier_checks_issuer_audience_scope_and_expiry() {
        let now = OffsetDateTime::now_utc();
        let verifier = IntrospectionTokenVerifier::new(Introspector(claims(now)));
        let verified = verifier
            .verify(
                &BearerToken::new(b"opaque".to_vec()).expect("token"),
                &TokenVerificationRequest {
                    accepted_issuers: BTreeSet::from(["https://issuer.example".to_owned()]),
                    audience: "https://aip.example".to_owned(),
                    required_scopes: BTreeSet::from(["action:write".to_owned()]),
                    now,
                },
            )
            .await
            .expect("verified token");
        assert_eq!(verified.subject, "principal:operator");
        assert_eq!(verified.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[tokio::test]
    async fn introspection_verifier_rejects_revoked_wrong_audience_and_expired_tokens() {
        let now = OffsetDateTime::now_utc();
        let mut revoked = claims(now);
        revoked.active = false;
        let verifier = IntrospectionTokenVerifier::new(Introspector(revoked));
        let request = TokenVerificationRequest {
            accepted_issuers: BTreeSet::from(["https://issuer.example".to_owned()]),
            audience: "https://aip.example".to_owned(),
            required_scopes: BTreeSet::new(),
            now,
        };
        assert!(
            verifier
                .verify(
                    &BearerToken::new(b"revoked".to_vec()).expect("token"),
                    &request,
                )
                .await
                .is_err()
        );

        let mut wrong_audience = claims(now);
        wrong_audience.audiences.clear();
        let verifier = IntrospectionTokenVerifier::new(Introspector(wrong_audience));
        assert!(
            verifier
                .verify(
                    &BearerToken::new(b"wrong-audience".to_vec()).expect("token"),
                    &request,
                )
                .await
                .is_err()
        );

        let mut expired = claims(now);
        expired.expires_at = Some(now - Duration::seconds(1));
        let verifier = IntrospectionTokenVerifier::new(Introspector(expired));
        assert!(
            verifier
                .verify(
                    &BearerToken::new(b"expired".to_vec()).expect("token"),
                    &request,
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn authority_cache_revalidates_revision_and_rejects_revocation() {
        let principal = Principal::new(
            PrincipalId::trusted("human:cached-approver"),
            PrincipalKind::Human,
        );
        let actor = AuthenticatedPrincipal {
            principal: principal.clone(),
            scheme: AuthScheme::Oauth2,
            issuer: "https://identity.example".to_owned(),
            audience: Some("aip-runtime".to_owned()),
            scopes: BTreeSet::from(["approval:write".to_owned()]),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            credential_fingerprint: Some("sha256:credential".to_owned()),
        };
        let membership = Arc::new(Mutex::new(AuthorityMembership {
            principal_id: principal.id.clone(),
            tenant_id: Some("tenant-a".to_owned()),
            roles: BTreeSet::from(["finance-approver".to_owned()]),
            groups: BTreeSet::new(),
            tenant_policies: BTreeSet::new(),
            external_systems: BTreeSet::new(),
            delegated_scopes: Vec::new(),
            revision: 1,
            expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            revoked: false,
        }));
        let resolves = Arc::new(AtomicUsize::new(0));
        let cache = CachedApprovalAuthorityResolver::new(
            MutableAuthorityResolver {
                membership: membership.clone(),
                resolves: resolves.clone(),
            },
            AuthorityCachePolicy {
                max_entries: 2,
                ttl_ms: 60_000,
            },
        )
        .expect("cache");
        let approval_id = ApprovalId::new();

        cache
            .resolve(&approval_id, &actor, Some("tenant-a"))
            .await
            .expect("initial resolve");
        cache
            .resolve(&approval_id, &actor, Some("tenant-a"))
            .await
            .expect("cache hit");
        assert_eq!(resolves.load(Ordering::SeqCst), 1);

        {
            let mut membership = membership.lock().expect("membership lock");
            membership.revision = 2;
            membership.revoked = true;
        }
        let rejected = cache.resolve(&approval_id, &actor, Some("tenant-a")).await;
        assert!(rejected.is_err());
        assert_eq!(resolves.load(Ordering::SeqCst), 2);
        assert_eq!(
            cache
                .invalidate_principal(&principal.id)
                .expect("invalidate"),
            1
        );
    }

    #[tokio::test]
    async fn identity_cache_revalidates_revision_and_rejects_revocation() {
        let principal = Principal::new(
            PrincipalId::trusted("service:cached-identity"),
            PrincipalKind::Service,
        );
        let actor = AuthenticatedPrincipal {
            principal: principal.clone(),
            scheme: AuthScheme::Oauth2,
            issuer: "https://identity.example".to_owned(),
            audience: Some("aip-runtime".to_owned()),
            scopes: BTreeSet::from(["action:execute".to_owned()]),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            credential_fingerprint: Some("sha256:identity-token".to_owned()),
        };
        let identity = IdentityContext {
            tenant: Some(TenantRef {
                id: "tenant-a".to_owned(),
                system: Some("directory".to_owned()),
            }),
            external_account: None,
            external_user: None,
            human_actor: None,
            service_account: Some(principal.clone()),
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        };
        let binding = Arc::new(Mutex::new(TrustedIdentityBinding {
            principal_id: principal.id.clone(),
            tenant: Some(VerifiedTenant {
                tenant: identity.tenant.clone().expect("tenant"),
                membership_id: "membership:tenant-a:service".to_owned(),
                roles: BTreeSet::from(["operator".to_owned()]),
                groups: BTreeSet::new(),
                verified_at: OffsetDateTime::now_utc(),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            }),
            credential: None,
            identity: Some(identity.clone()),
            revision: 1,
            revoked: false,
            expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
        }));
        let resolves = Arc::new(AtomicUsize::new(0));
        let cache = CachedTrustedIdentityResolver::new(
            MutableIdentityResolver {
                binding: binding.clone(),
                resolves: resolves.clone(),
            },
            IdentityCachePolicy {
                max_entries: 2,
                ttl_ms: 60_000,
            },
        )
        .expect("identity cache");
        let issuers = BTreeSet::new();
        let scopes = BTreeSet::new();

        for _ in 0..2 {
            cache
                .resolve(IdentityResolutionRequest {
                    actor: &actor,
                    claimed_identity: Some(&identity),
                    accepted_credential_issuers: &issuers,
                    credential_required: false,
                    required_credential_scopes: &scopes,
                })
                .await
                .expect("resolved identity");
        }
        assert_eq!(resolves.load(Ordering::SeqCst), 1);

        {
            let mut binding = binding.lock().expect("identity binding lock");
            binding.revision = 2;
            binding.revoked = true;
        }
        let rejected = cache
            .resolve(IdentityResolutionRequest {
                actor: &actor,
                claimed_identity: Some(&identity),
                accepted_credential_issuers: &issuers,
                credential_required: false,
                required_credential_scopes: &scopes,
            })
            .await;
        assert!(rejected.is_err());
        assert_eq!(resolves.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn omitted_identity_hints_accept_trusted_enrichment_but_conflicts_fail_closed() {
        let trusted = IdentityContext {
            tenant: None,
            external_account: Some(ExternalAccountRef {
                id: "account-42".to_owned(),
                system: "provider".to_owned(),
            }),
            external_user: None,
            human_actor: None,
            service_account: None,
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        };
        let omitted = IdentityContext {
            tenant: None,
            external_account: None,
            external_user: None,
            human_actor: None,
            service_account: None,
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        };
        validate_identity_lookup_hint(Some(&omitted), None, None, Some(&trusted))
            .expect("trusted directory may enrich an omitted optional lookup hint");

        let conflicting = IdentityContext {
            external_account: Some(ExternalAccountRef {
                id: "different-account".to_owned(),
                system: "provider".to_owned(),
            }),
            ..omitted
        };
        assert!(matches!(
            validate_identity_lookup_hint(Some(&conflicting), None, None, Some(&trusted)),
            Err(AuthError::Resolution(_))
        ));
    }

    #[test]
    fn optional_credential_policy_does_not_require_a_credential_handle() {
        let principal = Principal::new(
            PrincipalId::trusted("service:deployment-credential"),
            PrincipalKind::Service,
        );
        let actor = AuthenticatedPrincipal {
            principal: principal.clone(),
            scheme: AuthScheme::Oauth2,
            issuer: "https://identity.example".to_owned(),
            audience: Some("aip-runtime".to_owned()),
            scopes: BTreeSet::from(["action:execute".to_owned()]),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            credential_fingerprint: None,
        };
        let binding = TrustedIdentityBinding {
            principal_id: principal.id,
            tenant: None,
            credential: None,
            identity: None,
            revision: 1,
            revoked: false,
            expires_at: None,
        };
        let issuers = BTreeSet::from(["deployment-connector".to_owned()]);
        let scopes = BTreeSet::from(["records:read".to_owned()]);

        binding
            .validate(&IdentityResolutionRequest {
                actor: &actor,
                claimed_identity: None,
                accepted_credential_issuers: &issuers,
                credential_required: false,
                required_credential_scopes: &scopes,
            })
            .expect("optional deployment credential");

        let required = binding.validate(&IdentityResolutionRequest {
            actor: &actor,
            claimed_identity: None,
            accepted_credential_issuers: &issuers,
            credential_required: true,
            required_credential_scopes: &scopes,
        });
        assert!(matches!(required, Err(AuthError::MissingCredential)));
    }

    #[test]
    fn secrets_are_redacted_from_debug_output() {
        let token = BearerToken::new(b"super-secret".to_vec()).expect("token");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn deployment_identity_timestamps_use_rfc3339_json() {
        let timestamp =
            OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("qualification timestamp");
        let actor = AuthenticatedPrincipal {
            principal: Principal::new(
                PrincipalId::trusted("service:rfc3339-identity"),
                PrincipalKind::Service,
            ),
            scheme: AuthScheme::Oauth2,
            issuer: "https://identity.example".to_owned(),
            audience: Some("aip".to_owned()),
            scopes: BTreeSet::from(["*".to_owned()]),
            authenticated_at: timestamp,
            expires_at: Some(timestamp + Duration::minutes(5)),
            credential_fingerprint: None,
        };
        let encoded = serde_json::to_value(&actor).expect("serialize trusted actor");
        assert!(encoded["authenticated_at"].is_string());
        assert!(encoded["expires_at"].is_string());
        assert_eq!(
            serde_json::from_value::<AuthenticatedPrincipal>(encoded)
                .expect("deserialize trusted actor"),
            actor
        );

        let credential = CredentialHandle::new(
            "credential:rfc3339",
            "deployment",
            BTreeSet::from(["*".to_owned()]),
            Some("tenant-rfc3339".to_owned()),
            Some(timestamp + Duration::minutes(5)),
        )
        .expect("credential handle");
        let encoded = serde_json::to_value(&credential).expect("serialize credential handle");
        assert!(encoded["expires_at"].is_string());
        assert_eq!(
            serde_json::from_value::<CredentialHandle>(encoded)
                .expect("deserialize credential handle"),
            credential
        );
    }

    #[test]
    fn deployment_identity_timestamps_accept_legacy_tuple_json() {
        let authenticated_at =
            OffsetDateTime::from_unix_timestamp(1_750_000_000).expect("legacy timestamp");
        let expires_at = authenticated_at + Duration::minutes(5);
        let actor = AuthenticatedPrincipal {
            principal: Principal::new(
                PrincipalId::trusted("service:legacy-persisted-identity"),
                PrincipalKind::Service,
            ),
            scheme: AuthScheme::Oauth2,
            issuer: "https://identity.example".to_owned(),
            audience: Some("aip".to_owned()),
            scopes: BTreeSet::from(["action:read".to_owned()]),
            authenticated_at,
            expires_at: Some(expires_at),
            credential_fingerprint: None,
        };
        let mut legacy = serde_json::to_value(&actor).expect("serialize current actor");
        legacy["authenticated_at"] =
            serde_json::to_value(authenticated_at).expect("serialize legacy required timestamp");
        legacy["expires_at"] =
            serde_json::to_value(expires_at).expect("serialize legacy optional timestamp");
        assert!(legacy["authenticated_at"].is_array());
        assert!(legacy["expires_at"].is_array());

        let decoded = serde_json::from_value::<AuthenticatedPrincipal>(legacy)
            .expect("read identity persisted by the pre-RFC3339 runtime");
        assert_eq!(decoded, actor);
        let canonical = serde_json::to_value(decoded).expect("rewrite identity canonically");
        assert!(canonical["authenticated_at"].is_string());
        assert!(canonical["expires_at"].is_string());
    }
}
