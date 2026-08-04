//! OAuth 2.1 client lifecycle for remote MCP protected resources.

use crate::{McpClientError, McpClientResult, read_bounded_http_bytes};
use aip_transport_mcp_streamable_http::ProtectedResourceMetadata;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use constant_time_eq::constant_time_eq;
use rand_core::{OsRng, RngCore};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::Mutex;

const OAUTH_RESPONSE_MAX_BYTES: usize = 1024 * 1024;

/// Redacted bearer token returned only to the HTTP authorization boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBearerToken(String);

impl SecretBearerToken {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBearerToken(<redacted>)")
    }
}

/// OAuth authorization-server metadata required by the MCP host.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Supported PKCE methods.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported scopes.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// OAuth client settings for one MCP protected resource.
#[derive(Clone, Debug)]
pub struct McpOAuthClientConfig {
    /// Protected MCP resource identifier.
    pub resource: Url,
    /// RFC 9728 metadata URL.
    pub protected_resource_metadata_url: Url,
    /// Optional explicit authorization-server metadata URL.
    pub authorization_server_metadata_url: Option<Url>,
    /// Public or pre-registered OAuth client id.
    pub client_id: String,
    /// Authorization-code redirect URI.
    pub redirect_uri: Url,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Allows plain HTTP only for loopback integration tests and local tools.
    pub allow_insecure_loopback: bool,
    /// Refresh skew before token expiry.
    pub refresh_skew_seconds: i64,
}

impl McpOAuthClientConfig {
    /// Creates a config and derives the default protected-resource metadata URL.
    pub fn new(
        resource: Url,
        client_id: impl Into<String>,
        redirect_uri: Url,
    ) -> McpClientResult<Self> {
        let protected_resource_metadata_url = protected_resource_metadata_url(&resource)?;
        Ok(Self {
            resource,
            protected_resource_metadata_url,
            authorization_server_metadata_url: None,
            client_id: client_id.into(),
            redirect_uri,
            scopes: Vec::new(),
            allow_insecure_loopback: false,
            refresh_skew_seconds: 60,
        })
    }
}

/// Token set retained only by a deployment credential store.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokenSet {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    scopes: Vec<String>,
    expires_at: Option<OffsetDateTime>,
}

impl fmt::Debug for OAuthTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("token_type", &self.token_type)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl OAuthTokenSet {
    fn access_token(&self) -> SecretBearerToken {
        SecretBearerToken(self.access_token.clone())
    }

    fn needs_refresh(&self, skew_seconds: i64) -> bool {
        self.expires_at.is_some_and(|expiry| {
            expiry <= OffsetDateTime::now_utc() + time::Duration::seconds(skew_seconds.max(0))
        })
    }
}

/// Browser launch information for an authorization-code flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationLaunch {
    /// Authorization URL including PKCE and resource indicator parameters.
    pub url: Url,
    /// Opaque CSRF state value that must match the callback.
    pub state: String,
}

#[derive(Clone)]
pub struct PendingAuthorization {
    state: String,
    code_verifier: String,
    created_at: OffsetDateTime,
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("state", &"<redacted>")
            .field("code_verifier", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Secret-store boundary for OAuth callback state and token material.
#[async_trait]
pub trait McpOAuthCredentialStore: Send + Sync {
    /// Saves one pending PKCE authorization, replacing any older attempt.
    async fn save_pending(&self, pending: PendingAuthorization) -> McpClientResult<()>;
    /// Atomically consumes the pending authorization state.
    async fn take_pending(&self) -> McpClientResult<Option<PendingAuthorization>>;
    /// Loads the current token set.
    async fn load_tokens(&self) -> McpClientResult<Option<OAuthTokenSet>>;
    /// Atomically replaces the current token set after exchange or rotation.
    async fn save_tokens(&self, tokens: OAuthTokenSet) -> McpClientResult<()>;
    /// Removes unusable token material and forces reauthorization.
    async fn clear_tokens(&self) -> McpClientResult<()>;
}

/// In-memory credential store for embedded hosts and deterministic tests.
/// Production deployments should provide an encrypted secret-store adapter.
#[derive(Clone, Debug, Default)]
pub struct InMemoryMcpOAuthCredentialStore {
    pending: Arc<Mutex<Option<PendingAuthorization>>>,
    tokens: Arc<Mutex<Option<OAuthTokenSet>>>,
}

#[async_trait]
impl McpOAuthCredentialStore for InMemoryMcpOAuthCredentialStore {
    async fn save_pending(&self, pending: PendingAuthorization) -> McpClientResult<()> {
        *self.pending.lock().await = Some(pending);
        Ok(())
    }

    async fn take_pending(&self) -> McpClientResult<Option<PendingAuthorization>> {
        Ok(self.pending.lock().await.take())
    }

    async fn load_tokens(&self) -> McpClientResult<Option<OAuthTokenSet>> {
        Ok(self.tokens.lock().await.clone())
    }

    async fn save_tokens(&self, tokens: OAuthTokenSet) -> McpClientResult<()> {
        *self.tokens.lock().await = Some(tokens);
        Ok(())
    }

    async fn clear_tokens(&self) -> McpClientResult<()> {
        *self.tokens.lock().await = None;
        Ok(())
    }
}

/// Access-token source consumed by the Streamable HTTP transport.
#[async_trait]
pub trait McpAccessTokenProvider: Send + Sync {
    /// Returns a non-expired access token, refreshing it when needed.
    async fn access_token(&self) -> McpClientResult<SecretBearerToken>;
    /// Forces one refresh after a resource server rejects the current token.
    async fn force_refresh(&self) -> McpClientResult<SecretBearerToken>;
}

/// OAuth 2.1 authorization-code and refresh manager for an MCP resource.
#[derive(Clone)]
pub struct McpOAuthTokenManager {
    client: Client,
    config: McpOAuthClientConfig,
    protected_resource: ProtectedResourceMetadata,
    authorization_server: AuthorizationServerMetadata,
    credentials: Arc<dyn McpOAuthCredentialStore>,
    refresh_lock: Arc<Mutex<()>>,
}

impl fmt::Debug for McpOAuthTokenManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpOAuthTokenManager")
            .field("resource", &self.config.resource)
            .field("issuer", &self.authorization_server.issuer)
            .field("client_id", &self.config.client_id)
            .finish_non_exhaustive()
    }
}

impl McpOAuthTokenManager {
    /// Discovers and validates both metadata documents before constructing the
    /// token manager.
    pub async fn discover(
        config: McpOAuthClientConfig,
        credentials: Arc<dyn McpOAuthCredentialStore>,
    ) -> McpClientResult<Self> {
        validate_secure_url(&config.resource, config.allow_insecure_loopback)?;
        validate_secure_url(
            &config.protected_resource_metadata_url,
            config.allow_insecure_loopback,
        )?;
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        let protected_resource = fetch_json::<ProtectedResourceMetadata>(
            &client,
            config.protected_resource_metadata_url.clone(),
        )
        .await?;
        if normalize_resource(&protected_resource.resource)? != normalize_url(&config.resource) {
            return Err(McpClientError::Unexpected(
                "protected-resource metadata returned a different resource identifier".to_owned(),
            ));
        }
        let issuer = protected_resource
            .authorization_servers
            .first()
            .ok_or_else(|| {
                McpClientError::Unexpected(
                    "protected-resource metadata did not advertise an authorization server"
                        .to_owned(),
                )
            })?;
        let issuer_url =
            Url::parse(issuer).map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        validate_secure_url(&issuer_url, config.allow_insecure_loopback)?;
        let metadata_url = config
            .authorization_server_metadata_url
            .clone()
            .unwrap_or(authorization_server_metadata_url(&issuer_url)?);
        validate_secure_url(&metadata_url, config.allow_insecure_loopback)?;
        let authorization_server =
            fetch_json::<AuthorizationServerMetadata>(&client, metadata_url).await?;
        if normalize_resource(&authorization_server.issuer)? != normalize_url(&issuer_url) {
            return Err(McpClientError::Unexpected(
                "authorization-server metadata issuer mismatch".to_owned(),
            ));
        }
        if !authorization_server
            .code_challenge_methods_supported
            .iter()
            .any(|method| method == "S256")
        {
            return Err(McpClientError::Unexpected(
                "authorization server does not advertise PKCE S256".to_owned(),
            ));
        }
        for endpoint in [
            &authorization_server.authorization_endpoint,
            &authorization_server.token_endpoint,
        ] {
            let endpoint = Url::parse(endpoint)
                .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
            validate_secure_url(&endpoint, config.allow_insecure_loopback)?;
        }
        Ok(Self {
            client,
            config,
            protected_resource,
            authorization_server,
            credentials,
            refresh_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Creates and stores one PKCE authorization attempt.
    pub async fn begin_authorization(&self) -> McpClientResult<AuthorizationLaunch> {
        let state = random_secret(32);
        let code_verifier = random_secret(64);
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        self.credentials
            .save_pending(PendingAuthorization {
                state: state.clone(),
                code_verifier,
                created_at: OffsetDateTime::now_utc(),
            })
            .await?;
        let mut url = Url::parse(&self.authorization_server.authorization_endpoint)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.config.client_id)
                .append_pair("redirect_uri", self.config.redirect_uri.as_str())
                .append_pair("state", &state)
                .append_pair("code_challenge", &code_challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("resource", self.config.resource.as_str());
            if !self.config.scopes.is_empty() {
                query.append_pair("scope", &self.config.scopes.join(" "));
            }
        }
        Ok(AuthorizationLaunch { url, state })
    }

    /// Validates callback state and exchanges one authorization code.
    pub async fn complete_authorization(
        &self,
        code: &str,
        returned_state: &str,
    ) -> McpClientResult<()> {
        let pending =
            self.credentials.take_pending().await?.ok_or_else(|| {
                McpClientError::Unexpected("OAuth state was not found".to_owned())
            })?;
        if pending.created_at + time::Duration::minutes(10) <= OffsetDateTime::now_utc()
            || pending.state.len() != returned_state.len()
            || !constant_time_eq(pending.state.as_bytes(), returned_state.as_bytes())
        {
            return Err(McpClientError::Unexpected(
                "OAuth state is invalid or expired".to_owned(),
            ));
        }
        let tokens = self
            .token_request(&[
                ("grant_type", "authorization_code".to_owned()),
                ("code", code.to_owned()),
                ("redirect_uri", self.config.redirect_uri.to_string()),
                ("code_verifier", pending.code_verifier),
            ])
            .await?;
        self.credentials.save_tokens(tokens).await
    }

    async fn refresh(&self, force: bool) -> McpClientResult<SecretBearerToken> {
        let _guard = self.refresh_lock.lock().await;
        let current = self.credentials.load_tokens().await?.ok_or_else(|| {
            McpClientError::Unexpected("OAuth authorization is required".to_owned())
        })?;
        if !force && !current.needs_refresh(self.config.refresh_skew_seconds) {
            return Ok(current.access_token());
        }
        let refresh_token = current.refresh_token.clone().ok_or_else(|| {
            McpClientError::Unexpected("OAuth reauthorization is required".to_owned())
        })?;
        match self
            .token_request(&[
                ("grant_type", "refresh_token".to_owned()),
                ("refresh_token", refresh_token),
            ])
            .await
        {
            Ok(mut refreshed) => {
                if refreshed.refresh_token.is_none() {
                    refreshed.refresh_token = current.refresh_token;
                }
                let access = refreshed.access_token();
                self.credentials.save_tokens(refreshed).await?;
                Ok(access)
            }
            Err(error) => {
                self.credentials.clear_tokens().await?;
                Err(error)
            }
        }
    }

    async fn token_request(&self, fields: &[(&str, String)]) -> McpClientResult<OAuthTokenSet> {
        let mut form = fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect::<Vec<_>>();
        form.push(("client_id".to_owned(), self.config.client_id.clone()));
        form.push(("resource".to_owned(), self.config.resource.to_string()));
        if !self.config.scopes.is_empty() {
            form.push(("scope".to_owned(), self.config.scopes.join(" ")));
        }
        let endpoint = Url::parse(&self.authorization_server.token_endpoint)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let response = self
            .client
            .post(endpoint)
            .header("accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let body = read_bounded_http_bytes(response, OAUTH_RESPONSE_MAX_BYTES).await?;
        if !content_type.starts_with("application/json") {
            return Err(McpClientError::Unexpected(
                "OAuth token response is not application/json".to_owned(),
            ));
        }
        if status != StatusCode::OK {
            let error = serde_json::from_slice::<OAuthErrorResponse>(&body).ok();
            return Err(McpClientError::Peer {
                code: i64::from(status.as_u16()),
                message: error
                    .as_ref()
                    .and_then(|error| error.error_description.clone())
                    .or_else(|| error.map(|error| error.error))
                    .unwrap_or_else(|| "OAuth token endpoint rejected the request".to_owned()),
                data: None,
            });
        }
        let response: OAuthTokenResponse = serde_json::from_slice(&body)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        if !response.token_type.eq_ignore_ascii_case("bearer") || response.access_token.is_empty() {
            return Err(McpClientError::Unexpected(
                "OAuth token endpoint returned an invalid bearer token".to_owned(),
            ));
        }
        let expires_at = response.expires_in.map(|seconds| {
            OffsetDateTime::now_utc() + time::Duration::seconds(seconds.min(i64::MAX as u64) as i64)
        });
        let scopes = response
            .scope
            .map(|scope| scope.split_whitespace().map(ToOwned::to_owned).collect())
            .unwrap_or_else(|| self.config.scopes.clone());
        Ok(OAuthTokenSet {
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            token_type: response.token_type,
            scopes,
            expires_at,
        })
    }

    /// Returns the validated protected-resource metadata.
    #[must_use]
    pub fn protected_resource(&self) -> &ProtectedResourceMetadata {
        &self.protected_resource
    }
}

#[async_trait]
impl McpAccessTokenProvider for McpOAuthTokenManager {
    async fn access_token(&self) -> McpClientResult<SecretBearerToken> {
        self.refresh(false).await
    }

    async fn force_refresh(&self) -> McpClientResult<SecretBearerToken> {
        self.refresh(true).await
    }
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: String,
    error_description: Option<String>,
}

async fn fetch_json<T>(client: &Client, url: Url) -> McpClientResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    let response = client
        .get(url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| McpClientError::Transport(error.to_string()))?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(McpClientError::Transport(format!(
            "OAuth metadata endpoint returned HTTP {status}"
        )));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return Err(McpClientError::Unexpected(
            "OAuth metadata response is not application/json".to_owned(),
        ));
    }
    let body = read_bounded_http_bytes(response, OAUTH_RESPONSE_MAX_BYTES).await?;
    serde_json::from_slice::<T>(&body)
        .map_err(|error| McpClientError::Unexpected(error.to_string()))
}

fn protected_resource_metadata_url(resource: &Url) -> McpClientResult<Url> {
    let mut url = resource.clone();
    let path = resource.path().trim_matches('/');
    let metadata_path = if path.is_empty() {
        "/.well-known/oauth-protected-resource".to_owned()
    } else {
        format!("/.well-known/oauth-protected-resource/{path}")
    };
    url.set_path(&metadata_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn authorization_server_metadata_url(issuer: &Url) -> McpClientResult<Url> {
    let mut url = issuer.clone();
    let path = issuer.path().trim_matches('/');
    let metadata_path = if path.is_empty() {
        "/.well-known/oauth-authorization-server".to_owned()
    } else {
        format!("/.well-known/oauth-authorization-server/{path}")
    };
    url.set_path(&metadata_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn validate_secure_url(url: &Url, allow_insecure_loopback: bool) -> McpClientResult<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if allow_insecure_loopback && url.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(McpClientError::Unexpected(format!(
        "OAuth endpoint `{url}` must use HTTPS"
    )))
}

fn normalize_resource(value: &str) -> McpClientResult<String> {
    let url = Url::parse(value).map_err(|error| McpClientError::Unexpected(error.to_string()))?;
    Ok(normalize_url(&url))
}

fn normalize_url(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
}

fn random_secret(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        InMemoryMcpOAuthCredentialStore, McpAccessTokenProvider, McpOAuthClientConfig,
        McpOAuthTokenManager,
    };
    use axum::{Json, Router, extract::State, routing::get};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn discovery_pkce_exchange_and_refresh_cover_the_resource_lifecycle() {
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let issuer = format!("http://{address}");
        let resource = format!("{issuer}/mcp");
        let protected = {
            let issuer = issuer.clone();
            let resource = resource.clone();
            move || async move {
                Json(json!({
                    "resource": resource,
                    "authorization_servers": [issuer],
                    "bearer_methods_supported": ["header"]
                }))
            }
        };
        let metadata = {
            let issuer = issuer.clone();
            move || async move {
                Json(json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                    "code_challenge_methods_supported": ["S256"]
                }))
            }
        };
        async fn token(State(calls): State<Arc<AtomicUsize>>) -> Json<Value> {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            Json(if call == 0 {
                json!({
                    "access_token": "access-initial",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-initial",
                    "expires_in": 1
                })
            } else {
                json!({
                    "access_token": "access-refreshed",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-rotated",
                    "expires_in": 3600
                })
            })
        }
        let router = Router::new()
            .route("/resource-meta", get(protected))
            .route("/as-meta", get(metadata))
            .route("/token", axum::routing::post(token))
            .with_state(calls.clone());
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });

        let mut config = McpOAuthClientConfig::new(
            resource.parse().expect("resource"),
            "test-client",
            format!("{issuer}/callback").parse().expect("redirect"),
        )
        .expect("config");
        config.protected_resource_metadata_url =
            format!("{issuer}/resource-meta").parse().expect("metadata");
        config.authorization_server_metadata_url =
            Some(format!("{issuer}/as-meta").parse().expect("as metadata"));
        config.allow_insecure_loopback = true;
        config.scopes = vec!["mcp.read".to_owned()];
        config.refresh_skew_seconds = 60;
        let manager = McpOAuthTokenManager::discover(
            config,
            Arc::new(InMemoryMcpOAuthCredentialStore::default()),
        )
        .await
        .expect("discover");
        let launch = manager.begin_authorization().await.expect("authorize");
        let parameters = launch
            .url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            parameters
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert_eq!(
            parameters.get("resource").map(|value| value.as_ref()),
            Some(resource.as_str())
        );
        manager
            .complete_authorization("authorization-code", &launch.state)
            .await
            .expect("exchange");
        let refreshed = manager.access_token().await.expect("refresh by skew");
        assert_eq!(refreshed.expose(), "access-refreshed");
        assert!(!format!("{refreshed:?}").contains("access-refreshed"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
