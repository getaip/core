//! Cal.diy API v2 HTTP client boundary.

use crate::operations::{CalDiyHttpMethod, CalDiyOperation};
use aip_connector::ConnectorSecret;
use reqwest::{Client, RequestBuilder, header::HeaderValue, redirect::Policy};
use serde_json::{Map, Value, json};
use std::{fmt, time::Duration};
use thiserror::Error;
use url::Url;

/// Default maximum accepted Cal.diy response body size.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Hard upper bound for a deployment-configured response limit.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUERY_PAIRS: usize = 4_096;
const MAX_QUERY_KEY_BYTES: usize = 512;
const MAX_QUERY_VALUE_BYTES: usize = 32 * 1024;
const MAX_REQUEST_URL_BYTES: usize = 128 * 1024;

/// Supported Cal.diy API authentication mechanisms.
#[derive(Clone)]
pub enum CalDiyAuth {
    /// API key, managed-user access token, or OAuth access token carried as Bearer auth.
    Bearer(ConnectorSecret),
    /// Cal platform client credentials.
    OAuthClientCredentials {
        /// Public Cal OAuth client id.
        client_id: String,
        /// Cal OAuth client secret.
        client_secret: ConnectorSecret,
    },
}

impl fmt::Debug for CalDiyAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => formatter.write_str("Bearer([REDACTED])"),
            Self::OAuthClientCredentials { client_id, .. } => formatter
                .debug_struct("OAuthClientCredentials")
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Successful Cal.diy provider response.
#[derive(Clone, Debug, PartialEq)]
pub struct CalDiyProviderResponse {
    /// HTTP response status.
    pub status: u16,
    /// Provider-generated `X-Request-Id`, when present.
    pub request_id: Option<String>,
    /// Parsed response body.
    pub body: Value,
}

/// Trusted request metadata propagated from the AIP execution boundary.
///
/// These values are never accepted from action input. They are established by
/// the transport authenticator and tenant resolver, then attached by the
/// connector so provider-side audit records can be correlated with AIP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalDiyRequestMetadata {
    /// Authenticated AIP actor id.
    pub actor_id: String,
    /// Verified AIP tenant id.
    pub tenant_id: String,
    /// Cal.diy account selected by trusted deployment configuration.
    pub account_id: String,
    /// Trusted trace id, when one was established by the runtime.
    pub trace_id: Option<String>,
}

/// Redacted Cal.diy client error.
#[derive(Debug, Error)]
pub enum CalDiyClientError {
    /// Base URL or route construction failed.
    #[error("invalid Cal.diy URL: {0}")]
    InvalidUrl(String),
    /// An operation input is missing a required path or body field.
    #[error("invalid Cal.diy operation input: {0}")]
    InvalidInput(String),
    /// Configured credential material is invalid.
    #[error("configured Cal.diy credential is invalid")]
    InvalidCredential,
    /// HTTP transport failed.
    #[error("Cal.diy transport failed")]
    Transport,
    /// Cal.diy rejected the request.
    #[error("Cal.diy returned HTTP {status} ({code})")]
    Remote {
        /// HTTP status.
        status: u16,
        /// Redacted provider error code.
        code: String,
        /// Provider-generated request id.
        request_id: Option<String>,
        /// Parsed `Retry-After` delay.
        retry_after_ms: Option<u64>,
    },
    /// A successful response was not valid JSON.
    #[error("Cal.diy returned an invalid success response")]
    InvalidResponse,
    /// The provider response exceeded the deployment-owned memory bound.
    #[error("Cal.diy response exceeded the configured size limit")]
    ResponseTooLarge {
        /// HTTP status observed before the body was rejected.
        status: u16,
        /// Provider request id, when available.
        request_id: Option<String>,
    },
}

impl From<reqwest::Error> for CalDiyClientError {
    fn from(_error: reqwest::Error) -> Self {
        Self::Transport
    }
}

impl CalDiyClientError {
    /// Returns the provider request id when available.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Remote { request_id, .. } | Self::ResponseTooLarge { request_id, .. } => {
                request_id.as_deref()
            }
            _ => None,
        }
    }

    /// Returns the remote HTTP status when available.
    #[must_use]
    pub const fn remote_status(&self) -> Option<u16> {
        match self {
            Self::Remote { status, .. } | Self::ResponseTooLarge { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns the provider retry delay when available.
    #[must_use]
    pub const fn retry_after_ms(&self) -> Option<u64> {
        match self {
            Self::Remote { retry_after_ms, .. } => *retry_after_ms,
            _ => None,
        }
    }
}

/// Authenticated, version-aware Cal.diy API client.
#[derive(Clone, Debug)]
pub struct CalDiyClient {
    base_url: Url,
    auth: CalDiyAuth,
    client: Client,
    max_response_bytes: usize,
}

impl CalDiyClient {
    /// Creates a hardened client that does not follow redirects with credentials.
    pub fn new(base_url: impl AsRef<str>, auth: CalDiyAuth) -> Result<Self, CalDiyClientError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        Self::with_http_client(base_url, auth, client)
    }

    /// Creates a client using an explicitly supplied HTTP client for crate tests.
    pub(crate) fn with_http_client(
        base_url: impl AsRef<str>,
        auth: CalDiyAuth,
        client: Client,
    ) -> Result<Self, CalDiyClientError> {
        let mut base_url = Url::parse(base_url.as_ref())
            .map_err(|error| CalDiyClientError::InvalidUrl(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(CalDiyClientError::InvalidUrl(
                "scheme must be http or https".to_owned(),
            ));
        }
        if base_url.cannot_be_a_base() || base_url.host_str().is_none() {
            return Err(CalDiyClientError::InvalidUrl(
                "URL must contain an authority".to_owned(),
            ));
        }
        if !base_url.username().is_empty() || base_url.password().is_some() {
            return Err(CalDiyClientError::InvalidUrl(
                "embedded URL credentials are forbidden".to_owned(),
            ));
        }
        if base_url.scheme() == "http" && !base_url.host_str().is_some_and(is_loopback_host) {
            return Err(CalDiyClientError::InvalidUrl(
                "plain HTTP is allowed only for loopback development endpoints".to_owned(),
            ));
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        validate_auth(&auth)?;
        Ok(Self {
            base_url,
            auth,
            client,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Overrides the maximum response body accepted into memory.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, CalDiyClientError> {
        if !(1..=MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(CalDiyClientError::InvalidInput(format!(
                "max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}"
            )));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    /// Returns the configured provider base URL without credentials.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Returns the configured provider response bound.
    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Executes one version-pinned operation.
    pub async fn execute(
        &self,
        operation: CalDiyOperation,
        input: &Value,
        action_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<CalDiyProviderResponse, CalDiyClientError> {
        self.execute_with_metadata(operation, input, action_id, idempotency_key, None)
            .await
    }

    /// Executes one version-pinned operation with trusted AIP audit metadata.
    pub async fn execute_with_metadata(
        &self,
        operation: CalDiyOperation,
        input: &Value,
        action_id: &str,
        idempotency_key: Option<&str>,
        metadata: Option<&CalDiyRequestMetadata>,
    ) -> Result<CalDiyProviderResponse, CalDiyClientError> {
        let path = render_path(operation, input)?;
        let mut url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|error| CalDiyClientError::InvalidUrl(error.to_string()))?;
        if operation.uses_query() {
            append_query(&mut url, operation, input)?;
        }
        let method = match operation.method() {
            CalDiyHttpMethod::Get => reqwest::Method::GET,
            CalDiyHttpMethod::Post => reqwest::Method::POST,
            CalDiyHttpMethod::Patch => reqwest::Method::PATCH,
            CalDiyHttpMethod::Put => reqwest::Method::PUT,
            CalDiyHttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut request = self
            .apply_auth(self.client.request(method, url))?
            .header("accept", "application/json")
            .header("cal-api-version", operation.api_version())
            .header("x-aip-action-id", action_id);
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("idempotency-key", idempotency_key);
        }
        if let Some(metadata) = metadata {
            request = request
                .header("x-aip-principal-id", &metadata.actor_id)
                .header("x-aip-tenant-id", &metadata.tenant_id)
                .header("x-aip-external-account-id", &metadata.account_id);
            if let Some(trace_id) = &metadata.trace_id {
                request = request.header("x-aip-trace-id", trace_id);
            }
        }
        if !operation.is_read() && !matches!(operation.method(), CalDiyHttpMethod::Delete) {
            let body = body_for_operation(operation, input)?;
            ensure_request_size(&body)?;
            request = request.json(&body);
        }
        let mut response = request.send().await?;
        let status = response.status();
        let request_id = provider_request_id(response.headers());
        let retry_after_ms = parse_retry_after(response.headers().get("retry-after"));
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(CalDiyClientError::ResponseTooLarge {
                status: status.as_u16(),
                request_id,
            });
        }
        let mut bytes = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or_default()
                .min(self.max_response_bytes),
        );
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(CalDiyClientError::ResponseTooLarge {
                    status: status.as_u16(),
                    request_id,
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = if bytes.is_empty() {
            json!({ "status": "success" })
        } else {
            serde_json::from_slice::<Value>(&bytes).map_err(|_| {
                if status.is_success() {
                    CalDiyClientError::InvalidResponse
                } else {
                    CalDiyClientError::Remote {
                        status: status.as_u16(),
                        code: "invalid_error_response".to_owned(),
                        request_id: request_id.clone(),
                        retry_after_ms,
                    }
                }
            })?
        };
        if !status.is_success() {
            return Err(CalDiyClientError::Remote {
                status: status.as_u16(),
                code: provider_error_code(&body),
                request_id,
                retry_after_ms,
            });
        }
        if body.get("status").and_then(Value::as_str) == Some("error") {
            return Err(CalDiyClientError::Remote {
                status: status.as_u16(),
                code: provider_error_code(&body),
                request_id,
                retry_after_ms,
            });
        }
        Ok(CalDiyProviderResponse {
            status: status.as_u16(),
            request_id,
            body,
        })
    }

    /// Performs an authenticated readiness probe against the profile endpoint.
    pub async fn health(&self) -> Result<CalDiyProviderResponse, CalDiyClientError> {
        self.execute(CalDiyOperation::ProfileGet, &json!({}), "health", None)
            .await
    }

    fn apply_auth(&self, request: RequestBuilder) -> Result<RequestBuilder, CalDiyClientError> {
        match &self.auth {
            CalDiyAuth::Bearer(token) => Ok(request.bearer_auth(
                token
                    .expose_str()
                    .map_err(|_| CalDiyClientError::InvalidCredential)?,
            )),
            CalDiyAuth::OAuthClientCredentials {
                client_id,
                client_secret,
            } => Ok(request.header("x-cal-client-id", client_id).header(
                "x-cal-secret-key",
                client_secret
                    .expose_str()
                    .map_err(|_| CalDiyClientError::InvalidCredential)?,
            )),
        }
    }
}

fn validate_auth(auth: &CalDiyAuth) -> Result<(), CalDiyClientError> {
    match auth {
        CalDiyAuth::Bearer(token) => {
            let token = token
                .expose_str()
                .map_err(|_| CalDiyClientError::InvalidCredential)?;
            if token.is_empty()
                || token.len() > 16 * 1024
                || HeaderValue::from_str(&format!("Bearer {token}")).is_err()
            {
                return Err(CalDiyClientError::InvalidCredential);
            }
            Ok(())
        }
        CalDiyAuth::OAuthClientCredentials {
            client_id,
            client_secret,
        } => {
            let client_secret = client_secret
                .expose_str()
                .map_err(|_| CalDiyClientError::InvalidCredential)?;
            if client_id.trim().is_empty()
                || client_id.len() > 16 * 1024
                || client_secret.is_empty()
                || client_secret.len() > 16 * 1024
                || HeaderValue::from_str(client_id).is_err()
                || HeaderValue::from_str(client_secret).is_err()
            {
                return Err(CalDiyClientError::InvalidCredential);
            }
            Ok(())
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn render_path(operation: CalDiyOperation, input: &Value) -> Result<String, CalDiyClientError> {
    let mut url = Url::parse("http://cal-diy.invalid/")
        .map_err(|error| CalDiyClientError::InvalidUrl(error.to_string()))?;
    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            CalDiyClientError::InvalidUrl("route URL cannot contain path segments".to_owned())
        })?;
        segments.clear();
        for segment in operation.path_template().trim_matches('/').split('/') {
            if let Some(parameter) = segment
                .strip_prefix('{')
                .and_then(|segment| segment.strip_suffix('}'))
            {
                let value = scalar_string(input.get(parameter)).ok_or_else(|| {
                    CalDiyClientError::InvalidInput(format!("missing path parameter `{parameter}`"))
                })?;
                if value.len() > 512 || value.chars().any(char::is_control) {
                    return Err(CalDiyClientError::InvalidInput(format!(
                        "path parameter `{parameter}` must contain at most 512 bytes without control characters"
                    )));
                }
                segments.push(&value);
            } else {
                segments.push(segment);
            }
        }
    }
    Ok(url.path().to_owned())
}

fn append_query(
    url: &mut Url,
    operation: CalDiyOperation,
    input: &Value,
) -> Result<(), CalDiyClientError> {
    let object = input.as_object().ok_or_else(|| {
        CalDiyClientError::InvalidInput("action input must be a JSON object".to_owned())
    })?;
    let mut pairs = Vec::new();
    for key in operation.query_parameters() {
        let Some(value) = object.get(*key) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        append_query_value(&mut pairs, key, value, 0)?;
    }
    let mut query = url.query_pairs_mut();
    for (key, value) in pairs {
        query.append_pair(&key, &value);
    }
    drop(query);
    if url.as_str().len() > MAX_REQUEST_URL_BYTES {
        return Err(CalDiyClientError::InvalidInput(format!(
            "encoded request URL exceeds {MAX_REQUEST_URL_BYTES} bytes"
        )));
    }
    Ok(())
}

fn append_query_value(
    pairs: &mut Vec<(String, String)>,
    key: &str,
    value: &Value,
    depth: usize,
) -> Result<(), CalDiyClientError> {
    if depth > 8 {
        return Err(CalDiyClientError::InvalidInput(format!(
            "query parameter `{key}` exceeds the nesting limit"
        )));
    }
    if key.len() > MAX_QUERY_KEY_BYTES || key.chars().any(char::is_control) {
        return Err(CalDiyClientError::InvalidInput(format!(
            "query parameter name exceeds {MAX_QUERY_KEY_BYTES} bytes or contains control characters"
        )));
    }
    if pairs.len() >= MAX_QUERY_PAIRS {
        return Err(CalDiyClientError::InvalidInput(format!(
            "query exceeds {MAX_QUERY_PAIRS} encoded values"
        )));
    }
    if let Some(value) = scalar_string(Some(value)) {
        if value.len() > MAX_QUERY_VALUE_BYTES || value.chars().any(char::is_control) {
            return Err(CalDiyClientError::InvalidInput(format!(
                "query parameter `{key}` exceeds {MAX_QUERY_VALUE_BYTES} bytes or contains control characters"
            )));
        }
        pairs.push((key.to_owned(), value));
        return Ok(());
    }
    match value {
        Value::Null => Ok(()),
        Value::Array(values) => {
            let contains_composite = values
                .iter()
                .any(|value| matches!(value, Value::Array(_) | Value::Object(_)));
            for (index, value) in values.iter().enumerate() {
                let child_key = if contains_composite {
                    format!("{key}[{index}]")
                } else {
                    key.to_owned()
                };
                append_query_value(pairs, &child_key, value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for (child_key, child_value) in object {
                append_query_value(
                    pairs,
                    &format!("{key}[{child_key}]"),
                    child_value,
                    depth + 1,
                )?;
            }
            Ok(())
        }
        _ => Err(CalDiyClientError::InvalidInput(format!(
            "query parameter `{key}` contains an unsupported value"
        ))),
    }
}

fn body_for_operation(
    operation: CalDiyOperation,
    input: &Value,
) -> Result<Value, CalDiyClientError> {
    let mut body = input.as_object().cloned().ok_or_else(|| {
        CalDiyClientError::InvalidInput("action input must be a JSON object".to_owned())
    })?;
    for parameter in operation.path_parameters() {
        body.remove(*parameter);
    }
    for parameter in operation.query_parameters() {
        body.remove(*parameter);
    }
    body.remove("webhook_secret_ref");
    body.remove("compensation_input");
    Ok(Value::Object(body))
}

fn ensure_request_size(body: &Value) -> Result<(), CalDiyClientError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| CalDiyClientError::InvalidInput(error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(CalDiyClientError::InvalidInput(format!(
            "request body exceeds {MAX_REQUEST_BYTES} bytes"
        )));
    }
    Ok(())
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn provider_error_code(body: &Value) -> String {
    body.pointer("/error/code")
        .or_else(|| body.get("code"))
        .and_then(Value::as_str)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
                })
        })
        .unwrap_or("remote_error")
        .to_owned()
}

fn provider_request_id(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
                })
        })
        .map(ToOwned::to_owned)
}

fn parse_retry_after(value: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    let value = value?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1_000));
    }
    let retry_at = httpdate::parse_http_date(value).ok()?;
    let delay = retry_at.duration_since(std::time::SystemTime::now()).ok()?;
    Some(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX))
}

/// Adds non-secret webhook material resolved outside the AIP action payload.
pub(crate) fn inject_webhook_secret(
    input: &Value,
    secret: &str,
) -> Result<Value, CalDiyClientError> {
    let mut object: Map<String, Value> = input.as_object().cloned().ok_or_else(|| {
        CalDiyClientError::InvalidInput("action input must be a JSON object".to_owned())
    })?;
    object.insert("secret".to_owned(), Value::String(secret.to_owned()));
    Ok(Value::Object(object))
}

#[cfg(test)]
mod tests {
    use super::{
        CalDiyAuth, CalDiyClient, MAX_QUERY_VALUE_BYTES, MAX_REQUEST_BYTES, append_query,
        ensure_request_size, provider_error_code, render_path,
    };
    use crate::operations::CalDiyOperation;
    use aip_connector::ConnectorSecret;
    use serde_json::json;
    use url::Url;

    #[test]
    fn path_parameters_are_percent_encoded() {
        let path = render_path(
            CalDiyOperation::BookingGet,
            &json!({ "booking_uid": "uid/with space" }),
        )
        .expect("path should render");
        assert_eq!(path, "/v2/bookings/uid%2Fwith%20space");
    }

    #[test]
    fn provider_error_codes_are_redacted() {
        assert_eq!(
            provider_error_code(&json!({ "error": { "code": "Bad Request: email" } })),
            "remote_error"
        );
        assert_eq!(
            provider_error_code(&json!({ "error": { "code": "BOOKING_NOT_FOUND" } })),
            "BOOKING_NOT_FOUND"
        );
        assert_eq!(
            provider_error_code(&json!({ "error": "user alice@example.test not found" })),
            "remote_error"
        );
    }

    #[test]
    fn nested_calendar_query_uses_bracket_notation() {
        let mut url = Url::parse("https://cal.example/v2/calendars/busy-times")
            .expect("fixture URL should parse");
        append_query(
            &mut url,
            CalDiyOperation::CalendarBusyTimeList,
            &json!({
                "timeZone": "UTC",
                "dateFrom": "2026-07-11",
                "dateTo": "2026-07-12",
                "calendarsToLoad": [
                    { "credentialId": 42, "externalId": "primary@example.com" }
                ]
            }),
        )
        .expect("nested query should encode");

        let decoded = url.query_pairs().collect::<Vec<_>>();
        assert!(
            decoded
                .iter()
                .any(|(key, value)| { key == "calendarsToLoad[0][credentialId]" && value == "42" })
        );
        assert!(decoded.iter().any(|(key, value)| {
            key == "calendarsToLoad[0][externalId]" && value == "primary@example.com"
        }));
    }

    #[test]
    fn provider_request_inputs_are_bounded_before_dispatch() {
        let error = render_path(
            CalDiyOperation::BookingGet,
            &json!({ "booking_uid": "x".repeat(513) }),
        )
        .expect_err("oversized path segment must fail");
        assert!(error.to_string().contains("path parameter"));

        let mut url = Url::parse("https://cal.example/v2/slots").expect("fixture URL");
        let error = append_query(
            &mut url,
            CalDiyOperation::SlotList,
            &json!({ "start": "x".repeat(MAX_QUERY_VALUE_BYTES + 1) }),
        )
        .expect_err("oversized query value must fail");
        assert!(error.to_string().contains("query parameter"));

        let body = json!({ "value": "x".repeat(MAX_REQUEST_BYTES + 1) });
        assert!(ensure_request_size(&body).is_err());
    }

    #[test]
    fn rejects_plain_http_for_non_loopback_provider() {
        let error = CalDiyClient::new(
            "http://cal.internal.example/api",
            CalDiyAuth::Bearer(ConnectorSecret::new("token")),
        )
        .expect_err("remote plain HTTP must be rejected");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn rejects_embedded_base_url_credentials() {
        let error = CalDiyClient::new(
            "https://user:secret@cal.example.test/api",
            CalDiyAuth::Bearer(ConnectorSecret::new("token")),
        )
        .expect_err("URL credentials must be rejected");
        assert!(error.to_string().contains("credentials are forbidden"));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn rejects_invalid_auth_header_material_at_construction() {
        let error = CalDiyClient::new(
            "https://cal.example.test/api",
            CalDiyAuth::Bearer(ConnectorSecret::new(b"token\nheader-injection")),
        )
        .expect_err("invalid header material must fail before dispatch");
        assert_eq!(
            error.to_string(),
            "configured Cal.diy credential is invalid"
        );
    }
}
