//! Generic signed HTTP webhook profile for AIP connectors.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

/// Generic webhook profile id.
pub const PROFILE_ID: &str = "aip.http.webhook.v1";

/// Normalized AIP webhook headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookHeaders {
    /// Delivery id.
    pub delivery: String,
    /// Unix timestamp in seconds.
    pub timestamp: i64,
    /// Signature value.
    pub signature: String,
    /// Source system.
    pub source_system: String,
    /// Source event type.
    pub event_type: String,
}

/// Webhook verification error.
#[derive(Debug, Error)]
pub enum WebhookError {
    /// The signing key could not be initialized.
    #[error("invalid signing key")]
    InvalidKey,
    /// The timestamp was outside the accepted skew.
    #[error("timestamp outside allowed skew")]
    TimestampSkew,
    /// The signature was invalid.
    #[error("invalid webhook signature")]
    InvalidSignature,
    /// The signature encoding is invalid.
    #[error("invalid signature encoding: {0}")]
    InvalidEncoding(String),
}

/// Signs a webhook payload with HMAC-SHA256.
pub fn sign(
    secret: &[u8],
    delivery: &str,
    timestamp: i64,
    payload: &[u8],
) -> Result<String, WebhookError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WebhookError::InvalidKey)?;
    mac.update(signing_input(delivery, timestamp, payload).as_bytes());
    Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

/// Verifies a webhook HMAC signature and timestamp skew.
pub fn verify(
    secret: &[u8],
    headers: &WebhookHeaders,
    payload: &[u8],
    max_skew_seconds: i64,
) -> Result<(), WebhookError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if (now - headers.timestamp).abs() > max_skew_seconds {
        return Err(WebhookError::TimestampSkew);
    }
    let expected = sign(secret, &headers.delivery, headers.timestamp, payload)?;
    let expected_bytes = BASE64_STANDARD
        .decode(expected)
        .map_err(|error| WebhookError::InvalidEncoding(error.to_string()))?;
    let supplied_bytes = BASE64_STANDARD
        .decode(&headers.signature)
        .map_err(|error| WebhookError::InvalidEncoding(error.to_string()))?;
    if expected_bytes.len() != supplied_bytes.len() {
        return Err(WebhookError::InvalidSignature);
    }
    if !constant_time_eq::constant_time_eq(&expected_bytes, &supplied_bytes) {
        return Err(WebhookError::InvalidSignature);
    }
    Ok(())
}

fn signing_input(delivery: &str, timestamp: i64, payload: &[u8]) -> String {
    format!(
        "{timestamp}.{delivery}.{}",
        String::from_utf8_lossy(payload)
    )
}

#[cfg(test)]
mod tests {
    use super::{WebhookHeaders, sign, verify};
    use time::OffsetDateTime;

    #[test]
    fn verifies_signature() {
        let payload = br#"{"event":"message_created"}"#;
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let signature = sign(b"secret", "delivery-1", timestamp, payload).expect("signature");
        let headers = WebhookHeaders {
            delivery: "delivery-1".to_owned(),
            timestamp,
            signature,
            source_system: "chatwoot".to_owned(),
            event_type: "message_created".to_owned(),
        };
        verify(b"secret", &headers, payload, 300).expect("valid webhook");
    }
}
