//! Native HTTP JSON binding for AIP.

#![forbid(unsafe_code)]

use aip_core::{Envelope, ErrorCategory, MessageBody, MessageType, ProtocolError};
use aip_transport::{Metadata, RawFrame, TransportError, TransportMessage, TransportResult};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

/// HTTP endpoint paths used by the native binding.
pub mod paths {
    /// Generic message endpoint.
    pub const MESSAGES: &str = "/aip/v1/messages";
    /// Action invocation endpoint.
    pub const ACTIONS: &str = "/aip/v1/actions";
    /// Manifest endpoint.
    pub const MANIFEST: &str = "/aip/v1/manifest";
}

/// Encodes an envelope as an HTTP JSON frame.
pub fn encode_http_json(envelope: &Envelope) -> TransportResult<RawFrame> {
    let payload =
        serde_json::to_vec(envelope).map_err(|error| TransportError::Codec(error.to_string()))?;
    let mut metadata = Metadata::new();
    metadata.insert("content-type".to_owned(), "application/aip+json".to_owned());
    metadata.insert(
        "aip-message-type".to_owned(),
        envelope.message_type.as_str().to_owned(),
    );
    Ok(RawFrame {
        payload: Bytes::from(payload),
        metadata,
    })
}

/// Decodes an HTTP JSON frame as a native envelope.
pub fn decode_http_json(frame: &RawFrame) -> TransportResult<Envelope> {
    serde_json::from_slice(&frame.payload).map_err(|error| TransportError::Codec(error.to_string()))
}

/// Maps an envelope to the recommended endpoint path.
#[must_use]
pub fn path_for_message_type(message_type: MessageType) -> &'static str {
    match message_type {
        MessageType::Action => paths::ACTIONS,
        MessageType::ManifestRequest | MessageType::ManifestResponse => paths::MANIFEST,
        _ => paths::MESSAGES,
    }
}

/// Maps a protocol error to an HTTP status code.
#[must_use]
pub fn status_for_error(error: &ProtocolError) -> StatusCode {
    match error.category {
        ErrorCategory::Auth => StatusCode::UNAUTHORIZED,
        ErrorCategory::Policy => StatusCode::FORBIDDEN,
        ErrorCategory::Temporary | ErrorCategory::Transport => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCategory::Connector => StatusCode::BAD_GATEWAY,
        ErrorCategory::Economic => StatusCode::PAYMENT_REQUIRED,
        ErrorCategory::Permanent => StatusCode::BAD_REQUEST,
    }
}

/// Converts normalized metadata into HTTP headers.
pub fn metadata_to_headers(metadata: &Metadata) -> TransportResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (key, value) in metadata {
        let name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

/// Converts HTTP headers into normalized metadata.
#[must_use]
pub fn headers_to_metadata(headers: &HeaderMap) -> Metadata {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

/// Creates a transport message from an envelope.
#[must_use]
pub fn transport_message(envelope: Envelope) -> TransportMessage {
    TransportMessage::new(envelope)
}

/// Returns true when the body is an HTTP action request.
#[must_use]
pub fn is_action(envelope: &Envelope) -> bool {
    matches!(envelope.body, MessageBody::Action(_))
}
