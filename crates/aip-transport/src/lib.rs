//! Transport abstraction layer for AIP.

#![forbid(unsafe_code)]

use aip_core::{CorrelationId, Envelope};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Normalized transport metadata.
pub type Metadata = BTreeMap<String, String>;

/// Wire frame containing an envelope and transport metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransportMessage {
    /// Native AIP envelope.
    pub envelope: Envelope,
    /// Normalized headers or metadata.
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

impl TransportMessage {
    /// Creates a message from an envelope.
    #[must_use]
    pub fn new(envelope: Envelope) -> Self {
        Self {
            envelope,
            metadata: Metadata::new(),
        }
    }
}

/// Serialized transport frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFrame {
    /// Frame payload.
    pub payload: Bytes,
    /// Transport metadata.
    pub metadata: Metadata,
}

/// Transport-layer error.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Serialization or parsing failed.
    #[error("codec error: {0}")]
    Codec(String),
    /// Transport timed out.
    #[error("timeout")]
    Timeout,
    /// Transport connection failed.
    #[error("connection failed: {0}")]
    Connection(String),
    /// Operation is unsupported by this transport.
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
}

/// Result alias for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Fire-and-forget transport.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Publishes a message.
    async fn publish(&self, message: TransportMessage) -> TransportResult<()>;
}

/// Request/reply transport.
#[async_trait]
pub trait RequestReplyTransport: Transport {
    /// Sends a request and waits for a reply.
    async fn request(&self, message: TransportMessage) -> TransportResult<TransportMessage>;
}

/// Streaming transport.
#[async_trait]
pub trait StreamingTransport: Transport {
    /// Subscribes to a correlation-scoped stream.
    async fn subscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()>;

    /// Unsubscribes from a correlation-scoped stream.
    async fn unsubscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()>;
}

/// Serializes a transport message as JSON bytes.
pub fn encode_json(message: &TransportMessage) -> TransportResult<RawFrame> {
    let payload =
        serde_json::to_vec(message).map_err(|error| TransportError::Codec(error.to_string()))?;
    Ok(RawFrame {
        payload: Bytes::from(payload),
        metadata: message.metadata.clone(),
    })
}

/// Decodes a JSON transport frame.
pub fn decode_json(frame: &RawFrame) -> TransportResult<TransportMessage> {
    serde_json::from_slice(&frame.payload).map_err(|error| TransportError::Codec(error.to_string()))
}
