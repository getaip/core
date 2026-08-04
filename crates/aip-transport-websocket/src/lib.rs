//! WebSocket binding for AIP envelopes.
//!
//! This crate owns AIP WebSocket framing semantics without depending on a
//! concrete server implementation. HTTP servers can adapt their WebSocket
//! library frames to [`WebSocketFrame`] and reuse the transport state here for
//! multiplexing, ping/pong, close handling, and session-scoped queues.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{CorrelationId, Envelope, SessionId};
use aip_transport::{
    StreamingTransport, Transport, TransportError, TransportMessage, TransportResult,
};
use async_trait::async_trait;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};
use tokio::sync::RwLock;

/// Native WebSocket profile id.
pub const PROFILE_ID: &str = "aip.websocket.stream.v1";

/// Logical WebSocket frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSocketFrame {
    /// Text frame containing an AIP envelope as JSON.
    Text(String),
    /// Ping control frame.
    Ping(Vec<u8>),
    /// Pong control frame.
    Pong(Vec<u8>),
    /// Close frame with reason.
    Close(String),
}

/// Encodes an envelope as a text frame.
pub fn encode_ws(envelope: &Envelope) -> TransportResult<WebSocketFrame> {
    let data = serde_json::to_string(envelope)
        .map_err(|error| TransportError::Codec(error.to_string()))?;
    Ok(WebSocketFrame::Text(data))
}

/// Decodes a text frame into an envelope.
pub fn decode_ws(frame: &WebSocketFrame) -> TransportResult<Envelope> {
    match frame {
        WebSocketFrame::Text(data) => {
            serde_json::from_str(data).map_err(|error| TransportError::Codec(error.to_string()))
        }
        _ => Err(TransportError::Unsupported("non-text websocket frame")),
    }
}

/// Returns a pong frame for a ping frame.
#[must_use]
pub fn pong_for_ping(frame: &WebSocketFrame) -> Option<WebSocketFrame> {
    match frame {
        WebSocketFrame::Ping(payload) => Some(WebSocketFrame::Pong(payload.clone())),
        _ => None,
    }
}

/// Multiplexing key for a WebSocket connection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MultiplexKey {
    /// Session id carried by the envelope.
    pub session_id: Option<SessionId>,
    /// Message type.
    pub message_type: String,
}

impl MultiplexKey {
    /// Builds a key from an envelope.
    #[must_use]
    pub fn from_envelope(envelope: &Envelope) -> Self {
        Self {
            session_id: envelope.session_id.clone(),
            message_type: envelope.message_type.as_str().to_owned(),
        }
    }
}

/// Connection-level state for a WebSocket binding.
#[derive(Clone, Debug, Default)]
pub struct WebSocketConnectionState {
    queues: HashMap<Option<SessionId>, VecDeque<TransportMessage>>,
    subscribed_correlations: HashSet<CorrelationId>,
    closed: Option<String>,
}

impl WebSocketConnectionState {
    /// Queues a message under its session id.
    pub fn push(&mut self, message: TransportMessage) -> TransportResult<()> {
        if self.closed.is_some() {
            return Err(TransportError::Connection(
                "websocket connection is closed".to_owned(),
            ));
        }
        self.queues
            .entry(message.envelope.session_id.clone())
            .or_default()
            .push_back(message);
        Ok(())
    }

    /// Removes the next message for a session.
    pub fn pop_session(&mut self, session_id: Option<&SessionId>) -> Option<TransportMessage> {
        let key = session_id.cloned();
        self.queues.get_mut(&key).and_then(VecDeque::pop_front)
    }

    /// Marks the connection closed.
    pub fn close(&mut self, reason: impl Into<String>) {
        self.closed = Some(reason.into());
    }

    /// Returns the close reason when the connection is closed.
    #[must_use]
    pub fn close_reason(&self) -> Option<&str> {
        self.closed.as_deref()
    }
}

/// Framework-neutral WebSocket transport state.
#[derive(Clone, Debug, Default)]
pub struct WebSocketTransport {
    state: Arc<RwLock<WebSocketConnectionState>>,
}

impl WebSocketTransport {
    /// Creates an empty WebSocket transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles an inbound logical frame.
    ///
    /// Text frames are decoded and queued. Ping frames return a pong frame.
    /// Close frames close the transport state.
    pub async fn handle_frame(
        &self,
        frame: WebSocketFrame,
    ) -> TransportResult<Option<WebSocketFrame>> {
        match frame {
            WebSocketFrame::Text(_) => {
                let envelope = decode_ws(&frame)?;
                self.publish(TransportMessage::new(envelope)).await?;
                Ok(None)
            }
            WebSocketFrame::Ping(payload) => Ok(Some(WebSocketFrame::Pong(payload))),
            WebSocketFrame::Pong(_) => Ok(None),
            WebSocketFrame::Close(reason) => {
                self.state.write().await.close(reason);
                Ok(None)
            }
        }
    }

    /// Drains the next queued message for a session.
    pub async fn next_for_session(
        &self,
        session_id: Option<&SessionId>,
    ) -> Option<TransportMessage> {
        self.state.write().await.pop_session(session_id)
    }

    /// Returns the close reason when the transport has been closed.
    pub async fn close_reason(&self) -> Option<String> {
        self.state
            .read()
            .await
            .close_reason()
            .map(ToOwned::to_owned)
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn publish(&self, message: TransportMessage) -> TransportResult<()> {
        self.state.write().await.push(message)
    }
}

#[async_trait]
impl StreamingTransport for WebSocketTransport {
    async fn subscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()> {
        self.state
            .write()
            .await
            .subscribed_correlations
            .insert(correlation_id.clone());
        Ok(())
    }

    async fn unsubscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()> {
        self.state
            .write()
            .await
            .subscribed_correlations
            .remove(correlation_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{WebSocketFrame, WebSocketTransport, decode_ws, encode_ws, pong_for_ping};
    use aip_core::{Envelope, ManifestRequest, MessageBody, SessionId};

    #[test]
    fn ping_maps_to_pong() {
        assert_eq!(
            pong_for_ping(&WebSocketFrame::Ping(vec![1, 2, 3])),
            Some(WebSocketFrame::Pong(vec![1, 2, 3]))
        );
    }

    #[tokio::test]
    async fn text_frame_is_queued_by_session() {
        let transport = WebSocketTransport::new();
        let session_id = SessionId::new();
        let mut envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));
        envelope.session_id = Some(session_id.clone());
        let frame = encode_ws(&envelope).expect("frame");
        transport.handle_frame(frame).await.expect("handle");
        let queued = transport
            .next_for_session(Some(&session_id))
            .await
            .expect("queued message");
        assert_eq!(queued.envelope.session_id, Some(session_id));
    }

    #[test]
    fn text_frame_round_trips() {
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));
        let frame = encode_ws(&envelope).expect("frame");
        let decoded = decode_ws(&frame).expect("decoded");
        assert_eq!(decoded.message_id, envelope.message_id);
    }
}
