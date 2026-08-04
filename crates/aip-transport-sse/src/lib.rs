//! Server-Sent Events binding for AIP streaming.
//!
//! The crate is intentionally framework-neutral. It provides deterministic SSE
//! frame encoding/decoding, cursor handling, terminal event detection, and an
//! in-memory streaming transport that can be embedded by HTTP servers and tests.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{CorrelationId, Envelope, MessageBody, StreamChunkKind};
use aip_transport::{
    StreamingTransport, Transport, TransportError, TransportMessage, TransportResult,
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

/// Native SSE profile id.
pub const PROFILE_ID: &str = "aip.sse.stream.v1";

/// SSE event frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    /// SSE event name.
    pub event: String,
    /// Optional event id for reconnection.
    pub id: Option<String>,
    /// JSON data payload.
    pub data: String,
    /// Retry interval in milliseconds.
    pub retry_ms: Option<u64>,
}

impl SseEvent {
    /// Renders the event using the SSE wire format.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::new();
        if let Some(id) = &self.id {
            output.push_str("id: ");
            output.push_str(id);
            output.push('\n');
        }
        if let Some(retry_ms) = self.retry_ms {
            output.push_str("retry: ");
            output.push_str(&retry_ms.to_string());
            output.push('\n');
        }
        output.push_str("event: ");
        output.push_str(&self.event);
        output.push('\n');
        for line in self.data.lines() {
            output.push_str("data: ");
            output.push_str(line);
            output.push('\n');
        }
        output.push('\n');
        output
    }
}

/// Cursor used for SSE reconnection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SseCursor(usize);

impl SseCursor {
    /// Creates a cursor from a zero-based event index.
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Returns the zero-based event index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    /// Parses an SSE cursor from an event id.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        value
            .strip_prefix("sse_")
            .unwrap_or(value)
            .parse::<usize>()
            .ok()
            .map(Self)
    }
}

impl std::fmt::Display for SseCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "sse_{}", self.0)
    }
}

/// Encodes an AIP envelope into an SSE event.
pub fn encode_sse(envelope: &Envelope) -> TransportResult<SseEvent> {
    encode_sse_with_id(envelope, Some(envelope.message_id.to_string()))
}

/// Encodes an AIP envelope into an SSE event with an explicit reconnection id.
pub fn encode_sse_with_id(envelope: &Envelope, id: Option<String>) -> TransportResult<SseEvent> {
    let event = match &envelope.body {
        MessageBody::Ack(_) => "ack",
        MessageBody::StreamChunk(chunk) if chunk.kind == StreamChunkKind::Done => "done",
        MessageBody::StreamChunk(_) => "chunk",
        MessageBody::ActionResult(_) => "result",
        MessageBody::DelegationRequest(_) => "delegation_request",
        MessageBody::DelegationResult(_) => "delegation_result",
        MessageBody::Heartbeat(_) => "heartbeat",
        MessageBody::HeartbeatAck(_) => "heartbeat_ack",
        MessageBody::Error(_) => "error",
        _ => "message",
    };
    let data = serde_json::to_string(envelope)
        .map_err(|error| TransportError::Codec(error.to_string()))?;
    Ok(SseEvent {
        event: event.to_owned(),
        id,
        data,
        retry_ms: None,
    })
}

/// Decodes an SSE event data payload into an AIP envelope.
pub fn decode_sse(event: &SseEvent) -> TransportResult<Envelope> {
    serde_json::from_str(&event.data).map_err(|error| TransportError::Codec(error.to_string()))
}

/// Returns true when an envelope terminates an SSE stream.
#[must_use]
pub fn is_terminal_event(envelope: &Envelope) -> bool {
    match &envelope.body {
        MessageBody::StreamChunk(chunk) => chunk.kind == StreamChunkKind::Done,
        MessageBody::ActionResult(_) | MessageBody::DelegationResult(_) | MessageBody::Error(_) => {
            true
        }
        _ => false,
    }
}

/// In-memory SSE stream state.
#[derive(Clone, Debug, Default)]
pub struct SseStreamState {
    messages: Vec<TransportMessage>,
    closed: bool,
}

impl SseStreamState {
    /// Appends a message and marks the stream closed if it is terminal.
    pub fn push(&mut self, message: TransportMessage) {
        self.closed = self.closed || is_terminal_event(&message.envelope);
        self.messages.push(message);
    }

    /// Returns true after a terminal event has been appended.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns rendered SSE events after the supplied cursor.
    pub fn events_since(&self, cursor: Option<SseCursor>) -> TransportResult<Vec<SseEvent>> {
        let start = cursor.map_or(0, |cursor| cursor.index().saturating_add(1));
        self.messages
            .iter()
            .enumerate()
            .skip(start)
            .map(|(index, message)| {
                encode_sse_with_id(
                    &message.envelope,
                    Some(SseCursor::from_index(index).to_string()),
                )
            })
            .collect()
    }
}

/// Framework-neutral SSE transport backed by in-memory correlation streams.
#[derive(Clone, Debug, Default)]
pub struct SseTransport {
    streams: Arc<RwLock<HashMap<CorrelationId, SseStreamState>>>,
}

impl SseTransport {
    /// Creates an empty SSE transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes a message to an explicit correlation stream.
    pub async fn publish_to(
        &self,
        correlation_id: CorrelationId,
        message: TransportMessage,
    ) -> TransportResult<()> {
        self.streams
            .write()
            .await
            .entry(correlation_id)
            .or_default()
            .push(message);
        Ok(())
    }

    /// Returns rendered events after the cursor for a correlation stream.
    pub async fn events_since(
        &self,
        correlation_id: &CorrelationId,
        cursor: Option<SseCursor>,
    ) -> TransportResult<Vec<SseEvent>> {
        self.streams
            .read()
            .await
            .get(correlation_id)
            .map_or_else(|| Ok(Vec::new()), |stream| stream.events_since(cursor))
    }

    /// Returns true when the correlation stream has received a terminal event.
    pub async fn is_closed(&self, correlation_id: &CorrelationId) -> bool {
        self.streams
            .read()
            .await
            .get(correlation_id)
            .is_some_and(SseStreamState::is_closed)
    }
}

#[async_trait]
impl Transport for SseTransport {
    async fn publish(&self, message: TransportMessage) -> TransportResult<()> {
        let correlation_id =
            message
                .envelope
                .correlation_id
                .clone()
                .ok_or(TransportError::Unsupported(
                    "SSE publish requires envelope.correlation_id",
                ))?;
        self.publish_to(correlation_id, message).await
    }
}

#[async_trait]
impl StreamingTransport for SseTransport {
    async fn subscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()> {
        self.streams
            .write()
            .await
            .entry(correlation_id.clone())
            .or_default();
        Ok(())
    }

    async fn unsubscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()> {
        self.streams.write().await.remove(correlation_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SseCursor, SseTransport, is_terminal_event};
    use aip_core::{
        ActionId, ActionResult, ActionResultStatus, CorrelationId, Envelope, MessageBody,
    };
    use aip_transport::{StreamingTransport, Transport, TransportMessage};

    #[tokio::test]
    async fn stream_uses_reconnect_cursor() {
        let transport = SseTransport::new();
        let correlation_id = CorrelationId::new();
        transport
            .subscribe(&correlation_id)
            .await
            .expect("subscribe");
        for _ in 0..2 {
            let mut envelope = Envelope::new(MessageBody::ActionResult(ActionResult {
                action_id: ActionId::new(),
                status: ActionResultStatus::Completed,
                output: None,
                message: Vec::new(),
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            }));
            envelope.correlation_id = Some(correlation_id.clone());
            transport
                .publish(TransportMessage::new(envelope))
                .await
                .expect("publish");
        }
        let events = transport
            .events_since(&correlation_id, Some(SseCursor::from_index(0)))
            .await
            .expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id.as_deref(), Some("sse_1"));
    }

    #[test]
    fn action_result_is_terminal() {
        let envelope = Envelope::new(MessageBody::ActionResult(ActionResult {
            action_id: ActionId::new(),
            status: ActionResultStatus::Completed,
            output: None,
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        }));
        assert!(is_terminal_event(&envelope));
    }
}
