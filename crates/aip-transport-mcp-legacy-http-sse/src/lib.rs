//! Legacy MCP HTTP+SSE binding for protocol version `2024-11-05`.
//!
//! The binding is framework-neutral. A server opens an SSE session, emits the
//! required `endpoint` event, accepts client JSON-RPC frames through the
//! session-specific POST endpoint, and publishes server frames through a
//! bounded replay log. Newer MCP versions must use Streamable HTTP instead.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_mcp_session::McpFrame;
use aip_profile_mcp::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{RwLock, broadcast};
use url::Url;

/// The only MCP protocol version carried by this legacy binding.
pub const LEGACY_MCP_PROTOCOL_VERSION: &str = "2024-11-05";
/// Legacy SSE endpoint event name.
pub const ENDPOINT_EVENT: &str = "endpoint";
/// Legacy JSON-RPC SSE event name.
pub const MESSAGE_EVENT: &str = "message";

/// Legacy binding error.
#[derive(Debug, Error)]
pub enum LegacyHttpSseError {
    /// Session does not exist or has expired.
    #[error("legacy MCP session `{0}` was not found")]
    SessionNotFound(String),
    /// Session is owned by another authenticated principal.
    #[error("legacy MCP session owner mismatch")]
    OwnerMismatch,
    /// Endpoint URL is invalid.
    #[error("invalid legacy MCP endpoint: {0}")]
    Endpoint(String),
    /// JSON-RPC frame is invalid or exceeds the configured bound.
    #[error("invalid legacy MCP JSON-RPC frame: {0}")]
    Frame(String),
    /// Resume cursor is outside the bounded replay window.
    #[error("legacy MCP replay cursor `{0}` is no longer available")]
    CursorGone(String),
}

/// One SSE event emitted by the legacy binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySseEvent {
    /// Monotonic event id. Endpoint events do not require an id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// SSE event name.
    pub event: String,
    /// Event data.
    pub data: String,
}

impl LegacySseEvent {
    /// Encodes the event as one SSE frame.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut frame = String::new();
        if let Some(id) = &self.id {
            frame.push_str("id: ");
            frame.push_str(id);
            frame.push('\n');
        }
        frame.push_str("event: ");
        frame.push_str(&self.event);
        frame.push('\n');
        for line in self.data.lines() {
            frame.push_str("data: ");
            frame.push_str(line);
            frame.push('\n');
        }
        frame.push('\n');
        frame
    }
}

/// Open legacy SSE session returned to an HTTP adapter.
pub struct LegacySessionOpen {
    /// Opaque session id carried by the POST endpoint.
    pub session_id: String,
    /// Mandatory first SSE event containing the POST endpoint.
    pub endpoint_event: LegacySseEvent,
    /// Live event receiver.
    pub receiver: broadcast::Receiver<LegacySseEvent>,
}

/// Replay snapshot and live receiver acquired without a publication gap.
pub struct LegacySubscription {
    /// Events after the requested cursor.
    pub replay: Vec<LegacySseEvent>,
    /// Live events published after the snapshot.
    pub receiver: broadcast::Receiver<LegacySseEvent>,
}

#[derive(Clone, Debug)]
struct LegacySession {
    owner: String,
    expires_at: OffsetDateTime,
    next_sequence: u64,
    replay: Vec<LegacySseEvent>,
    sender: broadcast::Sender<LegacySseEvent>,
}

/// Isolated legacy MCP session registry with bounded replay.
#[derive(Clone, Debug)]
pub struct LegacySessionRegistry {
    sessions: Arc<RwLock<BTreeMap<String, LegacySession>>>,
    replay_capacity: usize,
    channel_capacity: usize,
    session_ttl_ms: u64,
    max_frame_bytes: usize,
}

impl Default for LegacySessionRegistry {
    fn default() -> Self {
        Self::new(1_024, 1_024, 3_600_000, 8 * 1024 * 1024)
    }
}

impl LegacySessionRegistry {
    /// Creates a registry with explicit replay, channel, lifetime, and frame
    /// bounds.
    #[must_use]
    pub fn new(
        replay_capacity: usize,
        channel_capacity: usize,
        session_ttl_ms: u64,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            sessions: Arc::default(),
            replay_capacity: replay_capacity.max(1),
            channel_capacity: channel_capacity.max(1),
            session_ttl_ms: session_ttl_ms.max(1),
            max_frame_bytes: max_frame_bytes.max(1),
        }
    }

    /// Opens one authenticated legacy session and creates its endpoint event.
    pub async fn open_session(
        &self,
        owner: impl Into<String>,
        message_endpoint: &str,
    ) -> Result<LegacySessionOpen, LegacyHttpSseError> {
        let session_id = random_session_id();
        let mut endpoint = Url::parse(message_endpoint)
            .map_err(|error| LegacyHttpSseError::Endpoint(error.to_string()))?;
        endpoint
            .query_pairs_mut()
            .append_pair("sessionId", &session_id);
        let (sender, receiver) = broadcast::channel(self.channel_capacity);
        let now = OffsetDateTime::now_utc();
        self.sessions.write().await.insert(
            session_id.clone(),
            LegacySession {
                owner: owner.into(),
                expires_at: now
                    + time::Duration::milliseconds(self.session_ttl_ms.min(i64::MAX as u64) as i64),
                next_sequence: 1,
                replay: Vec::new(),
                sender,
            },
        );
        Ok(LegacySessionOpen {
            session_id,
            endpoint_event: LegacySseEvent {
                id: None,
                event: ENDPOINT_EVENT.to_owned(),
                data: endpoint.to_string(),
            },
            receiver,
        })
    }

    /// Validates and decodes one client frame posted to a session endpoint.
    pub async fn accept_client_frame(
        &self,
        session_id: &str,
        owner: &str,
        bytes: &[u8],
    ) -> Result<McpFrame, LegacyHttpSseError> {
        self.authorize(session_id, owner).await?;
        if bytes.len() > self.max_frame_bytes {
            return Err(LegacyHttpSseError::Frame(format!(
                "frame exceeds {} bytes",
                self.max_frame_bytes
            )));
        }
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| LegacyHttpSseError::Frame(error.to_string()))?;
        decode_json_rpc_frame(value)
    }

    /// Publishes one server frame to the session replay log and live stream.
    pub async fn publish_server_frame(
        &self,
        session_id: &str,
        owner: &str,
        frame: &McpFrame,
    ) -> Result<LegacySseEvent, LegacyHttpSseError> {
        let data = match frame {
            McpFrame::Request(value) => serde_json::to_string(value),
            McpFrame::Notification(value) => serde_json::to_string(value),
            McpFrame::Response(value) => serde_json::to_string(value),
        }
        .map_err(|error| LegacyHttpSseError::Frame(error.to_string()))?;
        if data.len() > self.max_frame_bytes {
            return Err(LegacyHttpSseError::Frame(format!(
                "frame exceeds {} bytes",
                self.max_frame_bytes
            )));
        }
        let mut sessions = self.sessions.write().await;
        let session = live_session_mut(&mut sessions, session_id, owner)?;
        let event = LegacySseEvent {
            id: Some(session.next_sequence.to_string()),
            event: MESSAGE_EVENT.to_owned(),
            data,
        };
        session.next_sequence = session.next_sequence.saturating_add(1);
        session.replay.push(event.clone());
        if session.replay.len() > self.replay_capacity {
            let overflow = session.replay.len() - self.replay_capacity;
            session.replay.drain(..overflow);
        }
        let _ = session.sender.send(event.clone());
        Ok(event)
    }

    /// Acquires replay and a live receiver atomically with publication.
    pub async fn subscribe(
        &self,
        session_id: &str,
        owner: &str,
        last_event_id: Option<&str>,
    ) -> Result<LegacySubscription, LegacyHttpSseError> {
        let mut sessions = self.sessions.write().await;
        let session = live_session_mut(&mut sessions, session_id, owner)?;
        let replay = match last_event_id {
            None => session.replay.clone(),
            Some(cursor) => {
                let cursor = cursor.parse::<u64>().map_err(|_| {
                    LegacyHttpSseError::Frame("Last-Event-ID must be numeric".to_owned())
                })?;
                let earliest = session
                    .replay
                    .first()
                    .and_then(|event| event.id.as_deref())
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(session.next_sequence);
                if cursor.saturating_add(1) < earliest {
                    return Err(LegacyHttpSseError::CursorGone(cursor.to_string()));
                }
                session
                    .replay
                    .iter()
                    .filter(|event| {
                        event
                            .id
                            .as_deref()
                            .and_then(|id| id.parse::<u64>().ok())
                            .is_some_and(|id| id > cursor)
                    })
                    .cloned()
                    .collect()
            }
        };
        Ok(LegacySubscription {
            replay,
            receiver: session.sender.subscribe(),
        })
    }

    /// Closes a session only for its authenticated owner.
    pub async fn close_session(
        &self,
        session_id: &str,
        owner: &str,
    ) -> Result<(), LegacyHttpSseError> {
        self.authorize(session_id, owner).await?;
        self.sessions.write().await.remove(session_id);
        Ok(())
    }

    async fn authorize(&self, session_id: &str, owner: &str) -> Result<(), LegacyHttpSseError> {
        let mut sessions = self.sessions.write().await;
        let _ = live_session_mut(&mut sessions, session_id, owner)?;
        Ok(())
    }
}

fn live_session_mut<'a>(
    sessions: &'a mut BTreeMap<String, LegacySession>,
    session_id: &str,
    owner: &str,
) -> Result<&'a mut LegacySession, LegacyHttpSseError> {
    let expired = sessions
        .get(session_id)
        .is_some_and(|session| session.expires_at <= OffsetDateTime::now_utc());
    if expired {
        sessions.remove(session_id);
        return Err(LegacyHttpSseError::SessionNotFound(session_id.to_owned()));
    }
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| LegacyHttpSseError::SessionNotFound(session_id.to_owned()))?;
    if session.owner != owner {
        return Err(LegacyHttpSseError::OwnerMismatch);
    }
    Ok(session)
}

fn random_session_id() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_json_rpc_frame(value: Value) -> Result<McpFrame, LegacyHttpSseError> {
    let object = value
        .as_object()
        .ok_or_else(|| LegacyHttpSseError::Frame("JSON-RPC frame must be an object".to_owned()))?;
    match (object.contains_key("method"), object.contains_key("id")) {
        (true, true) => serde_json::from_value::<JsonRpcRequest>(value)
            .map(McpFrame::Request)
            .map_err(|error| LegacyHttpSseError::Frame(error.to_string())),
        (true, false) => serde_json::from_value::<JsonRpcNotification>(value)
            .map(McpFrame::Notification)
            .map_err(|error| LegacyHttpSseError::Frame(error.to_string())),
        (false, true) => serde_json::from_value::<JsonRpcResponse>(value)
            .map(McpFrame::Response)
            .map_err(|error| LegacyHttpSseError::Frame(error.to_string())),
        (false, false) => Err(LegacyHttpSseError::Frame(
            "JSON-RPC frame has neither method nor id".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{ENDPOINT_EVENT, LegacySessionRegistry, MESSAGE_EVENT};
    use aip_mcp_session::McpFrame;
    use aip_profile_mcp::{JsonRpcRequest, JsonRpcResponse, McpMethod};
    use serde_json::json;

    #[tokio::test]
    async fn endpoint_replay_and_owner_binding_are_isolated() {
        let registry = LegacySessionRegistry::new(2, 8, 60_000, 64 * 1024);
        let opened = registry
            .open_session("principal:a", "https://gateway.example/mcp/messages")
            .await
            .expect("open session");
        assert_eq!(opened.endpoint_event.event, ENDPOINT_EVENT);
        assert!(opened.endpoint_event.data.contains("sessionId="));
        let response =
            McpFrame::Response(JsonRpcResponse::success(json!(1), json!({ "ok": true })));
        let event = registry
            .publish_server_frame(&opened.session_id, "principal:a", &response)
            .await
            .expect("publish");
        assert_eq!(event.event, MESSAGE_EVENT);
        let subscription = registry
            .subscribe(&opened.session_id, "principal:a", Some("0"))
            .await
            .expect("subscribe");
        assert_eq!(subscription.replay, vec![event]);
        assert!(
            registry
                .subscribe(&opened.session_id, "principal:b", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn client_requests_and_responses_decode_bidirectionally() {
        let registry = LegacySessionRegistry::default();
        let opened = registry
            .open_session("principal:a", "https://gateway.example/mcp/messages")
            .await
            .expect("open session");
        let request = JsonRpcRequest::new(json!(7), McpMethod::Ping, None);
        let request_bytes = serde_json::to_vec(&request).expect("encode request");
        assert!(matches!(
            registry
                .accept_client_frame(&opened.session_id, "principal:a", &request_bytes)
                .await
                .expect("request"),
            McpFrame::Request(_)
        ));
        let response = JsonRpcResponse::success(json!(9), json!({}));
        let response_bytes = serde_json::to_vec(&response).expect("encode response");
        assert!(matches!(
            registry
                .accept_client_frame(&opened.session_id, "principal:a", &response_bytes)
                .await
                .expect("response"),
            McpFrame::Response(_)
        ));
    }
}
