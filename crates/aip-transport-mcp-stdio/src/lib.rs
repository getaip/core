//! MCP stdio transport codec.
//!
//! MCP stdio uses newline-delimited JSON-RPC messages over a subprocess'
//! stdin/stdout streams. This crate intentionally implements the framing and
//! validation rules without owning process spawning so hosts can apply their own
//! sandboxing and lifecycle policy.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_profile_mcp::{JSONRPC_VERSION, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use serde_json::Value;
use thiserror::Error;

/// Error returned by the MCP stdio codec.
#[derive(Debug, Error)]
pub enum McpStdioError {
    /// Frame was not valid UTF-8.
    #[error("stdio frame is not UTF-8: {0}")]
    Utf8(String),
    /// Frame contained embedded line delimiters.
    #[error("stdio frame must be one newline-delimited JSON-RPC message")]
    EmbeddedNewline,
    /// Frame was not valid JSON.
    #[error("stdio frame JSON decode failed: {0}")]
    Json(String),
    /// Frame was valid JSON but not an MCP JSON-RPC message.
    #[error("stdio frame is not an MCP JSON-RPC request, notification, or response")]
    NotJsonRpc,
    /// JSON-RPC version was invalid.
    #[error("invalid JSON-RPC version `{0}`")]
    InvalidJsonRpcVersion(String),
}

/// Result alias for stdio codec operations.
pub type McpStdioResult<T> = Result<T, McpStdioError>;

/// Decoded MCP stdio frame.
#[derive(Clone, Debug, PartialEq)]
pub enum McpStdioFrame {
    /// JSON-RPC request.
    Request(JsonRpcRequest),
    /// JSON-RPC notification.
    Notification(JsonRpcNotification),
    /// JSON-RPC response.
    Response(JsonRpcResponse),
}

impl McpStdioFrame {
    /// Returns true if this frame requires a response.
    #[must_use]
    pub const fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }
}

/// Encodes a frame as one JSON line.
pub fn encode_frame(frame: &McpStdioFrame) -> McpStdioResult<Vec<u8>> {
    let value = match frame {
        McpStdioFrame::Request(request) => serde_json::to_value(request),
        McpStdioFrame::Notification(notification) => serde_json::to_value(notification),
        McpStdioFrame::Response(response) => serde_json::to_value(response),
    }
    .map_err(|error| McpStdioError::Json(error.to_string()))?;
    encode_value(&value)
}

/// Encodes a JSON-RPC value as one JSON line.
pub fn encode_value(value: &Value) -> McpStdioResult<Vec<u8>> {
    let rendered =
        serde_json::to_string(value).map_err(|error| McpStdioError::Json(error.to_string()))?;
    if rendered.contains('\n') || rendered.contains('\r') {
        return Err(McpStdioError::EmbeddedNewline);
    }
    let mut bytes = rendered.into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decodes one newline-delimited JSON-RPC frame.
pub fn decode_frame(bytes: &[u8]) -> McpStdioResult<McpStdioFrame> {
    let line = std::str::from_utf8(bytes)
        .map_err(|error| McpStdioError::Utf8(error.to_string()))?
        .trim_end_matches(['\r', '\n']);
    if line.contains('\n') || line.contains('\r') {
        return Err(McpStdioError::EmbeddedNewline);
    }
    let value = serde_json::from_str::<Value>(line)
        .map_err(|error| McpStdioError::Json(error.to_string()))?;
    decode_value(value)
}

/// Decodes a JSON value into an MCP stdio frame.
pub fn decode_value(value: Value) -> McpStdioResult<McpStdioFrame> {
    let object = value.as_object().ok_or(McpStdioError::NotJsonRpc)?;
    let jsonrpc = object
        .get("jsonrpc")
        .and_then(Value::as_str)
        .ok_or(McpStdioError::NotJsonRpc)?;
    if jsonrpc != JSONRPC_VERSION {
        return Err(McpStdioError::InvalidJsonRpcVersion(jsonrpc.to_owned()));
    }
    if object.get("method").is_some() && object.get("id").is_some() {
        return serde_json::from_value::<JsonRpcRequest>(Value::Object(object.clone()))
            .map(McpStdioFrame::Request)
            .map_err(|error| McpStdioError::Json(error.to_string()));
    }
    if object.get("method").is_some() {
        return serde_json::from_value::<JsonRpcNotification>(Value::Object(object.clone()))
            .map(McpStdioFrame::Notification)
            .map_err(|error| McpStdioError::Json(error.to_string()));
    }
    if object.get("result").is_some() || object.get("error").is_some() {
        return serde_json::from_value::<JsonRpcResponse>(Value::Object(object.clone()))
            .map(McpStdioFrame::Response)
            .map_err(|error| McpStdioError::Json(error.to_string()));
    }
    Err(McpStdioError::NotJsonRpc)
}

/// Splits a byte buffer into complete stdio frames and a trailing partial frame.
pub fn split_complete_frames(buffer: &[u8]) -> (Vec<&[u8]>, &[u8]) {
    let mut frames = Vec::new();
    let mut start = 0;
    for (index, byte) in buffer.iter().enumerate() {
        if *byte == b'\n' {
            frames.push(&buffer[start..=index]);
            start = index + 1;
        }
    }
    (frames, &buffer[start..])
}

#[cfg(test)]
mod tests {
    use super::{McpStdioFrame, decode_frame, encode_frame};
    use aip_profile_mcp::{JsonRpcRequest, McpMethod};
    use serde_json::json;

    #[test]
    fn request_round_trips_as_one_line() {
        let frame = McpStdioFrame::Request(JsonRpcRequest::new(
            json!(1),
            McpMethod::ToolsList,
            Some(json!({})),
        ));
        let encoded = encode_frame(&frame).expect("encoded");
        assert!(encoded.ends_with(b"\n"));
        let decoded = decode_frame(&encoded).expect("decoded");
        assert_eq!(decoded, frame);
    }
}
