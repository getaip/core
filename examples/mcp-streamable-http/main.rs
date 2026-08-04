//! MCP Streamable HTTP SSE framing example.

use aip::profile::mcp::{JsonRpcNotification, McpMethod};
use aip::transport::mcp_streamable_http::{
    McpSseEvent, decode_sse_event, encode_json_rpc_sse_event,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let notification = JsonRpcNotification::new(
        McpMethod::ServerDiscover,
        Some(json!({
            "protocol": aip::profile::mcp::PROFILE_ID,
            "endpoints": {
                "jsonrpc": "/mcp",
                "stream": "/mcp"
            }
        })),
    );
    let value = serde_json::to_value(notification)?;
    let encoded = encode_json_rpc_sse_event(Some("event-1"), Some("message"), &value)?;
    let decoded: McpSseEvent = decode_sse_event(&encoded)?;

    println!("{}", encoded);
    println!("{}", serde_json::to_string_pretty(&decoded)?);
    Ok(())
}
