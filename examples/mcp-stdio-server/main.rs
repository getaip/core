//! MCP stdio server framing example.
//!
//! The example renders one newline-delimited JSON-RPC request frame that can be
//! sent to `getaip-server --mcp-stdio` or to `getaip mcp serve-stdio`.

use aip::profile::mcp::{
    ClientCapabilities, JsonRpcRequest, LATEST_STABLE_PROTOCOL_VERSION, McpMethod,
};
use aip::transport::mcp_stdio::{McpStdioFrame, encode_frame};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!(1),
        method: McpMethod::Initialize.as_str().to_owned(),
        params: Some(json!({
            "protocolVersion": LATEST_STABLE_PROTOCOL_VERSION,
            "capabilities": ClientCapabilities::default(),
            "clientInfo": {
                "name": "stdio-example-host",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
    };
    let frame = McpStdioFrame::Request(request);
    let encoded = encode_frame(&frame)?;
    print!("{}", String::from_utf8(encoded)?);
    Ok(())
}
