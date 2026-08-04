//! AIP daemon as an MCP Streamable HTTP server.
//!
//! This example prints the canonical MCP endpoints and an `initialize` request
//! that any MCP host can send to a running `getaip-server` process.

use aip::profile::mcp::{
    ClientCapabilities, JsonRpcRequest, LATEST_STABLE_PROTOCOL_VERSION, McpMethod,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let initialize = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!("init-1"),
        method: McpMethod::Initialize.as_str().to_owned(),
        params: Some(json!({
            "protocolVersion": LATEST_STABLE_PROTOCOL_VERSION,
            "capabilities": ClientCapabilities {
                roots: None,
                sampling: Some(json!({})),
                elicitation: Some(json!({})),
                tasks: Some(json!({})),
                experimental: None,
            },
            "clientInfo": {
                "name": "aip-example-host",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
    };

    println!("Start getaip-server:");
    println!(
        "cargo run -p getaip-server -- --bind 127.0.0.1:8080 --mcp-bearer-token local-dev-token"
    );
    println!();
    println!("MCP endpoints:");
    println!("POST http://127.0.0.1:8080/mcp");
    println!("GET  http://127.0.0.1:8080/mcp");
    println!("GET  http://127.0.0.1:8080/.well-known/oauth-protected-resource");
    println!();
    println!("{}", serde_json::to_string_pretty(&initialize)?);
    Ok(())
}
