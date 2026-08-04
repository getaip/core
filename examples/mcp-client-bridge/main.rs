//! Outbound MCP client bridge example.

use aip::connector::Connector;
use aip::mcp::client::{InMemoryMcpTransport, McpClient, McpClientConfig, McpClientConnector};
use aip::profile::mcp::McpMethod;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = InMemoryMcpTransport::default();
    transport
        .register_result(
            McpMethod::Initialize,
            json!({
                "protocolVersion": aip::profile::mcp::LATEST_STABLE_PROTOCOL_VERSION,
                "capabilities": { "tools": {}, "resources": {} },
                "serverInfo": { "name": "example-mcp", "version": "1.0.0" }
            }),
        )
        .await;
    transport
        .register_result(
            McpMethod::ToolsList,
            json!({
                "tools": [{
                    "name": "echo",
                    "description": "Echo a JSON object",
                    "inputSchema": { "type": "object" }
                }]
            }),
        )
        .await;
    transport
        .register_result(McpMethod::ResourcesList, json!({ "resources": [] }))
        .await;
    transport
        .register_result(
            McpMethod::ToolsCall,
            json!({
                "content": [{ "type": "text", "text": "echoed" }],
                "structuredContent": { "ok": true }
            }),
        )
        .await;

    let client = McpClient::new(McpClientConfig::new("example"), Arc::new(transport));
    client.initialize().await?;
    let connector = McpClientConnector::new(client);
    let manifest = connector.discover(&Default::default()).await?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
