//! MCP compatibility bridge example.

use aip::profile::mcp;
use aip_testkit::manifest;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tools = mcp::tools_list_result(&manifest());
    println!("{}", serde_json::to_string_pretty(&tools)?);

    let action = mcp::action_from_tools_call(&mcp::JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!(1),
        method: "tools/call".to_owned(),
        params: Some(json!({
            "name": "echo",
            "arguments": { "text": "hello through MCP" }
        })),
    })?;
    println!("{}", serde_json::to_string_pretty(&action)?);
    Ok(())
}
