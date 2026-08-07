//! MCP sampling and elicitation callback message example.
//!
//! AIP models these MCP client-request methods explicitly so agent runtimes can
//! map LLM sampling to model providers and human elicitation to escalation.

use aip::profile::mcp::{JsonRpcRequest, JsonRpcResponse, McpMethod};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sampling = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!("sample-1"),
        method: McpMethod::SamplingCreateMessage.as_str().to_owned(),
        params: Some(json!({
            "messages": [{
                "role": "user",
                "content": { "type": "text", "text": "Summarize the current AIP task." }
            }],
            "maxTokens": 256
        })),
    };
    let elicitation = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!("elicit-1"),
        method: McpMethod::ElicitationCreate.as_str().to_owned(),
        params: Some(json!({
            "message": "Confirm whether this workflow may call the remote agent.",
            "requestedSchema": {
                "type": "object",
                "required": ["approved"],
                "properties": {
                    "approved": { "type": "boolean" },
                    "reason": { "type": "string" }
                }
            }
        })),
    };
    let completion = JsonRpcResponse::success(
        json!("elicit-1"),
        json!({
            "action": "accept",
            "content": { "approved": true, "reason": "operator approved" }
        }),
    );

    println!("{}", serde_json::to_string_pretty(&sampling)?);
    println!("{}", serde_json::to_string_pretty(&elicitation)?);
    println!("{}", serde_json::to_string_pretty(&completion)?);
    Ok(())
}
