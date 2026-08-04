//! Production daemon smoke check for Hermes Agent through the AIP MCP profile.
//!
//! This binary validates the deployed path used by MCP hosts:
//! MCP client -> `getaip-server` Streamable HTTP MCP -> AIP gateway/runtime ->
//! Hermes connector -> Hermes Agent -> model backend.

#![forbid(unsafe_code)]

use aip_mcp_client::{McpClient, McpClientConfig, McpHttpClientTransport};
use clap::Parser;
use serde::Serialize;
use serde_json::{Value, json};
use std::{process::ExitCode, sync::Arc};

#[derive(Debug, Parser)]
#[command(
    name = "getaip-server-hermes-mcp-smoke",
    about = "Validate Hermes Agent health and chat through a deployed getaip-server MCP endpoint."
)]
struct Args {
    /// Streamable HTTP MCP URL exposed by the deployed AIP daemon.
    #[arg(long = "mcp-url", default_value = "http://127.0.0.1:18080/mcp")]
    mcp_url: String,
    /// Hermes endpoint id configured in getaip-server, for example `hermes-1`.
    #[arg(long = "endpoint-id", required = true)]
    endpoint_ids: Vec<String>,
    /// Optional bearer token enforced by the deployed MCP endpoint.
    #[arg(long = "bearer-token")]
    bearer_token: Option<String>,
    /// Optional model id passed through Hermes. Omit to use the Hermes default.
    #[arg(long)]
    model: Option<String>,
    /// Prompt template. `{endpoint_id}` is replaced per endpoint.
    #[arg(
        long,
        default_value = "Reply exactly with {endpoint_id}_MCP_PATH_OK and nothing else."
    )]
    prompt: String,
    /// Validate that the returned text exactly matches the expected marker.
    #[arg(long, default_value_t = true)]
    require_exact_content: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    let mut transport = McpHttpClientTransport::new(&args.mcp_url)
        .map_err(|error| format!("MCP transport setup failed: {error}"))?;
    if let Some(token) = &args.bearer_token {
        transport = transport.with_bearer_token(token);
    }
    let client = McpClient::new(
        McpClientConfig::new("getaip-server-hermes-mcp-smoke"),
        Arc::new(transport),
    );
    client
        .initialize()
        .await
        .map_err(|error| format!("MCP initialize failed: {error}"))?;
    let tools = client
        .list_tools()
        .await
        .map_err(|error| format!("MCP tools/list failed: {error}"))?;
    validate_tool_names(&tools)?;

    let mut endpoint_reports = Vec::with_capacity(args.endpoint_ids.len());
    for endpoint_id in &args.endpoint_ids {
        endpoint_reports.push(
            run_endpoint_check(
                &client,
                &tools,
                endpoint_id,
                args.model.as_deref(),
                &args.prompt,
                args.require_exact_content,
            )
            .await?,
        );
    }

    let report = json!({
        "status": "ok",
        "mcp_url": args.mcp_url,
        "tool_count": tools.len(),
        "model": args.model,
        "endpoints": endpoint_reports
    });
    let rendered = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

async fn run_endpoint_check(
    client: &McpClient,
    tools: &[aip_profile_mcp::McpTool],
    endpoint_id: &str,
    model: Option<&str>,
    prompt_template: &str,
    require_exact_content: bool,
) -> Result<EndpointReport, String> {
    let health_capability_id = capability_id(endpoint_id, "health");
    let chat_capability_id = capability_id(endpoint_id, "chat");
    let health_tool = tool_name_by_capability(tools, &health_capability_id)?;
    let chat_tool = tool_name_by_capability(tools, &chat_capability_id)?;

    let health_result = client
        .call_tool(&health_tool, json!({}))
        .await
        .map_err(|error| format!("MCP health call failed for `{endpoint_id}`: {error}"))?;
    let health = parse_health(endpoint_id, &health_result)?;

    let prompt = prompt_template.replace("{endpoint_id}", endpoint_id);
    let expected_content = expected_content_from_prompt(endpoint_id, &prompt);
    let mut chat_input = json!({
        "prompt": prompt,
        "temperature": 0,
        "max_tokens": 16
    });
    if let Some(model) = model {
        chat_input["model"] = json!(model);
    }
    let chat_result = client
        .call_tool(&chat_tool, chat_input)
        .await
        .map_err(|error| format!("MCP chat call failed for `{endpoint_id}`: {error}"))?;
    let chat = parse_chat(
        endpoint_id,
        &chat_result,
        &expected_content,
        require_exact_content,
    )?;

    Ok(EndpointReport {
        endpoint_id: endpoint_id.to_owned(),
        health_tool,
        chat_tool,
        health,
        chat,
    })
}

fn validate_tool_names(tools: &[aip_profile_mcp::McpTool]) -> Result<(), String> {
    if tools.is_empty() {
        return Err("MCP tools/list returned no tools".to_owned());
    }
    let invalid = tools
        .iter()
        .filter(|tool| !is_safe_tool_name(&tool.name))
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "MCP tools/list returned tool names that are unsafe for MCP hosts: {}",
            invalid.join(", ")
        ))
    }
}

fn is_safe_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn tool_name_by_capability(
    tools: &[aip_profile_mcp::McpTool],
    capability_id: &str,
) -> Result<String, String> {
    tools
        .iter()
        .find(|tool| {
            tool.meta
                .as_ref()
                .and_then(|meta| meta.get("org.getaip/aip"))
                .and_then(|meta| meta.get("capability_id"))
                .and_then(Value::as_str)
                == Some(capability_id)
        })
        .map(|tool| tool.name.clone())
        .ok_or_else(|| format!("MCP tools/list did not expose capability `{capability_id}`"))
}

fn parse_health(endpoint_id: &str, result: &Value) -> Result<HealthReport, String> {
    ensure_mcp_success(endpoint_id, "health", result)?;
    let structured = structured_content(endpoint_id, "health", result)?;
    let reported_endpoint = structured
        .get("endpoint_id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("health result for `{endpoint_id}` did not include endpoint_id"))?;
    if reported_endpoint != endpoint_id {
        return Err(format!(
            "health result endpoint mismatch: expected `{endpoint_id}`, got `{reported_endpoint}`"
        ));
    }
    let status = structured
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("health result for `{endpoint_id}` did not include status"))?;
    if status != "ok" {
        return Err(format!(
            "health result for `{endpoint_id}` returned status `{status}`"
        ));
    }
    Ok(HealthReport {
        endpoint_id: endpoint_id.to_owned(),
        status: status.to_owned(),
        platform: structured
            .get("platform")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        version: structured
            .get("version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        http_status: structured.get("http_status").and_then(Value::as_u64),
    })
}

fn parse_chat(
    endpoint_id: &str,
    result: &Value,
    expected_content: &str,
    require_exact_content: bool,
) -> Result<ChatReport, String> {
    ensure_mcp_success(endpoint_id, "chat", result)?;
    let content = text_content(result)
        .ok_or_else(|| format!("chat result for `{endpoint_id}` did not include text content"))?;
    let content_matches = if require_exact_content {
        content.trim() == expected_content
    } else {
        content.contains(expected_content)
    };
    if !content_matches {
        return Err(format!(
            "chat result for `{endpoint_id}` returned unexpected content `{content}`; expected `{expected_content}`"
        ));
    }
    let structured = structured_content(endpoint_id, "chat", result)?;
    Ok(ChatReport {
        expected_content: expected_content.to_owned(),
        content,
        model: structured
            .get("model")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        usage: structured.get("usage").cloned(),
    })
}

fn ensure_mcp_success(endpoint_id: &str, operation: &str, result: &Value) -> Result<(), String> {
    if result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(format!(
            "{operation} MCP tool call for `{endpoint_id}` returned isError=true: {result}"
        ));
    }
    Ok(())
}

fn structured_content<'a>(
    endpoint_id: &str,
    operation: &str,
    result: &'a Value,
) -> Result<&'a Value, String> {
    result.get("structuredContent").ok_or_else(|| {
        format!("{operation} MCP tool call for `{endpoint_id}` did not include structuredContent")
    })
}

fn text_content(result: &Value) -> Option<String> {
    result
        .get("content")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|block| {
            (block.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| {
                    block
                        .get("text")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .flatten()
        })
}

fn capability_id(endpoint_id: &str, operation: &str) -> String {
    format!("cap:hermes_agent:{endpoint_id}:{operation}")
}

fn expected_content_from_prompt(endpoint_id: &str, prompt: &str) -> String {
    prompt
        .strip_prefix("Reply exactly with ")
        .and_then(|value| value.strip_suffix(" and nothing else."))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{endpoint_id}_MCP_PATH_OK"))
}

#[derive(Debug, Serialize)]
struct EndpointReport {
    endpoint_id: String,
    health_tool: String,
    chat_tool: String,
    health: HealthReport,
    chat: ChatReport,
}

#[derive(Debug, Serialize)]
struct HealthReport {
    endpoint_id: String,
    status: String,
    platform: Option<String>,
    version: Option<String>,
    http_status: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ChatReport {
    expected_content: String,
    content: String,
    model: Option<String>,
    usage: Option<Value>,
}
