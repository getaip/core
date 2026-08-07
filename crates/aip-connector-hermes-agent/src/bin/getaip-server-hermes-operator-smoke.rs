//! Isolated-live Hermes router/operator conformance through AIP and MCP.
//!
//! The driver proves both governed operator invocation and connector-owned
//! delegation routing. Business facts are fetched from a real downstream AIP
//! capability; Hermes never receives database credentials.

#![forbid(unsafe_code)]

use aip_core::{
    ActionId, ApprovalDecision, ApprovalDecisionKind, ApprovalId, Envelope, MessageBody, Principal,
    PrincipalId, PrincipalKind,
};
use aip_mcp_client::{McpClient, McpClientConfig, McpHttpClientTransport};
use clap::Parser;
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;

const SUPPORT_CASE_CAPABILITY: &str = "cap:support_sandbox:support.case.get";
const AIP_CALL_TOOL: &str = "aip_call";
const AIP_ACTION_LIST_TOOL: &str = "aip_action_list";
const AIP_ACTION_STATUS_TOOL: &str = "aip_action_status";
const AIP_DELEGATE_TOOL: &str = "aip_delegate";

#[derive(Parser)]
#[command(
    name = "getaip-server-hermes-operator-smoke",
    about = "Validate governed Hermes operator and delegation paths through a deployed AIP stack."
)]
struct Args {
    /// Streamable HTTP MCP endpoint exposed by getaip-server.
    #[arg(long, default_value = "http://127.0.0.1:18080/mcp")]
    mcp_url: String,
    /// Native AIP HTTP base URL used by the independent approver.
    #[arg(long, default_value = "http://127.0.0.1:18080")]
    server_url: Url,
    /// OAuth access token accepted by the protected MCP resource.
    #[arg(long)]
    bearer_token: Option<String>,
    /// Bearer token bound to the independent native approval principal.
    #[arg(long)]
    native_bearer_token: Option<String>,
    /// Hermes endpoint id configured in getaip-server. Repeat for multiple endpoints.
    #[arg(long = "endpoint-id", required = true)]
    endpoint_ids: Vec<String>,
    /// Transport-authenticated human approver principal.
    #[arg(long, default_value = "human:aip-e2e-approver")]
    approver_principal: String,
    /// Downstream case fixture read through AIP.
    #[arg(long, default_value = "case_1001")]
    case_id: String,
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
    let mcp_token = args
        .bearer_token
        .or_else(|| env::var("GETAIP_SERVER_MCP_ACCESS_TOKEN").ok())
        .ok_or_else(|| {
            "MCP bearer token is required through --bearer-token or GETAIP_SERVER_MCP_ACCESS_TOKEN"
                .to_owned()
        })?;
    let native_token = args
        .native_bearer_token
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN").ok())
        .ok_or_else(|| {
            "native approver token is required through --native-bearer-token or GETAIP_SERVER_NATIVE_BEARER_TOKEN"
                .to_owned()
        })?;
    let approver = Principal::new(
        PrincipalId::parse(&args.approver_principal).map_err(|error| error.to_string())?,
        PrincipalKind::Human,
    );

    let mut transport = McpHttpClientTransport::new(&args.mcp_url)
        .map_err(|error| format!("MCP transport setup failed: {error}"))?;
    transport = transport.with_bearer_token(mcp_token);
    let mcp = McpClient::new(
        McpClientConfig::new("getaip-server-hermes-operator-smoke"),
        Arc::new(transport),
    );
    mcp.initialize()
        .await
        .map_err(|error| format!("MCP initialize failed: {error}"))?;
    let tools = mcp
        .list_tools()
        .await
        .map_err(|error| format!("MCP tools/list failed: {error}"))?;
    for required in [
        AIP_CALL_TOOL,
        AIP_ACTION_LIST_TOOL,
        AIP_ACTION_STATUS_TOOL,
        AIP_DELEGATE_TOOL,
    ] {
        if !tools.iter().any(|tool| tool.name == required) {
            return Err(format!(
                "MCP endpoint did not expose stable tool `{required}`"
            ));
        }
    }
    let support_tool = tool_name_by_capability(&tools, SUPPORT_CASE_CAPABILITY)?;
    let expected_result =
        call_mcp_success(&mcp, &support_tool, json!({ "case_id": args.case_id })).await?;
    let expected = ExpectedCase::from_support_output(structured_content(&expected_result)?)?;
    let native = native_http_client(&native_token)?;

    let mut reports = Vec::with_capacity(args.endpoint_ids.len());
    for endpoint_id in &args.endpoint_ids {
        let operator = run_operator(
            &mcp,
            &native,
            &args.server_url,
            endpoint_id,
            &args.case_id,
            &approver,
            &expected,
        )
        .await?;
        let delegation = run_delegation(&mcp, endpoint_id, &args.case_id, &expected).await?;
        reports.push(EndpointReport {
            endpoint_id: endpoint_id.clone(),
            operator,
            delegation,
        });
    }

    print_json(&json!({
        "status": "ok",
        "mcp_url": args.mcp_url,
        "server_url": args.server_url,
        "downstream_capability": SUPPORT_CASE_CAPABILITY,
        "expected_case": expected,
        "endpoints": reports
    }))
}

async fn run_operator(
    mcp: &McpClient,
    native: &Client,
    server_url: &Url,
    endpoint_id: &str,
    case_id: &str,
    approver: &Principal,
    expected: &ExpectedCase,
) -> Result<OperatorReport, String> {
    let before = support_actions(mcp).await?;
    let action_id = ActionId::new();
    let capability_id = format!("cap:hermes_agent:{endpoint_id}:operator");
    let marker = format!("{}_AIP_OPERATOR_OK", endpoint_id.to_ascii_uppercase());
    let objective = format!(
        "Use the authenticated AIP MCP tool aip_call exactly once. Call capability_id {SUPPORT_CASE_CAPABILITY} with input {{\"case_id\":\"{case_id}\"}}. Do not use terminal, code execution, files, memory, web, or any non-AIP data source. Return one compact JSON object with keys agent_marker, case_id, case_status, customer_email, order_id, charge_ids. Set agent_marker to {marker} only after the AIP tool succeeds. Every business value must come from the aip_call result. If the AIP call fails, return a JSON error and do not fabricate values."
    );
    let pending = mcp
        .call_tool(
            AIP_CALL_TOOL,
            json!({
                "action_id": action_id,
                "capability_id": capability_id,
                "idempotency_key": format!("hermes-operator-smoke:{action_id}"),
                "mode": "streaming",
                "input": {
                    "objective": objective,
                    "candidate_capabilities": [SUPPORT_CASE_CAPABILITY],
                    "constraints": {
                        "read_only": true,
                        "required_protocol": "AIP-over-MCP",
                        "forbid_non_aip_sources": true
                    }
                }
            }),
        )
        .await
        .map_err(|error| format!("operator call failed for `{endpoint_id}`: {error}"))?;
    if pending.get("isError").and_then(Value::as_bool) != Some(true)
        || pending
            .pointer("/structuredContent/requires_human_approval")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "operator `{endpoint_id}` did not enter pending approval: {pending}"
        ));
    }
    let request = pending
        .pointer("/structuredContent/approval_request")
        .ok_or_else(|| format!("operator `{endpoint_id}` omitted approval_request"))?;
    let approval_id =
        ApprovalId::parse(required_string(request, "/id")?).map_err(|error| error.to_string())?;
    let request_action_id = required_string(request, "/action_id")?;
    if request_action_id != action_id.as_str() {
        return Err(format!(
            "operator approval action mismatch: expected `{action_id}`, got `{request_action_id}`"
        ));
    }
    let policy_hash = required_string(request, "/policy_hash")?.to_owned();
    let decision = ApprovalDecision {
        approval_id: approval_id.clone(),
        decision: ApprovalDecisionKind::Approved,
        approver: approver.clone(),
        decided_at: OffsetDateTime::now_utc(),
        reason: Some(
            "Approved by the isolated-live Hermes operator conformance driver.".to_owned(),
        ),
        constraints: Vec::new(),
        evidence: Vec::new(),
        decision_id: Some(format!("decision:{approval_id}:operator-smoke")),
        policy_hash: Some(policy_hash),
        authority_path: Vec::new(),
        target_decision_id: None,
    };
    let approval_events =
        send_approval_decision(native, server_url, approver.clone(), decision).await?;
    assert_resume_events(&approval_events, &action_id)?;

    let status_result = call_mcp_success(
        mcp,
        AIP_ACTION_STATUS_TOOL,
        json!({
            "action_id": action_id,
            "include_result": true,
            "include_chunks": true,
            "include_receipts": true
        }),
    )
    .await?;
    let status = status_result
        .pointer("/structuredContent/body/action_status")
        .ok_or_else(|| format!("operator `{endpoint_id}` status response was malformed"))?;
    if status.get("state").and_then(Value::as_str) != Some("completed") {
        return Err(format!(
            "operator `{endpoint_id}` did not complete: {status}"
        ));
    }
    let provider_output = required_string(status, "/result/output/provider/output")?;
    let provider_json = parse_operator_json(provider_output).map_err(|error| {
        format!("operator `{endpoint_id}` returned invalid structured output: {error}")
    })?;
    expected.assert_operator_projection(&provider_json, &marker)?;
    let chunks = status
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("operator `{endpoint_id}` status omitted chunks"))?;
    let tool_started = chunks.iter().any(|chunk| {
        chunk.get("kind").and_then(Value::as_str) == Some("tool")
            && chunk
                .pointer("/data/hermes_operator/event")
                .and_then(Value::as_str)
                == Some("tool.started")
            && chunk
                .pointer("/data/hermes_operator/tool")
                .and_then(Value::as_str)
                == Some("mcp__aip__aip_call")
    });
    let tool_completed = chunks.iter().any(|chunk| {
        chunk.get("kind").and_then(Value::as_str) == Some("tool")
            && chunk
                .pointer("/data/hermes_operator/event")
                .and_then(Value::as_str)
                == Some("tool.completed")
            && chunk
                .pointer("/data/hermes_operator/tool")
                .and_then(Value::as_str)
                == Some("mcp__aip__aip_call")
            && chunk
                .pointer("/data/hermes_operator/error")
                .and_then(Value::as_bool)
                == Some(false)
    });
    if !tool_started || !tool_completed {
        return Err(format!(
            "operator `{endpoint_id}` did not retain a successful AIP MCP tool lifecycle"
        ));
    }
    let after = support_actions(mcp).await?;
    let downstream = new_business_action_ids(&before, &after, case_id, None);
    if downstream.len() != 1 {
        return Err(format!(
            "operator `{endpoint_id}` produced {} downstream business actions; expected exactly one",
            downstream.len()
        ));
    }

    Ok(OperatorReport {
        action_id: action_id.to_string(),
        approval_id: approval_id.to_string(),
        run_id: required_string(status, "/result/output/run_id")?.to_owned(),
        downstream_action_id: downstream[0].clone(),
        chunk_count: chunks.len(),
        aip_tool_started: tool_started,
        aip_tool_completed: tool_completed,
        output: provider_json,
    })
}

async fn run_delegation(
    mcp: &McpClient,
    endpoint_id: &str,
    case_id: &str,
    expected: &ExpectedCase,
) -> Result<DelegationReport, String> {
    let delegate_id = format!("agent:hermes_operator:{endpoint_id}");
    let denied = mcp
        .call_tool(
            AIP_DELEGATE_TOOL,
            json!({
                "delegate_id": delegate_id,
                "scope": "outside.allowed.scope",
                "capability_id": SUPPORT_CASE_CAPABILITY,
                "input": { "case_id": case_id }
            }),
        )
        .await;
    let denied_by_scope = match denied {
        Err(_) => true,
        Ok(result) => {
            result.get("isError").and_then(Value::as_bool) == Some(true)
                || result
                    .pointer("/structuredContent/body/delegation_result/status")
                    .and_then(Value::as_str)
                    == Some("failed")
        }
    };
    if !denied_by_scope {
        return Err(format!(
            "operator router `{endpoint_id}` accepted a delegation outside its scope allowlist"
        ));
    }

    let before = support_actions(mcp).await?;
    let child_action_id = ActionId::new();
    let parent_action_id = ActionId::new();
    let result = call_mcp_success(
        mcp,
        AIP_DELEGATE_TOOL,
        json!({
            "parent_action_id": parent_action_id,
            "action_id": child_action_id,
            "delegate_id": delegate_id,
            "scope": "support.case.read",
            "capability_id": SUPPORT_CASE_CAPABILITY,
            "idempotency_key": format!("hermes-delegation-smoke:{child_action_id}"),
            "mode": "sync",
            "input": { "case_id": case_id },
            "metadata": { "conformance": "hermes-router-isolated-live" }
        }),
    )
    .await?;
    let delegation = result
        .pointer("/structuredContent/body/delegation_result")
        .or_else(|| result.pointer("/structuredContent/body"))
        .ok_or_else(|| {
            format!("delegation response for `{endpoint_id}` was malformed: {result}")
        })?;
    if delegation.get("status").and_then(Value::as_str) != Some("completed") {
        return Err(format!(
            "delegation through `{endpoint_id}` did not complete: {delegation}"
        ));
    }
    if delegation.get("child_action_id").and_then(Value::as_str) != Some(child_action_id.as_str()) {
        return Err(format!(
            "delegation through `{endpoint_id}` returned the wrong child action id"
        ));
    }
    let business_output = delegation
        .pointer("/result/output")
        .ok_or_else(|| format!("delegation through `{endpoint_id}` omitted business output"))?;
    expected.assert_support_output(business_output)?;
    let after = support_actions(mcp).await?;
    let downstream = new_business_action_ids(&before, &after, case_id, None);
    if downstream.len() != 1
        || downstream.first().map(String::as_str) != Some(child_action_id.as_str())
    {
        return Err(format!(
            "delegation through `{endpoint_id}` did not execute exactly the protocol-assigned child action: {downstream:?}"
        ));
    }

    Ok(DelegationReport {
        parent_action_id: parent_action_id.to_string(),
        child_action_id: child_action_id.to_string(),
        downstream_action_id: downstream[0].clone(),
        scope_allowlist_rejection_verified: denied_by_scope,
        business_output: business_output.clone(),
    })
}

async fn support_actions(mcp: &McpClient) -> Result<BTreeMap<String, Value>, String> {
    let result = call_mcp_success(
        mcp,
        AIP_ACTION_LIST_TOOL,
        json!({
            "capability_id": SUPPORT_CASE_CAPABILITY,
            "limit": 1000,
            "include_results": true
        }),
    )
    .await?;
    let actions = result
        .pointer("/structuredContent/body/action_list/actions")
        .and_then(Value::as_array)
        .ok_or_else(|| "AIP action list response omitted actions".to_owned())?;
    Ok(actions
        .iter()
        .filter_map(|action| {
            action
                .get("action_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), action.clone()))
        })
        .collect())
}

fn new_business_action_ids(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    case_id: &str,
    excluded_action_id: Option<&str>,
) -> Vec<String> {
    after
        .iter()
        .filter(|(id, action)| {
            !before.contains_key(*id)
                && excluded_action_id != Some(id.as_str())
                && action
                    .pointer("/result/output/case/case_id")
                    .and_then(Value::as_str)
                    == Some(case_id)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

async fn call_mcp_success(mcp: &McpClient, tool: &str, arguments: Value) -> Result<Value, String> {
    let result = mcp
        .call_tool(tool, arguments)
        .await
        .map_err(|error| format!("MCP tool `{tool}` failed: {error}"))?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(format!("MCP tool `{tool}` returned isError=true: {result}"));
    }
    Ok(result)
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
        .ok_or_else(|| format!("MCP tools/list omitted capability `{capability_id}`"))
}

fn structured_content(result: &Value) -> Result<&Value, String> {
    result
        .get("structuredContent")
        .ok_or_else(|| "MCP result omitted structuredContent".to_owned())
}

fn native_http_client(token: &str) -> Result<Client, String> {
    let mut headers = HeaderMap::new();
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|error| format!("invalid native bearer token: {error}"))?;
    authorization.set_sensitive(true);
    headers.insert(AUTHORIZATION, authorization);
    Client::builder()
        .default_headers(headers)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(1_200))
        .build()
        .map_err(|error| error.to_string())
}

async fn send_approval_decision(
    client: &Client,
    server_url: &Url,
    actor: Principal,
    decision: ApprovalDecision,
) -> Result<Value, String> {
    let mut envelope = Envelope::new(MessageBody::ApprovalDecision(Box::new(decision)));
    envelope.from = Some(actor);
    let url = server_url
        .join("/aip/v1/messages")
        .map_err(|error| error.to_string())?;
    let response = client
        .post(url)
        .json(&envelope)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "approval decision failed with HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    match envelope.body {
        MessageBody::EventStream(stream) => {
            serde_json::to_value(stream).map_err(|error| error.to_string())
        }
        MessageBody::Error(error) => Err(error.error.message),
        other => Err(format!(
            "approval decision returned `{}`",
            other.message_type().as_str()
        )),
    }
}

fn assert_resume_events(events: &Value, action_id: &ActionId) -> Result<(), String> {
    let events = events
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| "approval response omitted events".to_owned())?;
    let granted = events.iter().any(|event| {
        event.get("kind").and_then(Value::as_str) == Some("aip.approval.granted")
            && event.get("action_id").and_then(Value::as_str) == Some(action_id.as_str())
    });
    let resumed = events.iter().any(|event| {
        event.get("kind").and_then(Value::as_str) == Some("aip.action.resumed_result")
            && event.get("action_id").and_then(Value::as_str) == Some(action_id.as_str())
            && event.pointer("/data/status").and_then(Value::as_str) == Some("completed")
    });
    if granted && resumed {
        Ok(())
    } else {
        Err(format!(
            "approval did not emit granted and completed resume events for `{action_id}`"
        ))
    }
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string at JSON pointer `{pointer}`"))
}

fn parse_operator_json(raw: &str) -> Result<Value, String> {
    let trimmed = raw.trim();
    if let Ok(value) = serde_json::from_str(trimmed) {
        return Ok(value);
    }
    let fenced = trimmed
        .strip_prefix("```json\n")
        .and_then(|value| value.strip_suffix("\n```"))
        .ok_or_else(|| {
            "expected one JSON value or one exact `json` Markdown fence without surrounding prose"
                .to_owned()
        })?;
    serde_json::from_str(fenced).map_err(|error| error.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ExpectedCase {
    case_id: String,
    case_status: String,
    customer_email: String,
    order_id: String,
    charge_ids: BTreeSet<String>,
}

impl ExpectedCase {
    fn from_support_output(output: &Value) -> Result<Self, String> {
        let case = output
            .get("case")
            .ok_or_else(|| "support result omitted case".to_owned())?;
        let charge_ids = case
            .get("charges")
            .and_then(Value::as_array)
            .ok_or_else(|| "support result omitted charges".to_owned())?
            .iter()
            .map(|charge| required_string(charge, "/charge_id").map(ToOwned::to_owned))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            case_id: required_string(case, "/case_id")?.to_owned(),
            case_status: required_string(case, "/case_status")?.to_owned(),
            customer_email: required_string(case, "/email")?.to_owned(),
            order_id: case
                .get("orders")
                .and_then(Value::as_array)
                .and_then(|orders| orders.first())
                .ok_or_else(|| "support result omitted first order".to_owned())
                .and_then(|order| required_string(order, "/order_id"))?
                .to_owned(),
            charge_ids,
        })
    }

    fn assert_operator_projection(&self, output: &Value, marker: &str) -> Result<(), String> {
        let charges = output
            .get("charge_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| "operator output omitted charge_ids".to_owned())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| "operator charge_ids must contain strings".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let matches = output.get("agent_marker").and_then(Value::as_str) == Some(marker)
            && output.get("case_id").and_then(Value::as_str) == Some(self.case_id.as_str())
            && output.get("case_status").and_then(Value::as_str) == Some(self.case_status.as_str())
            && output.get("customer_email").and_then(Value::as_str)
                == Some(self.customer_email.as_str())
            && output.get("order_id").and_then(Value::as_str) == Some(self.order_id.as_str())
            && charges == self.charge_ids;
        if matches {
            Ok(())
        } else {
            Err(format!(
                "operator output did not match downstream AIP facts: {output}"
            ))
        }
    }

    fn assert_support_output(&self, output: &Value) -> Result<(), String> {
        let actual = Self::from_support_output(output)?;
        if &actual == self {
            Ok(())
        } else {
            Err(format!(
                "delegated business output differed from downstream AIP facts: {actual:?}"
            ))
        }
    }
}

#[derive(Debug, Serialize)]
struct EndpointReport {
    endpoint_id: String,
    operator: OperatorReport,
    delegation: DelegationReport,
}

#[derive(Debug, Serialize)]
struct OperatorReport {
    action_id: String,
    approval_id: String,
    run_id: String,
    downstream_action_id: String,
    chunk_count: usize,
    aip_tool_started: bool,
    aip_tool_completed: bool,
    output: Value,
}

#[derive(Debug, Serialize)]
struct DelegationReport {
    parent_action_id: String,
    child_action_id: String,
    downstream_action_id: String,
    scope_allowlist_rejection_verified: bool,
    business_output: Value,
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_operator_json;
    use serde_json::json;

    #[test]
    fn operator_json_parser_accepts_only_raw_or_single_exact_fence() {
        assert_eq!(
            parse_operator_json(r#"{"status":"ok"}"#),
            Ok(json!({ "status": "ok" }))
        );
        assert_eq!(
            parse_operator_json("```json\n{\"status\":\"ok\"}\n```"),
            Ok(json!({ "status": "ok" }))
        );
        assert!(parse_operator_json("result: {\"status\":\"ok\"}").is_err());
        assert!(parse_operator_json("```\n{\"status\":\"ok\"}\n```").is_err());
    }
}
