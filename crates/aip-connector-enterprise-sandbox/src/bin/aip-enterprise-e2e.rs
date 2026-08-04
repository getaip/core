//! Deployed AIP end-to-end runner over the stable MCP facade.
//!
//! Every business read and mutation in this runner is issued through MCP
//! Streamable HTTP and the AIP gateway. Direct database access is reserved for
//! external fixture reset and independent post-run verification.

#![forbid(unsafe_code)]

use aip_connector_enterprise_sandbox::{
    ACCESS_COMMIT, ACCESS_GET, ACCESS_PLAN, INCIDENT_COMMIT, INCIDENT_GET, INCIDENT_PLAN,
    PROCUREMENT_COMMIT, PROCUREMENT_GET, PROCUREMENT_PLAN, TRAVEL_COMMIT, TRAVEL_GET, TRAVEL_PLAN,
};
use aip_core::ActionId;
use aip_mcp_client::{McpClient, McpClientConfig, McpHttpClientTransport};
use clap::{Parser, ValueEnum};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use time::OffsetDateTime;

const SUPPORT_CASE_GET: &str = "cap:support_sandbox:support.case.get";
const DUPLICATE_DETECT: &str = "cap:support_sandbox:billing.duplicate_charge.detect";
const REFUND_POLICY: &str = "cap:support_sandbox:refund.policy.evaluate";
const REFUND_PLAN: &str = "cap:support_sandbox:refund.plan";
const PRODUCT_APPROVAL: &str = "cap:support_sandbox:approval.decision.record";
const REFUND_COMMIT: &str = "cap:support_sandbox:refund.commit";
const HERMES_1_CHAT: &str = "cap:hermes_agent:hermes-1:chat";
const HERMES_2_CHAT: &str = "cap:hermes_agent:hermes-2:chat";
const HERMES_1_HEALTH: &str = "cap:hermes_agent:hermes-1:health";
const HERMES_2_HEALTH: &str = "cap:hermes_agent:hermes-2:health";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScenarioSelection {
    All,
    Support,
    SupportReplay,
    Incident,
    Procurement,
    Access,
    Travel,
    Omnichannel,
}

#[derive(Debug, Parser)]
#[command(name = "aip-enterprise-e2e")]
struct Args {
    /// Deployed AIP MCP Streamable HTTP endpoint.
    #[arg(long, default_value = "http://127.0.0.1:18080/mcp")]
    mcp_url: String,
    /// Scenario or complete scenario set to execute.
    #[arg(long, value_enum, default_value = "all")]
    scenario: ScenarioSelection,
    /// Optional bearer token for a protected MCP endpoint.
    #[arg(long)]
    bearer_token: Option<String>,
    /// Bearer token for the distinct human principal that approves governed actions.
    #[arg(long)]
    approver_bearer_token: String,
    /// Stable qualification run identifier reused by support-replay after restart.
    #[arg(long)]
    run_id: Option<String>,
    /// JSON evidence file written atomically after execution.
    #[arg(long, default_value = "artifacts/e2e/latest.json")]
    evidence: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    let run_id = match args.run_id.as_deref() {
        Some(run_id) => validate_run_id(run_id)?,
        None if matches!(args.scenario, ScenarioSelection::SupportReplay) => {
            return Err("--run-id is required for support-replay".to_owned());
        }
        None => ActionId::new().to_string(),
    };
    let client = connect_mcp_client(
        &args.mcp_url,
        args.bearer_token.as_deref(),
        "aip-enterprise-e2e-operator",
    )
    .await?;
    let approver = connect_mcp_client(
        &args.mcp_url,
        Some(&args.approver_bearer_token),
        "aip-enterprise-e2e-approver",
    )
    .await?;
    let manifest = client.refresh_manifest().await.map_err(display)?;
    let started_at = OffsetDateTime::now_utc();
    let mut scenarios = Vec::new();
    match args.scenario {
        ScenarioSelection::All => {
            scenarios.push(scenario_support(&client, &approver, &run_id).await?);
            scenarios.push(scenario_incident(&client, &approver).await?);
            scenarios.push(scenario_procurement(&client, &approver).await?);
            scenarios.push(scenario_access(&client, &approver).await?);
            scenarios.push(scenario_travel(&client, &approver).await?);
            scenarios.push(scenario_omnichannel(&client).await?);
        }
        ScenarioSelection::Support => {
            scenarios.push(scenario_support(&client, &approver, &run_id).await?)
        }
        ScenarioSelection::SupportReplay => {
            scenarios.push(scenario_support_replay(&client, &run_id).await?)
        }
        ScenarioSelection::Incident => scenarios.push(scenario_incident(&client, &approver).await?),
        ScenarioSelection::Procurement => {
            scenarios.push(scenario_procurement(&client, &approver).await?)
        }
        ScenarioSelection::Access => scenarios.push(scenario_access(&client, &approver).await?),
        ScenarioSelection::Travel => scenarios.push(scenario_travel(&client, &approver).await?),
        ScenarioSelection::Omnichannel => scenarios.push(scenario_omnichannel(&client).await?),
    }
    let evidence = json!({
        "status": "completed",
        "transport": "mcp_streamable_http",
        "mcp_url": args.mcp_url,
        "mcp_protocol_version": aip_profile_version(&manifest),
        "run_id": run_id,
        "started_at": started_at,
        "completed_at": OffsetDateTime::now_utc(),
        "scenario_count": scenarios.len(),
        "scenarios": scenarios
    });
    write_evidence(&args.evidence, &evidence).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).map_err(display)?
    );
    Ok(())
}

async fn connect_mcp_client(
    url: &str,
    bearer_token: Option<&str>,
    client_name: &str,
) -> Result<McpClient, String> {
    let mut transport = McpHttpClientTransport::new(url).map_err(display)?;
    if let Some(token) = bearer_token {
        transport = transport.with_bearer_token(token);
    }
    let client = McpClient::new(McpClientConfig::new(client_name), Arc::new(transport));
    client.initialize().await.map_err(display)?;
    Ok(client)
}

async fn scenario_support(
    client: &McpClient,
    approver: &McpClient,
    run_id: &str,
) -> Result<Value, String> {
    let case = call(
        client,
        SUPPORT_CASE_GET,
        json!({ "case_id": "case_1001" }),
        None,
        None,
    )
    .await?;
    let duplicates = call(
        client,
        DUPLICATE_DETECT,
        json!({ "case_id": "case_1001" }),
        None,
        None,
    )
    .await?;
    require(
        duplicates
            .pointer("/duplicate_count")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            > 0,
        "duplicate detector returned no candidates",
    )?;
    let policy = call(
        client,
        REFUND_POLICY,
        json!({ "case_id": "case_1001", "charge_id": "ch_1001_b" }),
        None,
        None,
    )
    .await?;
    require(
        policy
            .get("requires_human_approval")
            .and_then(Value::as_bool)
            == Some(true),
        "refund policy did not require approval",
    )?;
    let key = format!("e2e:support:{run_id}:case_1001:ch_1001_b");
    let plan = call(
        client,
        REFUND_PLAN,
        json!({ "case_id": "case_1001", "charge_id": "ch_1001_b", "reason": "duplicate_charge", "idempotency_key": key }),
        Some(&key),
        None,
    ).await?;
    let refund_id = string_at(&plan, "/refund/refund_id")?;
    let product_approval_id = string_at(&plan, "/refund/approval_request_id")?;
    let product_approval = call(
        client,
        PRODUCT_APPROVAL,
        json!({ "approval_request_id": product_approval_id, "decision": "granted", "reason": "duplicate charge confirmed" }),
        Some(&format!("e2e:product-approval:{product_approval_id}")),
        None,
    ).await?;
    let action_id = ActionId::new().to_string();
    let commit = call_with_action(
        client,
        REFUND_COMMIT,
        json!({ "refund_id": refund_id, "idempotency_key": key }),
        Some(&key),
        None,
        &action_id,
    )
    .await?;
    let approval_id = string_at(&commit, "/approval_id")?;
    let policy_hash = string_at(&commit, "/approval_request/policy_hash")?;
    let resumed = approve(
        approver,
        approval_id,
        "duplicate charge verified",
        &action_id,
        policy_hash,
    )
    .await?;
    let replay = call(
        client,
        REFUND_COMMIT,
        json!({ "refund_id": refund_id, "idempotency_key": key }),
        Some(&key),
        None,
    )
    .await?;
    let final_case = call(
        client,
        SUPPORT_CASE_GET,
        json!({ "case_id": "case_1001" }),
        None,
        None,
    )
    .await?;
    require(
        final_case
            .pointer("/case/case_status")
            .and_then(Value::as_str)
            == Some("resolved"),
        "refund did not resolve the support case",
    )?;
    Ok(json!({
        "id": "01-duplicate-charge-refund",
        "status": "passed",
        "case_before": case,
        "duplicates": duplicates,
        "policy": policy,
        "plan": plan,
        "product_approval": product_approval,
        "aip_approval_id": approval_id,
        "resumed_result": resumed,
        "idempotent_replay": replay,
        "case_after": final_case
    }))
}

async fn scenario_support_replay(client: &McpClient, run_id: &str) -> Result<Value, String> {
    let key = format!("e2e:support:{run_id}:case_1001:ch_1001_b");
    let replay = call(
        client,
        REFUND_COMMIT,
        json!({
            "refund_id": format!("rf:{key}"),
            "idempotency_key": key
        }),
        Some(&key),
        None,
    )
    .await?;
    require(
        replay.get("idempotent_replay").and_then(Value::as_bool) == Some(true),
        "post-restart refund replay was not deduplicated",
    )?;
    Ok(json!({
        "id": "01b-refund-replay-after-daemon-restart",
        "status": "passed",
        "result": replay
    }))
}

async fn scenario_incident(client: &McpClient, approver: &McpClient) -> Result<Value, String> {
    let run_namespace = ActionId::new().to_string();
    let incident = call_identity_read(client, INCIDENT_GET, "inc_5001").await?;
    let h1_health = call(client, HERMES_1_HEALTH, json!({}), None, None).await?;
    let h2_health = call(client, HERMES_2_HEALTH, json!({}), None, None).await?;
    let h1 = call(
        client,
        HERMES_1_CHAT,
        hermes_prompt("Act as incident commander. Produce a concise rollback plan using only these AIP-fetched facts:", &incident),
        Some(&format!("e2e:incident:{run_namespace}:hermes-1")),
        None,
    ).await?;
    let delegation = delegate(
        client,
        "agent:hermes-2",
        HERMES_2_CHAT,
        hermes_prompt(
            "Independently review this incident and identify rollback risks:",
            &incident,
        ),
        &format!("incident:review:{run_namespace}"),
    )
    .await?;
    let plan_key = format!("e2e:incident:{run_namespace}:plan");
    let commit_key = format!("e2e:incident:{run_namespace}:commit");
    let compensate_key = format!("e2e:incident:{run_namespace}:compensate");
    let plan = call_identity(
        client,
        INCIDENT_PLAN,
        json!({ "workflow_id": "inc_5001" }),
        &plan_key,
        json!({ "mode": "execute" }),
    )
    .await?;
    let plan_id = string_at(&plan, "/plan_id")?;
    let action_id = ActionId::new().to_string();
    let pending = call_identity_with_action(
        client,
        INCIDENT_COMMIT,
        json!({ "plan_id": plan_id }),
        &commit_key,
        json!({ "mode": "execute", "plan_id": plan_id }),
        &action_id,
    )
    .await?;
    let approval_id = string_at(&pending, "/approval_id")?;
    let policy_hash = string_at(&pending, "/approval_request/policy_hash")?;
    let committed = approve(
        approver,
        approval_id,
        "SEV1 rollback approved",
        &action_id,
        policy_hash,
    )
    .await?;
    let compensated = compensate(
        client,
        approver,
        INCIDENT_COMMIT,
        plan_id,
        &compensate_key,
        &action_id,
    )
    .await?;
    Ok(
        json!({ "id": "02-incident-response-delegation", "status": "passed", "incident": incident, "hermes_1_health": h1_health, "hermes_2_health": h2_health, "hermes_1_analysis": h1, "delegation": delegation, "plan": plan, "commit": committed, "compensation": compensated }),
    )
}

async fn scenario_procurement(client: &McpClient, approver: &McpClient) -> Result<Value, String> {
    let run_namespace = ActionId::new().to_string();
    let request = call_identity_read(client, PROCUREMENT_GET, "pr_7001").await?;
    let plan_key = format!("e2e:procurement:{run_namespace}:plan");
    let commit_key = format!("e2e:procurement:{run_namespace}:commit");
    let compensate_key = format!("e2e:procurement:{run_namespace}:compensate");
    let plan = call_identity(
        client,
        PROCUREMENT_PLAN,
        json!({ "workflow_id": "pr_7001" }),
        &plan_key,
        json!({ "mode": "execute" }),
    )
    .await?;
    let replay = call_identity(
        client,
        PROCUREMENT_PLAN,
        json!({ "workflow_id": "pr_7001" }),
        &plan_key,
        json!({ "mode": "execute" }),
    )
    .await?;
    require(
        replay.get("idempotent_replay").and_then(Value::as_bool) == Some(true),
        "procurement plan replay was not deduplicated",
    )?;
    let plan_id = string_at(&plan, "/plan_id")?;
    let action_id = ActionId::new().to_string();
    let pending = call_identity_with_action(
        client,
        PROCUREMENT_COMMIT,
        json!({ "plan_id": plan_id }),
        &commit_key,
        json!({ "mode": "execute", "plan_id": plan_id }),
        &action_id,
    )
    .await?;
    let approval_id = string_at(&pending, "/approval_id")?;
    let policy_hash = string_at(&pending, "/approval_request/policy_hash")?;
    let committed = approve(
        approver,
        approval_id,
        "finance and procurement policy satisfied",
        &action_id,
        policy_hash,
    )
    .await?;
    let compensated = compensate(
        client,
        approver,
        PROCUREMENT_COMMIT,
        plan_id,
        &compensate_key,
        &action_id,
    )
    .await?;
    Ok(
        json!({ "id": "03-procurement-saga", "status": "passed", "request": request, "plan": plan, "plan_replay": replay, "commit": committed, "compensation": compensated }),
    )
}

async fn scenario_access(client: &McpClient, approver: &McpClient) -> Result<Value, String> {
    let run_namespace = ActionId::new().to_string();
    let request = call_identity_read(client, ACCESS_GET, "ar_9001").await?;
    let cross_tenant = match raw_call(
        client,
        ACCESS_GET,
        json!({ "workflow_id": "ar_9001" }),
        None,
        None,
        Some(untrusted_identity_claim("tenant-other", "human:intruder")),
        None,
    )
    .await
    {
        Ok(result) => {
            require(
                result.get("isError").and_then(Value::as_bool) == Some(true),
                "cross-tenant access was not rejected",
            )?;
            result
        }
        Err(error) => {
            require(
                error.contains("requested tenant") && error.contains("verified tenant"),
                "cross-tenant probe failed for an unexpected reason",
            )?;
            json!({ "rejected": true, "transport_error": error })
        }
    };
    let plan_key = format!("e2e:access:{run_namespace}:plan");
    let commit_key = format!("e2e:access:{run_namespace}:commit");
    let compensate_key = format!("e2e:access:{run_namespace}:compensate");
    let plan = call_identity(
        client,
        ACCESS_PLAN,
        json!({ "workflow_id": "ar_9001", "ttl_seconds": 300 }),
        &plan_key,
        json!({ "mode": "execute" }),
    )
    .await?;
    let plan_id = string_at(&plan, "/plan_id")?;
    let action_id = ActionId::new().to_string();
    let pending = call_identity_with_action(
        client,
        ACCESS_COMMIT,
        json!({ "plan_id": plan_id, "ttl_seconds": 300 }),
        &commit_key,
        json!({ "mode": "execute", "plan_id": plan_id }),
        &action_id,
    )
    .await?;
    let approval_id = string_at(&pending, "/approval_id")?;
    let policy_hash = string_at(&pending, "/approval_request/policy_hash")?;
    let committed = approve(
        approver,
        approval_id,
        "time-limited break-glass access approved",
        &action_id,
        policy_hash,
    )
    .await?;
    let revoked = compensate(
        client,
        approver,
        ACCESS_COMMIT,
        plan_id,
        &compensate_key,
        &action_id,
    )
    .await?;
    Ok(
        json!({ "id": "04-privileged-access", "status": "passed", "request": request, "cross_tenant_rejection": cross_tenant, "plan": plan, "grant": committed, "revoke": revoked }),
    )
}

async fn scenario_travel(client: &McpClient, approver: &McpClient) -> Result<Value, String> {
    let run_namespace = ActionId::new().to_string();
    let disruption = call_identity_read(client, TRAVEL_GET, "trip_8001").await?;
    let plan_key = format!("e2e:travel:{run_namespace}:plan");
    let commit_key = format!("e2e:travel:{run_namespace}:commit");
    let compensate_key = format!("e2e:travel:{run_namespace}:compensate");
    let plan = call_identity(
        client,
        TRAVEL_PLAN,
        json!({ "workflow_id": "trip_8001", "option_id": "opt_1" }),
        &plan_key,
        json!({ "mode": "execute" }),
    )
    .await?;
    let plan_id = string_at(&plan, "/plan_id")?;
    let action_id = ActionId::new().to_string();
    let pending = call_identity_with_action(client, TRAVEL_COMMIT, json!({ "plan_id": plan_id, "option_id": "opt_1", "inject_failure_after_reservation": true }), &commit_key, json!({ "mode": "execute", "plan_id": plan_id }), &action_id).await?;
    let approval_id = string_at(&pending, "/approval_id")?;
    let policy_hash = string_at(&pending, "/approval_request/policy_hash")?;
    let failed_commit = approve(
        approver,
        approval_id,
        "rebooking price delta approved",
        &action_id,
        policy_hash,
    )
    .await?;
    require(
        failed_commit.get("error").is_some()
            || failed_commit.get("status").and_then(Value::as_str) == Some("failed"),
        "travel failure injection did not produce a failed action",
    )?;
    let compensated = compensate(
        client,
        approver,
        TRAVEL_COMMIT,
        plan_id,
        &compensate_key,
        &action_id,
    )
    .await?;
    let final_state = call_identity_read(client, TRAVEL_GET, "trip_8001").await?;
    require(
        final_state.get("state").and_then(Value::as_str) == Some("disrupted"),
        "travel compensation did not restore disrupted state",
    )?;
    Ok(
        json!({ "id": "05-travel-rebooking-partial-failure", "status": "passed", "disruption": disruption, "plan": plan, "failed_commit": failed_commit, "compensation": compensated, "final_state": final_state }),
    )
}

async fn scenario_omnichannel(client: &McpClient) -> Result<Value, String> {
    let capabilities = structured(
        client
            .call_tool(
                "aip_capabilities",
                json!({ "include_contracts": true, "limit": 500 }),
            )
            .await
            .map_err(display)?,
    )?;
    let ids = capabilities
        .get("capabilities")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_chatwoot = ids.iter().any(|capability| {
        capability
            .pointer("/id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("cap:chatwoot:"))
    });
    let has_dify = ids.iter().any(|capability| {
        capability
            .pointer("/id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("cap:dify:"))
    });
    let has_crewai = ids.iter().any(|capability| {
        capability
            .pointer("/id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("cap:crewai:"))
    });
    require(
        has_chatwoot && has_dify && has_crewai,
        "live Chatwoot, Dify, and CrewAI capabilities are not all registered in getaip-server",
    )?;
    Ok(
        json!({ "id": "06-omnichannel-handoff", "status": "ready", "capability_discovery": capabilities, "note": "live workflow requires product fixture identifiers configured by deployment" }),
    )
}

async fn call(
    client: &McpClient,
    capability: &str,
    input: Value,
    key: Option<&str>,
    transaction: Option<Value>,
) -> Result<Value, String> {
    structured(raw_call(client, capability, input, key, transaction, None, None).await?)
}

async fn call_with_action(
    client: &McpClient,
    capability: &str,
    input: Value,
    key: Option<&str>,
    transaction: Option<Value>,
    action_id: &str,
) -> Result<Value, String> {
    structured_allow_error(
        raw_call(
            client,
            capability,
            input,
            key,
            transaction,
            None,
            Some(action_id),
        )
        .await?,
    )
}

async fn call_identity(
    client: &McpClient,
    capability: &str,
    input: Value,
    key: &str,
    transaction: Value,
) -> Result<Value, String> {
    structured(
        raw_call(
            client,
            capability,
            input,
            Some(key),
            Some(transaction),
            Some(tenant_identity_hint()),
            None,
        )
        .await?,
    )
}

async fn call_identity_with_action(
    client: &McpClient,
    capability: &str,
    input: Value,
    key: &str,
    transaction: Value,
    action_id: &str,
) -> Result<Value, String> {
    structured_allow_error(
        raw_call(
            client,
            capability,
            input,
            Some(key),
            Some(transaction),
            Some(tenant_identity_hint()),
            Some(action_id),
        )
        .await?,
    )
}

async fn compensate(
    client: &McpClient,
    approver: &McpClient,
    capability: &str,
    plan_id: &str,
    key: &str,
    compensation_for: &str,
) -> Result<Value, String> {
    let action_id = ActionId::new().to_string();
    let result = call_identity_with_action(
        client,
        capability,
        json!({ "plan_id": plan_id }),
        key,
        json!({
            "mode": "compensate",
            "compensation_for": compensation_for
        }),
        &action_id,
    )
    .await?;
    let Some(approval_id) = result.get("approval_id").and_then(Value::as_str) else {
        return Ok(result);
    };
    let policy_hash = string_at(&result, "/approval_request/policy_hash")?;
    approve(
        approver,
        approval_id,
        "compensating operation approved",
        &action_id,
        policy_hash,
    )
    .await
}

async fn call_identity_read(
    client: &McpClient,
    capability: &str,
    workflow_id: &str,
) -> Result<Value, String> {
    structured(
        raw_call(
            client,
            capability,
            json!({ "workflow_id": workflow_id }),
            None,
            None,
            Some(tenant_identity_hint()),
            None,
        )
        .await?,
    )
}

async fn raw_call(
    client: &McpClient,
    capability: &str,
    input: Value,
    key: Option<&str>,
    transaction: Option<Value>,
    identity: Option<Value>,
    action_id: Option<&str>,
) -> Result<Value, String> {
    let mut arguments = json!({ "capability_id": capability, "input": input });
    if let Some(key) = key {
        arguments["idempotency_key"] = json!(key);
    }
    if let Some(transaction) = transaction {
        arguments["transaction"] = transaction;
    }
    if let Some(identity) = identity {
        arguments["identity"] = identity;
    }
    if let Some(action_id) = action_id {
        arguments["action_id"] = json!(action_id);
    }
    client
        .call_tool("aip_call", arguments)
        .await
        .map_err(display)
}

async fn approve(
    client: &McpClient,
    approval_id: &str,
    reason: &str,
    action_id: &str,
    policy_hash: &str,
) -> Result<Value, String> {
    let decision = client.call_tool("aip_approval_decide", json!({
        "approval_id": approval_id,
        "decision": "approved",
        "reason": reason,
        "policy_hash": policy_hash,
        "evidence": [
            { "id": format!("evidence:reason:{approval_id}"), "kind": "reason", "redacted": false },
            { "id": format!("evidence:input:{approval_id}"), "kind": "input_snapshot", "redacted": true },
            { "id": format!("evidence:policy:{approval_id}"), "kind": "policy_decision", "redacted": false },
            { "id": format!("evidence:ticket:{approval_id}"), "kind": "external_ticket", "uri": "support-sandbox://case/case_1001", "redacted": false },
            { "id": format!("evidence:attachment:{approval_id}"), "kind": "attachment", "uri": "support-sandbox://evidence/duplicate-charge", "redacted": false }
        ]
    })).await.map_err(display)?;
    let decision = structured(decision)?;
    if let Some(result) = decision
        .get("events")
        .and_then(Value::as_array)
        .and_then(|events| {
            events.iter().find_map(|event| {
                (event.get("kind").and_then(Value::as_str) == Some("aip.action.resumed_result"))
                    .then(|| event.get("data").cloned())
                    .flatten()
            })
        })
    {
        return Ok(result);
    }
    for _ in 0..40 {
        let value = structured(
            client
                .call_tool(
                    "aip_action_result",
                    json!({ "action_id": action_id, "include_receipts": true }),
                )
                .await
                .map_err(display)?,
        )?;
        if let Some(result) = value.get("action_result") {
            let status = result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if matches!(status, "completed" | "failed" | "cancelled") {
                return Ok(result.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "approved action `{action_id}` did not reach a terminal state"
    ))
}

async fn delegate(
    client: &McpClient,
    delegate_id: &str,
    capability: &str,
    input: Value,
    scope: &str,
) -> Result<Value, String> {
    structured(client.call_tool("aip_delegate", json!({ "delegate_id": delegate_id, "scope": scope, "capability_id": capability, "input": input, "mode": "sync", "idempotency_key": format!("e2e:delegate:{delegate_id}:{scope}") })).await.map_err(display)?)
}

fn structured(result: Value) -> Result<Value, String> {
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(format!("MCP tool returned an error: {result}"));
    }
    result
        .get("structuredContent")
        .cloned()
        .ok_or_else(|| format!("MCP result has no structuredContent: {result}"))
}

fn structured_allow_error(result: Value) -> Result<Value, String> {
    result
        .get("structuredContent")
        .cloned()
        .ok_or_else(|| format!("MCP result has no structuredContent: {result}"))
}

fn untrusted_identity_claim(tenant: &str, human: &str) -> Value {
    json!({
        "tenant": { "id": tenant, "system": "enterprise-sandbox" },
        "human_actor": {
            "id": human,
            "kind": "human",
            "scopes": [],
            "attributes": null,
            "auth_context": null
        }
    })
}

fn tenant_identity_hint() -> Value {
    json!({
        "tenant": { "id": "tenant-acme", "system": "enterprise-sandbox" }
    })
}

fn hermes_prompt(instruction: &str, facts: &Value) -> Value {
    json!({ "messages": [{ "role": "user", "content": format!("{instruction}\n{}", facts) }], "stream": false })
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string `{pointer}` in {value}"))
}

fn validate_run_id(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 96 {
        return Err("--run-id must contain between 1 and 96 characters".to_owned());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(
            "--run-id may contain only ASCII letters, digits, hyphen, underscore, dot, or colon"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn aip_profile_version(manifest: &aip_core::Manifest) -> Option<&str> {
    manifest
        .compatibility
        .as_ref()
        .and_then(|value| value.pointer("/mcp/protocol_version"))
        .and_then(Value::as_str)
}

async fn write_evidence(path: &PathBuf, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(display)?;
    }
    let temporary = path.with_extension("json.tmp");
    tokio::fs::write(
        &temporary,
        serde_json::to_vec_pretty(value).map_err(display)?,
    )
    .await
    .map_err(display)?;
    tokio::fs::rename(&temporary, path).await.map_err(display)
}

#[cfg(test)]
mod tests {
    use super::validate_run_id;

    #[test]
    fn run_id_accepts_stable_operator_identifiers() {
        assert_eq!(
            validate_run_id("restart-20260715").as_deref(),
            Ok("restart-20260715")
        );
    }

    #[test]
    fn run_id_rejects_empty_or_path_like_values() {
        assert!(validate_run_id("").is_err());
        assert!(validate_run_id("../../runtime").is_err());
        assert!(validate_run_id(&"a".repeat(97)).is_err());
    }
}
