//! Deployed support sandbox E2E smoke for native AIP approval and refund flow.

#![forbid(unsafe_code)]

use aip_connector_support_sandbox::{
    APPROVAL_DECISION_RECORD_CAPABILITY_ID, BILLING_DUPLICATE_CHARGE_DETECT_CAPABILITY_ID,
    REFUND_COMMIT_CAPABILITY_ID, REFUND_PLAN_CAPABILITY_ID, REFUND_POLICY_EVALUATE_CAPABILITY_ID,
    SUPPORT_CASE_GET_CAPABILITY_ID,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, ApprovalDecision, ApprovalDecisionKind, ApprovalId,
    CapabilityId, Envelope, EvidenceArtifact, Manifest, MessageBody, Principal, PrincipalId,
    PrincipalKind,
};
use clap::Parser;
use reqwest::{
    Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::env;
use time::OffsetDateTime;

/// Command-line options.
#[derive(Debug, Parser)]
#[command(name = "getaip-server-support-sandbox-smoke")]
struct Args {
    /// Deployed getaip-server base URL.
    #[arg(long, default_value = "http://127.0.0.1:18080")]
    server_url: Url,
    /// Bearer token enforced by the native AIP HTTP edge.
    #[arg(long = "native-bearer-token")]
    native_bearer_token: Option<String>,
    /// Seeded case id.
    #[arg(long, default_value = "case_1001")]
    case_id: String,
    /// Duplicate charge selected for refund.
    #[arg(long, default_value = "ch_1001_b")]
    charge_id: String,
    /// Stable E2E idempotency key.
    #[arg(long, default_value = "refund:case_1001:ch_1001_b:e2e")]
    idempotency_key: String,
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
    let native_bearer_token = args
        .native_bearer_token
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN").ok());
    let client = native_http_client(native_bearer_token.as_deref())?;
    let actor = Principal::new(
        PrincipalId::parse("agent:support-sandbox-smoke").map_err(|error| error.to_string())?,
        PrincipalKind::Agent,
    );
    let manifest = fetch_manifest(&client, &args.server_url).await?;
    assert_capabilities(&manifest)?;

    let case = run_completed_action(
        &client,
        &args.server_url,
        actor.clone(),
        SUPPORT_CASE_GET_CAPABILITY_ID,
        json!({ "case_id": args.case_id }),
        None,
        None,
    )
    .await?;
    let duplicates = run_completed_action(
        &client,
        &args.server_url,
        actor.clone(),
        BILLING_DUPLICATE_CHARGE_DETECT_CAPABILITY_ID,
        json!({ "case_id": args.case_id }),
        None,
        None,
    )
    .await?;
    if duplicates
        .pointer("/duplicate_count")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        == 0
    {
        return Err("duplicate charge detector returned no candidates".to_owned());
    }
    let policy = run_completed_action(
        &client,
        &args.server_url,
        actor.clone(),
        REFUND_POLICY_EVALUATE_CAPABILITY_ID,
        json!({ "case_id": args.case_id, "charge_id": args.charge_id }),
        None,
        None,
    )
    .await?;
    if policy
        .get("requires_human_approval")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("refund policy did not require approval".to_owned());
    }
    let plan = run_completed_action(
        &client,
        &args.server_url,
        actor.clone(),
        REFUND_PLAN_CAPABILITY_ID,
        json!({
            "case_id": args.case_id,
            "charge_id": args.charge_id,
            "reason": "duplicate_charge",
            "idempotency_key": args.idempotency_key
        }),
        Some(args.idempotency_key.clone()),
        None,
    )
    .await?;
    let refund_id = required_json_string(&plan, "/refund/refund_id")?;
    let approval_request_id = required_json_string(&plan, "/refund/approval_request_id")?;
    let product_approval = run_completed_action(
        &client,
        &args.server_url,
        actor.clone(),
        APPROVAL_DECISION_RECORD_CAPABILITY_ID,
        json!({
            "approval_request_id": approval_request_id,
            "decision": "granted",
            "approver_principal": "human:billing-manager",
            "reason": "Duplicate charge verified in support sandbox."
        }),
        Some(format!("approval:{approval_request_id}:granted")),
        None,
    )
    .await?;
    let pending_commit = run_action(
        &client,
        &args.server_url,
        actor.clone(),
        REFUND_COMMIT_CAPABILITY_ID,
        json!({
            "refund_id": refund_id,
            "idempotency_key": args.idempotency_key
        }),
        Some(args.idempotency_key.clone()),
        None,
    )
    .await?;
    if pending_commit.status != ActionResultStatus::PendingApproval {
        return Err(format!(
            "refund commit should be pending AIP approval before resume, got {:?}",
            pending_commit.status
        ));
    }
    let approval_id = pending_commit
        .output
        .as_ref()
        .and_then(|output| output.get("approval_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| "pending commit did not include approval_id".to_owned())?;
    let approval_id = ApprovalId::parse(approval_id).map_err(|error| error.to_string())?;
    let decision = ApprovalDecision {
        approval_id,
        decision: ApprovalDecisionKind::Approved,
        approver: Principal::new(
            PrincipalId::parse("human:billing-manager").map_err(|error| error.to_string())?,
            PrincipalKind::Human,
        ),
        decided_at: OffsetDateTime::now_utc(),
        reason: Some("Duplicate charge verified and product approval granted.".to_owned()),
        constraints: Vec::new(),
        evidence: vec![
            EvidenceArtifact {
                id: format!("evidence:external-ticket:{approval_request_id}"),
                kind: "external_ticket".to_owned(),
                uri: Some(format!("support-sandbox://approval/{approval_request_id}")),
                hash: None,
                redacted: false,
            },
            EvidenceArtifact {
                id: format!("evidence:refund-plan:{approval_request_id}"),
                kind: "attachment".to_owned(),
                uri: Some(format!("support-sandbox://refund/{refund_id}")),
                hash: None,
                redacted: false,
            },
        ],
        decision_id: Some(format!("decision:{approval_request_id}")),
        policy_hash: None,
        authority_path: vec!["tenant_policy:billing".to_owned()],
        target_decision_id: None,
    };
    let resumed =
        send_approval_decision(&client, &args.server_url, actor.clone(), decision).await?;
    let resumed_event = resumed
        .pointer("/events")
        .and_then(Value::as_array)
        .and_then(|events| {
            events.iter().find_map(|event| {
                (event.get("kind").and_then(Value::as_str) == Some("aip.action.resumed_result"))
                    .then_some(event)
                    .and_then(|event| event.get("data"))
                    .filter(|data| data.get("status").is_some())
                    .cloned()
            })
        })
        .ok_or_else(|| {
            format!("approval decision did not emit resumed action result: {resumed}")
        })?;
    if resumed_event.get("status").and_then(Value::as_str) != Some("completed") {
        return Err(format!("resumed commit did not complete: {resumed_event}"));
    }
    let final_case = run_completed_action(
        &client,
        &args.server_url,
        actor.clone(),
        SUPPORT_CASE_GET_CAPABILITY_ID,
        json!({ "case_id": args.case_id }),
        None,
        None,
    )
    .await?;
    if final_case
        .pointer("/case/case_status")
        .and_then(Value::as_str)
        != Some("resolved")
    {
        return Err(format!(
            "case was not resolved after refund commit: {final_case}"
        ));
    }
    let refunded_charge = final_case
        .pointer("/case/charges")
        .and_then(Value::as_array)
        .and_then(|charges| {
            charges.iter().find(|charge| {
                charge.get("charge_id").and_then(Value::as_str) == Some(args.charge_id.as_str())
            })
        })
        .ok_or_else(|| format!("final case did not include charge `{}`", args.charge_id))?;
    if refunded_charge.get("status").and_then(Value::as_str) != Some("refunded") {
        return Err(format!(
            "selected charge was not refunded after commit: {refunded_charge}"
        ));
    }

    print_json(&json!({
        "status": "ok",
        "server_url": args.server_url.as_str(),
        "manifest": {
            "agent": manifest.agent,
            "capability_count": manifest.capabilities.len()
        },
        "case": case,
        "duplicates": duplicates,
        "policy": policy,
        "plan": plan,
        "product_approval": product_approval,
        "aip_pending_commit": {
            "status": pending_commit.status,
            "action_id": pending_commit.action_id
        },
        "aip_resumed_commit": resumed_event,
        "final_case": final_case
    }))?;
    Ok(())
}

fn native_http_client(bearer_token: Option<&str>) -> Result<reqwest::Client, String> {
    let mut headers = HeaderMap::new();
    if let Some(token) = bearer_token.filter(|token| !token.trim().is_empty()) {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| format!("invalid native bearer token: {error}"))?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|error| error.to_string())
}

async fn fetch_manifest(client: &reqwest::Client, server_url: &Url) -> Result<Manifest, String> {
    let url = server_url
        .join("/aip/v1/manifest")
        .map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "manifest request failed with HTTP {status}: {body}"
        ));
    }
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

fn assert_capabilities(manifest: &Manifest) -> Result<(), String> {
    for required in [
        SUPPORT_CASE_GET_CAPABILITY_ID,
        BILLING_DUPLICATE_CHARGE_DETECT_CAPABILITY_ID,
        REFUND_POLICY_EVALUATE_CAPABILITY_ID,
        REFUND_PLAN_CAPABILITY_ID,
        APPROVAL_DECISION_RECORD_CAPABILITY_ID,
        REFUND_COMMIT_CAPABILITY_ID,
    ] {
        if !manifest
            .capabilities
            .iter()
            .any(|capability| capability.id.as_str() == required)
        {
            return Err(format!("manifest is missing `{required}`"));
        }
    }
    Ok(())
}

async fn run_completed_action(
    client: &reqwest::Client,
    server_url: &Url,
    actor: Principal,
    capability_id: &str,
    input: Value,
    idempotency_key: Option<String>,
    approval: Option<aip_core::ApprovalDecision>,
) -> Result<Value, String> {
    let result = run_action(
        client,
        server_url,
        actor,
        capability_id,
        input,
        idempotency_key,
        approval,
    )
    .await?;
    if result.status != ActionResultStatus::Completed {
        return Err(format!(
            "`{capability_id}` returned {:?}: {:?}",
            result.status, result.error
        ));
    }
    Ok(result.output.unwrap_or_else(|| json!({})))
}

async fn run_action(
    client: &reqwest::Client,
    server_url: &Url,
    actor: Principal,
    capability_id: &str,
    input: Value,
    idempotency_key: Option<String>,
    approval: Option<aip_core::ApprovalDecision>,
) -> Result<ActionResult, String> {
    let capability_id = CapabilityId::parse(capability_id).map_err(|error| error.to_string())?;
    let mut action = Action::new(capability_id, input);
    action.idempotency_key = idempotency_key;
    action.approval = approval;
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
    envelope.from = Some(actor);
    match post_envelope(client, server_url, envelope).await?.body {
        MessageBody::ActionResult(result) => Ok(result),
        MessageBody::Error(error) => Err(error.error.message),
        other => Err(format!(
            "unexpected AIP response: {:?}",
            other.message_type()
        )),
    }
}

async fn send_approval_decision(
    client: &reqwest::Client,
    server_url: &Url,
    actor: Principal,
    decision: ApprovalDecision,
) -> Result<Value, String> {
    let mut envelope = Envelope::new(MessageBody::ApprovalDecision(Box::new(decision)));
    envelope.from = Some(actor);
    match post_envelope(client, server_url, envelope).await?.body {
        MessageBody::EventStream(stream) => {
            serde_json::to_value(stream).map_err(|error| error.to_string())
        }
        MessageBody::Error(error) => Err(error.error.message),
        other => Err(format!(
            "unexpected approval response: {:?}",
            other.message_type()
        )),
    }
}

async fn post_envelope(
    client: &reqwest::Client,
    server_url: &Url,
    envelope: Envelope,
) -> Result<Envelope, String> {
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
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("AIP message failed with HTTP {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

fn required_json_string(value: &Value, pointer: &str) -> Result<String, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing string at JSON pointer `{pointer}` in {value}"))
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}
