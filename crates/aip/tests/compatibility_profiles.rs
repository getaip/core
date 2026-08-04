//! Compatibility profile integration tests.

#![allow(clippy::expect_used)]

use aip::{ActionResult, ActionResultStatus, MessagePart, profile};
use serde_json::json;

#[test]
fn mcp_tool_call_maps_to_aip_action() {
    let request = profile::mcp::JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!(1),
        method: "tools/call".to_owned(),
        params: Some(json!({"name": "triage", "arguments": {"query": "refund"}})),
    };
    let action = profile::mcp::action_from_tools_call(&request).expect("action");
    assert_eq!(action.capability_id.to_string(), "cap:mcp:triage");
}

#[test]
fn mcp_result_hides_native_fields() {
    let result = ActionResult {
        action_id: aip::ActionId::new(),
        status: ActionResultStatus::Completed,
        output: None,
        message: vec![MessagePart::text("done")],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    };
    let mapped = profile::mcp::call_tool_result(&result);
    assert_eq!(mapped["content"][0]["type"], "text");
    assert!(mapped.get("receipt").is_none());
}

#[test]
fn webhook_signature_verifies() {
    let payload = br#"{"event":"message_created"}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature =
        profile::webhook::sign(b"secret", "delivery-1", timestamp, payload).expect("signature");
    let headers = profile::webhook::WebhookHeaders {
        delivery: "delivery-1".to_owned(),
        timestamp,
        signature,
        source_system: "chatwoot".to_owned(),
        event_type: "message_created".to_owned(),
    };
    profile::webhook::verify(b"secret", &headers, payload, 300).expect("verified");
}
