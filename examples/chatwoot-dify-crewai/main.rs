//! Connector-chain contract example for Chatwoot, Dify, and CrewAI.

use aip::{Action, CapabilityId, MessagePart, connector};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = connector::chatwoot::channel_message_from_webhook(
        connector::chatwoot::ChatwootWebhook {
            event: "message_created".to_owned(),
            account: json!({ "id": 42 }),
            conversation: json!({ "id": 1001 }),
            message: Some(json!({ "content": "refund request" })),
            contact: Some(json!({ "id": 77 })),
        },
        "delivery-100".to_owned(),
    )?;

    let dify_manifest = connector::dify::manifest_from_apps(
        vec![connector::dify::DifyApp {
            id: "refund-workflow".to_owned(),
            name: "Refund Workflow".to_owned(),
            mode: "workflow".to_owned(),
            description: Some("Routes refund requests".to_owned()),
        }],
        "tenant-a",
    )?;

    let crew_action = Action::new(
        CapabilityId::trusted("cap:crewai:refund-crew"),
        json!({ "conversation": channel.conversation.external_refs }),
    );
    let crew_request = connector::crewai::run_request_from_action(
        "refund-crew".to_owned(),
        connector::crewai::CrewOperation::Run,
        &crew_action,
    );

    let outgoing = connector::chatwoot::outgoing_message(
        "1001".to_owned(),
        &[MessagePart::text("Refund workflow started")],
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "channel_message": channel,
            "dify_capabilities": dify_manifest.capabilities,
            "crew_request": crew_request,
            "chatwoot_reply": outgoing
        }))?
    );
    Ok(())
}
