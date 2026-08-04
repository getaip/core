//! Minimal in-process AIP agent.

use aip::{Envelope, MessageBody, Principal, PrincipalId, PrincipalKind, runtime::EchoHandler};
use aip_testkit::{action, manifest};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capability_id = aip::CapabilityId::trusted("cap:test:echo");
    let gateway = aip::gateway::Gateway::local_development_with_handlers(
        manifest(),
        HashMap::from([(
            capability_id,
            Arc::new(EchoHandler) as Arc<dyn aip::runtime::ActionHandler>,
        )]),
    )
    .await?;

    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action(json!({
        "prompt": "hello from minimal agent"
    })))));
    envelope.from = Some(Principal::new(
        PrincipalId::trusted("agent:minimal-client"),
        PrincipalKind::Agent,
    ));
    let response = gateway.handle_envelope(envelope).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
