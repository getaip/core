//! Cross-crate gateway/connector flow test.

use aip::{
    CapabilityId, Envelope, MessageBody, Principal, PrincipalId, PrincipalKind, gateway::Gateway,
};
use aip_testkit::{FakeConnector, action, handshake_envelope, manifest};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

#[tokio::test]
async fn gateway_routes_action_to_registered_connector() -> Result<(), Box<dyn std::error::Error>> {
    let connector = FakeConnector::new("fake");
    let gateway = Gateway::local_development_with_handlers(
        manifest(),
        HashMap::from([(
            CapabilityId::trusted("cap:test:echo"),
            Arc::new(connector.clone()) as Arc<dyn aip::runtime::ActionHandler>,
        )]),
    )
    .await?;
    gateway.register_connector(connector.clone()).await;

    let handshake = gateway
        .handle_envelope(handshake_envelope(vec![CapabilityId::trusted(
            "cap:test:echo",
        )]))
        .await?;
    assert!(matches!(handshake.body, MessageBody::HandshakeResponse(_)));

    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action(json!({
        "hello": "world"
    })))));
    envelope.from = Some(Principal::new(
        PrincipalId::trusted("agent:test-client"),
        PrincipalKind::Agent,
    ));
    let response = gateway.handle_envelope(envelope).await?;

    let MessageBody::ActionResult(result) = response.body else {
        return Err("unexpected response body".into());
    };
    assert_eq!(result.output, Some(json!({ "echo": { "hello": "world" } })));
    Ok(())
}
