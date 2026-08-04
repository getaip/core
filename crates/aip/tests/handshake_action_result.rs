//! Integration flow covering handshake, action dispatch, and action result.

#![allow(clippy::expect_used, clippy::panic)]

use aip::{
    Action, Capability, CapabilityId, CapabilityKind, Envelope, Handshake, Manifest, MessageBody,
    Principal, PrincipalId, PrincipalKind, ProfileId, runtime::EchoHandler,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

#[tokio::test]
async fn handshake_action_result_flow() {
    let principal = Principal::new(
        PrincipalId::parse("agent:test").expect("principal id"),
        PrincipalKind::Agent,
    );
    let capability_id = CapabilityId::parse("cap:test:echo").expect("capability id");
    let manifest = Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: principal.clone(),
        capabilities: vec![Capability {
            id: capability_id.clone(),
            name: "echo".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            description: None,
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        }],
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: None,
        extensions: None,
    };

    let gateway = aip::gateway::Gateway::local_development_with_handlers(
        manifest,
        HashMap::from([(
            capability_id.clone(),
            Arc::new(EchoHandler) as Arc<dyn aip::runtime::ActionHandler>,
        )]),
    )
    .await
    .expect("gateway");

    let handshake_response = gateway
        .handle_authenticated_envelope(
            Envelope::new(MessageBody::Handshake(Handshake {
                client: principal.clone(),
                purpose: "integration".to_owned(),
                requested_capabilities: vec![capability_id.clone()],
                profiles: vec![ProfileId::from("aip.native.http.v1")],
                auth: None,
                compliance_required: Vec::new(),
                heartbeat: None,
                encryption: None,
                billing: None,
            })),
            principal.clone(),
        )
        .await
        .expect("handshake response");
    assert!(matches!(
        handshake_response.body,
        MessageBody::HandshakeResponse(_)
    ));

    let mut action_envelope = Envelope::new(MessageBody::Action(Box::new(Action::new(
        capability_id,
        json!({"hello": "aip"}),
    ))));
    action_envelope.from = Some(principal.clone());
    let action_response = gateway
        .handle_authenticated_envelope(action_envelope, principal)
        .await
        .expect("action response");
    match action_response.body {
        MessageBody::ActionResult(result) => {
            assert_eq!(result.output, Some(json!({"echo": {"hello": "aip"}})));
        }
        other => panic!("unexpected response body: {other:?}"),
    }
}
