//! Property tests for transport-independent AIP model invariants.

#![forbid(unsafe_code)]

use aip_core::{
    Action, CapabilityId, Envelope, MessageBody, Principal, PrincipalId, PrincipalKind,
    validate_envelope,
};
use proptest::prelude::*;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

proptest! {
    #[test]
    fn valid_action_envelopes_round_trip_without_semantic_loss(
        fields in prop::collection::btree_map("[a-z][a-z0-9_]{0,12}", any::<i64>(), 0..32)
    ) {
        let input = object_from_fields(fields);
        let action = Action::new(CapabilityId::trusted("cap:property:roundtrip"), input);
        let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
        envelope.from = Some(Principal::new(
            PrincipalId::trusted("agent:property-test"),
            PrincipalKind::Agent,
        ));

        validate_envelope(&envelope)
            .map_err(|error| TestCaseError::fail(format!("generated envelope must validate: {error}")))?;
        let encoded = serde_json::to_vec(&envelope)
            .map_err(|error| TestCaseError::fail(format!("encode envelope: {error}")))?;
        let decoded: Envelope = serde_json::from_slice(&encoded)
            .map_err(|error| TestCaseError::fail(format!("decode envelope: {error}")))?;
        prop_assert_eq!(decoded, envelope);
    }
}

fn object_from_fields(fields: BTreeMap<String, i64>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key, Value::from(value)))
            .collect::<Map<_, _>>(),
    )
}
