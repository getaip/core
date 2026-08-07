//! Property tests for canonical AIP envelope signatures.

#![forbid(unsafe_code)]

use aip_core::{Action, CapabilityId, Envelope, MessageBody};
use aip_crypto::{sign_envelope, signing_key_from_seed, verify_envelope};
use proptest::prelude::*;
use serde_json::json;

proptest! {
    #[test]
    fn changing_any_business_signature_value_invalidates_envelope_signature(
        original in "[ -~]{0,128}",
        replacement in "[ -~]{0,128}"
    ) {
        prop_assume!(original != replacement);
        let key = signing_key_from_seed([17_u8; 32]);
        let mut envelope = Envelope::new(MessageBody::Action(Box::new(Action::new(
            CapabilityId::trusted("cap:property:signature"),
            json!({ "document": { "signature": original } }),
        ))));
        envelope.security = Some(json!({ "did": "did:key:property-test" }));
        let signature = sign_envelope(&envelope, &key)
            .map_err(|error| TestCaseError::fail(format!("sign envelope: {error}")))?;
        verify_envelope(&envelope, &signature, &key.verifying_key())
            .map_err(|error| TestCaseError::fail(format!("verify unchanged envelope: {error}")))?;

        let MessageBody::Action(action) = &mut envelope.body else {
            return Err(TestCaseError::fail("test did not construct an action envelope"));
        };
        action.input["document"]["signature"] = json!(replacement);
        prop_assert!(verify_envelope(&envelope, &signature, &key.verifying_key()).is_err());
    }
}
