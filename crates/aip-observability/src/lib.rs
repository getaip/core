//! Observability conventions for AIP gateways and connectors.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::Envelope;
use serde::{Deserialize, Serialize};
use tracing::Span;

/// Stable tracing field names.
pub mod fields {
    /// AIP message id.
    pub const MESSAGE_ID: &str = "aip.message_id";
    /// AIP message type.
    pub const MESSAGE_TYPE: &str = "aip.message_type";
    /// AIP session id.
    pub const SESSION_ID: &str = "aip.session_id";
    /// AIP correlation id.
    pub const CORRELATION_ID: &str = "aip.correlation_id";
    /// AIP capability id.
    pub const CAPABILITY_ID: &str = "aip.capability_id";
    /// AIP action id.
    pub const ACTION_ID: &str = "aip.action_id";
    /// AIP parent action id.
    pub const PARENT_ACTION_ID: &str = "aip.parent_action_id";
    /// AIP child action id.
    pub const CHILD_ACTION_ID: &str = "aip.child_action_id";
    /// AIP delegation id.
    pub const DELEGATION_ID: &str = "aip.delegation_id";
    /// AIP error code.
    pub const ERROR_CODE: &str = "aip.error_code";
    /// AIP transport profile.
    pub const PROFILE_ID: &str = "aip.profile_id";
    /// Connector id.
    pub const CONNECTOR_ID: &str = "aip.connector_id";
    /// Transport binding name.
    pub const TRANSPORT: &str = "aip.transport";
}

/// Stable metric names for AIP implementations.
pub mod metrics {
    /// Count of envelopes received by a gateway.
    pub const ENVELOPES_RECEIVED_TOTAL: &str = "aip_envelopes_received_total";
    /// Count of envelopes sent by a gateway.
    pub const ENVELOPES_SENT_TOTAL: &str = "aip_envelopes_sent_total";
    /// Count of action invocations.
    pub const ACTIONS_TOTAL: &str = "aip_actions_total";
    /// Count of delegation requests.
    pub const DELEGATIONS_TOTAL: &str = "aip_delegations_total";
    /// Delegation latency in milliseconds.
    pub const DELEGATION_DURATION_MS: &str = "aip_delegation_duration_ms";
    /// Action latency in milliseconds.
    pub const ACTION_DURATION_MS: &str = "aip_action_duration_ms";
    /// Count of connector invocations.
    pub const CONNECTOR_INVOCATIONS_TOTAL: &str = "aip_connector_invocations_total";
    /// Connector latency in milliseconds.
    pub const CONNECTOR_DURATION_MS: &str = "aip_connector_duration_ms";
    /// Count of protocol errors.
    pub const ERRORS_TOTAL: &str = "aip_errors_total";
    /// Count of active sessions.
    pub const SESSIONS_ACTIVE: &str = "aip_sessions_active";
    /// Count of event stream chunks emitted.
    pub const STREAM_CHUNKS_TOTAL: &str = "aip_stream_chunks_total";
}

/// Trace context carried across AIP profiles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    /// Trace id.
    pub trace_id: String,
    /// Span id.
    pub span_id: String,
}

impl TraceContext {
    /// Parses a W3C `traceparent` header value.
    #[must_use]
    pub fn from_traceparent(value: &str) -> Option<Self> {
        let mut parts = value.split('-');
        let version = parts.next()?;
        let trace_id = parts.next()?;
        let span_id = parts.next()?;
        let flags = parts.next()?;
        if parts.next().is_some()
            || version.len() != 2
            || trace_id.len() != 32
            || span_id.len() != 16
            || flags.len() != 2
            || trace_id.chars().all(|ch| ch == '0')
            || span_id.chars().all(|ch| ch == '0')
            || !trace_id.chars().all(|ch| ch.is_ascii_hexdigit())
            || !span_id.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            trace_id: trace_id.to_ascii_lowercase(),
            span_id: span_id.to_ascii_lowercase(),
        })
    }

    /// Formats this context as a W3C `traceparent` header with sampled flag set.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id, self.span_id)
    }
}

/// Extracts trace context from an envelope when present.
#[must_use]
pub fn trace_context(envelope: &Envelope) -> Option<TraceContext> {
    let trace = envelope.trace.as_ref()?;
    Some(TraceContext {
        trace_id: trace.get("trace_id")?.as_str()?.to_owned(),
        span_id: trace.get("span_id")?.as_str()?.to_owned(),
    })
}

/// Returns OpenTelemetry-compatible AIP attributes for an envelope.
#[must_use]
pub fn envelope_attributes(envelope: &Envelope) -> Vec<(&'static str, String)> {
    let mut attributes = vec![
        (fields::MESSAGE_ID, envelope.message_id.to_string()),
        (
            fields::MESSAGE_TYPE,
            envelope.message_type.as_str().to_owned(),
        ),
    ];
    if let Some(session_id) = &envelope.session_id {
        attributes.push((fields::SESSION_ID, session_id.to_string()));
    }
    if let Some(correlation_id) = &envelope.correlation_id {
        attributes.push((fields::CORRELATION_ID, correlation_id.to_string()));
    }
    match &envelope.body {
        aip_core::MessageBody::Action(action) => {
            attributes.push((fields::ACTION_ID, action.id.to_string()));
            attributes.push((fields::CAPABILITY_ID, action.capability_id.to_string()));
        }
        aip_core::MessageBody::ActionResult(result) => {
            attributes.push((fields::ACTION_ID, result.action_id.to_string()));
            if let Some(error) = &result.error {
                attributes.push((fields::ERROR_CODE, error.code.clone()));
            }
        }
        aip_core::MessageBody::DelegationRequest(request) => {
            attributes.push((fields::DELEGATION_ID, request.delegation_id.to_string()));
            attributes.push((
                fields::PARENT_ACTION_ID,
                request.parent_action_id.to_string(),
            ));
            attributes.push((fields::CHILD_ACTION_ID, request.child_action.id.to_string()));
            attributes.push((
                fields::CAPABILITY_ID,
                request.child_action.capability_id.to_string(),
            ));
        }
        aip_core::MessageBody::DelegationResult(result) => {
            attributes.push((fields::DELEGATION_ID, result.delegation_id.to_string()));
            attributes.push((
                fields::PARENT_ACTION_ID,
                result.parent_action_id.to_string(),
            ));
            attributes.push((fields::CHILD_ACTION_ID, result.child_action_id.to_string()));
            if let Some(error) = &result.error {
                attributes.push((fields::ERROR_CODE, error.code.clone()));
            }
            if let Some(action_result) = &result.result
                && let Some(error) = &action_result.error
            {
                attributes.push((fields::ERROR_CODE, error.code.clone()));
            }
        }
        aip_core::MessageBody::Error(error) => {
            attributes.push((fields::ERROR_CODE, error.error.code.clone()));
        }
        _ => {}
    }
    if let Some(profile) = envelope
        .trace
        .as_ref()
        .and_then(|trace| trace.get("profile"))
        .and_then(serde_json::Value::as_str)
    {
        attributes.push((fields::PROFILE_ID, profile.to_owned()));
    }
    attributes
}

/// Records standard AIP fields on the current tracing span.
pub fn record_envelope(span: &Span, envelope: &Envelope) {
    for (field, value) in envelope_attributes(envelope) {
        span.record(field, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{TraceContext, envelope_attributes, fields, metrics};
    use aip_core::{Action, CapabilityId, Envelope, MessageBody};
    use serde_json::json;

    #[test]
    fn parses_traceparent() {
        let context = TraceContext::from_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .expect("traceparent");
        assert_eq!(context.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(
            context.to_traceparent(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }

    #[test]
    fn extracts_action_attributes() {
        let mut envelope = Envelope::new(MessageBody::Action(Box::new(Action::new(
            CapabilityId::trusted("cap:test"),
            json!({}),
        ))));
        envelope.trace = Some(json!({ "profile": "aip.native.http.v1" }));
        let attributes = envelope_attributes(&envelope);
        assert!(
            attributes
                .iter()
                .any(|(name, value)| *name == fields::CAPABILITY_ID && value == "cap:test")
        );
        assert!(
            attributes
                .iter()
                .any(|(name, value)| *name == fields::PROFILE_ID && value == "aip.native.http.v1")
        );
        assert_eq!(metrics::ACTIONS_TOTAL, "aip_actions_total");
    }
}
