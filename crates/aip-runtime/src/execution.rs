//! Internal connector execution context.

use crate::{
    ActionStream, ApprovalRecord, CancellationToken, ExecutionCheckpointPublisher,
    IdempotencyReservation, TransactionCheckpointPublisher,
};
use aip_auth::{AuthenticatedPrincipal, CredentialHandle, VerifiedTenant};
use aip_core::{ApprovalId, TransactionId};
use std::{collections::BTreeSet, time::Duration};
use time::OffsetDateTime;

/// Bounded action deadline established by the runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    /// Absolute expiry time.
    pub expires_at: OffsetDateTime,
}

impl Deadline {
    /// Creates a deadline relative to `now`.
    #[must_use]
    pub fn after(now: OffsetDateTime, timeout_ms: u64) -> Self {
        Self {
            expires_at: now
                + time::Duration::milliseconds(timeout_ms.max(1).min(i64::MAX as u64) as i64),
        }
    }

    /// Returns the remaining duration, clamped at zero.
    #[must_use]
    pub fn remaining(self, now: OffsetDateTime) -> Duration {
        let milliseconds = (self.expires_at - now).whole_milliseconds().max(0);
        Duration::from_millis(u64::try_from(milliseconds).unwrap_or(u64::MAX))
    }

    /// Returns true once the deadline has elapsed.
    #[must_use]
    pub fn is_expired(self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }
}

/// Trace identifiers propagated to connectors without exposing arbitrary
/// payload-controlled observability fields as trusted metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TraceContext {
    /// W3C trace id or deployment trace identifier.
    pub trace_id: Option<String>,
    /// Current span id.
    pub span_id: Option<String>,
}

/// Runtime-enforced redaction policy for connector logs and errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionPolicy {
    /// JSON pointers that must be removed from diagnostic details.
    pub denied_pointers: BTreeSet<String>,
    /// Whether all action input must be treated as sensitive.
    pub redact_input: bool,
    /// Whether all connector output must be treated as sensitive.
    pub redact_output: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            denied_pointers: BTreeSet::from([
                "/authorization".to_owned(),
                "/token".to_owned(),
                "/access_token".to_owned(),
                "/refresh_token".to_owned(),
                "/api_key".to_owned(),
                "/password".to_owned(),
            ]),
            redact_input: false,
            redact_output: false,
        }
    }
}

/// Approval set verified by the runtime before connector invocation.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedApprovalSet {
    /// Approval workflow ids authorizing the action.
    pub approval_ids: BTreeSet<ApprovalId>,
    /// Idempotent decision ids included in the authorization proof.
    pub decision_ids: BTreeSet<String>,
    /// Immutable policy hashes covered by the decisions.
    pub policy_hashes: BTreeSet<String>,
    /// Complete durable authorization verified by the runtime.
    ///
    /// Remote connector dispatchers carry this record only inside the signed
    /// gateway-to-host envelope. It is never accepted from an untrusted action
    /// payload and lets an isolated connector host reproduce the approval
    /// policy decision without sharing the control-plane database.
    pub authorization: ApprovalRecord,
}

/// Transaction state supplied to a connector attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionExecutionContext {
    /// Stable AIP transaction id.
    pub transaction_id: TransactionId,
    /// Provider operation id recovered from a prior attempt, if any.
    pub provider_operation_id: Option<String>,
    /// Opaque reconciliation cursor recovered from durable state.
    pub reconciliation_cursor: Option<String>,
}

/// Trusted, bounded context supplied to an action handler or connector.
///
/// This type is deliberately not serializable and is not part of AIP schemas.
/// Durable stores persist only the verified, non-secret source records needed
/// to reconstruct it for another attempt.
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    /// Transport-authenticated actor.
    pub actor: AuthenticatedPrincipal,
    /// Verified tenant membership.
    pub tenant: Option<VerifiedTenant>,
    /// Opaque credential handle. Secret material is resolved only by the
    /// connector's deployment credential provider.
    pub credential: Option<CredentialHandle>,
    /// Absolute execution deadline.
    pub deadline: Deadline,
    /// Cooperative cancellation signal.
    pub cancellation: CancellationToken,
    /// Owned idempotency reservation for this attempt.
    pub idempotency: Option<IdempotencyReservation>,
    /// Verified approval evidence.
    pub approval: Option<VerifiedApprovalSet>,
    /// Transaction execution state.
    pub transaction: Option<TransactionExecutionContext>,
    /// Durable provider-operation checkpoint publisher.
    pub transaction_checkpoint: TransactionCheckpointPublisher,
    /// Process-local publisher for the provider-effect durability boundary.
    pub execution_checkpoints: ExecutionCheckpointPublisher,
    /// Incremental stream publisher.
    pub stream: ActionStream,
    /// Trusted trace identifiers.
    pub trace: TraceContext,
    /// Runtime redaction policy.
    pub redaction: RedactionPolicy,
}
