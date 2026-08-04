//! Durable connector dispatch and idempotency ledger.

use crate::operations::CalDiyOperation;
use aip_crypto::canonical_json_bytes;
use aip_runtime::{ProfileStateCasOutcome, ProfileStateStore, RuntimeError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const DISPATCH_NAMESPACE: &str = "aip.connector.cal_diy.dispatch.v1";
/// Default lease for work that has not crossed the provider-dispatch boundary.
pub const DEFAULT_DISPATCH_LEASE_SECONDS: i64 = 120;
const MAX_CAS_ATTEMPTS: usize = 16;

/// Durable state of one mutating Cal.diy dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalDiyDispatchStatus {
    /// The connector fenced the operation before downstream dispatch.
    Claimed,
    /// The connector durably recorded that provider dispatch may begin.
    Dispatching,
    /// Cal.diy returned a successful terminal response.
    Completed,
    /// Reconciliation proved that provider dispatch never began.
    NotCommitted,
    /// Dispatch occurred but the provider outcome is unknown.
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct CalDiyDispatchRecord {
    operation: CalDiyOperation,
    action_id: String,
    input_hash: String,
    status: CalDiyDispatchStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_status: Option<u16>,
    // Diagnostic timestamp; lease decisions use the backend-owned entry time.
    updated_at: OffsetDateTime,
}

/// Successful ownership of a new dispatch ledger entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalDiyDispatchClaim {
    key: String,
    revision: u64,
    input_hash: String,
    operation: CalDiyOperation,
    action_id: String,
}

impl CalDiyDispatchClaim {
    /// Stable opaque provider-operation id used by AIP reconciliation.
    #[must_use]
    pub fn provider_operation_id(&self) -> &str {
        &self.key
    }
}

/// Redacted durable state returned to reconciliation.
#[derive(Clone, Debug, PartialEq)]
pub struct CalDiyReconciliationState {
    /// Current dispatch status.
    pub status: CalDiyDispatchStatus,
    /// Stored terminal provider output, when known.
    pub output: Option<Value>,
    /// Provider request id, when known.
    pub provider_request_id: Option<String>,
    /// Provider HTTP status, when known.
    pub provider_status: Option<u16>,
}

/// Result of atomically claiming a mutating invocation.
#[derive(Clone, Debug, PartialEq)]
pub enum CalDiyClaimOutcome {
    /// This caller owns a new provider dispatch.
    Claimed(CalDiyDispatchClaim),
    /// A matching invocation already completed and its result is reusable.
    Completed(Value),
    /// An identical invocation is currently in flight.
    InFlight(String),
    /// A prior identical invocation has an unknown provider outcome.
    Uncertain(String),
    /// The idempotency key was reused with different input or capability.
    Collision,
}

/// Profile-state-backed dispatch ledger.
#[derive(Clone)]
pub struct CalDiyDispatchLedger {
    state: ProfileStateStore,
    scope: String,
    lease_seconds: i64,
}

impl std::fmt::Debug for CalDiyDispatchLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CalDiyDispatchLedger")
            .field("state", &"ProfileStateStore(..)")
            .field("scope", &self.scope)
            .field("lease_seconds", &self.lease_seconds)
            .finish()
    }
}

impl CalDiyDispatchLedger {
    /// Creates a ledger scoped to one Cal.diy deployment/account boundary.
    #[must_use]
    pub fn new(state: ProfileStateStore, scope: impl Into<String>) -> Self {
        Self {
            state,
            scope: scope.into(),
            lease_seconds: DEFAULT_DISPATCH_LEASE_SECONDS,
        }
    }

    #[cfg(test)]
    fn with_test_lease_seconds(mut self, lease_seconds: i64) -> Self {
        self.lease_seconds = lease_seconds;
        self
    }

    /// Claims one idempotency key before a mutating provider request is sent.
    pub async fn claim(
        &self,
        operation: CalDiyOperation,
        action_id: &str,
        idempotency_key: &str,
        input: &Value,
    ) -> Result<CalDiyClaimOutcome, RuntimeError> {
        let input_hash = input_hash(input)?;
        let key = dispatch_key(&self.scope, operation, idempotency_key);
        for _ in 0..MAX_CAS_ATTEMPTS {
            let record = CalDiyDispatchRecord {
                operation,
                action_id: action_id.to_owned(),
                input_hash: input_hash.clone(),
                status: CalDiyDispatchStatus::Claimed,
                output: None,
                provider_request_id: None,
                provider_status: None,
                updated_at: OffsetDateTime::now_utc(),
            };
            let value = record_value(&record)?;
            match self
                .state
                .create(DISPATCH_NAMESPACE, &key, value.clone())
                .await?
            {
                ProfileStateCasOutcome::Applied(entry) => {
                    return Ok(CalDiyClaimOutcome::Claimed(CalDiyDispatchClaim {
                        key,
                        revision: entry.revision,
                        input_hash,
                        operation,
                        action_id: action_id.to_owned(),
                    }));
                }
                ProfileStateCasOutcome::Conflict(Some(entry)) => {
                    let lease_updated_at = entry.updated_at;
                    let mut existing = decode_record(entry.value)?;
                    if existing.operation != operation || existing.input_hash != input_hash {
                        return Ok(CalDiyClaimOutcome::Collision);
                    }
                    match existing.status {
                        CalDiyDispatchStatus::Completed => {
                            return Ok(CalDiyClaimOutcome::Completed(
                                existing.output.unwrap_or(Value::Null),
                            ));
                        }
                        CalDiyDispatchStatus::Uncertain | CalDiyDispatchStatus::Dispatching
                            if !lease_expired(lease_updated_at, self.lease_seconds) =>
                        {
                            return Ok(if existing.status == CalDiyDispatchStatus::Dispatching {
                                CalDiyClaimOutcome::InFlight(key)
                            } else {
                                CalDiyClaimOutcome::Uncertain(key)
                            });
                        }
                        CalDiyDispatchStatus::Dispatching => {
                            existing.status = CalDiyDispatchStatus::Uncertain;
                            existing.updated_at = OffsetDateTime::now_utc();
                            match self
                                .state
                                .compare_and_set(
                                    DISPATCH_NAMESPACE,
                                    &key,
                                    Some(entry.revision),
                                    record_value(&existing)?,
                                )
                                .await?
                            {
                                ProfileStateCasOutcome::Applied(_) => {
                                    return Ok(CalDiyClaimOutcome::Uncertain(key));
                                }
                                ProfileStateCasOutcome::Conflict(_) => {
                                    tokio::task::yield_now().await;
                                }
                            }
                        }
                        CalDiyDispatchStatus::Claimed
                            if !lease_expired(lease_updated_at, self.lease_seconds) =>
                        {
                            return Ok(CalDiyClaimOutcome::InFlight(key));
                        }
                        CalDiyDispatchStatus::Claimed | CalDiyDispatchStatus::NotCommitted => {
                            match self
                                .state
                                .compare_and_set(
                                    DISPATCH_NAMESPACE,
                                    &key,
                                    Some(entry.revision),
                                    value,
                                )
                                .await?
                            {
                                ProfileStateCasOutcome::Applied(entry) => {
                                    return Ok(CalDiyClaimOutcome::Claimed(CalDiyDispatchClaim {
                                        key,
                                        revision: entry.revision,
                                        input_hash,
                                        operation,
                                        action_id: action_id.to_owned(),
                                    }));
                                }
                                ProfileStateCasOutcome::Conflict(_) => {
                                    tokio::task::yield_now().await;
                                }
                            }
                        }
                        CalDiyDispatchStatus::Uncertain => {
                            return Ok(CalDiyClaimOutcome::Uncertain(key));
                        }
                    }
                }
                ProfileStateCasOutcome::Conflict(None) => tokio::task::yield_now().await,
            }
        }
        Err(RuntimeError::Storage(
            "Cal.diy dispatch claim remained contended".to_owned(),
        ))
    }

    /// Durably moves an owned claim to the provider-dispatch boundary.
    ///
    /// The provider request must not be created or polled until this transition
    /// succeeds. A stale `Claimed` record is therefore safe for another worker
    /// to reclaim, while a stale `Dispatching` record is conservatively fenced
    /// as outcome-unknown.
    pub async fn begin_dispatch(
        &self,
        claim: &CalDiyDispatchClaim,
    ) -> Result<CalDiyDispatchClaim, RuntimeError> {
        let record = CalDiyDispatchRecord {
            operation: claim.operation,
            action_id: claim.action_id.clone(),
            input_hash: claim.input_hash.clone(),
            status: CalDiyDispatchStatus::Dispatching,
            output: None,
            provider_request_id: None,
            provider_status: None,
            updated_at: OffsetDateTime::now_utc(),
        };
        match self
            .state
            .compare_and_set(
                DISPATCH_NAMESPACE,
                &claim.key,
                Some(claim.revision),
                record_value(&record)?,
            )
            .await?
        {
            ProfileStateCasOutcome::Applied(entry) => Ok(CalDiyDispatchClaim {
                key: claim.key.clone(),
                revision: entry.revision,
                input_hash: claim.input_hash.clone(),
                operation: claim.operation,
                action_id: claim.action_id.clone(),
            }),
            ProfileStateCasOutcome::Conflict(Some(entry)) => {
                let existing = decode_record(entry.value)?;
                if owned_by(&existing, claim)
                    && existing.status == CalDiyDispatchStatus::Dispatching
                {
                    Ok(CalDiyDispatchClaim {
                        key: claim.key.clone(),
                        revision: entry.revision,
                        input_hash: claim.input_hash.clone(),
                        operation: claim.operation,
                        action_id: claim.action_id.clone(),
                    })
                } else {
                    Err(RuntimeError::Storage(
                        "Cal.diy dispatch claim changed before provider dispatch".to_owned(),
                    ))
                }
            }
            ProfileStateCasOutcome::Conflict(None) => Err(RuntimeError::Storage(
                "Cal.diy dispatch claim disappeared before provider dispatch".to_owned(),
            )),
        }
    }

    /// Settles a claimed dispatch with the successful provider response.
    pub async fn complete(
        &self,
        claim: CalDiyDispatchClaim,
        output: Value,
        provider_request_id: Option<String>,
        provider_status: u16,
    ) -> Result<(), RuntimeError> {
        let record = CalDiyDispatchRecord {
            operation: claim.operation,
            action_id: claim.action_id.clone(),
            input_hash: String::new(),
            status: CalDiyDispatchStatus::Completed,
            output: Some(output),
            provider_request_id,
            provider_status: Some(provider_status),
            updated_at: OffsetDateTime::now_utc(),
        };
        self.settle(claim, record).await
    }

    /// Marks a claimed dispatch as outcome-unknown before returning an error.
    pub async fn mark_uncertain(
        &self,
        claim: CalDiyDispatchClaim,
        provider_request_id: Option<String>,
        provider_status: Option<u16>,
    ) -> Result<(), RuntimeError> {
        let record = CalDiyDispatchRecord {
            operation: claim.operation,
            action_id: claim.action_id.clone(),
            input_hash: String::new(),
            status: CalDiyDispatchStatus::Uncertain,
            output: None,
            provider_request_id,
            provider_status,
            updated_at: OffsetDateTime::now_utc(),
        };
        self.settle(claim, record).await
    }

    /// Records provider evidence that a dispatch produced no side effect.
    pub async fn mark_not_committed(
        &self,
        claim: CalDiyDispatchClaim,
        provider_request_id: Option<String>,
        provider_status: Option<u16>,
    ) -> Result<(), RuntimeError> {
        let record = CalDiyDispatchRecord {
            operation: claim.operation,
            action_id: claim.action_id.clone(),
            input_hash: String::new(),
            status: CalDiyDispatchStatus::NotCommitted,
            output: None,
            provider_request_id,
            provider_status,
            updated_at: OffsetDateTime::now_utc(),
        };
        self.settle(claim, record).await
    }

    /// Releases a claim before the provider-dispatch boundary is crossed.
    pub async fn release(&self, claim: CalDiyDispatchClaim) -> Result<(), RuntimeError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let Some(entry) = self.state.get(DISPATCH_NAMESPACE, &claim.key).await? else {
                return Ok(());
            };
            let existing = decode_record(entry.value)?;
            if !owned_by(&existing, &claim) || existing.status == CalDiyDispatchStatus::Completed {
                return Err(RuntimeError::Storage(
                    "Cal.diy dispatch claim changed before release".to_owned(),
                ));
            }
            if self
                .state
                .delete(DISPATCH_NAMESPACE, &claim.key, entry.revision)
                .await?
            {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
        Err(RuntimeError::Storage(
            "Cal.diy dispatch claim remained contended during release".to_owned(),
        ))
    }

    /// Reads one opaque provider-operation record for AIP reconciliation.
    pub async fn reconcile(
        &self,
        provider_operation_id: &str,
    ) -> Result<Option<CalDiyReconciliationState>, RuntimeError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let Some(entry) = self
                .state
                .get(DISPATCH_NAMESPACE, provider_operation_id)
                .await?
            else {
                return Ok(None);
            };
            let lease_updated_at = entry.updated_at;
            let mut record = decode_record(entry.value)?;
            let stale_status = match record.status {
                CalDiyDispatchStatus::Claimed
                    if lease_expired(lease_updated_at, self.lease_seconds) =>
                {
                    Some(CalDiyDispatchStatus::NotCommitted)
                }
                CalDiyDispatchStatus::Dispatching
                    if lease_expired(lease_updated_at, self.lease_seconds) =>
                {
                    Some(CalDiyDispatchStatus::Uncertain)
                }
                _ => None,
            };
            if let Some(status) = stale_status {
                record.status = status;
                record.updated_at = OffsetDateTime::now_utc();
                match self
                    .state
                    .compare_and_set(
                        DISPATCH_NAMESPACE,
                        provider_operation_id,
                        Some(entry.revision),
                        record_value(&record)?,
                    )
                    .await?
                {
                    ProfileStateCasOutcome::Applied(_) => {}
                    ProfileStateCasOutcome::Conflict(_) => {
                        tokio::task::yield_now().await;
                        continue;
                    }
                }
            }
            return Ok(Some(reconciliation_state(record)));
        }
        Err(RuntimeError::Storage(
            "Cal.diy dispatch reconciliation remained contended".to_owned(),
        ))
    }

    async fn settle(
        &self,
        claim: CalDiyDispatchClaim,
        mut record: CalDiyDispatchRecord,
    ) -> Result<(), RuntimeError> {
        record.input_hash.clone_from(&claim.input_hash);
        let mut expected_revision = claim.revision;
        for attempt in 0..MAX_CAS_ATTEMPTS {
            match self
                .state
                .compare_and_set(
                    DISPATCH_NAMESPACE,
                    &claim.key,
                    Some(expected_revision),
                    record_value(&record)?,
                )
                .await
            {
                Ok(ProfileStateCasOutcome::Applied(_)) => return Ok(()),
                Ok(ProfileStateCasOutcome::Conflict(Some(entry))) => {
                    let existing = decode_record(entry.value)?;
                    if equivalent_settlement(&existing, &record)
                        || (existing.status == CalDiyDispatchStatus::Completed
                            && record.status == CalDiyDispatchStatus::Uncertain
                            && owned_by(&existing, &claim))
                    {
                        return Ok(());
                    }
                    if owned_by(&existing, &claim)
                        && matches!(
                            existing.status,
                            CalDiyDispatchStatus::Dispatching | CalDiyDispatchStatus::Uncertain
                        )
                    {
                        expected_revision = entry.revision;
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Err(RuntimeError::Storage(
                        "Cal.diy dispatch claim changed before settlement".to_owned(),
                    ));
                }
                Ok(ProfileStateCasOutcome::Conflict(None)) => {
                    return Err(RuntimeError::Storage(
                        "Cal.diy dispatch claim disappeared before settlement".to_owned(),
                    ));
                }
                Err(error) => match self.state.get(DISPATCH_NAMESPACE, &claim.key).await {
                    Ok(Some(entry)) => {
                        let existing = decode_record(entry.value)?;
                        if equivalent_settlement(&existing, &record)
                            || (existing.status == CalDiyDispatchStatus::Completed
                                && record.status == CalDiyDispatchStatus::Uncertain
                                && owned_by(&existing, &claim))
                        {
                            return Ok(());
                        }
                        if owned_by(&existing, &claim)
                            && matches!(
                                existing.status,
                                CalDiyDispatchStatus::Dispatching | CalDiyDispatchStatus::Uncertain
                            )
                            && attempt + 1 < MAX_CAS_ATTEMPTS
                        {
                            expected_revision = entry.revision;
                            tokio::task::yield_now().await;
                            continue;
                        }
                        return Err(error);
                    }
                    Ok(None) | Err(_) => return Err(error),
                },
            }
        }
        Err(RuntimeError::Storage(
            "Cal.diy dispatch settlement remained unavailable".to_owned(),
        ))
    }
}

fn record_value(record: &CalDiyDispatchRecord) -> Result<Value, RuntimeError> {
    serde_json::to_value(record).map_err(|error| RuntimeError::Storage(error.to_string()))
}

fn decode_record(value: Value) -> Result<CalDiyDispatchRecord, RuntimeError> {
    serde_json::from_value(value).map_err(|error| RuntimeError::Storage(error.to_string()))
}

fn owned_by(record: &CalDiyDispatchRecord, claim: &CalDiyDispatchClaim) -> bool {
    record.operation == claim.operation
        && record.action_id == claim.action_id
        && record.input_hash == claim.input_hash
}

fn equivalent_settlement(existing: &CalDiyDispatchRecord, expected: &CalDiyDispatchRecord) -> bool {
    existing.operation == expected.operation
        && existing.action_id == expected.action_id
        && existing.input_hash == expected.input_hash
        && existing.status == expected.status
        && existing.output == expected.output
        && existing.provider_request_id == expected.provider_request_id
        && existing.provider_status == expected.provider_status
}

fn reconciliation_state(record: CalDiyDispatchRecord) -> CalDiyReconciliationState {
    CalDiyReconciliationState {
        status: record.status,
        output: record.output,
        provider_request_id: record.provider_request_id,
        provider_status: record.provider_status,
    }
}

fn lease_expired(updated_at: OffsetDateTime, lease_seconds: i64) -> bool {
    (OffsetDateTime::now_utc() - updated_at).whole_seconds() >= lease_seconds
}

fn dispatch_key(scope: &str, operation: CalDiyOperation, idempotency_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope.as_bytes());
    hasher.update(b"\0");
    hasher.update(operation.suffix().as_bytes());
    hasher.update(b"\0");
    hasher.update(idempotency_key.as_bytes());
    hex::encode(hasher.finalize())
}

fn input_hash(input: &Value) -> Result<String, RuntimeError> {
    let bytes =
        canonical_json_bytes(input).map_err(|error| RuntimeError::Storage(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::{CalDiyClaimOutcome, CalDiyDispatchLedger, CalDiyDispatchStatus};
    use crate::operations::CalDiyOperation;
    use aip_runtime::ProfileStateStore;
    use serde_json::json;

    #[tokio::test]
    async fn stale_pre_dispatch_claim_is_safely_reclaimed() {
        let ledger = CalDiyDispatchLedger::new(ProfileStateStore::default(), "scope")
            .with_test_lease_seconds(0);
        let input = json!({ "event_type_id": 42 });
        let _first = match ledger
            .claim(
                CalDiyOperation::EventTypeDelete,
                "action-1",
                "idempotency-key",
                &input,
            )
            .await
            .expect("first claim")
        {
            CalDiyClaimOutcome::Claimed(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        let recovered = ledger
            .claim(
                CalDiyOperation::EventTypeDelete,
                "action-2",
                "idempotency-key",
                &input,
            )
            .await
            .expect("recovered claim");
        assert!(matches!(recovered, CalDiyClaimOutcome::Claimed(_)));
    }

    #[tokio::test]
    async fn stale_dispatch_is_promoted_to_uncertain_with_reconciliation_key() {
        let ledger = CalDiyDispatchLedger::new(ProfileStateStore::default(), "scope")
            .with_test_lease_seconds(0);
        let input = json!({ "event_type_id": 42 });
        let claim = match ledger
            .claim(
                CalDiyOperation::EventTypeDelete,
                "action-1",
                "idempotency-key",
                &input,
            )
            .await
            .expect("claim")
        {
            CalDiyClaimOutcome::Claimed(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        let dispatch = ledger.begin_dispatch(&claim).await.expect("dispatch phase");
        let retry = ledger
            .claim(
                CalDiyOperation::EventTypeDelete,
                "action-2",
                "idempotency-key",
                &input,
            )
            .await
            .expect("retry outcome");
        assert_eq!(
            retry,
            CalDiyClaimOutcome::Uncertain(dispatch.provider_operation_id().to_owned())
        );
        let reconciled = ledger
            .reconcile(dispatch.provider_operation_id())
            .await
            .expect("reconciliation")
            .expect("state");
        assert_eq!(reconciled.status, CalDiyDispatchStatus::Uncertain);
    }

    #[tokio::test]
    async fn reconciliation_proves_a_stale_claim_never_dispatched() {
        let ledger = CalDiyDispatchLedger::new(ProfileStateStore::default(), "scope")
            .with_test_lease_seconds(0);
        let input = json!({ "event_type_id": 42 });
        let claim = match ledger
            .claim(
                CalDiyOperation::EventTypeDelete,
                "action-1",
                "idempotency-key",
                &input,
            )
            .await
            .expect("claim")
        {
            CalDiyClaimOutcome::Claimed(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        let reconciled = ledger
            .reconcile(claim.provider_operation_id())
            .await
            .expect("reconciliation")
            .expect("state");
        assert_eq!(reconciled.status, CalDiyDispatchStatus::NotCommitted);
        assert!(matches!(
            ledger
                .claim(
                    CalDiyOperation::EventTypeDelete,
                    "action-2",
                    "idempotency-key",
                    &input,
                )
                .await
                .expect("retry claim"),
            CalDiyClaimOutcome::Claimed(_)
        ));
    }
}
