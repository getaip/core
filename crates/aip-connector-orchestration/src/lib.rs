//! Deterministic deployment contract for external connector orchestrators.
//!
//! AIP does not embed Kubernetes, Nomad, ECS, or Docker control code. This
//! crate instead derives a bounded, signed sequence of platform-neutral
//! operations from a cryptographically verified admission package. Executors
//! may only start exact pre-provisioned replica identities at the admitted OCI
//! digest. The same reconciliation algorithm handles initial rollout,
//! scale-to-zero, replacement, restart, and rollback without granting the
//! external orchestrator connector-registry administrator credentials.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used))]

use aip_connector_admission::VerifiedAdmissionPackage;
use aip_connector_registry::{
    ConnectorInstanceId, ConnectorInstanceStatus, ConnectorReplicaId, ConnectorTopology,
    ConnectorVersionId, ConnectorVersionStatus, digest_json,
};
use aip_core::PrincipalId;
use aip_crypto::{
    did_key_from_verifying_key, sign_value, verify_value, verifying_key_from_did_key,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

/// Versioned schema for deployment intents and signed reconciliation plans.
pub const ORCHESTRATION_SCHEMA: &str = "aip.connector-orchestration/v1";

/// Deployment-owned safety limits applied before reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationLimits {
    /// Maximum desired replicas for one connector instance.
    pub max_replicas_per_instance: usize,
    /// Maximum observations accepted in one reconciliation request.
    pub max_observations: usize,
    /// Maximum generated operations in one signed plan.
    pub max_operations: usize,
    /// Maximum validity window for one plan.
    pub max_plan_ttl_seconds: i64,
    /// Maximum accepted clock lead for an intent.
    pub max_clock_skew_seconds: i64,
}

/// Trust roots and hard limits installed at an orchestration executor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationTrustPolicy {
    /// `did:key` identities allowed to authorize deployment operations.
    pub trusted_signer_dids: BTreeSet<String>,
    /// Bounds applied again by the executor after signature verification.
    #[serde(default)]
    pub limits: OrchestrationLimits,
}

impl Default for OrchestrationLimits {
    fn default() -> Self {
        Self {
            max_replicas_per_instance: 1_000,
            max_observations: 2_000,
            max_operations: 2_000,
            max_plan_ttl_seconds: 300,
            max_clock_skew_seconds: 30,
        }
    }
}

/// Operator-reviewed desired state for one logical connector instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentIntent {
    /// Contract schema.
    pub schema_version: String,
    /// Stable monotonic generation for this instance.
    pub generation: u64,
    /// Earlier generation being restored, when this is a rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_of_generation: Option<u64>,
    /// Signed admission package stream id.
    pub package_id: String,
    /// Exact signed admission package revision.
    pub package_revision: u64,
    /// Canonical digest returned by admission verification.
    pub package_digest: String,
    /// Logical instance being reconciled.
    pub instance_id: ConnectorInstanceId,
    /// Exact pre-provisioned replica identities that should run.
    pub desired_replicas: BTreeSet<ConnectorReplicaId>,
    /// Temporary extra processes permitted during replacement.
    pub max_surge: u32,
    /// Desired replicas permitted to be unavailable while replacing.
    pub max_unavailable: u32,
    /// Intent issuance time.
    pub issued_at: OffsetDateTime,
    /// Hard plan expiration time.
    pub expires_at: OffsetDateTime,
}

/// Immutable, secret-free process specification handed to an orchestrator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaTarget {
    /// Pre-provisioned replica identity.
    pub replica_id: ConnectorReplicaId,
    /// Owning logical instance.
    pub instance_id: ConnectorInstanceId,
    /// Exact admitted version.
    pub version_id: ConnectorVersionId,
    /// Exact OCI digest; mutable tags are never part of this contract.
    pub artifact_digest: String,
    /// Native AIP endpoint registered for the process.
    pub endpoint: String,
    /// Expected process principal id.
    pub peer_principal_id: String,
    /// Expected process `did:key`.
    pub peer_did: String,
    /// Deployment trust domain.
    pub trust_domain: String,
    /// Indexed placement labels.
    pub topology: ConnectorTopology,
    /// Non-secret instance configuration revision.
    pub config_revision: u64,
    /// Opaque reference resolved only by the host deployment.
    pub secret_provider_ref: String,
    /// Maximum concurrency registered by this replica.
    pub capacity: u32,
}

/// Platform observation accepted by the pure reconciler.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedReplica {
    /// Concrete replica identity.
    pub replica_id: ConnectorReplicaId,
    /// Owning instance.
    pub instance_id: ConnectorInstanceId,
    /// Version reported by the immutable process artifact.
    pub version_id: ConnectorVersionId,
    /// Digest reported by the platform runtime.
    pub artifact_digest: String,
    /// Generation applied by the platform.
    pub generation: u64,
    /// Current platform lifecycle phase.
    pub phase: ObservedReplicaPhase,
}

/// Small, stable lifecycle vocabulary shared by orchestrator adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedReplicaPhase {
    /// Process creation has been accepted but readiness is not established.
    Starting,
    /// Process is serving and its registry lease is ready.
    Ready,
    /// Process is completing pinned actions and rejects new assignments.
    Draining,
    /// Process is absent.
    Stopped,
    /// Platform reports a terminal or restartable failure.
    Failed,
}

/// One deterministic external-orchestrator operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum OrchestrationOperation {
    /// Start one exact admitted replica.
    Start {
        /// Complete immutable process target.
        target: ReplicaTarget,
    },
    /// Restart a failed desired replica without changing its identity or digest.
    Restart {
        /// Complete immutable process target.
        target: ReplicaTarget,
    },
    /// Ask a ready replica to drain through the AIP lifecycle control plane.
    Drain {
        /// Replica that must stop receiving new assignments.
        replica_id: ConnectorReplicaId,
        /// Stable machine-readable drain cause.
        reason: String,
    },
    /// Remove a stopped, failed, or fully drained process.
    Stop {
        /// Replica process that must be absent.
        replica_id: ConnectorReplicaId,
        /// Stable machine-readable stop cause.
        reason: String,
    },
}

impl OrchestrationOperation {
    fn replica_id(&self) -> &ConnectorReplicaId {
        match self {
            Self::Start { target } | Self::Restart { target } => &target.replica_id,
            Self::Drain { replica_id, .. } | Self::Stop { replica_id, .. } => replica_id,
        }
    }
}

/// Deterministic plan that is safe to sign and execute idempotently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestrationPlan {
    /// Contract schema.
    pub schema_version: String,
    /// Exact reviewed intent.
    pub intent: DeploymentIntent,
    /// Exact immutable targets used by reconciliation, keyed by replica id.
    ///
    /// The map contains the complete desired set and no unrelated targets. An
    /// executor can therefore re-run the pure reconciler instead of trusting a
    /// signer-supplied operation list in isolation.
    pub targets: BTreeMap<ConnectorReplicaId, ReplicaTarget>,
    /// Canonically ordered platform snapshot used to derive this batch.
    ///
    /// An executor must compare this snapshot with a fresh platform read before
    /// applying the first operation. A mismatch is a stale-plan fence and
    /// requires a new reconciliation cycle.
    pub observed: Vec<ObservedReplica>,
    /// Ordered operations. Empty means the deployment is reconciled.
    pub operations: Vec<OrchestrationOperation>,
}

/// Plan signed by a deployment orchestration authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrchestrationPlan {
    /// Complete deterministic plan.
    pub plan: OrchestrationPlan,
    /// Trusted signing `did:key`.
    pub signer_did: String,
    /// Bounded operator or service identity.
    pub signer_identity: String,
    /// Base64 Ed25519 signature over canonical plan JSON.
    pub signature: String,
}

/// Orchestration validation or reconciliation failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OrchestrationError {
    /// Desired or observed state violates the bounded contract.
    #[error("invalid connector orchestration state: {0}")]
    Invalid(String),
    /// A signed plan failed identity, trust, or signature verification.
    #[error("connector orchestration signature failed: {0}")]
    Signature(String),
}

/// Derives immutable targets and the next safe operation batch.
pub fn reconcile_verified_package(
    verified: &VerifiedAdmissionPackage,
    intent: DeploymentIntent,
    observed: Vec<ObservedReplica>,
    now: OffsetDateTime,
    limits: &OrchestrationLimits,
) -> Result<OrchestrationPlan, OrchestrationError> {
    validate_intent(verified, &intent, now, limits)?;
    if observed.len() > limits.max_observations {
        return Err(OrchestrationError::Invalid(
            "observed replica count exceeds the configured limit".to_owned(),
        ));
    }
    let instance = verified
        .package
        .instances
        .iter()
        .find(|candidate| candidate.id == intent.instance_id)
        .ok_or_else(|| {
            OrchestrationError::Invalid("intent instance is not in the verified package".to_owned())
        })?;
    let targets = verified
        .package
        .replicas
        .iter()
        .filter(|replica| {
            replica.instance_id == intent.instance_id
                && intent.desired_replicas.contains(&replica.id)
        })
        .map(|replica| {
            (
                replica.id.clone(),
                ReplicaTarget {
                    replica_id: replica.id.clone(),
                    instance_id: replica.instance_id.clone(),
                    version_id: replica.version_id.clone(),
                    artifact_digest: verified
                        .connector_version
                        .attestation
                        .artifact_digest
                        .clone(),
                    endpoint: replica.endpoint.clone(),
                    peer_principal_id: replica.peer_principal_id.to_string(),
                    peer_did: replica.peer_did.clone(),
                    trust_domain: replica.trust_domain.clone(),
                    topology: replica.topology.clone(),
                    config_revision: instance.config_revision,
                    secret_provider_ref: instance.secret_provider_ref.clone(),
                    capacity: replica.capacity,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    reconcile_targets(intent, targets, observed, limits)
}

/// Reconciles already verified immutable targets.
pub fn reconcile_targets(
    intent: DeploymentIntent,
    targets: BTreeMap<ConnectorReplicaId, ReplicaTarget>,
    observed: Vec<ObservedReplica>,
    limits: &OrchestrationLimits,
) -> Result<OrchestrationPlan, OrchestrationError> {
    validate_limits(limits)?;
    if observed.len() > limits.max_observations {
        return Err(OrchestrationError::Invalid(
            "observed replica count exceeds the configured limit".to_owned(),
        ));
    }
    if intent.desired_replicas.len() > limits.max_replicas_per_instance {
        return Err(OrchestrationError::Invalid(
            "desired replica count exceeds the configured per-instance limit".to_owned(),
        ));
    }
    let target_ids = targets.keys().cloned().collect::<BTreeSet<_>>();
    if target_ids != intent.desired_replicas {
        return Err(OrchestrationError::Invalid(
            "orchestration targets must exactly match the desired replica set".to_owned(),
        ));
    }
    validate_rollout_budget(&intent, limits)?;
    for replica_id in &intent.desired_replicas {
        let target = targets.get(replica_id).ok_or_else(|| {
            OrchestrationError::Invalid(format!(
                "desired replica `{replica_id}` is not pre-provisioned"
            ))
        })?;
        validate_target(target, &intent.instance_id)?;
    }
    let observations = normalize_observations(&intent, observed, limits)?;

    let desired_count = intent.desired_replicas.len();
    let ready_serving = observations
        .values()
        .filter(|observation| observation.phase == ObservedReplicaPhase::Ready)
        .count();
    let active_count = observations
        .values()
        .filter(|observation| observation.phase != ObservedReplicaPhase::Stopped)
        .count();
    let capacity = desired_count.saturating_add(intent.max_surge as usize);
    let mut start_budget = capacity.saturating_sub(active_count);
    let minimum_ready = desired_count.saturating_sub(intent.max_unavailable as usize);
    let mut drain_budget = ready_serving.saturating_sub(minimum_ready);
    let mut operations = Vec::new();

    for replica_id in &intent.desired_replicas {
        let Some(target) = targets.get(replica_id) else {
            return Err(OrchestrationError::Invalid(format!(
                "desired replica `{replica_id}` disappeared during reconciliation"
            )));
        };
        match observations.get(replica_id) {
            None
            | Some(ObservedReplica {
                phase: ObservedReplicaPhase::Stopped,
                ..
            }) if start_budget > 0 => {
                operations.push(OrchestrationOperation::Start {
                    target: target.clone(),
                });
                start_budget -= 1;
            }
            Some(observation)
                if observation.version_id != target.version_id
                    || observation.artifact_digest != target.artifact_digest =>
            {
                return Err(OrchestrationError::Invalid(format!(
                    "desired replica `{replica_id}` reports a different immutable version or digest; allocate a new replica identity"
                )));
            }
            Some(observation) if observation.generation < intent.generation => {
                match observation.phase {
                    ObservedReplicaPhase::Ready if drain_budget > 0 => {
                        operations.push(OrchestrationOperation::Drain {
                            replica_id: replica_id.clone(),
                            reason: "generation_refresh".to_owned(),
                        });
                        drain_budget -= 1;
                    }
                    ObservedReplicaPhase::Draining | ObservedReplicaPhase::Starting => {
                        operations.push(OrchestrationOperation::Stop {
                            replica_id: replica_id.clone(),
                            reason: "generation_refresh".to_owned(),
                        });
                    }
                    ObservedReplicaPhase::Stopped if start_budget > 0 => {
                        operations.push(OrchestrationOperation::Start {
                            target: target.clone(),
                        });
                        start_budget -= 1;
                    }
                    ObservedReplicaPhase::Failed => {
                        operations.push(OrchestrationOperation::Restart {
                            target: target.clone(),
                        });
                    }
                    ObservedReplicaPhase::Ready | ObservedReplicaPhase::Stopped => {}
                }
            }
            Some(ObservedReplica {
                phase: ObservedReplicaPhase::Failed,
                ..
            }) => {
                operations.push(OrchestrationOperation::Restart {
                    target: target.clone(),
                });
            }
            _ => {}
        }
    }

    for (replica_id, observation) in &observations {
        if intent.desired_replicas.contains(replica_id) {
            continue;
        }
        match observation.phase {
            ObservedReplicaPhase::Ready if desired_count == 0 || drain_budget > 0 => {
                operations.push(OrchestrationOperation::Drain {
                    replica_id: replica_id.clone(),
                    reason: if desired_count == 0 {
                        "scale_to_zero".to_owned()
                    } else if intent.rollback_of_generation.is_some() {
                        "rollback_replacement".to_owned()
                    } else {
                        "rollout_replacement".to_owned()
                    },
                });
                drain_budget = drain_budget.saturating_sub(1);
            }
            ObservedReplicaPhase::Draining
            | ObservedReplicaPhase::Stopped
            | ObservedReplicaPhase::Failed => {
                operations.push(OrchestrationOperation::Stop {
                    replica_id: replica_id.clone(),
                    reason: "replica_not_in_desired_set".to_owned(),
                });
            }
            ObservedReplicaPhase::Starting if desired_count == 0 => {
                operations.push(OrchestrationOperation::Stop {
                    replica_id: replica_id.clone(),
                    reason: "scale_to_zero".to_owned(),
                });
            }
            _ => {}
        }
    }
    operations.sort_by(|left, right| {
        operation_order(left)
            .cmp(&operation_order(right))
            .then_with(|| left.replica_id().cmp(right.replica_id()))
    });
    if operations.len() > limits.max_operations {
        return Err(OrchestrationError::Invalid(
            "reconciliation operation count exceeds the configured limit".to_owned(),
        ));
    }
    Ok(OrchestrationPlan {
        schema_version: ORCHESTRATION_SCHEMA.to_owned(),
        intent,
        targets,
        observed: observations.into_values().collect(),
        operations,
    })
}

/// Signs a deterministic plan for an external executor.
pub fn sign_orchestration_plan(
    plan: OrchestrationPlan,
    signer_did: String,
    signer_identity: String,
    signing_key: &SigningKey,
) -> Result<SignedOrchestrationPlan, OrchestrationError> {
    if signer_identity.trim().is_empty() || signer_identity.len() > 512 {
        return Err(OrchestrationError::Invalid(
            "orchestration signer identity must contain 1 to 512 bytes".to_owned(),
        ));
    }
    let derived_did = did_key_from_verifying_key(&signing_key.verifying_key());
    if signer_did != derived_did {
        return Err(OrchestrationError::Signature(
            "orchestration signer DID does not identify the signing key".to_owned(),
        ));
    }
    let value = serde_json::to_value(&plan)
        .map_err(|error| OrchestrationError::Invalid(error.to_string()))?;
    let signature = sign_value(&value, signing_key)
        .map_err(|error| OrchestrationError::Signature(error.to_string()))?;
    Ok(SignedOrchestrationPlan {
        plan,
        signer_did,
        signer_identity,
        signature,
    })
}

/// Verifies signer trust, plan signature, time bounds, and operation bounds.
pub fn verify_signed_orchestration_plan(
    signed: SignedOrchestrationPlan,
    trusted_signers: &BTreeSet<String>,
    now: OffsetDateTime,
    limits: &OrchestrationLimits,
) -> Result<OrchestrationPlan, OrchestrationError> {
    validate_limits(limits)?;
    if !trusted_signers.contains(&signed.signer_did) {
        return Err(OrchestrationError::Signature(
            "orchestration signer is not trusted".to_owned(),
        ));
    }
    if signed.signer_identity.trim().is_empty() || signed.signer_identity.len() > 512 {
        return Err(OrchestrationError::Invalid(
            "orchestration signer identity must contain 1 to 512 bytes".to_owned(),
        ));
    }
    validate_plan_container_bounds(&signed.plan, limits)?;
    let value = serde_json::to_value(&signed.plan)
        .map_err(|error| OrchestrationError::Invalid(error.to_string()))?;
    let key = verifying_key_from_did_key(&signed.signer_did)
        .map_err(|error| OrchestrationError::Signature(error.to_string()))?;
    verify_value(&value, &signed.signature, &key)
        .map_err(|error| OrchestrationError::Signature(error.to_string()))?;
    validate_plan_shape(&signed.plan, now, limits)?;
    Ok(signed.plan)
}

/// Verifies a signed plan and fences it against a fresh platform snapshot.
///
/// External executors must call this immediately before applying the first
/// operation. A changed phase, generation, version, digest, missing replica,
/// or newly observed replica invalidates the complete batch. After the first
/// operation begins, the executor must durably journal the deterministic
/// operation ids returned by [`orchestration_operation_ids`] and resume only
/// that exact signed plan.
pub fn verify_signed_orchestration_plan_against_observed(
    signed: SignedOrchestrationPlan,
    trusted_signers: &BTreeSet<String>,
    current_observed: Vec<ObservedReplica>,
    now: OffsetDateTime,
    limits: &OrchestrationLimits,
) -> Result<OrchestrationPlan, OrchestrationError> {
    let plan = verify_signed_orchestration_plan(signed, trusted_signers, now, limits)?;
    validate_execution_snapshot(&plan, current_observed, limits)?;
    Ok(plan)
}

/// Validates that a plan was derived from the exact current platform state.
pub fn validate_execution_snapshot(
    plan: &OrchestrationPlan,
    current_observed: Vec<ObservedReplica>,
    limits: &OrchestrationLimits,
) -> Result<(), OrchestrationError> {
    let current = normalize_observations(&plan.intent, current_observed, limits)?
        .into_values()
        .collect::<Vec<_>>();
    if current != plan.observed {
        return Err(OrchestrationError::Invalid(
            "orchestration plan platform snapshot is stale; reconcile a new plan".to_owned(),
        ));
    }
    Ok(())
}

/// Computes stable, secret-free idempotency keys for every operation.
///
/// Platform adapters persist these ids with their execution journal. An
/// operation id is bound to the complete plan digest, operation index, replica,
/// and operation payload, so it cannot be reused across generations or plans.
pub fn orchestration_operation_ids(
    plan: &OrchestrationPlan,
) -> Result<Vec<String>, OrchestrationError> {
    let plan_value = serde_json::to_value(plan)
        .map_err(|error| OrchestrationError::Invalid(error.to_string()))?;
    let plan_digest =
        digest_json(&plan_value).map_err(|error| OrchestrationError::Invalid(error.to_string()))?;
    plan.operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            digest_json(&serde_json::json!({
                "schema_version": ORCHESTRATION_SCHEMA,
                "plan_digest": plan_digest,
                "operation_index": index,
                "replica_id": operation.replica_id(),
                "operation": operation,
            }))
            .map(|digest| format!("orchop_{}", &digest[7..]))
            .map_err(|error| OrchestrationError::Invalid(error.to_string()))
        })
        .collect()
}

fn validate_intent(
    verified: &VerifiedAdmissionPackage,
    intent: &DeploymentIntent,
    now: OffsetDateTime,
    limits: &OrchestrationLimits,
) -> Result<(), OrchestrationError> {
    validate_limits(limits)?;
    if intent.package_id != verified.package.package_id
        || intent.package_revision != verified.package.revision
        || intent.package_digest != verified.package_digest
    {
        return Err(OrchestrationError::Invalid(
            "intent does not identify the verified admission package".to_owned(),
        ));
    }
    let instance = verified
        .package
        .instances
        .iter()
        .find(|candidate| candidate.id == intent.instance_id)
        .ok_or_else(|| {
            OrchestrationError::Invalid("intent instance is not in the verified package".to_owned())
        })?;
    if (!verified.package.connector_type.enabled
        || instance.status == ConnectorInstanceStatus::Disabled)
        && !intent.desired_replicas.is_empty()
    {
        return Err(OrchestrationError::Invalid(
            "disabled connector types and instances must scale to zero".to_owned(),
        ));
    }
    if !intent.desired_replicas.is_empty()
        && verified.connector_version.status != ConnectorVersionStatus::Active
    {
        return Err(OrchestrationError::Invalid(
            "only an active admitted version may start connector processes".to_owned(),
        ));
    }
    validate_rollout_budget(intent, limits)?;
    validate_plan_times(intent, now, limits)
}

fn validate_plan_shape(
    plan: &OrchestrationPlan,
    now: OffsetDateTime,
    limits: &OrchestrationLimits,
) -> Result<(), OrchestrationError> {
    validate_limits(limits)?;
    validate_plan_container_bounds(plan, limits)?;
    if plan.schema_version != ORCHESTRATION_SCHEMA
        || plan.intent.schema_version != ORCHESTRATION_SCHEMA
    {
        return Err(OrchestrationError::Invalid(
            "unsupported orchestration schema".to_owned(),
        ));
    }
    validate_plan_times(&plan.intent, now, limits)?;
    validate_rollout_budget(&plan.intent, limits)?;
    let expected = reconcile_targets(
        plan.intent.clone(),
        plan.targets.clone(),
        plan.observed.clone(),
        limits,
    )?;
    if &expected != plan {
        return Err(OrchestrationError::Invalid(
            "signed orchestration operations are not the deterministic result of the embedded intent, targets, and platform snapshot"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_plan_container_bounds(
    plan: &OrchestrationPlan,
    limits: &OrchestrationLimits,
) -> Result<(), OrchestrationError> {
    if plan.intent.desired_replicas.len() > limits.max_replicas_per_instance
        || plan.targets.len() > limits.max_replicas_per_instance
        || plan.observed.len() > limits.max_observations
        || plan.operations.len() > limits.max_operations
    {
        return Err(OrchestrationError::Invalid(
            "signed plan exceeds configured collection bounds".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_observations(
    intent: &DeploymentIntent,
    observed: Vec<ObservedReplica>,
    limits: &OrchestrationLimits,
) -> Result<BTreeMap<ConnectorReplicaId, ObservedReplica>, OrchestrationError> {
    if observed.len() > limits.max_observations {
        return Err(OrchestrationError::Invalid(
            "observed replica count exceeds the configured limit".to_owned(),
        ));
    }
    let mut observations = BTreeMap::new();
    for observation in observed {
        if observation.instance_id != intent.instance_id {
            return Err(OrchestrationError::Invalid(format!(
                "observed replica `{}` belongs to another instance",
                observation.replica_id
            )));
        }
        if observation.generation == 0 {
            return Err(OrchestrationError::Invalid(format!(
                "observed replica `{}` reports generation zero",
                observation.replica_id
            )));
        }
        if observation.generation > intent.generation {
            return Err(OrchestrationError::Invalid(format!(
                "observed replica `{}` is at generation {}, newer than intent generation {}; the intent is stale",
                observation.replica_id, observation.generation, intent.generation
            )));
        }
        if observations
            .insert(observation.replica_id.clone(), observation)
            .is_some()
        {
            return Err(OrchestrationError::Invalid(
                "observed replica ids must be unique".to_owned(),
            ));
        }
    }
    Ok(observations)
}

fn validate_plan_times(
    intent: &DeploymentIntent,
    now: OffsetDateTime,
    limits: &OrchestrationLimits,
) -> Result<(), OrchestrationError> {
    if intent.schema_version != ORCHESTRATION_SCHEMA || intent.generation == 0 {
        return Err(OrchestrationError::Invalid(
            "intent schema and generation are invalid".to_owned(),
        ));
    }
    if intent.expires_at <= intent.issued_at
        || intent.expires_at - intent.issued_at
            > time::Duration::seconds(limits.max_plan_ttl_seconds)
        || intent.issued_at > now + time::Duration::seconds(limits.max_clock_skew_seconds)
        || intent.expires_at <= now
    {
        return Err(OrchestrationError::Invalid(
            "intent time window is invalid, stale, or too long".to_owned(),
        ));
    }
    if intent.package_id.trim().is_empty()
        || intent.package_id.len() > 256
        || intent.package_revision == 0
        || !is_sha256_digest(&intent.package_digest)
        || intent
            .rollback_of_generation
            .is_some_and(|rollback| rollback == 0 || rollback >= intent.generation)
    {
        return Err(OrchestrationError::Invalid(
            "intent package coordinates are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_limits(limits: &OrchestrationLimits) -> Result<(), OrchestrationError> {
    if limits.max_replicas_per_instance == 0
        || limits.max_observations == 0
        || limits.max_operations == 0
        || !(1..=86_400).contains(&limits.max_plan_ttl_seconds)
        || !(0..=300).contains(&limits.max_clock_skew_seconds)
    {
        return Err(OrchestrationError::Invalid(
            "orchestration limits must be non-zero; plan TTL must be at most one day and clock skew at most five minutes"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_rollout_budget(
    intent: &DeploymentIntent,
    limits: &OrchestrationLimits,
) -> Result<(), OrchestrationError> {
    let desired = intent.desired_replicas.len();
    let max_surge = usize::try_from(intent.max_surge).map_err(|_| {
        OrchestrationError::Invalid("max_surge does not fit this platform".to_owned())
    })?;
    let max_unavailable = usize::try_from(intent.max_unavailable).map_err(|_| {
        OrchestrationError::Invalid("max_unavailable does not fit this platform".to_owned())
    })?;
    if max_surge > limits.max_replicas_per_instance
        || max_unavailable > desired
        || desired.saturating_add(max_surge) > limits.max_replicas_per_instance
    {
        return Err(OrchestrationError::Invalid(
            "rollout surge or unavailability exceeds the desired-set safety bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_target(
    target: &ReplicaTarget,
    instance_id: &ConnectorInstanceId,
) -> Result<(), OrchestrationError> {
    let endpoint = Url::parse(&target.endpoint).map_err(|_| {
        OrchestrationError::Invalid(format!(
            "replica target `{}` has an invalid native AIP endpoint",
            target.replica_id
        ))
    })?;
    let endpoint_valid = endpoint.scheme() == "https"
        && endpoint.host_str().is_some()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
        && endpoint.path() == "/aip/v1/messages";
    let principal_valid = PrincipalId::parse(target.peer_principal_id.clone()).is_ok();
    let did_valid = verifying_key_from_did_key(&target.peer_did).is_ok();
    if &target.instance_id != instance_id
        || target.config_revision == 0
        || target.capacity == 0
        || !endpoint_valid
        || target.endpoint.len() > 2_048
        || target.secret_provider_ref.trim().is_empty()
        || target.secret_provider_ref.len() > 2_048
        || !is_sha256_digest(&target.artifact_digest)
        || !principal_valid
        || !did_valid
    {
        return Err(OrchestrationError::Invalid(format!(
            "replica target `{}` is not an immutable bounded deployment",
            target.replica_id
        )));
    }
    for value in [
        target.peer_principal_id.as_str(),
        target.peer_did.as_str(),
        target.trust_domain.as_str(),
        target.topology.region.as_str(),
        target.topology.zone.as_str(),
        target.topology.capacity_class.as_str(),
    ] {
        if value.trim().is_empty() || value.len() > 512 {
            return Err(OrchestrationError::Invalid(format!(
                "replica target `{}` contains invalid identity or topology metadata",
                target.replica_id
            )));
        }
    }
    Ok(())
}

fn operation_order(operation: &OrchestrationOperation) -> u8 {
    match operation {
        OrchestrationOperation::Start { .. } | OrchestrationOperation::Restart { .. } => 0,
        OrchestrationOperation::Drain { .. } => 1,
        OrchestrationOperation::Stop { .. } => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_connector_registry::ConnectorTopology;
    use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed};

    fn id(value: &str) -> ConnectorReplicaId {
        ConnectorReplicaId::trusted(value)
    }

    fn intent(desired: &[&str]) -> DeploymentIntent {
        let now = OffsetDateTime::now_utc();
        DeploymentIntent {
            schema_version: ORCHESTRATION_SCHEMA.to_owned(),
            generation: 3,
            rollback_of_generation: None,
            package_id: "release-crewai".to_owned(),
            package_revision: 7,
            package_digest: format!("sha256:{}", "b".repeat(64)),
            instance_id: ConnectorInstanceId::trusted("cinst_acme"),
            desired_replicas: desired.iter().map(|value| id(value)).collect(),
            max_surge: 1,
            max_unavailable: 0,
            issued_at: now - time::Duration::seconds(1),
            expires_at: now + time::Duration::minutes(2),
        }
    }

    fn target(replica_id: &str, version: &str) -> ReplicaTarget {
        let peer_key = signing_key_from_seed([17; 32]);
        ReplicaTarget {
            replica_id: id(replica_id),
            instance_id: ConnectorInstanceId::trusted("cinst_acme"),
            version_id: ConnectorVersionId::trusted(version),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            endpoint: format!("https://{replica_id}.connectors.internal/aip/v1/messages"),
            peer_principal_id: format!("agent:{replica_id}"),
            peer_did: did_key_from_verifying_key(&peer_key.verifying_key()),
            trust_domain: "production".to_owned(),
            topology: ConnectorTopology {
                region: "eu-west-1".to_owned(),
                zone: "eu-west-1a".to_owned(),
                capacity_class: "standard".to_owned(),
            },
            config_revision: 4,
            secret_provider_ref: "vault://connectors/acme".to_owned(),
            capacity: 32,
        }
    }

    fn observed(replica_id: &str, version: &str, phase: ObservedReplicaPhase) -> ObservedReplica {
        ObservedReplica {
            replica_id: id(replica_id),
            instance_id: ConnectorInstanceId::trusted("cinst_acme"),
            version_id: ConnectorVersionId::trusted(version),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            generation: 3,
            phase,
        }
    }

    fn observed_at_generation(
        replica_id: &str,
        version: &str,
        generation: u64,
        phase: ObservedReplicaPhase,
    ) -> ObservedReplica {
        let mut observation = observed(replica_id, version, phase);
        observation.generation = generation;
        observation
    }

    #[test]
    fn rollout_starts_new_digest_before_draining_old_replica() {
        let mut targets = BTreeMap::new();
        targets.insert(id("crepl_new"), target("crepl_new", "cver_v2"));
        let plan = reconcile_targets(
            intent(&["crepl_new"]),
            targets,
            vec![observed(
                "crepl_old",
                "cver_v1",
                ObservedReplicaPhase::Ready,
            )],
            &OrchestrationLimits::default(),
        )
        .expect("reconcile rollout");
        assert!(matches!(
            plan.operations.as_slice(),
            [OrchestrationOperation::Start { .. }]
        ));
    }

    #[test]
    fn ready_replacement_allows_old_replica_to_drain() {
        let mut targets = BTreeMap::new();
        targets.insert(id("crepl_new"), target("crepl_new", "cver_v2"));
        let plan = reconcile_targets(
            intent(&["crepl_new"]),
            targets,
            vec![
                observed("crepl_new", "cver_v2", ObservedReplicaPhase::Ready),
                observed("crepl_old", "cver_v1", ObservedReplicaPhase::Ready),
            ],
            &OrchestrationLimits::default(),
        )
        .expect("reconcile replacement");
        assert!(matches!(
            plan.operations.as_slice(),
            [OrchestrationOperation::Drain { replica_id, .. }] if replica_id == &id("crepl_old")
        ));
    }

    #[test]
    fn empty_desired_set_drains_and_stops_without_starting() {
        let plan = reconcile_targets(
            intent(&[]),
            BTreeMap::new(),
            vec![
                observed("crepl_ready", "cver_v1", ObservedReplicaPhase::Ready),
                observed("crepl_draining", "cver_v1", ObservedReplicaPhase::Draining),
            ],
            &OrchestrationLimits::default(),
        )
        .expect("scale to zero");
        assert_eq!(plan.operations.len(), 2);
        assert!(matches!(
            plan.operations[0],
            OrchestrationOperation::Drain { .. }
        ));
        assert!(matches!(
            plan.operations[1],
            OrchestrationOperation::Stop { .. }
        ));
    }

    #[test]
    fn signed_plan_detects_mutation() {
        let key = signing_key_from_seed([9; 32]);
        let did = did_key_from_verifying_key(&key.verifying_key());
        let plan = OrchestrationPlan {
            schema_version: ORCHESTRATION_SCHEMA.to_owned(),
            intent: intent(&[]),
            targets: BTreeMap::new(),
            observed: Vec::new(),
            operations: Vec::new(),
        };
        let mut signed =
            sign_orchestration_plan(plan, did.clone(), "deployment-controller".to_owned(), &key)
                .expect("sign plan");
        let trusted = BTreeSet::from([did]);
        verify_signed_orchestration_plan(
            signed.clone(),
            &trusted,
            OffsetDateTime::now_utc(),
            &OrchestrationLimits::default(),
        )
        .expect("verify plan");
        signed.plan.intent.generation += 1;
        assert!(matches!(
            verify_signed_orchestration_plan(
                signed,
                &trusted,
                OffsetDateTime::now_utc(),
                &OrchestrationLimits::default()
            ),
            Err(OrchestrationError::Signature(_))
        ));
    }

    #[test]
    fn stale_intent_is_fenced_by_a_newer_observed_generation() {
        let mut targets = BTreeMap::new();
        targets.insert(id("crepl_new"), target("crepl_new", "cver_v2"));
        let error = reconcile_targets(
            intent(&["crepl_new"]),
            targets,
            vec![observed_at_generation(
                "crepl_new",
                "cver_v2",
                4,
                ObservedReplicaPhase::Ready,
            )],
            &OrchestrationLimits::default(),
        )
        .expect_err("newer observation must fence a stale intent");
        assert!(matches!(
            error,
            OrchestrationError::Invalid(message) if message.contains("intent is stale")
        ));
    }

    #[test]
    fn older_generation_is_drained_within_unavailability_budget() {
        let mut rollout = intent(&["crepl_a", "crepl_b"]);
        rollout.max_unavailable = 1;
        let targets = BTreeMap::from([
            (id("crepl_a"), target("crepl_a", "cver_v2")),
            (id("crepl_b"), target("crepl_b", "cver_v2")),
        ]);
        let plan = reconcile_targets(
            rollout,
            targets,
            vec![
                observed_at_generation("crepl_a", "cver_v2", 2, ObservedReplicaPhase::Ready),
                observed_at_generation("crepl_b", "cver_v2", 2, ObservedReplicaPhase::Ready),
            ],
            &OrchestrationLimits::default(),
        )
        .expect("reconcile generation refresh");
        assert!(matches!(
            plan.operations.as_slice(),
            [OrchestrationOperation::Drain { reason, .. }] if reason == "generation_refresh"
        ));
    }

    #[test]
    fn plan_signer_did_must_match_the_signing_key() {
        let key = signing_key_from_seed([9; 32]);
        let other_key = signing_key_from_seed([10; 32]);
        let plan = OrchestrationPlan {
            schema_version: ORCHESTRATION_SCHEMA.to_owned(),
            intent: intent(&[]),
            targets: BTreeMap::new(),
            observed: Vec::new(),
            operations: Vec::new(),
        };
        assert!(matches!(
            sign_orchestration_plan(
                plan,
                did_key_from_verifying_key(&other_key.verifying_key()),
                "deployment-controller".to_owned(),
                &key,
            ),
            Err(OrchestrationError::Signature(message)) if message.contains("signing key")
        ));
    }

    #[test]
    fn signed_plan_is_rederived_and_fenced_to_its_platform_snapshot() {
        let key = signing_key_from_seed([19; 32]);
        let did = did_key_from_verifying_key(&key.verifying_key());
        let targets = BTreeMap::from([(id("crepl_new"), target("crepl_new", "cver_v2"))]);
        let snapshot = vec![observed(
            "crepl_old",
            "cver_v1",
            ObservedReplicaPhase::Ready,
        )];
        let plan = reconcile_targets(
            intent(&["crepl_new"]),
            targets,
            snapshot.clone(),
            &OrchestrationLimits::default(),
        )
        .expect("reconcile signed plan");
        let signed = sign_orchestration_plan(
            plan.clone(),
            did.clone(),
            "deployment-controller".to_owned(),
            &key,
        )
        .expect("sign plan");
        let trusted = BTreeSet::from([did]);
        let verified = verify_signed_orchestration_plan_against_observed(
            signed.clone(),
            &trusted,
            snapshot,
            OffsetDateTime::now_utc(),
            &OrchestrationLimits::default(),
        )
        .expect("verify exact snapshot");
        assert_eq!(verified, plan);

        let mut changed = verified.observed.clone();
        changed[0].phase = ObservedReplicaPhase::Draining;
        assert!(matches!(
            verify_signed_orchestration_plan_against_observed(
                signed,
                &trusted,
                changed,
                OffsetDateTime::now_utc(),
                &OrchestrationLimits::default(),
            ),
            Err(OrchestrationError::Invalid(message)) if message.contains("snapshot is stale")
        ));
    }

    #[test]
    fn verifier_rejects_a_validly_signed_non_deterministic_operation_batch() {
        let key = signing_key_from_seed([20; 32]);
        let did = did_key_from_verifying_key(&key.verifying_key());
        let mut plan = reconcile_targets(
            intent(&["crepl_new"]),
            BTreeMap::from([(id("crepl_new"), target("crepl_new", "cver_v2"))]),
            Vec::new(),
            &OrchestrationLimits::default(),
        )
        .expect("reconcile plan");
        plan.operations.clear();
        let signed =
            sign_orchestration_plan(plan, did.clone(), "compromised-controller".to_owned(), &key)
                .expect("cryptographically valid but semantically invalid plan");
        assert!(matches!(
            verify_signed_orchestration_plan(
                signed,
                &BTreeSet::from([did]),
                OffsetDateTime::now_utc(),
                &OrchestrationLimits::default(),
            ),
            Err(OrchestrationError::Invalid(message)) if message.contains("deterministic result")
        ));
    }

    #[test]
    fn operation_ids_are_stable_and_bound_to_the_complete_plan() {
        let plan = reconcile_targets(
            intent(&["crepl_new"]),
            BTreeMap::from([(id("crepl_new"), target("crepl_new", "cver_v2"))]),
            Vec::new(),
            &OrchestrationLimits::default(),
        )
        .expect("reconcile plan");
        let first = orchestration_operation_ids(&plan).expect("operation ids");
        let second = orchestration_operation_ids(&plan).expect("stable operation ids");
        assert_eq!(first, second);
        assert_eq!(first.len(), plan.operations.len());
        assert!(first.iter().all(|value| value.len() == 71));

        let mut next_generation = plan;
        next_generation.intent.generation += 1;
        assert_ne!(
            first,
            orchestration_operation_ids(&next_generation).expect("new generation ids")
        );
    }

    #[test]
    fn unrelated_targets_are_rejected_before_plan_creation() {
        let targets = BTreeMap::from([
            (id("crepl_new"), target("crepl_new", "cver_v2")),
            (id("crepl_hidden"), target("crepl_hidden", "cver_v2")),
        ]);
        assert!(matches!(
            reconcile_targets(
                intent(&["crepl_new"]),
                targets,
                Vec::new(),
                &OrchestrationLimits::default(),
            ),
            Err(OrchestrationError::Invalid(message)) if message.contains("exactly match")
        ));
    }
}
