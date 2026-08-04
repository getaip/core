//! Cryptographic admission pipeline for immutable connector artifacts.
//!
//! This crate is the only supported bridge between build evidence and mutable
//! connector-registry administration. A signed package binds an OCI digest,
//! manifest, implementation claims, topology, instances, tenant bindings, and
//! seven independently signed evidence documents. Verification derives the
//! registry [`ArtifactAttestation`];
//! callers cannot self-assert `Passed` statuses.
//!
//! Application is deliberately restartable. The durable journal claims one
//! `(package_id, revision, digest)` before any catalog write. Every registry
//! write is idempotent, and a failed process resumes the exact package. This
//! provides a safe multi-step commit without granting long-running data-plane
//! processes catalog-administrator credentials.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use aip_connector_registry::{
    AdmissionPolicy, ArtifactAttestation, ArtifactCheckStatus, CapabilityBinding,
    ConnectorInstance, ConnectorRegistryAdmin, ConnectorReplica, ConnectorType, ConnectorTypeId,
    ConnectorVersion, ConnectorVersionId, ConnectorVersionStatus, RegistryError, RegistryLimits,
    digest_json, schema_bundle_digest, validate_connector_version,
};
use aip_core::{Manifest, MessageId};
use aip_crypto::{
    did_key_from_verifying_key, sign_value, verify_value, verifying_key_from_did_key,
};
use aip_discovery::CapabilityImplementationSupport;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Signed-package schema accepted by this release.
pub const ADMISSION_PACKAGE_SCHEMA: &str = "aip.connector-admission/v1";
/// Evidence-statement schema accepted by this release.
pub const EVIDENCE_STATEMENT_SCHEMA: &str = "aip.connector-evidence/v1";
const ADMISSION_CLAIM_LEASE: Duration = Duration::minutes(5);

/// Mandatory evidence families for a production connector artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Detached signature statement over the immutable OCI digest.
    OciSignature,
    /// SPDX or CycloneDX software bill of materials.
    Sbom,
    /// Build provenance binding source and builder to the artifact.
    Provenance,
    /// AIP connector conformance report.
    Conformance,
    /// Vulnerability-policy evaluation for the exact artifact and SBOM.
    Vulnerability,
    /// License-policy evaluation for the exact artifact and SBOM.
    License,
    /// Non-revocation observation for the artifact and signer.
    Revocation,
}

impl EvidenceKind {
    /// Returns every evidence family required by the admission schema.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::OciSignature,
            Self::Sbom,
            Self::Provenance,
            Self::Conformance,
            Self::Vulnerability,
            Self::License,
            Self::Revocation,
        ]
    }

    /// Returns the only policy outcome accepted for this evidence family.
    #[must_use]
    pub const fn required_outcome(self) -> EvidenceOutcome {
        match self {
            Self::OciSignature | Self::Sbom | Self::Provenance => EvidenceOutcome::Verified,
            Self::Conformance | Self::Vulnerability | Self::License | Self::Revocation => {
                EvidenceOutcome::Passed
            }
        }
    }
}

/// Cryptographically signed policy outcome for one evidence document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    /// Structural evidence exists and its subject is cryptographically bound.
    Verified,
    /// A policy evaluator accepted the evidence.
    Passed,
    /// A policy evaluator rejected the evidence.
    Failed,
}

/// Canonical statement signed independently for one evidence document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStatement {
    /// Evidence schema identifier.
    pub schema_version: String,
    /// Evidence family.
    pub kind: EvidenceKind,
    /// Exact OCI or artifact digest evaluated by this statement.
    pub artifact_digest: String,
    /// Canonical connector manifest digest evaluated by this statement.
    pub manifest_digest: String,
    /// Canonical digest of the embedded document.
    pub document_digest: String,
    /// Human- or service-readable signer identity.
    pub signer_identity: String,
    /// Statement creation time.
    pub issued_at: OffsetDateTime,
    /// Hard expiration time; stale scans cannot admit a new version.
    pub expires_at: OffsetDateTime,
    /// Signed evaluation outcome.
    pub outcome: EvidenceOutcome,
}

/// One independently signed evidence document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedEvidence {
    /// Canonical signed statement.
    pub statement: EvidenceStatement,
    /// Complete evidence payload retained by the release pipeline.
    pub document: Value,
    /// Ed25519 `did:key` that signed the statement.
    pub signer_did: String,
    /// Base64 Ed25519 signature over the canonical statement.
    pub signature: String,
}

/// Immutable version fields declared before admission derives trusted evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectorVersionDeclaration {
    /// Stable immutable version record id.
    pub id: ConnectorVersionId,
    /// Owning connector type.
    pub connector_type_id: ConnectorTypeId,
    /// Human-readable release version.
    pub version: String,
    /// Requested post-admission lifecycle status.
    pub status: ConnectorVersionStatus,
    /// Exact bounded connector manifest.
    pub manifest: Manifest,
    /// Canonical manifest digest.
    pub manifest_digest: String,
    /// Exact immutable OCI or artifact digest.
    pub artifact_digest: String,
    /// Runtime support for every callable capability.
    pub implementation_support: BTreeMap<aip_core::CapabilityId, CapabilityImplementationSupport>,
    /// AIP versions asserted by the signed release package.
    pub supported_aip_versions: BTreeSet<String>,
    /// Cargo-style version requirement for the connector SDK.
    pub sdk_version_requirement: String,
}

/// Declarative catalog change signed by the connector release authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmissionPackage {
    /// Package schema identifier.
    pub schema_version: String,
    /// Stable package stream id.
    pub package_id: String,
    /// Monotonic package revision.
    pub revision: u64,
    /// Package creation time.
    pub issued_at: OffsetDateTime,
    /// Package expiration time.
    pub expires_at: OffsetDateTime,
    /// Connector implementation family.
    pub connector_type: ConnectorType,
    /// Immutable implementation release.
    pub version: ConnectorVersionDeclaration,
    /// Hard admission policies created before bindings.
    #[serde(default)]
    pub admission_policies: Vec<AdmissionPolicy>,
    /// Tenant-owned connector instances.
    #[serde(default)]
    pub instances: Vec<ConnectorInstance>,
    /// Pre-provisioned replica identities. Hosts later renew their leases.
    #[serde(default)]
    pub replicas: Vec<ConnectorReplica>,
    /// Tenant capability bindings.
    #[serde(default)]
    pub bindings: Vec<CapabilityBinding>,
    /// Complete independently signed evidence set.
    pub evidence: BTreeMap<EvidenceKind, SignedEvidence>,
}

/// Root signature over one complete admission package.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedAdmissionPackage {
    /// Complete declarative payload.
    pub package: AdmissionPackage,
    /// Trusted release authority `did:key`.
    pub signer_did: String,
    /// Human- or service-readable release authority identity.
    pub signer_identity: String,
    /// Base64 Ed25519 signature over canonical package JSON.
    pub signature: String,
}

/// Deployment-owned limits and trust roots for admission verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionTrustPolicy {
    /// Ed25519 `did:key` values authorized to sign complete release packages.
    pub trusted_package_signer_dids: BTreeSet<String>,
    /// Evidence-policy trust roots keyed by mandatory evidence family.
    ///
    /// Each family must have at least one explicit root. A broad release key
    /// therefore cannot silently self-assert scanner or conformance outcomes.
    pub trusted_evidence_signer_dids: BTreeMap<EvidenceKind, BTreeSet<String>>,
    /// Require the package and all seven evidence statements to use distinct
    /// signing identities, enforcing separation of release duties.
    pub require_distinct_signers: bool,
    /// Optional connector owner required by this registry boundary.
    pub required_owner: Option<String>,
    /// Maximum canonical package size.
    pub max_package_bytes: usize,
    /// Maximum embedded evidence document size.
    pub max_evidence_document_bytes: usize,
    /// Maximum instances in one operation.
    pub max_instances: usize,
    /// Maximum pre-provisioned replicas in one operation.
    pub max_replicas: usize,
    /// Maximum tenant bindings in one operation.
    pub max_bindings: usize,
    /// Maximum accepted clock lead for signed timestamps.
    pub max_clock_skew_seconds: i64,
}

impl Default for AdmissionTrustPolicy {
    fn default() -> Self {
        Self {
            trusted_package_signer_dids: BTreeSet::new(),
            trusted_evidence_signer_dids: BTreeMap::new(),
            require_distinct_signers: true,
            required_owner: None,
            max_package_bytes: 16 * 1024 * 1024,
            max_evidence_document_bytes: 8 * 1024 * 1024,
            max_instances: 10_000,
            max_replicas: 50_000,
            max_bindings: 100_000,
            max_clock_skew_seconds: 300,
        }
    }
}

/// Package after all signatures, evidence, bounds, and registry invariants pass.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedAdmissionPackage {
    /// Canonical signed-package digest used for replay fencing.
    pub package_digest: String,
    /// Verified package payload.
    pub package: AdmissionPackage,
    /// Registry-ready connector version with derived attestation statuses.
    pub connector_version: ConnectorVersion,
    /// Verified release authority identity.
    pub signer_identity: String,
}

/// Durable operator operation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOperationState {
    /// Exact operation is claimed and may be resumed.
    Applying,
    /// Every catalog mutation completed.
    Applied,
    /// A resumable step failed.
    Failed,
    /// An operator terminalized a failed revision without admitting traffic.
    Abandoned,
    /// New traffic was disabled by an explicit revoke operation.
    Revoked,
}

/// Secret-free durable audit record for one package revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionOperation {
    /// Stable package id.
    pub package_id: String,
    /// Monotonic package revision.
    pub revision: u64,
    /// Canonical signed-package digest.
    pub package_digest: String,
    /// Connector type affected by the operation.
    pub connector_type_id: ConnectorTypeId,
    /// Immutable version affected by the operation.
    pub version_id: ConnectorVersionId,
    /// Verified release authority identity.
    pub signer_identity: String,
    /// Unique owner of the current fenced application attempt.
    pub claim_id: String,
    /// Deadline after which another operator process may recover the claim.
    pub claim_expires_at: OffsetDateTime,
    /// Current operation state.
    pub state: AdmissionOperationState,
    /// Bounded last failure without credential material.
    pub last_error: Option<String>,
    /// Last durable state transition.
    pub updated_at: OffsetDateTime,
}

/// Result of claiming a durable operator operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionOperationClaim {
    /// No earlier operation existed.
    New,
    /// The same digest can safely resume after interruption.
    Resume,
    /// The exact operation already completed.
    AlreadyApplied,
}

/// Durable journal implemented by short-lived catalog administrator backends.
#[async_trait]
pub trait AdmissionJournal: Send + Sync {
    /// Claims or resumes the exact signed operation.
    async fn claim_admission_operation(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationClaim, AdmissionError>;

    /// Extends the active fenced claim before another idempotent catalog step.
    async fn renew_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: &str,
        claim_expires_at: OffsetDateTime,
    ) -> Result<(), AdmissionError>;

    /// Marks the exact operation applied.
    async fn complete_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: &str,
    ) -> Result<(), AdmissionError>;

    /// Records a bounded resumable failure.
    async fn fail_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: &str,
        error: &str,
    ) -> Result<(), AdmissionError>;

    /// Reads one exact operation or the latest revision when revision is absent.
    async fn admission_operation(
        &self,
        package_id: &str,
        revision: Option<u64>,
    ) -> Result<Option<AdmissionOperation>, AdmissionError>;

    /// Marks an applied operation revoked after catalog traffic is disabled.
    async fn revoke_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        reason: &str,
    ) -> Result<(), AdmissionError>;

    /// Terminalizes one failed revision so a higher revision may be claimed.
    async fn abandon_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        reason: &str,
    ) -> Result<(), AdmissionError>;
}

/// Admission pipeline failure.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// Package or policy structure is invalid.
    #[error("invalid connector admission package: {0}")]
    Invalid(String),
    /// A signature or signer trust decision failed.
    #[error("connector admission signature failed: {0}")]
    Signature(String),
    /// Evidence is missing, stale, mismatched, or rejected.
    #[error("connector admission evidence failed: {0}")]
    Evidence(String),
    /// Registry mutation failed.
    #[error("connector admission registry operation failed: {0}")]
    Registry(String),
    /// Durable operator journal failed.
    #[error("connector admission journal failed: {0}")]
    Journal(String),
    /// Exact operation conflicts with an earlier digest or terminal revoke.
    #[error("connector admission operation conflict: {0}")]
    Conflict(String),
}

impl From<RegistryError> for AdmissionError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value.to_string())
    }
}

/// Verifies one complete signed package and derives its trusted attestation.
pub fn verify_admission_package(
    signed: SignedAdmissionPackage,
    policy: &AdmissionTrustPolicy,
    now: OffsetDateTime,
) -> Result<VerifiedAdmissionPackage, AdmissionError> {
    validate_policy(policy)?;
    let signed_value = serde_json::to_value(&signed)
        .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    let signed_bytes = aip_crypto::canonical_json_bytes(&signed_value)
        .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    if signed_bytes.len() > policy.max_package_bytes {
        return Err(AdmissionError::Invalid(format!(
            "canonical package is {} bytes; limit is {}",
            signed_bytes.len(),
            policy.max_package_bytes
        )));
    }
    require_trusted_signer(
        &signed.signer_did,
        &policy.trusted_package_signer_dids,
        "admission package",
    )?;
    if signed.signer_identity.trim().is_empty() || signed.signer_identity.len() > 512 {
        return Err(AdmissionError::Invalid(
            "package signer identity must contain 1 to 512 bytes".to_owned(),
        ));
    }
    let package_value = serde_json::to_value(&signed.package)
        .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    let package_key = verifying_key_from_did_key(&signed.signer_did)
        .map_err(|error| AdmissionError::Signature(error.to_string()))?;
    verify_value(&package_value, &signed.signature, &package_key)
        .map_err(|error| AdmissionError::Signature(error.to_string()))?;

    let package = &signed.package;
    if package.schema_version != ADMISSION_PACKAGE_SCHEMA {
        return Err(AdmissionError::Invalid(format!(
            "unsupported package schema `{}`",
            package.schema_version
        )));
    }
    validate_identifier("package id", &package.package_id, 256)?;
    if package.revision == 0 {
        return Err(AdmissionError::Invalid(
            "package revision must be greater than zero".to_owned(),
        ));
    }
    validate_time_window(
        "admission package",
        package.issued_at,
        package.expires_at,
        now,
        policy.max_clock_skew_seconds,
    )?;
    if package.instances.len() > policy.max_instances
        || package.replicas.len() > policy.max_replicas
        || package.bindings.len() > policy.max_bindings
    {
        return Err(AdmissionError::Invalid(
            "package exceeds configured instance, replica, or binding limits".to_owned(),
        ));
    }
    if let Some(owner) = policy.required_owner.as_deref()
        && package.connector_type.owner != owner
    {
        return Err(AdmissionError::Invalid(format!(
            "connector owner `{}` does not match required owner `{owner}`",
            package.connector_type.owner
        )));
    }
    if package.version.connector_type_id != package.connector_type.id {
        return Err(AdmissionError::Invalid(
            "version connector type does not match package connector type".to_owned(),
        ));
    }
    if package.version.status == ConnectorVersionStatus::Candidate
        || package.version.status == ConnectorVersionStatus::Revoked
    {
        return Err(AdmissionError::Invalid(
            "admission package version must request admitted or active status".to_owned(),
        ));
    }
    let manifest_value = serde_json::to_value(&package.version.manifest)
        .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    let manifest_digest = digest_json(&manifest_value)?;
    if manifest_digest != package.version.manifest_digest {
        return Err(AdmissionError::Invalid(
            "declared manifest digest does not match canonical manifest".to_owned(),
        ));
    }

    for instance in &package.instances {
        if instance.connector_type_id != package.connector_type.id
            || instance.version_id != package.version.id
        {
            return Err(AdmissionError::Invalid(format!(
                "instance `{}` is not bound to the package type and version",
                instance.id
            )));
        }
    }
    let instance_ids = package
        .instances
        .iter()
        .map(|instance| (&instance.id, &instance.tenant_id))
        .collect::<BTreeMap<_, _>>();
    for replica in &package.replicas {
        if replica.version_id != package.version.id
            || !instance_ids.contains_key(&replica.instance_id)
            || replica.status != aip_connector_registry::ConnectorReplicaStatus::Offline
            || replica.active_assignments != 0
        {
            return Err(AdmissionError::Invalid(format!(
                "replica `{}` must be offline, empty, and bound to a package instance/version",
                replica.id
            )));
        }
    }
    for binding in &package.bindings {
        let Some(tenant_id) = instance_ids.get(&binding.instance_id) else {
            return Err(AdmissionError::Invalid(format!(
                "binding references unknown package instance `{}`",
                binding.instance_id
            )));
        };
        if *tenant_id != &binding.tenant_id {
            return Err(AdmissionError::Invalid(
                "binding tenant does not own its package instance".to_owned(),
            ));
        }
    }

    let evidence = verify_evidence_set(package, policy, now, &signed.signer_did)?;
    let attestation = ArtifactAttestation {
        artifact_digest: package.version.artifact_digest.clone(),
        schema_bundle_digest: schema_bundle_digest(&package.version.manifest)?,
        sbom_digest: evidence[&EvidenceKind::Sbom]
            .statement
            .document_digest
            .clone(),
        provenance_digest: evidence[&EvidenceKind::Provenance]
            .statement
            .document_digest
            .clone(),
        conformance_report_digest: evidence[&EvidenceKind::Conformance]
            .statement
            .document_digest
            .clone(),
        vulnerability_report_digest: evidence[&EvidenceKind::Vulnerability]
            .statement
            .document_digest
            .clone(),
        license_report_digest: evidence[&EvidenceKind::License]
            .statement
            .document_digest
            .clone(),
        signature_ref: format!(
            "{}#{}",
            evidence[&EvidenceKind::OciSignature].signer_did,
            evidence[&EvidenceKind::OciSignature]
                .statement
                .document_digest
        ),
        signer_identity: signed.signer_identity.clone(),
        owner: package.connector_type.owner.clone(),
        supported_aip_versions: package.version.supported_aip_versions.clone(),
        sdk_version_requirement: package.version.sdk_version_requirement.clone(),
        conformance_status: ArtifactCheckStatus::Passed,
        vulnerability_policy_status: ArtifactCheckStatus::Passed,
        license_policy_status: ArtifactCheckStatus::Passed,
        revocation_status: ArtifactCheckStatus::Passed,
    };
    let connector_version = ConnectorVersion {
        id: package.version.id.clone(),
        connector_type_id: package.version.connector_type_id.clone(),
        version: package.version.version.clone(),
        status: package.version.status,
        manifest: package.version.manifest.clone(),
        manifest_digest: package.version.manifest_digest.clone(),
        attestation,
        implementation_support: package.version.implementation_support.clone(),
        admitted_at: now,
    };
    validate_connector_version(&connector_version, &RegistryLimits::default())?;
    let package_digest = digest_json(&signed_value)?;
    Ok(VerifiedAdmissionPackage {
        package_digest,
        package: signed.package,
        connector_version,
        signer_identity: signed.signer_identity,
    })
}

fn verify_evidence_set<'a>(
    package: &'a AdmissionPackage,
    policy: &AdmissionTrustPolicy,
    now: OffsetDateTime,
    package_signer_did: &str,
) -> Result<&'a BTreeMap<EvidenceKind, SignedEvidence>, AdmissionError> {
    let mut observed_signers = BTreeSet::from([package_signer_did.to_owned()]);
    for kind in EvidenceKind::all() {
        let evidence = package.evidence.get(&kind).ok_or_else(|| {
            AdmissionError::Evidence(format!("mandatory `{kind:?}` evidence is missing"))
        })?;
        if evidence.statement.schema_version != EVIDENCE_STATEMENT_SCHEMA
            || evidence.statement.kind != kind
            || evidence.statement.artifact_digest != package.version.artifact_digest
            || evidence.statement.manifest_digest != package.version.manifest_digest
        {
            return Err(AdmissionError::Evidence(format!(
                "`{kind:?}` statement does not match its package subject"
            )));
        }
        let trusted_signers = policy
            .trusted_evidence_signer_dids
            .get(&kind)
            .ok_or_else(|| {
                AdmissionError::Signature(format!(
                    "admission policy has no trust roots for `{kind:?}` evidence"
                ))
            })?;
        require_trusted_signer(
            &evidence.signer_did,
            trusted_signers,
            &format!("{kind:?} evidence"),
        )?;
        if policy.require_distinct_signers && !observed_signers.insert(evidence.signer_did.clone())
        {
            return Err(AdmissionError::Signature(format!(
                "`{kind:?}` evidence reuses a signing identity while distinct signers are required"
            )));
        }
        if evidence.statement.signer_identity.trim().is_empty()
            || evidence.statement.signer_identity.len() > 512
        {
            return Err(AdmissionError::Evidence(format!(
                "`{kind:?}` signer identity must contain 1 to 512 bytes"
            )));
        }
        validate_time_window(
            "evidence statement",
            evidence.statement.issued_at,
            evidence.statement.expires_at,
            now,
            policy.max_clock_skew_seconds,
        )?;
        let document_value = &evidence.document;
        let document_bytes = aip_crypto::canonical_json_bytes(document_value)
            .map_err(|error| AdmissionError::Evidence(error.to_string()))?;
        if document_bytes.len() > policy.max_evidence_document_bytes {
            return Err(AdmissionError::Evidence(format!(
                "`{kind:?}` document exceeds the configured byte limit"
            )));
        }
        let document_digest = digest_json(document_value)?;
        if document_digest != evidence.statement.document_digest {
            return Err(AdmissionError::Evidence(format!(
                "`{kind:?}` document digest does not match its statement"
            )));
        }
        let statement_value = serde_json::to_value(&evidence.statement)
            .map_err(|error| AdmissionError::Evidence(error.to_string()))?;
        let key = verifying_key_from_did_key(&evidence.signer_did)
            .map_err(|error| AdmissionError::Signature(error.to_string()))?;
        verify_value(&statement_value, &evidence.signature, &key)
            .map_err(|error| AdmissionError::Signature(error.to_string()))?;
        let required_outcome = kind.required_outcome();
        if evidence.statement.outcome != required_outcome {
            return Err(AdmissionError::Evidence(format!(
                "`{kind:?}` outcome did not satisfy admission policy"
            )));
        }
    }
    if package.evidence.len() != EvidenceKind::all().len() {
        return Err(AdmissionError::Evidence(
            "package contains an unsupported evidence family".to_owned(),
        ));
    }
    Ok(&package.evidence)
}

/// Applies one verified package through idempotent, durably journaled steps.
pub async fn apply_verified_package<R>(
    registry: &R,
    verified: &VerifiedAdmissionPackage,
) -> Result<AdmissionOperation, AdmissionError>
where
    R: ConnectorRegistryAdmin + AdmissionJournal,
{
    let operation = AdmissionOperation {
        package_id: verified.package.package_id.clone(),
        revision: verified.package.revision,
        package_digest: verified.package_digest.clone(),
        connector_type_id: verified.package.connector_type.id.clone(),
        version_id: verified.connector_version.id.clone(),
        signer_identity: verified.signer_identity.clone(),
        claim_id: MessageId::new().to_string(),
        claim_expires_at: OffsetDateTime::now_utc() + ADMISSION_CLAIM_LEASE,
        state: AdmissionOperationState::Applying,
        last_error: None,
        updated_at: OffsetDateTime::now_utc(),
    };
    let claim = registry
        .claim_admission_operation(operation.clone())
        .await?;
    if claim == AdmissionOperationClaim::AlreadyApplied {
        return registry
            .admission_operation(&operation.package_id, Some(operation.revision))
            .await?
            .ok_or_else(|| {
                AdmissionError::Journal(
                    "applied operation disappeared from the durable journal".to_owned(),
                )
            });
    }
    let result = apply_catalog_steps(registry, verified, &operation).await;
    if let Err(error) = &result {
        let detail = bounded_detail(error.to_string());
        registry
            .fail_admission_operation(
                &operation.package_id,
                operation.revision,
                &operation.package_digest,
                &operation.claim_id,
                &detail,
            )
            .await?;
    }
    result?;
    registry
        .complete_admission_operation(
            &operation.package_id,
            operation.revision,
            &operation.package_digest,
            &operation.claim_id,
        )
        .await?;
    registry
        .admission_operation(&operation.package_id, Some(operation.revision))
        .await?
        .ok_or_else(|| {
            AdmissionError::Journal(
                "completed operation disappeared from the durable journal".to_owned(),
            )
        })
}

async fn apply_catalog_steps<R>(
    registry: &R,
    verified: &VerifiedAdmissionPackage,
    operation: &AdmissionOperation,
) -> Result<(), AdmissionError>
where
    R: ConnectorRegistryAdmin + AdmissionJournal,
{
    for policy in &verified.package.admission_policies {
        renew_admission_claim(registry, operation).await?;
        registry.put_admission_policy(policy.clone()).await?;
    }
    renew_admission_claim(registry, operation).await?;
    registry
        .put_connector_type(verified.package.connector_type.clone())
        .await?;
    renew_admission_claim(registry, operation).await?;
    if let Err(error) = registry
        .admit_version(verified.connector_version.clone())
        .await
    {
        // A prior attempt may have committed the immutable version before a
        // later instance, replica, or binding step failed. A freshly signed
        // retry legitimately carries new evidence-document digests and an
        // admission timestamp, so the complete record is not byte-identical.
        // Reuse only the already qualified record for the exact same binary,
        // manifest, implementation support, and policy-derived properties;
        // every material runtime or contract change still fails closed.
        let reusable = registry
            .connector_version(&verified.connector_version.id)
            .await?
            .is_some_and(|existing| {
                same_admitted_release_identity(&existing, &verified.connector_version)
            });
        if !reusable {
            return Err(error.into());
        }
    }
    for instance in &verified.package.instances {
        renew_admission_claim(registry, operation).await?;
        registry.put_instance(instance.clone()).await?;
    }
    for replica in &verified.package.replicas {
        renew_admission_claim(registry, operation).await?;
        registry.put_replica(replica.clone()).await?;
    }
    for binding in &verified.package.bindings {
        renew_admission_claim(registry, operation).await?;
        registry.put_binding(binding.clone()).await?;
    }
    Ok(())
}

fn same_admitted_release_identity(
    existing: &ConnectorVersion,
    candidate: &ConnectorVersion,
) -> bool {
    existing.id == candidate.id
        && existing.connector_type_id == candidate.connector_type_id
        && existing.version == candidate.version
        && existing.status == candidate.status
        && existing.manifest == candidate.manifest
        && existing.manifest_digest == candidate.manifest_digest
        && existing.attestation.artifact_digest == candidate.attestation.artifact_digest
        && existing.attestation.schema_bundle_digest == candidate.attestation.schema_bundle_digest
        && existing.attestation.owner == candidate.attestation.owner
        && existing.attestation.supported_aip_versions
            == candidate.attestation.supported_aip_versions
        && existing.attestation.sdk_version_requirement
            == candidate.attestation.sdk_version_requirement
        && existing.attestation.conformance_status == candidate.attestation.conformance_status
        && existing.attestation.vulnerability_policy_status
            == candidate.attestation.vulnerability_policy_status
        && existing.attestation.license_policy_status == candidate.attestation.license_policy_status
        && existing.attestation.revocation_status == candidate.attestation.revocation_status
        && existing.implementation_support == candidate.implementation_support
}

async fn renew_admission_claim<R>(
    registry: &R,
    operation: &AdmissionOperation,
) -> Result<(), AdmissionError>
where
    R: AdmissionJournal,
{
    registry
        .renew_admission_operation(
            &operation.package_id,
            operation.revision,
            &operation.package_digest,
            &operation.claim_id,
            OffsetDateTime::now_utc() + ADMISSION_CLAIM_LEASE,
        )
        .await
}

/// Revokes one applied package and stops all new traffic for its exact version.
///
/// The connector type remains enabled so an independent admitted version of
/// the same connector can continue serving traffic. Type-wide emergency stops
/// are a separate operator action exposed by [`ConnectorRegistryAdmin`].
pub async fn revoke_applied_package<R>(
    registry: &R,
    package_id: &str,
    revision: u64,
    reason: &str,
) -> Result<AdmissionOperation, AdmissionError>
where
    R: ConnectorRegistryAdmin + AdmissionJournal,
{
    validate_identifier("revoke reason", reason, 1_024)?;
    let operation = registry
        .admission_operation(package_id, Some(revision))
        .await?
        .ok_or_else(|| AdmissionError::Conflict("admission operation was not found".to_owned()))?;
    if operation.state == AdmissionOperationState::Revoked {
        return Ok(operation);
    }
    if operation.state != AdmissionOperationState::Applied {
        return Err(AdmissionError::Conflict(
            "only an applied package can be revoked".to_owned(),
        ));
    }
    registry
        .set_version_status(&operation.version_id, ConnectorVersionStatus::Revoked)
        .await?;
    registry
        .revoke_admission_operation(package_id, revision, reason)
        .await?;
    registry
        .admission_operation(package_id, Some(revision))
        .await?
        .ok_or_else(|| {
            AdmissionError::Journal(
                "revoked operation disappeared from the durable journal".to_owned(),
            )
        })
}

/// Terminalizes one failed package while preserving its complete audit row.
///
/// This does not alter an admitted connector version or disable traffic: a
/// failed admission never reached the applied state. It exists specifically to
/// unblock a corrected higher revision after an operator has determined that
/// resuming the exact failed package can never succeed.
pub async fn abandon_failed_package<R>(
    registry: &R,
    package_id: &str,
    revision: u64,
    reason: &str,
) -> Result<AdmissionOperation, AdmissionError>
where
    R: AdmissionJournal,
{
    validate_identifier("abandon reason", reason, 1_024)?;
    let operation = registry
        .admission_operation(package_id, Some(revision))
        .await?
        .ok_or_else(|| AdmissionError::Conflict("admission operation was not found".to_owned()))?;
    if operation.state == AdmissionOperationState::Abandoned {
        return Ok(operation);
    }
    if operation.state != AdmissionOperationState::Failed {
        return Err(AdmissionError::Conflict(
            "only a failed package can be abandoned".to_owned(),
        ));
    }
    registry
        .abandon_admission_operation(package_id, revision, reason)
        .await?;
    registry
        .admission_operation(package_id, Some(revision))
        .await?
        .ok_or_else(|| {
            AdmissionError::Journal(
                "abandoned operation disappeared from the durable journal".to_owned(),
            )
        })
}

/// Signs one evidence statement with an Ed25519 release-policy key.
pub fn sign_evidence(
    statement: EvidenceStatement,
    document: Value,
    signing_key: &SigningKey,
) -> Result<SignedEvidence, AdmissionError> {
    let expected = digest_json(&document)?;
    if statement.document_digest != expected {
        return Err(AdmissionError::Invalid(
            "evidence statement document digest does not match the supplied document".to_owned(),
        ));
    }
    let value = serde_json::to_value(&statement)
        .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    let signature = sign_value(&value, signing_key)
        .map_err(|error| AdmissionError::Signature(error.to_string()))?;
    Ok(SignedEvidence {
        statement,
        document,
        signer_did: did_key_from_verifying_key(&signing_key.verifying_key()),
        signature,
    })
}

/// Signs one complete admission package with an Ed25519 release-authority key.
pub fn sign_admission_package(
    package: AdmissionPackage,
    signer_identity: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedAdmissionPackage, AdmissionError> {
    let value = serde_json::to_value(&package)
        .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    let signature = sign_value(&value, signing_key)
        .map_err(|error| AdmissionError::Signature(error.to_string()))?;
    Ok(SignedAdmissionPackage {
        package,
        signer_did: did_key_from_verifying_key(&signing_key.verifying_key()),
        signer_identity: signer_identity.into(),
        signature,
    })
}

fn require_trusted_signer(
    signer_did: &str,
    trusted_signer_dids: &BTreeSet<String>,
    role: &str,
) -> Result<(), AdmissionError> {
    if !trusted_signer_dids.contains(signer_did) {
        return Err(AdmissionError::Signature(format!(
            "{role} signer `{signer_did}` is not trusted by admission policy"
        )));
    }
    verifying_key_from_did_key(signer_did)
        .map(|_| ())
        .map_err(|error| AdmissionError::Signature(error.to_string()))
}

fn validate_policy(policy: &AdmissionTrustPolicy) -> Result<(), AdmissionError> {
    if policy.trusted_package_signer_dids.is_empty()
        || policy.max_package_bytes == 0
        || policy.max_evidence_document_bytes == 0
        || policy.max_instances == 0
        || policy.max_replicas == 0
        || policy.max_bindings == 0
        || !(0..=3_600).contains(&policy.max_clock_skew_seconds)
    {
        return Err(AdmissionError::Invalid(
            "admission trust policy requires trust roots and non-zero bounded limits".to_owned(),
        ));
    }
    for signer in &policy.trusted_package_signer_dids {
        verifying_key_from_did_key(signer)
            .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
    }
    for kind in EvidenceKind::all() {
        let roots = policy
            .trusted_evidence_signer_dids
            .get(&kind)
            .filter(|roots| !roots.is_empty())
            .ok_or_else(|| {
                AdmissionError::Invalid(format!(
                    "admission trust policy requires at least one `{kind:?}` evidence signer"
                ))
            })?;
        for signer in roots {
            verifying_key_from_did_key(signer)
                .map_err(|error| AdmissionError::Invalid(error.to_string()))?;
        }
    }
    Ok(())
}

fn validate_time_window(
    label: &str,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
    skew_seconds: i64,
) -> Result<(), AdmissionError> {
    let skew = time::Duration::seconds(skew_seconds);
    if expires_at <= issued_at || issued_at > now + skew || expires_at <= now {
        return Err(AdmissionError::Evidence(format!(
            "{label} is expired, not yet valid, or has an invalid time window"
        )));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str, max: usize) -> Result<(), AdmissionError> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(AdmissionError::Invalid(format!(
            "{label} must contain 1 to {max} printable bytes"
        )));
    }
    Ok(())
}

fn bounded_detail(mut detail: String) -> String {
    detail.truncate(1_024);
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_connector_registry::{
        CapabilityBinding, ConnectorInstance, ConnectorInstanceId, ConnectorRegistryReader,
        ConnectorReplica, ConnectorReplicaId, InMemoryConnectorRegistry,
    };
    use aip_core::{
        AIP_VERSION, Capability, CapabilityId, CapabilityKind, Principal, PrincipalId,
        PrincipalKind, ProfileId,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use time::Duration;
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct TestRegistry {
        registry: InMemoryConnectorRegistry,
        operations: Arc<Mutex<BTreeMap<(String, u64), AdmissionOperation>>>,
        type_disable_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ConnectorRegistryReader for TestRegistry {
        async fn connector_version(
            &self,
            version_id: &ConnectorVersionId,
        ) -> Result<Option<ConnectorVersion>, RegistryError> {
            self.registry.connector_version(version_id).await
        }

        async fn connector_instance(
            &self,
            instance_id: &ConnectorInstanceId,
        ) -> Result<Option<ConnectorInstance>, RegistryError> {
            self.registry.connector_instance(instance_id).await
        }

        async fn connector_replica(
            &self,
            replica_id: &ConnectorReplicaId,
        ) -> Result<Option<ConnectorReplica>, RegistryError> {
            self.registry.connector_replica(replica_id).await
        }
    }

    #[async_trait]
    impl ConnectorRegistryAdmin for TestRegistry {
        async fn put_admission_policy(&self, policy: AdmissionPolicy) -> Result<(), RegistryError> {
            self.registry.put_admission_policy(policy).await
        }

        async fn put_connector_type(
            &self,
            connector_type: ConnectorType,
        ) -> Result<(), RegistryError> {
            self.registry.put_connector_type(connector_type).await
        }

        async fn set_connector_type_enabled(
            &self,
            connector_type_id: &ConnectorTypeId,
            enabled: bool,
        ) -> Result<(), RegistryError> {
            if !enabled {
                self.type_disable_calls.fetch_add(1, Ordering::SeqCst);
            }
            self.registry
                .set_connector_type_enabled(connector_type_id, enabled)
                .await
        }

        async fn admit_version(&self, version: ConnectorVersion) -> Result<(), RegistryError> {
            self.registry.admit_version(version).await
        }

        async fn set_version_status(
            &self,
            version_id: &ConnectorVersionId,
            status: ConnectorVersionStatus,
        ) -> Result<(), RegistryError> {
            self.registry.set_version_status(version_id, status).await
        }

        async fn put_instance(&self, instance: ConnectorInstance) -> Result<(), RegistryError> {
            self.registry.put_instance(instance).await
        }

        async fn put_replica(&self, replica: ConnectorReplica) -> Result<(), RegistryError> {
            self.registry.put_replica(replica).await
        }

        async fn put_binding(&self, binding: CapabilityBinding) -> Result<(), RegistryError> {
            self.registry.put_binding(binding).await
        }
    }

    #[async_trait]
    impl AdmissionJournal for TestRegistry {
        async fn claim_admission_operation(
            &self,
            mut operation: AdmissionOperation,
        ) -> Result<AdmissionOperationClaim, AdmissionError> {
            let key = (operation.package_id.clone(), operation.revision);
            let mut operations = self.operations.lock().await;
            let latest = operations
                .range((operation.package_id.clone(), 0)..=(operation.package_id.clone(), u64::MAX))
                .next_back()
                .map(|(_, operation)| operation.clone());
            if let Some(latest) = latest {
                if latest.revision > operation.revision {
                    return Err(AdmissionError::Conflict(format!(
                        "package `{}` revision {} is stale; revision {} is already durable",
                        operation.package_id, operation.revision, latest.revision
                    )));
                }
                if latest.revision < operation.revision
                    && matches!(
                        latest.state,
                        AdmissionOperationState::Applying | AdmissionOperationState::Failed
                    )
                {
                    return Err(AdmissionError::Conflict(format!(
                        "package `{}` revision {} must be completed before revision {} can be claimed",
                        operation.package_id, latest.revision, operation.revision
                    )));
                }
            }
            if let Some(existing) = operations.get_mut(&key) {
                if existing.package_digest != operation.package_digest
                    || existing.connector_type_id != operation.connector_type_id
                    || existing.version_id != operation.version_id
                {
                    return Err(AdmissionError::Conflict(
                        "operation revision was already claimed with different content".to_owned(),
                    ));
                }
                return match existing.state {
                    AdmissionOperationState::Applied => Ok(AdmissionOperationClaim::AlreadyApplied),
                    AdmissionOperationState::Abandoned | AdmissionOperationState::Revoked => {
                        Err(AdmissionError::Conflict(
                            "terminal admission operation cannot be resumed".to_owned(),
                        ))
                    }
                    AdmissionOperationState::Applying
                        if existing.claim_expires_at > OffsetDateTime::now_utc()
                            && existing.claim_id != operation.claim_id =>
                    {
                        Err(AdmissionError::Conflict(
                            "operation is owned by another live admission claim".to_owned(),
                        ))
                    }
                    AdmissionOperationState::Applying | AdmissionOperationState::Failed => {
                        existing.state = AdmissionOperationState::Applying;
                        existing.claim_id = operation.claim_id;
                        existing.claim_expires_at = operation.claim_expires_at;
                        existing.last_error = None;
                        existing.updated_at = OffsetDateTime::now_utc();
                        Ok(AdmissionOperationClaim::Resume)
                    }
                };
            }
            operation.state = AdmissionOperationState::Applying;
            operations.insert(key, operation);
            Ok(AdmissionOperationClaim::New)
        }

        async fn renew_admission_operation(
            &self,
            package_id: &str,
            revision: u64,
            package_digest: &str,
            claim_id: &str,
            claim_expires_at: OffsetDateTime,
        ) -> Result<(), AdmissionError> {
            let mut operations = self.operations.lock().await;
            let operation = operations
                .get_mut(&(package_id.to_owned(), revision))
                .ok_or_else(|| AdmissionError::Journal("operation is missing".to_owned()))?;
            if operation.package_digest != package_digest
                || operation.claim_id != claim_id
                || operation.state != AdmissionOperationState::Applying
            {
                return Err(AdmissionError::Conflict(
                    "admission claim was superseded or is no longer active".to_owned(),
                ));
            }
            operation.claim_expires_at = claim_expires_at;
            operation.updated_at = OffsetDateTime::now_utc();
            Ok(())
        }

        async fn complete_admission_operation(
            &self,
            package_id: &str,
            revision: u64,
            package_digest: &str,
            claim_id: &str,
        ) -> Result<(), AdmissionError> {
            self.update_operation(
                package_id,
                revision,
                package_digest,
                Some(claim_id),
                AdmissionOperationState::Applied,
                None,
            )
            .await
        }

        async fn fail_admission_operation(
            &self,
            package_id: &str,
            revision: u64,
            package_digest: &str,
            claim_id: &str,
            error: &str,
        ) -> Result<(), AdmissionError> {
            self.update_operation(
                package_id,
                revision,
                package_digest,
                Some(claim_id),
                AdmissionOperationState::Failed,
                Some(error.to_owned()),
            )
            .await
        }

        async fn admission_operation(
            &self,
            package_id: &str,
            revision: Option<u64>,
        ) -> Result<Option<AdmissionOperation>, AdmissionError> {
            let operations = self.operations.lock().await;
            if let Some(revision) = revision {
                return Ok(operations.get(&(package_id.to_owned(), revision)).cloned());
            }
            Ok(operations
                .iter()
                .filter(|((candidate, _), _)| candidate == package_id)
                .max_by_key(|((_, revision), _)| *revision)
                .map(|(_, operation)| operation.clone()))
        }

        async fn revoke_admission_operation(
            &self,
            package_id: &str,
            revision: u64,
            reason: &str,
        ) -> Result<(), AdmissionError> {
            let digest = self
                .admission_operation(package_id, Some(revision))
                .await?
                .ok_or_else(|| AdmissionError::Journal("operation is missing".to_owned()))?
                .package_digest;
            self.update_operation(
                package_id,
                revision,
                &digest,
                None,
                AdmissionOperationState::Revoked,
                Some(reason.to_owned()),
            )
            .await
        }

        async fn abandon_admission_operation(
            &self,
            package_id: &str,
            revision: u64,
            reason: &str,
        ) -> Result<(), AdmissionError> {
            let digest = self
                .admission_operation(package_id, Some(revision))
                .await?
                .ok_or_else(|| AdmissionError::Journal("operation is missing".to_owned()))?
                .package_digest;
            self.update_operation(
                package_id,
                revision,
                &digest,
                None,
                AdmissionOperationState::Abandoned,
                Some(reason.to_owned()),
            )
            .await
        }
    }

    impl TestRegistry {
        async fn update_operation(
            &self,
            package_id: &str,
            revision: u64,
            package_digest: &str,
            claim_id: Option<&str>,
            state: AdmissionOperationState,
            detail: Option<String>,
        ) -> Result<(), AdmissionError> {
            let mut operations = self.operations.lock().await;
            let operation = operations
                .get_mut(&(package_id.to_owned(), revision))
                .ok_or_else(|| AdmissionError::Journal("operation is missing".to_owned()))?;
            if operation.package_digest != package_digest {
                return Err(AdmissionError::Conflict(
                    "operation digest does not match".to_owned(),
                ));
            }
            if claim_id.is_some_and(|claim_id| operation.claim_id != claim_id) {
                return Err(AdmissionError::Conflict(
                    "admission claim was superseded".to_owned(),
                ));
            }
            let allowed = matches!(
                (operation.state, state),
                (
                    AdmissionOperationState::Applying,
                    AdmissionOperationState::Applied
                ) | (
                    AdmissionOperationState::Applying,
                    AdmissionOperationState::Failed
                ) | (
                    AdmissionOperationState::Applied,
                    AdmissionOperationState::Applied
                ) | (
                    AdmissionOperationState::Failed,
                    AdmissionOperationState::Failed
                ) | (
                    AdmissionOperationState::Failed,
                    AdmissionOperationState::Abandoned
                ) | (
                    AdmissionOperationState::Abandoned,
                    AdmissionOperationState::Abandoned
                ) | (
                    AdmissionOperationState::Applied,
                    AdmissionOperationState::Revoked
                ) | (
                    AdmissionOperationState::Revoked,
                    AdmissionOperationState::Revoked
                )
            );
            if !allowed {
                return Err(AdmissionError::Conflict(
                    "admission operation state transition is invalid".to_owned(),
                ));
            }
            operation.state = state;
            operation.last_error = detail;
            operation.claim_expires_at = OffsetDateTime::now_utc();
            operation.updated_at = OffsetDateTime::now_utc();
            Ok(())
        }
    }

    struct Fixture {
        signed: SignedAdmissionPackage,
        policy: AdmissionTrustPolicy,
        package_signing_key: SigningKey,
        evidence_signing_keys: BTreeMap<EvidenceKind, SigningKey>,
        now: OffsetDateTime,
    }

    fn fixture() -> Fixture {
        let now = OffsetDateTime::now_utc();
        let package_signing_key = SigningKey::from_bytes(&[41_u8; 32]);
        let package_signer_did = did_key_from_verifying_key(&package_signing_key.verifying_key());
        let capability_id = CapabilityId::trusted("cap:test:admission");
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::trusted("service:test-admission-host"),
                PrincipalKind::Service,
            ),
            capabilities: vec![Capability {
                id: capability_id.clone(),
                name: "Admission test action".to_owned(),
                kind: CapabilityKind::Tool,
                input_schema: json!({ "type": "object" }),
                output_schema: Some(json!({ "type": "object" })),
                description: Some("Cryptographic admission fixture".to_owned()),
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
        let manifest_digest =
            digest_json(&serde_json::to_value(&manifest).expect("serialize manifest"))
                .expect("digest manifest");
        let artifact_digest =
            digest_json(&json!({ "artifact": "admission-test" })).expect("digest artifact fixture");
        let mut evidence = BTreeMap::new();
        let evidence_signing_keys = EvidenceKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| (kind, SigningKey::from_bytes(&[50 + index as u8; 32])))
            .collect::<BTreeMap<_, _>>();
        for kind in EvidenceKind::all() {
            let document = json!({
                "kind": kind,
                "artifact_digest": artifact_digest,
                "result": "fixture"
            });
            let statement = EvidenceStatement {
                schema_version: EVIDENCE_STATEMENT_SCHEMA.to_owned(),
                kind,
                artifact_digest: artifact_digest.clone(),
                manifest_digest: manifest_digest.clone(),
                document_digest: digest_json(&document).expect("digest evidence"),
                signer_identity: "https://ci.getaip.example/admission-test".to_owned(),
                issued_at: now - Duration::minutes(1),
                expires_at: now + Duration::hours(1),
                outcome: match kind {
                    EvidenceKind::OciSignature | EvidenceKind::Sbom | EvidenceKind::Provenance => {
                        EvidenceOutcome::Verified
                    }
                    EvidenceKind::Conformance
                    | EvidenceKind::Vulnerability
                    | EvidenceKind::License
                    | EvidenceKind::Revocation => EvidenceOutcome::Passed,
                },
            };
            evidence.insert(
                kind,
                sign_evidence(statement, document, &evidence_signing_keys[&kind])
                    .expect("sign evidence"),
            );
        }
        let connector_type_id = ConnectorTypeId::new();
        let version_id = ConnectorVersionId::new();
        let package = AdmissionPackage {
            schema_version: ADMISSION_PACKAGE_SCHEMA.to_owned(),
            package_id: "admission-test-package".to_owned(),
            revision: 1,
            issued_at: now - Duration::minutes(1),
            expires_at: now + Duration::hours(1),
            connector_type: ConnectorType {
                id: connector_type_id.clone(),
                name: "Admission test connector".to_owned(),
                owner: "WAI LLC".to_owned(),
                enabled: true,
            },
            version: ConnectorVersionDeclaration {
                id: version_id,
                connector_type_id,
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest,
                manifest_digest,
                artifact_digest,
                implementation_support: BTreeMap::from([(
                    capability_id,
                    CapabilityImplementationSupport {
                        invocation: true,
                        ..CapabilityImplementationSupport::default()
                    },
                )]),
                supported_aip_versions: BTreeSet::from([AIP_VERSION.to_owned()]),
                sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
            },
            admission_policies: Vec::new(),
            instances: Vec::new(),
            replicas: Vec::new(),
            bindings: Vec::new(),
            evidence,
        };
        let signed = sign_admission_package(
            package,
            "https://ci.getaip.example/release-authority",
            &package_signing_key,
        )
        .expect("sign package");
        Fixture {
            signed,
            policy: AdmissionTrustPolicy {
                trusted_package_signer_dids: BTreeSet::from([package_signer_did]),
                trusted_evidence_signer_dids: evidence_signing_keys
                    .iter()
                    .map(|(kind, key)| {
                        (
                            *kind,
                            BTreeSet::from([did_key_from_verifying_key(&key.verifying_key())]),
                        )
                    })
                    .collect(),
                required_owner: Some("WAI LLC".to_owned()),
                ..AdmissionTrustPolicy::default()
            },
            package_signing_key,
            evidence_signing_keys,
            now,
        }
    }

    fn resign(fixture: &Fixture, package: AdmissionPackage) -> SignedAdmissionPackage {
        sign_admission_package(
            package,
            "https://ci.getaip.example/release-authority",
            &fixture.package_signing_key,
        )
        .expect("resign package")
    }

    #[test]
    fn complete_evidence_set_derives_registry_attestation() {
        let fixture = fixture();
        let verified = verify_admission_package(fixture.signed, &fixture.policy, fixture.now)
            .expect("verify complete package");
        assert_eq!(
            verified.connector_version.status,
            ConnectorVersionStatus::Active
        );
        assert_eq!(verified.connector_version.attestation.owner, "WAI LLC");
        assert_eq!(
            verified
                .connector_version
                .attestation
                .vulnerability_policy_status,
            ArtifactCheckStatus::Passed
        );
    }

    #[test]
    fn refreshed_evidence_can_resume_the_exact_admitted_release_only() {
        let fixture = fixture();
        let verified = verify_admission_package(fixture.signed, &fixture.policy, fixture.now)
            .expect("verify complete package");
        let existing = verified.connector_version.clone();
        let mut refreshed = existing.clone();
        refreshed.admitted_at += Duration::minutes(1);
        refreshed.attestation.sbom_digest =
            digest_json(&json!({ "sbom": "refreshed" })).expect("digest refreshed SBOM");
        refreshed.attestation.signature_ref = "did:key:refreshed#signature".to_owned();
        assert!(same_admitted_release_identity(&existing, &refreshed));

        refreshed.manifest_digest =
            digest_json(&json!({ "manifest": "different" })).expect("digest changed manifest");
        assert!(!same_admitted_release_identity(&existing, &refreshed));
    }

    #[test]
    fn tampered_document_is_rejected_after_root_is_resigned() {
        let fixture = fixture();
        let mut package = fixture.signed.package.clone();
        package
            .evidence
            .get_mut(&EvidenceKind::Sbom)
            .expect("SBOM evidence")
            .document = json!({ "tampered": true });
        let signed = resign(&fixture, package);
        assert!(matches!(
            verify_admission_package(signed, &fixture.policy, fixture.now),
            Err(AdmissionError::Evidence(message)) if message.contains("document digest")
        ));
    }

    #[test]
    fn missing_mandatory_evidence_is_rejected() {
        let fixture = fixture();
        let mut package = fixture.signed.package.clone();
        package.evidence.remove(&EvidenceKind::Revocation);
        let signed = resign(&fixture, package);
        assert!(matches!(
            verify_admission_package(signed, &fixture.policy, fixture.now),
            Err(AdmissionError::Evidence(message)) if message.contains("missing")
        ));
    }

    #[test]
    fn self_asserted_policy_outcome_cannot_replace_required_verification() {
        let fixture = fixture();
        let mut package = fixture.signed.package.clone();
        let evidence = package
            .evidence
            .get_mut(&EvidenceKind::OciSignature)
            .expect("OCI signature evidence");
        let document = evidence.document.clone();
        let mut statement = evidence.statement.clone();
        statement.outcome = EvidenceOutcome::Passed;
        *evidence = sign_evidence(
            statement,
            document,
            &fixture.evidence_signing_keys[&EvidenceKind::OciSignature],
        )
        .expect("resign evidence");
        let signed = resign(&fixture, package);
        assert!(matches!(
            verify_admission_package(signed, &fixture.policy, fixture.now),
            Err(AdmissionError::Evidence(message)) if message.contains("outcome")
        ));
    }

    #[test]
    fn evidence_from_an_untrusted_signer_is_rejected() {
        let fixture = fixture();
        let untrusted = SigningKey::from_bytes(&[99_u8; 32]);
        let mut package = fixture.signed.package.clone();
        let evidence = package
            .evidence
            .get_mut(&EvidenceKind::License)
            .expect("license evidence");
        *evidence = sign_evidence(
            evidence.statement.clone(),
            evidence.document.clone(),
            &untrusted,
        )
        .expect("sign untrusted evidence");
        let signed = resign(&fixture, package);
        assert!(matches!(
            verify_admission_package(signed, &fixture.policy, fixture.now),
            Err(AdmissionError::Signature(message)) if message.contains("not trusted")
        ));
    }

    #[test]
    fn evidence_roles_cannot_reuse_one_trusted_signing_identity() {
        let mut fixture = fixture();
        let shared_key = &fixture.evidence_signing_keys[&EvidenceKind::Sbom];
        let shared_did = did_key_from_verifying_key(&shared_key.verifying_key());
        fixture
            .policy
            .trusted_evidence_signer_dids
            .get_mut(&EvidenceKind::License)
            .expect("license trust roots")
            .insert(shared_did);
        let mut package = fixture.signed.package.clone();
        let evidence = package
            .evidence
            .get_mut(&EvidenceKind::License)
            .expect("license evidence");
        *evidence = sign_evidence(
            evidence.statement.clone(),
            evidence.document.clone(),
            shared_key,
        )
        .expect("sign duplicate-role evidence");
        let signed = resign(&fixture, package);
        assert!(matches!(
            verify_admission_package(signed, &fixture.policy, fixture.now),
            Err(AdmissionError::Signature(message)) if message.contains("distinct signers")
        ));
    }

    #[tokio::test]
    async fn apply_is_restartable_and_revoke_is_terminal() {
        let fixture = fixture();
        let verified = verify_admission_package(fixture.signed, &fixture.policy, fixture.now)
            .expect("verify complete package");
        let registry = TestRegistry::default();
        let first = apply_verified_package(&registry, &verified)
            .await
            .expect("apply package");
        assert_eq!(first.state, AdmissionOperationState::Applied);
        let replay = apply_verified_package(&registry, &verified)
            .await
            .expect("replay exact package");
        assert_eq!(replay, first);
        assert!(
            registry
                .connector_version(&verified.connector_version.id)
                .await
                .expect("read version")
                .is_some()
        );

        let revoked = revoke_applied_package(
            &registry,
            &verified.package.package_id,
            verified.package.revision,
            "operator security revocation",
        )
        .await
        .expect("revoke package");
        assert_eq!(revoked.state, AdmissionOperationState::Revoked);
        assert_eq!(
            registry.type_disable_calls.load(Ordering::SeqCst),
            0,
            "revoking one version must not disable sibling versions of its connector type"
        );
        assert!(matches!(
            apply_verified_package(&registry, &verified).await,
            Err(AdmissionError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn admission_claims_fence_stale_and_overlapping_revisions() {
        let registry = TestRegistry::default();
        let operation = |revision: u64| AdmissionOperation {
            package_id: "package:fenced".to_owned(),
            revision,
            package_digest: format!("sha256:{revision:064x}"),
            connector_type_id: ConnectorTypeId::trusted("ctype_fenced"),
            version_id: ConnectorVersionId::trusted(format!("cver_fenced_{revision}")),
            signer_identity: "release:test".to_owned(),
            claim_id: format!("claim-{revision}"),
            claim_expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            state: AdmissionOperationState::Applying,
            last_error: None,
            updated_at: OffsetDateTime::now_utc(),
        };

        assert_eq!(
            registry
                .claim_admission_operation(operation(2))
                .await
                .expect("claim revision two"),
            AdmissionOperationClaim::New
        );
        assert!(matches!(
            registry.claim_admission_operation(operation(1)).await,
            Err(AdmissionError::Conflict(message)) if message.contains("stale")
        ));
        assert!(matches!(
            registry.claim_admission_operation(operation(3)).await,
            Err(AdmissionError::Conflict(message)) if message.contains("must be completed")
        ));

        let revision_two = operation(2);
        let mut competing_revision_two = revision_two.clone();
        competing_revision_two.claim_id = "competing-claim-2".to_owned();
        assert!(matches!(
            registry
                .claim_admission_operation(competing_revision_two)
                .await,
            Err(AdmissionError::Conflict(message)) if message.contains("live admission claim")
        ));
        registry
            .complete_admission_operation(
                &revision_two.package_id,
                revision_two.revision,
                &revision_two.package_digest,
                &revision_two.claim_id,
            )
            .await
            .expect("complete revision two");
        assert_eq!(
            registry
                .claim_admission_operation(operation(3))
                .await
                .expect("claim next revision"),
            AdmissionOperationClaim::New
        );
        let revision_three = operation(3);
        registry
            .fail_admission_operation(
                &revision_three.package_id,
                revision_three.revision,
                &revision_three.package_digest,
                &revision_three.claim_id,
                "interrupted",
            )
            .await
            .expect("record resumable failure");
        assert!(matches!(
            registry.claim_admission_operation(operation(4)).await,
            Err(AdmissionError::Conflict(message)) if message.contains("must be completed")
        ));
        let abandoned = abandon_failed_package(
            &registry,
            &revision_three.package_id,
            revision_three.revision,
            "superseded by a corrected immutable contract",
        )
        .await
        .expect("abandon irrecoverable failed revision");
        assert_eq!(abandoned.state, AdmissionOperationState::Abandoned);
        assert!(matches!(
            registry.claim_admission_operation(operation(3)).await,
            Err(AdmissionError::Conflict(message)) if message.contains("terminal")
        ));
        assert_eq!(
            registry
                .claim_admission_operation(operation(4))
                .await
                .expect("claim revision after abandoned failure"),
            AdmissionOperationClaim::New
        );
    }
}
