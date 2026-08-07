//! Product-neutral connector fleet catalog and routing contracts.
//!
//! This crate is deliberately independent from connector implementations and
//! the AIP runtime. It models immutable connector versions, logical instances,
//! live replicas, tenant bindings, and durable per-action route assignments.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use aip_core::{
    ActionId, Capability, CapabilityId, Manifest, MessageId, PrincipalId, PrincipalKind, ProfileId,
};
use aip_crypto::canonical_json_bytes;
use aip_discovery::{CapabilityImplementationSupport, DiscoveryService, ManifestAdmissionPolicy};
use async_trait::async_trait;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    str::FromStr,
    sync::Arc,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

/// Error returned when a registry identifier is empty or has the wrong prefix.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegistryIdError {
    /// The identifier was empty.
    #[error("registry identifier is empty")]
    Empty,
    /// The identifier did not use the required prefix.
    #[error("registry identifier `{actual}` does not start with `{expected}`")]
    InvalidPrefix {
        /// Expected prefix.
        expected: &'static str,
        /// Supplied value.
        actual: String,
    },
}

macro_rules! registry_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a time-sortable identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(format!("{}{}", $prefix, Uuid::now_v7().simple()))
            }

            /// Parses and validates an external identifier.
            pub fn parse(value: impl Into<String>) -> Result<Self, RegistryIdError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(RegistryIdError::Empty);
                }
                if !value.starts_with($prefix) {
                    return Err(RegistryIdError::InvalidPrefix {
                        expected: $prefix,
                        actual: value,
                    });
                }
                Ok(Self(value))
            }

            /// Creates a trusted identifier for constants and controlled tests.
            #[must_use]
            pub fn trusted(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrows the identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = RegistryIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

registry_id!(
    ConnectorTypeId,
    "ctype_",
    "Stable identifier of one connector implementation type."
);
registry_id!(
    ConnectorVersionId,
    "cver_",
    "Immutable connector artifact version identifier."
);
registry_id!(
    ConnectorInstanceId,
    "cinst_",
    "Logical configured connector account or installation identifier."
);
registry_id!(
    ConnectorReplicaId,
    "crepl_",
    "Live connector-host replica identifier."
);

/// Monotonic revision of the published fleet catalog.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CatalogRevision(pub u64);

/// Lifecycle status of an immutable connector version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorVersionStatus {
    /// Metadata exists but admission is incomplete.
    Candidate,
    /// Artifact and manifest passed admission.
    Admitted,
    /// The version may receive new traffic.
    Active,
    /// The version is retained for audit but cannot receive new traffic.
    Revoked,
}

/// Desired status of a logical connector instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorInstanceStatus {
    /// Instance may receive new assignments.
    Enabled,
    /// Instance is intentionally disabled.
    Disabled,
}

/// Routing status reported for one live replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorReplicaStatus {
    /// Replica may accept new assignments.
    Ready,
    /// Replica may finish pinned work but receives no new assignments.
    Draining,
    /// Replica is unavailable.
    Offline,
}

/// Deployment topology carried by a connector-host replica.
///
/// The values are operator-defined stable labels, not metric dimensions. They
/// are persisted as indexed columns by durable registries so routing can keep
/// traffic in a preferred failure domain without materializing the fleet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorTopology {
    /// Geographic or deployment region, for example `eu-west-1`.
    pub region: String,
    /// Independent failure zone within the region.
    pub zone: String,
    /// Operator-defined capacity class, for example `standard` or `gpu`.
    pub capacity_class: String,
}

impl Default for ConnectorTopology {
    fn default() -> Self {
        Self {
            region: "global".to_owned(),
            zone: "default".to_owned(),
            capacity_class: "standard".to_owned(),
        }
    }
}

/// Locality constraints applied only while creating a new route assignment.
///
/// A previously persisted assignment remains pinned to its exact replica.
/// Cross-region failover is enabled by default; deployments that have data
/// residency constraints can disable it explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTopologyPreference {
    /// Region preferred for a new assignment.
    pub region: Option<String>,
    /// Zone preferred inside the selected region.
    pub zone: Option<String>,
    /// Capacity class required by the workload.
    pub capacity_class: Option<String>,
    /// Permit a healthy replica in another region when the preferred region
    /// has no eligible capacity.
    pub allow_cross_region: bool,
}

impl Default for RouteTopologyPreference {
    fn default() -> Self {
        Self {
            region: None,
            zone: None,
            capacity_class: None,
            allow_cross_region: true,
        }
    }
}

/// One connector implementation family, independent of versions and accounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorType {
    /// Stable type identifier.
    pub id: ConnectorTypeId,
    /// Human-readable type name.
    pub name: String,
    /// Owning organization or team.
    pub owner: String,
    /// Whether new versions and instances may be admitted.
    pub enabled: bool,
}

/// Supply-chain evidence retained for one immutable artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAttestation {
    /// Immutable OCI or artifact digest.
    pub artifact_digest: String,
    /// Digest of the canonical bundle of input and output schemas.
    #[serde(default)]
    pub schema_bundle_digest: String,
    /// Software bill of materials digest.
    pub sbom_digest: String,
    /// Build provenance digest.
    pub provenance_digest: String,
    /// Conformance report digest for this exact artifact and manifest.
    #[serde(default)]
    pub conformance_report_digest: String,
    /// Vulnerability scan report digest for this exact artifact and SBOM.
    #[serde(default)]
    pub vulnerability_report_digest: String,
    /// License scan report digest for this exact artifact and SBOM.
    #[serde(default)]
    pub license_report_digest: String,
    /// Detached signature or signature-bundle reference.
    pub signature_ref: String,
    /// Verified signer identity recorded by the control plane.
    #[serde(default)]
    pub signer_identity: String,
    /// Owner asserted by the signed evidence; must match the connector type.
    #[serde(default)]
    pub owner: String,
    /// AIP protocol versions supported by this artifact.
    #[serde(default)]
    pub supported_aip_versions: BTreeSet<String>,
    /// Cargo-style SDK version requirement asserted by this artifact.
    #[serde(default)]
    pub sdk_version_requirement: String,
    /// Result of connector conformance policy evaluation.
    #[serde(default)]
    pub conformance_status: ArtifactCheckStatus,
    /// Result of vulnerability policy evaluation.
    #[serde(default)]
    pub vulnerability_policy_status: ArtifactCheckStatus,
    /// Result of license policy evaluation.
    #[serde(default)]
    pub license_policy_status: ArtifactCheckStatus,
    /// Result of artifact revocation checking at admission time.
    #[serde(default)]
    pub revocation_status: ArtifactCheckStatus,
}

/// Result of a mandatory supply-chain evidence check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCheckStatus {
    /// The control plane did not evaluate the evidence.
    #[default]
    NotEvaluated,
    /// The evidence satisfies the configured admission policy.
    Passed,
    /// The evidence violates the configured admission policy.
    Failed,
}

/// One admitted immutable connector version.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectorVersion {
    /// Stable version record identifier.
    pub id: ConnectorVersionId,
    /// Owning connector type.
    pub connector_type_id: ConnectorTypeId,
    /// Human-readable semantic or release version.
    pub version: String,
    /// Current lifecycle status.
    pub status: ConnectorVersionStatus,
    /// Exact connector-host manifest.
    pub manifest: Manifest,
    /// Canonical manifest digest.
    pub manifest_digest: String,
    /// Supply-chain evidence.
    pub attestation: ArtifactAttestation,
    /// Runtime support asserted for every callable capability.
    pub implementation_support: BTreeMap<CapabilityId, CapabilityImplementationSupport>,
    /// Time of successful admission.
    pub admitted_at: OffsetDateTime,
}

/// Canonical capability contract shared by versions and instances.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDefinition {
    /// Complete callable capability contract.
    pub capability: Capability,
    /// Digest of the complete capability definition.
    pub contract_digest: String,
    /// Digest of input and output schemas.
    pub schema_digest: String,
}

/// Logical configured installation of a connector type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorInstance {
    /// Stable logical instance identifier.
    pub id: ConnectorInstanceId,
    /// Connector type implemented by this instance.
    pub connector_type_id: ConnectorTypeId,
    /// Immutable version selected for new replica rollout.
    pub version_id: ConnectorVersionId,
    /// Tenant that owns this instance.
    pub tenant_id: String,
    /// Non-secret configuration revision.
    pub config_revision: u64,
    /// Opaque reference to the host-owned secret provider entry.
    pub secret_provider_ref: String,
    /// Desired routing status.
    pub status: ConnectorInstanceStatus,
}

/// One connector-host process eligible to execute assigned actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorReplica {
    /// Stable replica identifier.
    pub id: ConnectorReplicaId,
    /// Logical instance served by this replica.
    pub instance_id: ConnectorInstanceId,
    /// Exact immutable version running in the replica.
    pub version_id: ConnectorVersionId,
    /// Native AIP endpoint selected only by the trusted control plane.
    pub endpoint: String,
    /// Expected AIP principal identifier of the connector host.
    pub peer_principal_id: PrincipalId,
    /// Expected AIP principal kind of the connector host.
    pub peer_principal_kind: PrincipalKind,
    /// Expected signed native AIP peer DID.
    pub peer_did: String,
    /// Trust domain used to verify the connector-host identity.
    pub trust_domain: String,
    /// Native AIP transport profile used by this endpoint.
    pub transport_profile: ProfileId,
    /// Indexed deployment failure domain and capacity class.
    #[serde(default)]
    pub topology: ConnectorTopology,
    /// Current routing status.
    pub status: ConnectorReplicaStatus,
    /// Time after which the replica is considered offline.
    pub lease_expires_at: OffsetDateTime,
    /// Maximum concurrent assignments.
    pub capacity: u32,
    /// Assignments currently reserved through this registry.
    pub active_assignments: u32,
    /// Monotonic health observation revision.
    pub health_revision: u64,
    /// Last idempotent lifecycle request committed with this health revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_control_request_id: Option<MessageId>,
    /// Canonical digest of the last committed lifecycle request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_control_request_digest: Option<String>,
}

/// Tenant policy binding a capability to one configured instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityBinding {
    /// Verified tenant identifier.
    pub tenant_id: String,
    /// Capability exposed to the tenant.
    pub capability_id: CapabilityId,
    /// Configured connector instance selected by the binding.
    pub instance_id: ConnectorInstanceId,
    /// Lower values are preferred when several bindings are enabled.
    pub priority: u32,
    /// Monotonic policy revision for conflict-safe updates.
    pub policy_revision: u64,
    /// Opaque credential revision reference pinned into new routes.
    pub credential_revision_ref: Option<String>,
    /// Opaque reference to an admission and quota policy.
    pub quota_policy_ref: Option<String>,
    /// Whether the binding may receive new assignments.
    pub enabled: bool,
}

/// Hard admission and circuit-breaker policy referenced by tenant bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Stable opaque policy reference used by bindings.
    pub policy_ref: String,
    /// Monotonic policy revision pinned into new route assignments.
    pub revision: u64,
    /// Whether new assignments may use this policy.
    pub enabled: bool,
    /// Maximum simultaneous fleet reservations observed under this policy.
    /// `u32::MAX` disables this counter to avoid a global serialization point.
    pub max_global_in_flight: u32,
    /// Maximum simultaneous reservations for one tenant. `u32::MAX` disables
    /// this counter.
    pub max_tenant_in_flight: u32,
    /// Maximum simultaneous reservations for one connector type. `u32::MAX`
    /// disables this counter.
    pub max_connector_type_in_flight: u32,
    /// Maximum simultaneous reservations for one connector instance.
    /// `u32::MAX` disables this counter.
    pub max_instance_in_flight: u32,
    /// Maximum simultaneous reservations for one tenant-capability binding.
    /// `u32::MAX` disables this counter.
    pub max_binding_in_flight: u32,
    /// Maximum simultaneous retried attempts for one tenant. `u32::MAX`
    /// disables this counter.
    pub max_tenant_retry_in_flight: u32,
    /// Consecutive unknown outcomes required to open a replica circuit.
    pub circuit_failure_threshold: u32,
    /// Duration of an opened replica circuit.
    pub circuit_open_ms: u64,
}

impl AdmissionPolicy {
    /// Creates a conservative policy suitable for small production fleets.
    #[must_use]
    pub fn conservative(policy_ref: impl Into<String>) -> Self {
        Self {
            policy_ref: policy_ref.into(),
            revision: 1,
            enabled: true,
            max_global_in_flight: 10_000,
            max_tenant_in_flight: 1_000,
            max_connector_type_in_flight: 2_000,
            max_instance_in_flight: 500,
            max_binding_in_flight: 250,
            max_tenant_retry_in_flight: 100,
            circuit_failure_threshold: 5,
            circuit_open_ms: 30_000,
        }
    }

    /// Creates a horizontally scalable fleet policy.
    ///
    /// Exact fleet-wide and connector-type counters are intentionally disabled:
    /// either one would serialize every otherwise independent tenant through a
    /// shared PostgreSQL row. Hard tenant, instance, binding, retry, and replica
    /// capacity limits remain active, so a noisy tenant or connector cannot
    /// consume another tenant's reservation budget. Deployments that require an
    /// emergency exact fleet-wide ceiling may configure a finite global limit
    /// explicitly and accept that coordination point.
    #[must_use]
    pub fn fleet(policy_ref: impl Into<String>) -> Self {
        Self {
            policy_ref: policy_ref.into(),
            revision: 1,
            enabled: true,
            max_global_in_flight: u32::MAX,
            max_tenant_in_flight: 1_000,
            max_connector_type_in_flight: u32::MAX,
            max_instance_in_flight: 500,
            max_binding_in_flight: 250,
            max_tenant_retry_in_flight: 100,
            circuit_failure_threshold: 5,
            circuit_open_ms: 30_000,
        }
    }
}

/// Fixed set of hard-capacity dimensions used by admission counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionScopeKind {
    /// Complete fleet.
    Global,
    /// Verified tenant.
    Tenant,
    /// Connector implementation type.
    ConnectorType,
    /// Logical connector instance.
    Instance,
    /// Tenant-capability-instance binding.
    Binding,
    /// Retried attempts for one tenant.
    TenantRetry,
}

/// One exact counter reservation and its hard upper bound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionScopeReservation {
    /// Counter dimension.
    pub kind: AdmissionScopeKind,
    /// Internal counter key; never exported as a metric label.
    pub key: String,
    /// Hard upper bound applied during reservation.
    pub limit: u32,
}

/// Admission contract pinned into one immutable route assignment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReservation {
    /// Policy reference selected by the binding.
    pub policy_ref: Option<String>,
    /// Policy revision selected before dispatch.
    pub policy_revision: u64,
    /// Counters reserved by every attempt.
    pub base_scopes: Vec<AdmissionScopeReservation>,
    /// Additional counter applied only when a settled action is retried.
    pub retry_scope: Option<AdmissionScopeReservation>,
    /// Consecutive unknown outcomes required to open the pinned replica circuit.
    #[serde(default)]
    pub circuit_failure_threshold: u32,
    /// Duration of the pinned replica circuit after it opens.
    #[serde(default)]
    pub circuit_open_ms: u64,
}

/// Immutable execution target selected before an external side effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAssignment {
    /// Action whose retries, cancellation, and reconciliation use this route.
    pub action_id: ActionId,
    /// Capability selected for the action.
    pub capability_id: CapabilityId,
    /// Verified tenant boundary.
    pub tenant_id: String,
    /// Logical provider account.
    pub instance_id: ConnectorInstanceId,
    /// Exact executing replica.
    pub replica_id: ConnectorReplicaId,
    /// Native AIP endpoint pinned at assignment time.
    pub endpoint: String,
    /// Expected AIP principal identifier pinned at assignment time.
    pub peer_principal_id: PrincipalId,
    /// Expected AIP principal kind pinned at assignment time.
    pub peer_principal_kind: PrincipalKind,
    /// Expected signed native AIP peer DID pinned at assignment time.
    pub peer_did: String,
    /// Trust domain pinned at assignment time.
    pub trust_domain: String,
    /// Native AIP transport profile pinned at assignment time.
    pub transport_profile: ProfileId,
    /// Replica topology pinned for audit and failure-domain analysis.
    #[serde(default)]
    pub topology: ConnectorTopology,
    /// Exact immutable connector version.
    pub version_id: ConnectorVersionId,
    /// Manifest digest admitted for that version.
    pub manifest_digest: String,
    /// Catalog revision under which the route was admitted.
    pub catalog_revision: CatalogRevision,
    /// Tenant binding policy revision pinned before execution.
    pub binding_policy_revision: u64,
    /// Credential revision pinned at assignment time.
    pub credential_revision_ref: Option<String>,
    /// Opaque quota-policy reference pinned at assignment time.
    pub quota_policy_ref: Option<String>,
    /// Replica health revision observed while reserving capacity.
    pub replica_health_revision: u64,
    /// Fencing token required when releasing reserved capacity.
    pub fence_token: String,
    /// Assignment creation time.
    pub assigned_at: OffsetDateTime,
    /// Hard admission contract pinned before the first external side effect.
    #[serde(default)]
    pub admission: AdmissionReservation,
}

/// Trusted context applied before reading the capability catalog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogReadContext {
    /// Verified tenant. `None` is reserved for internal administrative reads.
    pub tenant_id: Option<String>,
    /// Whether an internal caller may see definitions without tenant bindings.
    pub allow_unbound: bool,
}

impl CatalogReadContext {
    /// Creates a tenant-scoped catalog read.
    #[must_use]
    pub fn for_tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: Some(tenant_id.into()),
            allow_unbound: false,
        }
    }

    /// Creates a trusted internal read used for recovery and administration.
    #[must_use]
    pub fn internal() -> Self {
        Self {
            tenant_id: None,
            allow_unbound: true,
        }
    }
}

/// One capability resolved from a particular catalog revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCapabilityDefinition {
    /// Canonical capability definition.
    pub definition: CapabilityDefinition,
    /// Catalog revision that produced this view.
    pub catalog_revision: CatalogRevision,
}

/// Server-side capability search request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityCatalogQuery {
    /// Exact capability identifier filter.
    pub capability_id: Option<CapabilityId>,
    /// Case-insensitive search across id, name, and description.
    pub text: Option<String>,
    /// Require a tenant-visible implementation supporting this profile.
    pub profile: Option<ProfileId>,
    /// Opaque stable cursor returned by an earlier page.
    pub cursor: Option<String>,
    /// Requested page size.
    pub limit: usize,
}

/// Bounded server-side capability page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityPage {
    /// Catalog revision used for the complete page.
    pub catalog_revision: CatalogRevision,
    /// Matching capability definitions.
    pub capabilities: Vec<CapabilityDefinition>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
    /// Total matches at this catalog revision.
    pub total: u64,
}

/// Request to resolve and persist an execution route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteResolutionRequest {
    /// Stable action identifier.
    pub action_id: ActionId,
    /// Selected capability.
    pub capability_id: CapabilityId,
    /// Verified tenant identifier.
    pub tenant_id: String,
    /// Deployment locality constraints for a new assignment.
    pub topology: RouteTopologyPreference,
}

/// Terminal assignment outcome used to release reserved replica capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteSettlement {
    /// Execution returned a terminal response.
    Completed,
    /// Execution did not establish a terminal provider outcome.
    OutcomeUnknown,
    /// Execution was cancelled before or during dispatch.
    Cancelled,
    /// The executing replica lease expired before settlement completed.
    LeaseExpired,
}

/// Bounded aggregate of connector-fleet lifecycle state.
///
/// The summary intentionally contains no tenant, instance, replica, endpoint,
/// or action identifiers, so it is safe to expose as fixed-cardinality
/// operational state. Detailed records remain behind separately authorized,
/// server-paginated control-plane APIs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatusSummary {
    /// Catalog revision observed while the aggregate was computed.
    pub catalog_revision: CatalogRevision,
    /// Registered connector implementation types.
    pub connector_types: u64,
    /// Versions currently active for new traffic.
    pub active_versions: u64,
    /// Logical instances currently enabled.
    pub enabled_instances: u64,
    /// All retained replica records.
    pub replicas: u64,
    /// Ready replicas with a non-expired lease.
    pub ready_replicas: u64,
    /// Draining replicas with a non-expired lease.
    pub draining_replicas: u64,
    /// Replicas explicitly marked offline.
    pub offline_replicas: u64,
    /// Replica leases at or before the observation timestamp.
    pub expired_leases: u64,
    /// Sum of ready, non-expired replica capacity.
    pub ready_capacity: u64,
    /// Registry-owned reservations across all retained replicas.
    pub active_assignments: u64,
    /// Time represented by this aggregate.
    pub observed_at: OffsetDateTime,
}

/// Fixed-cardinality connector-registry connection-pool telemetry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRegistryPoolSnapshot {
    /// Open control-plane connections.
    pub control_size: u32,
    /// Idle control-plane connections.
    pub control_idle: u32,
    /// Configured control-plane connection ceiling.
    pub control_max: u32,
    /// Open data-plane connections.
    pub data_size: u32,
    /// Idle data-plane connections.
    pub data_idle: u32,
    /// Configured data-plane connection ceiling.
    pub data_max: u32,
}

impl Default for FleetStatusSummary {
    fn default() -> Self {
        Self {
            catalog_revision: CatalogRevision::default(),
            connector_types: 0,
            active_versions: 0,
            enabled_instances: 0,
            replicas: 0,
            ready_replicas: 0,
            draining_replicas: 0,
            offline_replicas: 0,
            expired_leases: 0,
            ready_capacity: 0,
            active_assignments: 0,
            observed_at: OffsetDateTime::UNIX_EPOCH,
        }
    }
}

/// Fleet catalog and routing error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// Supplied data is structurally invalid.
    #[error("invalid registry input: {0}")]
    Invalid(String),
    /// Manifest or implementation admission failed.
    #[error("connector version admission failed: {0}")]
    Admission(String),
    /// An immutable record conflicts with an existing value.
    #[error("immutable registry conflict: {0}")]
    Conflict(String),
    /// A requested record does not exist.
    #[error("registry record was not found: {0}")]
    NotFound(String),
    /// No enabled tenant binding exists.
    #[error(
        "no enabled connector binding for tenant `{tenant_id}` and capability `{capability_id}`"
    )]
    BindingUnavailable {
        /// Verified tenant.
        tenant_id: String,
        /// Requested capability.
        capability_id: CapabilityId,
    },
    /// The selected instance has no ready capacity.
    #[error("no ready connector replica for instance `{0}`")]
    ReplicaUnavailable(ConnectorInstanceId),
    /// A hard admission counter reached its configured limit.
    #[error("connector admission capacity is exhausted for `{scope:?}`")]
    CapacityExceeded {
        /// Exhausted counter dimension.
        scope: AdmissionScopeKind,
        /// Bounded retry guidance.
        retry_after_ms: u64,
    },
    /// A page cursor belongs to another catalog revision.
    #[error("catalog cursor revision is stale")]
    StaleCursor,
    /// Assignment fencing failed.
    #[error("route assignment fencing failed")]
    FenceLost,
    /// Durable backend failed.
    #[error("connector registry storage failed: {0}")]
    Storage(String),
}

/// Read-only capability catalog used by runtimes and compatibility profiles.
#[async_trait]
pub trait CapabilityCatalogProvider: Send + Sync {
    /// Resolves one tenant-visible capability.
    async fn get(
        &self,
        capability_id: &CapabilityId,
        context: &CatalogReadContext,
    ) -> Result<Option<ResolvedCapabilityDefinition>, RegistryError>;

    /// Returns one bounded server-side page.
    async fn query(
        &self,
        request: CapabilityCatalogQuery,
        context: &CatalogReadContext,
    ) -> Result<CapabilityPage, RegistryError>;
}

/// Durable, deterministic action target resolver.
#[async_trait]
pub trait ActionTargetResolver: Send + Sync {
    /// Returns an existing assignment or atomically creates a new one.
    async fn resolve(
        &self,
        request: RouteResolutionRequest,
    ) -> Result<RouteAssignment, RegistryError>;

    /// Returns the pinned assignment for an action.
    async fn assignment(
        &self,
        action_id: &ActionId,
    ) -> Result<Option<RouteAssignment>, RegistryError>;

    /// Releases reserved replica capacity without deleting the assignment.
    async fn settle(
        &self,
        assignment: &RouteAssignment,
        settlement: RouteSettlement,
    ) -> Result<(), RegistryError>;
}

/// Read-only connector identity and admission records used on the data plane.
#[async_trait]
pub trait ConnectorRegistryReader: Send + Sync {
    /// Reads one immutable connector version for host admission.
    async fn connector_version(
        &self,
        version_id: &ConnectorVersionId,
    ) -> Result<Option<ConnectorVersion>, RegistryError>;

    /// Reads one logical connector instance for replica admission.
    async fn connector_instance(
        &self,
        instance_id: &ConnectorInstanceId,
    ) -> Result<Option<ConnectorInstance>, RegistryError>;

    /// Reads one registered connector-host replica.
    async fn connector_replica(
        &self,
        replica_id: &ConnectorReplicaId,
    ) -> Result<Option<ConnectorReplica>, RegistryError>;
}

/// Mutable control-plane operations required before a connector can receive traffic.
#[async_trait]
pub trait ConnectorRegistryAdmin: ConnectorRegistryReader {
    /// Creates or revision-updates one hard admission policy.
    async fn put_admission_policy(&self, policy: AdmissionPolicy) -> Result<(), RegistryError>;

    /// Creates a connector type or verifies an identical existing definition.
    async fn put_connector_type(&self, connector_type: ConnectorType) -> Result<(), RegistryError>;

    /// Enables or disables admission and routing for a connector type.
    async fn set_connector_type_enabled(
        &self,
        connector_type_id: &ConnectorTypeId,
        enabled: bool,
    ) -> Result<(), RegistryError>;

    /// Atomically admits an immutable version and its capability definitions.
    async fn admit_version(&self, version: ConnectorVersion) -> Result<(), RegistryError>;

    /// Changes only the lifecycle status of an already admitted version.
    async fn set_version_status(
        &self,
        version_id: &ConnectorVersionId,
        status: ConnectorVersionStatus,
    ) -> Result<(), RegistryError>;

    /// Creates or updates one logical instance.
    async fn put_instance(&self, instance: ConnectorInstance) -> Result<(), RegistryError>;

    /// Creates or renews one replica lease.
    async fn put_replica(&self, replica: ConnectorReplica) -> Result<(), RegistryError>;

    /// Creates or updates one tenant capability binding.
    async fn put_binding(&self, binding: CapabilityBinding) -> Result<(), RegistryError>;
}

/// Bounded lifecycle maintenance and aggregate status for a connector fleet.
///
/// Implementations must not contact connector endpoints. Lease expiry is a
/// storage operation, and summaries must be computed server-side without
/// returning per-replica material to callers.
#[async_trait]
pub trait ConnectorFleetStatusProvider: Send + Sync {
    /// Marks at most `limit` expired replicas offline and releases their fenced
    /// reservations. Returns the number of replicas transitioned.
    async fn expire_stale_replicas(
        &self,
        now: OffsetDateTime,
        limit: usize,
    ) -> Result<usize, RegistryError>;

    /// Returns a fixed-size aggregate at the supplied observation time.
    async fn fleet_status(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<FleetStatusSummary, RegistryError>;

    /// Returns fixed-cardinality resource telemetry when the backend exposes
    /// independent control/data pools.
    fn pool_snapshot(&self) -> Option<ConnectorRegistryPoolSnapshot> {
        None
    }
}

/// Catalog provider that never exposes remote capabilities.
#[derive(Clone, Debug, Default)]
pub struct EmptyCapabilityCatalog;

#[async_trait]
impl CapabilityCatalogProvider for EmptyCapabilityCatalog {
    async fn get(
        &self,
        _capability_id: &CapabilityId,
        _context: &CatalogReadContext,
    ) -> Result<Option<ResolvedCapabilityDefinition>, RegistryError> {
        Ok(None)
    }

    async fn query(
        &self,
        _request: CapabilityCatalogQuery,
        _context: &CatalogReadContext,
    ) -> Result<CapabilityPage, RegistryError> {
        Ok(CapabilityPage {
            catalog_revision: CatalogRevision::default(),
            capabilities: Vec::new(),
            next_cursor: None,
            total: 0,
        })
    }
}

/// Safety and resource bounds applied during in-memory reference admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryLimits {
    /// Maximum callable and resource capabilities in one connector version.
    pub max_capabilities_per_version: usize,
    /// Maximum canonical serialized manifest size.
    pub max_manifest_bytes: usize,
    /// Maximum canonical serialized size of one capability definition.
    pub max_capability_bytes: usize,
    /// Maximum capability page size.
    pub max_page_size: usize,
    /// Maximum canonical serialized capability bytes returned in one page.
    pub max_page_bytes: usize,
    /// Bounded retries when otherwise eligible replica rows are briefly locked.
    pub max_route_lock_retries: u32,
    /// Delay between contended route-selection attempts.
    pub route_lock_retry_ms: u64,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            max_capabilities_per_version: 512,
            max_manifest_bytes: 4 * 1024 * 1024,
            max_capability_bytes: 256 * 1024,
            max_page_size: 200,
            max_page_bytes: 4 * 1024 * 1024,
            max_route_lock_retries: 32,
            route_lock_retry_ms: 1,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct InMemoryRegistryState {
    revision: u64,
    connector_types: BTreeMap<ConnectorTypeId, ConnectorType>,
    versions: BTreeMap<ConnectorVersionId, ConnectorVersion>,
    capabilities: BTreeMap<CapabilityId, CapabilityDefinition>,
    version_capabilities: BTreeMap<ConnectorVersionId, BTreeSet<CapabilityId>>,
    instances: BTreeMap<ConnectorInstanceId, ConnectorInstance>,
    replicas: BTreeMap<ConnectorReplicaId, ConnectorReplica>,
    bindings: BTreeMap<(String, CapabilityId, ConnectorInstanceId), CapabilityBinding>,
    admission_policies: BTreeMap<String, AdmissionPolicy>,
    admission_counters: BTreeMap<(AdmissionScopeKind, String), u64>,
    replica_circuits: BTreeMap<ConnectorReplicaId, ReplicaCircuitState>,
    assignments: HashMap<ActionId, RouteAssignment>,
    active_reservation_scopes: HashMap<ActionId, Vec<AdmissionScopeReservation>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplicaCircuitState {
    consecutive_failures: u32,
    open_until: Option<OffsetDateTime>,
}

impl InMemoryRegistryState {
    fn advance_revision(&mut self) {
        self.revision = self.revision.saturating_add(1).max(1);
    }
}

/// Deterministic in-memory registry used by embedded deployments and conformance tests.
#[derive(Clone, Debug)]
pub struct InMemoryConnectorRegistry {
    state: Arc<RwLock<InMemoryRegistryState>>,
    limits: RegistryLimits,
}

impl Default for InMemoryConnectorRegistry {
    fn default() -> Self {
        Self::new(RegistryLimits::default())
    }
}

impl InMemoryConnectorRegistry {
    /// Creates a registry with explicit safety bounds.
    #[must_use]
    pub fn new(limits: RegistryLimits) -> Self {
        Self {
            state: Arc::default(),
            limits,
        }
    }

    /// Returns the current monotonic catalog revision.
    pub async fn revision(&self) -> CatalogRevision {
        CatalogRevision(self.state.read().await.revision)
    }
}

#[async_trait]
impl ConnectorRegistryReader for InMemoryConnectorRegistry {
    async fn connector_version(
        &self,
        version_id: &ConnectorVersionId,
    ) -> Result<Option<ConnectorVersion>, RegistryError> {
        Ok(self.state.read().await.versions.get(version_id).cloned())
    }

    async fn connector_instance(
        &self,
        instance_id: &ConnectorInstanceId,
    ) -> Result<Option<ConnectorInstance>, RegistryError> {
        Ok(self.state.read().await.instances.get(instance_id).cloned())
    }

    async fn connector_replica(
        &self,
        replica_id: &ConnectorReplicaId,
    ) -> Result<Option<ConnectorReplica>, RegistryError> {
        Ok(self.state.read().await.replicas.get(replica_id).cloned())
    }
}

#[async_trait]
impl ConnectorRegistryAdmin for InMemoryConnectorRegistry {
    async fn put_admission_policy(&self, policy: AdmissionPolicy) -> Result<(), RegistryError> {
        validate_admission_policy(&policy)?;
        let mut state = self.state.write().await;
        if let Some(existing) = state.admission_policies.get(&policy.policy_ref) {
            if existing == &policy {
                return Ok(());
            }
            if policy.revision <= existing.revision {
                return Err(RegistryError::Conflict(format!(
                    "admission policy `{}` requires a newer revision",
                    policy.policy_ref
                )));
            }
        }
        state
            .admission_policies
            .insert(policy.policy_ref.clone(), policy);
        state.advance_revision();
        Ok(())
    }

    async fn put_connector_type(&self, connector_type: ConnectorType) -> Result<(), RegistryError> {
        validate_nonempty("connector type name", &connector_type.name)?;
        validate_nonempty("connector type owner", &connector_type.owner)?;
        let mut state = self.state.write().await;
        if let Some(existing) = state.connector_types.get(&connector_type.id) {
            if existing == &connector_type {
                return Ok(());
            }
            return Err(RegistryError::Conflict(format!(
                "connector type `{}` already exists with another definition",
                connector_type.id
            )));
        }
        state
            .connector_types
            .insert(connector_type.id.clone(), connector_type);
        state.advance_revision();
        Ok(())
    }

    async fn set_connector_type_enabled(
        &self,
        connector_type_id: &ConnectorTypeId,
        enabled: bool,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.write().await;
        let connector_type = state
            .connector_types
            .get_mut(connector_type_id)
            .ok_or_else(|| RegistryError::NotFound(connector_type_id.to_string()))?;
        if connector_type.enabled == enabled {
            return Ok(());
        }
        connector_type.enabled = enabled;
        state.advance_revision();
        Ok(())
    }

    async fn admit_version(&self, version: ConnectorVersion) -> Result<(), RegistryError> {
        let definitions = validate_connector_version(&version, &self.limits)?;
        let mut state = self.state.write().await;
        let connector_type = state
            .connector_types
            .get(&version.connector_type_id)
            .ok_or_else(|| RegistryError::NotFound(version.connector_type_id.to_string()))?;
        if !connector_type.enabled {
            return Err(RegistryError::Admission(format!(
                "connector type `{}` is disabled",
                connector_type.id
            )));
        }
        if version.attestation.owner != connector_type.owner {
            return Err(RegistryError::Admission(format!(
                "artifact owner `{}` does not match connector type owner `{}`",
                version.attestation.owner, connector_type.owner
            )));
        }
        if let Some(existing) = state.versions.get(&version.id) {
            if existing == &version {
                return Ok(());
            }
            return Err(RegistryError::Conflict(format!(
                "connector version `{}` is immutable",
                version.id
            )));
        }
        for definition in &definitions {
            if let Some(existing) = state.capabilities.get(&definition.capability.id)
                && existing != definition
            {
                return Err(RegistryError::Conflict(format!(
                    "capability `{}` has another admitted contract digest",
                    definition.capability.id
                )));
            }
        }
        let capability_ids = definitions
            .iter()
            .map(|definition| definition.capability.id.clone())
            .collect::<BTreeSet<_>>();
        for definition in definitions {
            state
                .capabilities
                .entry(definition.capability.id.clone())
                .or_insert(definition);
        }
        state
            .version_capabilities
            .insert(version.id.clone(), capability_ids);
        state.versions.insert(version.id.clone(), version);
        state.advance_revision();
        Ok(())
    }

    async fn set_version_status(
        &self,
        version_id: &ConnectorVersionId,
        status: ConnectorVersionStatus,
    ) -> Result<(), RegistryError> {
        if status == ConnectorVersionStatus::Candidate {
            return Err(RegistryError::Invalid(
                "an admitted version cannot return to candidate status".to_owned(),
            ));
        }
        let mut state = self.state.write().await;
        let version = state
            .versions
            .get_mut(version_id)
            .ok_or_else(|| RegistryError::NotFound(version_id.to_string()))?;
        if version.status == status {
            return Ok(());
        }
        if version.status == ConnectorVersionStatus::Revoked {
            return Err(RegistryError::Conflict(format!(
                "revoked connector version `{version_id}` cannot be reactivated"
            )));
        }
        if status == ConnectorVersionStatus::Active {
            validate_artifact_attestation(&version.attestation, &version.manifest)?;
        }
        version.status = status;
        state.advance_revision();
        Ok(())
    }

    async fn put_instance(&self, instance: ConnectorInstance) -> Result<(), RegistryError> {
        validate_nonempty("tenant id", &instance.tenant_id)?;
        validate_nonempty("secret provider reference", &instance.secret_provider_ref)?;
        let mut state = self.state.write().await;
        let version = state
            .versions
            .get(&instance.version_id)
            .ok_or_else(|| RegistryError::NotFound(instance.version_id.to_string()))?;
        if version.connector_type_id != instance.connector_type_id {
            return Err(RegistryError::Invalid(
                "instance connector type does not match its version".to_owned(),
            ));
        }
        if let Some(existing) = state.instances.get(&instance.id) {
            if existing == &instance {
                return Ok(());
            }
            if existing.connector_type_id != instance.connector_type_id
                || existing.tenant_id != instance.tenant_id
            {
                return Err(RegistryError::Conflict(format!(
                    "connector instance `{}` cannot change type or tenant",
                    instance.id
                )));
            }
            if instance.config_revision <= existing.config_revision {
                return Err(RegistryError::Conflict(format!(
                    "connector instance `{}` requires a newer config revision",
                    instance.id
                )));
            }
        }
        if let Some(capabilities) = state.version_capabilities.get(&instance.version_id) {
            let missing_binding = state.bindings.values().find(|binding| {
                binding.enabled
                    && binding.instance_id == instance.id
                    && !capabilities.contains(&binding.capability_id)
            });
            if let Some(binding) = missing_binding {
                return Err(RegistryError::Conflict(format!(
                    "instance rollout version `{}` does not implement bound capability `{}`",
                    instance.version_id, binding.capability_id
                )));
            }
        }
        state.instances.insert(instance.id.clone(), instance);
        state.advance_revision();
        Ok(())
    }

    async fn put_replica(&self, replica: ConnectorReplica) -> Result<(), RegistryError> {
        validate_connector_replica(&replica)?;
        let mut state = self.state.write().await;
        let instance = state
            .instances
            .get(&replica.instance_id)
            .ok_or_else(|| RegistryError::NotFound(replica.instance_id.to_string()))?;
        if instance.version_id != replica.version_id {
            return Err(RegistryError::Invalid(
                "replica version does not match the instance rollout version".to_owned(),
            ));
        }
        if let Some(existing) = state.replicas.get(&replica.id) {
            if existing == &replica {
                return Ok(());
            }
            if existing.instance_id != replica.instance_id
                || existing.version_id != replica.version_id
                || existing.endpoint != replica.endpoint
                || existing.peer_principal_id != replica.peer_principal_id
                || existing.peer_principal_kind != replica.peer_principal_kind
                || existing.peer_did != replica.peer_did
                || existing.trust_domain != replica.trust_domain
                || existing.transport_profile != replica.transport_profile
                || existing.topology != replica.topology
            {
                return Err(RegistryError::Conflict(format!(
                    "connector replica `{}` cannot change immutable identity or endpoint",
                    replica.id
                )));
            }
            if replica.health_revision <= existing.health_revision {
                return Err(RegistryError::Conflict(format!(
                    "replica `{}` requires a newer health revision",
                    replica.id
                )));
            }
            if replica.active_assignments != existing.active_assignments {
                return Err(RegistryError::Conflict(format!(
                    "replica `{}` active assignments are registry-owned",
                    replica.id
                )));
            }
        } else if replica.active_assignments != 0 {
            return Err(RegistryError::Invalid(
                "a new replica must start with zero active assignments".to_owned(),
            ));
        }
        state.replicas.insert(replica.id.clone(), replica);
        Ok(())
    }

    async fn put_binding(&self, binding: CapabilityBinding) -> Result<(), RegistryError> {
        validate_nonempty("tenant id", &binding.tenant_id)?;
        let mut state = self.state.write().await;
        if let Some(policy_ref) = binding.quota_policy_ref.as_deref()
            && !state.admission_policies.contains_key(policy_ref)
        {
            return Err(RegistryError::NotFound(format!(
                "admission policy `{policy_ref}`"
            )));
        }
        let instance = state
            .instances
            .get(&binding.instance_id)
            .ok_or_else(|| RegistryError::NotFound(binding.instance_id.to_string()))?;
        if instance.tenant_id != binding.tenant_id {
            return Err(RegistryError::Invalid(
                "binding tenant does not own the connector instance".to_owned(),
            ));
        }
        let capabilities = state
            .version_capabilities
            .get(&instance.version_id)
            .ok_or_else(|| RegistryError::NotFound(instance.version_id.to_string()))?;
        if !capabilities.contains(&binding.capability_id) {
            return Err(RegistryError::Invalid(format!(
                "version `{}` does not implement `{}`",
                instance.version_id, binding.capability_id
            )));
        }
        let key = (
            binding.tenant_id.clone(),
            binding.capability_id.clone(),
            binding.instance_id.clone(),
        );
        if let Some(existing) = state.bindings.get(&key) {
            if existing == &binding {
                return Ok(());
            }
            if binding.policy_revision <= existing.policy_revision {
                return Err(RegistryError::Conflict(format!(
                    "binding for `{}` and `{}` requires a newer policy revision",
                    binding.tenant_id, binding.capability_id
                )));
            }
        }
        state.bindings.insert(key, binding);
        state.advance_revision();
        Ok(())
    }
}

#[async_trait]
impl ConnectorFleetStatusProvider for InMemoryConnectorRegistry {
    async fn expire_stale_replicas(
        &self,
        now: OffsetDateTime,
        limit: usize,
    ) -> Result<usize, RegistryError> {
        if limit == 0 {
            return Err(RegistryError::Invalid(
                "replica expiry batch limit must be greater than zero".to_owned(),
            ));
        }
        let mut state = self.state.write().await;
        let expired = state
            .replicas
            .values()
            .filter(|replica| {
                replica.status != ConnectorReplicaStatus::Offline && replica.lease_expires_at <= now
            })
            .take(limit)
            .map(|replica| replica.id.clone())
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return Ok(0);
        }
        let expired_set = expired.iter().cloned().collect::<BTreeSet<_>>();
        let released_actions = state
            .assignments
            .values()
            .filter(|assignment| {
                expired_set.contains(&assignment.replica_id)
                    && state
                        .active_reservation_scopes
                        .contains_key(&assignment.action_id)
            })
            .map(|assignment| assignment.action_id.clone())
            .collect::<Vec<_>>();
        for action_id in released_actions {
            if let Some(scopes) = state.active_reservation_scopes.remove(&action_id) {
                release_admission_scopes(&mut state, &scopes)?;
            }
        }
        for replica_id in &expired {
            if let Some(replica) = state.replicas.get_mut(replica_id) {
                replica.status = ConnectorReplicaStatus::Offline;
                replica.active_assignments = 0;
                replica.health_revision = replica.health_revision.saturating_add(1);
                replica.lease_expires_at = now;
                replica.last_control_request_id = None;
                replica.last_control_request_digest = None;
            }
        }
        Ok(expired.len())
    }

    async fn fleet_status(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<FleetStatusSummary, RegistryError> {
        let state = self.state.read().await;
        let mut summary = FleetStatusSummary {
            catalog_revision: CatalogRevision(state.revision),
            connector_types: state.connector_types.len() as u64,
            active_versions: state
                .versions
                .values()
                .filter(|version| version.status == ConnectorVersionStatus::Active)
                .count() as u64,
            enabled_instances: state
                .instances
                .values()
                .filter(|instance| instance.status == ConnectorInstanceStatus::Enabled)
                .count() as u64,
            replicas: state.replicas.len() as u64,
            observed_at,
            ..FleetStatusSummary::default()
        };
        for replica in state.replicas.values() {
            if replica.lease_expires_at <= observed_at {
                summary.expired_leases = summary.expired_leases.saturating_add(1);
            }
            match replica.status {
                ConnectorReplicaStatus::Ready if replica.lease_expires_at > observed_at => {
                    summary.ready_replicas = summary.ready_replicas.saturating_add(1);
                    summary.ready_capacity = summary
                        .ready_capacity
                        .saturating_add(u64::from(replica.capacity));
                }
                ConnectorReplicaStatus::Draining if replica.lease_expires_at > observed_at => {
                    summary.draining_replicas = summary.draining_replicas.saturating_add(1);
                }
                ConnectorReplicaStatus::Offline => {
                    summary.offline_replicas = summary.offline_replicas.saturating_add(1);
                }
                ConnectorReplicaStatus::Ready | ConnectorReplicaStatus::Draining => {}
            }
            summary.active_assignments = summary
                .active_assignments
                .saturating_add(u64::from(replica.active_assignments));
        }
        Ok(summary)
    }
}

#[async_trait]
impl CapabilityCatalogProvider for InMemoryConnectorRegistry {
    async fn get(
        &self,
        capability_id: &CapabilityId,
        context: &CatalogReadContext,
    ) -> Result<Option<ResolvedCapabilityDefinition>, RegistryError> {
        let state = self.state.read().await;
        if !catalog_capability_visible(&state, capability_id, context) {
            return Ok(None);
        }
        Ok(state
            .capabilities
            .get(capability_id)
            .cloned()
            .map(|definition| ResolvedCapabilityDefinition {
                definition,
                catalog_revision: CatalogRevision(state.revision),
            }))
    }

    async fn query(
        &self,
        request: CapabilityCatalogQuery,
        context: &CatalogReadContext,
    ) -> Result<CapabilityPage, RegistryError> {
        validate_registry_limits(&self.limits)?;
        let state = self.state.read().await;
        let revision = CatalogRevision(state.revision);
        let after = parse_cursor(request.cursor.as_deref(), revision)?;
        let text = request.text.as_deref().map(str::to_ascii_lowercase);
        let matches = || {
            state
                .capabilities
                .values()
                .filter(|definition| {
                    catalog_capability_visible_with_profile(
                        &state,
                        &definition.capability.id,
                        request.profile.as_ref(),
                        context,
                    )
                })
                .filter(|definition| {
                    request
                        .capability_id
                        .as_ref()
                        .is_none_or(|id| id == &definition.capability.id)
                })
                .filter(|definition| {
                    text.as_ref().is_none_or(|text| {
                        format!(
                            "{} {} {}",
                            definition.capability.id,
                            definition.capability.name,
                            definition
                                .capability
                                .description
                                .as_deref()
                                .unwrap_or_default()
                        )
                        .to_ascii_lowercase()
                        .contains(text)
                    })
                })
        };
        let total = u64::try_from(matches().count())
            .map_err(|_| RegistryError::Storage("catalog match count overflowed".to_owned()))?;
        let limit = request.limit.max(1).min(self.limits.max_page_size);
        let mut capabilities = Vec::with_capacity(limit);
        let mut page_bytes = 0_usize;
        let mut has_more = false;
        for definition in matches().filter(|definition| {
            after
                .as_ref()
                .is_none_or(|after| definition.capability.id > *after)
        }) {
            if capabilities.len() == limit {
                has_more = true;
                break;
            }
            let definition_bytes = capability_definition_size(definition)?;
            if definition_bytes > self.limits.max_capability_bytes {
                return Err(RegistryError::Storage(format!(
                    "stored capability `{}` exceeds the configured {} byte definition limit",
                    definition.capability.id, self.limits.max_capability_bytes
                )));
            }
            if page_bytes.saturating_add(definition_bytes) > self.limits.max_page_bytes {
                has_more = true;
                break;
            }
            page_bytes = page_bytes.saturating_add(definition_bytes);
            capabilities.push(definition.clone());
        }
        let next_cursor = if has_more {
            let definition = capabilities.last().ok_or_else(|| {
                RegistryError::Invalid(
                    "catalog byte limits cannot fit one admitted capability".to_owned(),
                )
            })?;
            Some(format!("{}:{}", revision.0, definition.capability.id))
        } else {
            None
        };
        Ok(CapabilityPage {
            catalog_revision: revision,
            capabilities,
            next_cursor,
            total,
        })
    }
}

fn admission_for_route(
    state: &InMemoryRegistryState,
    binding: &CapabilityBinding,
    instance: &ConnectorInstance,
    version: &ConnectorVersion,
) -> Result<AdmissionReservation, RegistryError> {
    let policy = match binding.quota_policy_ref.as_deref() {
        Some(policy_ref) => state
            .admission_policies
            .get(policy_ref)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(format!("admission policy `{policy_ref}`")))?,
        None => AdmissionPolicy::fleet("quota:implicit-default"),
    };
    build_admission_reservation(
        binding.quota_policy_ref.clone(),
        &policy,
        binding,
        instance,
        version,
    )
}

/// Builds the exact hard-counter contract pinned into a new route.
pub fn build_admission_reservation(
    policy_ref: Option<String>,
    policy: &AdmissionPolicy,
    binding: &CapabilityBinding,
    instance: &ConnectorInstance,
    version: &ConnectorVersion,
) -> Result<AdmissionReservation, RegistryError> {
    validate_admission_policy(policy)?;
    if !policy.enabled {
        return Err(RegistryError::Admission(format!(
            "admission policy `{}` is disabled",
            policy.policy_ref
        )));
    }
    let binding_key = sha256_digest(
        format!(
            "{}\u{1f}{}\u{1f}{}",
            binding.tenant_id, binding.capability_id, binding.instance_id
        )
        .as_bytes(),
    );
    let base_scopes = [
        AdmissionScopeReservation {
            kind: AdmissionScopeKind::Global,
            key: "fleet".to_owned(),
            limit: policy.max_global_in_flight,
        },
        AdmissionScopeReservation {
            kind: AdmissionScopeKind::Tenant,
            key: binding.tenant_id.clone(),
            limit: policy.max_tenant_in_flight,
        },
        AdmissionScopeReservation {
            kind: AdmissionScopeKind::ConnectorType,
            key: version.connector_type_id.to_string(),
            limit: policy.max_connector_type_in_flight,
        },
        AdmissionScopeReservation {
            kind: AdmissionScopeKind::Instance,
            key: instance.id.to_string(),
            limit: policy.max_instance_in_flight,
        },
        AdmissionScopeReservation {
            kind: AdmissionScopeKind::Binding,
            key: binding_key,
            limit: policy.max_binding_in_flight,
        },
    ]
    .into_iter()
    .filter(|scope| scope.limit != u32::MAX)
    .collect();
    let retry_scope =
        (policy.max_tenant_retry_in_flight != u32::MAX).then(|| AdmissionScopeReservation {
            kind: AdmissionScopeKind::TenantRetry,
            key: binding.tenant_id.clone(),
            limit: policy.max_tenant_retry_in_flight,
        });
    Ok(AdmissionReservation {
        policy_ref,
        policy_revision: policy.revision,
        base_scopes,
        retry_scope,
        circuit_failure_threshold: policy.circuit_failure_threshold,
        circuit_open_ms: policy.circuit_open_ms,
    })
}

/// Returns the exact counters reserved by a first attempt or retry.
#[must_use]
pub fn attempt_admission_scopes(
    admission: &AdmissionReservation,
    retry: bool,
) -> Vec<AdmissionScopeReservation> {
    let mut scopes = admission.base_scopes.clone();
    if retry && let Some(scope) = admission.retry_scope.clone() {
        scopes.push(scope);
    }
    scopes
}

fn reserve_admission_scopes(
    state: &mut InMemoryRegistryState,
    scopes: &[AdmissionScopeReservation],
) -> Result<(), RegistryError> {
    for scope in scopes {
        let active = state
            .admission_counters
            .get(&(scope.kind, scope.key.clone()))
            .copied()
            .unwrap_or_default();
        if active >= u64::from(scope.limit) {
            return Err(RegistryError::CapacityExceeded {
                scope: scope.kind,
                retry_after_ms: 100,
            });
        }
    }
    for scope in scopes {
        let active = state
            .admission_counters
            .entry((scope.kind, scope.key.clone()))
            .or_default();
        *active = active.saturating_add(1);
    }
    Ok(())
}

fn release_admission_scopes(
    state: &mut InMemoryRegistryState,
    scopes: &[AdmissionScopeReservation],
) -> Result<(), RegistryError> {
    for scope in scopes {
        if state
            .admission_counters
            .get(&(scope.kind, scope.key.clone()))
            .copied()
            .unwrap_or_default()
            == 0
        {
            return Err(RegistryError::FenceLost);
        }
    }
    for scope in scopes {
        let key = (scope.kind, scope.key.clone());
        if let Some(active) = state.admission_counters.get_mut(&key) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                state.admission_counters.remove(&key);
            }
        }
    }
    Ok(())
}

#[async_trait]
impl ActionTargetResolver for InMemoryConnectorRegistry {
    async fn resolve(
        &self,
        request: RouteResolutionRequest,
    ) -> Result<RouteAssignment, RegistryError> {
        let mut state = self.state.write().await;
        if let Some(existing) = state.assignments.get(&request.action_id).cloned() {
            if existing.capability_id != request.capability_id
                || existing.tenant_id != request.tenant_id
            {
                return Err(RegistryError::Conflict(format!(
                    "action `{}` already has a different route contract",
                    request.action_id
                )));
            }
            if !state
                .active_reservation_scopes
                .contains_key(&request.action_id)
            {
                let instance = state
                    .instances
                    .get(&existing.instance_id)
                    .ok_or_else(|| RegistryError::NotFound(existing.instance_id.to_string()))?;
                let version = state
                    .versions
                    .get(&existing.version_id)
                    .ok_or_else(|| RegistryError::NotFound(existing.version_id.to_string()))?;
                let connector_type = state
                    .connector_types
                    .get(&version.connector_type_id)
                    .ok_or_else(|| {
                        RegistryError::NotFound(version.connector_type_id.to_string())
                    })?;
                if instance.status != ConnectorInstanceStatus::Enabled
                    || version.status != ConnectorVersionStatus::Active
                    || !connector_type.enabled
                    || validate_artifact_attestation(&version.attestation, &version.manifest)
                        .is_err()
                {
                    return Err(RegistryError::Admission(
                        "pinned connector route is no longer admitted for another attempt"
                            .to_owned(),
                    ));
                }
                let replica = state
                    .replicas
                    .get(&existing.replica_id)
                    .ok_or_else(|| RegistryError::NotFound(existing.replica_id.to_string()))?;
                let now = OffsetDateTime::now_utc();
                if !matches!(
                    replica.status,
                    ConnectorReplicaStatus::Ready | ConnectorReplicaStatus::Draining
                ) || replica.lease_expires_at <= now
                    || replica.active_assignments >= replica.capacity
                    || state
                        .replica_circuits
                        .get(&existing.replica_id)
                        .and_then(|circuit| circuit.open_until)
                        .is_some_and(|open_until| open_until > now)
                {
                    return Err(RegistryError::ReplicaUnavailable(existing.instance_id));
                }
                let scopes = attempt_admission_scopes(&existing.admission, true);
                reserve_admission_scopes(&mut state, &scopes)?;
                let replica = state
                    .replicas
                    .get_mut(&existing.replica_id)
                    .ok_or_else(|| RegistryError::NotFound(existing.replica_id.to_string()))?;
                replica.active_assignments = replica.active_assignments.saturating_add(1);
                state
                    .active_reservation_scopes
                    .insert(request.action_id.clone(), scopes);
            }
            return Ok(existing);
        }
        let mut bindings = state
            .bindings
            .values()
            .filter(|binding| {
                binding.enabled
                    && binding.tenant_id == request.tenant_id
                    && binding.capability_id == request.capability_id
            })
            .cloned()
            .collect::<Vec<_>>();
        bindings.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.instance_id.cmp(&right.instance_id))
        });
        let now = OffsetDateTime::now_utc();
        let mut first_valid_instance = None;
        let mut candidates = Vec::new();
        for binding in bindings {
            let Some(instance) = state.instances.get(&binding.instance_id).cloned() else {
                continue;
            };
            if instance.status != ConnectorInstanceStatus::Enabled {
                continue;
            }
            let Some(version) = state.versions.get(&instance.version_id).cloned() else {
                continue;
            };
            let type_enabled = state
                .connector_types
                .get(&instance.connector_type_id)
                .is_some_and(|connector_type| connector_type.enabled);
            if version.status != ConnectorVersionStatus::Active || !type_enabled {
                continue;
            }
            first_valid_instance.get_or_insert_with(|| instance.id.clone());
            let replicas = state
                .replicas
                .values()
                .filter(|replica| {
                    replica.instance_id == instance.id
                        && replica.version_id == instance.version_id
                        && replica.status == ConnectorReplicaStatus::Ready
                        && replica.lease_expires_at > now
                        && replica.active_assignments < replica.capacity
                        && request
                            .topology
                            .capacity_class
                            .as_ref()
                            .is_none_or(|class| &replica.topology.capacity_class == class)
                        && (request.topology.allow_cross_region
                            || request
                                .topology
                                .region
                                .as_ref()
                                .is_none_or(|region| &replica.topology.region == region))
                        && state
                            .replica_circuits
                            .get(&replica.id)
                            .and_then(|circuit| circuit.open_until)
                            .is_none_or(|open_until| open_until <= now)
                })
                .cloned()
                .collect::<Vec<_>>();
            for replica in replicas {
                candidates.push((binding.clone(), instance.clone(), version.clone(), replica));
            }
        }
        candidates.sort_by(|left, right| {
            topology_rank(&left.3.topology, &request.topology)
                .cmp(&topology_rank(&right.3.topology, &request.topology))
                .then_with(|| left.0.priority.cmp(&right.0.priority))
                .then_with(|| left.3.active_assignments.cmp(&right.3.active_assignments))
                .then_with(|| left.1.id.cmp(&right.1.id))
                .then_with(|| left.3.id.cmp(&right.3.id))
        });
        let (binding, instance, version, replica) = match candidates.into_iter().next() {
            Some(selected) => selected,
            None => {
                return match first_valid_instance {
                    Some(instance_id) => Err(RegistryError::ReplicaUnavailable(instance_id)),
                    None => Err(RegistryError::BindingUnavailable {
                        tenant_id: request.tenant_id,
                        capability_id: request.capability_id,
                    }),
                };
            }
        };
        let stored_replica = state
            .replicas
            .get(&replica.id)
            .ok_or_else(|| RegistryError::NotFound(replica.id.to_string()))?;
        if stored_replica.active_assignments >= stored_replica.capacity {
            return Err(RegistryError::ReplicaUnavailable(instance.id));
        }
        let admission = admission_for_route(&state, &binding, &instance, &version)?;
        let reservation_scopes = attempt_admission_scopes(&admission, false);
        reserve_admission_scopes(&mut state, &reservation_scopes)?;
        let stored_replica = state
            .replicas
            .get_mut(&replica.id)
            .ok_or_else(|| RegistryError::NotFound(replica.id.to_string()))?;
        stored_replica.active_assignments = stored_replica.active_assignments.saturating_add(1);
        let assignment = RouteAssignment {
            action_id: request.action_id,
            capability_id: request.capability_id,
            tenant_id: request.tenant_id,
            instance_id: instance.id,
            replica_id: replica.id,
            endpoint: replica.endpoint,
            peer_principal_id: replica.peer_principal_id,
            peer_principal_kind: replica.peer_principal_kind,
            peer_did: replica.peer_did,
            trust_domain: replica.trust_domain,
            transport_profile: replica.transport_profile,
            topology: replica.topology,
            version_id: version.id,
            manifest_digest: version.manifest_digest,
            catalog_revision: CatalogRevision(state.revision),
            binding_policy_revision: binding.policy_revision,
            credential_revision_ref: binding.credential_revision_ref,
            quota_policy_ref: binding.quota_policy_ref,
            replica_health_revision: replica.health_revision,
            fence_token: format!("route_{}", Uuid::now_v7().simple()),
            assigned_at: now,
            admission,
        };
        state
            .assignments
            .insert(assignment.action_id.clone(), assignment.clone());
        state
            .active_reservation_scopes
            .insert(assignment.action_id.clone(), reservation_scopes);
        Ok(assignment)
    }

    async fn assignment(
        &self,
        action_id: &ActionId,
    ) -> Result<Option<RouteAssignment>, RegistryError> {
        Ok(self.state.read().await.assignments.get(action_id).cloned())
    }

    async fn settle(
        &self,
        assignment: &RouteAssignment,
        settlement: RouteSettlement,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.write().await;
        let existing = state
            .assignments
            .get(&assignment.action_id)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(assignment.action_id.to_string()))?;
        if existing != *assignment {
            return Err(RegistryError::FenceLost);
        }
        let Some(scopes) = state
            .active_reservation_scopes
            .remove(&assignment.action_id)
        else {
            return Ok(());
        };
        release_admission_scopes(&mut state, &scopes)?;
        let replica = state
            .replicas
            .get_mut(&assignment.replica_id)
            .ok_or_else(|| RegistryError::NotFound(assignment.replica_id.to_string()))?;
        replica.active_assignments = replica.active_assignments.saturating_sub(1);
        match settlement {
            RouteSettlement::Completed => {
                state.replica_circuits.remove(&assignment.replica_id);
            }
            RouteSettlement::OutcomeUnknown
                if assignment.admission.circuit_failure_threshold > 0
                    && assignment.admission.circuit_open_ms > 0 =>
            {
                let circuit = state
                    .replica_circuits
                    .entry(assignment.replica_id.clone())
                    .or_default();
                circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
                if circuit.consecutive_failures >= assignment.admission.circuit_failure_threshold {
                    let duration_ms = assignment.admission.circuit_open_ms.min(i64::MAX as u64);
                    circuit.open_until = Some(
                        OffsetDateTime::now_utc()
                            + time::Duration::milliseconds(duration_ms as i64),
                    );
                }
            }
            RouteSettlement::OutcomeUnknown
            | RouteSettlement::Cancelled
            | RouteSettlement::LeaseExpired => {}
        }
        Ok(())
    }
}

/// Validates version admission and returns its canonical capability definitions.
pub fn validate_connector_version(
    version: &ConnectorVersion,
    limits: &RegistryLimits,
) -> Result<Vec<CapabilityDefinition>, RegistryError> {
    validate_registry_limits(limits)?;
    validate_nonempty("connector version", &version.version)?;
    validate_digest("manifest digest", &version.manifest_digest)?;
    if version.status == ConnectorVersionStatus::Candidate {
        return Err(RegistryError::Admission(
            "candidate versions cannot be installed as admitted records".to_owned(),
        ));
    }
    if version.manifest.capabilities.len() > limits.max_capabilities_per_version {
        return Err(RegistryError::Admission(format!(
            "manifest contains {} capabilities; limit is {}",
            version.manifest.capabilities.len(),
            limits.max_capabilities_per_version
        )));
    }
    let manifest_value = serde_json::to_value(&version.manifest)
        .map_err(|error| RegistryError::Invalid(error.to_string()))?;
    let manifest_bytes = canonical_json_bytes(&manifest_value)
        .map_err(|error| RegistryError::Invalid(error.to_string()))?;
    if manifest_bytes.len() > limits.max_manifest_bytes {
        return Err(RegistryError::Admission(format!(
            "manifest is {} bytes; limit is {}",
            manifest_bytes.len(),
            limits.max_manifest_bytes
        )));
    }
    let computed_digest = sha256_digest(&manifest_bytes);
    if computed_digest != version.manifest_digest {
        return Err(RegistryError::Admission(
            "declared manifest digest does not match canonical manifest".to_owned(),
        ));
    }
    validate_artifact_attestation(&version.attestation, &version.manifest)?;
    let support = version
        .implementation_support
        .iter()
        .map(|(capability_id, support)| (capability_id.clone(), support.clone()))
        .collect::<HashMap<_, _>>();
    DiscoveryService::admit_manifest(
        version.manifest.clone(),
        &ManifestAdmissionPolicy {
            require_implementation_claims: true,
            ..ManifestAdmissionPolicy::default()
        },
        &support,
    )
    .map_err(|report| RegistryError::Admission(report.to_string()))?;
    capability_definitions(&version.manifest, limits)
}

/// Validates all mandatory supply-chain evidence for the current AIP and SDK.
pub fn validate_artifact_attestation(
    attestation: &ArtifactAttestation,
    manifest: &Manifest,
) -> Result<(), RegistryError> {
    validate_digest("artifact digest", &attestation.artifact_digest)?;
    validate_digest("schema bundle digest", &attestation.schema_bundle_digest)?;
    validate_digest("SBOM digest", &attestation.sbom_digest)?;
    validate_digest("provenance digest", &attestation.provenance_digest)?;
    validate_digest(
        "conformance report digest",
        &attestation.conformance_report_digest,
    )?;
    validate_digest(
        "vulnerability report digest",
        &attestation.vulnerability_report_digest,
    )?;
    validate_digest("license report digest", &attestation.license_report_digest)?;
    validate_nonempty("signature reference", &attestation.signature_ref)?;
    validate_nonempty("signer identity", &attestation.signer_identity)?;
    validate_nonempty("artifact owner", &attestation.owner)?;
    validate_nonempty(
        "SDK version requirement",
        &attestation.sdk_version_requirement,
    )?;
    if !attestation
        .supported_aip_versions
        .contains(aip_core::AIP_VERSION)
    {
        return Err(RegistryError::Admission(format!(
            "artifact does not declare compatibility with AIP {}",
            aip_core::AIP_VERSION
        )));
    }
    let sdk_requirement =
        VersionReq::parse(&attestation.sdk_version_requirement).map_err(|error| {
            RegistryError::Admission(format!(
                "artifact SDK version requirement is invalid: {error}"
            ))
        })?;
    let sdk_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|error| {
        RegistryError::Invalid(format!("registry SDK version is invalid: {error}"))
    })?;
    if !sdk_requirement.matches(&sdk_version) {
        return Err(RegistryError::Admission(format!(
            "artifact SDK requirement `{}` does not include registry SDK `{sdk_version}`",
            attestation.sdk_version_requirement
        )));
    }
    for (label, status) in [
        ("connector conformance", attestation.conformance_status),
        (
            "vulnerability policy",
            attestation.vulnerability_policy_status,
        ),
        ("license policy", attestation.license_policy_status),
        ("artifact revocation", attestation.revocation_status),
    ] {
        if status != ArtifactCheckStatus::Passed {
            return Err(RegistryError::Admission(format!(
                "{label} evidence did not pass admission"
            )));
        }
    }
    let expected_schema_digest = schema_bundle_digest(manifest)?;
    if attestation.schema_bundle_digest != expected_schema_digest {
        return Err(RegistryError::Admission(
            "declared schema bundle digest does not match the manifest schemas".to_owned(),
        ));
    }
    Ok(())
}

/// Computes the canonical digest of every input and output schema in a manifest.
pub fn schema_bundle_digest(manifest: &Manifest) -> Result<String, RegistryError> {
    let schemas = manifest
        .capabilities
        .iter()
        .map(|capability| {
            serde_json::json!({
                "capability_id": capability.id,
                "input": capability.input_schema,
                "output": capability.output_schema,
            })
        })
        .collect::<Vec<_>>();
    digest_json(&serde_json::json!({ "schemas": schemas }))
}

fn capability_definitions(
    manifest: &Manifest,
    limits: &RegistryLimits,
) -> Result<Vec<CapabilityDefinition>, RegistryError> {
    manifest
        .capabilities
        .iter()
        .map(|capability| {
            let value = serde_json::to_value(capability)
                .map_err(|error| RegistryError::Invalid(error.to_string()))?;
            let bytes = canonical_json_bytes(&value)
                .map_err(|error| RegistryError::Invalid(error.to_string()))?;
            let schema = serde_json::json!({
                "input": &capability.input_schema,
                "output": &capability.output_schema
            });
            let schema_bytes = canonical_json_bytes(&schema)
                .map_err(|error| RegistryError::Invalid(error.to_string()))?;
            let definition = CapabilityDefinition {
                capability: capability.clone(),
                contract_digest: sha256_digest(&bytes),
                schema_digest: sha256_digest(&schema_bytes),
            };
            let definition_bytes = capability_definition_size(&definition)?;
            if definition_bytes > limits.max_capability_bytes {
                return Err(RegistryError::Admission(format!(
                    "capability `{}` is {definition_bytes} bytes; limit is {}",
                    definition.capability.id, limits.max_capability_bytes
                )));
            }
            Ok(definition)
        })
        .collect()
}

/// Returns the canonical serialized size used by catalog page byte limits.
pub fn capability_definition_size(
    definition: &CapabilityDefinition,
) -> Result<usize, RegistryError> {
    let value = serde_json::to_value(definition)
        .map_err(|error| RegistryError::Invalid(error.to_string()))?;
    canonical_json_bytes(&value)
        .map(|bytes| bytes.len())
        .map_err(|error| RegistryError::Invalid(error.to_string()))
}

/// Validates connector registry count, byte, and retry bounds.
pub fn validate_registry_limits(limits: &RegistryLimits) -> Result<(), RegistryError> {
    if limits.max_capabilities_per_version == 0
        || limits.max_manifest_bytes == 0
        || limits.max_capability_bytes == 0
        || limits.max_page_size == 0
        || limits.max_page_bytes == 0
    {
        return Err(RegistryError::Invalid(
            "connector registry count and byte limits must be non-zero".to_owned(),
        ));
    }
    if limits.max_capability_bytes > limits.max_page_bytes {
        return Err(RegistryError::Invalid(
            "the capability definition byte limit must not exceed the page byte limit".to_owned(),
        ));
    }
    Ok(())
}

fn catalog_capability_visible(
    state: &InMemoryRegistryState,
    capability_id: &CapabilityId,
    context: &CatalogReadContext,
) -> bool {
    catalog_capability_visible_with_profile(state, capability_id, None, context)
}

fn catalog_capability_visible_with_profile(
    state: &InMemoryRegistryState,
    capability_id: &CapabilityId,
    profile: Option<&ProfileId>,
    context: &CatalogReadContext,
) -> bool {
    if context.allow_unbound {
        return state.capabilities.contains_key(capability_id)
            && state
                .version_capabilities
                .iter()
                .any(|(version_id, capabilities)| {
                    capabilities.contains(capability_id)
                        && state.versions.get(version_id).is_some_and(|version| {
                            version.status == ConnectorVersionStatus::Active
                                && state
                                    .connector_types
                                    .get(&version.connector_type_id)
                                    .is_some_and(|connector_type| connector_type.enabled)
                                && profile.is_none_or(|profile| {
                                    version.manifest.profiles.contains(profile)
                                })
                        })
                });
    }
    let Some(tenant_id) = context.tenant_id.as_deref() else {
        return false;
    };
    state.bindings.values().any(|binding| {
        binding.enabled
            && binding.tenant_id == tenant_id
            && &binding.capability_id == capability_id
            && state
                .instances
                .get(&binding.instance_id)
                .is_some_and(|instance| {
                    instance.status == ConnectorInstanceStatus::Enabled
                        && state
                            .versions
                            .get(&instance.version_id)
                            .is_some_and(|version| {
                                version.status == ConnectorVersionStatus::Active
                                    && state
                                        .connector_types
                                        .get(&version.connector_type_id)
                                        .is_some_and(|connector_type| connector_type.enabled)
                                    && profile.is_none_or(|profile| {
                                        version.manifest.profiles.contains(profile)
                                    })
                            })
                })
    })
}

fn parse_cursor(
    cursor: Option<&str>,
    revision: CatalogRevision,
) -> Result<Option<CapabilityId>, RegistryError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let (cursor_revision, capability_id) = cursor
        .split_once(':')
        .ok_or_else(|| RegistryError::Invalid("invalid capability cursor".to_owned()))?;
    let cursor_revision = cursor_revision
        .parse::<u64>()
        .map_err(|_| RegistryError::Invalid("invalid capability cursor revision".to_owned()))?;
    if cursor_revision != revision.0 {
        return Err(RegistryError::StaleCursor);
    }
    CapabilityId::parse(capability_id)
        .map(Some)
        .map_err(|error| RegistryError::Invalid(error.to_string()))
}

/// Validates one connector-host replica record before persistence.
pub fn validate_connector_replica(replica: &ConnectorReplica) -> Result<(), RegistryError> {
    validate_nonempty("replica endpoint", &replica.endpoint)?;
    let endpoint = Url::parse(&replica.endpoint)
        .map_err(|error| RegistryError::Invalid(format!("invalid replica endpoint: {error}")))?;
    if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
        return Err(RegistryError::Invalid(
            "replica endpoint must be an absolute HTTP or HTTPS URL".to_owned(),
        ));
    }
    validate_nonempty("replica peer DID", &replica.peer_did)?;
    validate_nonempty("replica trust domain", &replica.trust_domain)?;
    validate_topology_label("replica region", &replica.topology.region)?;
    validate_topology_label("replica zone", &replica.topology.zone)?;
    validate_topology_label("replica capacity class", &replica.topology.capacity_class)?;
    if replica.capacity == 0 {
        return Err(RegistryError::Invalid(
            "replica capacity must be greater than zero".to_owned(),
        ));
    }
    if replica.active_assignments > replica.capacity {
        return Err(RegistryError::Invalid(
            "replica active assignments exceed capacity".to_owned(),
        ));
    }
    match (
        &replica.last_control_request_id,
        &replica.last_control_request_digest,
    ) {
        (Some(_), Some(digest)) => validate_digest("replica lifecycle request digest", digest)?,
        (None, None) => {}
        _ => {
            return Err(RegistryError::Invalid(
                "replica lifecycle request id and digest must be stored together".to_owned(),
            ));
        }
    }
    Ok(())
}

fn topology_rank(
    topology: &ConnectorTopology,
    preference: &RouteTopologyPreference,
) -> (u8, u8, u8) {
    let region = preference
        .region
        .as_ref()
        .map_or(0, |expected| u8::from(&topology.region != expected));
    let zone = preference
        .zone
        .as_ref()
        .map_or(0, |expected| u8::from(&topology.zone != expected));
    let capacity_class = preference
        .capacity_class
        .as_ref()
        .map_or(0, |expected| u8::from(&topology.capacity_class != expected));
    (region, zone, capacity_class)
}

fn validate_topology_label(label: &str, value: &str) -> Result<(), RegistryError> {
    validate_nonempty(label, value)?;
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RegistryError::Invalid(format!(
            "{label} must contain at most 128 ASCII letters, digits, dots, dashes, or underscores"
        )));
    }
    Ok(())
}

/// Validates one hard admission policy before control-plane persistence.
pub fn validate_admission_policy(policy: &AdmissionPolicy) -> Result<(), RegistryError> {
    validate_nonempty("admission policy reference", &policy.policy_ref)?;
    if policy.policy_ref.len() > 256 {
        return Err(RegistryError::Invalid(
            "admission policy reference exceeds 256 bytes".to_owned(),
        ));
    }
    if policy.revision == 0 {
        return Err(RegistryError::Invalid(
            "admission policy revision must be greater than zero".to_owned(),
        ));
    }
    if [
        policy.max_global_in_flight,
        policy.max_tenant_in_flight,
        policy.max_connector_type_in_flight,
        policy.max_instance_in_flight,
        policy.max_binding_in_flight,
        policy.max_tenant_retry_in_flight,
        policy.circuit_failure_threshold,
    ]
    .contains(&0)
    {
        return Err(RegistryError::Invalid(
            "admission policy limits and circuit threshold must be greater than zero".to_owned(),
        ));
    }
    if !(100..=3_600_000).contains(&policy.circuit_open_ms) {
        return Err(RegistryError::Invalid(
            "admission policy circuit duration must be between 100 and 3600000 milliseconds"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest(label: &str, value: &str) -> Result<(), RegistryError> {
    if !value.starts_with("sha256:") || value.len() != 71 {
        return Err(RegistryError::Invalid(format!(
            "{label} must be a sha256 digest"
        )));
    }
    if !value[7..].bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RegistryError::Invalid(format!(
            "{label} contains non-hex characters"
        )));
    }
    Ok(())
}

fn validate_nonempty(label: &str, value: &str) -> Result<(), RegistryError> {
    if value.trim().is_empty() {
        Err(RegistryError::Invalid(format!("{label} must be non-empty")))
    } else {
        Ok(())
    }
}

/// Computes the canonical SHA-256 digest used by registry admission.
pub fn digest_json(value: &Value) -> Result<String, RegistryError> {
    let bytes =
        canonical_json_bytes(value).map_err(|error| RegistryError::Invalid(error.to_string()))?;
    Ok(sha256_digest(&bytes))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_core::{CapabilityKind, Principal, PrincipalId, PrincipalKind, ProfileId};
    use serde_json::json;
    use time::Duration;

    fn capability(id: &str) -> Capability {
        Capability {
            id: CapabilityId::trusted(id),
            name: id.to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({ "type": "object" }),
            output_schema: Some(json!({ "type": "object" })),
            description: Some(format!("Capability {id}")),
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        }
    }

    fn manifest(capabilities: Vec<Capability>) -> Manifest {
        Manifest {
            manifest_version: "1.0".to_owned(),
            agent: Principal::new(
                PrincipalId::trusted("service:test-connector-host"),
                PrincipalKind::Service,
            ),
            capabilities,
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        }
    }

    fn digest(value: &impl Serialize) -> String {
        digest_json(&serde_json::to_value(value).expect("serializable")).expect("digest")
    }

    fn qualified_attestation(
        manifest: &Manifest,
        artifact_nibble: char,
        signature_ref: &str,
    ) -> ArtifactAttestation {
        ArtifactAttestation {
            artifact_digest: format!("sha256:{}", artifact_nibble.to_string().repeat(64)),
            schema_bundle_digest: schema_bundle_digest(manifest).expect("schema bundle digest"),
            sbom_digest: format!("sha256:{}", "2".repeat(64)),
            provenance_digest: format!("sha256:{}", "3".repeat(64)),
            conformance_report_digest: format!("sha256:{}", "4".repeat(64)),
            vulnerability_report_digest: format!("sha256:{}", "5".repeat(64)),
            license_report_digest: format!("sha256:{}", "6".repeat(64)),
            signature_ref: signature_ref.to_owned(),
            signer_identity: "https://fulcio.example/identity/aip-test".to_owned(),
            owner: "AIP".to_owned(),
            supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
            sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
            conformance_status: ArtifactCheckStatus::Passed,
            vulnerability_policy_status: ArtifactCheckStatus::Passed,
            license_policy_status: ArtifactCheckStatus::Passed,
            revocation_status: ArtifactCheckStatus::Passed,
        }
    }

    #[test]
    fn mandatory_supply_chain_evidence_fails_closed() {
        let manifest = manifest(vec![capability("cap:test:supply-chain")]);
        let qualified = qualified_attestation(&manifest, 'a', "sigstore:supply-chain");
        validate_artifact_attestation(&qualified, &manifest).expect("qualified evidence");

        let mut missing_conformance = qualified.clone();
        missing_conformance.conformance_status = ArtifactCheckStatus::NotEvaluated;
        assert!(matches!(
            validate_artifact_attestation(&missing_conformance, &manifest),
            Err(RegistryError::Admission(_))
        ));

        let mut vulnerable = qualified.clone();
        vulnerable.vulnerability_policy_status = ArtifactCheckStatus::Failed;
        assert!(matches!(
            validate_artifact_attestation(&vulnerable, &manifest),
            Err(RegistryError::Admission(_))
        ));

        let mut incompatible_aip = qualified.clone();
        incompatible_aip.supported_aip_versions.clear();
        assert!(matches!(
            validate_artifact_attestation(&incompatible_aip, &manifest),
            Err(RegistryError::Admission(_))
        ));

        let mut incompatible_sdk = qualified.clone();
        incompatible_sdk.sdk_version_requirement = ">=999.0.0".to_owned();
        assert!(matches!(
            validate_artifact_attestation(&incompatible_sdk, &manifest),
            Err(RegistryError::Admission(_))
        ));

        let mut wrong_schemas = qualified;
        wrong_schemas.schema_bundle_digest = format!("sha256:{}", "f".repeat(64));
        assert!(matches!(
            validate_artifact_attestation(&wrong_schemas, &manifest),
            Err(RegistryError::Admission(_))
        ));
    }

    #[test]
    fn fleet_policy_preserves_isolation_without_broad_serialization_scopes() {
        let policy = AdmissionPolicy::fleet("quota:fleet");
        assert_eq!(policy.max_global_in_flight, u32::MAX);
        assert_eq!(policy.max_connector_type_in_flight, u32::MAX);
        assert!(policy.max_tenant_in_flight < u32::MAX);
        assert!(policy.max_instance_in_flight < u32::MAX);
        assert!(policy.max_binding_in_flight < u32::MAX);
        assert!(policy.max_tenant_retry_in_flight < u32::MAX);
        validate_admission_policy(&policy).expect("valid fleet policy");
    }

    #[tokio::test]
    async fn artifact_owner_must_match_connector_type_owner() {
        let registry = InMemoryConnectorRegistry::default();
        let connector_type_id = ConnectorTypeId::trusted("ctype_owner_test");
        registry
            .put_connector_type(ConnectorType {
                id: connector_type_id.clone(),
                name: "Owner test".to_owned(),
                owner: "Expected owner".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");
        let manifest = manifest(Vec::new());
        let mut attestation = qualified_attestation(&manifest, 'b', "sigstore:owner-test");
        attestation.owner = "Different owner".to_owned();
        let error = registry
            .admit_version(ConnectorVersion {
                id: ConnectorVersionId::trusted("cver_owner_test_v1"),
                connector_type_id,
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Admitted,
                manifest_digest: digest(&manifest),
                attestation,
                manifest,
                implementation_support: BTreeMap::new(),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect_err("owner mismatch");
        assert!(matches!(error, RegistryError::Admission(_)));
    }

    async fn installed_registry() -> (
        InMemoryConnectorRegistry,
        ConnectorInstanceId,
        ConnectorReplicaId,
        CapabilityId,
    ) {
        let registry = InMemoryConnectorRegistry::default();
        registry
            .put_admission_policy(AdmissionPolicy::conservative("quota:test"))
            .await
            .expect("admission policy");
        let connector_type_id = ConnectorTypeId::trusted("ctype_test");
        registry
            .put_connector_type(ConnectorType {
                id: connector_type_id.clone(),
                name: "Test".to_owned(),
                owner: "AIP".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");
        let capability_id = CapabilityId::trusted("cap:test:run");
        let manifest = manifest(vec![capability(capability_id.as_str())]);
        let version_id = ConnectorVersionId::trusted("cver_test_v1");
        registry
            .admit_version(ConnectorVersion {
                id: version_id.clone(),
                connector_type_id: connector_type_id.clone(),
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest_digest: digest(&manifest),
                attestation: qualified_attestation(&manifest, '1', "sigstore:test"),
                manifest,
                implementation_support: BTreeMap::from([(
                    capability_id.clone(),
                    CapabilityImplementationSupport {
                        invocation: true,
                        ..CapabilityImplementationSupport::default()
                    },
                )]),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("connector version");
        let instance_id = ConnectorInstanceId::trusted("cinst_test_acme");
        registry
            .put_instance(ConnectorInstance {
                id: instance_id.clone(),
                connector_type_id,
                version_id: version_id.clone(),
                tenant_id: "tenant-acme".to_owned(),
                config_revision: 1,
                secret_provider_ref: "vault://tenant-acme/test".to_owned(),
                status: ConnectorInstanceStatus::Enabled,
            })
            .await
            .expect("connector instance");
        let replica_id = ConnectorReplicaId::trusted("crepl_test_one");
        registry
            .put_replica(ConnectorReplica {
                id: replica_id.clone(),
                instance_id: instance_id.clone(),
                version_id,
                endpoint: "https://connector.test/aip/v1/messages".to_owned(),
                peer_principal_id: PrincipalId::trusted("service:test-connector-host"),
                peer_principal_kind: PrincipalKind::Service,
                peer_did: "did:key:test".to_owned(),
                trust_domain: "connectors.test".to_owned(),
                transport_profile: ProfileId::from("aip.native.http.v1"),
                topology: ConnectorTopology::default(),
                status: ConnectorReplicaStatus::Ready,
                lease_expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
                capacity: 2,
                active_assignments: 0,
                health_revision: 1,
                last_control_request_id: None,
                last_control_request_digest: None,
            })
            .await
            .expect("connector replica");
        registry
            .put_binding(CapabilityBinding {
                tenant_id: "tenant-acme".to_owned(),
                capability_id: capability_id.clone(),
                instance_id: instance_id.clone(),
                priority: 0,
                policy_revision: 1,
                credential_revision_ref: Some("credential-revision-7".to_owned()),
                quota_policy_ref: Some("quota:test".to_owned()),
                enabled: true,
            })
            .await
            .expect("binding");
        (registry, instance_id, replica_id, capability_id)
    }

    #[tokio::test]
    async fn catalog_is_tenant_scoped_and_cursor_is_revision_fenced() {
        let (registry, _instance_id, _replica_id, capability_id) = installed_registry().await;
        assert!(
            registry
                .get(
                    &capability_id,
                    &CatalogReadContext::for_tenant("tenant-acme")
                )
                .await
                .expect("catalog")
                .is_some()
        );
        assert!(
            registry
                .get(
                    &capability_id,
                    &CatalogReadContext::for_tenant("tenant-other")
                )
                .await
                .expect("catalog")
                .is_none()
        );
        let page = registry
            .query(
                CapabilityCatalogQuery {
                    limit: 1,
                    ..CapabilityCatalogQuery::default()
                },
                &CatalogReadContext::for_tenant("tenant-acme"),
            )
            .await
            .expect("page");
        assert_eq!(page.total, 1);
        assert_eq!(page.capabilities[0].capability.id, capability_id);
    }

    #[tokio::test]
    async fn catalog_pages_are_bounded_by_rows_and_canonical_bytes() {
        let connector_type_id = ConnectorTypeId::trusted("ctype_catalog_bytes");
        let capabilities = vec![
            capability("cap:test:catalog-a"),
            capability("cap:test:catalog-b"),
        ];
        let manifest = manifest(capabilities.clone());
        let definitions = capability_definitions(&manifest, &RegistryLimits::default())
            .expect("capability definitions");
        let max_definition_bytes = definitions
            .iter()
            .map(capability_definition_size)
            .collect::<Result<Vec<_>, _>>()
            .expect("definition sizes")
            .into_iter()
            .max()
            .expect("definition size");
        let limits = RegistryLimits {
            max_capability_bytes: max_definition_bytes,
            max_page_bytes: max_definition_bytes,
            ..RegistryLimits::default()
        };
        let registry = InMemoryConnectorRegistry::new(limits.clone());
        registry
            .put_connector_type(ConnectorType {
                id: connector_type_id.clone(),
                name: "Catalog byte test".to_owned(),
                owner: "AIP".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");
        registry
            .admit_version(ConnectorVersion {
                id: ConnectorVersionId::trusted("cver_catalog_bytes_v1"),
                connector_type_id,
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest_digest: digest(&manifest),
                attestation: qualified_attestation(&manifest, '8', "sigstore:catalog-bytes"),
                manifest,
                implementation_support: capabilities
                    .iter()
                    .map(|capability| {
                        (
                            capability.id.clone(),
                            CapabilityImplementationSupport {
                                invocation: true,
                                ..CapabilityImplementationSupport::default()
                            },
                        )
                    })
                    .collect(),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("connector version");

        let first = registry
            .query(
                CapabilityCatalogQuery {
                    limit: 200,
                    ..CapabilityCatalogQuery::default()
                },
                &CatalogReadContext::internal(),
            )
            .await
            .expect("first page");
        assert_eq!(first.total, 2);
        assert_eq!(first.capabilities.len(), 1);
        assert!(
            first
                .capabilities
                .iter()
                .map(capability_definition_size)
                .collect::<Result<Vec<_>, _>>()
                .expect("page sizes")
                .into_iter()
                .sum::<usize>()
                <= limits.max_page_bytes
        );
        let second = registry
            .query(
                CapabilityCatalogQuery {
                    cursor: first.next_cursor,
                    limit: 200,
                    ..CapabilityCatalogQuery::default()
                },
                &CatalogReadContext::internal(),
            )
            .await
            .expect("second page");
        assert_eq!(second.capabilities.len(), 1);
        assert!(second.next_cursor.is_none());
        assert_ne!(
            first.capabilities[0].capability.id,
            second.capabilities[0].capability.id
        );
    }

    #[tokio::test]
    async fn oversized_capability_is_rejected_during_version_admission() {
        let limits = RegistryLimits {
            max_capability_bytes: 256,
            max_page_bytes: 256,
            ..RegistryLimits::default()
        };
        let registry = InMemoryConnectorRegistry::new(limits);
        let connector_type_id = ConnectorTypeId::trusted("ctype_oversized_capability");
        registry
            .put_connector_type(ConnectorType {
                id: connector_type_id.clone(),
                name: "Oversized capability test".to_owned(),
                owner: "AIP".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");
        let mut oversized = capability("cap:test:oversized");
        oversized.description = Some("x".repeat(1_024));
        let manifest = manifest(vec![oversized.clone()]);
        let error = registry
            .admit_version(ConnectorVersion {
                id: ConnectorVersionId::trusted("cver_oversized_capability_v1"),
                connector_type_id,
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest_digest: digest(&manifest),
                attestation: qualified_attestation(&manifest, '9', "sigstore:oversized"),
                manifest,
                implementation_support: BTreeMap::from([(
                    oversized.id,
                    CapabilityImplementationSupport {
                        invocation: true,
                        ..CapabilityImplementationSupport::default()
                    },
                )]),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect_err("oversized capability");
        assert!(matches!(error, RegistryError::Admission(_)));
    }

    #[tokio::test]
    async fn action_route_is_pinned_and_capacity_is_released_once() {
        let (registry, _instance_id, replica_id, capability_id) = installed_registry().await;
        let request = RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id,
            tenant_id: "tenant-acme".to_owned(),
            topology: RouteTopologyPreference::default(),
        };
        let first = registry
            .resolve(request.clone())
            .await
            .expect("first route");
        let replay = registry
            .resolve(request.clone())
            .await
            .expect("replayed route");
        assert_eq!(first, replay);
        assert_eq!(first.replica_id, replica_id);
        registry
            .settle(&first, RouteSettlement::Completed)
            .await
            .expect("settle");
        registry
            .settle(&first, RouteSettlement::Completed)
            .await
            .expect("idempotent settle");
        let retry = registry.resolve(request).await.expect("pinned retry route");
        assert_eq!(first, retry);
        assert_eq!(
            registry
                .state
                .read()
                .await
                .replicas
                .get(&replica_id)
                .expect("replica")
                .active_assignments,
            1
        );
        registry
            .settle(&retry, RouteSettlement::OutcomeUnknown)
            .await
            .expect("retry settlement");
        assert_eq!(
            registry
                .state
                .read()
                .await
                .replicas
                .get(&replica_id)
                .expect("replica")
                .active_assignments,
            0
        );
    }

    #[tokio::test]
    async fn replica_heartbeat_does_not_invalidate_catalog_cursor_revision() {
        let (registry, instance_id, replica_id, _capability_id) = installed_registry().await;
        let before = registry.revision().await;
        let mut replica = registry
            .state
            .read()
            .await
            .replicas
            .get(&replica_id)
            .expect("replica")
            .clone();
        replica.health_revision += 1;
        replica.lease_expires_at += Duration::minutes(5);
        registry
            .put_replica(replica)
            .await
            .expect("renew replica lease");
        assert_eq!(registry.revision().await, before);
        assert_eq!(
            registry
                .state
                .read()
                .await
                .replicas
                .get(&replica_id)
                .expect("replica")
                .instance_id,
            instance_id
        );
    }

    #[tokio::test]
    async fn lease_expiry_releases_capacity_without_changing_the_pinned_route() {
        let (registry, instance_id, replica_id, capability_id) = installed_registry().await;
        let request = RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id,
            tenant_id: "tenant-acme".to_owned(),
            topology: RouteTopologyPreference::default(),
        };
        let assignment = registry
            .resolve(request.clone())
            .await
            .expect("initial route");
        let mut replica = registry
            .connector_replica(&replica_id)
            .await
            .expect("replica read")
            .expect("registered replica");
        replica.health_revision += 1;
        replica.lease_expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        registry
            .put_replica(replica)
            .await
            .expect("expire lease observation");
        let before = registry
            .fleet_status(OffsetDateTime::now_utc())
            .await
            .expect("fleet summary before expiry");
        assert_eq!(before.expired_leases, 1);
        assert_eq!(before.active_assignments, 1);

        assert_eq!(
            registry
                .expire_stale_replicas(OffsetDateTime::now_utc(), 10)
                .await
                .expect("expire replica"),
            1
        );
        let offline = registry
            .connector_replica(&replica_id)
            .await
            .expect("offline replica read")
            .expect("offline replica");
        assert_eq!(offline.status, ConnectorReplicaStatus::Offline);
        assert_eq!(offline.active_assignments, 0);
        assert!(matches!(
            registry.resolve(request.clone()).await,
            Err(RegistryError::ReplicaUnavailable(id)) if id == instance_id
        ));

        let mut recovered = offline;
        recovered.status = ConnectorReplicaStatus::Ready;
        recovered.health_revision += 1;
        recovered.lease_expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        registry
            .put_replica(recovered)
            .await
            .expect("recover replica");
        let retried = registry.resolve(request).await.expect("pinned retry route");
        assert_eq!(retried, assignment);
        registry
            .settle(&retried, RouteSettlement::Completed)
            .await
            .expect("settle recovered route");
    }

    #[tokio::test]
    async fn tenant_capacity_is_hard_and_released_by_the_assignment_fence() {
        let (registry, _instance_id, _replica_id, capability_id) = installed_registry().await;
        let mut policy = AdmissionPolicy::conservative("quota:test");
        policy.revision = 2;
        policy.max_global_in_flight = u32::MAX;
        policy.max_tenant_in_flight = 1;
        policy.max_connector_type_in_flight = u32::MAX;
        policy.max_instance_in_flight = u32::MAX;
        policy.max_binding_in_flight = u32::MAX;
        policy.max_tenant_retry_in_flight = u32::MAX;
        registry
            .put_admission_policy(policy)
            .await
            .expect("tight tenant policy");
        let first = registry
            .resolve(RouteResolutionRequest {
                action_id: ActionId::new(),
                capability_id: capability_id.clone(),
                tenant_id: "tenant-acme".to_owned(),
                topology: RouteTopologyPreference::default(),
            })
            .await
            .expect("first tenant route");
        assert_eq!(first.admission.base_scopes.len(), 1);
        assert_eq!(
            first.admission.base_scopes[0].kind,
            AdmissionScopeKind::Tenant
        );
        assert!(first.admission.retry_scope.is_none());
        let second = registry
            .resolve(RouteResolutionRequest {
                action_id: ActionId::new(),
                capability_id,
                tenant_id: "tenant-acme".to_owned(),
                topology: RouteTopologyPreference::default(),
            })
            .await
            .expect_err("tenant capacity must be hard");
        assert!(matches!(
            second,
            RegistryError::CapacityExceeded {
                scope: AdmissionScopeKind::Tenant,
                ..
            }
        ));
        registry
            .settle(&first, RouteSettlement::Completed)
            .await
            .expect("release tenant reservation");
    }

    #[tokio::test]
    async fn retried_attempts_use_a_separate_tenant_budget() {
        let (registry, _instance_id, _replica_id, capability_id) = installed_registry().await;
        let mut policy = AdmissionPolicy::conservative("quota:test");
        policy.revision = 2;
        policy.max_tenant_retry_in_flight = 1;
        registry
            .put_admission_policy(policy)
            .await
            .expect("retry policy");
        let requests = [ActionId::new(), ActionId::new()].map(|action_id| RouteResolutionRequest {
            action_id,
            capability_id: capability_id.clone(),
            tenant_id: "tenant-acme".to_owned(),
            topology: RouteTopologyPreference::default(),
        });
        let first = registry
            .resolve(requests[0].clone())
            .await
            .expect("first assignment");
        let second = registry
            .resolve(requests[1].clone())
            .await
            .expect("second assignment");
        registry
            .settle(&first, RouteSettlement::OutcomeUnknown)
            .await
            .expect("settle first attempt");
        registry
            .settle(&second, RouteSettlement::OutcomeUnknown)
            .await
            .expect("settle second attempt");
        let first_retry = registry
            .resolve(requests[0].clone())
            .await
            .expect("first retry");
        let second_retry = registry
            .resolve(requests[1].clone())
            .await
            .expect_err("retry capacity must be isolated");
        assert!(matches!(
            second_retry,
            RegistryError::CapacityExceeded {
                scope: AdmissionScopeKind::TenantRetry,
                ..
            }
        ));
        registry
            .settle(&first_retry, RouteSettlement::Completed)
            .await
            .expect("settle retried attempt");
    }

    #[tokio::test]
    async fn unknown_outcomes_open_the_pinned_replica_circuit() {
        let (registry, instance_id, _replica_id, capability_id) = installed_registry().await;
        let mut policy = AdmissionPolicy::conservative("quota:test");
        policy.revision = 2;
        policy.circuit_failure_threshold = 1;
        policy.circuit_open_ms = 1_000;
        registry
            .put_admission_policy(policy)
            .await
            .expect("circuit policy");
        let request = RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id,
            tenant_id: "tenant-acme".to_owned(),
            topology: RouteTopologyPreference::default(),
        };
        let assignment = registry
            .resolve(request.clone())
            .await
            .expect("initial route");
        registry
            .settle(&assignment, RouteSettlement::OutcomeUnknown)
            .await
            .expect("unknown settlement");
        assert!(matches!(
            registry.resolve(request).await,
            Err(RegistryError::ReplicaUnavailable(id)) if id == instance_id
        ));
    }

    #[tokio::test]
    async fn zonal_failure_routes_to_a_healthy_zone_without_crossing_a_residency_boundary() {
        let (registry, instance_id, original_replica_id, capability_id) =
            installed_registry().await;
        let original = registry
            .connector_replica(&original_replica_id)
            .await
            .expect("original replica read")
            .expect("original replica");
        let mut primary = original.clone();
        primary.id = ConnectorReplicaId::trusted("crepl_test_region_a_zone_1");
        primary.endpoint = "https://zone-1.connector.test/aip/v1/messages".to_owned();
        primary.peer_principal_id = PrincipalId::trusted("service:test-zone-1");
        primary.peer_did = "did:key:test-zone-1".to_owned();
        primary.topology = ConnectorTopology {
            region: "region-a".to_owned(),
            zone: "zone-1".to_owned(),
            capacity_class: "standard".to_owned(),
        };
        registry
            .put_replica(primary.clone())
            .await
            .expect("primary zone replica");
        let mut secondary = primary.clone();
        secondary.id = ConnectorReplicaId::trusted("crepl_test_region_a_zone_2");
        secondary.endpoint = "https://zone-2.connector.test/aip/v1/messages".to_owned();
        secondary.peer_principal_id = PrincipalId::trusted("service:test-zone-2");
        secondary.peer_did = "did:key:test-zone-2".to_owned();
        secondary.topology.zone = "zone-2".to_owned();
        registry
            .put_replica(secondary.clone())
            .await
            .expect("secondary zone replica");
        let mut remote = primary.clone();
        remote.id = ConnectorReplicaId::trusted("crepl_test_region_b_zone_1");
        remote.endpoint = "https://region-b.connector.test/aip/v1/messages".to_owned();
        remote.peer_principal_id = PrincipalId::trusted("service:test-region-b");
        remote.peer_did = "did:key:test-region-b".to_owned();
        remote.topology.region = "region-b".to_owned();
        registry
            .put_replica(remote)
            .await
            .expect("remote region replica");
        let topology = RouteTopologyPreference {
            region: Some("region-a".to_owned()),
            zone: Some("zone-1".to_owned()),
            capacity_class: Some("standard".to_owned()),
            allow_cross_region: false,
        };
        let selected = registry
            .resolve(RouteResolutionRequest {
                action_id: ActionId::new(),
                capability_id: capability_id.clone(),
                tenant_id: "tenant-acme".to_owned(),
                topology: topology.clone(),
            })
            .await
            .expect("preferred zone route");
        assert_eq!(selected.replica_id, primary.id);
        registry
            .settle(&selected, RouteSettlement::Completed)
            .await
            .expect("settle preferred route");

        primary.status = ConnectorReplicaStatus::Offline;
        primary.health_revision += 1;
        registry
            .put_replica(primary)
            .await
            .expect("take preferred zone offline");
        let failed_over = registry
            .resolve(RouteResolutionRequest {
                action_id: ActionId::new(),
                capability_id: capability_id.clone(),
                tenant_id: "tenant-acme".to_owned(),
                topology: topology.clone(),
            })
            .await
            .expect("same-region zone failover");
        assert_eq!(failed_over.replica_id, secondary.id);
        registry
            .settle(&failed_over, RouteSettlement::Completed)
            .await
            .expect("settle same-region route");

        secondary.status = ConnectorReplicaStatus::Offline;
        secondary.health_revision += 1;
        registry
            .put_replica(secondary)
            .await
            .expect("take secondary zone offline");
        assert!(matches!(
            registry
                .resolve(RouteResolutionRequest {
                    action_id: ActionId::new(),
                    capability_id,
                    tenant_id: "tenant-acme".to_owned(),
                    topology,
                })
                .await,
            Err(RegistryError::ReplicaUnavailable(id)) if id == instance_id
        ));
    }

    #[tokio::test]
    async fn incompatible_contract_reuse_is_rejected() {
        let (registry, _instance_id, _replica_id, capability_id) = installed_registry().await;
        let connector_type_id = ConnectorTypeId::trusted("ctype_test");
        let mut changed = capability(capability_id.as_str());
        changed.input_schema = json!({
            "type": "object",
            "required": ["different"]
        });
        let manifest = manifest(vec![changed]);
        let error = registry
            .admit_version(ConnectorVersion {
                id: ConnectorVersionId::trusted("cver_test_v2"),
                connector_type_id,
                version: "2.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest_digest: digest(&manifest),
                attestation: qualified_attestation(&manifest, '4', "sigstore:test-v2"),
                manifest,
                implementation_support: BTreeMap::from([(
                    capability_id,
                    CapabilityImplementationSupport {
                        invocation: true,
                        ..CapabilityImplementationSupport::default()
                    },
                )]),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect_err("contract collision");
        assert!(matches!(error, RegistryError::Conflict(_)));
    }
}
