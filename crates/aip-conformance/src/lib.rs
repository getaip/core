//! Conformance checks for AIP implementations.

#![forbid(unsafe_code)]

use aip_core::{
    Capability, CapabilityId, CompensationMode, Envelope, IdempotencyRequirement, Manifest,
    MessageBody, ProfileId, RetrySafety, RiskLevel, SideEffect, TransactionMode, validate_envelope,
};
use aip_discovery::{CapabilityImplementationSupport, DiscoveryService, ManifestAdmissionPolicy};
use aip_schema::{SchemaRegistry, SchemaResult};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// A conformance check result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    /// Check name.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Detail message.
    pub detail: String,
}

/// Ordered conformance report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConformanceReport {
    /// Individual check results.
    pub checks: Vec<CheckResult>,
}

impl ConformanceReport {
    /// Returns true when all checks passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }

    /// Adds one check to the report.
    pub fn push(&mut self, check: CheckResult) {
        self.checks.push(check);
    }
}

/// Behavioral scenario executed by the connector conformance kit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectorConformanceScenario {
    /// Transport actor, tenant, and opaque credential mapping.
    IdentityAndCredentials,
    /// Rejection of invalid inputs and invalid provider outputs.
    SchemaEnforcement,
    /// Duplicate delivery, idempotency, and collision behavior.
    IdempotencyAndDuplicates,
    /// Retry classification, backoff, exhaustion, and dead-letter behavior.
    RetryAndExhaustion,
    /// Cancellation before dispatch, while running, and after settlement.
    CancellationRaces,
    /// Ordered incremental output and bounded backpressure.
    StreamingAndBackpressure,
    /// Lossless typed errors and uncertain provider outcomes.
    ErrorsAndUncertainOutcomes,
    /// Approval authority, quorum, evidence, and exactly-once resume.
    ApprovalLifecycle,
    /// Plan, commit, reconciliation, and governed compensation.
    TransactionLifecycle,
    /// Audit correlation, receipts, redaction, and secret non-disclosure.
    AuditAndRedaction,
    /// Signature, timestamp skew, and delivery replay rejection.
    WebhookSecurity,
    /// Restart recovery, reconnect, and duplicate-effect fencing.
    RestartAndReconnect,
}

impl ConnectorConformanceScenario {
    /// Returns the stable check id suffix.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::IdentityAndCredentials => "identity_credentials",
            Self::SchemaEnforcement => "schema_enforcement",
            Self::IdempotencyAndDuplicates => "idempotency_duplicates",
            Self::RetryAndExhaustion => "retry_exhaustion",
            Self::CancellationRaces => "cancellation_races",
            Self::StreamingAndBackpressure => "streaming_backpressure",
            Self::ErrorsAndUncertainOutcomes => "errors_uncertain_outcomes",
            Self::ApprovalLifecycle => "approval_lifecycle",
            Self::TransactionLifecycle => "transaction_lifecycle",
            Self::AuditAndRedaction => "audit_redaction",
            Self::WebhookSecurity => "webhook_security",
            Self::RestartAndReconnect => "restart_reconnect",
        }
    }

    const fn required_assertions(self) -> &'static [&'static str] {
        match self {
            Self::IdentityAndCredentials => &[
                "transport_actor_bound",
                "tenant_isolated",
                "credential_handle_opaque",
            ],
            Self::SchemaEnforcement => &["invalid_input_rejected", "invalid_output_rejected"],
            Self::IdempotencyAndDuplicates => &[
                "duplicate_suppressed",
                "collision_rejected",
                "delivery_id_stable",
            ],
            Self::RetryAndExhaustion => &[
                "retryable_error_preserved",
                "backoff_observed",
                "exhaustion_dead_lettered",
            ],
            Self::CancellationRaces => &[
                "before_dispatch_cancelled",
                "in_flight_cancelled",
                "late_cancel_preserved_terminal",
            ],
            Self::StreamingAndBackpressure => &[
                "ordered_chunks",
                "bounded_backpressure",
                "terminal_chunk_unique",
            ],
            Self::ErrorsAndUncertainOutcomes => &[
                "protocol_fields_preserved",
                "uncertain_outcome_reconciled",
                "error_secrets_redacted",
            ],
            Self::ApprovalLifecycle => &[
                "authority_verified",
                "quorum_enforced",
                "evidence_persisted",
                "resume_once",
            ],
            Self::TransactionLifecycle => &[
                "plan_before_commit",
                "provider_operation_checkpointed",
                "reconcile_before_retry",
                "compensation_governed",
            ],
            Self::AuditAndRedaction => &[
                "receipts_emitted",
                "audit_correlated",
                "sensitive_fields_redacted",
                "raw_secret_absent",
            ],
            Self::WebhookSecurity => &["signature_verified", "skew_rejected", "replay_rejected"],
            Self::RestartAndReconnect => &[
                "state_recovered",
                "duplicate_effect_prevented",
                "reconnect_cursor_resumed",
            ],
        }
    }
}

const CONNECTOR_CONFORMANCE_SCENARIOS: [ConnectorConformanceScenario; 12] = [
    ConnectorConformanceScenario::IdentityAndCredentials,
    ConnectorConformanceScenario::SchemaEnforcement,
    ConnectorConformanceScenario::IdempotencyAndDuplicates,
    ConnectorConformanceScenario::RetryAndExhaustion,
    ConnectorConformanceScenario::CancellationRaces,
    ConnectorConformanceScenario::StreamingAndBackpressure,
    ConnectorConformanceScenario::ErrorsAndUncertainOutcomes,
    ConnectorConformanceScenario::ApprovalLifecycle,
    ConnectorConformanceScenario::TransactionLifecycle,
    ConnectorConformanceScenario::AuditAndRedaction,
    ConnectorConformanceScenario::WebhookSecurity,
    ConnectorConformanceScenario::RestartAndReconnect,
];

/// Evidence source accepted by the behavioral connector harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorEvidenceSource {
    /// A deterministic provider implementation that records real requests,
    /// failures, retries, cancellation, and side effects.
    DeterministicProviderDouble,
    /// An isolated live provider deployment.
    IsolatedLiveProvider,
}

/// Machine-readable observations produced by one executable scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorScenarioEvidence {
    /// Whether the scenario was executed. `false` is accepted only when no
    /// published capability or profile requires the behavior.
    pub executed: bool,
    /// Source that produced the observations.
    pub source: ConnectorEvidenceSource,
    /// Named invariant outcomes required by the shared harness.
    pub assertions: BTreeMap<String, bool>,
    /// Stable log, trace, receipt, or fixture identifiers retained by CI.
    pub artifacts: Vec<String>,
    /// Redacted operator-facing detail.
    pub detail: String,
}

impl ConnectorScenarioEvidence {
    /// Builds executed evidence from named invariant outcomes.
    #[must_use]
    pub fn executed(
        source: ConnectorEvidenceSource,
        assertions: impl IntoIterator<Item = (impl Into<String>, bool)>,
        artifacts: Vec<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            executed: true,
            source,
            assertions: assertions
                .into_iter()
                .map(|(name, passed)| (name.into(), passed))
                .collect(),
            artifacts,
            detail: detail.into(),
        }
    }

    /// Marks an unclaimed optional scenario as not applicable.
    #[must_use]
    pub fn not_applicable(detail: impl Into<String>) -> Self {
        Self {
            executed: false,
            source: ConnectorEvidenceSource::DeterministicProviderDouble,
            assertions: BTreeMap::new(),
            artifacts: Vec::new(),
            detail: detail.into(),
        }
    }
}

/// Deployment-specific executable driver consumed by the shared harness.
///
/// Implementations must exercise the real connector through an isolated live
/// provider or deterministic provider double. Returning static booleans from
/// production code is not valid release evidence; artifact ids are mandatory
/// for every executed scenario so CI can retain the underlying trace.
#[async_trait]
pub trait ConnectorConformanceDriver: Send + Sync {
    /// Stable connector id.
    fn connector_id(&self) -> &str;
    /// Exact manifest published by the connector under test.
    fn manifest(&self) -> &Manifest;
    /// Actual per-capability implementation support used during admission.
    fn implementation_support(&self) -> HashMap<CapabilityId, CapabilityImplementationSupport>;
    /// Executes one behavioral scenario and returns observed invariants.
    async fn exercise(
        &self,
        scenario: ConnectorConformanceScenario,
    ) -> Result<ConnectorScenarioEvidence, String>;
}

/// Runs atomic admission and every RFC 0004 connector behavior family.
pub async fn run_connector_conformance(
    driver: &dyn ConnectorConformanceDriver,
) -> ConformanceReport {
    let mut report = ConformanceReport::default();
    let manifest = driver.manifest();
    let support = driver.implementation_support();
    match DiscoveryService::admit_manifest(
        manifest.clone(),
        &ManifestAdmissionPolicy::default(),
        &support,
    ) {
        Ok(_) => report.push(CheckResult {
            name: "connector.atomic_manifest_admission".to_owned(),
            passed: true,
            detail: driver.connector_id().to_owned(),
        }),
        Err(admission) => report.push(CheckResult {
            name: "connector.atomic_manifest_admission".to_owned(),
            passed: false,
            detail: admission.to_string(),
        }),
    }

    for scenario in CONNECTOR_CONFORMANCE_SCENARIOS {
        let required = connector_scenario_required(manifest, scenario);
        let check_name = format!("connector.behavior.{}", scenario.id());
        let evidence = driver.exercise(scenario).await;
        let check = match evidence {
            Err(error) => CheckResult {
                name: check_name,
                passed: false,
                detail: error,
            },
            Ok(evidence) if !evidence.executed && required => CheckResult {
                name: check_name,
                passed: false,
                detail: format!(
                    "published connector contract requires this scenario: {}",
                    evidence.detail
                ),
            },
            Ok(evidence) if !evidence.executed => CheckResult {
                name: check_name,
                passed: true,
                detail: format!("not applicable: {}", evidence.detail),
            },
            Ok(evidence) => {
                let missing = scenario
                    .required_assertions()
                    .iter()
                    .filter(|assertion| !evidence.assertions.contains_key(**assertion))
                    .copied()
                    .collect::<Vec<_>>();
                let failed = scenario
                    .required_assertions()
                    .iter()
                    .filter(|assertion| evidence.assertions.get(**assertion) == Some(&false))
                    .copied()
                    .collect::<Vec<_>>();
                let artifacts_valid = !evidence.artifacts.is_empty()
                    && evidence
                        .artifacts
                        .iter()
                        .all(|artifact| !artifact.trim().is_empty());
                let passed = missing.is_empty() && failed.is_empty() && artifacts_valid;
                CheckResult {
                    name: check_name,
                    passed,
                    detail: if passed {
                        format!(
                            "{:?}; artifacts={}; {}",
                            evidence.source,
                            evidence.artifacts.join(","),
                            evidence.detail
                        )
                    } else {
                        format!(
                            "missing={missing:?}; failed={failed:?}; artifacts_valid={artifacts_valid}; {}",
                            evidence.detail
                        )
                    },
                }
            }
        };
        report.push(check);
    }
    report
}

fn connector_scenario_required(
    manifest: &Manifest,
    scenario: ConnectorConformanceScenario,
) -> bool {
    let contracts = manifest
        .capabilities
        .iter()
        .filter_map(|capability| capability.contract.as_ref())
        .collect::<Vec<_>>();
    match scenario {
        ConnectorConformanceScenario::IdentityAndCredentials
        | ConnectorConformanceScenario::SchemaEnforcement
        | ConnectorConformanceScenario::ErrorsAndUncertainOutcomes
        | ConnectorConformanceScenario::AuditAndRedaction
        | ConnectorConformanceScenario::RestartAndReconnect => !manifest.capabilities.is_empty(),
        ConnectorConformanceScenario::IdempotencyAndDuplicates => contracts
            .iter()
            .any(|contract| contract.idempotency.requirement == IdempotencyRequirement::Required),
        ConnectorConformanceScenario::RetryAndExhaustion => contracts
            .iter()
            .any(|contract| contract.execution.supports_retry),
        ConnectorConformanceScenario::CancellationRaces => contracts
            .iter()
            .any(|contract| contract.execution.supports_cancel),
        ConnectorConformanceScenario::StreamingAndBackpressure => contracts
            .iter()
            .any(|contract| contract.execution.supports_streaming),
        ConnectorConformanceScenario::ApprovalLifecycle => contracts.iter().any(|contract| {
            contract
                .approval
                .as_ref()
                .is_some_and(|approval| approval.required)
        }),
        ConnectorConformanceScenario::TransactionLifecycle => contracts
            .iter()
            .any(|contract| contract.transaction.is_some()),
        ConnectorConformanceScenario::WebhookSecurity => manifest
            .profiles
            .iter()
            .any(|profile| profile.as_str() == aip_profile_webhook::PROFILE_ID),
    }
}

/// Core conformance suite.
#[derive(Clone, Debug, Default)]
pub struct CoreConformance {
    schemas: SchemaRegistry,
}

impl CoreConformance {
    /// Creates the core conformance suite.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schemas: SchemaRegistry::new(),
        }
    }

    /// Validates a native envelope against core and schema requirements.
    pub fn check_envelope(&self, envelope: &Envelope) -> CheckResult {
        match self.schemas.validate_envelope(envelope) {
            Ok(()) => CheckResult {
                name: "core.envelope".to_owned(),
                passed: true,
                detail: "valid".to_owned(),
            },
            Err(error) => CheckResult {
                name: "core.envelope".to_owned(),
                passed: false,
                detail: error.to_string(),
            },
        }
    }

    /// Validates a manifest against core AIP publication requirements.
    #[must_use]
    pub fn check_manifest(manifest: &Manifest) -> CheckResult {
        let mut errors = Vec::new();
        if manifest.manifest_version.trim().is_empty() {
            errors.push("manifest_version is empty");
        }
        if manifest.profiles.is_empty() {
            errors.push("profiles must not be empty");
        }
        for capability in &manifest.capabilities {
            if let Err(error) = check_capability(capability) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            CheckResult {
                name: "discovery.manifest".to_owned(),
                passed: true,
                detail: "valid".to_owned(),
            }
        } else {
            CheckResult {
                name: "discovery.manifest".to_owned(),
                passed: false,
                detail: errors.join("; "),
            }
        }
    }

    /// Runs the core conformance suite against a manifest.
    #[must_use]
    pub fn report_for_manifest(manifest: &Manifest) -> ConformanceReport {
        let mut report = ConformanceReport::default();
        report.push(Self::check_manifest(manifest));
        report.push(check_profile_set(manifest, &[]));
        report.push(check_profile_bindings(manifest));
        report.push(check_enterprise_capability_contracts(manifest));
        report.push(check_mcp_projection(manifest));
        report
    }

    /// Ensures all core message types can be represented.
    #[must_use]
    pub fn check_message_body(body: &MessageBody) -> CheckResult {
        let envelope = Envelope::new(body.clone());
        match validate_envelope(&envelope) {
            Ok(()) => CheckResult {
                name: "core.message_body".to_owned(),
                passed: true,
                detail: envelope.message_type.as_str().to_owned(),
            },
            Err(error) => CheckResult {
                name: "core.message_body".to_owned(),
                passed: false,
                detail: error.to_string(),
            },
        }
    }

    /// Exports the schema registry.
    pub fn schemas(&self) -> SchemaResult<Vec<(&'static str, serde_json::Value)>> {
        Ok(self.schemas.all())
    }
}

/// Validates that a manifest advertises required profiles and has no empty profile ids.
#[must_use]
pub fn check_profile_set(manifest: &Manifest, required: &[ProfileId]) -> CheckResult {
    let mut errors = Vec::new();
    for profile in &manifest.profiles {
        if profile.as_str().trim().is_empty() {
            errors.push("profile id is empty".to_owned());
        }
    }
    for required_profile in required {
        if !manifest.profiles.contains(required_profile) {
            errors.push(format!("missing required profile `{required_profile}`"));
        }
    }
    if errors.is_empty() {
        CheckResult {
            name: "discovery.profile_set".to_owned(),
            passed: true,
            detail: format!("{} profiles", manifest.profiles.len()),
        }
    } else {
        CheckResult {
            name: "discovery.profile_set".to_owned(),
            passed: false,
            detail: errors.join("; "),
        }
    }
}

/// Validates that an AIP manifest can be projected into MCP `tools/list`.
#[must_use]
pub fn check_mcp_projection(manifest: &Manifest) -> CheckResult {
    let projected = aip_profile_mcp::tools_list_result(manifest);
    let tools = projected
        .get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if tools.len() != manifest.capabilities.len() {
        return CheckResult {
            name: "profile.mcp.tools_list".to_owned(),
            passed: false,
            detail: format!(
                "projected {} tools for {} capabilities",
                tools.len(),
                manifest.capabilities.len()
            ),
        };
    }
    let missing_names = tools
        .iter()
        .filter(|tool| tool.get("name").and_then(Value::as_str).is_none())
        .count();
    if missing_names == 0 {
        CheckResult {
            name: "profile.mcp.tools_list".to_owned(),
            passed: true,
            detail: format!("{} tools", tools.len()),
        }
    } else {
        CheckResult {
            name: "profile.mcp.tools_list".to_owned(),
            passed: false,
            detail: format!("{missing_names} tools missing name"),
        }
    }
}

/// Validates that advertised profiles have concrete compatibility binding metadata.
#[must_use]
pub fn check_profile_bindings(manifest: &Manifest) -> CheckResult {
    let compatibility = manifest.compatibility.as_ref();
    let mut errors = Vec::new();
    for profile in &manifest.profiles {
        match profile.as_str() {
            "aip.native.http.v1" => {
                if !has_string_pointer(compatibility, "/native_http/messages")
                    || !has_string_pointer(compatibility, "/native_http/manifest")
                {
                    errors.push(
                        "native HTTP profile requires native_http messages and manifest paths",
                    );
                }
            }
            "aip.native.nats.v1" => {
                if !has_string_pointer(compatibility, "/native_nats/subject") {
                    errors.push("native NATS profile requires native_nats subject");
                }
            }
            aip_profile_mcp::PROFILE_ID => {
                if !has_string_pointer(compatibility, "/mcp/jsonrpc") {
                    errors.push("MCP profile requires mcp jsonrpc path");
                }
            }
            "aip.a2a.compat.v1" => {
                if !has_string_pointer(compatibility, "/a2a/agent_card")
                    || !has_string_pointer(compatibility, "/a2a/jsonrpc")
                {
                    errors.push("A2A profile requires a2a agent_card and jsonrpc paths");
                }
            }
            aip_profile_webhook::PROFILE_ID if manifest.channels.is_empty() => {
                errors.push("webhook profile requires at least one channel descriptor");
            }
            _ => {}
        }
    }
    if errors.is_empty() {
        CheckResult {
            name: "discovery.profile_bindings".to_owned(),
            passed: true,
            detail: "valid".to_owned(),
        }
    } else {
        CheckResult {
            name: "discovery.profile_bindings".to_owned(),
            passed: false,
            detail: errors.join("; "),
        }
    }
}

/// Validates connector-public manifest requirements.
#[must_use]
pub fn check_connector_manifest(connector_id: &str, manifest: &Manifest) -> CheckResult {
    let compatibility_mentions_connector = manifest
        .compatibility
        .as_ref()
        .is_some_and(|value| value.to_string().contains(connector_id));
    let has_surface = !manifest.capabilities.is_empty()
        || !manifest.resources.is_empty()
        || !manifest.channels.is_empty();
    if compatibility_mentions_connector && has_surface {
        CheckResult {
            name: "connector.manifest".to_owned(),
            passed: true,
            detail: connector_id.to_owned(),
        }
    } else {
        CheckResult {
            name: "connector.manifest".to_owned(),
            passed: false,
            detail: format!(
                "connector `{connector_id}` must expose compatibility metadata and at least one capability/resource/channel"
            ),
        }
    }
}

/// Manifest-level rules that keep connector-specific lifecycle details out of
/// `aip-core` while still making the projection explicit and testable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorBoundarySpec<'a> {
    /// Stable connector id, for example `dify` or `chatwoot`.
    pub connector_id: &'a str,
    /// Connector-owned profile id used for product-specific binding metadata.
    pub connector_profile: &'a str,
    /// Required capability id prefix for all capabilities owned by the connector.
    pub capability_id_prefix: &'a str,
    /// Binding metadata keys that must be present for every connector binding.
    pub required_binding_metadata: &'a [&'a str],
}

/// Validates RFC 0003 adapter/profile boundary rules for one connector manifest.
///
/// This check intentionally validates the published AIP manifest instead of
/// product DTOs. Product-specific operations remain inside connector-owned
/// profile bindings and compatibility metadata, while `aip-core` sees native
/// capabilities, resources, channels, and events only.
#[must_use]
pub fn check_connector_boundary(
    manifest: &Manifest,
    spec: ConnectorBoundarySpec<'_>,
) -> CheckResult {
    let mut errors = Vec::new();
    if !manifest
        .profiles
        .iter()
        .any(|profile| profile.as_str() == spec.connector_profile)
    {
        errors.push(format!(
            "connector `{}` must advertise profile `{}`",
            spec.connector_id, spec.connector_profile
        ));
    }
    if !compatibility_mentions_connector(manifest, spec.connector_id) {
        errors.push(format!(
            "connector `{}` must declare itself in manifest compatibility metadata",
            spec.connector_id
        ));
    }
    if manifest.capabilities.is_empty()
        && manifest.resources.is_empty()
        && manifest.channels.is_empty()
    {
        errors.push(format!(
            "connector `{}` must expose at least one capability, resource, or channel",
            spec.connector_id
        ));
    }
    for capability in &manifest.capabilities {
        let capability_id = capability.id.as_str();
        if !capability_id.starts_with(spec.capability_id_prefix) {
            errors.push(format!(
                "{capability_id} must use connector-owned prefix `{}`",
                spec.capability_id_prefix
            ));
        }
        let matching_bindings = capability
            .bindings
            .iter()
            .filter(|binding| binding.profile.as_str() == spec.connector_profile)
            .collect::<Vec<_>>();
        if matching_bindings.is_empty() {
            errors.push(format!(
                "{capability_id} must publish a `{}` binding",
                spec.connector_profile
            ));
            continue;
        }
        for binding in matching_bindings {
            for required_key in spec.required_binding_metadata {
                if !binding
                    .metadata
                    .get(*required_key)
                    .is_some_and(non_empty_json_value)
                {
                    errors.push(format!(
                        "{capability_id} `{}` binding missing metadata `{required_key}`",
                        spec.connector_profile
                    ));
                }
            }
        }
    }
    if errors.is_empty() {
        CheckResult {
            name: "rfc0003.connector_boundary".to_owned(),
            passed: true,
            detail: format!(
                "{} capabilities under {}",
                manifest.capabilities.len(),
                spec.connector_profile
            ),
        }
    } else {
        CheckResult {
            name: "rfc0003.connector_boundary".to_owned(),
            passed: false,
            detail: errors.join("; "),
        }
    }
}

/// Evidence flags for the RFC 0003 runtime/conformance matrix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rfc0003RuntimeEvidence {
    /// File-backed runtime state survives restart.
    pub file_restart_recovery: bool,
    /// SQL-backed runtime state survives restart.
    pub sql_restart_recovery: bool,
    /// Unauthorized action lookup is covered.
    pub unauthorized_action_lookup: bool,
    /// Result-not-ready behavior is covered.
    pub result_not_ready: bool,
    /// Expired cursor behavior is covered.
    pub expired_cursor: bool,
    /// Cross-tenant or mismatched session behavior is covered.
    pub tenant_or_session_mismatch: bool,
    /// Missing resource and resource ACL behavior is covered.
    pub missing_or_forbidden_resource: bool,
    /// Callback lease, recovery, and dead-letter behavior is covered.
    pub callback_delivery_recovery: bool,
    /// External network WebSocket behavior is covered.
    pub external_websocket: bool,
    /// Adapter/profile boundary conformance is covered.
    pub connector_boundary: bool,
}

/// Builds a conformance report from explicit RFC 0003 runtime evidence.
#[must_use]
pub fn rfc0003_runtime_matrix_report(evidence: &Rfc0003RuntimeEvidence) -> ConformanceReport {
    let mut report = ConformanceReport::default();
    report.push(evidence_check(
        "rfc0003.runtime.file_restart_recovery",
        evidence.file_restart_recovery,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.sql_restart_recovery",
        evidence.sql_restart_recovery,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.unauthorized_action_lookup",
        evidence.unauthorized_action_lookup,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.result_not_ready",
        evidence.result_not_ready,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.expired_cursor",
        evidence.expired_cursor,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.tenant_or_session_mismatch",
        evidence.tenant_or_session_mismatch,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.missing_or_forbidden_resource",
        evidence.missing_or_forbidden_resource,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.callback_delivery_recovery",
        evidence.callback_delivery_recovery,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.external_websocket",
        evidence.external_websocket,
    ));
    report.push(evidence_check(
        "rfc0003.runtime.connector_boundary",
        evidence.connector_boundary,
    ));
    report
}

/// Validates a signed HTTP webhook profile delivery.
#[must_use]
pub fn check_webhook_signature(
    secret: &[u8],
    headers: &aip_profile_webhook::WebhookHeaders,
    payload: &[u8],
    max_skew_seconds: i64,
) -> CheckResult {
    match aip_profile_webhook::verify(secret, headers, payload, max_skew_seconds) {
        Ok(()) => CheckResult {
            name: "profile.webhook.signature".to_owned(),
            passed: true,
            detail: headers.delivery.clone(),
        },
        Err(error) => CheckResult {
            name: "profile.webhook.signature".to_owned(),
            passed: false,
            detail: error.to_string(),
        },
    }
}

/// Runs manifest-level checks for a deployed gateway.
#[must_use]
pub fn gateway_manifest_report(
    manifest: &Manifest,
    required_profiles: &[ProfileId],
) -> ConformanceReport {
    let mut report = ConformanceReport::default();
    report.push(CoreConformance::check_manifest(manifest));
    report.push(check_profile_set(manifest, required_profiles));
    report.push(check_profile_bindings(manifest));
    report.push(check_enterprise_capability_contracts(manifest));
    report.push(check_mcp_projection(manifest));
    report
}

/// Validates enterprise Capability Contract 2.0 declarations.
#[must_use]
pub fn check_enterprise_capability_contracts(manifest: &Manifest) -> CheckResult {
    let mut errors = Vec::new();
    for capability in &manifest.capabilities {
        let Some(contract) = &capability.contract else {
            if capability.requires_human_approval == Some(true)
                || matches!(capability.risk, Some(RiskLevel::High | RiskLevel::Critical))
            {
                errors.push(format!(
                    "{} requires enterprise policy but has no CapabilityContract",
                    capability.id
                ));
            }
            continue;
        };
        if contract.side_effects.is_empty() {
            errors.push(format!("{} contract side_effects is empty", capability.id));
        }
        if !contract.execution.supports_sync
            && !contract.execution.supports_async
            && !contract.execution.supports_streaming
        {
            errors.push(format!(
                "{} contract execution supports no invocation mode",
                capability.id
            ));
        }
        if contract.idempotency.requirement == IdempotencyRequirement::Required
            && !contract.execution.supports_retry
            && matches!(
                contract.execution.retry_safety,
                RetrySafety::Safe | RetrySafety::SafeWithIdempotencyKey
            )
        {
            errors.push(format!(
                "{} contract declares retry safety without retry support",
                capability.id
            ));
        }
        if let Some(approval) = &contract.approval
            && approval.required
            && approval.evidence_requirements.is_empty()
        {
            errors.push(format!(
                "{} approval policy should declare evidence requirements",
                capability.id
            ));
        }
        if (contract.data.contains_pii
            || matches!(
                contract.data.sensitivity,
                aip_core::DataSensitivity::Restricted | aip_core::DataSensitivity::Regulated
            ))
            && !contract.data.redaction_required
        {
            errors.push(format!(
                "{} restricted, regulated, or PII-bearing contract must require redaction",
                capability.id
            ));
        }
        if let Some(credentials) = &contract.credentials {
            if credentials.required && credentials.required_scopes.is_empty() {
                errors.push(format!(
                    "{} required credential policy should declare required scopes",
                    capability.id
                ));
            }
            if credentials
                .accepted_issuers
                .iter()
                .any(|issuer| issuer.trim().is_empty())
            {
                errors.push(format!(
                    "{} credential policy has an empty accepted issuer",
                    capability.id
                ));
            }
            if credentials
                .required_scopes
                .iter()
                .any(|scope| scope.trim().is_empty())
            {
                errors.push(format!(
                    "{} credential policy has an empty required scope",
                    capability.id
                ));
            }
        }
        if contract
            .side_effects
            .iter()
            .any(|effect| !matches!(effect, SideEffect::Read))
            && contract.idempotency.requirement != IdempotencyRequirement::Required
        {
            errors.push(format!(
                "{} mutating contract must require idempotency",
                capability.id
            ));
        }
        if contract.side_effects.iter().any(|effect| {
            matches!(
                effect,
                SideEffect::Financial
                    | SideEffect::Legal
                    | SideEffect::Medical
                    | SideEffect::Identity
                    | SideEffect::Delete
                    | SideEffect::SendMessage
            )
        }) && !contract
            .approval
            .as_ref()
            .is_some_and(|approval| approval.required)
        {
            errors.push(format!(
                "{} regulated or externally visible side effects must require approval",
                capability.id
            ));
        }
        if let Some(transaction) = &contract.transaction
            && transaction.supported_modes.is_empty()
        {
            errors.push(format!(
                "{} transaction contract has no supported modes",
                capability.id
            ));
        }
        if let Some(transaction) = &contract.transaction
            && transaction
                .supported_modes
                .contains(&TransactionMode::Commit)
            && !transaction.supported_modes.contains(&TransactionMode::Plan)
        {
            errors.push(format!(
                "{} commit support must also publish plan support",
                capability.id
            ));
        }
        if let Some(compensation) = &contract.compensation
            && compensation.mode == CompensationMode::Supported
            && compensation.compensation_capability_id.is_none()
        {
            errors.push(format!(
                "{} compensation is supported but no compensation capability is declared",
                capability.id
            ));
        }
    }
    if errors.is_empty() {
        CheckResult {
            name: "enterprise.capability_contract".to_owned(),
            passed: true,
            detail: "valid".to_owned(),
        }
    } else {
        CheckResult {
            name: "enterprise.capability_contract".to_owned(),
            passed: false,
            detail: errors.join("; "),
        }
    }
}

fn has_string_pointer(value: Option<&Value>, pointer: &str) -> bool {
    value
        .and_then(|value| value.pointer(pointer))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn compatibility_mentions_connector(manifest: &Manifest, connector_id: &str) -> bool {
    let Some(compatibility) = &manifest.compatibility else {
        return false;
    };
    let normalized = normalize_connector_id(connector_id);
    compatibility
        .get("connector")
        .or_else(|| compatibility.get("system"))
        .and_then(Value::as_str)
        .is_some_and(|value| normalize_connector_id(value).contains(&normalized))
        || compatibility.to_string().contains(connector_id)
}

fn normalize_connector_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn non_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn evidence_check(name: &str, passed: bool) -> CheckResult {
    CheckResult {
        name: name.to_owned(),
        passed,
        detail: if passed { "covered" } else { "missing" }.to_owned(),
    }
}

fn check_capability(capability: &Capability) -> Result<(), &'static str> {
    if capability.name.trim().is_empty() {
        return Err("capability name is empty");
    }
    if !capability.input_schema.is_object() {
        return Err("capability input_schema must be a JSON object");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectorBoundarySpec, ConnectorConformanceDriver, ConnectorConformanceScenario,
        ConnectorEvidenceSource, ConnectorScenarioEvidence, Rfc0003RuntimeEvidence,
        check_connector_boundary, check_enterprise_capability_contracts, check_profile_bindings,
        rfc0003_runtime_matrix_report, run_connector_conformance,
    };
    use aip_core::{
        CapabilityId, CompensationMode, Manifest, Principal, PrincipalId, PrincipalKind, ProfileId,
    };
    use aip_discovery::CapabilityImplementationSupport;
    use aip_testkit::{enterprise_capability, manifest};
    use serde_json::json;
    use std::collections::HashMap;

    struct CompleteConnectorDriver {
        manifest: Manifest,
        omit_assertion: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl ConnectorConformanceDriver for CompleteConnectorDriver {
        fn connector_id(&self) -> &str {
            "complete-test-connector"
        }

        fn manifest(&self) -> &Manifest {
            &self.manifest
        }

        fn implementation_support(&self) -> HashMap<CapabilityId, CapabilityImplementationSupport> {
            self.manifest
                .capabilities
                .iter()
                .map(|capability| {
                    (
                        capability.id.clone(),
                        CapabilityImplementationSupport {
                            invocation: true,
                            cancellation: true,
                            streaming: true,
                            retry: true,
                            transaction: true,
                            reconciliation: true,
                            compensation: true,
                            approval: true,
                            credentials: true,
                        },
                    )
                })
                .collect()
        }

        async fn exercise(
            &self,
            scenario: ConnectorConformanceScenario,
        ) -> Result<ConnectorScenarioEvidence, String> {
            let assertions = scenario
                .required_assertions()
                .iter()
                .filter(|assertion| self.omit_assertion != Some(**assertion))
                .map(|assertion| ((*assertion).to_owned(), true))
                .collect::<Vec<_>>();
            Ok(ConnectorScenarioEvidence::executed(
                ConnectorEvidenceSource::DeterministicProviderDouble,
                assertions,
                vec![format!("trace://connector-test/{}", scenario.id())],
                "deterministic provider observations retained",
            ))
        }
    }

    #[test]
    fn profile_bindings_require_compatibility_metadata() {
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent),
            capabilities: Vec::new(),
            profiles: vec![
                ProfileId::from("aip.native.http.v1"),
                ProfileId::from(aip_profile_mcp::PROFILE_ID),
            ],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };

        let result = check_profile_bindings(&manifest);
        assert!(!result.passed);
        assert!(result.detail.contains("native HTTP"));
        assert!(result.detail.contains("MCP"));
    }

    #[tokio::test]
    async fn connector_harness_requires_every_behavioral_invariant() {
        let driver = CompleteConnectorDriver {
            manifest: manifest(),
            omit_assertion: None,
        };
        let report = run_connector_conformance(&driver).await;
        assert!(report.passed(), "{report:#?}");
        assert_eq!(report.checks.len(), 13);

        let incomplete = CompleteConnectorDriver {
            manifest: driver.manifest,
            omit_assertion: Some("raw_secret_absent"),
        };
        let report = run_connector_conformance(&incomplete).await;
        assert!(!report.passed());
        assert!(report.checks.iter().any(|check| {
            check.name == "connector.behavior.audit_redaction"
                && !check.passed
                && check.detail.contains("raw_secret_absent")
        }));
    }

    #[test]
    fn profile_bindings_accept_declared_http_mcp_paths() {
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent),
            capabilities: Vec::new(),
            profiles: vec![
                ProfileId::from("aip.native.http.v1"),
                ProfileId::from(aip_profile_mcp::PROFILE_ID),
            ],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: Some(json!({
                "native_http": {
                    "messages": "/aip/v1/messages",
                    "manifest": "/aip/v1/manifest"
                },
                "mcp": {
                    "jsonrpc": "/mcp"
                }
            })),
            extensions: None,
        };

        assert!(check_profile_bindings(&manifest).passed);
    }

    #[test]
    fn enterprise_contracts_accept_testkit_fixture() {
        let manifest = manifest_with_capability(enterprise_capability("cap:test:refund", "refund"));

        let result = check_enterprise_capability_contracts(&manifest);

        assert!(result.passed, "{}", result.detail);
    }

    #[test]
    fn enterprise_contracts_reject_missing_compensation_capability() {
        let mut capability = enterprise_capability("cap:test:refund", "refund");
        let compensation = capability
            .contract
            .as_mut()
            .and_then(|contract| contract.compensation.as_mut());
        assert!(
            compensation.is_some(),
            "fixture includes compensation contract"
        );
        if let Some(compensation) = compensation {
            compensation.mode = CompensationMode::Supported;
            compensation.compensation_capability_id = None;
        }
        let manifest = manifest_with_capability(capability);

        let result = check_enterprise_capability_contracts(&manifest);

        assert!(!result.passed);
        assert!(result.detail.contains("compensation capability"));
    }

    #[test]
    fn connector_boundary_rejects_missing_profile_binding() {
        let manifest = manifest_with_capability(enterprise_capability("cap:test:refund", "refund"));

        let result = check_connector_boundary(
            &manifest,
            ConnectorBoundarySpec {
                connector_id: "test",
                connector_profile: "aip.connector.test.v1",
                capability_id_prefix: "cap:test:",
                required_binding_metadata: &["connector"],
            },
        );

        assert!(!result.passed);
        assert!(result.detail.contains("aip.connector.test.v1"));
    }

    #[test]
    fn rfc0003_runtime_matrix_requires_all_evidence() {
        let missing = rfc0003_runtime_matrix_report(&Rfc0003RuntimeEvidence {
            file_restart_recovery: true,
            ..Rfc0003RuntimeEvidence::default()
        });
        assert!(!missing.passed());

        let complete = rfc0003_runtime_matrix_report(&Rfc0003RuntimeEvidence {
            file_restart_recovery: true,
            sql_restart_recovery: true,
            unauthorized_action_lookup: true,
            result_not_ready: true,
            expired_cursor: true,
            tenant_or_session_mismatch: true,
            missing_or_forbidden_resource: true,
            callback_delivery_recovery: true,
            external_websocket: true,
            connector_boundary: true,
        });
        assert!(complete.passed());
    }

    fn manifest_with_capability(capability: aip_core::Capability) -> Manifest {
        Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent),
            capabilities: vec![capability],
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
}
