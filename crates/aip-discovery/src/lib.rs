//! Manifest registry, cache, and profile negotiation for AIP.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{
    ApprovalRule, Capability, CapabilityId, CapabilityKind, CompensationMode, DataSensitivity,
    Manifest, ProfileId, SideEffect, TransactionMode,
};
use aip_schema::{SchemaError, SchemaResult, compile_draft202012};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Discovery-layer error.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Manifest validation failed.
    #[error("schema validation failed: {0}")]
    Schema(#[from] aip_schema::SchemaError),
    /// A capability was not found.
    #[error("capability `{0}` not found")]
    CapabilityNotFound(String),
    /// A manifest was not found.
    #[error("manifest `{0}` not found")]
    ManifestNotFound(String),
    /// Manifest admission failed before publication.
    #[error("manifest admission failed with {} issue(s)", .0.issues.len())]
    Admission(ManifestAdmissionReport),
}

/// Stable machine-readable manifest admission issue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionIssue {
    /// Stable issue code suitable for conformance assertions.
    pub code: String,
    /// JSON Pointer-like path in the submitted manifest.
    pub path: String,
    /// Capability associated with the issue, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,
    /// JSON Schema pointer associated with the issue, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_pointer: Option<String>,
    /// Compatibility profile associated with the issue, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileId>,
    /// Human-readable diagnostic without credentials or invocation payloads.
    pub message: String,
}

/// Complete admission report returned atomically for one manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAdmissionReport {
    /// Every issue detected in stable manifest order.
    pub issues: Vec<AdmissionIssue>,
}

impl std::fmt::Display for ManifestAdmissionReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, issue) in self.issues.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(
                formatter,
                "{} at {}: {}",
                issue.code, issue.path, issue.message
            )?;
        }
        Ok(())
    }
}

/// Runtime support advertised by the implementation behind one capability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityImplementationSupport {
    /// Normal invocation is implemented.
    pub invocation: bool,
    /// Runtime cancellation reaches the downstream operation.
    pub cancellation: bool,
    /// Incremental streaming is implemented.
    pub streaming: bool,
    /// Retry classification and downstream idempotency are implemented.
    pub retry: bool,
    /// Transaction plan and commit operations are implemented.
    pub transaction: bool,
    /// Reconciliation after uncertain outcomes is implemented.
    pub reconciliation: bool,
    /// Compensation is implemented as a governed action.
    pub compensation: bool,
    /// Approval evidence and resume behavior are implemented.
    pub approval: bool,
    /// Credential handles are resolved through a deployment provider.
    pub credentials: bool,
}

/// Manifest admission policy supplied by the owning runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestAdmissionPolicy {
    /// Whether non-fragment JSON Schema references are permitted.
    pub allow_remote_schema_references: bool,
    /// Whether every callable capability must have an implementation claim.
    pub require_implementation_claims: bool,
    /// Profiles for which bindings may be admitted. Empty accepts manifest profiles.
    pub allowed_binding_profiles: BTreeSet<ProfileId>,
}

/// Successful admission output retained for atomic publication.
#[derive(Clone, Debug)]
pub struct AdmittedManifest {
    manifest: Manifest,
    projected_names: BTreeMap<(ProfileId, String), CapabilityId>,
}

impl AdmittedManifest {
    /// Returns the validated manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Consumes the admission token and returns the validated manifest.
    #[must_use]
    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }

    /// Returns stable projected identifiers by profile.
    #[must_use]
    pub fn projected_names(&self) -> &BTreeMap<(ProfileId, String), CapabilityId> {
        &self.projected_names
    }
}

/// Cached manifest with an absolute expiry.
#[derive(Clone, Debug)]
pub struct CachedManifest {
    /// Manifest value.
    pub manifest: Manifest,
    /// Expiration timestamp.
    pub expires_at: OffsetDateTime,
}

impl CachedManifest {
    /// Returns true when the cached entry is still usable.
    #[must_use]
    pub fn is_fresh(&self, now: OffsetDateTime) -> bool {
        self.expires_at > now
    }
}

/// In-memory manifest cache.
#[derive(Clone, Debug)]
pub struct ManifestCache {
    manifests: HashMap<String, CachedManifest>,
    default_ttl: Duration,
}

impl Default for ManifestCache {
    fn default() -> Self {
        Self::new(Duration::minutes(5))
    }
}

impl ManifestCache {
    /// Creates a manifest cache with a default TTL.
    #[must_use]
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            manifests: HashMap::new(),
            default_ttl,
        }
    }

    /// Inserts a manifest using the default TTL.
    pub fn insert(&mut self, key: impl Into<String>, manifest: Manifest) {
        let expires_at = OffsetDateTime::now_utc() + self.default_ttl;
        self.manifests.insert(
            key.into(),
            CachedManifest {
                manifest,
                expires_at,
            },
        );
    }

    /// Returns a fresh manifest.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Manifest> {
        let now = OffsetDateTime::now_utc();
        self.manifests
            .get(key)
            .filter(|cached| cached.is_fresh(now))
            .map(|cached| &cached.manifest)
    }

    /// Returns all fresh manifests in stable key order.
    #[must_use]
    pub fn all(&self) -> Vec<&Manifest> {
        let now = OffsetDateTime::now_utc();
        let mut manifests = self
            .manifests
            .iter()
            .filter(|(_key, cached)| cached.is_fresh(now))
            .map(|(key, cached)| (key, &cached.manifest))
            .collect::<Vec<_>>();
        manifests.sort_by_key(|(key, _)| *key);
        manifests
            .into_iter()
            .map(|(_key, manifest)| manifest)
            .collect()
    }

    fn entries(&self) -> Vec<(&str, &Manifest)> {
        let now = OffsetDateTime::now_utc();
        let mut manifests = self
            .manifests
            .iter()
            .filter(|(_key, cached)| cached.is_fresh(now))
            .map(|(key, cached)| (key.as_str(), &cached.manifest))
            .collect::<Vec<_>>();
        manifests.sort_by_key(|(key, _)| *key);
        manifests
    }
}

/// Capability lookup table derived from manifests.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    capabilities: HashMap<CapabilityId, Capability>,
}

/// Enterprise capability query over native AIP contract metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnterpriseCapabilityQuery {
    /// Required side effects. A capability must include every listed side effect.
    pub side_effects: Vec<SideEffect>,
    /// Required data sensitivity classifications. Empty means any sensitivity.
    pub data_sensitivity: Vec<DataSensitivity>,
    /// Required transaction modes. A capability must support every listed mode.
    pub transaction_modes: Vec<TransactionMode>,
    /// Whether the capability must require approval.
    pub requires_approval: Option<bool>,
    /// Whether the capability must require a credential reference or OAuth state.
    pub requires_credentials: Option<bool>,
}

impl CapabilityRegistry {
    /// Adds all capabilities from a manifest.
    pub fn register_manifest(&mut self, manifest: &Manifest) {
        for capability in &manifest.capabilities {
            self.capabilities
                .insert(capability.id.clone(), capability.clone());
        }
    }

    /// Finds a capability by id.
    #[must_use]
    pub fn get(&self, id: &CapabilityId) -> Option<&Capability> {
        self.capabilities.get(id)
    }

    /// Returns all known capabilities.
    #[must_use]
    pub fn all(&self) -> Vec<&Capability> {
        self.capabilities.values().collect()
    }

    /// Finds capabilities whose enterprise contract satisfies a query.
    #[must_use]
    pub fn query(&self, query: &EnterpriseCapabilityQuery) -> Vec<&Capability> {
        let mut matches = self
            .capabilities
            .values()
            .filter(|capability| capability_matches_query(capability, query))
            .collect::<Vec<_>>();
        matches.sort_by_key(|capability| capability.id.as_str().to_owned());
        matches
    }
}

/// Discovery service combining cache, validation, and capability lookup.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryService {
    cache: ManifestCache,
    capabilities: CapabilityRegistry,
}

impl DiscoveryService {
    /// Validates a manifest and its implementation claims without publishing it.
    ///
    /// The returned token is the only input accepted by [`Self::publish_admitted`],
    /// which prevents a caller from validating one value and publishing another.
    pub fn admit_manifest(
        manifest: Manifest,
        policy: &ManifestAdmissionPolicy,
        implementations: &HashMap<CapabilityId, CapabilityImplementationSupport>,
    ) -> Result<AdmittedManifest, ManifestAdmissionReport> {
        let mut issues = Vec::new();
        validate_manifest_structure(&manifest, &mut issues);
        validate_schemas(&manifest, policy, &mut issues);
        validate_bindings(&manifest, policy, &mut issues);
        validate_implementation_claims(&manifest, policy, implementations, &mut issues);
        let projected_names = validate_projected_names(&manifest, &mut issues);
        if issues.is_empty() {
            Ok(AdmittedManifest {
                manifest,
                projected_names,
            })
        } else {
            Err(ManifestAdmissionReport { issues })
        }
    }

    /// Atomically publishes a previously admitted manifest to discovery indexes.
    pub fn publish_admitted(&mut self, key: impl Into<String>, admitted: AdmittedManifest) {
        self.cache.insert(key, admitted.into_manifest());
        self.rebuild_capability_registry();
    }

    /// Registers a manifest and updates capability lookup.
    pub fn register_manifest(
        &mut self,
        key: impl Into<String>,
        manifest: Manifest,
    ) -> SchemaResult<()> {
        let admitted = Self::admit_manifest(
            manifest,
            &ManifestAdmissionPolicy::default(),
            &HashMap::new(),
        )
        .map_err(|report| SchemaError::Validate(report.to_string()))?;
        self.publish_admitted(key, admitted);
        Ok(())
    }

    /// Gets a fresh manifest by cache key.
    #[must_use]
    pub fn manifest(&self, key: &str) -> Option<&Manifest> {
        self.cache.get(key)
    }

    /// Returns all fresh registered manifests.
    #[must_use]
    pub fn manifests(&self) -> Vec<&Manifest> {
        self.cache.all()
    }

    /// Returns fresh manifests with their registry keys in stable key order.
    #[must_use]
    pub fn manifest_entries(&self) -> Vec<(&str, &Manifest)> {
        self.cache.entries()
    }

    /// Gets a registered capability by id.
    #[must_use]
    pub fn capability(&self, id: &CapabilityId) -> Option<&Capability> {
        self.capabilities.get(id)
    }

    /// Searches registered capabilities by native enterprise contract metadata.
    #[must_use]
    pub fn query_capabilities(&self, query: &EnterpriseCapabilityQuery) -> Vec<&Capability> {
        self.capabilities.query(query)
    }

    /// Selects profiles supported by both sides, preserving the client's order.
    #[must_use]
    pub fn negotiate_profiles(client: &[ProfileId], server: &[ProfileId]) -> Vec<ProfileId> {
        client
            .iter()
            .filter(|profile| server.iter().any(|candidate| candidate == *profile))
            .cloned()
            .collect()
    }

    fn rebuild_capability_registry(&mut self) {
        let mut capabilities = CapabilityRegistry::default();
        for manifest in self.cache.all() {
            capabilities.register_manifest(manifest);
        }
        self.capabilities = capabilities;
    }
}

fn validate_manifest_structure(manifest: &Manifest, issues: &mut Vec<AdmissionIssue>) {
    if manifest.manifest_version.trim().is_empty() {
        push_issue(
            issues,
            "manifest.version.empty",
            "/manifest_version",
            None,
            None,
            None,
            "manifest_version must not be empty",
        );
    }
    if manifest.profiles.is_empty() {
        push_issue(
            issues,
            "manifest.profiles.empty",
            "/profiles",
            None,
            None,
            None,
            "at least one profile is required",
        );
    }
    reject_duplicates(
        manifest.profiles.iter().map(ProfileId::as_str),
        issues,
        "manifest.profile.duplicate",
        "/profiles",
    );

    let mut capability_ids = HashSet::new();
    for (index, capability) in manifest.capabilities.iter().enumerate() {
        let path = format!("/capabilities/{index}");
        if !capability_ids.insert(capability.id.clone()) {
            push_issue(
                issues,
                "manifest.capability.duplicate",
                &format!("{path}/id"),
                Some(&capability.id),
                None,
                None,
                "capability id is duplicated",
            );
        }
        if capability.name.trim().is_empty() {
            push_issue(
                issues,
                "manifest.capability.name_empty",
                &format!("{path}/name"),
                Some(&capability.id),
                None,
                None,
                "capability name must not be empty",
            );
        }
        validate_capability_contract(capability, index, issues);
    }

    let mut resource_ids = HashSet::new();
    for (index, resource) in manifest.resources.iter().enumerate() {
        if resource.id.trim().is_empty() || !resource_ids.insert(resource.id.as_str()) {
            push_issue(
                issues,
                if resource.id.trim().is_empty() {
                    "manifest.resource.id_empty"
                } else {
                    "manifest.resource.duplicate"
                },
                &format!("/resources/{index}/id"),
                resource.capability_id.as_ref(),
                None,
                None,
                "resource id must be non-empty and unique",
            );
        }
        if let Some(capability_id) = resource.capability_id.as_ref()
            && !capability_ids.contains(capability_id)
        {
            push_issue(
                issues,
                "manifest.resource.capability_missing",
                &format!("/resources/{index}/capability_id"),
                Some(capability_id),
                None,
                None,
                "resource references an undeclared capability",
            );
        }
    }

    let mut channel_ids = HashSet::new();
    for (index, channel) in manifest.channels.iter().enumerate() {
        let identity = channel
            .get("id")
            .or_else(|| channel.get("name"))
            .and_then(Value::as_str);
        match identity {
            Some(identity) if !identity.trim().is_empty() => {
                if !channel_ids.insert(identity.to_owned()) {
                    push_issue(
                        issues,
                        "manifest.channel.duplicate",
                        &format!("/channels/{index}"),
                        None,
                        None,
                        None,
                        "channel id or name is duplicated",
                    );
                }
            }
            _ => push_issue(
                issues,
                "manifest.channel.identifier_missing",
                &format!("/channels/{index}"),
                None,
                None,
                None,
                "channel must declare a non-empty id or name",
            ),
        }
    }
}

fn validate_capability_contract(
    capability: &Capability,
    index: usize,
    issues: &mut Vec<AdmissionIssue>,
) {
    let Some(contract) = capability.contract.as_ref() else {
        return;
    };
    let path = format!("/capabilities/{index}/contract");
    if !contract.execution.supports_sync
        && !contract.execution.supports_async
        && !contract.execution.supports_streaming
    {
        push_issue(
            issues,
            "contract.execution.no_completion_mode",
            &format!("{path}/execution"),
            Some(&capability.id),
            None,
            None,
            "execution must support sync, async, or streaming",
        );
    }
    if has_duplicates(&contract.side_effects) {
        push_issue(
            issues,
            "contract.side_effect.duplicate",
            &format!("{path}/side_effects"),
            Some(&capability.id),
            None,
            None,
            "side effects must be unique",
        );
    }
    if contract.idempotency.ttl_ms == Some(0) {
        push_issue(
            issues,
            "contract.idempotency.invalid_ttl",
            &format!("{path}/idempotency/ttl_ms"),
            Some(&capability.id),
            None,
            None,
            "idempotency TTL must be greater than zero",
        );
    }
    if let Some(approval) = contract.approval.as_ref() {
        if approval.minimum_distinct_principals == 0 {
            push_issue(
                issues,
                "contract.approval.invalid_distinct_principals",
                &format!("{path}/approval/minimum_distinct_principals"),
                Some(&capability.id),
                None,
                None,
                "minimum_distinct_principals must be greater than zero",
            );
        }
        if let Some(rule) = approval.rule.as_ref() {
            validate_approval_rule(rule, &format!("{path}/approval/rule"), capability, issues);
        }
    }
    if let Some(transaction) = contract.transaction.as_ref() {
        if transaction.supported_modes.is_empty() {
            push_issue(
                issues,
                "contract.transaction.modes_empty",
                &format!("{path}/transaction/supported_modes"),
                Some(&capability.id),
                None,
                None,
                "transaction contract must declare at least one mode",
            );
        }
        if has_duplicates(&transaction.supported_modes) {
            push_issue(
                issues,
                "contract.transaction.mode_duplicate",
                &format!("{path}/transaction/supported_modes"),
                Some(&capability.id),
                None,
                None,
                "transaction modes must be unique",
            );
        }
    }
    if let Some(compensation) = contract.compensation.as_ref() {
        if compensation.mode == CompensationMode::Supported
            && compensation.compensation_capability_id.is_none()
        {
            push_issue(
                issues,
                "contract.compensation.capability_missing",
                &format!("{path}/compensation/compensation_capability_id"),
                Some(&capability.id),
                None,
                None,
                "supported compensation requires a compensation capability id",
            );
        }
        if compensation.compensation_window_ms == Some(0) {
            push_issue(
                issues,
                "contract.compensation.invalid_window",
                &format!("{path}/compensation/compensation_window_ms"),
                Some(&capability.id),
                None,
                None,
                "compensation window must be greater than zero",
            );
        }
    }
}

fn validate_approval_rule(
    rule: &ApprovalRule,
    path: &str,
    capability: &Capability,
    issues: &mut Vec<AdmissionIssue>,
) {
    match rule {
        ApprovalRule::All { rules, .. } | ApprovalRule::Any { rules } => {
            if rules.is_empty() {
                push_issue(
                    issues,
                    "contract.approval.rule_empty",
                    path,
                    Some(&capability.id),
                    None,
                    None,
                    "all and any rules require at least one child",
                );
            }
            for (index, child) in rules.iter().enumerate() {
                validate_approval_rule(child, &format!("{path}/rules/{index}"), capability, issues);
            }
        }
        ApprovalRule::Quorum {
            required, rules, ..
        } => {
            if *required == 0
                || usize::try_from(*required).map_or(true, |count| count > rules.len())
            {
                push_issue(
                    issues,
                    "contract.approval.quorum_invalid",
                    path,
                    Some(&capability.id),
                    None,
                    None,
                    "quorum must be within the number of child rules",
                );
            }
            for (index, child) in rules.iter().enumerate() {
                validate_approval_rule(child, &format!("{path}/rules/{index}"), capability, issues);
            }
        }
        ApprovalRule::Role { name } if name.trim().is_empty() => push_issue(
            issues,
            "contract.approval.role_empty",
            path,
            Some(&capability.id),
            None,
            None,
            "role name must not be empty",
        ),
        ApprovalRule::Group { name } if name.trim().is_empty() => push_issue(
            issues,
            "contract.approval.group_empty",
            path,
            Some(&capability.id),
            None,
            None,
            "group name must not be empty",
        ),
        ApprovalRule::TenantPolicy { policy_id } if policy_id.trim().is_empty() => push_issue(
            issues,
            "contract.approval.tenant_policy_empty",
            path,
            Some(&capability.id),
            None,
            None,
            "tenant policy id must not be empty",
        ),
        ApprovalRule::ExternalSystem { system } if system.trim().is_empty() => push_issue(
            issues,
            "contract.approval.external_system_empty",
            path,
            Some(&capability.id),
            None,
            None,
            "external approval system id must not be empty",
        ),
        ApprovalRule::DelegatedAuthority { scope, .. } if scope.trim().is_empty() => push_issue(
            issues,
            "contract.approval.delegated_scope_empty",
            path,
            Some(&capability.id),
            None,
            None,
            "delegated authority scope must not be empty",
        ),
        _ => {}
    }
}

fn validate_schemas(
    manifest: &Manifest,
    policy: &ManifestAdmissionPolicy,
    issues: &mut Vec<AdmissionIssue>,
) {
    for (index, capability) in manifest.capabilities.iter().enumerate() {
        validate_schema(
            &capability.input_schema,
            &format!("/capabilities/{index}/input_schema"),
            &capability.id,
            policy,
            issues,
        );
        if let Some(schema) = capability.output_schema.as_ref() {
            validate_schema(
                schema,
                &format!("/capabilities/{index}/output_schema"),
                &capability.id,
                policy,
                issues,
            );
        }
    }
    match compile_manifest_schemas(manifest) {
        Ok(failures) => {
            for failure in failures {
                push_issue(
                    issues,
                    "schema.compile_failed",
                    &failure.path,
                    Some(&failure.capability_id),
                    Some(""),
                    None,
                    &failure.message,
                );
            }
        }
        Err(message) => push_issue(
            issues,
            "schema.compiler_unavailable",
            "/capabilities",
            None,
            None,
            None,
            &message,
        ),
    }
}

fn validate_schema(
    schema: &Value,
    path: &str,
    capability_id: &CapabilityId,
    policy: &ManifestAdmissionPolicy,
    issues: &mut Vec<AdmissionIssue>,
) {
    if !schema.is_object() && !schema.is_boolean() {
        push_issue(
            issues,
            "schema.invalid_root",
            path,
            Some(capability_id),
            Some(""),
            None,
            "JSON Schema root must be an object or boolean",
        );
        return;
    }
    if !policy.allow_remote_schema_references {
        collect_remote_refs(schema, "", &mut |pointer, reference| {
            push_issue(
                issues,
                "schema.remote_reference_forbidden",
                path,
                Some(capability_id),
                Some(pointer),
                None,
                &format!("non-fragment schema reference `{reference}` is forbidden"),
            );
        });
    }
}

fn collect_remote_refs(value: &Value, pointer: &str, callback: &mut impl FnMut(&str, &str)) {
    let mut pending = vec![(pointer.to_owned(), value)];
    while let Some((current_pointer, current)) = pending.pop() {
        match current {
            Value::Object(object) => {
                let mut children = object
                    .iter()
                    .map(|(key, child)| {
                        (
                            format!("{current_pointer}/{}", escape_pointer_segment(key)),
                            key,
                            child,
                        )
                    })
                    .collect::<Vec<_>>();
                children.reverse();
                for (child_pointer, key, child) in children {
                    if key == "$ref"
                        && let Some(reference) = child.as_str()
                        && !reference.starts_with('#')
                    {
                        callback(&child_pointer, reference);
                    }
                    pending.push((child_pointer, child));
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter().enumerate().rev() {
                    pending.push((format!("{current_pointer}/{index}"), child));
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct SchemaCompilationFailure {
    path: String,
    capability_id: CapabilityId,
    message: String,
}

fn compile_manifest_schemas(manifest: &Manifest) -> Result<Vec<SchemaCompilationFailure>, String> {
    let mut failures = Vec::new();
    for (index, capability) in manifest.capabilities.iter().enumerate() {
        compile_one_schema(
            &capability.input_schema,
            format!("/capabilities/{index}/input_schema"),
            &capability.id,
            &mut failures,
        );
        if let Some(schema) = capability.output_schema.as_ref() {
            compile_one_schema(
                schema,
                format!("/capabilities/{index}/output_schema"),
                &capability.id,
                &mut failures,
            );
        }
    }
    Ok(failures)
}

fn compile_one_schema(
    schema: &Value,
    path: String,
    capability_id: &CapabilityId,
    failures: &mut Vec<SchemaCompilationFailure>,
) {
    if let Err(error) = compile_draft202012(schema) {
        failures.push(SchemaCompilationFailure {
            path,
            capability_id: capability_id.clone(),
            message: error.to_string(),
        });
    }
}

fn validate_bindings(
    manifest: &Manifest,
    policy: &ManifestAdmissionPolicy,
    issues: &mut Vec<AdmissionIssue>,
) {
    let manifest_profiles = manifest.profiles.iter().collect::<HashSet<_>>();
    for (capability_index, capability) in manifest.capabilities.iter().enumerate() {
        let mut profiles = HashSet::new();
        for (binding_index, binding) in capability.bindings.iter().enumerate() {
            let path = format!("/capabilities/{capability_index}/bindings/{binding_index}/profile");
            if !profiles.insert(&binding.profile) {
                push_issue(
                    issues,
                    "manifest.binding.duplicate",
                    &path,
                    Some(&capability.id),
                    None,
                    Some(&binding.profile),
                    "one capability cannot declare the same profile binding twice",
                );
            }
            if !manifest_profiles.contains(&binding.profile) {
                push_issue(
                    issues,
                    "manifest.binding.profile_undeclared",
                    &path,
                    Some(&capability.id),
                    None,
                    Some(&binding.profile),
                    "binding profile is not declared by the manifest",
                );
            }
            if !policy.allowed_binding_profiles.is_empty()
                && !policy.allowed_binding_profiles.contains(&binding.profile)
            {
                push_issue(
                    issues,
                    "manifest.binding.profile_unsupported",
                    &path,
                    Some(&capability.id),
                    None,
                    Some(&binding.profile),
                    "runtime does not support this binding profile",
                );
            }
        }
    }
}

fn validate_implementation_claims(
    manifest: &Manifest,
    policy: &ManifestAdmissionPolicy,
    implementations: &HashMap<CapabilityId, CapabilityImplementationSupport>,
    issues: &mut Vec<AdmissionIssue>,
) {
    for (index, capability) in manifest.capabilities.iter().enumerate() {
        let path = format!("/capabilities/{index}");
        let callable = capability.kind != CapabilityKind::Resource;
        let support = implementations.get(&capability.id);
        if callable && policy.require_implementation_claims && support.is_none() {
            push_issue(
                issues,
                "implementation.missing",
                &path,
                Some(&capability.id),
                None,
                None,
                "callable capability has no registered implementation claim",
            );
            continue;
        }
        let Some(support) = support else {
            continue;
        };
        if callable && !support.invocation {
            implementation_issue(issues, capability, &path, "invocation");
        }
        let Some(contract) = capability.contract.as_ref() else {
            continue;
        };
        if contract.execution.supports_cancel && !support.cancellation {
            implementation_issue(issues, capability, &path, "cancellation");
        }
        if contract.execution.supports_streaming && !support.streaming {
            implementation_issue(issues, capability, &path, "streaming");
        }
        if contract.execution.supports_retry && !support.retry {
            implementation_issue(issues, capability, &path, "retry");
        }
        if contract.transaction.is_some() && !support.transaction {
            implementation_issue(issues, capability, &path, "transaction");
        }
        if contract.transaction.as_ref().is_some_and(|transaction| {
            transaction
                .supported_modes
                .contains(&TransactionMode::Reconcile)
        }) && !support.reconciliation
        {
            implementation_issue(issues, capability, &path, "reconciliation");
        }
        if contract
            .compensation
            .as_ref()
            .is_some_and(|compensation| compensation.mode == CompensationMode::Supported)
            && !support.compensation
        {
            implementation_issue(issues, capability, &path, "compensation");
        }
        if contract
            .approval
            .as_ref()
            .is_some_and(|approval| approval.required)
            && !support.approval
        {
            implementation_issue(issues, capability, &path, "approval");
        }
        if contract
            .credentials
            .as_ref()
            .is_some_and(|credentials| credentials.required)
            && !support.credentials
        {
            implementation_issue(issues, capability, &path, "credentials");
        }
    }
}

fn implementation_issue(
    issues: &mut Vec<AdmissionIssue>,
    capability: &Capability,
    path: &str,
    operation: &str,
) {
    push_issue(
        issues,
        "implementation.claim_unsupported",
        path,
        Some(&capability.id),
        None,
        None,
        &format!("capability claims `{operation}` but its implementation does not support it"),
    );
}

fn validate_projected_names(
    manifest: &Manifest,
    issues: &mut Vec<AdmissionIssue>,
) -> BTreeMap<(ProfileId, String), CapabilityId> {
    let mut projected = BTreeMap::new();
    for (index, capability) in manifest.capabilities.iter().enumerate() {
        for profile in &manifest.profiles {
            let raw_name = capability
                .bindings
                .iter()
                .find(|binding| &binding.profile == profile)
                .and_then(|binding| {
                    binding
                        .metadata
                        .get("tool_name")
                        .or_else(|| binding.metadata.get("operation_id"))
                        .or_else(|| binding.metadata.get("name"))
                })
                .and_then(Value::as_str)
                .unwrap_or_else(|| capability.id.as_str());
            let stable_name = stable_profile_name(raw_name);
            let key = (profile.clone(), stable_name.clone());
            if let Some(existing) = projected.insert(key, capability.id.clone())
                && existing != capability.id
            {
                push_issue(
                    issues,
                    "manifest.profile_name.collision",
                    &format!("/capabilities/{index}/bindings"),
                    Some(&capability.id),
                    None,
                    Some(profile),
                    &format!(
                        "projected identifier `{stable_name}` collides with capability `{existing}`"
                    ),
                );
            }
        }
    }
    projected
}

fn stable_profile_name(raw_name: &str) -> String {
    let mut normalized = String::with_capacity(raw_name.len());
    let mut separator = false;
    for character in raw_name.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
            normalized.push(character.to_ascii_lowercase());
            separator = false;
        } else if !separator && !normalized.is_empty() {
            normalized.push('_');
            separator = true;
        }
    }
    let normalized = normalized.trim_matches('_');
    let normalized = if normalized.is_empty() {
        "operation".to_owned()
    } else if normalized
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
    {
        normalized.to_owned()
    } else {
        format!("operation_{normalized}")
    };
    if normalized.len() <= 128 {
        return normalized;
    }
    let digest = Sha256::digest(raw_name.as_bytes());
    let suffix = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut shortened = normalized;
    shortened.truncate(115);
    format!("{}_{}", shortened.trim_end_matches(['_', '.', '-']), suffix)
}

fn reject_duplicates<'a>(
    values: impl Iterator<Item = &'a str>,
    issues: &mut Vec<AdmissionIssue>,
    code: &str,
    path: &str,
) {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            push_issue(
                issues,
                code,
                path,
                None,
                None,
                None,
                &format!("duplicate identifier `{value}`"),
            );
        }
    }
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

#[allow(clippy::too_many_arguments)]
fn push_issue(
    issues: &mut Vec<AdmissionIssue>,
    code: &str,
    path: &str,
    capability_id: Option<&CapabilityId>,
    schema_pointer: Option<&str>,
    profile: Option<&ProfileId>,
    message: &str,
) {
    issues.push(AdmissionIssue {
        code: code.to_owned(),
        path: path.to_owned(),
        capability_id: capability_id.cloned(),
        schema_pointer: schema_pointer.map(ToOwned::to_owned),
        profile: profile.cloned(),
        message: message.to_owned(),
    });
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn capability_matches_query(capability: &Capability, query: &EnterpriseCapabilityQuery) -> bool {
    let Some(contract) = &capability.contract else {
        return query.side_effects.is_empty()
            && query.data_sensitivity.is_empty()
            && query.transaction_modes.is_empty()
            && query.requires_approval.is_none_or(|required| !required)
            && query.requires_credentials.is_none_or(|required| !required);
    };
    if !query
        .side_effects
        .iter()
        .all(|side_effect| contract.side_effects.contains(side_effect))
    {
        return false;
    }
    if !query.data_sensitivity.is_empty()
        && !query.data_sensitivity.contains(&contract.data.sensitivity)
    {
        return false;
    }
    if !query.transaction_modes.is_empty() {
        let Some(transaction) = &contract.transaction else {
            return false;
        };
        if !query
            .transaction_modes
            .iter()
            .all(|mode| transaction.supported_modes.contains(mode))
        {
            return false;
        }
    }
    if let Some(required) = query.requires_approval {
        let actual = contract
            .approval
            .as_ref()
            .is_some_and(|approval| approval.required)
            || capability.requires_human_approval.unwrap_or(false);
        if actual != required {
            return false;
        }
    }
    if let Some(required) = query.requires_credentials {
        let actual = contract
            .credentials
            .as_ref()
            .is_some_and(|credentials| credentials.required);
        if actual != required {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityImplementationSupport, DiscoveryService, EnterpriseCapabilityQuery,
        ManifestAdmissionPolicy,
    };
    use aip_core::{
        ApprovalPolicy, ApproverSelector, Binding, Capability, CapabilityContract, CapabilityId,
        CapabilityKind, CompensationContract, CompensationMode, CredentialPolicy, DataContract,
        DataSensitivity, DryRunFidelity, ExecutionContract, ExpectedCompletionMode,
        IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope,
        IdempotencyRequirement, Manifest, Principal, PrincipalId, PrincipalKind, ProfileId,
        RetrySafety, SideEffect, TransactionContract, TransactionMode,
    };
    use serde_json::json;
    use std::collections::HashMap;

    fn admission_manifest(capabilities: Vec<Capability>) -> Manifest {
        Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::trusted("agent:admission-test"),
                PrincipalKind::Agent,
            ),
            capabilities,
            profiles: vec![ProfileId::from("aip.mcp.compat.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        }
    }

    fn admission_capability(id: &str, schema: serde_json::Value) -> Capability {
        Capability {
            id: CapabilityId::trusted(id),
            name: id.to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: schema,
            output_schema: Some(json!({ "type": "object" })),
            description: None,
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        }
    }

    fn admission_contract() -> CapabilityContract {
        CapabilityContract {
            side_effects: vec![SideEffect::Write],
            idempotency: IdempotencyContract {
                requirement: IdempotencyRequirement::Required,
                collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
                key_scope: IdempotencyKeyScope::Capability,
                ttl_ms: Some(60_000),
            },
            execution: ExecutionContract {
                supports_sync: true,
                supports_async: false,
                supports_streaming: true,
                supports_cancel: true,
                supports_retry: true,
                expected_completion: ExpectedCompletionMode::Any,
                retry_safety: RetrySafety::SafeWithIdempotencyKey,
            },
            data: DataContract {
                sensitivity: DataSensitivity::Internal,
                contains_pii: false,
                redaction_required: false,
                residency: None,
                retention: None,
            },
            credentials: None,
            approval: None,
            sla: None,
            transaction: Some(TransactionContract {
                supported_modes: vec![TransactionMode::Execute, TransactionMode::Reconcile],
                requires_plan_before_commit: false,
                dry_run_fidelity: DryRunFidelity::PolicyAndSchema,
            }),
            compensation: None,
        }
    }

    #[test]
    fn admission_rejects_remote_refs_invalid_schemas_and_projected_collisions() {
        let mut first = admission_capability(
            "cap:test:first",
            json!({ "$ref": "https://schemas.example/remote.json" }),
        );
        first.bindings.push(Binding {
            profile: ProfileId::from("aip.mcp.compat.v1"),
            metadata: serde_json::Map::from_iter([("tool_name".to_owned(), json!("same name"))]),
        });
        let mut second = admission_capability(
            "cap:test:second",
            json!({ "type": "definitely-not-a-json-schema-type" }),
        );
        second.bindings.push(Binding {
            profile: ProfileId::from("aip.mcp.compat.v1"),
            metadata: serde_json::Map::from_iter([("tool_name".to_owned(), json!("same_name"))]),
        });
        let implementations = HashMap::from([
            (
                first.id.clone(),
                CapabilityImplementationSupport {
                    invocation: true,
                    ..CapabilityImplementationSupport::default()
                },
            ),
            (
                second.id.clone(),
                CapabilityImplementationSupport {
                    invocation: true,
                    ..CapabilityImplementationSupport::default()
                },
            ),
        ]);
        let report = DiscoveryService::admit_manifest(
            admission_manifest(vec![first, second]),
            &ManifestAdmissionPolicy {
                require_implementation_claims: true,
                ..ManifestAdmissionPolicy::default()
            },
            &implementations,
        )
        .expect_err("invalid manifest must be rejected");
        let codes = report
            .issues
            .iter()
            .map(|issue| issue.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"schema.remote_reference_forbidden"));
        assert!(codes.contains(&"schema.compile_failed"));
        assert!(codes.contains(&"manifest.profile_name.collision"));
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.path.starts_with('/'))
        );
    }

    #[test]
    fn admission_rejects_declared_runtime_support_that_handler_does_not_implement() {
        let mut capability =
            admission_capability("cap:test:overclaim", json!({ "type": "object" }));
        capability.contract = Some(admission_contract());
        let report = DiscoveryService::admit_manifest(
            admission_manifest(vec![capability.clone()]),
            &ManifestAdmissionPolicy {
                require_implementation_claims: true,
                ..ManifestAdmissionPolicy::default()
            },
            &HashMap::from([(
                capability.id,
                CapabilityImplementationSupport {
                    invocation: true,
                    cancellation: true,
                    retry: true,
                    transaction: true,
                    ..CapabilityImplementationSupport::default()
                },
            )]),
        )
        .expect_err("unsupported implementation claims must be rejected");
        let messages = report
            .issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|message| message.contains("streaming")));
        assert!(
            messages
                .iter()
                .any(|message| message.contains("reconciliation"))
        );
    }

    #[test]
    fn negotiates_profiles_in_client_order() {
        let client = vec![
            ProfileId::from("aip.mcp.compat.v1"),
            ProfileId::from("aip.native.http.v1"),
        ];
        let server = vec![
            ProfileId::from("aip.native.http.v1"),
            ProfileId::from("aip.mcp.compat.v1"),
        ];
        let selected = DiscoveryService::negotiate_profiles(&client, &server);
        assert_eq!(selected, client);
    }

    #[test]
    fn registers_manifest() {
        let mut service = DiscoveryService::default();
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::parse("agent:test").expect("principal"),
                PrincipalKind::Agent,
            ),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        service
            .register_manifest("test", manifest)
            .expect("manifest registered");
        assert!(service.manifest("test").is_some());
    }

    #[test]
    fn replacing_manifest_removes_stale_capabilities_from_lookup() {
        let mut service = DiscoveryService::default();
        let principal = Principal::new(
            PrincipalId::parse("agent:replace").expect("principal"),
            PrincipalKind::Agent,
        );
        let first = CapabilityId::parse("cap:replace:first").expect("capability");
        let second = CapabilityId::parse("cap:replace:second").expect("capability");

        service
            .register_manifest(
                "replace",
                Manifest {
                    manifest_version: "aip-manifest/v1".to_owned(),
                    agent: principal.clone(),
                    capabilities: vec![Capability {
                        id: first.clone(),
                        name: "first".to_owned(),
                        kind: CapabilityKind::Tool,
                        input_schema: json!({ "type": "object" }),
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
                },
            )
            .expect("first manifest");
        assert!(service.capability(&first).is_some());

        service
            .register_manifest(
                "replace",
                Manifest {
                    manifest_version: "aip-manifest/v1".to_owned(),
                    agent: principal,
                    capabilities: vec![Capability {
                        id: second.clone(),
                        name: "second".to_owned(),
                        kind: CapabilityKind::Tool,
                        input_schema: json!({ "type": "object" }),
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
                },
            )
            .expect("second manifest");
        assert!(service.capability(&first).is_none());
        assert!(service.capability(&second).is_some());
    }

    #[test]
    fn queries_enterprise_capabilities_by_contract_metadata() {
        let mut service = DiscoveryService::default();
        let capability = Capability {
            id: CapabilityId::parse("cap:enterprise-refund").expect("capability"),
            name: "enterprise refund".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            description: None,
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: Some(CapabilityContract {
                side_effects: vec![SideEffect::Financial, SideEffect::Write],
                idempotency: IdempotencyContract {
                    requirement: IdempotencyRequirement::Required,
                    collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
                    key_scope: IdempotencyKeyScope::Tenant,
                    ttl_ms: Some(86_400_000),
                },
                execution: ExecutionContract {
                    supports_sync: true,
                    supports_async: true,
                    supports_streaming: false,
                    supports_cancel: true,
                    supports_retry: true,
                    expected_completion: ExpectedCompletionMode::Any,
                    retry_safety: RetrySafety::SafeWithIdempotencyKey,
                },
                data: DataContract {
                    sensitivity: DataSensitivity::Restricted,
                    contains_pii: true,
                    redaction_required: true,
                    residency: None,
                    retention: None,
                },
                credentials: Some(CredentialPolicy {
                    required: true,
                    accepted_issuers: vec!["vault:primary".to_owned()],
                    required_scopes: vec!["refund:write".to_owned()],
                    allow_oauth_refresh: false,
                }),
                approval: Some(ApprovalPolicy {
                    required: true,
                    reason: None,
                    approver_selector: ApproverSelector::TenantPolicy,
                    ttl_ms: None,
                    evidence_requirements: Vec::new(),
                    delegated_authority: None,
                    ..ApprovalPolicy::default()
                }),
                sla: None,
                transaction: Some(TransactionContract {
                    supported_modes: vec![TransactionMode::Execute, TransactionMode::Compensate],
                    requires_plan_before_commit: false,
                    dry_run_fidelity: DryRunFidelity::PolicyAndSchema,
                }),
                compensation: Some(CompensationContract {
                    mode: CompensationMode::Supported,
                    compensation_capability_id: Some(
                        CapabilityId::parse("cap:enterprise-refund-compensate")
                            .expect("capability"),
                    ),
                    compensation_window_ms: Some(86_400_000),
                    requires_approval: true,
                }),
            }),
        };
        service
            .register_manifest(
                "enterprise",
                Manifest {
                    manifest_version: "aip-manifest/v1".to_owned(),
                    agent: Principal::new(
                        PrincipalId::parse("agent:enterprise").expect("principal"),
                        PrincipalKind::Agent,
                    ),
                    capabilities: vec![capability],
                    profiles: vec![ProfileId::from("aip.native.http.v1")],
                    resources: Vec::new(),
                    channels: Vec::new(),
                    security: None,
                    governance: None,
                    limits: None,
                    compatibility: None,
                    extensions: None,
                },
            )
            .expect("manifest");

        let matches = service.query_capabilities(&EnterpriseCapabilityQuery {
            side_effects: vec![SideEffect::Financial],
            data_sensitivity: vec![DataSensitivity::Restricted],
            transaction_modes: vec![TransactionMode::Compensate],
            requires_approval: Some(true),
            requires_credentials: Some(true),
        });
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id.as_str(), "cap:enterprise-refund");
    }
}
