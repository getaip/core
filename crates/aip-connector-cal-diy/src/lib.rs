//! Production-oriented Cal.diy scheduling connector for AIP.
//!
//! The connector projects the versioned Cal.diy API v2 scheduling surface into
//! typed AIP capabilities. It owns provider authentication, per-resource API
//! version selection, mutation idempotency fencing, outcome reconciliation,
//! approval and compensation declarations, and signed webhook ingestion.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic))]

mod client;
mod operations;
mod state;
mod webhook;

pub use client::{
    CalDiyAuth, CalDiyClient, CalDiyClientError, CalDiyProviderResponse, CalDiyRequestMetadata,
    DEFAULT_MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES,
};
pub use operations::{
    ALL_OPERATIONS, BOOKINGS_API_VERSION, CalDiyHttpMethod, CalDiyOperation,
    DEPRECATED_ALIAS_EXCLUDED_ROUTES, EVENT_TYPES_API_VERSION, GENERAL_API_VERSION,
    OPERATOR_ONLY_EXCLUDED_ROUTES, PRIVATE_LINKS_API_VERSION, SCHEDULES_API_VERSION,
    SLOTS_API_VERSION,
};
pub use state::{
    CalDiyClaimOutcome, CalDiyDispatchClaim, CalDiyDispatchLedger, CalDiyDispatchStatus,
    CalDiyReconciliationState, DEFAULT_DISPATCH_LEASE_SECONDS,
};
pub use webhook::{
    CAL_DIY_WEBHOOK_VERSION, CalDiyWebhook, CalDiyWebhookDelivery, CalDiyWebhookError,
    CalDiyWebhookReplayStore, CalDiyWebhookSecretResolver, FileCalDiyWebhookReplayStore,
    InMemoryCalDiyWebhookReplayStore, ProfileStateCalDiyWebhookReplayStore,
    StaticCalDiyWebhookSecrets, event_from_webhook, ingest_cal_diy_webhook, verify_cal_diy_webhook,
};

use aip_auth::CredentialProvider;
use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    FrozenConnector, InboundConnector, OutboundConnector, ReconciliationRequest,
    ReconciliationResult,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Binding,
    Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
    CompensationMode, CredentialPolicy, DataContract, DataSensitivity, DryRunFidelity, Envelope,
    ErrorCategory, EvidenceRequirement, ExecutionContract, ExpectedCompletionMode,
    IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement,
    MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError,
    ProviderOperationRef, RetrySafety, ServiceLevelContract, SideEffect, TransactionContract,
    TransactionMode,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ProfileStateStore, RuntimeError, RuntimeResult,
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use time::{Duration, OffsetDateTime};

/// Stable connector id.
pub const CONNECTOR_ID: &str = "cal-diy";
/// Cal.diy-specific AIP binding profile.
pub const PROFILE_ID: &str = "aip.connector.cal_diy.v1";
/// Exact local upstream revision used to design this connector.
pub const UPSTREAM_REVISION: &str = "f00434927386c9ecdcbd7e6c5f82d22044a245bc";
/// Stable logical issuer for opaque Cal.diy credential handles.
///
/// This is part of the immutable connector manifest. Deployments may resolve
/// the handle through any Vault, KMS, or secret-provider implementation, but
/// the host-issued handle must retain this connector-specific issuer.
pub const CREDENTIAL_ISSUER: &str = "cal_diy_deployment";
const CAPABILITY_PREFIX: &str = "cap:cal_diy:";

/// Deployment-owned HTTPS prefixes accepted for provider webhook delivery.
///
/// The policy is deny-by-default. Prefixes should normally bind Cal.diy to the
/// public AIP ingress path, for example
/// `https://aip.example.com/connectors/cal-diy/webhooks/`.
#[derive(Clone, Default)]
pub struct CalDiyWebhookDestinationPolicy {
    prefixes: Vec<url::Url>,
}

impl std::fmt::Debug for CalDiyWebhookDestinationPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CalDiyWebhookDestinationPolicy")
            .field("configured_prefix_count", &self.prefixes.len())
            .finish()
    }
}

impl CalDiyWebhookDestinationPolicy {
    /// Builds a fail-closed destination policy from trusted deployment config.
    pub fn from_prefixes<I, S>(prefixes: I) -> Result<Self, CalDiyConnectorError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for prefix in prefixes {
            let mut prefix = url::Url::parse(prefix.as_ref()).map_err(|_| {
                CalDiyConnectorError::Configuration(
                    "webhook destination prefixes must be absolute HTTPS URLs".to_owned(),
                )
            })?;
            if prefix.scheme() != "https"
                || prefix.host_str().is_none()
                || !prefix.username().is_empty()
                || prefix.password().is_some()
                || prefix.query().is_some()
                || prefix.fragment().is_some()
            {
                return Err(CalDiyConnectorError::Configuration(
                    "webhook destination prefixes must be credential-free HTTPS URLs without query or fragment"
                        .to_owned(),
                ));
            }
            if !prefix.path().ends_with('/') {
                let path = format!("{}/", prefix.path());
                prefix.set_path(&path);
            }
            parsed.push(prefix);
        }
        parsed.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        parsed.dedup();
        Ok(Self { prefixes: parsed })
    }

    fn allows(&self, candidate: &url::Url, selector: &str) -> bool {
        candidate.scheme() == "https"
            && candidate.host_str().is_some()
            && candidate.username().is_empty()
            && candidate.password().is_none()
            && candidate.query().is_none()
            && candidate.fragment().is_none()
            && self.prefixes.iter().any(|prefix| {
                prefix.scheme() == candidate.scheme()
                    && prefix.host_str() == candidate.host_str()
                    && prefix.port_or_known_default() == candidate.port_or_known_default()
                    && candidate.path() == format!("{}{selector}", prefix.path())
            })
    }
}

/// Trusted mapping from one verified AIP tenant to a Cal.diy account boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalDiyTenantAccountBinding {
    /// Tenant id established by the AIP trusted identity resolver.
    pub tenant_id: String,
    /// Stable Cal.diy account id used to partition idempotency and recovery state.
    pub account_id: String,
}

#[derive(Clone)]
struct CalDiyCredentialRouting {
    accounts: Arc<BTreeMap<String, String>>,
    provider: Arc<dyn CredentialProvider>,
}

impl std::fmt::Debug for CalDiyCredentialRouting {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CalDiyCredentialRouting")
            .field("tenant_count", &self.accounts.len())
            .field("provider", &"CredentialProvider(..)")
            .finish()
    }
}

/// Complete Cal.diy connector.
#[derive(Clone)]
pub struct CalDiyConnector {
    client: CalDiyClient,
    account_id: String,
    profile_state: ProfileStateStore,
    ledger: CalDiyDispatchLedger,
    credential_routing: Option<CalDiyCredentialRouting>,
    webhook_secrets: Arc<dyn CalDiyWebhookSecretResolver>,
    webhook_replay: Arc<dyn CalDiyWebhookReplayStore>,
    webhook_destinations: CalDiyWebhookDestinationPolicy,
    webhook_ingress_enabled: bool,
}

impl std::fmt::Debug for CalDiyConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CalDiyConnector")
            .field("base_url", self.client.base_url())
            .field("account_id", &self.account_id)
            .field("ledger", &self.ledger)
            .field("credential_routing", &self.credential_routing)
            .field("webhook_secrets", &"CalDiyWebhookSecretResolver(..)")
            .field("webhook_replay", &"CalDiyWebhookReplayStore(..)")
            .field("webhook_destinations", &self.webhook_destinations)
            .field("webhook_ingress_enabled", &self.webhook_ingress_enabled)
            .finish()
    }
}

impl CalDiyConnector {
    /// Creates a connector using a protected Bearer credential.
    pub fn new(
        base_url: impl AsRef<str>,
        account_id: impl Into<String>,
        bearer_token: impl AsRef<[u8]>,
    ) -> Result<Self, CalDiyConnectorError> {
        Self::with_auth(
            base_url,
            account_id,
            CalDiyAuth::Bearer(aip_connector::ConnectorSecret::new(bearer_token)),
        )
    }

    /// Creates a connector using one supported Cal.diy authentication mechanism.
    pub fn with_auth(
        base_url: impl AsRef<str>,
        account_id: impl Into<String>,
        auth: CalDiyAuth,
    ) -> Result<Self, CalDiyConnectorError> {
        let account_id = normalize_account_id(account_id.into())?;
        let client = CalDiyClient::new(base_url, auth)?;
        let scope = format!("{}:{account_id}", client.base_url());
        let profile_state = ProfileStateStore::default();
        Ok(Self {
            client,
            account_id,
            ledger: CalDiyDispatchLedger::new(profile_state.clone(), scope),
            profile_state,
            credential_routing: None,
            webhook_secrets: Arc::new(StaticCalDiyWebhookSecrets::default()),
            webhook_replay: Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
            webhook_destinations: CalDiyWebhookDestinationPolicy::default(),
            webhook_ingress_enabled: false,
        })
    }

    /// Restricts provider webhook delivery to deployment-owned HTTPS prefixes.
    #[must_use]
    pub fn with_webhook_destination_policy(
        mut self,
        policy: CalDiyWebhookDestinationPolicy,
    ) -> Self {
        self.webhook_destinations = policy;
        self
    }

    /// Overrides the bounded provider response size for this deployment.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, CalDiyConnectorError> {
        self.client = self.client.with_max_response_bytes(max_response_bytes)?;
        Ok(self)
    }

    /// Injects the deployment's durable profile-state store.
    #[must_use]
    pub fn with_profile_state_store(mut self, state: ProfileStateStore) -> Self {
        let scope = format!("{}:{}", self.client.base_url(), self.account_id);
        self.ledger = CalDiyDispatchLedger::new(state.clone(), scope);
        self.profile_state = state;
        self
    }

    /// Enables fail-closed tenant/account routing with deployment-owned credentials.
    ///
    /// The runtime must supply both a verified tenant and an opaque credential
    /// handle. The connector resolves short-lived bearer material only for the
    /// immediate provider request; action payload identity fields are ignored.
    pub fn with_tenant_credential_routing(
        mut self,
        bindings: impl IntoIterator<Item = CalDiyTenantAccountBinding>,
        provider: Arc<dyn CredentialProvider>,
    ) -> Result<Self, CalDiyConnectorError> {
        let mut accounts = BTreeMap::new();
        for binding in bindings {
            let tenant_id = normalize_tenant_id(binding.tenant_id)?;
            let account_id = normalize_account_id(binding.account_id)?;
            if accounts.insert(tenant_id.clone(), account_id).is_some() {
                return Err(CalDiyConnectorError::Configuration(format!(
                    "duplicate Cal.diy tenant binding `{tenant_id}`"
                )));
            }
        }
        if accounts.is_empty() {
            return Err(CalDiyConnectorError::Configuration(
                "tenant credential routing requires at least one binding".to_owned(),
            ));
        }
        self.credential_routing = Some(CalDiyCredentialRouting {
            accounts: Arc::new(accounts),
            provider,
        });
        Ok(self)
    }

    /// Installs deployment-owned webhook secret resolution and replay fencing.
    #[must_use]
    pub fn with_webhook_security(
        mut self,
        secrets: Arc<dyn CalDiyWebhookSecretResolver>,
        replay: Arc<dyn CalDiyWebhookReplayStore>,
    ) -> Self {
        self.webhook_secrets = secrets;
        self.webhook_replay = replay;
        self.webhook_ingress_enabled = true;
        self
    }

    /// Returns the external account boundary represented by this connector.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    async fn execution_target(
        &self,
        operation: Option<CalDiyOperation>,
        connector_operation: ConnectorOperation,
        context: &ActionExecutionContext,
    ) -> Result<Self, ConnectorFailure> {
        let Some(routing) = &self.credential_routing else {
            return Ok(self.clone());
        };
        context.actor.validate(&BTreeSet::new()).map_err(|_| {
            credential_failure(connector_operation, "authenticated actor is expired")
        })?;
        let tenant = context.tenant.as_ref().ok_or_else(|| {
            credential_failure(
                connector_operation,
                "verified tenant membership is required for Cal.diy routing",
            )
        })?;
        tenant.validate().map_err(|_| {
            credential_failure(connector_operation, "verified tenant membership is expired")
        })?;
        let tenant_id = normalize_tenant_id(tenant.tenant.id.clone()).map_err(|_| {
            credential_failure(
                connector_operation,
                "verified tenant id is outside the Cal.diy routing contract",
            )
        })?;
        let account_id = routing.accounts.get(&tenant_id).cloned().ok_or_else(|| {
            credential_failure(
                connector_operation,
                "verified tenant has no Cal.diy account binding",
            )
        })?;
        let handle = context.credential.as_ref().ok_or_else(|| {
            credential_failure(
                connector_operation,
                "opaque Cal.diy credential handle is required",
            )
        })?;
        if handle.issuer() != CREDENTIAL_ISSUER {
            return Err(credential_failure(
                connector_operation,
                "Cal.diy credential issuer is not trusted",
            ));
        }
        if handle.tenant_id() != Some(tenant_id.as_str()) {
            return Err(credential_failure(
                connector_operation,
                "Cal.diy credential tenant does not match verified membership",
            ));
        }
        let required_scopes = operation
            .map(|operation| format!("cal_diy:{}", operation.suffix()))
            .into_iter()
            .collect();
        handle.validate(&required_scopes).map_err(|_| {
            credential_failure(
                connector_operation,
                "Cal.diy credential is expired or lacks the required operation scope",
            )
        })?;
        let material = routing.provider.resolve(handle).await.map_err(|_| {
            credential_failure(
                connector_operation,
                "Cal.diy credential handle could not be resolved",
            )
        })?;
        let client = CalDiyClient::new(
            self.client.base_url().as_str(),
            CalDiyAuth::Bearer(aip_connector::ConnectorSecret::new(material.expose())),
        )
        .and_then(|client| client.with_max_response_bytes(self.client.max_response_bytes()))
        .map_err(|_| {
            credential_failure(
                connector_operation,
                "resolved Cal.diy credential is invalid",
            )
        })?;
        let mut target = self.clone();
        target.client = client;
        target.account_id = account_id;
        target.ledger = CalDiyDispatchLedger::new(
            target.profile_state.clone(),
            format!("{}:{}", target.client.base_url(), target.account_id),
        );
        target.credential_routing = None;
        Ok(target)
    }

    fn request_metadata(
        &self,
        context: Option<&ActionExecutionContext>,
    ) -> Option<CalDiyRequestMetadata> {
        let context = context?;
        let tenant = context.tenant.as_ref()?;
        Some(CalDiyRequestMetadata {
            actor_id: context.actor.principal.id.as_str().to_owned(),
            tenant_id: tenant.tenant.id.clone(),
            account_id: self.account_id.clone(),
            trace_id: context.trace.trace_id.clone(),
        })
    }

    /// Builds the complete connector manifest without making a network request.
    pub fn discover_manifest(&self) -> Result<aip_core::Manifest, CalDiyConnectorError> {
        let credential_routing = self.credential_routing.is_some();
        let mut profiles = vec![
            ProfileId::from(PROFILE_ID),
            ProfileId::from("aip.native.http.v1"),
        ];
        let channels = if self.webhook_ingress_enabled {
            profiles.push(ProfileId::from(aip_profile_webhook::PROFILE_ID));
            vec![json!({
                "id": "cal-diy-webhooks",
                "name": "Cal.diy signed scheduling events",
                "system": "cal_diy",
                "kind": "signed_scheduling_events",
                "webhook_version": CAL_DIY_WEBHOOK_VERSION
            })]
        } else {
            Vec::new()
        };
        Ok(aip_core::Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::parse(format!("agent:cal_diy:{}", self.account_id))
                    .map_err(|error| CalDiyConnectorError::Configuration(error.to_string()))?,
                PrincipalKind::Agent,
            ),
            capabilities: cal_diy_capabilities_with_credentials(credential_routing)?,
            profiles,
            resources: Vec::new(),
            channels,
            security: Some(json!({
                "api_auth": ["bearer", "oauth_client_credentials"],
                "tenant_credential_routing": credential_routing,
                "credential_material_in_protocol": false,
                "webhook_hmac": "sha256_hex_exact_raw_body",
                "webhook_ingress_enabled": self.webhook_ingress_enabled,
                "mutation_idempotency": "aip_profile_state_cas",
                "provider_idempotency": false
            })),
            governance: Some(json!({
                "mutations_require_approval": true,
                "uncertain_mutations_require_reconciliation": true,
                "automatic_reconciliation_sources": [
                    "dispatch_ledger",
                    "trusted_transaction_outcome_checkpoint"
                ],
                "unresolved_provider_outcome": "operator_evidence_required"
            })),
            limits: Some(json!({
                "webhook_max_body_bytes": 1_048_576,
                "provider_max_response_bytes": self.client.max_response_bytes()
            })),
            compatibility: Some(json!({
                "system": "cal.diy",
                "connector": CONNECTOR_ID,
                "upstream_revision": UPSTREAM_REVISION,
                "api": "v2",
                "business_operations": ALL_OPERATIONS.len(),
                "operator_only_routes_excluded": OPERATOR_ONLY_EXCLUDED_ROUTES.len(),
                "deprecated_aliases_excluded": DEPRECATED_ALIAS_EXCLUDED_ROUTES.len()
            })),
            extensions: None,
        })
    }

    async fn invoke_action(
        &self,
        action: Action,
        context: Option<&ActionExecutionContext>,
    ) -> Result<ActionResult, ConnectorFailure> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction(format!(
                    "unsupported capability `{}`",
                    action.capability_id
                )),
                ConnectorOperation::Invocation,
                None,
                false,
            )
        })?;
        if self.credential_routing.is_some() {
            let context = context.ok_or_else(|| {
                credential_failure(
                    ConnectorOperation::Invocation,
                    "trusted execution context is required for tenant-routed Cal.diy access",
                )
            })?;
            let target = self
                .execution_target(Some(operation), ConnectorOperation::Invocation, context)
                .await?;
            return Box::pin(target.invoke_action(action, Some(context))).await;
        }
        if operation.is_read() {
            return self.execute_read(operation, action, context).await;
        }
        self.execute_mutation(operation, action, context).await
    }

    async fn execute_read(
        &self,
        operation: CalDiyOperation,
        action: Action,
        context: Option<&ActionExecutionContext>,
    ) -> Result<ActionResult, ConnectorFailure> {
        validate_operation_input(operation, &action.input, ConnectorOperation::Invocation)?;
        let action_id = action.id.to_string();
        let request_metadata = self.request_metadata(context);
        let request = self.client.execute_with_metadata(
            operation,
            &action.input,
            &action_id,
            None,
            request_metadata.as_ref(),
        );
        let response = if let Some(context) = context {
            tokio::select! {
                result = request => result,
                () = context.cancellation.cancelled() => {
                    return Err(cancelled_failure(ConnectorOperation::Invocation, false, None));
                }
            }
        } else {
            request.await
        }
        .map_err(|error| client_failure(error, ConnectorOperation::Invocation, None, false))?;
        validate_operation_output(
            operation,
            &response.body,
            ConnectorOperation::Invocation,
            None,
            response.request_id.clone(),
            Some(response.status),
            false,
        )?;
        Ok(completed_result(
            action,
            redact_provider_secrets(response.body),
        ))
    }

    async fn execute_mutation(
        &self,
        operation: CalDiyOperation,
        action: Action,
        context: Option<&ActionExecutionContext>,
    ) -> Result<ActionResult, ConnectorFailure> {
        validate_operation_input(operation, &action.input, ConnectorOperation::Invocation)?;
        let action_id = action.id.to_string();
        let trusted_key = context
            .and_then(|context| {
                context
                    .idempotency
                    .as_ref()
                    .map(|reservation| reservation.key.as_str())
            })
            .or(action.idempotency_key.as_deref())
            .ok_or_else(|| {
                failure(
                    CalDiyConnectorError::MissingIdempotencyKey,
                    ConnectorOperation::Invocation,
                    None,
                    false,
                )
            })?;
        let claim = match self
            .ledger
            .claim(operation, &action_id, trusted_key, &action.input)
            .await
            .map_err(|error| state_failure(error, ConnectorOperation::Invocation))?
        {
            CalDiyClaimOutcome::Claimed(claim) => claim,
            CalDiyClaimOutcome::Completed(output) => return Ok(completed_result(action, output)),
            CalDiyClaimOutcome::InFlight(operation_id) => {
                return Err(failure(
                    CalDiyConnectorError::IdempotencyInFlight,
                    ConnectorOperation::Invocation,
                    Some(ProviderOperationRef {
                        provider: CONNECTOR_ID.to_owned(),
                        operation_id,
                        request_id: None,
                    }),
                    false,
                ));
            }
            CalDiyClaimOutcome::Uncertain(operation_id) => {
                return Err(failure(
                    CalDiyConnectorError::OutcomeUnknown,
                    ConnectorOperation::Reconciliation,
                    Some(ProviderOperationRef {
                        provider: CONNECTOR_ID.to_owned(),
                        operation_id,
                        request_id: None,
                    }),
                    true,
                ));
            }
            CalDiyClaimOutcome::Collision => {
                return Err(failure(
                    CalDiyConnectorError::IdempotencyCollision,
                    ConnectorOperation::Invocation,
                    None,
                    false,
                ));
            }
        };
        let provider_operation = ProviderOperationRef {
            provider: CONNECTOR_ID.to_owned(),
            operation_id: claim.provider_operation_id().to_owned(),
            request_id: None,
        };
        let transaction_id = context
            .and_then(|context| context.transaction.as_ref())
            .map(|transaction| transaction.transaction_id.to_string());
        let prepared_input = match self
            .prepare_provider_input(
                operation,
                &action.input,
                &action_id,
                claim.provider_operation_id(),
                trusted_key,
                transaction_id.as_deref(),
            )
            .await
        {
            Ok(input) => input,
            Err(error) => {
                if let Err(state) = self.ledger.release(claim).await {
                    return Err(pre_dispatch_state_failure(
                        state,
                        ConnectorOperation::Invocation,
                        provider_operation,
                    ));
                }
                return Err(error);
            }
        };
        if let Some(context) = context
            && context.transaction.is_some()
            && let Err(error) = context
                .transaction_checkpoint
                .checkpoint(provider_operation.clone(), None)
                .await
        {
            if let Err(release_error) = self.ledger.release(claim.clone()).await {
                return Err(pre_dispatch_state_failure(
                    release_error,
                    ConnectorOperation::TransactionCommit,
                    provider_operation,
                ));
            }
            return Err(state_failure(error, ConnectorOperation::TransactionCommit));
        }
        let claim = match self.ledger.begin_dispatch(&claim).await {
            Ok(dispatch) => dispatch,
            Err(error) => {
                if let Err(release_error) = self.ledger.release(claim).await {
                    return Err(pre_dispatch_state_failure(
                        release_error,
                        ConnectorOperation::Invocation,
                        provider_operation,
                    ));
                }
                return Err(state_failure(error, ConnectorOperation::Invocation));
            }
        };
        let request_metadata = self.request_metadata(context);
        let request = self.client.execute_with_metadata(
            operation,
            &prepared_input,
            &action_id,
            Some(claim.provider_operation_id()),
            request_metadata.as_ref(),
        );
        let response = if let Some(context) = context {
            tokio::select! {
                result = request => result,
                () = context.cancellation.cancelled() => {
                    if let Err(error) = self.ledger.mark_uncertain(
                        claim,
                        None,
                        None,
                    ).await {
                        return Err(post_dispatch_state_failure(
                            error,
                            ConnectorOperation::Invocation,
                            provider_operation.clone(),
                            None,
                            None,
                            false,
                        ));
                    }
                    return Err(cancelled_failure(
                        ConnectorOperation::Invocation,
                        true,
                        Some(provider_operation.clone()),
                    ));
                }
            }
        } else {
            request.await
        };
        match response {
            Ok(response) => {
                if let Err(invalid_output) = validate_operation_output(
                    operation,
                    &response.body,
                    ConnectorOperation::Invocation,
                    Some(provider_operation.clone()),
                    response.request_id.clone(),
                    Some(response.status),
                    true,
                ) {
                    self.ledger
                        .mark_uncertain(claim, response.request_id.clone(), Some(response.status))
                        .await
                        .map_err(|error| {
                            post_dispatch_state_failure(
                                error,
                                ConnectorOperation::Invocation,
                                provider_operation,
                                Some(response.status),
                                None,
                                false,
                            )
                        })?;
                    return Err(invalid_output);
                }
                let output = redact_provider_secrets(response.body);
                let mut completed_operation = provider_operation.clone();
                completed_operation
                    .request_id
                    .clone_from(&response.request_id);
                let outcome_checkpointed = checkpoint_provider_outcome(
                    context,
                    completed_operation.clone(),
                    true,
                    Some(response.status),
                )
                .await;
                if let Err(error) = self
                    .ledger
                    .complete(claim, output.clone(), response.request_id, response.status)
                    .await
                {
                    return Err(post_dispatch_state_failure(
                        error,
                        ConnectorOperation::Invocation,
                        completed_operation,
                        Some(response.status),
                        Some(true),
                        outcome_checkpointed,
                    ));
                }
                Ok(completed_result(action, output))
            }
            Err(error) if guaranteed_no_dispatch(&error) => {
                let outcome_checkpointed =
                    checkpoint_provider_outcome(context, provider_operation.clone(), false, None)
                        .await;
                if let Err(state) = self.ledger.mark_not_committed(claim, None, None).await {
                    return Err(post_dispatch_state_failure(
                        state,
                        ConnectorOperation::Invocation,
                        provider_operation.clone(),
                        None,
                        Some(false),
                        outcome_checkpointed,
                    ));
                }
                Err(client_failure(
                    error,
                    ConnectorOperation::Invocation,
                    Some(provider_operation),
                    false,
                ))
            }
            Err(error) if definitive_rejection(&error) => {
                let mut rejected_operation = provider_operation.clone();
                rejected_operation.request_id = error.request_id().map(ToOwned::to_owned);
                let remote_status = error.remote_status();
                let outcome_checkpointed = checkpoint_provider_outcome(
                    context,
                    rejected_operation.clone(),
                    false,
                    remote_status,
                )
                .await;
                if let Err(state) = self
                    .ledger
                    .mark_not_committed(claim, rejected_operation.request_id.clone(), remote_status)
                    .await
                {
                    return Err(post_dispatch_state_failure(
                        state,
                        ConnectorOperation::Invocation,
                        rejected_operation,
                        remote_status,
                        Some(false),
                        outcome_checkpointed,
                    ));
                }
                Err(client_failure(
                    error,
                    ConnectorOperation::Invocation,
                    Some(provider_operation),
                    false,
                ))
            }
            Err(error) => {
                let request_id = error.request_id().map(ToOwned::to_owned);
                let status = error.remote_status();
                let mut provider_operation = provider_operation;
                provider_operation.request_id.clone_from(&request_id);
                if let Err(state) = self
                    .ledger
                    .mark_uncertain(claim, request_id.clone(), status)
                    .await
                {
                    return Err(post_dispatch_state_failure(
                        state,
                        ConnectorOperation::Invocation,
                        provider_operation,
                        status,
                        None,
                        false,
                    ));
                }
                Err(client_failure(
                    error,
                    ConnectorOperation::Invocation,
                    Some(provider_operation),
                    true,
                ))
            }
        }
    }

    async fn prepare_provider_input(
        &self,
        operation: CalDiyOperation,
        input: &Value,
        action_id: &str,
        provider_operation_id: &str,
        idempotency_key: &str,
        transaction_id: Option<&str>,
    ) -> Result<Value, ConnectorFailure> {
        let mut prepared = input.clone();
        if operation == CalDiyOperation::BookingCreate {
            let object = prepared.as_object_mut().ok_or_else(|| {
                failure(
                    CalDiyConnectorError::InvalidAction(
                        "booking.create input must be an object".to_owned(),
                    ),
                    ConnectorOperation::Invocation,
                    None,
                    false,
                )
            })?;
            let metadata = object
                .entry("metadata")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| {
                    failure(
                        CalDiyConnectorError::InvalidAction(
                            "booking metadata must be an object".to_owned(),
                        ),
                        ConnectorOperation::Invocation,
                        None,
                        false,
                    )
                })?;
            metadata.insert(
                "aip_action_id".to_owned(),
                Value::String(action_id.to_owned()),
            );
            metadata.insert(
                "aip_operation_id".to_owned(),
                Value::String(provider_operation_id.to_owned()),
            );
            metadata.insert(
                "aip_idempotency_hash".to_owned(),
                Value::String(hex::encode(Sha256::digest(idempotency_key.as_bytes()))),
            );
            if let Some(transaction_id) = transaction_id {
                metadata.insert(
                    "aip_transaction_id".to_owned(),
                    Value::String(transaction_id.to_owned()),
                );
            }
        }
        if !matches!(
            operation,
            CalDiyOperation::WebhookCreate
                | CalDiyOperation::WebhookUpdate
                | CalDiyOperation::EventTypeWebhookCreate
                | CalDiyOperation::EventTypeWebhookUpdate
        ) {
            return Ok(prepared);
        }
        let object = prepared.as_object_mut().ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction("webhook input must be an object".to_owned()),
                ConnectorOperation::Invocation,
                None,
                false,
            )
        })?;
        if object.contains_key("secret") {
            return Err(failure(
                CalDiyConnectorError::InvalidAction(
                    "raw webhook secrets are forbidden; use webhook_secret_ref".to_owned(),
                ),
                ConnectorOperation::Invocation,
                None,
                false,
            ));
        }
        if object
            .get("payloadTemplate")
            .is_some_and(|value| !value.is_null())
        {
            return Err(failure(
                CalDiyConnectorError::InvalidAction(
                    "AIP-managed Cal.diy webhooks require the standard payload shape".to_owned(),
                ),
                ConnectorOperation::Invocation,
                None,
                false,
            ));
        }
        if let Some(version) = object.get("version").and_then(Value::as_str)
            && version != CAL_DIY_WEBHOOK_VERSION
        {
            return Err(failure(
                CalDiyConnectorError::InvalidAction(format!(
                    "webhook version must be {CAL_DIY_WEBHOOK_VERSION}"
                )),
                ConnectorOperation::Invocation,
                None,
                false,
            ));
        }
        object.insert(
            "version".to_owned(),
            Value::String(CAL_DIY_WEBHOOK_VERSION.to_owned()),
        );
        if object.get("webhook_secret_ref").is_some_and(|value| {
            value
                .as_str()
                .is_none_or(|value| !webhook::valid_webhook_secret_ref(value))
        }) {
            return Err(failure(
                CalDiyConnectorError::InvalidAction(
                    "webhook_secret_ref must be a bounded URL-segment-safe identifier".to_owned(),
                ),
                ConnectorOperation::Invocation,
                None,
                false,
            ));
        }
        let secret_ref = object
            .get("webhook_secret_ref")
            .and_then(Value::as_str)
            .filter(|value| webhook::valid_webhook_secret_ref(value));
        if secret_ref.is_some()
            && object.get("subscriberUrl").is_none()
            && matches!(
                operation,
                CalDiyOperation::WebhookUpdate | CalDiyOperation::EventTypeWebhookUpdate
            )
        {
            return Err(failure(
                CalDiyConnectorError::InvalidAction(
                    "webhook secret rotation requires the bound subscriberUrl".to_owned(),
                ),
                ConnectorOperation::Invocation,
                None,
                false,
            ));
        }
        if let Some(subscriber_url) = object.get("subscriberUrl").and_then(Value::as_str) {
            let subscriber_url = url::Url::parse(subscriber_url).map_err(|_| {
                failure(
                    CalDiyConnectorError::InvalidAction(
                        "webhook subscriberUrl must be an absolute HTTPS URL".to_owned(),
                    ),
                    ConnectorOperation::Invocation,
                    None,
                    false,
                )
            })?;
            let Some(secret_ref) = secret_ref else {
                return Err(failure(
                    CalDiyConnectorError::InvalidAction(
                        "webhook subscriberUrl changes require a URL-segment-safe webhook_secret_ref"
                            .to_owned(),
                    ),
                    ConnectorOperation::Invocation,
                    None,
                    false,
                ));
            };
            if !self
                .webhook_destinations
                .allows(&subscriber_url, secret_ref)
            {
                return Err(failure(
                    CalDiyConnectorError::InvalidAction(
                        "webhook subscriberUrl is outside the deployment-owned HTTPS prefix allowlist"
                            .to_owned(),
                    ),
                    ConnectorOperation::Invocation,
                    None,
                    false,
                ));
            }
        }
        if matches!(
            operation,
            CalDiyOperation::WebhookCreate | CalDiyOperation::EventTypeWebhookCreate
        ) && secret_ref.is_none()
        {
            return Err(failure(
                CalDiyConnectorError::InvalidAction(
                    "webhook.create requires an opaque webhook_secret_ref".to_owned(),
                ),
                ConnectorOperation::Invocation,
                None,
                false,
            ));
        }
        let Some(secret_ref) = secret_ref else {
            return Ok(prepared);
        };
        let secret = self
            .webhook_secrets
            .resolve(secret_ref)
            .await
            .map_err(|error| {
                failure(
                    CalDiyConnectorError::WebhookSecretResolver(error),
                    ConnectorOperation::Invocation,
                    None,
                    false,
                )
            })?
            .ok_or_else(|| {
                failure(
                    CalDiyConnectorError::WebhookSecretNotFound,
                    ConnectorOperation::Invocation,
                    None,
                    false,
                )
            })?;
        let secret = secret.expose_str().map_err(|_| {
            failure(
                CalDiyConnectorError::WebhookSecretNotFound,
                ConnectorOperation::Invocation,
                None,
                false,
            )
        })?;
        client::inject_webhook_secret(&prepared, secret)
            .map_err(|error| client_failure(error, ConnectorOperation::Invocation, None, false))
    }
}

/// Connector-specific error with redacted diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum CalDiyConnectorError {
    /// Provider client failure.
    #[error(transparent)]
    Client(#[from] CalDiyClientError),
    /// Connector account or identity configuration is invalid.
    #[error("invalid Cal.diy connector configuration: {0}")]
    Configuration(String),
    /// AIP action input is invalid for the selected operation.
    #[error("invalid Cal.diy action: {0}")]
    InvalidAction(String),
    /// A mutating action omitted the mandatory idempotency reservation.
    #[error("Cal.diy mutations require an AIP idempotency key")]
    MissingIdempotencyKey,
    /// The same idempotency key was used for different input.
    #[error("Cal.diy idempotency key collided with different input")]
    IdempotencyCollision,
    /// Another attempt currently owns the provider dispatch.
    #[error("Cal.diy mutation is already in flight")]
    IdempotencyInFlight,
    /// A prior provider dispatch has an unknown outcome.
    #[error("Cal.diy mutation outcome is unknown and requires reconciliation")]
    OutcomeUnknown,
    /// Durable connector state failed.
    #[error("Cal.diy connector state failed: {0}")]
    State(String),
    /// Webhook secret lookup failed.
    #[error("Cal.diy webhook secret resolver failed: {0}")]
    WebhookSecretResolver(String),
    /// An opaque webhook secret reference could not be resolved.
    #[error("Cal.diy webhook secret reference is unknown")]
    WebhookSecretNotFound,
    /// Signed webhook ingestion failed.
    #[error(transparent)]
    Webhook(#[from] CalDiyWebhookError),
}

#[async_trait]
impl Connector for CalDiyConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<aip_core::Manifest> {
        self.discover_manifest()
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        match error {
            ConnectorError::Failure(failure) => failure.to_protocol_error(),
            other => ProtocolError {
                code: "connector.cal_diy".to_owned(),
                message: other.to_string(),
                category: ErrorCategory::Connector,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": CONNECTOR_ID }))),
            },
        }
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        self.client.health().await.map_err(|error| {
            ConnectorError::Failure(client_failure(
                error,
                ConnectorOperation::Health,
                None,
                false,
            ))
        })?;
        Ok(ConnectorHealth {
            ready: true,
            detail: "Cal.diy API v2 profile endpoint is reachable and authenticated".to_owned(),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for CalDiyConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        cal_diy_capabilities_with_credentials(self.credential_routing.is_some())
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }
}

#[async_trait]
impl OutboundConnector for CalDiyConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        self.invoke_action(action, None)
            .await
            .map_err(ConnectorError::Failure)
    }

    async fn emit(
        &self,
        _context: &ConnectorContext,
        _result: ActionResult,
    ) -> ConnectorResult<()> {
        Err(ConnectorFailure::unsupported(ConnectorOperation::Emission, CONNECTOR_ID).into())
    }
}

#[async_trait]
impl InboundConnector for CalDiyConnector {
    async fn ingest(
        &self,
        context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>> {
        let raw_body = required_metadata(context, "raw_body").map_err(ConnectorError::Verify)?;
        let parsed = serde_json::from_str::<Value>(&raw_body)
            .map_err(|error| ConnectorError::Verify(error.to_string()))?;
        if parsed != payload {
            return Err(ConnectorError::Verify(
                "raw Cal.diy webhook body does not match supplied parsed payload".to_owned(),
            ));
        }
        let delivery = CalDiyWebhookDelivery {
            subscription_id: required_metadata(context, "subscription_id")
                .map_err(ConnectorError::Verify)?,
            signature: required_metadata(context, "signature").map_err(ConnectorError::Verify)?,
            webhook_version: Some(
                required_metadata(context, "webhook_version").map_err(ConnectorError::Verify)?,
            ),
            raw_body,
            received_at: OffsetDateTime::now_utc().unix_timestamp(),
        };
        ingest_cal_diy_webhook(
            self.webhook_secrets.as_ref(),
            self.webhook_replay.as_ref(),
            delivery,
        )
        .await
        .map_err(|error| {
            ConnectorError::Failure(failure(
                CalDiyConnectorError::Webhook(error),
                ConnectorOperation::Ingestion,
                None,
                false,
            ))
        })
    }
}

#[async_trait]
impl FrozenConnector for CalDiyConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        let operation = operation_from_capability(&capability.id);
        CapabilityImplementationSupport {
            invocation: operation.is_some(),
            cancellation: false,
            streaming: false,
            retry: operation.is_some_and(CalDiyOperation::is_read),
            transaction: operation.is_some_and(|operation| !operation.is_read()),
            reconciliation: operation.is_some_and(|operation| !operation.is_read()),
            compensation: operation.is_some_and(|operation| operation.destructive()),
            approval: operation.is_some_and(requires_approval),
            credentials: self.credential_routing.is_some(),
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction("unsupported capability".to_owned()),
                ConnectorOperation::Invocation,
                None,
                false,
            )
        })?;
        if requires_planned_commit(operation) {
            return Err(ConnectorFailure {
                code: "connector.cal_diy.transaction_required".to_owned(),
                message: "high-risk booking mutations require AIP plan and commit".to_owned(),
                category: ErrorCategory::Policy,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::Invocation,
            });
        }
        self.invoke_action(action, Some(&context)).await
    }

    async fn plan_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction("unsupported capability".to_owned()),
                ConnectorOperation::TransactionPlan,
                None,
                false,
            )
        })?;
        let target = self
            .execution_target(
                Some(operation),
                ConnectorOperation::TransactionPlan,
                &context,
            )
            .await?;
        target.validate_plan(action, &context).await
    }

    async fn commit_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction("unsupported capability".to_owned()),
                ConnectorOperation::TransactionCommit,
                None,
                false,
            )
        })?;
        if operation.is_read() {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionCommit,
                CONNECTOR_ID,
            ));
        }
        let target = self
            .execution_target(
                Some(operation),
                ConnectorOperation::TransactionCommit,
                &context,
            )
            .await?;
        target
            .execute_mutation(operation, action, Some(&context))
            .await
    }

    async fn compensate_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction("unsupported capability".to_owned()),
                ConnectorOperation::Compensation,
                None,
                false,
            )
        })?;
        if !operation.destructive() {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::Compensation,
                CONNECTOR_ID,
            ));
        }
        let target = self
            .execution_target(Some(operation), ConnectorOperation::Compensation, &context)
            .await?;
        target
            .execute_mutation(operation, action, Some(&context))
            .await
    }

    async fn reconcile_typed(
        &self,
        request: ReconciliationRequest,
        context: ActionExecutionContext,
    ) -> Result<ReconciliationResult, ConnectorFailure> {
        if self.credential_routing.is_some() {
            let target = self
                .execution_target(None, ConnectorOperation::Reconciliation, &context)
                .await?;
            return Box::pin(target.reconcile_typed(request, context)).await;
        }
        let trusted_cursor = context
            .transaction
            .as_ref()
            .filter(|transaction| {
                transaction.provider_operation_id.as_deref()
                    == Some(request.provider_operation_id.as_str())
            })
            .and_then(|transaction| transaction.reconciliation_cursor.as_deref())
            .filter(|cursor| request.cursor.as_deref() == Some(*cursor));
        if let Some((committed, provider_status)) =
            trusted_cursor.and_then(parse_provider_outcome_cursor)
        {
            return Ok(ReconciliationResult {
                terminal: true,
                committed: Some(committed),
                cursor: None,
                evidence: Some(json!({
                    "source": "durable_transaction_checkpoint",
                    "provider_status": provider_status
                })),
            });
        }
        let state = self
            .ledger
            .reconcile(&request.provider_operation_id)
            .await
            .map_err(|error| state_failure(error, ConnectorOperation::Reconciliation))?;
        match state {
            Some(CalDiyReconciliationState {
                status: CalDiyDispatchStatus::Completed,
                output,
                provider_request_id,
                provider_status,
            }) => Ok(ReconciliationResult {
                terminal: true,
                committed: Some(true),
                cursor: None,
                evidence: Some(json!({
                    "provider_request_id": provider_request_id,
                    "provider_status": provider_status,
                    "output": output
                })),
            }),
            Some(CalDiyReconciliationState {
                status: CalDiyDispatchStatus::Uncertain,
                provider_request_id,
                provider_status,
                ..
            }) => Ok(ReconciliationResult {
                terminal: false,
                committed: None,
                cursor: Some(request.provider_operation_id),
                evidence: Some(json!({
                    "provider_request_id": provider_request_id,
                    "provider_status": provider_status,
                    "reason": "provider outcome remains unknown"
                })),
            }),
            Some(CalDiyReconciliationState {
                status: CalDiyDispatchStatus::NotCommitted,
                ..
            }) => Ok(ReconciliationResult {
                terminal: true,
                committed: Some(false),
                cursor: None,
                evidence: Some(json!({
                    "reason": "provider dispatch never crossed the durable dispatch boundary"
                })),
            }),
            Some(CalDiyReconciliationState {
                status: CalDiyDispatchStatus::Claimed,
                ..
            }) => Ok(ReconciliationResult {
                terminal: false,
                committed: None,
                cursor: Some(request.provider_operation_id),
                evidence: Some(json!({ "reason": "provider dispatch is still claimed" })),
            }),
            Some(CalDiyReconciliationState {
                status: CalDiyDispatchStatus::Dispatching,
                ..
            }) => Ok(ReconciliationResult {
                terminal: false,
                committed: None,
                cursor: Some(request.provider_operation_id),
                evidence: Some(json!({ "reason": "provider request is still in flight" })),
            }),
            None => Err(ConnectorFailure {
                code: "connector.cal_diy.reconciliation_not_found".to_owned(),
                message: "Cal.diy provider operation was not found".to_owned(),
                category: ErrorCategory::Permanent,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::Reconciliation,
            }),
        }
    }

    async fn ingest_typed(
        &self,
        payload: Value,
        _context: ActionExecutionContext,
    ) -> Result<Vec<Envelope>, ConnectorFailure> {
        let mut delivery =
            serde_json::from_value::<CalDiyWebhookDelivery>(payload).map_err(|error| {
                failure(
                    CalDiyConnectorError::InvalidAction(error.to_string()),
                    ConnectorOperation::Ingestion,
                    None,
                    false,
                )
            })?;
        delivery.received_at = OffsetDateTime::now_utc().unix_timestamp();
        ingest_cal_diy_webhook(
            self.webhook_secrets.as_ref(),
            self.webhook_replay.as_ref(),
            delivery,
        )
        .await
        .map_err(|error| {
            failure(
                CalDiyConnectorError::Webhook(error),
                ConnectorOperation::Ingestion,
                None,
                false,
            )
        })
    }
}

#[async_trait]
impl ActionHandler for CalDiyConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke(&ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        self.invoke_action(action, Some(&context))
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }
}

impl CalDiyConnector {
    /// Verifies and maps one exact provider webhook delivery.
    ///
    /// Standalone hosts append the returned deterministic events to their
    /// durable runtime event log before acknowledging the provider request.
    pub async fn ingest_webhook_delivery(
        &self,
        delivery: CalDiyWebhookDelivery,
    ) -> Result<Vec<Envelope>, CalDiyWebhookError> {
        ingest_cal_diy_webhook(
            self.webhook_secrets.as_ref(),
            self.webhook_replay.as_ref(),
            delivery,
        )
        .await
    }

    async fn validate_plan(
        &self,
        action: Action,
        context: &ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let action_id = action.id.to_string();
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction("unsupported capability".to_owned()),
                ConnectorOperation::TransactionPlan,
                None,
                false,
            )
        })?;
        if operation.is_read() {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionPlan,
                CONNECTOR_ID,
            ));
        }
        validate_operation_input(
            operation,
            &action.input,
            ConnectorOperation::TransactionPlan,
        )?;
        let validation = match operation {
            CalDiyOperation::BookingCreate => {
                self.validate_booking_slot(&action, None, context).await?;
                "downstream_slot_availability"
            }
            CalDiyOperation::BookingReschedule => {
                let booking_uid = required_input_string(&action.input, "booking_uid")?;
                let request_metadata = self.request_metadata(Some(context));
                let booking = self
                    .client
                    .execute_with_metadata(
                        CalDiyOperation::BookingGet,
                        &json!({ "booking_uid": booking_uid }),
                        &action_id,
                        None,
                        request_metadata.as_ref(),
                    )
                    .await
                    .map_err(|error| {
                        client_failure(error, ConnectorOperation::TransactionPlan, None, false)
                    })?;
                validate_operation_output(
                    CalDiyOperation::BookingGet,
                    &booking.body,
                    ConnectorOperation::TransactionPlan,
                    None,
                    booking.request_id.clone(),
                    Some(booking.status),
                    false,
                )?;
                let event_type_id = booking
                    .body
                    .pointer("/data/eventTypeId")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| {
                        failure(
                            CalDiyConnectorError::InvalidAction(
                                "booking response omitted eventTypeId".to_owned(),
                            ),
                            ConnectorOperation::TransactionPlan,
                            None,
                            false,
                        )
                    })?;
                self.validate_booking_slot(&action, Some(event_type_id), context)
                    .await?;
                "booking_state_and_downstream_slot_availability"
            }
            operation => {
                if let Some((read_operation, read_input)) = preflight_read(operation, &action.input)
                {
                    let request_metadata = self.request_metadata(Some(context));
                    let response = tokio::select! {
                        result = self.client.execute_with_metadata(
                            read_operation,
                            &read_input,
                            &action_id,
                            None,
                            request_metadata.as_ref(),
                        ) => {
                            result.map_err(|error| client_failure(
                                error,
                                ConnectorOperation::TransactionPlan,
                                None,
                                false,
                            ))?
                        }
                        () = context.cancellation.cancelled() => {
                            return Err(cancelled_failure(
                                ConnectorOperation::TransactionPlan,
                                false,
                                None,
                            ));
                        }
                    };
                    validate_operation_output(
                        read_operation,
                        &response.body,
                        ConnectorOperation::TransactionPlan,
                        None,
                        response.request_id,
                        Some(response.status),
                        false,
                    )?;
                    "downstream_target_exists"
                } else {
                    "schema_and_policy"
                }
            }
        };
        let output = json!({
            "status": "success",
            "planned": true,
            "operation": operation.suffix(),
            "api_version": operation.api_version(),
            "provider_path": operation.path_template(),
            "input_hash": hex::encode(Sha256::digest(
                serde_json::to_vec(&action.input).map_err(|error| failure(
                    CalDiyConnectorError::InvalidAction(error.to_string()),
                    ConnectorOperation::TransactionPlan,
                    None,
                    false,
                ))?
            )),
            "validation": validation,
            "side_effect_committed": false
        });
        Ok(completed_result(action, output))
    }

    async fn validate_booking_slot(
        &self,
        action: &Action,
        fallback_event_type_id: Option<i64>,
        context: &ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        let start = required_input_string(&action.input, "start")?;
        let start_time = OffsetDateTime::parse(
            &start,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|error| {
            failure(
                CalDiyConnectorError::InvalidAction(format!("invalid start timestamp: {error}")),
                ConnectorOperation::TransactionPlan,
                None,
                false,
            )
        })?;
        let end = (start_time + Duration::days(1))
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| {
                failure(
                    CalDiyConnectorError::InvalidAction(error.to_string()),
                    ConnectorOperation::TransactionPlan,
                    None,
                    false,
                )
            })?;
        let mut query = Map::new();
        query.insert("start".to_owned(), Value::String(start.clone()));
        query.insert("end".to_owned(), Value::String(end));
        query.insert("format".to_owned(), Value::String("time".to_owned()));
        for field in [
            "eventTypeId",
            "eventTypeSlug",
            "username",
            "organizationSlug",
            "timeZone",
            "duration",
            "booking_uid",
        ] {
            if let Some(value) = action.input.get(field) {
                let target = if field == "booking_uid" {
                    "bookingUidToReschedule"
                } else {
                    field
                };
                query.insert(target.to_owned(), value.clone());
            }
        }
        if !query.contains_key("eventTypeId")
            && let Some(event_type_id) = fallback_event_type_id
        {
            query.insert("eventTypeId".to_owned(), Value::from(event_type_id));
        }
        let query = Value::Object(query);
        let action_id = action.id.to_string();
        let request_metadata = self.request_metadata(Some(context));
        let response = tokio::select! {
            result = self.client.execute_with_metadata(
                CalDiyOperation::SlotList,
                &query,
                &action_id,
                None,
                request_metadata.as_ref(),
            ) => result,
            () = context.cancellation.cancelled() => {
                return Err(cancelled_failure(
                    ConnectorOperation::TransactionPlan,
                    false,
                    None,
                ));
            }
        }
        .map_err(|error| client_failure(error, ConnectorOperation::TransactionPlan, None, false))?;
        validate_operation_output(
            CalDiyOperation::SlotList,
            &response.body,
            ConnectorOperation::TransactionPlan,
            None,
            response.request_id.clone(),
            Some(response.status),
            false,
        )?;
        if !slot_response_contains(&response.body, start_time) {
            return Err(ConnectorFailure {
                code: "connector.cal_diy.slot_unavailable".to_owned(),
                message: "requested Cal.diy booking start is not currently available".to_owned(),
                category: ErrorCategory::Policy,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: response.request_id,
                provider_operation: None,
                remote_status: Some(response.status),
                uncertain_outcome: false,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::TransactionPlan,
            });
        }
        Ok(())
    }
}

/// Returns the complete set of typed Cal.diy capabilities.
pub fn cal_diy_capabilities() -> Result<Vec<Capability>, CalDiyConnectorError> {
    cal_diy_capabilities_with_credentials(false)
}

fn cal_diy_capabilities_with_credentials(
    credential_required: bool,
) -> Result<Vec<Capability>, CalDiyConnectorError> {
    ALL_OPERATIONS
        .iter()
        .copied()
        .map(|operation| capability_for_operation_with_credentials(operation, credential_required))
        .collect()
}

/// Builds one typed capability from the stable operation catalogue.
pub fn capability_for_operation(
    operation: CalDiyOperation,
) -> Result<Capability, CalDiyConnectorError> {
    capability_for_operation_with_credentials(operation, false)
}

fn capability_for_operation_with_credentials(
    operation: CalDiyOperation,
    credential_required: bool,
) -> Result<Capability, CalDiyConnectorError> {
    let capability_id = CapabilityId::parse(format!("{CAPABILITY_PREFIX}{}", operation.suffix()))
        .map_err(|error| CalDiyConnectorError::Configuration(error.to_string()))?;
    let mut bindings = Vec::new();
    for profile in ["aip.native.http.v1", PROFILE_ID] {
        bindings.push(Binding {
            profile: ProfileId::from(profile),
            metadata: json!({
                "system": "cal_diy",
                "connector": CONNECTOR_ID,
                "operation": operation.suffix(),
                "method": method_name(operation.method()),
                "path": operation.path_template(),
                "api_version": operation.api_version()
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        });
    }
    Ok(Capability {
        id: capability_id,
        name: operation.name().to_owned(),
        kind: CapabilityKind::Tool,
        input_schema: operation.input_schema(),
        output_schema: Some(cal_diy_output_schema()),
        description: Some(operation_description(operation).to_owned()),
        risk: Some(operation.risk()),
        stability: None,
        cost: None,
        auth: Some(json!({
            "type": "configured_cal_diy_credential",
            "accepted": ["bearer", "oauth_client_credentials"]
        })),
        bindings,
        requires_human_approval: Some(requires_approval(operation)),
        contract: Some(contract_for_operation(operation, credential_required)?),
    })
}

fn contract_for_operation(
    operation: CalDiyOperation,
    credential_required: bool,
) -> Result<CapabilityContract, CalDiyConnectorError> {
    let read = operation.is_read();
    let mut side_effects = vec![
        if read {
            SideEffect::Read
        } else {
            SideEffect::Write
        },
        SideEffect::ExternalNetwork,
    ];
    if operation.destructive() {
        side_effects.push(SideEffect::Delete);
    }
    if matches!(
        operation,
        CalDiyOperation::BookingCreate
            | CalDiyOperation::BookingReschedule
            | CalDiyOperation::BookingCancel
            | CalDiyOperation::BookingConfirm
            | CalDiyOperation::BookingDecline
            | CalDiyOperation::BookingAttendeeAdd
            | CalDiyOperation::BookingAttendeeDelete
            | CalDiyOperation::BookingGuestAdd
    ) {
        side_effects.push(SideEffect::SendMessage);
    }
    if operation == CalDiyOperation::ProfileUpdate {
        side_effects.push(SideEffect::Identity);
    }
    let approval = requires_approval(operation).then(|| ApprovalPolicy {
        required: true,
        reason: Some(approval_reason(operation).to_owned()),
        approver_selector: ApproverSelector::TenantPolicy,
        ttl_ms: Some(900_000),
        evidence_requirements: vec![
            EvidenceRequirement::Reason,
            EvidenceRequirement::InputSnapshot,
            EvidenceRequirement::PolicyDecision,
        ],
        delegated_authority: None,
        ..ApprovalPolicy::default()
    });
    let compensation_capability_id = operation
        .compensation_suffix()
        .map(|suffix| CapabilityId::parse(format!("{CAPABILITY_PREFIX}{suffix}")))
        .transpose()
        .map_err(|error| CalDiyConnectorError::Configuration(error.to_string()))?;
    Ok(CapabilityContract {
        side_effects,
        idempotency: IdempotencyContract {
            requirement: if read {
                IdempotencyRequirement::Optional
            } else {
                IdempotencyRequirement::Required
            },
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: if read {
                IdempotencyKeyScope::Action
            } else {
                IdempotencyKeyScope::ExternalAccount
            },
            ttl_ms: None,
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: read,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: if read {
                RetrySafety::Safe
            } else {
                RetrySafety::Unsafe
            },
        },
        data: DataContract {
            sensitivity: data_sensitivity(operation),
            contains_pii: operation_contains_pii(operation),
            redaction_required: operation_contains_pii(operation),
            residency: None,
            retention: None,
        },
        credentials: Some(CredentialPolicy {
            required: credential_required,
            accepted_issuers: vec![CREDENTIAL_ISSUER.to_owned()],
            required_scopes: vec![format!("cal_diy:{}", operation.suffix())],
            allow_oauth_refresh: false,
        }),
        approval,
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(if read { 2_000 } else { 5_000 }),
            timeout_ms: Some(30_000),
            async_expected: false,
            max_queue_delay_ms: Some(5_000),
            availability_target: None,
        }),
        transaction: (!read).then(|| TransactionContract {
            supported_modes: vec![
                TransactionMode::DryRun,
                TransactionMode::Plan,
                TransactionMode::Commit,
                TransactionMode::Reconcile,
            ],
            requires_plan_before_commit: requires_planned_commit(operation),
            dry_run_fidelity: if requires_planned_commit(operation) {
                DryRunFidelity::DownstreamValidation
            } else {
                DryRunFidelity::PolicyAndSchema
            },
        }),
        compensation: Some(match compensation_capability_id {
            Some(capability_id) => CompensationContract {
                mode: CompensationMode::BestEffort,
                compensation_capability_id: Some(capability_id),
                compensation_window_ms: Some(86_400_000),
                requires_approval: true,
            },
            None if read => CompensationContract {
                mode: CompensationMode::NotRequired,
                compensation_capability_id: None,
                compensation_window_ms: None,
                requires_approval: false,
            },
            None => CompensationContract {
                mode: CompensationMode::RollbackNotSupported,
                compensation_capability_id: None,
                compensation_window_ms: None,
                requires_approval: true,
            },
        }),
    })
}

fn operation_from_capability(capability_id: &CapabilityId) -> Option<CalDiyOperation> {
    let suffix = capability_id.as_str().strip_prefix(CAPABILITY_PREFIX)?;
    ALL_OPERATIONS
        .iter()
        .copied()
        .find(|operation| operation.suffix() == suffix)
}

fn method_name(method: CalDiyHttpMethod) -> &'static str {
    match method {
        CalDiyHttpMethod::Get => "GET",
        CalDiyHttpMethod::Post => "POST",
        CalDiyHttpMethod::Patch => "PATCH",
        CalDiyHttpMethod::Put => "PUT",
        CalDiyHttpMethod::Delete => "DELETE",
    }
}

fn operation_description(operation: CalDiyOperation) -> &'static str {
    match operation {
        CalDiyOperation::ProfileGet => "Reads the authenticated Cal.diy profile.",
        CalDiyOperation::ProfileUpdate => "Updates the authenticated Cal.diy profile.",
        CalDiyOperation::EventTypeList => {
            "Lists event types visible to the configured Cal.diy identity."
        }
        CalDiyOperation::EventTypeGet => "Reads one Cal.diy event type by id.",
        CalDiyOperation::EventTypeCreate => "Creates a Cal.diy event type.",
        CalDiyOperation::EventTypeUpdate => "Updates an owned Cal.diy event type.",
        CalDiyOperation::EventTypeDelete => "Deletes an owned Cal.diy event type.",
        CalDiyOperation::EventTypePrivateLinkList => {
            "Lists access-controlled private links for an event type."
        }
        CalDiyOperation::EventTypePrivateLinkCreate => {
            "Creates an expiring or usage-limited event-type private link."
        }
        CalDiyOperation::EventTypePrivateLinkUpdate => {
            "Updates an event-type private-link expiry or usage limit."
        }
        CalDiyOperation::EventTypePrivateLinkDelete => "Revokes an event-type private link.",
        CalDiyOperation::EventTypeWebhookList => "Lists webhooks scoped to an event type.",
        CalDiyOperation::EventTypeWebhookGet => "Reads one event-type webhook.",
        CalDiyOperation::EventTypeWebhookCreate => {
            "Creates a signed event-type webhook from an opaque deployment secret reference."
        }
        CalDiyOperation::EventTypeWebhookUpdate => {
            "Updates an event-type webhook without accepting raw secrets in AIP input."
        }
        CalDiyOperation::EventTypeWebhookDelete => "Deletes an event-type webhook.",
        CalDiyOperation::EventTypeWebhookDeleteAll => {
            "Deletes every webhook scoped to an event type."
        }
        CalDiyOperation::SlotList => "Queries versioned Cal.diy availability slots.",
        CalDiyOperation::SlotReservationCreate => "Creates a short-lived Cal.diy slot reservation.",
        CalDiyOperation::SlotReservationGet => "Reads a slot reservation by its sensitive uid.",
        CalDiyOperation::SlotReservationUpdate => {
            "Updates a slot reservation by its sensitive uid."
        }
        CalDiyOperation::SlotReservationDelete => {
            "Releases a slot reservation by its sensitive uid."
        }
        CalDiyOperation::BookingList => "Lists bookings with Cal.diy filters and pagination.",
        CalDiyOperation::BookingGet => "Reads a booking or recurring booking set by uid.",
        CalDiyOperation::BookingGetBySeat => "Reads a seated booking by its seat uid.",
        CalDiyOperation::BookingCreate => {
            "Creates a regular, recurring, seated, or instant booking."
        }
        CalDiyOperation::BookingReschedule => {
            "Reschedules a booking after downstream availability validation."
        }
        CalDiyOperation::BookingCancel => "Cancels a booking, recurrence, or individual seat.",
        CalDiyOperation::BookingConfirm => "Confirms a pending booking.",
        CalDiyOperation::BookingDecline => "Declines a pending booking with an optional reason.",
        CalDiyOperation::BookingMarkAbsent => "Updates host or attendee absence state.",
        CalDiyOperation::BookingReassign => "Reassigns a round-robin booking automatically.",
        CalDiyOperation::BookingReassignToUser => {
            "Reassigns a round-robin booking to a specified user."
        }
        CalDiyOperation::BookingLocationUpdate => {
            "Updates an existing booking location and conferencing integration."
        }
        CalDiyOperation::BookingAttendeeList => "Lists booking attendees.",
        CalDiyOperation::BookingAttendeeGet => "Reads one booking attendee.",
        CalDiyOperation::BookingAttendeeAdd => {
            "Adds an attendee and updates connected calendar events."
        }
        CalDiyOperation::BookingAttendeeDelete => {
            "Removes an attendee and updates connected calendar events."
        }
        CalDiyOperation::BookingGuestAdd => "Adds guests and sends applicable notifications.",
        CalDiyOperation::BookingCalendarLinksGet => "Reads generated booking calendar links.",
        CalDiyOperation::BookingReferenceList => {
            "Lists provider calendar references for a booking."
        }
        CalDiyOperation::BookingRecordingList => "Lists restricted recording download metadata.",
        CalDiyOperation::BookingTranscriptList => "Lists restricted transcript download metadata.",
        CalDiyOperation::BookingConferencingSessionList => {
            "Lists conferencing sessions associated with a booking."
        }
        CalDiyOperation::CalendarList => "Lists connected Cal.diy calendars.",
        CalDiyOperation::CalendarProviderCheck => {
            "Checks whether a calendar provider connection is healthy."
        }
        CalDiyOperation::CalendarDisconnect => {
            "Deletes an owned calendar credential and invalidates its connection."
        }
        CalDiyOperation::CalendarIcsFeedCheck => {
            "Checks the authenticated user's ICS feed connection."
        }
        CalDiyOperation::CalendarBusyTimeList => {
            "Reads busy intervals from an explicit set of connected calendars."
        }
        CalDiyOperation::CalendarConnectionList => {
            "Lists credential-safe unified calendar connection identifiers."
        }
        CalDiyOperation::CalendarConnectionEventList => {
            "Lists events for a unified calendar connection."
        }
        CalDiyOperation::CalendarConnectionEventGet => {
            "Reads one event from a unified calendar connection."
        }
        CalDiyOperation::CalendarConnectionEventCreate => {
            "Creates an event on a unified calendar connection."
        }
        CalDiyOperation::CalendarConnectionEventUpdate => {
            "Updates an event on a unified calendar connection."
        }
        CalDiyOperation::CalendarConnectionEventDelete => {
            "Deletes an event from a unified calendar connection."
        }
        CalDiyOperation::CalendarConnectionFreeBusyGet => {
            "Reads free/busy intervals for a unified calendar connection."
        }
        CalDiyOperation::CalendarEventList => "Lists calendar events in a bounded date range.",
        CalDiyOperation::CalendarEventGet => "Reads one provider calendar event.",
        CalDiyOperation::CalendarEventCreate => "Creates a provider calendar event.",
        CalDiyOperation::CalendarEventUpdate => {
            "Updates provider calendar event details and attendees."
        }
        CalDiyOperation::CalendarEventDelete => "Deletes a provider calendar event.",
        CalDiyOperation::CalendarFreeBusyGet => {
            "Reads free/busy intervals for a calendar provider."
        }
        CalDiyOperation::DestinationCalendarUpdate => {
            "Changes the destination calendar used for new bookings."
        }
        CalDiyOperation::SelectedCalendarAdd => "Adds a calendar to conflict detection.",
        CalDiyOperation::SelectedCalendarDelete => "Removes a calendar from conflict detection.",
        CalDiyOperation::ConferencingList => "Lists installed conferencing applications.",
        CalDiyOperation::ConferencingDefaultGet => "Reads the default conferencing application.",
        CalDiyOperation::ConferencingDefaultSet => "Changes the default conferencing application.",
        CalDiyOperation::ConferencingConnect => {
            "Connects a supported non-OAuth conferencing application."
        }
        CalDiyOperation::ConferencingDisconnect => "Disconnects a conferencing application.",
        CalDiyOperation::ScheduleList => "Lists authenticated-user schedules.",
        CalDiyOperation::ScheduleDefaultGet => "Reads the authenticated user's default schedule.",
        CalDiyOperation::ScheduleGet => "Reads one owned schedule.",
        CalDiyOperation::ScheduleCreate => "Creates an availability schedule.",
        CalDiyOperation::ScheduleUpdate => "Updates an availability schedule.",
        CalDiyOperation::ScheduleDelete => "Deletes an availability schedule.",
        CalDiyOperation::WebhookList => "Lists user-level Cal.diy webhooks with secrets redacted.",
        CalDiyOperation::WebhookGet => "Reads a user-level webhook with its secret redacted.",
        CalDiyOperation::WebhookCreate => {
            "Creates a signed user webhook from an opaque deployment secret reference."
        }
        CalDiyOperation::WebhookUpdate => {
            "Updates a user webhook without accepting raw secrets in AIP input."
        }
        CalDiyOperation::WebhookDelete => "Deletes a user webhook.",
    }
}

fn requires_approval(operation: CalDiyOperation) -> bool {
    !operation.is_read()
        || matches!(
            operation,
            CalDiyOperation::BookingRecordingList | CalDiyOperation::BookingTranscriptList
        )
}

fn requires_planned_commit(operation: CalDiyOperation) -> bool {
    matches!(
        operation,
        CalDiyOperation::BookingCreate
            | CalDiyOperation::BookingReschedule
            | CalDiyOperation::BookingCancel
    )
}

fn approval_reason(operation: CalDiyOperation) -> &'static str {
    if matches!(
        operation,
        CalDiyOperation::BookingRecordingList | CalDiyOperation::BookingTranscriptList
    ) {
        "The response may expose restricted meeting media or transcript data."
    } else if operation.destructive() {
        "The operation deletes or irreversibly transitions scheduling state."
    } else {
        "The operation changes customer-visible scheduling state or notifications."
    }
}

fn data_sensitivity(operation: CalDiyOperation) -> DataSensitivity {
    match operation {
        CalDiyOperation::SlotList => DataSensitivity::Public,
        CalDiyOperation::BookingRecordingList
        | CalDiyOperation::BookingTranscriptList
        | CalDiyOperation::ProfileGet
        | CalDiyOperation::ProfileUpdate
        | CalDiyOperation::WebhookList
        | CalDiyOperation::WebhookGet
        | CalDiyOperation::WebhookCreate
        | CalDiyOperation::WebhookUpdate
        | CalDiyOperation::WebhookDelete
        | CalDiyOperation::EventTypePrivateLinkList
        | CalDiyOperation::EventTypePrivateLinkCreate
        | CalDiyOperation::EventTypePrivateLinkUpdate
        | CalDiyOperation::EventTypePrivateLinkDelete
        | CalDiyOperation::EventTypeWebhookList
        | CalDiyOperation::EventTypeWebhookGet
        | CalDiyOperation::EventTypeWebhookCreate
        | CalDiyOperation::EventTypeWebhookUpdate
        | CalDiyOperation::EventTypeWebhookDelete
        | CalDiyOperation::EventTypeWebhookDeleteAll => DataSensitivity::Restricted,
        _ if operation.suffix().starts_with("booking.") => DataSensitivity::Restricted,
        _ if operation.suffix().starts_with("calendar.") => DataSensitivity::Restricted,
        _ => DataSensitivity::Confidential,
    }
}

fn operation_contains_pii(operation: CalDiyOperation) -> bool {
    matches!(
        data_sensitivity(operation),
        DataSensitivity::Restricted | DataSensitivity::Regulated
    ) || operation.suffix().starts_with("booking.")
        || operation.suffix().starts_with("event_type.")
}

fn definitive_rejection(error: &CalDiyClientError) -> bool {
    matches!(
        error,
        CalDiyClientError::Remote { status, .. }
            if (400..500).contains(status) && *status != 408
    )
}

fn guaranteed_no_dispatch(error: &CalDiyClientError) -> bool {
    matches!(
        error,
        CalDiyClientError::InvalidUrl(_)
            | CalDiyClientError::InvalidInput(_)
            | CalDiyClientError::InvalidCredential
    )
}

fn completed_result(action: Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id,
        status: ActionResultStatus::Completed,
        output: Some(output.clone()),
        message: vec![MessagePart::Json {
            data: output,
            schema: None,
        }],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

async fn checkpoint_provider_outcome(
    context: Option<&ActionExecutionContext>,
    provider_operation: ProviderOperationRef,
    committed: bool,
    provider_status: Option<u16>,
) -> bool {
    let Some(context) = context.filter(|context| context.transaction.is_some()) else {
        return false;
    };
    context
        .transaction_checkpoint
        .checkpoint(
            provider_operation,
            Some(provider_outcome_cursor(committed, provider_status)),
        )
        .await
        .is_ok()
}

fn provider_outcome_cursor(committed: bool, provider_status: Option<u16>) -> String {
    format!(
        "cal_diy.outcome.v1:{}:{}",
        if committed { "committed" } else { "rejected" },
        provider_status.map_or_else(|| "none".to_owned(), |status| status.to_string())
    )
}

fn parse_provider_outcome_cursor(cursor: &str) -> Option<(bool, Option<u16>)> {
    let value = cursor.strip_prefix("cal_diy.outcome.v1:")?;
    let (outcome, status) = value.split_once(':')?;
    if status.contains(':') {
        return None;
    }
    let committed = match outcome {
        "committed" => true,
        "rejected" => false,
        _ => return None,
    };
    let status = if status == "none" {
        None
    } else {
        let status = status.parse::<u16>().ok()?;
        Some((100..=599).contains(&status).then_some(status)?)
    };
    Some((committed, status))
}

fn client_failure(
    error: CalDiyClientError,
    operation: ConnectorOperation,
    provider_operation: Option<ProviderOperationRef>,
    uncertain_outcome: bool,
) -> ConnectorFailure {
    let remote_status = error.remote_status();
    let provider_request_id = error.request_id().map(ToOwned::to_owned);
    let retry_after_ms = error.retry_after_ms();
    let (code, category, retryable) = match &error {
        CalDiyClientError::Remote {
            status: 401 | 403, ..
        } => (
            "connector.cal_diy.authentication",
            ErrorCategory::Auth,
            false,
        ),
        CalDiyClientError::Remote {
            status: 409 | 412, ..
        } => (
            "connector.cal_diy.state_conflict",
            ErrorCategory::Policy,
            false,
        ),
        CalDiyClientError::Remote { status: 429, .. } => (
            "connector.cal_diy.rate_limited",
            ErrorCategory::Temporary,
            !uncertain_outcome,
        ),
        CalDiyClientError::Remote { status, .. } if *status >= 500 => (
            "connector.cal_diy.remote_temporary",
            ErrorCategory::Temporary,
            !uncertain_outcome,
        ),
        CalDiyClientError::Remote { .. } => (
            "connector.cal_diy.remote_rejected",
            ErrorCategory::Permanent,
            false,
        ),
        CalDiyClientError::Transport => (
            "connector.cal_diy.transport",
            ErrorCategory::Transport,
            !uncertain_outcome,
        ),
        CalDiyClientError::ResponseTooLarge { .. } => (
            "connector.cal_diy.response_too_large",
            ErrorCategory::Transport,
            false,
        ),
        CalDiyClientError::InvalidCredential => (
            "connector.cal_diy.invalid_credential",
            ErrorCategory::Auth,
            false,
        ),
        CalDiyClientError::InvalidInput(_)
        | CalDiyClientError::InvalidUrl(_)
        | CalDiyClientError::InvalidResponse => (
            "connector.cal_diy.invalid_request",
            ErrorCategory::Permanent,
            false,
        ),
    };
    ConnectorFailure {
        code: code.to_owned(),
        message: error.to_string(),
        category,
        retryable,
        retry_after_ms,
        provider_request_id,
        provider_operation,
        remote_status,
        uncertain_outcome,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn credential_failure(operation: ConnectorOperation, message: &'static str) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.cal_diy.credential_resolution".to_owned(),
        message: message.to_owned(),
        category: ErrorCategory::Auth,
        retryable: false,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation: None,
        remote_status: None,
        uncertain_outcome: false,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn state_failure(_error: RuntimeError, operation: ConnectorOperation) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.cal_diy.state".to_owned(),
        message: "Cal.diy durable connector state failed".to_owned(),
        category: ErrorCategory::Temporary,
        retryable: false,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation: None,
        remote_status: None,
        uncertain_outcome: false,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn pre_dispatch_state_failure(
    _error: RuntimeError,
    operation: ConnectorOperation,
    provider_operation: ProviderOperationRef,
) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.cal_diy.pre_dispatch_state".to_owned(),
        message: "Cal.diy provider dispatch did not begin, but durable claim cleanup failed"
            .to_owned(),
        category: ErrorCategory::Temporary,
        retryable: false,
        retry_after_ms: Some((DEFAULT_DISPATCH_LEASE_SECONDS as u64).saturating_mul(1_000)),
        provider_request_id: None,
        provider_operation: Some(provider_operation),
        remote_status: None,
        uncertain_outcome: false,
        redacted_details: Some(json!({ "provider_dispatch_started": false })),
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn post_dispatch_state_failure(
    _error: RuntimeError,
    operation: ConnectorOperation,
    provider_operation: ProviderOperationRef,
    remote_status: Option<u16>,
    provider_commit_confirmed: Option<bool>,
    durable_outcome_checkpoint: bool,
) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.cal_diy.post_dispatch_state".to_owned(),
        message: "Cal.diy provider dispatch crossed the durable boundary, but connector settlement failed"
            .to_owned(),
        category: ErrorCategory::Temporary,
        retryable: false,
        retry_after_ms: None,
        provider_request_id: provider_operation.request_id.clone(),
        provider_operation: Some(provider_operation),
        remote_status,
        uncertain_outcome: true,
        redacted_details: Some(json!({
            "provider_commit_confirmed": provider_commit_confirmed,
            "durable_outcome_checkpoint": durable_outcome_checkpoint
        })),
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn failure(
    error: CalDiyConnectorError,
    operation: ConnectorOperation,
    provider_operation: Option<ProviderOperationRef>,
    uncertain_outcome: bool,
) -> ConnectorFailure {
    let (code, category, retryable) = match &error {
        CalDiyConnectorError::MissingIdempotencyKey
        | CalDiyConnectorError::WebhookSecretNotFound => {
            ("connector.cal_diy.policy", ErrorCategory::Policy, false)
        }
        CalDiyConnectorError::IdempotencyCollision => (
            "connector.cal_diy.idempotency_collision",
            ErrorCategory::Policy,
            false,
        ),
        CalDiyConnectorError::IdempotencyInFlight => (
            "connector.cal_diy.in_flight",
            ErrorCategory::Temporary,
            true,
        ),
        CalDiyConnectorError::OutcomeUnknown => (
            "connector.cal_diy.outcome_unknown",
            ErrorCategory::Temporary,
            false,
        ),
        CalDiyConnectorError::Webhook(CalDiyWebhookError::InvalidSignature)
        | CalDiyConnectorError::Webhook(CalDiyWebhookError::InvalidSignatureEncoding)
        | CalDiyConnectorError::Webhook(CalDiyWebhookError::UnknownSubscription) => {
            ("connector.cal_diy.webhook_auth", ErrorCategory::Auth, false)
        }
        CalDiyConnectorError::Webhook(CalDiyWebhookError::Replay(_))
        | CalDiyConnectorError::Webhook(CalDiyWebhookError::TimestampSkew)
        | CalDiyConnectorError::Webhook(CalDiyWebhookError::UnsupportedVersion(_)) => (
            "connector.cal_diy.webhook_policy",
            ErrorCategory::Policy,
            false,
        ),
        CalDiyConnectorError::State(_)
        | CalDiyConnectorError::WebhookSecretResolver(_)
        | CalDiyConnectorError::Webhook(CalDiyWebhookError::SecretResolver(_))
        | CalDiyConnectorError::Webhook(CalDiyWebhookError::ReplayStore(_)) => {
            ("connector.cal_diy.state", ErrorCategory::Temporary, false)
        }
        CalDiyConnectorError::Client(_) => {
            ("connector.cal_diy.client", ErrorCategory::Connector, false)
        }
        _ => (
            "connector.cal_diy.invalid_action",
            ErrorCategory::Permanent,
            false,
        ),
    };
    ConnectorFailure {
        code: code.to_owned(),
        message: error.to_string(),
        category,
        retryable,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation,
        remote_status: None,
        uncertain_outcome,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn cancelled_failure(
    operation: ConnectorOperation,
    uncertain_outcome: bool,
    provider_operation: Option<ProviderOperationRef>,
) -> ConnectorFailure {
    let provider_request_id = provider_operation
        .as_ref()
        .and_then(|operation| operation.request_id.clone());
    ConnectorFailure {
        code: "connector.cal_diy.cancelled".to_owned(),
        message: if uncertain_outcome {
            "Cal.diy invocation was cancelled after provider dispatch".to_owned()
        } else {
            "Cal.diy invocation was cancelled before a terminal response".to_owned()
        },
        category: ErrorCategory::Temporary,
        retryable: false,
        retry_after_ms: None,
        provider_request_id,
        provider_operation,
        remote_status: None,
        uncertain_outcome,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

// The frozen connector API returns `ConnectorFailure` by value. Keeping that
// boundary avoids boxing failures differently from the other connector paths.
#[allow(clippy::result_large_err)]
fn required_input_string(input: &Value, field: &'static str) -> Result<String, ConnectorFailure> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            failure(
                CalDiyConnectorError::InvalidAction(format!("missing input `{field}`")),
                ConnectorOperation::TransactionPlan,
                None,
                false,
            )
        })
}

#[allow(clippy::result_large_err)]
fn validate_operation_input(
    operation: CalDiyOperation,
    input: &Value,
    connector_operation: ConnectorOperation,
) -> Result<(), ConnectorFailure> {
    aip_schema::validate_draft202012(&operation.input_schema(), input).map_err(|_| {
        failure(
            CalDiyConnectorError::InvalidAction(format!(
                "input does not match the published `{}` schema",
                operation.suffix()
            )),
            connector_operation,
            None,
            false,
        )
    })
}

fn cal_diy_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status"],
        "properties": {
            "status": { "type": "string", "minLength": 1 },
            "data": {},
            "pagination": { "type": "object" }
        },
        "additionalProperties": true
    })
}

#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn validate_operation_output(
    operation: CalDiyOperation,
    output: &Value,
    connector_operation: ConnectorOperation,
    provider_operation: Option<ProviderOperationRef>,
    provider_request_id: Option<String>,
    remote_status: Option<u16>,
    uncertain_outcome: bool,
) -> Result<(), ConnectorFailure> {
    aip_schema::validate_draft202012(&cal_diy_output_schema(), output).map_err(|_| {
        ConnectorFailure {
            code: "connector.cal_diy.invalid_provider_output".to_owned(),
            message: format!(
                "Cal.diy returned output outside the published `{}` schema",
                operation.suffix()
            ),
            category: ErrorCategory::Connector,
            retryable: false,
            retry_after_ms: None,
            provider_request_id,
            provider_operation,
            remote_status,
            uncertain_outcome,
            redacted_details: None,
            source_component: CONNECTOR_ID.to_owned(),
            operation: connector_operation,
        }
    })
}

fn preflight_read(operation: CalDiyOperation, input: &Value) -> Option<(CalDiyOperation, Value)> {
    let fields = |names: &[&str]| {
        let mut object = Map::new();
        for name in names {
            if let Some(value) = input.get(*name) {
                object.insert((*name).to_owned(), value.clone());
            }
        }
        Value::Object(object)
    };
    match operation {
        CalDiyOperation::ProfileUpdate => Some((CalDiyOperation::ProfileGet, json!({}))),
        CalDiyOperation::EventTypeUpdate | CalDiyOperation::EventTypeDelete => {
            Some((CalDiyOperation::EventTypeGet, fields(&["event_type_id"])))
        }
        CalDiyOperation::EventTypePrivateLinkCreate
        | CalDiyOperation::EventTypePrivateLinkUpdate
        | CalDiyOperation::EventTypePrivateLinkDelete
        | CalDiyOperation::EventTypeWebhookCreate
        | CalDiyOperation::EventTypeWebhookDeleteAll => {
            Some((CalDiyOperation::EventTypeGet, fields(&["event_type_id"])))
        }
        CalDiyOperation::EventTypeWebhookUpdate | CalDiyOperation::EventTypeWebhookDelete => {
            Some((
                CalDiyOperation::EventTypeWebhookGet,
                fields(&["event_type_id", "webhook_id"]),
            ))
        }
        CalDiyOperation::SlotReservationUpdate | CalDiyOperation::SlotReservationDelete => Some((
            CalDiyOperation::SlotReservationGet,
            fields(&["reservation_uid"]),
        )),
        CalDiyOperation::BookingCancel
        | CalDiyOperation::BookingConfirm
        | CalDiyOperation::BookingDecline
        | CalDiyOperation::BookingMarkAbsent
        | CalDiyOperation::BookingReassign
        | CalDiyOperation::BookingReassignToUser
        | CalDiyOperation::BookingLocationUpdate
        | CalDiyOperation::BookingAttendeeAdd
        | CalDiyOperation::BookingGuestAdd => {
            Some((CalDiyOperation::BookingGet, fields(&["booking_uid"])))
        }
        CalDiyOperation::BookingAttendeeDelete => Some((
            CalDiyOperation::BookingAttendeeGet,
            fields(&["booking_uid", "attendee_id"]),
        )),
        CalDiyOperation::CalendarConnectionEventCreate
        | CalDiyOperation::CalendarEventCreate
        | CalDiyOperation::DestinationCalendarUpdate
        | CalDiyOperation::SelectedCalendarAdd
        | CalDiyOperation::SelectedCalendarDelete => {
            Some((CalDiyOperation::CalendarList, json!({})))
        }
        CalDiyOperation::CalendarEventUpdate | CalDiyOperation::CalendarEventDelete => Some((
            CalDiyOperation::CalendarEventGet,
            fields(&["calendar", "event_uid"]),
        )),
        CalDiyOperation::CalendarConnectionEventUpdate
        | CalDiyOperation::CalendarConnectionEventDelete => Some((
            CalDiyOperation::CalendarConnectionEventGet,
            fields(&["connection_id", "event_id", "calendarId"]),
        )),
        CalDiyOperation::CalendarDisconnect => Some((
            CalDiyOperation::CalendarProviderCheck,
            fields(&["calendar"]),
        )),
        CalDiyOperation::ConferencingDefaultSet
        | CalDiyOperation::ConferencingConnect
        | CalDiyOperation::ConferencingDisconnect => {
            Some((CalDiyOperation::ConferencingList, json!({})))
        }
        CalDiyOperation::ScheduleUpdate | CalDiyOperation::ScheduleDelete => {
            Some((CalDiyOperation::ScheduleGet, fields(&["schedule_id"])))
        }
        CalDiyOperation::WebhookUpdate | CalDiyOperation::WebhookDelete => {
            Some((CalDiyOperation::WebhookGet, fields(&["webhook_id"])))
        }
        _ => None,
    }
}

fn slot_response_contains(body: &Value, requested: OffsetDateTime) -> bool {
    body.get("data")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|days| days.values())
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(|slot| slot.get("start").and_then(Value::as_str))
        .filter_map(|start| {
            OffsetDateTime::parse(start, &time::format_description::well_known::Rfc3339).ok()
        })
        .any(|start| start == requested)
}

fn redact_provider_secrets(mut value: Value) -> Value {
    fn redact(value: &mut Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let normalized = key.to_ascii_lowercase().replace(['-', '_'], "");
                    if matches!(
                        normalized.as_str(),
                        "secret"
                            | "apikey"
                            | "hashedkey"
                            | "token"
                            | "accesstoken"
                            | "refreshtoken"
                            | "clientsecret"
                    ) {
                        *value = Value::String("[REDACTED]".to_owned());
                    } else {
                        redact(value);
                    }
                }
            }
            Value::Array(values) => values.iter_mut().for_each(redact),
            _ => {}
        }
    }
    redact(&mut value);
    value
}

fn normalize_account_id(account_id: String) -> Result<String, CalDiyConnectorError> {
    if account_id.is_empty()
        || account_id.len() > 128
        || !account_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(CalDiyConnectorError::Configuration(
            "account id must contain 1..=128 ASCII letters, digits, dot, underscore, or hyphen"
                .to_owned(),
        ));
    }
    Ok(account_id)
}

fn normalize_tenant_id(tenant_id: String) -> Result<String, CalDiyConnectorError> {
    if tenant_id.is_empty()
        || tenant_id.len() > 128
        || !tenant_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
    {
        return Err(CalDiyConnectorError::Configuration(
            "tenant id must contain 1..=128 ASCII letters, digits, colon, dot, underscore, or hyphen"
                .to_owned(),
        ));
    }
    Ok(tenant_id)
}

fn required_metadata(context: &ConnectorContext, key: &'static str) -> Result<String, String> {
    context
        .metadata
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing metadata `{key}`"))
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_OPERATIONS, CAPABILITY_PREFIX, CONNECTOR_ID, CalDiyConnector, CalDiyOperation,
        DEPRECATED_ALIAS_EXCLUDED_ROUTES, InMemoryCalDiyWebhookReplayStore,
        OPERATOR_ONLY_EXCLUDED_ROUTES, PROFILE_ID, StaticCalDiyWebhookSecrets, cancelled_failure,
        capability_for_operation, data_sensitivity, operation_from_capability,
        redact_provider_secrets,
    };
    use aip_conformance::{
        ConnectorBoundarySpec, check_connector_boundary, check_connector_manifest,
    };
    use aip_connector::{ConnectorSecret, FrozenConnector};
    use aip_core::{DataSensitivity, IdempotencyRequirement, ProviderOperationRef};
    use aip_discovery::{DiscoveryService, ManifestAdmissionPolicy};
    use serde_json::json;
    use std::{
        collections::{BTreeSet, HashMap},
        sync::Arc,
    };

    #[test]
    fn operation_catalogue_has_unique_capability_ids() {
        assert_eq!(ALL_OPERATIONS.len(), 81);
        let mut ids = BTreeSet::new();
        for operation in ALL_OPERATIONS {
            let capability = capability_for_operation(*operation).expect("valid capability");
            assert!(ids.insert(capability.id.to_string()));
            assert_eq!(operation_from_capability(&capability.id), Some(*operation));
            assert!(capability.contract.is_some());
        }
        assert_eq!(ids.len(), ALL_OPERATIONS.len());
    }

    #[test]
    fn pinned_openapi_exclusions_are_explicit_unique_and_outside_the_business_catalogue() {
        assert_eq!(OPERATOR_ONLY_EXCLUDED_ROUTES.len(), 38);
        assert_eq!(DEPRECATED_ALIAS_EXCLUDED_ROUTES.len(), 2);
        assert_eq!(
            ALL_OPERATIONS.len()
                + OPERATOR_ONLY_EXCLUDED_ROUTES.len()
                + DEPRECATED_ALIAS_EXCLUDED_ROUTES.len(),
            121
        );
        let published = ALL_OPERATIONS
            .iter()
            .map(|operation| (operation.method(), operation.path_template()))
            .collect::<BTreeSet<_>>();
        let excluded = OPERATOR_ONLY_EXCLUDED_ROUTES
            .iter()
            .chain(DEPRECATED_ALIAS_EXCLUDED_ROUTES)
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(excluded.len(), 40);
        assert!(published.is_disjoint(&excluded));
    }

    #[test]
    fn every_published_input_schema_compiles_as_draft_2020_12() {
        for operation in ALL_OPERATIONS {
            let schema = operation.input_schema();
            jsonschema::draft202012::new(&schema).unwrap_or_else(|error| {
                panic!("{} schema did not compile: {error}", operation.suffix())
            });
        }
    }

    #[test]
    fn connector_manifest_passes_public_boundary_checks() {
        let connector =
            CalDiyConnector::new("http://127.0.0.1:65535/api", "account-1", "provider-secret")
                .expect("connector configuration");
        let manifest = connector.discover_manifest().expect("manifest");
        let connector_check = check_connector_manifest(CONNECTOR_ID, &manifest);
        assert!(
            connector_check.passed,
            "{}: {}",
            connector_check.name, connector_check.detail
        );
        let boundary = check_connector_boundary(
            &manifest,
            ConnectorBoundarySpec {
                connector_id: CONNECTOR_ID,
                connector_profile: PROFILE_ID,
                capability_id_prefix: CAPABILITY_PREFIX,
                required_binding_metadata: &[
                    "connector",
                    "operation",
                    "method",
                    "path",
                    "api_version",
                ],
            },
        );
        assert!(boundary.passed, "{}: {}", boundary.name, boundary.detail);
        let implementations = manifest
            .capabilities
            .iter()
            .map(|capability| {
                (
                    capability.id.clone(),
                    connector.implementation_support(capability),
                )
            })
            .collect::<HashMap<_, _>>();
        DiscoveryService::admit_manifest(
            manifest,
            &ManifestAdmissionPolicy::default(),
            &implementations,
        )
        .unwrap_or_else(|report| panic!("manifest admission failed: {report}"));
    }

    #[test]
    fn webhook_profile_is_advertised_only_after_security_is_installed() {
        let connector =
            CalDiyConnector::new("http://127.0.0.1:65535/api", "account-1", "provider-secret")
                .expect("connector");
        let outbound = connector.discover_manifest().expect("outbound manifest");
        assert!(outbound.channels.is_empty());
        assert!(
            !outbound
                .profiles
                .iter()
                .any(|profile| profile.as_str() == aip_profile_webhook::PROFILE_ID)
        );
        let secrets = StaticCalDiyWebhookSecrets::new([(
            "booking-events".to_owned(),
            ConnectorSecret::new("webhook-secret"),
        )])
        .expect("webhook secrets");
        let secured = connector.with_webhook_security(
            Arc::new(secrets),
            Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
        );
        let inbound = secured.discover_manifest().expect("inbound manifest");
        assert_eq!(inbound.channels.len(), 1);
        assert!(
            inbound
                .profiles
                .iter()
                .any(|profile| profile.as_str() == aip_profile_webhook::PROFILE_ID)
        );
    }

    #[test]
    fn connector_debug_output_redacts_provider_credentials() {
        let connector = CalDiyConnector::new(
            "http://127.0.0.1:65535/api",
            "account-1",
            "do-not-print-this-provider-secret",
        )
        .expect("connector configuration");
        let debug = format!("{connector:?}");
        assert!(!debug.contains("do-not-print-this-provider-secret"));
        assert!(debug.contains("CalDiyWebhookSecretResolver(..)"));
        assert!(debug.contains("CalDiyWebhookDestinationPolicy"));
    }

    #[test]
    fn every_mutation_requires_idempotency_and_approval() {
        for operation in ALL_OPERATIONS
            .iter()
            .copied()
            .filter(|operation| !operation.is_read())
        {
            let capability = capability_for_operation(operation).expect("valid capability");
            let contract = capability.contract.expect("contract");
            assert_eq!(
                contract.idempotency.requirement,
                IdempotencyRequirement::Required
            );
            assert!(capability.requires_human_approval.unwrap_or(false));
        }
    }

    #[test]
    fn sensitive_media_reads_are_restricted() {
        assert_eq!(
            data_sensitivity(CalDiyOperation::BookingRecordingList),
            DataSensitivity::Restricted
        );
        assert_eq!(
            data_sensitivity(CalDiyOperation::BookingTranscriptList),
            DataSensitivity::Restricted
        );
        assert_eq!(
            data_sensitivity(CalDiyOperation::EventTypeGet),
            DataSensitivity::Confidential
        );
    }

    #[test]
    fn provider_secrets_are_removed_recursively() {
        let redacted = redact_provider_secrets(json!({
            "data": [{ "id": "hook", "secret": "raw" }],
            "access_token": "token"
        }));
        assert_eq!(
            redacted.pointer("/data/0/secret"),
            Some(&json!("[REDACTED]"))
        );
        assert_eq!(redacted.get("access_token"), Some(&json!("[REDACTED]")));
    }

    #[test]
    fn post_dispatch_cancellation_retains_the_reconciliation_key() {
        let provider_operation = ProviderOperationRef {
            provider: CONNECTOR_ID.to_owned(),
            operation_id: "opaque-ledger-key".to_owned(),
            request_id: None,
        };
        let failure = cancelled_failure(
            aip_connector::ConnectorOperation::Invocation,
            true,
            Some(provider_operation.clone()),
        );
        assert!(failure.uncertain_outcome);
        assert_eq!(failure.provider_operation, Some(provider_operation));
    }
}
