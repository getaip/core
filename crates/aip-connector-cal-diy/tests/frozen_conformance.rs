//! Frozen RFC 0004 behavioral conformance for the Cal.diy connector.
//!
//! Required behavior is exercised through the public frozen connector and AIP
//! runtime boundaries against a deterministic HTTP provider. Cancellation and
//! streaming are the only not-applicable families because the pinned Cal.diy
//! API surface and the published manifest claim neither behavior.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use aip_auth::{
    AuthError, AuthScheme, AuthenticatedPrincipal, AuthorityMembership, CredentialHandle,
    CredentialMaterial, CredentialProvider, StaticApprovalAuthorityResolver, VerifiedTenant,
};
use aip_conformance::{
    ConnectorConformanceDriver, ConnectorConformanceScenario, ConnectorEvidenceSource,
    ConnectorScenarioEvidence, run_connector_conformance,
};
use aip_connector::{
    CapabilityImplementationSupport, ConnectorSecret, FrozenConnector, FrozenConnectorHandler,
    ReconciliationRequest,
};
use aip_connector_cal_diy::{
    CAL_DIY_WEBHOOK_VERSION, CalDiyConnector, CalDiyTenantAccountBinding, CalDiyWebhookDelivery,
    InMemoryCalDiyWebhookReplayStore, StaticCalDiyWebhookSecrets,
};
use aip_core::{
    Action, ActionResultStatus, ActionTransaction, ApprovalDecision, ApprovalDecisionKind,
    ApprovalId, ApprovalPolicy, ApprovalRequest, ApprovalRule, ApproverSelector, CapabilityId,
    CapabilityKind, ErrorCategory, EventStreamRequest, EvidenceArtifact, ExternalAccountRef,
    IdentityContext, Manifest, Principal, PrincipalId, PrincipalKind, ReceiptType, RiskLevel,
    SeparationOfDuties, TenantRef, TransactionMode,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ActionStream, ApprovalStatus, CancellationToken,
    Deadline, FileRuntimeStore, MessageContext, ProfileStateStore, QueuedActionRecord,
    QueuedActionStatus, RedactionPolicy, RetryPolicy, Runtime, TraceContext,
    TransactionCheckpointPublisher,
};
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, Response, StatusCode, Uri, header},
    routing::any,
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{net::TcpListener, task::JoinHandle};

const TENANT_ID: &str = "tenant-cal-qualified";
const ACCOUNT_ID: &str = "account-cal-qualified";
const CREDENTIAL_ID: &str = "credential:cal-qualified";
const PROVIDER_SECRET: &str = "cal-qualified-secret-never-disclose";
const WEBHOOK_SECRET: &str = "cal-qualified-webhook-secret";
const BOOKING_START: &str = "2050-01-01T10:00:00Z";

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

#[derive(Clone)]
struct ProviderState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    profile_status: Arc<AtomicU16>,
    booking_status: Arc<AtomicU16>,
    invalid_profile_output: Arc<AtomicBool>,
    booking_delay_ms: Arc<AtomicU64>,
}

impl Default for ProviderState {
    fn default() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            profile_status: Arc::new(AtomicU16::new(200)),
            booking_status: Arc::new(AtomicU16::new(200)),
            invalid_profile_output: Arc::new(AtomicBool::new(false)),
            booking_delay_ms: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ProviderState {
    fn request_count(&self, method: Method, path: &str) -> usize {
        self.requests
            .lock()
            .expect("provider request lock")
            .iter()
            .filter(|request| request.method == method && request.path == path)
            .count()
    }

    fn last_request(&self, path: &str) -> CapturedRequest {
        self.requests
            .lock()
            .expect("provider request lock")
            .iter()
            .rev()
            .find(|request| request.path == path)
            .cloned()
            .expect("captured provider request")
    }
}

struct ProviderHandle {
    base_url: String,
    task: JoinHandle<()>,
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_provider(state: ProviderState) -> ProviderHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("provider listener");
    let address = listener.local_addr().expect("provider address");
    let router = Router::new()
        .route("/{*path}", any(provider))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("deterministic Cal.diy provider");
    });
    ProviderHandle {
        base_url: format!("http://{address}"),
        task,
    }
}

async fn provider(
    State(state): State<ProviderState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let body = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body).unwrap_or_else(|_| json!({ "invalid": true }))
    };
    state
        .requests
        .lock()
        .expect("provider request lock")
        .push(CapturedRequest {
            method: method.clone(),
            path: uri.path().to_owned(),
            headers: capture_headers(&headers),
            body: body.clone(),
        });

    if method == Method::GET && uri.path() == "/v2/me" {
        let status = state.profile_status.load(Ordering::SeqCst);
        if status != 200 {
            return provider_response(
                status,
                json!({
                    "status": "error",
                    "error": {
                        "code": "PROVIDER_TEMPORARY",
                        "authorization": format!("Bearer {PROVIDER_SECRET}")
                    }
                }),
                status == 429,
            );
        }
        if state.invalid_profile_output.load(Ordering::SeqCst) {
            return provider_response(200, json!({ "data": { "id": 1 } }), false);
        }
        return provider_response(
            200,
            json!({ "status": "success", "data": { "id": 1, "username": "aip" } }),
            false,
        );
    }
    if method == Method::GET && uri.path() == "/v2/slots" {
        return provider_response(
            200,
            json!({
                "status": "success",
                "data": { "2050-01-01": [{ "start": BOOKING_START }] }
            }),
            false,
        );
    }
    if method == Method::GET && uri.path().starts_with("/v2/bookings/") {
        return provider_response(
            200,
            json!({
                "status": "success",
                "data": { "uid": "booking-qualified", "eventTypeId": 42 }
            }),
            false,
        );
    }
    if method == Method::POST && uri.path() == "/v2/bookings" {
        let delay = state.booking_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let status = state.booking_status.load(Ordering::SeqCst);
        if status != 200 {
            return provider_response(
                status,
                json!({
                    "status": "error",
                    "error": {
                        "code": "BOOKING_PROVIDER_FAILURE",
                        "token": PROVIDER_SECRET
                    }
                }),
                false,
            );
        }
        return provider_response(
            200,
            json!({
                "status": "success",
                "data": { "uid": "booking-qualified", "metadata": body.get("metadata") }
            }),
            false,
        );
    }
    if method == Method::POST && uri.path() == "/v2/bookings/booking-qualified/cancel" {
        return provider_response(
            200,
            json!({ "status": "success", "data": { "uid": "booking-qualified", "cancelled": true } }),
            false,
        );
    }
    provider_response(200, json!({ "status": "success", "data": body }), false)
}

fn provider_response(status: u16, body: Value, retry_after: bool) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).expect("provider status"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-request-id", format!("cal-request-{status}"));
    if retry_after {
        builder = builder.header(header::RETRY_AFTER, "0");
    }
    builder
        .body(Body::from(
            serde_json::to_vec(&body).expect("provider JSON"),
        ))
        .expect("provider response")
}

fn capture_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

#[derive(Clone)]
struct TestCredentialProvider {
    resolutions: Arc<AtomicUsize>,
}

impl Default for TestCredentialProvider {
    fn default() -> Self {
        Self {
            resolutions: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl std::fmt::Debug for TestCredentialProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestCredentialProvider([REDACTED])")
    }
}

#[async_trait]
impl CredentialProvider for TestCredentialProvider {
    async fn resolve(&self, handle: &CredentialHandle) -> Result<CredentialMaterial, AuthError> {
        if handle.id() != CREDENTIAL_ID {
            return Err(AuthError::Credential("unknown test handle".to_owned()));
        }
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(CredentialMaterial::new(PROVIDER_SECRET.as_bytes().to_vec()))
    }
}

fn connector(
    base_url: &str,
    state: ProfileStateStore,
    credentials: Arc<TestCredentialProvider>,
) -> CalDiyConnector {
    let webhook_secrets = StaticCalDiyWebhookSecrets::new([(
        "qualified".to_owned(),
        ConnectorSecret::new(WEBHOOK_SECRET),
    )])
    .expect("webhook secrets");
    CalDiyConnector::new(base_url, "bootstrap", "bootstrap-readiness-secret")
        .expect("Cal.diy connector")
        .with_profile_state_store(state)
        .with_tenant_credential_routing(
            [CalDiyTenantAccountBinding {
                tenant_id: TENANT_ID.to_owned(),
                account_id: ACCOUNT_ID.to_owned(),
            }],
            credentials,
        )
        .expect("tenant credential routing")
        .with_webhook_security(
            Arc::new(webhook_secrets),
            Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
        )
}

fn principal(id: &str, kind: PrincipalKind) -> Principal {
    Principal::new(PrincipalId::trusted(id), kind)
}

fn authenticated(principal: &Principal) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        principal: principal.clone(),
        scheme: AuthScheme::DidProof,
        issuer: "https://identity.cal-conformance.invalid".to_owned(),
        audience: Some("aip-runtime".to_owned()),
        scopes: BTreeSet::from(["*".to_owned()]),
        authenticated_at: OffsetDateTime::now_utc(),
        expires_at: None,
        credential_fingerprint: Some("sha256:cal-conformance-transport".to_owned()),
    }
}

fn tenant(tenant_id: &str) -> VerifiedTenant {
    VerifiedTenant {
        tenant: TenantRef {
            id: tenant_id.to_owned(),
            system: Some("cal-conformance".to_owned()),
        },
        membership_id: format!("membership:{tenant_id}"),
        roles: BTreeSet::from(["scheduler".to_owned()]),
        groups: BTreeSet::new(),
        verified_at: OffsetDateTime::now_utc(),
        expires_at: None,
    }
}

fn credential(tenant_id: &str) -> CredentialHandle {
    CredentialHandle::new(
        CREDENTIAL_ID,
        "cal_diy_deployment",
        BTreeSet::from(["*".to_owned()]),
        Some(tenant_id.to_owned()),
        None,
    )
    .expect("credential handle")
}

fn execution_context(
    actor: &Principal,
    tenant_id: &str,
    cancellation: CancellationToken,
) -> ActionExecutionContext {
    ActionExecutionContext {
        actor: authenticated(actor),
        tenant: Some(tenant(tenant_id)),
        credential: Some(credential(tenant_id)),
        deadline: Deadline::after(OffsetDateTime::now_utc(), 10_000),
        cancellation,
        idempotency: None,
        approval: None,
        transaction: None,
        transaction_checkpoint: TransactionCheckpointPublisher::default(),
        execution_checkpoints: aip_runtime::ExecutionCheckpointPublisher::default(),
        stream: ActionStream::default(),
        trace: TraceContext {
            trace_id: Some("trace-cal-conformance".to_owned()),
            span_id: Some("span-cal-conformance".to_owned()),
        },
        redaction: RedactionPolicy::default(),
    }
}

fn message_context(actor: &Principal, tenant_id: &str) -> MessageContext {
    MessageContext {
        actor: Some(actor.clone()),
        authenticated: Some(authenticated(actor)),
        tenant: Some(tenant(tenant_id)),
        credential: Some(credential(tenant_id)),
        resolved_identity: Some(IdentityContext {
            tenant: Some(TenantRef {
                id: tenant_id.to_owned(),
                system: Some("cal-conformance".to_owned()),
            }),
            external_account: Some(ExternalAccountRef {
                id: ACCOUNT_ID.to_owned(),
                system: "cal_diy".to_owned(),
            }),
            external_user: None,
            human_actor: (actor.kind == PrincipalKind::Human).then(|| actor.clone()),
            service_account: (actor.kind == PrincipalKind::Service).then(|| actor.clone()),
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        }),
        ..MessageContext::default()
    }
}

fn booking_action(key: &str) -> Action {
    let mut action = Action::new(
        CapabilityId::trusted("cap:cal_diy:booking.create"),
        json!({
            "start": BOOKING_START,
            "eventTypeId": 42,
            "attendee": {
                "name": "Ava",
                "email": "ava@example.test",
                "timeZone": "UTC"
            }
        }),
    );
    action.idempotency_key = Some(key.to_owned());
    action
}

fn profile_action() -> Action {
    Action::new(CapabilityId::trusted("cap:cal_diy:profile.get"), json!({}))
}

async fn admitted_runtime(
    connector: Arc<CalDiyConnector>,
    authority: Option<StaticApprovalAuthorityResolver>,
) -> Runtime {
    let manifest = connector.discover_manifest().expect("Cal.diy manifest");
    let handlers = manifest
        .capabilities
        .iter()
        .filter(|capability| capability.kind != CapabilityKind::Resource)
        .map(|capability| {
            (
                capability.id.clone(),
                Arc::new(FrozenConnectorHandler::new(
                    connector.clone(),
                    capability.clone(),
                )) as Arc<dyn ActionHandler>,
            )
        })
        .collect::<HashMap<_, _>>();
    let runtime = authority.map_or_else(Runtime::new, |authority| {
        Runtime::new().with_approval_authority(authority)
    });
    runtime
        .admit_manifest_with_handlers("cal-diy-frozen-conformance", manifest, handlers)
        .await
        .expect("atomic Cal.diy admission");
    runtime
}

fn evidence(
    scenario: ConnectorConformanceScenario,
    assertions: impl IntoIterator<Item = (&'static str, bool)>,
    artifact_ids: impl IntoIterator<Item = String>,
) -> ConnectorScenarioEvidence {
    ConnectorScenarioEvidence::executed(
        ConnectorEvidenceSource::DeterministicProviderDouble,
        assertions,
        artifact_ids
            .into_iter()
            .map(|id| format!("test://cal-diy-frozen/{}/{id}", scenario.id()))
            .collect(),
        "public connector, runtime, provider, and durable-state observations retained by the test report",
    )
}

struct CalDiyConformanceDriver {
    manifest: Manifest,
    connector: CalDiyConnector,
}

impl CalDiyConformanceDriver {
    fn new() -> Self {
        let connector = connector(
            "http://127.0.0.1:9",
            ProfileStateStore::default(),
            Arc::new(TestCredentialProvider::default()),
        );
        let manifest = connector.discover_manifest().expect("Cal.diy manifest");
        Self {
            manifest,
            connector,
        }
    }
}

#[async_trait]
impl ConnectorConformanceDriver for CalDiyConformanceDriver {
    fn connector_id(&self) -> &str {
        "cal-diy"
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
                    FrozenConnector::implementation_support(&self.connector, capability),
                )
            })
            .collect()
    }

    async fn exercise(
        &self,
        scenario: ConnectorConformanceScenario,
    ) -> Result<ConnectorScenarioEvidence, String> {
        match scenario {
            ConnectorConformanceScenario::IdentityAndCredentials => identity_scenario().await,
            ConnectorConformanceScenario::SchemaEnforcement => schema_scenario().await,
            ConnectorConformanceScenario::IdempotencyAndDuplicates => idempotency_scenario().await,
            ConnectorConformanceScenario::RetryAndExhaustion => retry_scenario().await,
            ConnectorConformanceScenario::CancellationRaces => {
                Ok(ConnectorScenarioEvidence::not_applicable(
                    "the pinned Cal.diy API and manifest publish no cancellable operation",
                ))
            }
            ConnectorConformanceScenario::StreamingAndBackpressure => {
                Ok(ConnectorScenarioEvidence::not_applicable(
                    "the pinned Cal.diy API and manifest publish no streaming operation",
                ))
            }
            ConnectorConformanceScenario::ErrorsAndUncertainOutcomes => errors_scenario().await,
            ConnectorConformanceScenario::ApprovalLifecycle => approval_scenario().await,
            ConnectorConformanceScenario::TransactionLifecycle => transaction_scenario().await,
            ConnectorConformanceScenario::AuditAndRedaction => audit_scenario().await,
            ConnectorConformanceScenario::WebhookSecurity => webhook_scenario().await,
            ConnectorConformanceScenario::RestartAndReconnect => restart_scenario().await,
        }
    }
}

async fn identity_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::IdentityAndCredentials;
    let state = ProviderState::default();
    let provider = start_provider(state.clone()).await;
    let credential_provider = Arc::new(TestCredentialProvider::default());
    let connector = connector(
        &provider.base_url,
        ProfileStateStore::default(),
        credential_provider.clone(),
    );
    let actor = principal("service:cal-identity-client", PrincipalKind::Service);
    let result = connector
        .invoke_typed(
            profile_action(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let request = state.last_request("/v2/me");
    let transport_actor_bound = result.status == ActionResultStatus::Completed
        && request.headers.get("x-aip-principal-id") == Some(&actor.id.to_string())
        && request.headers.get("x-aip-tenant-id") == Some(&TENANT_ID.to_owned())
        && request.headers.get("x-aip-external-account-id") == Some(&ACCOUNT_ID.to_owned())
        && request.headers.get("x-aip-trace-id") == Some(&"trace-cal-conformance".to_owned())
        && request.headers.get("authorization") == Some(&format!("Bearer {PROVIDER_SECRET}"));
    let rejected = connector
        .invoke_typed(
            profile_action(),
            execution_context(&actor, "tenant-unbound", CancellationToken::default()),
        )
        .await
        .expect_err("cross-tenant routing must fail");
    let tenant_isolated = rejected.code == "connector.cal_diy.credential_resolution"
        && state.request_count(Method::GET, "/v2/me") == 1;
    let diagnostics = format!(
        "{connector:?}{}",
        serde_json::to_string(&connector.discover_manifest().unwrap()).unwrap()
    );
    let credential_handle_opaque = credential_provider.resolutions.load(Ordering::SeqCst) == 1
        && !diagnostics.contains(PROVIDER_SECRET)
        && diagnostics.contains("CredentialProvider(..)");
    Ok(evidence(
        scenario,
        [
            ("transport_actor_bound", transport_actor_bound),
            ("tenant_isolated", tenant_isolated),
            ("credential_handle_opaque", credential_handle_opaque),
        ],
        [result.action_id.to_string()],
    ))
}

async fn schema_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::SchemaEnforcement;
    let state = ProviderState::default();
    let provider = start_provider(state.clone()).await;
    let connector = connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    );
    let actor = principal("service:cal-schema-client", PrincipalKind::Service);
    let invalid = Action::new(
        CapabilityId::trusted("cap:cal_diy:booking.create"),
        json!({ "start": BOOKING_START }),
    );
    let invalid_input_rejected = connector
        .commit_typed(
            invalid,
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .is_err()
        && state.request_count(Method::POST, "/v2/bookings") == 0;
    state.invalid_profile_output.store(true, Ordering::SeqCst);
    let output_error = connector
        .invoke_typed(
            profile_action(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("malformed provider output must fail");
    let invalid_output_rejected = output_error.code == "connector.cal_diy.invalid_provider_output";
    Ok(evidence(
        scenario,
        [
            ("invalid_input_rejected", invalid_input_rejected),
            ("invalid_output_rejected", invalid_output_rejected),
        ],
        [output_error.code],
    ))
}

async fn idempotency_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::IdempotencyAndDuplicates;
    let state = ProviderState::default();
    let provider = start_provider(state.clone()).await;
    let connector = connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    );
    let actor = principal("service:cal-idempotency-client", PrincipalKind::Service);
    let action = booking_action("booking-idempotency-key");
    let first = connector
        .commit_typed(
            action.clone(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let replay = connector
        .commit_typed(
            action.clone(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let duplicate_suppressed =
        first.output == replay.output && state.request_count(Method::POST, "/v2/bookings") == 1;
    let mut changed = booking_action("booking-idempotency-key");
    changed.input["start"] = json!("2050-01-02T10:00:00Z");
    let collision = connector
        .commit_typed(
            changed,
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("idempotency collision must fail");
    let collision_rejected = collision.code == "connector.cal_diy.idempotency_collision"
        && state.request_count(Method::POST, "/v2/bookings") == 1;
    let provider_request = state.last_request("/v2/bookings");
    let delivery_id_stable = provider_request
        .headers
        .get("idempotency-key")
        .is_some_and(|value| !value.is_empty())
        && provider_request
            .body
            .pointer("/metadata/aip_operation_id")
            .is_some();
    Ok(evidence(
        scenario,
        [
            ("duplicate_suppressed", duplicate_suppressed),
            ("collision_rejected", collision_rejected),
            ("delivery_id_stable", delivery_id_stable),
        ],
        [action.id.to_string()],
    ))
}

async fn retry_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::RetryAndExhaustion;
    let state = ProviderState::default();
    state.profile_status.store(429, Ordering::SeqCst);
    let provider = start_provider(state.clone()).await;
    let connector = Arc::new(connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    ));
    let runtime = admitted_runtime(connector, None).await;
    let actor = principal("service:cal-retry-client", PrincipalKind::Service);
    let now = OffsetDateTime::now_utc();
    let action = profile_action();
    let action_id = action.id.clone();
    runtime
        .action_queue
        .enqueue(QueuedActionRecord {
            action,
            principal: actor.clone(),
            context: message_context(&actor, TENANT_ID),
            status: QueuedActionStatus::Queued,
            result: None,
            cancellation_reason: None,
            attempts: 0,
            retry_policy: Some(RetryPolicy {
                max_attempts: 2,
                initial_backoff_ms: 10,
                max_backoff_ms: 10,
                backoff_multiplier: 1,
                requires_idempotency_key: false,
                max_elapsed_ms: Some(1_000),
                retryable_error_categories: vec![
                    ErrorCategory::Temporary,
                    ErrorCategory::Transport,
                ],
            }),
            first_attempted_at: None,
            last_attempted_at: None,
            next_attempt_at: None,
            last_error: None,
            dead_letter_reason: None,
            lease: None,
            idempotency_reservation: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|error| error.to_string())?;
    let first = runtime
        .run_queued_action_once("cal-retry-1", 5_000)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "first retry attempt was not leased".to_owned())?;
    let queued = runtime
        .action_queue
        .get(&action_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "retry record disappeared".to_owned())?;
    let retryable_error_preserved = first.error.as_ref().is_some_and(|error| {
        error.retryable == Some(true) && error.category == ErrorCategory::Temporary
    });
    let backoff_observed = queued.status == QueuedActionStatus::Queued
        && queued
            .next_attempt_at
            .zip(queued.last_attempted_at)
            .is_some_and(|(next, previous)| next >= previous);
    let wait_ms = queued
        .next_attempt_at
        .map(|next| {
            (next - OffsetDateTime::now_utc())
                .whole_milliseconds()
                .max(0) as u64
        })
        .unwrap_or_default();
    tokio::time::sleep(Duration::from_millis(wait_ms.saturating_add(2))).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !runtime.action_queue.dead_letters().await?.is_empty() {
                break Ok::<(), aip_runtime::RuntimeError>(());
            }
            if runtime
                .run_queued_action_by_id_once(&action_id, "cal-retry-2", 5_000)
                .await?
                .is_some()
            {
                break Ok::<(), aip_runtime::RuntimeError>(());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|_| "second retry attempt was not leased".to_owned())?
    .map_err(|error| error.to_string())?;
    let dead_letters = runtime
        .action_queue
        .dead_letters()
        .await
        .map_err(|error| error.to_string())?;
    let exhaustion_dead_lettered = dead_letters.len() == 1
        && dead_letters[0].record.action.id == action_id
        && dead_letters[0].attempts == 2
        && state.request_count(Method::GET, "/v2/me") == 2;
    Ok(evidence(
        scenario,
        [
            ("retryable_error_preserved", retryable_error_preserved),
            ("backoff_observed", backoff_observed),
            ("exhaustion_dead_lettered", exhaustion_dead_lettered),
        ],
        [action_id.to_string()],
    ))
}

async fn errors_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::ErrorsAndUncertainOutcomes;
    let state = ProviderState::default();
    let provider = start_provider(state.clone()).await;
    let connector = connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    );
    let actor = principal("service:cal-error-client", PrincipalKind::Service);
    state.profile_status.store(503, Ordering::SeqCst);
    let read_failure = connector
        .invoke_typed(
            profile_action(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("provider read failure");
    let protocol = read_failure.to_protocol_error();
    let protocol_fields_preserved = read_failure.remote_status == Some(503)
        && read_failure.retryable
        && !read_failure.uncertain_outcome
        && protocol.retryable == Some(true);
    state.profile_status.store(200, Ordering::SeqCst);
    state.booking_status.store(503, Ordering::SeqCst);
    let action = booking_action("uncertain-booking-key");
    let mutation_failure = connector
        .commit_typed(
            action.clone(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("uncertain mutation failure");
    let provider_operation = mutation_failure
        .provider_operation
        .as_ref()
        .map(|operation| operation.operation_id.clone())
        .ok_or_else(|| "uncertain failure omitted provider operation".to_owned())?;
    let reconciled = connector
        .reconcile_typed(
            ReconciliationRequest {
                transaction_id: aip_core::TransactionId::new(),
                provider_operation_id: provider_operation.clone(),
                cursor: None,
            },
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let uncertain_outcome_reconciled = mutation_failure.uncertain_outcome
        && !mutation_failure.retryable
        && !reconciled.terminal
        && reconciled.cursor.as_deref() == Some(provider_operation.as_str());
    let diagnostics = format!(
        "{read_failure:?}{mutation_failure:?}{}{}",
        serde_json::to_string(&read_failure).unwrap(),
        serde_json::to_string(&mutation_failure).unwrap()
    );
    let error_secrets_redacted = !diagnostics.contains(PROVIDER_SECRET);
    Ok(evidence(
        scenario,
        [
            ("protocol_fields_preserved", protocol_fields_preserved),
            ("uncertain_outcome_reconciled", uncertain_outcome_reconciled),
            ("error_secrets_redacted", error_secrets_redacted),
        ],
        [action.id.to_string(), provider_operation],
    ))
}

fn authority_membership(principal: &Principal) -> AuthorityMembership {
    AuthorityMembership {
        principal_id: principal.id.clone(),
        tenant_id: Some(TENANT_ID.to_owned()),
        roles: BTreeSet::from(["scheduling_approver".to_owned()]),
        groups: BTreeSet::new(),
        tenant_policies: BTreeSet::from(["cal-diy-qualified".to_owned()]),
        external_systems: BTreeSet::from(["cal_diy".to_owned()]),
        delegated_scopes: Vec::new(),
        revision: 1,
        expires_at: None,
        revoked: false,
    }
}

fn evidence_artifact(id: &str) -> EvidenceArtifact {
    EvidenceArtifact {
        id: id.to_owned(),
        kind: "conformance".to_owned(),
        uri: Some(format!("test://cal-diy-evidence/{id}")),
        hash: Some(format!("sha256:{id}")),
        redacted: true,
    }
}

fn approval_decision(
    request: &ApprovalRequest,
    approver: Principal,
    suffix: &str,
) -> ApprovalDecision {
    ApprovalDecision {
        approval_id: request.id.clone(),
        decision: ApprovalDecisionKind::Approved,
        approver,
        decided_at: OffsetDateTime::now_utc(),
        reason: Some("independent Cal.diy conformance approval".to_owned()),
        constraints: Vec::new(),
        evidence: vec![evidence_artifact(&format!("decision-{suffix}"))],
        decision_id: Some(format!("decision:{}:{suffix}", request.id)),
        policy_hash: request.policy_hash.clone(),
        authority_path: Vec::new(),
        target_decision_id: None,
    }
}

async fn approval_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::ApprovalLifecycle;
    let requester = principal("service:cal-approval-requester", PrincipalKind::Service);
    let left = principal("human:cal-approval-left", PrincipalKind::Human);
    let right = principal("human:cal-approval-right", PrincipalKind::Human);
    let intruder = principal("human:cal-approval-intruder", PrincipalKind::Human);
    let runtime = Runtime::new().with_approval_authority(StaticApprovalAuthorityResolver::new([
        authority_membership(&left),
        authority_membership(&right),
    ]));
    let policy = ApprovalPolicy {
        required: true,
        reason: Some("two-person scheduling mutation control".to_owned()),
        approver_selector: ApproverSelector::TenantPolicy,
        ttl_ms: Some(60_000),
        evidence_requirements: Vec::new(),
        delegated_authority: None,
        rule: Some(ApprovalRule::Quorum {
            required: 2,
            rules: vec![
                ApprovalRule::Principal {
                    id: left.id.clone(),
                },
                ApprovalRule::Principal {
                    id: right.id.clone(),
                },
            ],
            distinct_principals: true,
        }),
        minimum_distinct_principals: 2,
        separation_of_duties: SeparationOfDuties {
            requester_must_differ: true,
            operator_must_differ: false,
            allow_self_approval: false,
        },
        policy_version: Some("cal-diy-conformance/quorum-v1".to_owned()),
    };
    let request = ApprovalRequest {
        id: ApprovalId::new(),
        action_id: aip_core::ActionId::new(),
        capability_id: CapabilityId::trusted("cap:cal_diy:booking.create"),
        requester: requester.clone(),
        subject: requester.clone(),
        approver_selector: ApproverSelector::TenantPolicy,
        reason: "govern scheduling mutation".to_owned(),
        evidence: vec![evidence_artifact("approval-input")],
        expires_at: Some(OffsetDateTime::now_utc() + time::Duration::minutes(1)),
        policy_decision_id: Some("policy:cal-diy-conformance".to_owned()),
        identity: None,
        policy_snapshot: Some(policy),
        policy_hash: Some("sha256:cal-diy-conformance-policy".to_owned()),
        operator: Some(requester.clone()),
        risk: Some(RiskLevel::High),
        governed_value: None,
    };
    runtime
        .record_approval_request(request.clone(), message_context(&requester, TENANT_ID))
        .await
        .map_err(|error| error.to_string())?;
    let authority_verified = runtime
        .record_approval_decision(
            approval_decision(&request, intruder.clone(), "intruder"),
            message_context(&intruder, TENANT_ID),
        )
        .await
        .is_err();
    runtime
        .record_approval_decision(
            approval_decision(&request, left.clone(), "left"),
            message_context(&left, TENANT_ID),
        )
        .await
        .map_err(|error| error.to_string())?;
    let pending_after_one = runtime
        .approvals
        .get(&request.id)
        .await
        .map_err(|error| error.to_string())?
        .is_some_and(|record| record.status == ApprovalStatus::Pending);
    runtime
        .record_approval_decision(
            approval_decision(&request, right.clone(), "right"),
            message_context(&right, TENANT_ID),
        )
        .await
        .map_err(|error| error.to_string())?;
    let approval = runtime
        .approvals
        .get(&request.id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "approval record disappeared".to_owned())?;
    let quorum_enforced = pending_after_one
        && approval.status == ApprovalStatus::Approved
        && approval.decisions.len() == 2;
    let evidence_persisted = approval
        .decisions
        .iter()
        .all(|decision| !decision.decision.evidence.is_empty());

    let state = ProviderState::default();
    let provider = start_provider(state.clone()).await;
    let connector = Arc::new(connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    ));
    let approver = principal("human:cal-resume-approver", PrincipalKind::Human);
    let runtime = admitted_runtime(
        connector,
        Some(StaticApprovalAuthorityResolver::new([
            authority_membership(&approver),
        ])),
    )
    .await;
    let plan_id = "plan:cal-approval-resume";
    let mut plan = booking_action("approval-plan-key");
    plan.transaction = Some(ActionTransaction {
        mode: TransactionMode::Plan,
        transaction_id: None,
        plan_id: Some(plan_id.to_owned()),
        compensation_for: None,
    });
    runtime
        .process_action_with_context(plan, &requester, message_context(&requester, TENANT_ID))
        .await
        .map_err(|error| error.to_string())?;
    let mut commit = booking_action("approval-commit-key");
    commit.transaction = Some(ActionTransaction {
        mode: TransactionMode::Commit,
        transaction_id: None,
        plan_id: Some(plan_id.to_owned()),
        compensation_for: None,
    });
    let blocked = runtime
        .process_action_with_context(commit, &requester, message_context(&requester, TENANT_ID))
        .await
        .map_err(|error| error.to_string())?;
    if blocked.status != ActionResultStatus::PendingApproval {
        return Err(format!(
            "Cal.diy approval resume commit was not blocked: {blocked:?}"
        ));
    }
    let pending = runtime
        .approvals
        .pending()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|record| record.request.action_id == blocked.action_id)
        .ok_or_else(|| {
            format!(
                "runtime did not persist the blocked commit approval for {}",
                blocked.action_id
            )
        })?
        .request;
    let decision = approval_decision(&pending, approver.clone(), "resume");
    runtime
        .record_approval_decision(decision.clone(), message_context(&approver, TENANT_ID))
        .await
        .map_err(|error| error.to_string())?;
    let replay_rejected = runtime
        .record_approval_decision(decision, message_context(&approver, TENANT_ID))
        .await
        .is_err();
    let transaction = runtime
        .transactions
        .by_plan_id(plan_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "approved transaction disappeared".to_owned())?;
    let resume_once = blocked.status == ActionResultStatus::PendingApproval
        && transaction.status == aip_runtime::TransactionStatus::Committed
        && replay_rejected
        && state.request_count(Method::POST, "/v2/bookings") == 1;
    Ok(evidence(
        scenario,
        [
            ("authority_verified", authority_verified),
            ("quorum_enforced", quorum_enforced),
            ("evidence_persisted", evidence_persisted),
            ("resume_once", resume_once),
        ],
        [request.id.to_string(), pending.id.to_string()],
    ))
}

struct ApprovedBookingWorkflow {
    runtime: Runtime,
    plan_id: String,
    plan_action_id: aip_core::ActionId,
    commit_action_id: aip_core::ActionId,
}

async fn execute_approved_booking(
    connector: Arc<CalDiyConnector>,
    requester: &Principal,
    approver: &Principal,
    plan_id: &str,
) -> Result<ApprovedBookingWorkflow, String> {
    let runtime = admitted_runtime(
        connector,
        Some(StaticApprovalAuthorityResolver::new([
            authority_membership(approver),
        ])),
    )
    .await;
    let mut plan = booking_action(&format!("{plan_id}:plan"));
    let plan_action_id = plan.id.clone();
    plan.transaction = Some(ActionTransaction {
        mode: TransactionMode::Plan,
        transaction_id: None,
        plan_id: Some(plan_id.to_owned()),
        compensation_for: None,
    });
    let planned = runtime
        .process_action_with_context(plan, requester, message_context(requester, TENANT_ID))
        .await
        .map_err(|error| error.to_string())?;
    if planned.status != ActionResultStatus::Completed {
        return Err(format!(
            "Cal.diy transaction plan did not complete: {planned:?}"
        ));
    }
    let mut commit = booking_action(&format!("{plan_id}:commit"));
    let commit_action_id = commit.id.clone();
    commit.transaction = Some(ActionTransaction {
        mode: TransactionMode::Commit,
        transaction_id: None,
        plan_id: Some(plan_id.to_owned()),
        compensation_for: None,
    });
    let blocked = runtime
        .process_action_with_context(commit, requester, message_context(requester, TENANT_ID))
        .await
        .map_err(|error| error.to_string())?;
    if blocked.status != ActionResultStatus::PendingApproval {
        return Err(format!(
            "Cal.diy commit was not blocked for approval: {blocked:?}"
        ));
    }
    let approval = runtime
        .approvals
        .pending()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|record| record.request.action_id == commit_action_id)
        .ok_or_else(|| "Cal.diy commit approval was not persisted".to_owned())?
        .request;
    runtime
        .record_approval_decision(
            approval_decision(&approval, approver.clone(), "workflow"),
            message_context(approver, TENANT_ID),
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(ApprovedBookingWorkflow {
        runtime,
        plan_id: plan_id.to_owned(),
        plan_action_id,
        commit_action_id,
    })
}

async fn transaction_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::TransactionLifecycle;
    let state = ProviderState::default();
    let provider = start_provider(state.clone()).await;
    let primary_connector = Arc::new(connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    ));
    let requester = principal("service:cal-transaction-requester", PrincipalKind::Service);
    let approver = principal("human:cal-transaction-approver", PrincipalKind::Human);
    let workflow = execute_approved_booking(
        primary_connector.clone(),
        &requester,
        &approver,
        "plan:cal-transaction",
    )
    .await?;
    let transaction = workflow
        .runtime
        .transactions
        .by_plan_id(&workflow.plan_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "committed Cal.diy transaction disappeared".to_owned())?;
    let plan_before_commit = transaction.status == aip_runtime::TransactionStatus::Committed
        && state.request_count(Method::GET, "/v2/slots") == 1
        && state.request_count(Method::POST, "/v2/bookings") == 1;
    let provider_operation_checkpointed = transaction
        .provider_operation
        .as_ref()
        .is_some_and(|operation| operation.provider == "cal-diy");

    let uncertain_state = ProviderState::default();
    uncertain_state.booking_status.store(503, Ordering::SeqCst);
    let uncertain_provider = start_provider(uncertain_state.clone()).await;
    let uncertain_connector = connector(
        &uncertain_provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    );
    let uncertain_action = booking_action("transaction-uncertain-key");
    let failure = uncertain_connector
        .commit_typed(
            uncertain_action.clone(),
            execution_context(&requester, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("uncertain commit must fail");
    let operation_id = failure
        .provider_operation
        .as_ref()
        .map(|operation| operation.operation_id.clone())
        .ok_or_else(|| "uncertain commit omitted provider operation".to_owned())?;
    let replay = uncertain_connector
        .commit_typed(
            uncertain_action,
            execution_context(&requester, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("uncertain retry must be fenced");
    let reconciliation = uncertain_connector
        .reconcile_typed(
            ReconciliationRequest {
                transaction_id: aip_core::TransactionId::new(),
                provider_operation_id: operation_id.clone(),
                cursor: None,
            },
            execution_context(&requester, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let reconcile_before_retry = replay.code == "connector.cal_diy.outcome_unknown"
        && uncertain_state.request_count(Method::POST, "/v2/bookings") == 1
        && !reconciliation.terminal
        && reconciliation.cursor.as_deref() == Some(operation_id.as_str());

    let mut cancel_plan = Action::new(
        CapabilityId::trusted("cap:cal_diy:booking.cancel"),
        json!({ "booking_uid": "booking-qualified", "cancellationReason": "conformance" }),
    );
    cancel_plan.idempotency_key = Some("cancel-plan-key".to_owned());
    cancel_plan.transaction = Some(ActionTransaction {
        mode: TransactionMode::Plan,
        transaction_id: None,
        plan_id: Some("plan:cal-cancel".to_owned()),
        compensation_for: None,
    });
    workflow
        .runtime
        .process_action_with_context(
            cancel_plan,
            &requester,
            message_context(&requester, TENANT_ID),
        )
        .await
        .map_err(|error| error.to_string())?;
    let mut cancel_commit = Action::new(
        CapabilityId::trusted("cap:cal_diy:booking.cancel"),
        json!({ "booking_uid": "booking-qualified", "cancellationReason": "conformance" }),
    );
    cancel_commit.idempotency_key = Some("cancel-commit-key".to_owned());
    cancel_commit.transaction = Some(ActionTransaction {
        mode: TransactionMode::Commit,
        transaction_id: None,
        plan_id: Some("plan:cal-cancel".to_owned()),
        compensation_for: Some(workflow.commit_action_id.clone()),
    });
    let governed = workflow
        .runtime
        .process_action_with_context(
            cancel_commit,
            &requester,
            message_context(&requester, TENANT_ID),
        )
        .await
        .map_err(|error| error.to_string())?;
    let compensation_governed = governed.status == ActionResultStatus::PendingApproval
        && state.request_count(Method::POST, "/v2/bookings/booking-qualified/cancel") == 0;
    Ok(evidence(
        scenario,
        [
            ("plan_before_commit", plan_before_commit),
            (
                "provider_operation_checkpointed",
                provider_operation_checkpointed,
            ),
            ("reconcile_before_retry", reconcile_before_retry),
            ("compensation_governed", compensation_governed),
        ],
        [
            workflow.plan_action_id.to_string(),
            workflow.commit_action_id.to_string(),
            operation_id,
        ],
    ))
}

async fn audit_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::AuditAndRedaction;
    let state = ProviderState::default();
    let provider = start_provider(state).await;
    let connector = Arc::new(connector(
        &provider.base_url,
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    ));
    let requester = principal("service:cal-audit-requester", PrincipalKind::Service);
    let approver = principal("human:cal-audit-approver", PrincipalKind::Human);
    let workflow =
        execute_approved_booking(connector, &requester, &approver, "plan:cal-audit").await?;
    let transaction = workflow
        .runtime
        .transactions
        .by_plan_id(&workflow.plan_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "audit transaction disappeared".to_owned())?;
    let chain = workflow
        .runtime
        .lifecycle
        .receipt_chain(&format!("transaction:{}", transaction.transaction_id))
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "transaction receipt chain disappeared".to_owned())?;
    let receipts_emitted = chain
        .receipts
        .iter()
        .any(|receipt| receipt.receipt_type == ReceiptType::TransactionPlanned)
        && chain
            .receipts
            .iter()
            .any(|receipt| receipt.receipt_type == ReceiptType::TransactionCommitted)
        && chain.root_hash.is_some();
    let events = workflow
        .runtime
        .events
        .stream(&EventStreamRequest {
            cursor: None,
            limit: Some(500),
            kinds: Vec::new(),
        })
        .await
        .map_err(|error| error.to_string())?;
    let audit_correlated = events.events.iter().any(|event| {
        event.action_id.as_ref() == Some(&workflow.commit_action_id)
            || event.action_id.as_ref() == Some(&workflow.plan_action_id)
    });
    let serialized = format!(
        "{}{}",
        serde_json::to_string(&chain).map_err(|error| error.to_string())?,
        serde_json::to_string(&events).map_err(|error| error.to_string())?
    );
    let sensitive_fields_redacted = !serialized.contains("ava@example.test");
    let raw_secret_absent = !serialized.contains(PROVIDER_SECRET)
        && !serialized.contains("bootstrap-readiness-secret")
        && !serialized.contains(WEBHOOK_SECRET);
    Ok(evidence(
        scenario,
        [
            ("receipts_emitted", receipts_emitted),
            ("audit_correlated", audit_correlated),
            ("sensitive_fields_redacted", sensitive_fields_redacted),
            ("raw_secret_absent", raw_secret_absent),
        ],
        [transaction.transaction_id.to_string()],
    ))
}

fn webhook_signature(body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

async fn webhook_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::WebhookSecurity;
    let connector = connector(
        "http://127.0.0.1:9",
        ProfileStateStore::default(),
        Arc::new(TestCredentialProvider::default()),
    );
    let actor = principal("service:cal-webhook-ingress", PrincipalKind::Service);
    let now = OffsetDateTime::now_utc();
    let created_at = now
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| error.to_string())?;
    let raw_body = serde_json::to_string(&json!({
        "triggerEvent": "BOOKING_CREATED",
        "createdAt": created_at,
        "payload": { "uid": "booking-qualified" }
    }))
    .map_err(|error| error.to_string())?;
    let delivery = CalDiyWebhookDelivery {
        subscription_id: "qualified".to_owned(),
        signature: webhook_signature(&raw_body),
        webhook_version: Some(CAL_DIY_WEBHOOK_VERSION.to_owned()),
        raw_body: raw_body.clone(),
        received_at: now.unix_timestamp(),
    };
    let first = connector
        .ingest_typed(
            serde_json::to_value(&delivery).map_err(|error| error.to_string())?,
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let replay = connector
        .ingest_typed(
            serde_json::to_value(&delivery).map_err(|error| error.to_string())?,
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let signature_verified = first.len() == 1;
    let replay_rejected = first.len() == 1 && replay.len() == 1 && first[0].body == replay[0].body;
    let stale_created_at = (now - time::Duration::days(2))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| error.to_string())?;
    let stale_body = serde_json::to_string(&json!({
        "triggerEvent": "BOOKING_CREATED",
        "createdAt": stale_created_at,
        "payload": { "uid": "booking-stale" }
    }))
    .map_err(|error| error.to_string())?;
    let stale = CalDiyWebhookDelivery {
        subscription_id: "qualified".to_owned(),
        signature: webhook_signature(&stale_body),
        webhook_version: Some(CAL_DIY_WEBHOOK_VERSION.to_owned()),
        raw_body: stale_body,
        received_at: now.unix_timestamp(),
    };
    let skew_rejected = connector
        .ingest_typed(
            serde_json::to_value(stale).map_err(|error| error.to_string())?,
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .is_err();
    Ok(evidence(
        scenario,
        [
            ("signature_verified", signature_verified),
            ("skew_rejected", skew_rejected),
            ("replay_rejected", replay_rejected),
        ],
        [first[0].message_id.to_string()],
    ))
}

async fn restart_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::RestartAndReconnect;
    let root = std::env::temp_dir().join(format!(
        "aip-cal-restart-{}-{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let state = ProviderState::default();
    state.booking_status.store(503, Ordering::SeqCst);
    let provider = start_provider(state.clone()).await;
    let actor = principal("service:cal-restart-client", PrincipalKind::Service);
    let first_backend = Arc::new(
        FileRuntimeStore::open(&root)
            .await
            .map_err(|error| error.to_string())?,
    );
    let first_connector = connector(
        &provider.base_url,
        ProfileStateStore::new(first_backend),
        Arc::new(TestCredentialProvider::default()),
    );
    let action = booking_action("restart-uncertain-key");
    let failure = first_connector
        .commit_typed(
            action.clone(),
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("first process must persist uncertain state");
    let provider_operation = failure
        .provider_operation
        .as_ref()
        .map(|operation| operation.operation_id.clone())
        .ok_or_else(|| "restart failure omitted provider operation".to_owned())?;
    drop(first_connector);

    let second_backend = Arc::new(
        FileRuntimeStore::open(&root)
            .await
            .map_err(|error| error.to_string())?,
    );
    let second_connector = connector(
        &provider.base_url,
        ProfileStateStore::new(second_backend),
        Arc::new(TestCredentialProvider::default()),
    );
    let recovered = second_connector
        .reconcile_typed(
            ReconciliationRequest {
                transaction_id: aip_core::TransactionId::new(),
                provider_operation_id: provider_operation.clone(),
                cursor: None,
            },
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let state_recovered = !recovered.terminal;
    let replay = second_connector
        .commit_typed(
            action,
            execution_context(&actor, TENANT_ID, CancellationToken::default()),
        )
        .await
        .expect_err("restart replay must remain fenced");
    let duplicate_effect_prevented = replay.code == "connector.cal_diy.outcome_unknown"
        && state.request_count(Method::POST, "/v2/bookings") == 1;
    let reconnect_cursor_resumed = recovered.cursor.as_deref() == Some(provider_operation.as_str());

    let _ = tokio::fs::remove_dir_all(&root).await;
    Ok(evidence(
        scenario,
        [
            ("state_recovered", state_recovered),
            ("duplicate_effect_prevented", duplicate_effect_prevented),
            ("reconnect_cursor_resumed", reconnect_cursor_resumed),
        ],
        [provider_operation],
    ))
}

#[test]
fn cal_diy_connector_passes_complete_frozen_conformance() {
    std::thread::Builder::new()
        .name("cal-diy-frozen-conformance".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("conformance runtime");
            runtime.block_on(async {
                let report = run_connector_conformance(&CalDiyConformanceDriver::new()).await;
                assert!(
                    report.passed(),
                    "Cal.diy frozen conformance failed: {:#?}",
                    report.checks
                );
                assert_eq!(report.checks.len(), 13);
            });
        })
        .expect("Cal.diy conformance test thread")
        .join()
        .expect("Cal.diy conformance test thread must not panic");
}
