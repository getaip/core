//! Frozen RFC 0004 behavioral conformance for the Hermes Agent connector.
//!
//! Every required assertion is derived from an executed public connector or
//! runtime boundary against a deterministic HTTP/SSE provider double. The two
//! optional families are marked not applicable only because the Hermes
//! manifest publishes neither transactions nor inbound webhooks.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use aip_auth::{
    AuthScheme, AuthenticatedPrincipal, AuthorityMembership, CredentialHandle,
    StaticApprovalAuthorityResolver, VerifiedTenant,
};
use aip_conformance::{
    ConnectorConformanceDriver, ConnectorConformanceScenario, ConnectorEvidenceSource,
    ConnectorScenarioEvidence, run_connector_conformance,
};
use aip_connector::{CapabilityImplementationSupport, FrozenConnector, FrozenConnectorHandler};
use aip_connector_hermes_agent::{
    HermesAgentConnector, HermesAgentEndpoint, HermesDelegatedResultExpectation,
    HermesDelegatedResultResolver, HermesOperatorPolicy, HermesOperatorRunStatus,
};
use aip_core::{
    Action, ActionMode, ActionResult, ActionResultStatus, ApprovalDecision, ApprovalDecisionKind,
    ApprovalId, ApprovalPolicy, ApprovalRequest, ApprovalRule, ApproverSelector, CapabilityId,
    CapabilityKind, DelegationId, DelegationRequest, ErrorCategory, EventStreamRequest,
    EvidenceArtifact, Manifest, Principal, PrincipalId, PrincipalKind, ProtocolError, RiskLevel,
    SeparationOfDuties, StreamChunkKind, TenantRef,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ActionStream, ApprovalStatus, CancellationToken,
    Deadline, DelegationRouter, MessageContext, ProfileStateStore, QueuedActionRecord,
    QueuedActionStatus, RedactionPolicy, RetryPolicy, Runtime, RuntimeError, RuntimeResult,
    TraceContext, TransactionCheckpointPublisher,
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Response, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{net::TcpListener, task::JoinHandle};

const STATUS_RUNNING: u8 = 0;
const STATUS_WAITING: u8 = 1;
const STATUS_COMPLETED: u8 = 2;
const STATUS_CANCELLED: u8 = 3;
const TEST_SECRET: &str = "hermes-conformance-secret-do-not-disclose";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    CompletedJson,
    CompletedProse,
    Approval,
    Cancellable,
    ProgressThenDisconnect,
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: BTreeMap<String, String>,
}

#[derive(Clone)]
struct ProviderState {
    run_mode: RunMode,
    starts: Arc<AtomicUsize>,
    approvals: Arc<AtomicUsize>,
    stops: Arc<AtomicUsize>,
    models_attempts: Arc<AtomicUsize>,
    chat_requests: Arc<AtomicUsize>,
    status: Arc<AtomicU8>,
    start_delay_ms: u64,
    models_status: u16,
    chat_status: u16,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl ProviderState {
    fn new(run_mode: RunMode) -> Self {
        let status = match run_mode {
            RunMode::Approval => STATUS_WAITING,
            _ => STATUS_RUNNING,
        };
        Self {
            run_mode,
            starts: Arc::new(AtomicUsize::new(0)),
            approvals: Arc::new(AtomicUsize::new(0)),
            stops: Arc::new(AtomicUsize::new(0)),
            models_attempts: Arc::new(AtomicUsize::new(0)),
            chat_requests: Arc::new(AtomicUsize::new(0)),
            status: Arc::new(AtomicU8::new(status)),
            start_delay_ms: 0,
            models_status: 200,
            chat_status: 200,
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_start_delay(mut self, delay_ms: u64) -> Self {
        self.start_delay_ms = delay_ms;
        self
    }

    fn with_models_status(mut self, status: u16) -> Self {
        self.models_status = status;
        self
    }

    fn with_chat_status(mut self, status: u16) -> Self {
        self.chat_status = status;
        self
    }

    fn complete(&self) {
        self.status.store(STATUS_COMPLETED, Ordering::SeqCst);
    }

    fn first_request(&self) -> CapturedRequest {
        self.captured
            .lock()
            .expect("captured request lock")
            .first()
            .cloned()
            .expect("captured request")
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
    let app = Router::new()
        .route("/v1/runs", post(run_start))
        .route("/v1/runs/{run_id}", get(run_status))
        .route("/v1/runs/{run_id}/events", get(run_events))
        .route("/v1/runs/{run_id}/approval", post(run_approval))
        .route("/v1/runs/{run_id}/stop", post(run_stop))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("deterministic Hermes provider");
    });
    ProviderHandle {
        base_url: format!("http://{address}"),
        task,
    }
}

async fn run_start(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Json(_input): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state.starts.fetch_add(1, Ordering::SeqCst);
    state
        .captured
        .lock()
        .expect("captured request lock")
        .push(CapturedRequest {
            headers: capture_headers(&headers),
        });
    if state.start_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(state.start_delay_ms)).await;
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "run_id": "run_conformance",
            "status": "started"
        })),
    )
}

async fn run_status(
    State(state): State<ProviderState>,
    Path(_run_id): Path<String>,
) -> Json<Value> {
    let response = match state.status.load(Ordering::SeqCst) {
        STATUS_WAITING => json!({
            "object": "hermes.run",
            "run_id": "run_conformance",
            "status": "waiting_for_approval"
        }),
        STATUS_COMPLETED => json!({
            "object": "hermes.run",
            "run_id": "run_conformance",
            "status": "completed",
            "output": completed_output(state.run_mode)
        }),
        STATUS_CANCELLED => json!({
            "object": "hermes.run",
            "run_id": "run_conformance",
            "status": "cancelled"
        }),
        _ => json!({
            "object": "hermes.run",
            "run_id": "run_conformance",
            "status": "running"
        }),
    };
    Json(response)
}

async fn run_events(State(state): State<ProviderState>) -> Response<Body> {
    if state.models_status != 200 {
        state.models_attempts.fetch_add(1, Ordering::SeqCst);
        return json_status_response(
            state.models_status,
            json!({
                "error": "temporary run event failure",
                "authorization": format!("Bearer {TEST_SECRET}")
            }),
        );
    }
    match state.run_mode {
        RunMode::CompletedJson | RunMode::CompletedProse => {
            state.complete();
            sse_response(Body::from(format!(
                "data: {}\n\n",
                json!({
                    "event": "run.completed",
                    "run_id": "run_conformance",
                    "output": completed_output(state.run_mode)
                })
            )))
        }
        RunMode::Approval => sse_response(Body::from(format!(
            "data: {}\n\n",
            json!({
                "event": "approval.request",
                "run_id": "run_conformance",
                "command": "redacted command",
                "choices": ["once", "session", "always", "deny"]
            })
        ))),
        RunMode::Cancellable => {
            while state.status.load(Ordering::SeqCst) != STATUS_CANCELLED {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            sse_response(Body::from(format!(
                "data: {}\n\n",
                json!({ "event": "run.cancelled", "run_id": "run_conformance" })
            )))
        }
        RunMode::ProgressThenDisconnect => {
            let first = stream::once(async {
                Ok::<_, Infallible>(Bytes::from(format!(
                    "data: {}\n\n",
                    json!({
                        "event": "message.delta",
                        "run_id": "run_conformance",
                        "delta": "checkpoint"
                    })
                )))
            });
            let pending = stream::pending::<Result<Bytes, Infallible>>();
            sse_response(Body::from_stream(first.chain(pending)))
        }
    }
}

async fn run_approval(
    State(state): State<ProviderState>,
    Path(_run_id): Path<String>,
    Json(_input): Json<Value>,
) -> Json<Value> {
    state.approvals.fetch_add(1, Ordering::SeqCst);
    state.complete();
    Json(json!({
        "run_id": "run_conformance",
        "status": "approval_resolved"
    }))
}

async fn run_stop(State(state): State<ProviderState>, Path(_run_id): Path<String>) -> Json<Value> {
    state.stops.fetch_add(1, Ordering::SeqCst);
    state.status.store(STATUS_CANCELLED, Ordering::SeqCst);
    Json(json!({ "run_id": "run_conformance", "status": "stopping" }))
}

async fn models(State(state): State<ProviderState>) -> Response<Body> {
    state.models_attempts.fetch_add(1, Ordering::SeqCst);
    if state.models_status == 200 {
        return Json(json!({ "object": "list", "data": [] })).into_response();
    }
    json_status_response(
        state.models_status,
        json!({
            "error": "temporary model catalog failure",
            "authorization": format!("Bearer {TEST_SECRET}")
        }),
    )
}

async fn chat(State(state): State<ProviderState>) -> Response<Body> {
    state.chat_requests.fetch_add(1, Ordering::SeqCst);
    if state.chat_status != 200 {
        return json_status_response(
            state.chat_status,
            json!({
                "error": "uncertain chat mutation",
                "access_token": TEST_SECRET
            }),
        );
    }
    let frames = vec![
        "data: {\"choices\":[{\"delta\":{\"content\":\"alpha\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"beta\"}}]}\n\n",
        "data: [DONE]\n\n",
    ];
    let frames = stream::iter(frames.into_iter().enumerate()).then(|(index, frame)| async move {
        if index > 0 {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        Ok::<_, Infallible>(Bytes::from(frame))
    });
    sse_response(Body::from_stream(frames))
}

fn sse_response(body: Body) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(body)
        .expect("SSE response")
}

fn json_status_response(status: u16, body: Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::from_u16(status).expect("valid provider status"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("JSON response")
}

fn completed_output(mode: RunMode) -> String {
    match mode {
        RunMode::CompletedProse => "provider returned prose instead of JSON".to_owned(),
        _ => json!({
            "case": {
                "case_id": "case_conformance",
                "status": "open"
            }
        })
        .to_string(),
    }
}

fn capture_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
        })
        .collect()
}

fn endpoint(base_url: &str) -> HermesAgentEndpoint {
    HermesAgentEndpoint::new("mock", base_url, Some(TEST_SECRET.to_owned()))
        .expect("Hermes endpoint")
}

fn connector(base_url: &str, state: ProfileStateStore) -> HermesAgentConnector {
    HermesAgentConnector::new(vec![endpoint(base_url)])
        .expect("Hermes connector")
        .with_profile_state_store(state)
}

fn operator_policy() -> HermesOperatorPolicy {
    HermesOperatorPolicy {
        delegation_enabled: true,
        delegation_requires_approval: true,
        delegation_approval_exempt_capability_prefixes: vec!["cap:support:case.get".to_owned()],
        allowed_capability_prefixes: vec!["cap:support:".to_owned()],
        allowed_scope_prefixes: vec!["support.".to_owned()],
        poll_interval_ms: 10,
        start_claim_ttl_ms: 1_000,
        cancel_grace_ms: 1_000,
        ..HermesOperatorPolicy::default()
    }
}

fn governed_connector(base_url: &str, state: ProfileStateStore) -> HermesAgentConnector {
    connector(base_url, state)
        .with_operator_policy(operator_policy())
        .expect("operator policy")
        .with_delegated_result_resolver(TestDelegatedResultResolver::completed())
}

#[derive(Clone)]
struct TestDelegatedResultResolver {
    error_code: Option<&'static str>,
}

impl TestDelegatedResultResolver {
    const fn completed() -> Self {
        Self { error_code: None }
    }

    const fn missing_execution() -> Self {
        Self {
            error_code: Some("connector.hermes_agent.delegated_execution_not_observed"),
        }
    }
}

#[async_trait]
impl HermesDelegatedResultResolver for TestDelegatedResultResolver {
    async fn resolve(
        &self,
        expectation: &HermesDelegatedResultExpectation,
    ) -> RuntimeResult<ActionResult> {
        if let Some(code) = self.error_code {
            return Err(RuntimeError::Protocol(ProtocolError {
                code: code.to_owned(),
                message: "deterministic provider did not execute the delegated AIP action"
                    .to_owned(),
                category: ErrorCategory::Policy,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(json!({
                    "delegation_id": expectation.delegation_id,
                    "child_action_id": expectation.action.id
                }))),
                source: None,
            }));
        }
        Ok(ActionResult {
            action_id: expectation.action.id.clone(),
            status: ActionResultStatus::Completed,
            output: Some(json!({
                "case_id": expectation.action.input.get("case_id"),
                "status": "open"
            })),
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        })
    }
}

fn principal(id: &str, kind: PrincipalKind) -> Principal {
    Principal::new(PrincipalId::trusted(id), kind)
}

fn authenticated(principal: &Principal) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        principal: principal.clone(),
        scheme: AuthScheme::DidProof,
        issuer: "https://identity.conformance.invalid".to_owned(),
        audience: Some("aip-runtime".to_owned()),
        scopes: BTreeSet::from(["*".to_owned()]),
        authenticated_at: OffsetDateTime::now_utc(),
        expires_at: None,
        credential_fingerprint: Some("sha256:conformance-credential".to_owned()),
    }
}

fn tenant(tenant_id: &str) -> VerifiedTenant {
    VerifiedTenant {
        tenant: TenantRef {
            id: tenant_id.to_owned(),
            system: Some("hermes-conformance".to_owned()),
        },
        membership_id: format!("membership:{tenant_id}"),
        roles: BTreeSet::from(["operator".to_owned()]),
        groups: BTreeSet::new(),
        verified_at: OffsetDateTime::now_utc(),
        expires_at: None,
    }
}

fn message_context(actor: &Principal, tenant_id: Option<&str>) -> MessageContext {
    MessageContext {
        actor: Some(actor.clone()),
        authenticated: Some(authenticated(actor)),
        tenant: tenant_id.map(tenant),
        ..MessageContext::default()
    }
}

fn execution_context(
    actor: &Principal,
    tenant_id: Option<&str>,
    cancellation: CancellationToken,
) -> ActionExecutionContext {
    ActionExecutionContext {
        actor: authenticated(actor),
        tenant: tenant_id.map(tenant),
        credential: Some(
            CredentialHandle::new(
                "credential:hermes-conformance",
                "deployment-secret-manager",
                BTreeSet::from(["hermes:invoke".to_owned()]),
                tenant_id.map(ToOwned::to_owned),
                None,
            )
            .expect("opaque credential handle"),
        ),
        deadline: Deadline::after(OffsetDateTime::now_utc(), 10_000),
        cancellation,
        idempotency: None,
        approval: None,
        transaction: None,
        transaction_checkpoint: TransactionCheckpointPublisher::default(),
        execution_checkpoints: aip_runtime::ExecutionCheckpointPublisher::default(),
        stream: ActionStream::default(),
        trace: TraceContext {
            trace_id: Some("trace-hermes-conformance".to_owned()),
            span_id: Some("span-hermes-conformance".to_owned()),
        },
        redaction: RedactionPolicy::default(),
    }
}

fn operator_action(objective: &str) -> Action {
    let mut action = Action::new(
        CapabilityId::trusted("cap:hermes_agent:mock:operator"),
        json!({ "objective": objective }),
    );
    action.idempotency_key = Some(format!("operator:{}", action.id));
    action
}

async fn admitted_runtime(connector: Arc<HermesAgentConnector>) -> Runtime {
    let manifest = connector.discover_manifest().expect("Hermes manifest");
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
    let runtime = Runtime::new();
    runtime
        .admit_manifest_with_handlers("hermes-frozen-conformance", manifest, handlers)
        .await
        .expect("atomic Hermes admission");
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
            .map(|id| format!("test://hermes-frozen/{}/{id}", scenario.id()))
            .collect(),
        "public connector and runtime observations retained by the test report",
    )
}

struct HermesConformanceDriver {
    manifest: Manifest,
    connector: HermesAgentConnector,
}

impl HermesConformanceDriver {
    fn new() -> Self {
        let connector = connector("http://127.0.0.1:9", ProfileStateStore::default());
        let manifest = connector.discover_manifest().expect("Hermes manifest");
        Self {
            manifest,
            connector,
        }
    }
}

#[async_trait]
impl ConnectorConformanceDriver for HermesConformanceDriver {
    fn connector_id(&self) -> &str {
        "hermes-agent"
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
            ConnectorConformanceScenario::CancellationRaces => cancellation_scenario().await,
            ConnectorConformanceScenario::StreamingAndBackpressure => streaming_scenario().await,
            ConnectorConformanceScenario::ErrorsAndUncertainOutcomes => errors_scenario().await,
            ConnectorConformanceScenario::ApprovalLifecycle => approval_scenario().await,
            ConnectorConformanceScenario::TransactionLifecycle => {
                Ok(ConnectorScenarioEvidence::not_applicable(
                    "the Hermes manifest declares no transaction contract or compensation operation",
                ))
            }
            ConnectorConformanceScenario::AuditAndRedaction => audit_scenario().await,
            ConnectorConformanceScenario::WebhookSecurity => {
                Ok(ConnectorScenarioEvidence::not_applicable(
                    "the Hermes connector publishes no inbound webhook profile",
                ))
            }
            ConnectorConformanceScenario::RestartAndReconnect => restart_scenario().await,
        }
    }
}

async fn identity_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::IdentityAndCredentials;
    let state = ProviderState::new(RunMode::CompletedJson);
    let provider = start_provider(state.clone()).await;
    let endpoint = endpoint(&provider.base_url)
        .with_tenant_id("tenant-a")
        .map_err(|error| error.to_string())?;
    let connector = HermesAgentConnector::new(vec![endpoint]).map_err(|error| error.to_string())?;
    let actor = principal("agent:hermes-conformance-actor", PrincipalKind::Agent);
    let mut action = operator_action("prove trusted identity projection");
    action.memory_context = Some(json!({
        "_aip": {
            "correlation_id": "payload-controlled-correlation",
            "actor": { "id": "agent:forged" }
        }
    }));
    let result = connector
        .invoke_typed(
            action.clone(),
            execution_context(&actor, Some("tenant-a"), CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let request = state.first_request();
    let actor_bound = result.status == ActionResultStatus::Completed
        && request.headers.get("x-aip-principal-id") == Some(&actor.id.to_string())
        && request.headers.get("x-aip-tenant-id") == Some(&"tenant-a".to_owned())
        && request.headers.get("x-aip-correlation-id")
            == Some(&"trace-hermes-conformance".to_owned())
        && request.headers.get("authorization") == Some(&format!("Bearer {TEST_SECRET}"));

    let rejected = connector
        .invoke_typed(
            operator_action("cross tenant request"),
            execution_context(&actor, Some("tenant-b"), CancellationToken::default()),
        )
        .await
        .expect_err("cross-tenant endpoint use must fail");
    let tenant_isolated = rejected.code == "connector.hermes_agent.tenant_mismatch"
        && state.starts.load(Ordering::SeqCst) == 1;
    let manifest = serde_json::to_string(&connector.discover_manifest().unwrap()).unwrap();
    let diagnostics = format!("{connector:?}");
    let credential_opaque = !manifest.contains(TEST_SECRET)
        && !diagnostics.contains(TEST_SECRET)
        && diagnostics.contains("redacted");
    Ok(evidence(
        scenario,
        [
            ("transport_actor_bound", actor_bound),
            ("tenant_isolated", tenant_isolated),
            ("credential_handle_opaque", credential_opaque),
        ],
        [action.id.to_string()],
    ))
}

async fn schema_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::SchemaEnforcement;
    let state = ProviderState::new(RunMode::CompletedProse);
    let provider = start_provider(state.clone()).await;
    let connector = connector(&provider.base_url, ProfileStateStore::default())
        .with_operator_policy(operator_policy())
        .expect("operator policy")
        .with_delegated_result_resolver(TestDelegatedResultResolver::missing_execution());
    let actor = principal("agent:schema-requester", PrincipalKind::Agent);
    let invalid = Action::new(
        CapabilityId::trusted("cap:hermes_agent:mock:operator"),
        json!({}),
    );
    let invalid_input_rejected = connector
        .invoke_typed(
            invalid,
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .is_err()
        && state.starts.load(Ordering::SeqCst) == 0;

    let request = DelegationRequest {
        delegation_id: DelegationId::new(),
        parent_action_id: aip_core::ActionId::new(),
        child_action: Action::new(
            CapabilityId::trusted("cap:support:case.get"),
            json!({ "case_id": "case_conformance" }),
        ),
        requested_by: actor.clone(),
        delegate: connector
            .operator_principal("mock")
            .map_err(|error| error.to_string())?,
        scope: "support.case.read".to_owned(),
        callback: None,
        metadata: None,
    };
    let error = connector
        .route(&request, &message_context(&actor, None))
        .await
        .expect_err("model prose must not become a delegated AIP result");
    let invalid_output_rejected = matches!(
        error,
        RuntimeError::Protocol(ProtocolError { ref code, .. })
            if code == "connector.hermes_agent.delegated_execution_not_observed"
    );
    Ok(evidence(
        scenario,
        [
            ("invalid_input_rejected", invalid_input_rejected),
            ("invalid_output_rejected", invalid_output_rejected),
        ],
        [request.delegation_id.to_string()],
    ))
}

async fn idempotency_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::IdempotencyAndDuplicates;
    let state = ProviderState::new(RunMode::CompletedJson).with_start_delay(75);
    let provider = start_provider(state.clone()).await;
    let connector = connector(&provider.base_url, ProfileStateStore::default());
    let actor = principal("agent:idempotency-requester", PrincipalKind::Agent);
    let action = operator_action("execute exactly once");
    let (left, right) = tokio::join!(
        connector.invoke_typed(
            action.clone(),
            execution_context(&actor, None, CancellationToken::default())
        ),
        connector.invoke_typed(
            action.clone(),
            execution_context(&actor, None, CancellationToken::default())
        ),
    );
    let duplicate_suppressed = left
        .as_ref()
        .is_ok_and(|result| result.status == ActionResultStatus::Completed)
        && right
            .as_ref()
            .is_ok_and(|result| result.status == ActionResultStatus::Completed)
        && state.starts.load(Ordering::SeqCst) == 1;
    let mut changed = action.clone();
    changed.input = json!({ "objective": "different input" });
    let collision = connector
        .invoke_typed(
            changed,
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .expect_err("action-id collision must fail");
    let collision_rejected = collision.code == "connector.hermes_agent.operator_policy"
        && state.starts.load(Ordering::SeqCst) == 1;
    let binding = connector
        .operator_binding(&action.id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "operator binding was not persisted".to_owned())?;
    let delivery_id_stable =
        binding.action_id == action.id && binding.run_id.as_deref() == Some("run_conformance");
    Ok(evidence(
        scenario,
        [
            ("duplicate_suppressed", duplicate_suppressed),
            ("collision_rejected", collision_rejected),
            ("delivery_id_stable", delivery_id_stable),
        ],
        [action.id.to_string(), "run_conformance".to_owned()],
    ))
}

async fn retry_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::RetryAndExhaustion;
    let state = ProviderState::new(RunMode::CompletedJson).with_models_status(503);
    let provider = start_provider(state.clone()).await;
    let connector = Arc::new(connector(&provider.base_url, ProfileStateStore::default()));
    let runtime = admitted_runtime(connector).await;
    let actor = principal("agent:retry-requester", PrincipalKind::Agent);
    let now = OffsetDateTime::now_utc();
    let mut action = Action::new(
        CapabilityId::trusted("cap:hermes_agent:mock:run_events"),
        json!({ "run_id": "run_retry" }),
    );
    action.mode = Some(ActionMode::Async);
    let action_id = action.id.clone();
    runtime
        .action_queue
        .enqueue(QueuedActionRecord {
            action,
            principal: actor.clone(),
            context: message_context(&actor, None),
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
        .run_queued_action_once("hermes-retry-1", 5_000)
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
            .is_some_and(|(next, previous)| next > previous);
    let wait_ms = queued
        .next_attempt_at
        .map(|next| {
            (next - OffsetDateTime::now_utc())
                .whole_milliseconds()
                .max(0) as u64
        })
        .unwrap_or(0);
    tokio::time::sleep(Duration::from_millis(wait_ms.saturating_add(2))).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .run_queued_action_by_id_once(&action_id, "hermes-retry-2", 5_000)
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
        && state.models_attempts.load(Ordering::SeqCst) == 2;
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

async fn cancellation_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::CancellationRaces;
    let pre_state = ProviderState::new(RunMode::CompletedJson);
    let pre_provider = start_provider(pre_state.clone()).await;
    let pre_connector = connector(&pre_provider.base_url, ProfileStateStore::default());
    let actor = principal("agent:cancellation-requester", PrincipalKind::Agent);
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let before_dispatch = pre_connector
        .invoke_typed(
            Action::new(
                CapabilityId::trusted("cap:hermes_agent:mock:chat_stream"),
                json!({ "prompt": "never dispatched" }),
            ),
            execution_context(&actor, None, cancellation),
        )
        .await
        .expect_err("pre-cancelled invocation must fail");
    let before_dispatch_cancelled = before_dispatch.code == "connector.hermes_agent.cancelled"
        && pre_state.chat_requests.load(Ordering::SeqCst) == 0;

    let active_state = ProviderState::new(RunMode::Cancellable);
    let active_provider = start_provider(active_state.clone()).await;
    let active_connector = connector(&active_provider.base_url, ProfileStateStore::default());
    let active_action = operator_action("wait for cancellation");
    let active_action_for_task = active_action.clone();
    let active_connector_for_task = active_connector.clone();
    let active_actor = actor.clone();
    let task = tokio::spawn(async move {
        active_connector_for_task
            .invoke_typed(
                active_action_for_task,
                execution_context(&active_actor, None, CancellationToken::default()),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while active_connector
            .operator_binding(&active_action.id)
            .await
            .expect("active binding")
            .is_none_or(|binding| binding.run_id.is_none())
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "active Hermes run was not bound".to_owned())?;
    active_connector
        .cancel_typed(
            &active_action,
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let active_result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .map_err(|_| "active cancellation timed out".to_owned())?
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    let in_flight_cancelled = active_result.status == ActionResultStatus::Cancelled
        && active_state.stops.load(Ordering::SeqCst) == 1;

    let terminal_state = ProviderState::new(RunMode::CompletedJson);
    let terminal_provider = start_provider(terminal_state.clone()).await;
    let terminal_connector = connector(&terminal_provider.base_url, ProfileStateStore::default());
    let terminal_action = operator_action("complete before late cancellation");
    let terminal_result = terminal_connector
        .invoke_typed(
            terminal_action.clone(),
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    terminal_connector
        .cancel_typed(
            &terminal_action,
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let terminal_binding = terminal_connector
        .operator_binding(&terminal_action.id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "terminal binding disappeared".to_owned())?;
    let late_cancel_preserved_terminal = terminal_result.status == ActionResultStatus::Completed
        && terminal_binding.status == HermesOperatorRunStatus::Completed
        && terminal_state.stops.load(Ordering::SeqCst) == 0;
    Ok(evidence(
        scenario,
        [
            ("before_dispatch_cancelled", before_dispatch_cancelled),
            ("in_flight_cancelled", in_flight_cancelled),
            (
                "late_cancel_preserved_terminal",
                late_cancel_preserved_terminal,
            ),
        ],
        [active_action.id.to_string(), terminal_action.id.to_string()],
    ))
}

async fn streaming_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::StreamingAndBackpressure;
    let state = ProviderState::new(RunMode::CompletedJson);
    let provider = start_provider(state).await;
    let connector = Arc::new(connector(&provider.base_url, ProfileStateStore::default()));
    let runtime = admitted_runtime(connector).await;
    let actor = principal("agent:stream-requester", PrincipalKind::Agent);
    let action = Action::new(
        CapabilityId::trusted("cap:hermes_agent:mock:chat_stream"),
        json!({ "prompt": "stream ordered output" }),
    );
    let action_id = action.id.clone();
    let runtime_for_task = runtime.clone();
    let actor_for_task = actor.clone();
    let task = tokio::spawn(async move {
        runtime_for_task
            .process_action_with_context(
                action,
                &actor_for_task,
                message_context(&actor_for_task, None),
            )
            .await
    });
    let first_visible_while_running = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !runtime
                .lifecycle
                .stream_chunks(&action_id)
                .await
                .expect("stream chunks")
                .is_empty()
            {
                break !task.is_finished();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "first incremental chunk was not published".to_owned())?;
    let result = task
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    let chunks = runtime
        .lifecycle
        .stream_chunks(&action_id)
        .await
        .map_err(|error| error.to_string())?;
    let ordered_chunks = first_visible_while_running
        && result.status == ActionResultStatus::Completed
        && chunks
            .iter()
            .enumerate()
            .all(|(index, chunk)| chunk.sequence == index as u64);
    let terminal_chunk_unique = chunks
        .iter()
        .filter(|chunk| chunk.kind == StreamChunkKind::Done)
        .count()
        == 1;

    let bounded_action = Action::new(
        CapabilityId::trusted("cap:hermes_agent:mock:chat_stream"),
        json!({ "prompt": "enforce event bound", "max_events": 1 }),
    );
    let bounded_id = bounded_action.id.clone();
    let bounded_result = runtime
        .process_action_with_context(bounded_action, &actor, message_context(&actor, None))
        .await
        .map_err(|error| error.to_string())?;
    let bounded_chunks = runtime
        .lifecycle
        .stream_chunks(&bounded_id)
        .await
        .map_err(|error| error.to_string())?;
    let bounded_backpressure = bounded_result.status == ActionResultStatus::Failed
        && bounded_result
            .error
            .as_ref()
            .map(|error| error.code.as_str())
            == Some("connector.hermes_agent.stream_truncated")
        && bounded_chunks.len() == 1;
    Ok(evidence(
        scenario,
        [
            ("ordered_chunks", ordered_chunks),
            ("bounded_backpressure", bounded_backpressure),
            ("terminal_chunk_unique", terminal_chunk_unique),
        ],
        [action_id.to_string(), bounded_id.to_string()],
    ))
}

async fn errors_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::ErrorsAndUncertainOutcomes;
    let state = ProviderState::new(RunMode::CompletedJson)
        .with_models_status(503)
        .with_chat_status(503);
    let provider = start_provider(state).await;
    let connector = connector(&provider.base_url, ProfileStateStore::default());
    let actor = principal("agent:error-requester", PrincipalKind::Agent);
    let read_failure = connector
        .invoke_typed(
            Action::new(
                CapabilityId::trusted("cap:hermes_agent:mock:models"),
                json!({}),
            ),
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .expect_err("models failure");
    let protocol = read_failure.to_protocol_error();
    let protocol_fields_preserved = read_failure.remote_status == Some(503)
        && read_failure.retryable
        && !read_failure.uncertain_outcome
        && protocol.retryable == Some(true)
        && protocol
            .details
            .as_deref()
            .and_then(|details| details.get("remote_status"))
            .and_then(Value::as_u64)
            == Some(503);
    let mutation_failure = connector
        .invoke_typed(
            Action::new(
                CapabilityId::trusted("cap:hermes_agent:mock:chat"),
                json!({ "prompt": "may have mutated provider state" }),
            ),
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .expect_err("chat failure");
    let uncertain_outcome_reconciled = mutation_failure.uncertain_outcome
        && !mutation_failure.retryable
        && mutation_failure.remote_status == Some(503);
    let serialized = format!(
        "{}{}",
        serde_json::to_string(&read_failure).unwrap(),
        serde_json::to_string(&mutation_failure).unwrap()
    );
    let error_secrets_redacted = !serialized.contains(TEST_SECRET)
        && !format!("{read_failure:?}{mutation_failure:?}").contains(TEST_SECRET);
    Ok(evidence(
        scenario,
        [
            ("protocol_fields_preserved", protocol_fields_preserved),
            ("uncertain_outcome_reconciled", uncertain_outcome_reconciled),
            ("error_secrets_redacted", error_secrets_redacted),
        ],
        ["read-503".to_owned(), "mutation-503".to_owned()],
    ))
}

async fn approval_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::ApprovalLifecycle;
    let requester = principal("agent:approval-requester", PrincipalKind::Agent);
    let left = principal("human:approval-left", PrincipalKind::Human);
    let right = principal("human:approval-right", PrincipalKind::Human);
    let intruder = principal("human:approval-intruder", PrincipalKind::Human);
    let memberships = [&left, &right].into_iter().map(authority_membership);
    let runtime =
        Runtime::new().with_approval_authority(StaticApprovalAuthorityResolver::new(memberships));
    let policy = ApprovalPolicy {
        required: true,
        reason: Some("two-person Hermes operator control".to_owned()),
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
            operator_must_differ: true,
            allow_self_approval: false,
        },
        policy_version: Some("hermes-conformance/quorum-v1".to_owned()),
    };
    let request = ApprovalRequest {
        id: ApprovalId::new(),
        action_id: aip_core::ActionId::new(),
        capability_id: CapabilityId::trusted("cap:hermes_agent:mock:operator"),
        requester: requester.clone(),
        subject: requester.clone(),
        approver_selector: ApproverSelector::TenantPolicy,
        reason: "govern Hermes operator execution".to_owned(),
        evidence: vec![evidence_artifact("request-input")],
        expires_at: Some(OffsetDateTime::now_utc() + time::Duration::minutes(1)),
        policy_decision_id: Some("policy:hermes-conformance".to_owned()),
        identity: None,
        policy_snapshot: Some(policy),
        policy_hash: Some("sha256:hermes-conformance-policy".to_owned()),
        operator: Some(requester.clone()),
        risk: Some(RiskLevel::High),
        governed_value: None,
    };
    runtime
        .record_approval_request(request.clone(), message_context(&requester, None))
        .await
        .map_err(|error| error.to_string())?;
    let authority_verified = runtime
        .record_approval_decision(
            approval_decision(&request, intruder, "intruder"),
            message_context(
                &principal("human:approval-intruder", PrincipalKind::Human),
                None,
            ),
        )
        .await
        .is_err();
    runtime
        .record_approval_decision(
            approval_decision(&request, left.clone(), "left"),
            message_context(&left, None),
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
            message_context(&right, None),
        )
        .await
        .map_err(|error| error.to_string())?;
    let approval_record = runtime
        .approvals
        .get(&request.id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "approval record disappeared".to_owned())?;
    let quorum_enforced = pending_after_one
        && approval_record.status == ApprovalStatus::Approved
        && approval_record.decisions.len() == 2;
    let evidence_persisted = approval_record
        .decisions
        .iter()
        .all(|decision| !decision.decision.evidence.is_empty());

    let state = ProviderState::new(RunMode::Approval);
    let provider = start_provider(state.clone()).await;
    let connector = connector(&provider.base_url, ProfileStateStore::default());
    let source = operator_action("provider requires approval");
    let pending = connector
        .invoke_typed(
            source.clone(),
            execution_context(&requester, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let mut resume = Action::new(
        CapabilityId::trusted("cap:hermes_agent:mock:operator"),
        json!({
            "resume": {
                "source_action_id": source.id,
                "choice": "once",
                "resolve_all": false
            }
        }),
    );
    resume.idempotency_key = Some(format!("resume:{}", resume.id));
    let first = connector
        .invoke_typed(
            resume.clone(),
            execution_context(&requester, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let replay = connector
        .invoke_typed(
            resume.clone(),
            execution_context(&requester, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let resume_once = pending.status == ActionResultStatus::RequiresHuman
        && first.status == ActionResultStatus::Completed
        && replay.status == ActionResultStatus::Completed
        && state.approvals.load(Ordering::SeqCst) == 1;
    Ok(evidence(
        scenario,
        [
            ("authority_verified", authority_verified),
            ("quorum_enforced", quorum_enforced),
            ("evidence_persisted", evidence_persisted),
            ("resume_once", resume_once),
        ],
        [
            request.id.to_string(),
            source.id.to_string(),
            resume.id.to_string(),
        ],
    ))
}

fn authority_membership(principal: &Principal) -> AuthorityMembership {
    AuthorityMembership {
        principal_id: principal.id.clone(),
        tenant_id: None,
        roles: BTreeSet::new(),
        groups: BTreeSet::new(),
        tenant_policies: BTreeSet::from(["hermes-conformance".to_owned()]),
        external_systems: BTreeSet::new(),
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
        uri: Some(format!("test://evidence/{id}")),
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
        reason: Some("independent conformance approval".to_owned()),
        constraints: Vec::new(),
        evidence: vec![evidence_artifact(&format!("decision-{suffix}"))],
        decision_id: Some(format!("decision:{}:{suffix}", request.id)),
        policy_hash: request.policy_hash.clone(),
        authority_path: Vec::new(),
        target_decision_id: None,
    }
}

async fn audit_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::AuditAndRedaction;
    let state = ProviderState::new(RunMode::CompletedJson);
    let provider = start_provider(state).await;
    let connector = governed_connector(&provider.base_url, ProfileStateStore::default());
    let runtime = Runtime::new().with_delegation_router(connector.clone());
    let requester = principal("agent:audit-requester", PrincipalKind::Agent);
    let request = DelegationRequest {
        delegation_id: DelegationId::new(),
        parent_action_id: aip_core::ActionId::new(),
        child_action: Action::new(
            CapabilityId::trusted("cap:support:case.get"),
            json!({
                "case_id": "case_conformance",
                "authorization": format!("Bearer {TEST_SECRET}")
            }),
        ),
        requested_by: requester.clone(),
        delegate: connector
            .operator_principal("mock")
            .map_err(|error| error.to_string())?,
        scope: "support.case.read".to_owned(),
        callback: None,
        metadata: None,
    };
    let result = runtime
        .process_delegation_request(
            request.clone(),
            &requester,
            message_context(&requester, None),
        )
        .await
        .map_err(|error| error.to_string())?;
    let receipt_chain = result
        .receipt_chain
        .clone()
        .ok_or_else(|| "routed delegation omitted receipt chain".to_owned())?;
    let receipt_chain_id = receipt_chain.chain_id.clone();
    let receipts_emitted = !receipt_chain.receipts.is_empty()
        && runtime
            .lifecycle
            .receipt_chain(&receipt_chain.chain_id)
            .await
            .map_err(|error| error.to_string())?
            .is_some();
    let events = runtime
        .events
        .stream(&EventStreamRequest {
            cursor: None,
            limit: Some(100),
            kinds: vec![
                "aip.delegation.requested".to_owned(),
                "aip.delegation.completed".to_owned(),
            ],
        })
        .await
        .map_err(|error| error.to_string())?;
    let audit_correlated = events.events.len() == 2
        && events.events.iter().all(|event| {
            event
                .data
                .as_ref()
                .and_then(|data| data.get("delegation_id"))
                .and_then(Value::as_str)
                == Some(request.delegation_id.as_str())
        });
    let retained = serde_json::to_string(&(events, receipt_chain, result)).unwrap();
    let sensitive_fields_redacted =
        !retained.contains(TEST_SECRET) && !retained.contains("authorization");
    let raw_secret_absent = !retained.contains("Bearer ");
    Ok(evidence(
        scenario,
        [
            ("receipts_emitted", receipts_emitted),
            ("audit_correlated", audit_correlated),
            ("sensitive_fields_redacted", sensitive_fields_redacted),
            ("raw_secret_absent", raw_secret_absent),
        ],
        [request.delegation_id.to_string(), receipt_chain_id],
    ))
}

async fn restart_scenario() -> Result<ConnectorScenarioEvidence, String> {
    let scenario = ConnectorConformanceScenario::RestartAndReconnect;
    let unknown_state = ProviderState::new(RunMode::CompletedJson).with_start_delay(500);
    let unknown_provider = start_provider(unknown_state.clone()).await;
    let unknown_store = ProfileStateStore::default();
    let first = connector(&unknown_provider.base_url, unknown_store.clone());
    let actor = principal("agent:restart-requester", PrincipalKind::Agent);
    let unknown_action = operator_action("crash before run id persistence");
    let first_action = unknown_action.clone();
    let first_actor = actor.clone();
    let task = tokio::spawn(async move {
        first
            .invoke_typed(
                first_action,
                execution_context(&first_actor, None, CancellationToken::default()),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while unknown_state.starts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "unknown-outcome start did not reach provider".to_owned())?;
    task.abort();
    let recovered = connector(&unknown_provider.base_url, unknown_store);
    let recovered_error = tokio::time::timeout(
        Duration::from_secs(2),
        recovered.invoke_typed(
            unknown_action.clone(),
            execution_context(&actor, None, CancellationToken::default()),
        ),
    )
    .await
    .map_err(|_| "unbound start recovery did not fail closed".to_owned())?
    .expect_err("unbound start must be outcome unknown");
    let unknown_binding = recovered
        .operator_binding(&unknown_action.id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "unknown binding disappeared".to_owned())?;
    let duplicate_effect_prevented = unknown_state.starts.load(Ordering::SeqCst) == 1
        && recovered_error.uncertain_outcome
        && unknown_binding.status == HermesOperatorRunStatus::OutcomeUnknown;

    let reconnect_state = ProviderState::new(RunMode::ProgressThenDisconnect);
    let reconnect_provider = start_provider(reconnect_state.clone()).await;
    let reconnect_store = ProfileStateStore::default();
    let before_restart = connector(&reconnect_provider.base_url, reconnect_store.clone());
    let reconnect_action = operator_action("resume from durable provider binding");
    let reconnect_action_for_task = reconnect_action.clone();
    let reconnect_actor = actor.clone();
    let reconnect_task = tokio::spawn(async move {
        before_restart
            .invoke_typed(
                reconnect_action_for_task,
                execution_context(&reconnect_actor, None, CancellationToken::default()),
            )
            .await
    });
    let pre_restart_sequence = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let observer = connector(&reconnect_provider.base_url, reconnect_store.clone());
            if let Some(binding) = observer
                .operator_binding(&reconnect_action.id)
                .await
                .expect("reconnect binding")
                && binding.run_id.is_some()
                && binding.next_sequence > 0
            {
                break binding.next_sequence;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "progress checkpoint was not persisted".to_owned())?;
    reconnect_task.abort();
    reconnect_state.complete();
    let after_restart = connector(&reconnect_provider.base_url, reconnect_store);
    let resumed = after_restart
        .invoke_typed(
            reconnect_action.clone(),
            execution_context(&actor, None, CancellationToken::default()),
        )
        .await
        .map_err(|error| error.to_string())?;
    let final_binding = after_restart
        .operator_binding(&reconnect_action.id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "reconnected binding disappeared".to_owned())?;
    let state_recovered = resumed.status == ActionResultStatus::Completed
        && final_binding.status == HermesOperatorRunStatus::Completed;
    let reconnect_cursor_resumed = final_binding.next_sequence == pre_restart_sequence
        && pre_restart_sequence == 1
        && reconnect_state.starts.load(Ordering::SeqCst) == 1;
    Ok(evidence(
        scenario,
        [
            ("state_recovered", state_recovered),
            ("duplicate_effect_prevented", duplicate_effect_prevented),
            ("reconnect_cursor_resumed", reconnect_cursor_resumed),
        ],
        [
            unknown_action.id.to_string(),
            reconnect_action.id.to_string(),
        ],
    ))
}

#[test]
fn hermes_connector_passes_the_frozen_behavioral_conformance_kit() {
    std::thread::Builder::new()
        .name("hermes-frozen-conformance".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("conformance runtime");
            runtime.block_on(async {
                let report = run_connector_conformance(&HermesConformanceDriver::new()).await;
                assert!(report.passed(), "{report:#?}");
                assert_eq!(report.checks.len(), 13);
            });
        })
        .expect("conformance thread")
        .join()
        .expect("conformance thread result");
}
