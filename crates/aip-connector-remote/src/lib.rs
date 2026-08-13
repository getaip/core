//! Product-neutral runtime handler for connector hosts reached over native AIP.
//!
//! The handler persists a deterministic route before dispatch and reuses that
//! assignment for retries and cancellation. Concrete HTTP or NATS transport is
//! deployment-owned and cannot influence tenant or instance selection.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_connector_registry::{
    ActionTargetResolver, CatalogRevision, ConnectorInstanceId, ConnectorInstanceStatus,
    ConnectorRegistryReader, ConnectorReplicaId, ConnectorReplicaStatus, ConnectorVersionId,
    ConnectorVersionStatus, RegistryError, RouteAssignment, RouteResolutionRequest,
    RouteSettlement, RouteTopologyPreference, validate_artifact_attestation,
};
use aip_core::{
    Action, ActionId, ActionMode, ActionResult, Callback, Cancel, CancelTarget, CapabilityId,
    CorrelationId, Envelope, ErrorBody, ErrorCategory, Event, EventStream, IdentityContext,
    MessageBody, MessageReference, Principal, ProfileId, ProtocolError, StreamChunk, TenantRef,
};
use aip_discovery::CapabilityImplementationSupport;
use aip_gateway::{
    CallbackSigner, DelegationPeerSecurity, GatewayCallbackPolicy, NATIVE_HTTP_PROFILE,
    NativeAipHttpClient, sign_native_envelope, verify_native_envelope_signature,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, EventLog, MessageContext, Runtime, RuntimeError,
    RuntimeResult, VerifiedApprovalSet, runtime_error_to_protocol,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use tracing::warn;
use url::Url;

/// Hard local bounds and tenant weights for remote connector dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteAdmissionLimits {
    /// Maximum remote actions executing through one daemon.
    pub max_in_flight: usize,
    /// Maximum remote actions executing for one verified tenant.
    pub max_in_flight_per_tenant: usize,
    /// Maximum actions waiting for a dispatch permit.
    pub max_queued: usize,
    /// Maximum actions waiting for one tenant.
    pub max_queued_per_tenant: usize,
    /// Maximum canonical action bytes retained by all waiting callers.
    pub max_queue_bytes: usize,
    /// Maximum canonical size of one remote action.
    pub max_request_bytes: usize,
    /// Maximum time an action may wait for local admission.
    pub max_queue_age: Duration,
    /// Optional positive scheduling weights keyed by verified tenant id.
    pub tenant_weights: BTreeMap<String, u32>,
}

impl Default for RemoteAdmissionLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 1_024,
            max_in_flight_per_tenant: 128,
            max_queued: 4_096,
            max_queued_per_tenant: 512,
            max_queue_bytes: 64 * 1024 * 1024,
            max_request_bytes: 4 * 1024 * 1024,
            max_queue_age: Duration::from_secs(30),
            tenant_weights: BTreeMap::new(),
        }
    }
}

impl RemoteAdmissionLimits {
    /// Validates all hard bounds before the scheduler is published.
    pub fn validate(&self) -> Result<(), FairAdmissionError> {
        if self.max_in_flight == 0
            || self.max_in_flight_per_tenant == 0
            || self.max_queued == 0
            || self.max_queued_per_tenant == 0
            || self.max_queue_bytes == 0
            || self.max_request_bytes == 0
            || self.max_queue_age.is_zero()
        {
            return Err(FairAdmissionError::InvalidLimits);
        }
        if self.max_in_flight_per_tenant > self.max_in_flight
            || self.max_queued_per_tenant > self.max_queued
            || self.tenant_weights.values().any(|weight| *weight == 0)
        {
            return Err(FairAdmissionError::InvalidLimits);
        }
        Ok(())
    }
}

/// Fixed-size scheduler telemetry safe for bounded metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FairAdmissionSnapshot {
    /// Actions currently holding dispatch permits.
    pub active: usize,
    /// Actions waiting across all tenants.
    pub queued: usize,
    /// Canonical action bytes represented by waiting callers.
    pub queued_bytes: usize,
    /// Tenants with active work.
    pub active_tenants: usize,
    /// Tenants with queued work.
    pub queued_tenants: usize,
}

/// Local scheduler rejection with stable overload semantics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FairAdmissionError {
    /// Scheduler limits are internally inconsistent.
    #[error("remote admission limits are invalid")]
    InvalidLimits,
    /// One action exceeds the hard request bound.
    #[error("remote action exceeds the configured request-byte limit")]
    RequestTooLarge,
    /// The global waiting-action bound is exhausted.
    #[error("remote action queue is full")]
    QueueFull,
    /// One tenant exhausted its waiting-action bound.
    #[error("remote tenant action queue is full")]
    TenantQueueFull,
    /// The global waiting-byte bound is exhausted.
    #[error("remote action queue byte budget is exhausted")]
    QueueBytesExhausted,
    /// The action exceeded its maximum queue residence time.
    #[error("remote action exceeded its maximum queue age")]
    QueueExpired,
    /// The scheduler stopped before returning a decision.
    #[error("remote admission scheduler stopped")]
    SchedulerStopped,
}

/// Weighted fair, hard-bounded scheduler shared by all remote capabilities.
#[derive(Clone)]
pub struct FairAdmissionScheduler {
    inner: Arc<FairAdmissionInner>,
}

struct FairAdmissionInner {
    limits: RemoteAdmissionLimits,
    state: Mutex<FairAdmissionState>,
}

#[derive(Default)]
struct FairAdmissionState {
    next_request_id: u64,
    active: usize,
    active_by_tenant: HashMap<String, usize>,
    queued: usize,
    queued_bytes: usize,
    tenant_queues: BTreeMap<String, TenantAdmissionQueue>,
    rotation: VecDeque<String>,
}

#[derive(Default)]
struct TenantAdmissionQueue {
    credit: u32,
    requests: VecDeque<QueuedAdmission>,
}

struct QueuedAdmission {
    id: u64,
    bytes: usize,
    queued_at: Instant,
    response: oneshot::Sender<Result<FairAdmissionPermit, FairAdmissionError>>,
}

/// RAII dispatch permit; cancellation releases capacity automatically.
pub struct FairAdmissionPermit {
    inner: Arc<FairAdmissionInner>,
    tenant_id: String,
    released: bool,
}

struct QueuedAdmissionTicket {
    inner: Arc<FairAdmissionInner>,
    tenant_id: String,
    request_id: u64,
    armed: bool,
}

enum AdmissionDecision {
    Granted(FairAdmissionPermit),
    Queued {
        receiver: oneshot::Receiver<Result<FairAdmissionPermit, FairAdmissionError>>,
        ticket: QueuedAdmissionTicket,
    },
}

impl FairAdmissionScheduler {
    /// Creates a scheduler after validating all bounds and tenant weights.
    pub fn new(limits: RemoteAdmissionLimits) -> Result<Self, FairAdmissionError> {
        limits.validate()?;
        Ok(Self::from_validated_limits(limits))
    }

    fn from_validated_limits(limits: RemoteAdmissionLimits) -> Self {
        Self {
            inner: Arc::new(FairAdmissionInner {
                limits,
                state: Mutex::new(FairAdmissionState::default()),
            }),
        }
    }

    /// Waits for a weighted-fair dispatch permit within all hard bounds.
    pub async fn acquire(
        &self,
        tenant_id: &str,
        request_bytes: usize,
    ) -> Result<FairAdmissionPermit, FairAdmissionError> {
        let decision = self.inner.admit(tenant_id, request_bytes)?;
        match decision {
            AdmissionDecision::Granted(permit) => Ok(permit),
            AdmissionDecision::Queued {
                receiver,
                mut ticket,
            } => {
                let result = tokio::time::timeout(self.inner.limits.max_queue_age, receiver).await;
                match result {
                    Ok(Ok(result)) => {
                        ticket.armed = false;
                        result
                    }
                    Ok(Err(_)) => Err(FairAdmissionError::SchedulerStopped),
                    Err(_) => Err(FairAdmissionError::QueueExpired),
                }
            }
        }
    }

    /// Returns a fixed-size snapshot without tenant identifiers.
    #[must_use]
    pub fn snapshot(&self) -> FairAdmissionSnapshot {
        let state = self.inner.lock_state();
        FairAdmissionSnapshot {
            active: state.active,
            queued: state.queued,
            queued_bytes: state.queued_bytes,
            active_tenants: state.active_by_tenant.len(),
            queued_tenants: state.tenant_queues.len(),
        }
    }
}

impl Default for FairAdmissionScheduler {
    fn default() -> Self {
        Self::from_validated_limits(RemoteAdmissionLimits::default())
    }
}

impl FairAdmissionInner {
    fn lock_state(&self) -> MutexGuard<'_, FairAdmissionState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn admit(
        self: &Arc<Self>,
        tenant_id: &str,
        request_bytes: usize,
    ) -> Result<AdmissionDecision, FairAdmissionError> {
        if request_bytes > self.limits.max_request_bytes {
            return Err(FairAdmissionError::RequestTooLarge);
        }
        let tenant_id = tenant_id.to_owned();
        let mut state = self.lock_state();
        self.dispatch_locked(&mut state);
        let tenant_active = state
            .active_by_tenant
            .get(&tenant_id)
            .copied()
            .unwrap_or_default();
        if state.queued == 0
            && state.active < self.limits.max_in_flight
            && tenant_active < self.limits.max_in_flight_per_tenant
        {
            state.active = state.active.saturating_add(1);
            *state.active_by_tenant.entry(tenant_id.clone()).or_default() += 1;
            return Ok(AdmissionDecision::Granted(FairAdmissionPermit {
                inner: self.clone(),
                tenant_id,
                released: false,
            }));
        }
        if state.queued >= self.limits.max_queued {
            return Err(FairAdmissionError::QueueFull);
        }
        let tenant_queued = state
            .tenant_queues
            .get(&tenant_id)
            .map_or(0, |queue| queue.requests.len());
        if tenant_queued >= self.limits.max_queued_per_tenant {
            return Err(FairAdmissionError::TenantQueueFull);
        }
        if request_bytes
            > self
                .limits
                .max_queue_bytes
                .saturating_sub(state.queued_bytes)
        {
            return Err(FairAdmissionError::QueueBytesExhausted);
        }
        state.next_request_id = state.next_request_id.wrapping_add(1).max(1);
        let request_id = state.next_request_id;
        let (response, receiver) = oneshot::channel();
        let queue = state.tenant_queues.entry(tenant_id.clone()).or_default();
        let queue_was_empty = queue.requests.is_empty();
        queue.requests.push_back(QueuedAdmission {
            id: request_id,
            bytes: request_bytes,
            queued_at: Instant::now(),
            response,
        });
        if queue_was_empty {
            state.rotation.push_back(tenant_id.clone());
        }
        state.queued = state.queued.saturating_add(1);
        state.queued_bytes = state.queued_bytes.saturating_add(request_bytes);
        self.dispatch_locked(&mut state);
        Ok(AdmissionDecision::Queued {
            receiver,
            ticket: QueuedAdmissionTicket {
                inner: self.clone(),
                tenant_id,
                request_id,
                armed: true,
            },
        })
    }

    fn release(self: &Arc<Self>, tenant_id: &str) {
        let mut state = self.lock_state();
        state.active = state.active.saturating_sub(1);
        if let Some(active) = state.active_by_tenant.get_mut(tenant_id) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                state.active_by_tenant.remove(tenant_id);
            }
        }
        self.dispatch_locked(&mut state);
    }

    fn cancel(self: &Arc<Self>, tenant_id: &str, request_id: u64) {
        let mut state = self.lock_state();
        let removed = state.tenant_queues.get_mut(tenant_id).and_then(|queue| {
            let position = queue
                .requests
                .iter()
                .position(|request| request.id == request_id)?;
            queue.requests.remove(position)
        });
        if let Some(request) = removed {
            state.queued = state.queued.saturating_sub(1);
            state.queued_bytes = state.queued_bytes.saturating_sub(request.bytes);
        }
        let empty = state
            .tenant_queues
            .get(tenant_id)
            .is_some_and(|queue| queue.requests.is_empty());
        if empty {
            state.tenant_queues.remove(tenant_id);
            state.rotation.retain(|candidate| candidate != tenant_id);
        }
        self.dispatch_locked(&mut state);
    }

    fn dispatch_locked(self: &Arc<Self>, state: &mut FairAdmissionState) {
        let mut visits_without_grant = 0usize;
        while state.active < self.limits.max_in_flight && !state.rotation.is_empty() {
            if visits_without_grant >= state.rotation.len() {
                break;
            }
            let Some(tenant_id) = state.rotation.pop_front() else {
                break;
            };
            self.expire_front_locked(state, &tenant_id);
            let Some(queue) = state.tenant_queues.get_mut(&tenant_id) else {
                visits_without_grant = 0;
                continue;
            };
            if queue.requests.is_empty() {
                state.tenant_queues.remove(&tenant_id);
                visits_without_grant = 0;
                continue;
            }
            let tenant_active = state
                .active_by_tenant
                .get(&tenant_id)
                .copied()
                .unwrap_or_default();
            if tenant_active >= self.limits.max_in_flight_per_tenant {
                state.rotation.push_back(tenant_id);
                visits_without_grant = visits_without_grant.saturating_add(1);
                continue;
            }
            if queue.credit == 0 {
                queue.credit = self
                    .limits
                    .tenant_weights
                    .get(&tenant_id)
                    .copied()
                    .unwrap_or(1);
            }
            let Some(request) = queue.requests.pop_front() else {
                state.tenant_queues.remove(&tenant_id);
                continue;
            };
            queue.credit = queue.credit.saturating_sub(1);
            let has_more = !queue.requests.is_empty();
            let remaining_credit = queue.credit;
            if !has_more {
                state.tenant_queues.remove(&tenant_id);
            } else if remaining_credit > 0 {
                state.rotation.push_front(tenant_id.clone());
            } else {
                state.rotation.push_back(tenant_id.clone());
            }
            state.queued = state.queued.saturating_sub(1);
            state.queued_bytes = state.queued_bytes.saturating_sub(request.bytes);
            state.active = state.active.saturating_add(1);
            *state.active_by_tenant.entry(tenant_id.clone()).or_default() += 1;
            let permit = FairAdmissionPermit {
                inner: self.clone(),
                tenant_id: tenant_id.clone(),
                released: false,
            };
            if let Err(undelivered) = request.response.send(Ok(permit)) {
                if let Ok(mut permit) = undelivered {
                    permit.released = true;
                }
                state.active = state.active.saturating_sub(1);
                if let Some(active) = state.active_by_tenant.get_mut(&tenant_id) {
                    *active = active.saturating_sub(1);
                    if *active == 0 {
                        state.active_by_tenant.remove(&tenant_id);
                    }
                }
            }
            visits_without_grant = 0;
        }
    }

    fn expire_front_locked(&self, state: &mut FairAdmissionState, tenant_id: &str) {
        loop {
            let expired = state
                .tenant_queues
                .get(tenant_id)
                .and_then(|queue| queue.requests.front())
                .is_some_and(|request| request.queued_at.elapsed() >= self.limits.max_queue_age);
            if !expired {
                break;
            }
            let request = state
                .tenant_queues
                .get_mut(tenant_id)
                .and_then(|queue| queue.requests.pop_front());
            let Some(request) = request else {
                break;
            };
            state.queued = state.queued.saturating_sub(1);
            state.queued_bytes = state.queued_bytes.saturating_sub(request.bytes);
            let _ = request.response.send(Err(FairAdmissionError::QueueExpired));
        }
    }
}

impl Drop for FairAdmissionPermit {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.inner.release(&self.tenant_id);
        }
    }
}

impl Drop for QueuedAdmissionTicket {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            self.inner.cancel(&self.tenant_id, self.request_id);
        }
    }
}

/// Hard bounds for the shared authenticated connector-event ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorEventIngressLimits {
    /// Maximum serialized signed envelope size.
    pub max_envelope_bytes: usize,
    /// Maximum events accepted in one existing AIP event stream.
    pub max_events_per_envelope: usize,
    /// Maximum serialized size of one enriched event.
    pub max_event_bytes: usize,
    /// Maximum serialized size of one connector stream chunk.
    pub max_stream_chunk_bytes: usize,
    /// Maximum concurrent storage operations through this daemon.
    pub max_in_flight: usize,
    /// Maximum age accepted for the signed transport envelope.
    ///
    /// The events inside the envelope may describe arbitrarily old source
    /// observations. Authenticity and replay protection are provided by the
    /// fresh signed envelope, the active connector lease, and stable event
    /// identifiers; `Event::occurred_at` is source chronology, not transport
    /// freshness.
    pub max_event_age: Duration,
    /// Maximum accepted future clock skew.
    pub max_future_skew: Duration,
    /// Maximum age accepted for a signed connector stream callback envelope.
    pub max_stream_callback_age: Duration,
}

/// Fixed-size connector-event ingress telemetry safe for bounded metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorEventIngressSnapshot {
    /// Configured concurrent storage-operation capacity.
    pub max_in_flight: usize,
    /// Capacity currently available without waiting.
    pub available: usize,
}

impl Default for ConnectorEventIngressLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 4 * 1024 * 1024,
            max_events_per_envelope: 100,
            max_event_bytes: 256 * 1024,
            max_stream_chunk_bytes: 256 * 1024,
            max_in_flight: 128,
            max_event_age: Duration::from_secs(24 * 60 * 60),
            max_future_skew: Duration::from_secs(5 * 60),
            max_stream_callback_age: Duration::from_secs(5 * 60),
        }
    }
}

impl ConnectorEventIngressLimits {
    /// Rejects invalid or effectively unbounded ingress configuration.
    pub fn validate(&self) -> Result<(), FairAdmissionError> {
        if self.max_envelope_bytes == 0
            || self.max_events_per_envelope == 0
            || self.max_events_per_envelope > 1_000
            || self.max_event_bytes == 0
            || self.max_event_bytes > self.max_envelope_bytes
            || self.max_stream_chunk_bytes == 0
            || self.max_stream_chunk_bytes > self.max_envelope_bytes
            || self.max_in_flight == 0
            || self.max_event_age.is_zero()
            || self.max_future_skew.is_zero()
            || self.max_stream_callback_age.is_zero()
        {
            return Err(FairAdmissionError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorEventRoute {
    tenant_id: String,
    instance_id: ConnectorInstanceId,
    replica_id: ConnectorReplicaId,
    version_id: ConnectorVersionId,
    manifest_digest: String,
    lease_sequence: u64,
    channel_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConnectorCallbackRoute {
    action_id: ActionId,
    capability_id: CapabilityId,
    tenant_id: String,
    instance_id: ConnectorInstanceId,
    replica_id: ConnectorReplicaId,
    version_id: ConnectorVersionId,
    manifest_digest: String,
    catalog_revision: CatalogRevision,
    binding_policy_revision: u64,
    credential_revision_ref: Option<String>,
    quota_policy_ref: Option<String>,
    replica_health_revision: u64,
    fence_token: String,
    original_mode: Option<ActionMode>,
}

/// Trusted sink invoked only after connector callback route authentication.
#[async_trait]
pub trait ConnectorStreamSink: Send + Sync {
    /// Records one authenticated stream chunk for its active central action.
    async fn ingest_connector_stream_chunk(
        &self,
        chunk: StreamChunk,
        context: MessageContext,
    ) -> RuntimeResult<EventStream>;
}

#[async_trait]
impl ConnectorStreamSink for Runtime {
    async fn ingest_connector_stream_chunk(
        &self,
        chunk: StreamChunk,
        context: MessageContext,
    ) -> RuntimeResult<EventStream> {
        self.ingest_assigned_connector_stream_chunk(chunk, context)
            .await
    }
}

/// Shared ingress for connector-originated existing AIP [`Event`] values.
#[derive(Clone)]
pub struct ConnectorEventIngress {
    registry: Arc<dyn ConnectorRegistryReader>,
    events: EventLog,
    stream_resolver: Option<Arc<dyn ActionTargetResolver>>,
    stream_sink: Option<Arc<dyn ConnectorStreamSink>>,
    signer: CallbackSigner,
    limits: ConnectorEventIngressLimits,
    capacity: Arc<tokio::sync::Semaphore>,
}

impl ConnectorEventIngress {
    /// Creates one bounded ingress independent of connector count.
    pub fn new(
        registry: Arc<dyn ConnectorRegistryReader>,
        events: EventLog,
        signer: CallbackSigner,
        limits: ConnectorEventIngressLimits,
    ) -> Result<Self, FairAdmissionError> {
        limits.validate()?;
        let capacity = Arc::new(tokio::sync::Semaphore::new(limits.max_in_flight));
        Ok(Self {
            registry,
            events,
            stream_resolver: None,
            stream_sink: None,
            signer,
            limits,
            capacity,
        })
    }

    /// Installs the durable route resolver and central runtime stream sink.
    ///
    /// Event-only deployments may omit this pair. Fleet deployments must
    /// install both before advertising streaming support.
    #[must_use]
    pub fn with_stream_callbacks(
        mut self,
        resolver: Arc<dyn ActionTargetResolver>,
        sink: Arc<dyn ConnectorStreamSink>,
    ) -> Self {
        self.stream_resolver = Some(resolver);
        self.stream_sink = Some(sink);
        self
    }

    /// Returns the HTTP body bound that must be installed before JSON parsing.
    #[must_use]
    pub const fn max_envelope_bytes(&self) -> usize {
        self.limits.max_envelope_bytes
    }

    /// Returns a fixed-size snapshot without connector or tenant identifiers.
    #[must_use]
    pub fn snapshot(&self) -> ConnectorEventIngressSnapshot {
        ConnectorEventIngressSnapshot {
            max_in_flight: self.limits.max_in_flight,
            available: self.capacity.available_permits(),
        }
    }

    /// Validates one shared connector event or stream-callback envelope.
    pub async fn handle(&self, envelope: &Envelope) -> Result<Envelope, ProtocolError> {
        let _permit = self.capacity.clone().try_acquire_owned().map_err(|_| {
            connector_event_error(
                "connector_event.capacity",
                "connector ingress capacity is exhausted",
                ErrorCategory::Temporary,
                true,
                Some(100),
            )
        })?;
        let serialized = serde_json::to_vec(envelope).map_err(|error| {
            connector_event_invalid(format!(
                "connector ingress envelope encoding failed: {error}"
            ))
        })?;
        if serialized.len() > self.limits.max_envelope_bytes {
            return Err(connector_event_invalid(
                "connector ingress envelope exceeds its byte limit",
            ));
        }
        if envelope.to.as_ref().is_none_or(|recipient| {
            recipient.id != self.signer.principal.id || recipient.kind != self.signer.principal.kind
        }) {
            return Err(connector_event_denied(
                "connector ingress recipient does not match this daemon",
            ));
        }
        let signer_did = verify_native_envelope_signature(envelope)
            .map_err(|error| connector_event_denied(error.to_string()))?;
        let sender = envelope
            .from
            .as_ref()
            .ok_or_else(|| connector_event_denied("connector ingress sender is missing"))?;
        match &envelope.body {
            MessageBody::EventStream(stream) => {
                self.handle_event_stream(envelope, stream, sender, &signer_did)
                    .await
            }
            MessageBody::StreamChunk(chunk) => {
                self.handle_stream_callback(envelope, chunk, sender, &signer_did)
                    .await
            }
            _ => Err(connector_event_invalid(
                "connector ingress accepts only existing AIP event streams and stream chunks",
            )),
        }
    }

    async fn handle_event_stream(
        &self,
        envelope: &Envelope,
        stream: &EventStream,
        sender: &Principal,
        signer_did: &str,
    ) -> Result<Envelope, ProtocolError> {
        let route_value = envelope
            .security
            .as_ref()
            .and_then(|security| security.get("connector_event"))
            .cloned()
            .ok_or_else(|| connector_event_denied("connector event route metadata is missing"))?;
        let route: ConnectorEventRoute = serde_json::from_value(route_value)
            .map_err(|error| connector_event_denied(format!("invalid event route: {error}")))?;
        self.validate_event_envelope_timestamp(envelope)?;
        self.authorize_event_route(&route, sender, signer_did)
            .await?;
        if stream.next_cursor.is_some()
            || stream.events.is_empty()
            || stream.events.len() > self.limits.max_events_per_envelope
        {
            return Err(connector_event_invalid(
                "connector event stream must contain a bounded non-empty event batch without a cursor",
            ));
        }
        let mut events = stream.events.clone();
        for event in &mut events {
            self.validate_and_enrich_event(event, &route, sender)?;
        }
        let mut stored = Vec::with_capacity(events.len());
        for event in events {
            let accepted = self
                .events
                .append(event.clone())
                .await
                .map_err(|error| runtime_error_to_protocol(&error))?;
            if accepted != event && !connector_event_replay_equivalent(&accepted, &event) {
                return Err(connector_event_error(
                    "connector_event.idempotency_conflict",
                    "connector event id already identifies different retained content",
                    ErrorCategory::Permanent,
                    false,
                    None,
                ));
            }
            stored.push(accepted);
        }
        self.signed_response(
            envelope,
            MessageBody::EventStream(EventStream {
                events: stored,
                next_cursor: None,
            }),
        )
    }

    fn validate_event_envelope_timestamp(&self, envelope: &Envelope) -> Result<(), ProtocolError> {
        let now = OffsetDateTime::now_utc();
        let oldest = now
            - time::Duration::seconds(
                self.limits.max_event_age.as_secs().min(i64::MAX as u64) as i64
            );
        let newest = now
            + time::Duration::seconds(
                self.limits.max_future_skew.as_secs().min(i64::MAX as u64) as i64
            );
        if envelope.sent_at < oldest || envelope.sent_at > newest {
            return Err(connector_event_invalid(
                "connector event envelope timestamp is outside the accepted window",
            ));
        }
        Ok(())
    }

    async fn handle_stream_callback(
        &self,
        envelope: &Envelope,
        chunk: &StreamChunk,
        sender: &Principal,
        signer_did: &str,
    ) -> Result<Envelope, ProtocolError> {
        let resolver = self.stream_resolver.as_ref().ok_or_else(|| {
            connector_event_unavailable("connector stream callbacks are not configured")
        })?;
        let sink = self.stream_sink.as_ref().ok_or_else(|| {
            connector_event_unavailable("connector stream callbacks are not configured")
        })?;
        let route_value = envelope
            .security
            .as_ref()
            .and_then(|security| security.get("connector_callback"))
            .cloned()
            .ok_or_else(|| {
                connector_event_denied("connector stream callback route metadata is missing")
            })?;
        let route: ConnectorCallbackRoute =
            serde_json::from_value(route_value).map_err(|error| {
                connector_event_denied(format!("invalid stream callback route: {error}"))
            })?;
        if route.original_mode != Some(ActionMode::Streaming) || chunk.action_id != route.action_id
        {
            return Err(connector_event_denied(
                "connector stream callback action or original mode does not match its route",
            ));
        }
        let now = OffsetDateTime::now_utc();
        let oldest = now
            - time::Duration::seconds(
                self.limits
                    .max_stream_callback_age
                    .as_secs()
                    .min(i64::MAX as u64) as i64,
            );
        let newest = now
            + time::Duration::seconds(
                self.limits.max_future_skew.as_secs().min(i64::MAX as u64) as i64
            );
        if envelope.sent_at < oldest || envelope.sent_at > newest {
            return Err(connector_event_invalid(
                "connector stream callback timestamp is outside the accepted window",
            ));
        }
        let chunk_bytes = serde_json::to_vec(chunk).map_err(|error| {
            connector_event_invalid(format!("connector stream chunk encoding failed: {error}"))
        })?;
        if chunk_bytes.len() > self.limits.max_stream_chunk_bytes {
            return Err(connector_event_invalid(
                "connector stream chunk exceeds its byte limit",
            ));
        }
        let assignment = resolver
            .assignment(&route.action_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| {
                connector_event_denied("connector stream callback route is not assigned")
            })?;
        self.authorize_callback_route(&route, &assignment, sender, signer_did)
            .await?;
        let context = MessageContext::from_envelope(envelope);
        let stream = sink
            .ingest_connector_stream_chunk(chunk.clone(), context)
            .await
            .map_err(|error| runtime_error_to_protocol(&error))?;
        self.signed_response(envelope, MessageBody::EventStream(stream))
    }

    /// Builds a signed AIP error correlated to a rejected ingress request.
    pub fn signed_error(
        &self,
        request: &Envelope,
        error: ProtocolError,
    ) -> RuntimeResult<Envelope> {
        self.signed_response(request, MessageBody::Error(ErrorBody { error }))
            .map_err(RuntimeError::Protocol)
    }

    async fn authorize_event_route(
        &self,
        route: &ConnectorEventRoute,
        sender: &Principal,
        signer_did: &str,
    ) -> Result<(), ProtocolError> {
        let replica = self
            .registry
            .connector_replica(&route.replica_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| connector_event_denied("connector event replica is not registered"))?;
        let now = OffsetDateTime::now_utc();
        if replica.instance_id != route.instance_id
            || replica.version_id != route.version_id
            || !matches!(
                replica.status,
                ConnectorReplicaStatus::Ready | ConnectorReplicaStatus::Draining
            )
            || replica.lease_expires_at <= now
            // Event batches are durably queued before transport. A heartbeat can
            // advance the replica revision after the batch is signed but before
            // it reaches ingress, so equality would reject an authenticated
            // batch from the same still-leased replica. A zero or future
            // sequence is never valid; an earlier positive sequence remains
            // fenced by the current replica identity, DID, version, status, and
            // unexpired lease checks around it.
            || route.lease_sequence == 0
            || route.lease_sequence > replica.health_revision
            || replica.peer_principal_id != sender.id
            || replica.peer_principal_kind != sender.kind
            || replica.peer_did != signer_did
            || sender.trust_domain.as_deref() != Some(replica.trust_domain.as_str())
        {
            return Err(connector_event_denied(
                "connector event sender, replica identity, or active lease does not match the registry",
            ));
        }
        let instance = self
            .registry
            .connector_instance(&route.instance_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| connector_event_denied("connector event instance is not registered"))?;
        if instance.status != ConnectorInstanceStatus::Enabled
            || instance.tenant_id != route.tenant_id
            || instance.version_id != route.version_id
        {
            return Err(connector_event_denied(
                "connector event tenant or instance is not enabled for this version",
            ));
        }
        let version = self
            .registry
            .connector_version(&route.version_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| connector_event_denied("connector event version is not admitted"))?;
        if version.status != ConnectorVersionStatus::Active
            || version.manifest_digest != route.manifest_digest
            || !manifest_declares_channel(&version.manifest.channels, &route.channel_id)
        {
            return Err(connector_event_denied(
                "connector event version, manifest digest, or channel contract is not active",
            ));
        }
        validate_artifact_attestation(&version.attestation, &version.manifest)
            .map_err(|error| connector_event_denied(error.to_string()))?;
        Ok(())
    }

    async fn authorize_callback_route(
        &self,
        route: &ConnectorCallbackRoute,
        assignment: &RouteAssignment,
        sender: &Principal,
        signer_did: &str,
    ) -> Result<(), ProtocolError> {
        if route.action_id != assignment.action_id
            || route.capability_id != assignment.capability_id
            || route.tenant_id != assignment.tenant_id
            || route.instance_id != assignment.instance_id
            || route.replica_id != assignment.replica_id
            || route.version_id != assignment.version_id
            || route.manifest_digest != assignment.manifest_digest
            || route.catalog_revision != assignment.catalog_revision
            || route.binding_policy_revision != assignment.binding_policy_revision
            || route.credential_revision_ref != assignment.credential_revision_ref
            || route.quota_policy_ref != assignment.quota_policy_ref
            || route.replica_health_revision != assignment.replica_health_revision
            || route.fence_token != assignment.fence_token
        {
            return Err(connector_event_denied(
                "connector stream callback does not match its durable route assignment",
            ));
        }
        let replica = self
            .registry
            .connector_replica(&route.replica_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| {
                connector_event_denied("connector stream callback replica is not registered")
            })?;
        let now = OffsetDateTime::now_utc();
        if replica.instance_id != route.instance_id
            || replica.version_id != route.version_id
            || !matches!(
                replica.status,
                ConnectorReplicaStatus::Ready | ConnectorReplicaStatus::Draining
            )
            || replica.lease_expires_at <= now
            || replica.health_revision < route.replica_health_revision
            || replica.endpoint != assignment.endpoint
            || replica.peer_principal_id != assignment.peer_principal_id
            || replica.peer_principal_kind != assignment.peer_principal_kind
            || replica.peer_did != assignment.peer_did
            || replica.trust_domain != assignment.trust_domain
            || replica.transport_profile != assignment.transport_profile
            || replica.peer_principal_id != sender.id
            || replica.peer_principal_kind != sender.kind
            || replica.peer_did != signer_did
            || sender.trust_domain.as_deref() != Some(replica.trust_domain.as_str())
        {
            return Err(connector_event_denied(
                "connector stream callback sender, replica identity, or active lease does not match the assigned route",
            ));
        }
        let instance = self
            .registry
            .connector_instance(&route.instance_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| {
                connector_event_denied("connector stream callback instance is not registered")
            })?;
        if instance.status != ConnectorInstanceStatus::Enabled
            || instance.tenant_id != route.tenant_id
            || instance.version_id != route.version_id
        {
            return Err(connector_event_denied(
                "connector stream callback tenant or instance is not enabled for this version",
            ));
        }
        let version = self
            .registry
            .connector_version(&route.version_id)
            .await
            .map_err(registry_event_error)?
            .ok_or_else(|| {
                connector_event_denied("connector stream callback version is not admitted")
            })?;
        if version.status != ConnectorVersionStatus::Active
            || version.manifest_digest != route.manifest_digest
            || !version
                .manifest
                .capabilities
                .iter()
                .any(|capability| capability.id == route.capability_id)
        {
            return Err(connector_event_denied(
                "connector stream callback version, manifest digest, or capability is not active",
            ));
        }
        validate_artifact_attestation(&version.attestation, &version.manifest)
            .map_err(|error| connector_event_denied(error.to_string()))?;
        Ok(())
    }

    fn validate_and_enrich_event(
        &self,
        event: &mut Event,
        route: &ConnectorEventRoute,
        sender: &Principal,
    ) -> Result<(), ProtocolError> {
        if event.kind.trim().is_empty() || event.kind.len() > 256 {
            return Err(connector_event_invalid(
                "connector event kind must contain 1 to 256 bytes",
            ));
        }
        let now = OffsetDateTime::now_utc();
        let newest = now
            + time::Duration::seconds(
                self.limits.max_future_skew.as_secs().min(i64::MAX as u64) as i64
            );
        if event.occurred_at > newest {
            return Err(connector_event_invalid(
                "connector event occurrence timestamp exceeds the accepted future skew",
            ));
        }
        if event.actor.as_ref().is_some_and(|actor| actor != sender) {
            return Err(connector_event_denied(
                "connector event actor does not match its signed sender",
            ));
        }
        event.actor = Some(sender.clone());
        let data = event.data.get_or_insert_with(|| serde_json::json!({}));
        let data = data
            .as_object_mut()
            .ok_or_else(|| connector_event_invalid("connector event data must be a JSON object"))?;
        let identity = data
            .entry("identity")
            .or_insert_with(|| serde_json::json!({}));
        let identity = identity.as_object_mut().ok_or_else(|| {
            connector_event_invalid("connector event identity must be a JSON object")
        })?;
        let tenant = identity
            .entry("tenant")
            .or_insert_with(|| serde_json::json!({}));
        let tenant = tenant.as_object_mut().ok_or_else(|| {
            connector_event_invalid("connector event tenant identity must be a JSON object")
        })?;
        if tenant
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|tenant_id| tenant_id != route.tenant_id)
        {
            return Err(connector_event_denied(
                "connector event payload tenant conflicts with its verified instance",
            ));
        }
        tenant.insert("id".to_owned(), serde_json::json!(route.tenant_id));
        let provenance = serde_json::json!({
            "instance_id": route.instance_id,
            "replica_id": route.replica_id,
            "version_id": route.version_id,
            "channel_id": route.channel_id,
            "lease_sequence": route.lease_sequence
        });
        if data
            .get("aip_connector")
            .is_some_and(|existing| existing != &provenance)
        {
            return Err(connector_event_denied(
                "connector event provenance conflicts with its verified route",
            ));
        }
        data.insert("aip_connector".to_owned(), provenance);
        let event_bytes = serde_json::to_vec(event).map_err(|error| {
            connector_event_invalid(format!("connector event encoding failed: {error}"))
        })?;
        if event_bytes.len() > self.limits.max_event_bytes {
            return Err(connector_event_invalid(
                "connector event exceeds its byte limit",
            ));
        }
        Ok(())
    }

    fn signed_response(
        &self,
        request: &Envelope,
        body: MessageBody,
    ) -> Result<Envelope, ProtocolError> {
        let mut response = Envelope::new(body);
        response.session_id.clone_from(&request.session_id);
        response.correlation_id.clone_from(&request.correlation_id);
        response.in_response_to = Some(MessageReference::Message(request.message_id.clone()));
        response.to.clone_from(&request.from);
        sign_native_envelope(response, &self.signer)
            .map_err(|error| connector_event_unavailable(error.to_string()))
    }
}

fn connector_event_replay_equivalent(retained: &Event, candidate: &Event) -> bool {
    let retained_upstream_actor = connector_event_upstream_actor(retained);
    let candidate_upstream_actor = connector_event_upstream_actor(candidate);
    match (
        connector_event_replay_view(retained, candidate_upstream_actor.as_ref()),
        connector_event_replay_view(candidate, retained_upstream_actor.as_ref()),
    ) {
        (Some(retained), Some(candidate)) => retained == candidate,
        _ => false,
    }
}

fn connector_event_upstream_actor(event: &Event) -> Option<Principal> {
    event
        .data
        .as_ref()
        .and_then(|data| data.get("upstream_actor"))
        .and_then(|actor| serde_json::from_value(actor.clone()).ok())
}

fn connector_event_replay_view(
    event: &Event,
    counterpart_upstream_actor: Option<&Principal>,
) -> Option<Event> {
    let mut event = event.clone();
    let original_actor = event.actor.take();
    let data = event.data.as_mut()?.as_object_mut()?;

    // Before connector-host actor projection, provider identity occupied the
    // protocol actor field. Accept those retained events across a rolling
    // upgrade only when the old actor is exactly the new upstream actor.
    if !data.contains_key("upstream_actor")
        && original_actor.as_ref() == counterpart_upstream_actor
        && let Some(original_actor) = original_actor
    {
        data.insert(
            "upstream_actor".to_owned(),
            serde_json::to_value(original_actor).ok()?,
        );
    }

    // These fields prove one authenticated delivery but are not semantic
    // provider-event content. Heartbeat renewal, replica failover, or an
    // immutable connector rollout must not turn the same provider event id
    // and payload into a permanent idempotency conflict.
    if let Some(provenance) = data
        .get_mut("aip_connector")
        .and_then(serde_json::Value::as_object_mut)
    {
        provenance.remove("replica_id");
        provenance.remove("version_id");
        provenance.remove("lease_sequence");
    }
    Some(event)
}

fn manifest_declares_channel(channels: &[serde_json::Value], channel_id: &str) -> bool {
    channels.iter().any(|channel| match channel {
        serde_json::Value::String(value) => value == channel_id,
        serde_json::Value::Object(value) => {
            value
                .get("id")
                .or_else(|| value.get("channel_id"))
                .and_then(serde_json::Value::as_str)
                == Some(channel_id)
        }
        _ => false,
    })
}

fn registry_event_error(error: RegistryError) -> ProtocolError {
    connector_event_unavailable(error.to_string())
}

fn connector_event_invalid(message: impl Into<String>) -> ProtocolError {
    connector_event_error(
        "connector_event.invalid",
        message,
        ErrorCategory::Permanent,
        false,
        None,
    )
}

fn connector_event_denied(message: impl Into<String>) -> ProtocolError {
    connector_event_error(
        "connector_event.not_authorized",
        message,
        ErrorCategory::Auth,
        false,
        None,
    )
}

fn connector_event_unavailable(message: impl Into<String>) -> ProtocolError {
    connector_event_error(
        "connector_event.unavailable",
        message,
        ErrorCategory::Temporary,
        true,
        Some(1_000),
    )
}

fn connector_event_error(
    code: &str,
    message: impl Into<String>,
    category: ErrorCategory,
    retryable: bool,
    retry_after_ms: Option<u64>,
) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: message.into(),
        category,
        retryable: Some(retryable),
        retry_after_ms,
        details: None,
        source: Some(Box::new(serde_json::json!({
            "component": "aip-connector-remote.events"
        }))),
    }
}

/// Deployment transport that delivers one assigned action to a connector host.
///
/// Implementations must authenticate the endpoint from [`RouteAssignment`],
/// project only trusted non-secret execution claims, and validate the signed
/// correlated native AIP response.
#[async_trait]
pub trait RemoteConnectorDispatcher: Send + Sync {
    /// Invokes the assigned connector host.
    async fn invoke(
        &self,
        assignment: &RouteAssignment,
        action: Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<ActionResult>;

    /// Cancels an action through its existing assignment.
    async fn cancel(
        &self,
        assignment: &RouteAssignment,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<()>;
}

/// Generic remote action handler shared by every fleet capability.
#[derive(Clone)]
pub struct RemoteConnectorHandler {
    resolver: Arc<dyn ActionTargetResolver>,
    dispatcher: Arc<dyn RemoteConnectorDispatcher>,
    support: CapabilityImplementationSupport,
    admission: FairAdmissionScheduler,
    topology: RouteTopologyPreference,
}

impl RemoteConnectorHandler {
    /// Creates a handler with deployment-owned routing and transport.
    #[must_use]
    pub fn new(
        resolver: Arc<dyn ActionTargetResolver>,
        dispatcher: Arc<dyn RemoteConnectorDispatcher>,
        support: CapabilityImplementationSupport,
    ) -> Self {
        Self {
            resolver,
            dispatcher,
            support,
            admission: FairAdmissionScheduler::default(),
            topology: RouteTopologyPreference::default(),
        }
    }

    /// Replaces the default local scheduler with deployment-owned bounds.
    #[must_use]
    pub fn with_admission_scheduler(mut self, admission: FairAdmissionScheduler) -> Self {
        self.admission = admission;
        self
    }

    /// Applies deployment locality constraints when creating new assignments.
    /// Existing assignments remain pinned to their original replica.
    #[must_use]
    pub fn with_topology_preference(mut self, topology: RouteTopologyPreference) -> Self {
        self.topology = topology;
        self
    }

    /// Returns fixed-size admission telemetry without tenant identifiers.
    #[must_use]
    pub fn admission_snapshot(&self) -> FairAdmissionSnapshot {
        self.admission.snapshot()
    }

    fn route_request(
        &self,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<RouteResolutionRequest> {
        let tenant = context.tenant.as_ref().ok_or_else(|| {
            RuntimeError::Authorization(
                "remote connector execution requires a verified tenant".to_owned(),
            )
        })?;
        tenant
            .validate()
            .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
        Ok(RouteResolutionRequest {
            action_id: action.id.clone(),
            capability_id: action.capability_id.clone(),
            tenant_id: tenant.tenant.id.clone(),
            topology: self.topology.clone(),
        })
    }

    async fn settle_best_effort(&self, assignment: &RouteAssignment, settlement: RouteSettlement) {
        if let Err(error) = self.resolver.settle(assignment, settlement).await {
            warn!(
                action_id = %assignment.action_id,
                replica_id = %assignment.replica_id,
                error = %error,
                "remote route capacity settlement requires reconciliation"
            );
        }
    }
}

#[async_trait]
impl ActionHandler for RemoteConnectorHandler {
    fn implementation_support(&self) -> CapabilityImplementationSupport {
        self.support.clone()
    }

    async fn handle(&self, _action: Action) -> RuntimeResult<ActionResult> {
        Err(RuntimeError::Authorization(
            "remote connectors require a trusted execution context".to_owned(),
        ))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        let route_request = self.route_request(&action, &context)?;
        let request_bytes = serde_json::to_vec(&action)
            .map_err(|error| {
                RuntimeError::Handler(format!("remote action encoding failed: {error}"))
            })?
            .len();
        let _permit = self
            .admission
            .acquire(&route_request.tenant_id, request_bytes)
            .await
            .map_err(fair_admission_runtime_error)?;
        let assignment = self
            .resolver
            .resolve(route_request)
            .await
            .map_err(registry_runtime_error)?;
        let result = self.dispatcher.invoke(&assignment, action, &context).await;
        match &result {
            Ok(_) => {
                self.settle_best_effort(&assignment, RouteSettlement::Completed)
                    .await;
            }
            Err(_) => {
                self.settle_best_effort(&assignment, RouteSettlement::OutcomeUnknown)
                    .await;
            }
        }
        result
    }

    async fn cancel_with_context(
        &self,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<()> {
        let assignment = self
            .resolver
            .assignment(&action.id)
            .await
            .map_err(registry_runtime_error)?
            .ok_or_else(|| {
                RuntimeError::Handler(format!(
                    "remote action `{}` has no durable route assignment",
                    action.id
                ))
            })?;
        self.dispatcher.cancel(&assignment, action, context).await?;
        self.settle_best_effort(&assignment, RouteSettlement::Cancelled)
            .await;
        Ok(())
    }
}

fn fair_admission_runtime_error(error: FairAdmissionError) -> RuntimeError {
    let request_error = matches!(
        error,
        FairAdmissionError::InvalidLimits | FairAdmissionError::RequestTooLarge
    );
    RuntimeError::Protocol(ProtocolError {
        code: if request_error {
            "connector.request_rejected"
        } else {
            "connector.scheduler_overloaded"
        }
        .to_owned(),
        message: error.to_string(),
        category: if request_error {
            ErrorCategory::Permanent
        } else {
            ErrorCategory::Temporary
        },
        retryable: Some(!request_error),
        retry_after_ms: (!request_error).then_some(100),
        details: None,
        source: Some(Box::new(serde_json::json!({
            "component": "aip-connector-remote.scheduler"
        }))),
    })
}

fn registry_runtime_error(error: RegistryError) -> RuntimeError {
    match error {
        RegistryError::CapacityExceeded {
            scope,
            retry_after_ms,
        } => RuntimeError::Protocol(ProtocolError {
            code: "connector.admission_capacity".to_owned(),
            message: format!("connector admission capacity is exhausted for `{scope:?}`"),
            category: ErrorCategory::Temporary,
            retryable: Some(true),
            retry_after_ms: Some(retry_after_ms),
            details: serde_json::to_value(scope).ok().map(Box::new),
            source: Some(Box::new(serde_json::json!({
                "component": "aip-connector-remote"
            }))),
        }),
        RegistryError::BindingUnavailable { .. }
        | RegistryError::ReplicaUnavailable(_)
        | RegistryError::StaleCursor => RuntimeError::Handler(error.to_string()),
        RegistryError::Invalid(_)
        | RegistryError::Admission(_)
        | RegistryError::Conflict(_)
        | RegistryError::NotFound(_)
        | RegistryError::FenceLost
        | RegistryError::Storage(_) => RuntimeError::Storage(error.to_string()),
    }
}

/// Supplies destination policy for one admitted route assignment.
#[async_trait]
pub trait RemoteEndpointPolicyProvider: Send + Sync {
    /// Returns the SSRF, timeout, and response-size policy for this route.
    async fn policy_for(
        &self,
        assignment: &RouteAssignment,
    ) -> RuntimeResult<GatewayCallbackPolicy>;
}

/// Static endpoint policy for deployments with an explicit host allowlist.
#[derive(Clone, Debug)]
pub struct StaticRemoteEndpointPolicy {
    policy: GatewayCallbackPolicy,
}

impl StaticRemoteEndpointPolicy {
    /// Creates an immutable static policy provider.
    #[must_use]
    pub fn new(policy: GatewayCallbackPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl RemoteEndpointPolicyProvider for StaticRemoteEndpointPolicy {
    async fn policy_for(
        &self,
        _assignment: &RouteAssignment,
    ) -> RuntimeResult<GatewayCallbackPolicy> {
        Ok(self.policy.clone())
    }
}

/// Policy provider that treats the admitted registry endpoint as its allowlist.
///
/// Use this only when registry writes are restricted to the trusted connector
/// control plane. Scheme and private-network rules remain enforced by the base
/// policy on every request.
#[derive(Clone, Debug)]
pub struct RegistryBoundEndpointPolicy {
    base: GatewayCallbackPolicy,
}

impl RegistryBoundEndpointPolicy {
    /// Creates a provider whose host allowlist is derived from the pinned route.
    #[must_use]
    pub fn new(base: GatewayCallbackPolicy) -> Self {
        Self { base }
    }
}

#[async_trait]
impl RemoteEndpointPolicyProvider for RegistryBoundEndpointPolicy {
    async fn policy_for(
        &self,
        assignment: &RouteAssignment,
    ) -> RuntimeResult<GatewayCallbackPolicy> {
        let endpoint = Url::parse(&assignment.endpoint).map_err(|error| {
            RuntimeError::Authorization(format!("invalid admitted connector endpoint: {error}"))
        })?;
        let host = endpoint.host_str().ok_or_else(|| {
            RuntimeError::Authorization("admitted connector endpoint has no host".to_owned())
        })?;
        let mut policy = self.base.clone();
        policy.allowed_hosts.insert(host.to_ascii_lowercase());
        Ok(policy)
    }
}

/// Native AIP HTTP transport for the generic remote connector handler.
#[derive(Clone)]
pub struct NativeAipHttpDispatcher {
    client: NativeAipHttpClient,
    request_signer: CallbackSigner,
    endpoint_policy: Arc<dyn RemoteEndpointPolicyProvider>,
    retry_budget: u32,
    stream_callback_target: Option<Url>,
}

impl NativeAipHttpDispatcher {
    /// Creates a dispatcher with a static destination allowlist.
    #[must_use]
    pub fn new(
        request_signer: CallbackSigner,
        endpoint_policy: GatewayCallbackPolicy,
        retry_budget: u32,
    ) -> Self {
        Self::with_policy_provider(
            request_signer,
            Arc::new(StaticRemoteEndpointPolicy::new(endpoint_policy)),
            retry_budget,
        )
    }

    /// Creates a dispatcher whose policy is resolved for every pinned route.
    #[must_use]
    pub fn with_policy_provider(
        request_signer: CallbackSigner,
        endpoint_policy: Arc<dyn RemoteEndpointPolicyProvider>,
        retry_budget: u32,
    ) -> Self {
        Self {
            client: NativeAipHttpClient::default(),
            request_signer,
            endpoint_policy,
            retry_budget,
            stream_callback_target: None,
        }
    }

    /// Replaces the pooled native HTTP client, primarily for explicit cache bounds.
    #[must_use]
    pub fn with_client(mut self, client: NativeAipHttpClient) -> Self {
        self.client = client;
        self
    }

    /// Installs the shared central callback endpoint used only for streaming
    /// connector actions.
    ///
    /// The original client callback is retained exclusively by the central
    /// runtime. Connector hosts receive this fixed endpoint plus the exact
    /// signed route assignment needed by the callback ingress.
    pub fn with_stream_callback_target(mut self, target: Url) -> RuntimeResult<Self> {
        if !matches!(target.scheme(), "http" | "https")
            || target.host_str().is_none()
            || target.username() != ""
            || target.password().is_some()
            || target.query().is_some()
            || target.fragment().is_some()
            || target.path() != "/aip/v1/connector-callbacks"
        {
            return Err(RuntimeError::Authorization(
                "connector stream callback target must be an absolute HTTP(S) URL ending exactly in /aip/v1/connector-callbacks without credentials, query, or fragment"
                    .to_owned(),
            ));
        }
        self.stream_callback_target = Some(target);
        Ok(self)
    }

    /// Returns whether this dispatcher can relay connector stream callbacks.
    #[must_use]
    pub const fn stream_callbacks_enabled(&self) -> bool {
        self.stream_callback_target.is_some()
    }

    async fn security(
        &self,
        assignment: &RouteAssignment,
    ) -> RuntimeResult<DelegationPeerSecurity> {
        if assignment.transport_profile.as_str() != NATIVE_HTTP_PROFILE {
            return Err(RuntimeError::Handler(format!(
                "remote connector profile `{}` is not supported by the HTTP dispatcher",
                assignment.transport_profile
            )));
        }
        let mut expected_peer = Principal::new(
            assignment.peer_principal_id.clone(),
            assignment.peer_principal_kind,
        );
        expected_peer.did = Some(assignment.peer_did.clone());
        expected_peer.trust_domain = Some(assignment.trust_domain.clone());
        DelegationPeerSecurity::new(
            assignment.trust_domain.clone(),
            self.request_signer.clone(),
            expected_peer,
            assignment.peer_did.clone(),
            self.endpoint_policy.policy_for(assignment).await?,
        )
        .map(|mut security| {
            security.retry_budget = self.retry_budget;
            security
        })
    }

    fn envelope(
        &self,
        assignment: &RouteAssignment,
        body: MessageBody,
        connector_route: serde_json::Value,
    ) -> Envelope {
        let mut envelope = Envelope::new(body);
        envelope.from = Some(self.request_signer.bound_principal());
        envelope.to = Some(Principal::new(
            assignment.peer_principal_id.clone(),
            assignment.peer_principal_kind,
        ));
        envelope.correlation_id = Some(CorrelationId::new());
        envelope.security = Some(serde_json::json!({
            "connector_route": connector_route
        }));
        envelope
    }
}

fn connector_route_metadata(
    assignment: &RouteAssignment,
    original_mode: Option<ActionMode>,
    approval: Option<&VerifiedApprovalSet>,
) -> RuntimeResult<serde_json::Value> {
    let mut route = serde_json::json!({
        "action_id": assignment.action_id,
        "capability_id": assignment.capability_id,
        "tenant_id": assignment.tenant_id,
        "instance_id": assignment.instance_id,
        "replica_id": assignment.replica_id,
        "version_id": assignment.version_id,
        "manifest_digest": assignment.manifest_digest,
        "catalog_revision": assignment.catalog_revision,
        "binding_policy_revision": assignment.binding_policy_revision,
        "credential_revision_ref": assignment.credential_revision_ref,
        "quota_policy_ref": assignment.quota_policy_ref,
        "replica_health_revision": assignment.replica_health_revision,
        "fence_token": assignment.fence_token,
        "original_mode": original_mode
    });
    if let Some(approval) = approval {
        let object = route.as_object_mut().ok_or_else(|| {
            RuntimeError::Handler("connector route metadata must be a JSON object".to_owned())
        })?;
        object.insert(
            "approval_authorization".to_owned(),
            serde_json::to_value(&approval.authorization).map_err(|error| {
                RuntimeError::Handler(format!(
                    "verified approval authorization encoding failed: {error}"
                ))
            })?,
        );
    }
    Ok(route)
}

#[async_trait]
impl RemoteConnectorDispatcher for NativeAipHttpDispatcher {
    async fn invoke(
        &self,
        assignment: &RouteAssignment,
        mut action: Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        project_verified_tenant(&mut action, assignment, context)?;
        let original_mode = action.mode;
        let connector_route =
            connector_route_metadata(assignment, original_mode, context.approval.as_ref())?;
        // The central runtime owns async admission. Its queued attempt executes
        // synchronously at the connector-host hop, while a streaming attempt
        // retains its mode and receives only the central callback endpoint.
        action.callback = None;
        if original_mode == Some(ActionMode::Async) {
            action.mode = Some(ActionMode::Sync);
        } else if original_mode == Some(ActionMode::Streaming) {
            let target = self.stream_callback_target.as_ref().ok_or_else(|| {
                RuntimeError::Authorization(
                    "remote streaming requires a configured central connector callback endpoint"
                        .to_owned(),
                )
            })?;
            action.callback = Some(Callback {
                profile: ProfileId::from(NATIVE_HTTP_PROFILE),
                target: target.to_string(),
                metadata: Some(serde_json::json!({
                    "connector_callback": connector_route.clone(),
                    "connector_callback_recipient": self.request_signer.bound_principal()
                })),
            });
        }
        let envelope = self.envelope(
            assignment,
            MessageBody::Action(Box::new(action)),
            connector_route,
        );
        let response = self
            .client
            .exchange(
                &assignment.endpoint,
                envelope,
                &self.security(assignment).await?,
            )
            .await?;
        match response.body {
            MessageBody::ActionResult(result) if result.action_id == assignment.action_id => {
                Ok(result)
            }
            MessageBody::ActionResult(_) => Err(RuntimeError::Authorization(
                "remote connector result action id does not match its route".to_owned(),
            )),
            MessageBody::Error(error) => Err(RuntimeError::Protocol(error.error)),
            body => Err(RuntimeError::Handler(format!(
                "remote connector returned unexpected `{}`",
                body.message_type().as_str()
            ))),
        }
    }

    async fn cancel(
        &self,
        assignment: &RouteAssignment,
        action: &Action,
        _context: &ActionExecutionContext,
    ) -> RuntimeResult<()> {
        if action.id != assignment.action_id {
            return Err(RuntimeError::Authorization(
                "remote cancellation action id does not match its route".to_owned(),
            ));
        }
        let connector_route = connector_route_metadata(assignment, None, None)?;
        let envelope = self.envelope(
            assignment,
            MessageBody::Cancel(Cancel {
                target: CancelTarget::Action(action.id.clone()),
                reason: Some("cancelled by the AIP connector fleet runtime".to_owned()),
            }),
            connector_route,
        );
        let response = self
            .client
            .exchange(
                &assignment.endpoint,
                envelope,
                &self.security(assignment).await?,
            )
            .await?;
        match response.body {
            MessageBody::ActionResult(result) if result.action_id == assignment.action_id => Ok(()),
            MessageBody::ActionResult(_) => Err(RuntimeError::Authorization(
                "remote cancellation result action id does not match its route".to_owned(),
            )),
            MessageBody::Error(error) => Err(RuntimeError::Protocol(error.error)),
            body => Err(RuntimeError::Handler(format!(
                "remote cancellation returned unexpected `{}`",
                body.message_type().as_str()
            ))),
        }
    }
}

fn project_verified_tenant(
    action: &mut Action,
    assignment: &RouteAssignment,
    context: &ActionExecutionContext,
) -> RuntimeResult<()> {
    let tenant = context.tenant.as_ref().ok_or_else(|| {
        RuntimeError::Authorization(
            "native remote connector execution requires a verified tenant".to_owned(),
        )
    })?;
    if tenant.tenant.id != assignment.tenant_id {
        return Err(RuntimeError::Authorization(
            "verified tenant does not match the pinned connector route".to_owned(),
        ));
    }
    match action.identity.as_mut() {
        Some(identity) => match identity.tenant.as_ref() {
            Some(existing) if existing.id != tenant.tenant.id => {
                return Err(RuntimeError::Authorization(
                    "action tenant claim conflicts with the verified connector route".to_owned(),
                ));
            }
            Some(_) => {}
            None => identity.tenant = Some(tenant.tenant.clone()),
        },
        None => {
            action.identity = Some(IdentityContext {
                tenant: Some(TenantRef {
                    id: tenant.tenant.id.clone(),
                    system: tenant.tenant.system.clone(),
                }),
                external_account: None,
                external_user: None,
                human_actor: None,
                service_account: None,
                acted_on_behalf_of: None,
                credential_ref: None,
                oauth: None,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_auth::{AuthScheme, AuthenticatedPrincipal, VerifiedTenant};
    use aip_connector_registry::{
        ArtifactAttestation, ArtifactCheckStatus, CapabilityBinding, ConnectorInstance,
        ConnectorInstanceId, ConnectorInstanceStatus, ConnectorRegistryAdmin, ConnectorReplica,
        ConnectorReplicaId, ConnectorReplicaStatus, ConnectorType, ConnectorTypeId,
        ConnectorVersion, ConnectorVersionId, ConnectorVersionStatus, InMemoryConnectorRegistry,
        digest_json, schema_bundle_digest,
    };
    use aip_core::{
        ActionId, ActionResultStatus, Capability, CapabilityId, CapabilityKind, EventStreamRequest,
        Manifest, Principal, PrincipalId, PrincipalKind, ProfileId, StreamChunkKind, TenantRef,
    };
    use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed};
    use aip_gateway::{sign_native_envelope, verify_native_envelope_signature};
    use aip_runtime::{
        ActionStream, CancellationToken, Deadline, RedactionPolicy, TraceContext,
        TransactionCheckpointPublisher,
    };
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct TestResolver {
        assignment: Mutex<Option<RouteAssignment>>,
        settlements: Mutex<Vec<RouteSettlement>>,
    }

    #[async_trait]
    impl ActionTargetResolver for TestResolver {
        async fn resolve(
            &self,
            request: RouteResolutionRequest,
        ) -> Result<RouteAssignment, RegistryError> {
            let mut assignment = self.assignment.lock().await;
            if let Some(existing) = assignment.as_ref() {
                return Ok(existing.clone());
            }
            let created = RouteAssignment {
                action_id: request.action_id,
                capability_id: request.capability_id,
                tenant_id: request.tenant_id,
                instance_id: ConnectorInstanceId::trusted("cinst_test"),
                replica_id: ConnectorReplicaId::trusted("crepl_test"),
                endpoint: "https://connector.test/aip/v1/messages".to_owned(),
                peer_principal_id: PrincipalId::trusted("service:test-connector-host"),
                peer_principal_kind: PrincipalKind::Service,
                peer_did: "did:key:test-connector-host".to_owned(),
                trust_domain: "connectors.test".to_owned(),
                transport_profile: ProfileId::from("aip.native.http.v1"),
                topology: Default::default(),
                version_id: ConnectorVersionId::trusted("cver_test"),
                manifest_digest: format!("sha256:{}", "1".repeat(64)),
                catalog_revision: aip_connector_registry::CatalogRevision(7),
                binding_policy_revision: 3,
                credential_revision_ref: None,
                quota_policy_ref: Some("quota:test".to_owned()),
                replica_health_revision: 11,
                fence_token: "route_test".to_owned(),
                assigned_at: OffsetDateTime::now_utc(),
                admission: aip_connector_registry::AdmissionReservation::default(),
            };
            *assignment = Some(created.clone());
            Ok(created)
        }

        async fn assignment(
            &self,
            _action_id: &ActionId,
        ) -> Result<Option<RouteAssignment>, RegistryError> {
            Ok(self.assignment.lock().await.clone())
        }

        async fn settle(
            &self,
            _assignment: &RouteAssignment,
            settlement: RouteSettlement,
        ) -> Result<(), RegistryError> {
            self.settlements.lock().await.push(settlement);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestDispatcher {
        invocations: Mutex<Vec<RouteAssignment>>,
        cancellations: Mutex<Vec<ActionId>>,
    }

    #[derive(Default)]
    struct RecordingStreamSink {
        chunks: Mutex<Vec<StreamChunk>>,
    }

    #[async_trait]
    impl ConnectorStreamSink for RecordingStreamSink {
        async fn ingest_connector_stream_chunk(
            &self,
            chunk: StreamChunk,
            _context: MessageContext,
        ) -> RuntimeResult<EventStream> {
            self.chunks.lock().await.push(chunk);
            Ok(EventStream {
                events: Vec::new(),
                next_cursor: None,
            })
        }
    }

    #[derive(Clone)]
    struct NativePeerState {
        signer: CallbackSigner,
        expected_request_did: String,
        expected_stream_callback: Option<String>,
    }

    async fn native_peer(
        State(state): State<NativePeerState>,
        Json(request): Json<Envelope>,
    ) -> Json<Envelope> {
        let request_did = verify_native_envelope_signature(&request).expect("signed request");
        assert_eq!(request_did, state.expected_request_did);
        let request_from = request.from.clone().expect("request sender");
        let request_message_id = request.message_id.clone();
        let request_session_id = request.session_id.clone();
        let correlation_id = request.correlation_id.clone();
        let route = request
            .security
            .as_ref()
            .and_then(|security| security.get("connector_route"))
            .cloned()
            .expect("signed connector route");
        let route_tenant = route
            .get("tenant_id")
            .and_then(serde_json::Value::as_str)
            .expect("signed route tenant")
            .to_owned();
        let MessageBody::Action(action) = request.body else {
            panic!("expected native action");
        };
        let original_mode = route
            .get("original_mode")
            .cloned()
            .map(serde_json::from_value::<ActionMode>)
            .transpose()
            .expect("original action mode");
        match original_mode {
            Some(ActionMode::Async) => {
                assert_eq!(action.mode, Some(ActionMode::Sync));
                assert!(action.callback.is_none());
            }
            Some(ActionMode::Streaming) => {
                assert_eq!(action.mode, Some(ActionMode::Streaming));
                let callback = action.callback.as_ref().expect("central stream callback");
                assert_eq!(
                    Some(callback.target.as_str()),
                    state.expected_stream_callback.as_deref()
                );
                assert_eq!(
                    callback
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.get("connector_callback")),
                    Some(&route)
                );
                assert_eq!(
                    callback
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.get("connector_callback_recipient")),
                    Some(&json!(request_from))
                );
            }
            mode => panic!("unexpected original mode {mode:?}"),
        }
        assert_eq!(
            action
                .identity
                .as_ref()
                .and_then(|identity| identity.tenant.as_ref())
                .map(|tenant| tenant.id.as_str()),
            Some(route_tenant.as_str())
        );
        let mut response = Envelope::new(MessageBody::ActionResult(ActionResult {
            action_id: action.id,
            status: ActionResultStatus::Completed,
            output: Some(json!({
                "native_aip": true,
                "tenant_id": route_tenant
            })),
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        }));
        response.from = Some(state.signer.principal.clone());
        response.to = Some(request_from);
        response.session_id = request_session_id;
        response.correlation_id = correlation_id;
        response.in_response_to = Some(MessageReference::Message(request_message_id));
        Json(sign_native_envelope(response, &state.signer).expect("signed response"))
    }

    #[async_trait]
    impl RemoteConnectorDispatcher for TestDispatcher {
        async fn invoke(
            &self,
            assignment: &RouteAssignment,
            action: Action,
            _context: &ActionExecutionContext,
        ) -> RuntimeResult<ActionResult> {
            self.invocations.lock().await.push(assignment.clone());
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Completed,
                output: Some(json!({ "remote": true })),
                message: Vec::new(),
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }

        async fn cancel(
            &self,
            _assignment: &RouteAssignment,
            action: &Action,
            _context: &ActionExecutionContext,
        ) -> RuntimeResult<()> {
            self.cancellations.lock().await.push(action.id.clone());
            Ok(())
        }
    }

    fn execution_context() -> ActionExecutionContext {
        let principal = Principal::new(
            PrincipalId::trusted("service:test-client"),
            PrincipalKind::Service,
        );
        ActionExecutionContext {
            actor: AuthenticatedPrincipal {
                principal,
                scheme: AuthScheme::DidProof,
                issuer: "test".to_owned(),
                audience: Some("aip".to_owned()),
                scopes: BTreeSet::from(["*".to_owned()]),
                authenticated_at: OffsetDateTime::now_utc(),
                expires_at: None,
                credential_fingerprint: None,
            },
            tenant: Some(VerifiedTenant {
                tenant: TenantRef {
                    id: "tenant-acme".to_owned(),
                    system: None,
                },
                membership_id: "membership-test".to_owned(),
                roles: BTreeSet::new(),
                groups: BTreeSet::new(),
                verified_at: OffsetDateTime::now_utc(),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            }),
            credential: None,
            deadline: Deadline::after(OffsetDateTime::now_utc(), 30_000),
            cancellation: CancellationToken::default(),
            idempotency: None,
            approval: None,
            transaction: None,
            transaction_checkpoint: TransactionCheckpointPublisher::default(),
            execution_checkpoints: aip_runtime::ExecutionCheckpointPublisher::default(),
            stream: ActionStream::default(),
            trace: TraceContext::default(),
            redaction: RedactionPolicy::default(),
        }
    }

    #[tokio::test]
    async fn handler_routes_and_settles_remote_action() {
        let resolver = Arc::new(TestResolver::default());
        let dispatcher = Arc::new(TestDispatcher::default());
        let handler = RemoteConnectorHandler::new(
            resolver.clone(),
            dispatcher.clone(),
            CapabilityImplementationSupport {
                invocation: true,
                cancellation: true,
                ..CapabilityImplementationSupport::default()
            },
        );
        let action = Action::new(CapabilityId::trusted("cap:test:remote"), json!({}));
        let result = handler
            .handle_with_context(action.clone(), execution_context())
            .await
            .expect("remote result");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(dispatcher.invocations.lock().await.len(), 1);
        assert_eq!(
            resolver.settlements.lock().await.as_slice(),
            &[RouteSettlement::Completed]
        );
        handler
            .cancel_with_context(&action, &execution_context())
            .await
            .expect("remote cancel");
        assert_eq!(
            dispatcher.cancellations.lock().await.as_slice(),
            &[action.id]
        );
    }

    #[tokio::test]
    async fn handler_rejects_execution_without_verified_tenant() {
        let handler = RemoteConnectorHandler::new(
            Arc::new(TestResolver::default()),
            Arc::new(TestDispatcher::default()),
            CapabilityImplementationSupport {
                invocation: true,
                ..CapabilityImplementationSupport::default()
            },
        );
        let mut context = execution_context();
        context.tenant = None;
        let error = handler
            .handle_with_context(
                Action::new(CapabilityId::trusted("cap:test:remote"), json!({})),
                context,
            )
            .await
            .expect_err("tenant is mandatory");
        assert!(matches!(error, RuntimeError::Authorization(_)));
    }

    fn scheduler_limits() -> RemoteAdmissionLimits {
        RemoteAdmissionLimits {
            max_in_flight: 1,
            max_in_flight_per_tenant: 1,
            max_queued: 8,
            max_queued_per_tenant: 4,
            max_queue_bytes: 1_024,
            max_request_bytes: 512,
            max_queue_age: std::time::Duration::from_secs(1),
            tenant_weights: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn fair_scheduler_prevents_a_noisy_tenant_from_starving_a_peer() {
        let scheduler = FairAdmissionScheduler::new(scheduler_limits()).expect("scheduler");
        let active = scheduler.acquire("tenant-noisy", 1).await.expect("active");
        let (order_tx, mut order_rx) = tokio::sync::mpsc::channel(3);
        let mut waiters = Vec::new();
        for tenant in ["tenant-noisy", "tenant-noisy", "tenant-healthy"] {
            let scheduler = scheduler.clone();
            let order_tx = order_tx.clone();
            waiters.push(tokio::spawn(async move {
                let permit = scheduler.acquire(tenant, 1).await.expect("queued permit");
                order_tx
                    .send((tenant, permit))
                    .await
                    .expect("record acquisition");
            }));
            tokio::task::yield_now().await;
        }
        drop(order_tx);
        assert_eq!(scheduler.snapshot().queued, 3);
        drop(active);
        let (first_tenant, first_permit) =
            tokio::time::timeout(std::time::Duration::from_secs(1), order_rx.recv())
                .await
                .expect("first admission timeout")
                .expect("first admission");
        assert_eq!(first_tenant, "tenant-noisy");
        drop(first_permit);
        let (second_tenant, second_permit) =
            tokio::time::timeout(std::time::Duration::from_secs(1), order_rx.recv())
                .await
                .expect("second admission timeout")
                .expect("second admission");
        assert_eq!(second_tenant, "tenant-healthy");
        drop(second_permit);
        let (_third_tenant, third_permit) =
            tokio::time::timeout(std::time::Duration::from_secs(1), order_rx.recv())
                .await
                .expect("third admission timeout")
                .expect("third admission");
        drop(third_permit);
        for waiter in waiters {
            waiter.await.expect("waiter");
        }
        assert_eq!(scheduler.snapshot(), FairAdmissionSnapshot::default());
    }

    #[tokio::test]
    async fn fair_scheduler_enforces_depth_byte_and_age_bounds() {
        let mut limits = scheduler_limits();
        limits.max_queued = 2;
        limits.max_queued_per_tenant = 1;
        limits.max_queue_bytes = 10;
        limits.max_request_bytes = 8;
        // Keep expiry comfortably outside the admission-bound assertions. The
        // age limit is exercised independently below so a loaded CI runner
        // cannot expire these waiters before the queue-full check observes
        // them.
        limits.max_queue_age = std::time::Duration::from_secs(30);
        let scheduler = FairAdmissionScheduler::new(limits).expect("scheduler");
        assert_eq!(
            scheduler.acquire("tenant-a", 9).await.err(),
            Some(FairAdmissionError::RequestTooLarge)
        );
        let active = scheduler.acquire("tenant-a", 1).await.expect("active");
        let first_scheduler = scheduler.clone();
        let first = tokio::spawn(async move { first_scheduler.acquire("tenant-a", 6).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while scheduler.snapshot().queued != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first waiter should enter the queue");
        assert_eq!(
            scheduler.acquire("tenant-a", 1).await.err(),
            Some(FairAdmissionError::TenantQueueFull)
        );
        assert_eq!(
            scheduler.acquire("tenant-b", 5).await.err(),
            Some(FairAdmissionError::QueueBytesExhausted)
        );
        let second_scheduler = scheduler.clone();
        let second = tokio::spawn(async move { second_scheduler.acquire("tenant-b", 4).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while scheduler.snapshot().queued != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second waiter should enter the queue");
        assert_eq!(
            scheduler.acquire("tenant-c", 1).await.err(),
            Some(FairAdmissionError::QueueFull)
        );
        assert_eq!(scheduler.snapshot().queued, 2);

        first.abort();
        second.abort();
        assert!(matches!(first.await, Err(error) if error.is_cancelled()));
        assert!(matches!(second.await, Err(error) if error.is_cancelled()));
        assert_eq!(scheduler.snapshot().queued, 0);
        drop(active);
        assert_eq!(scheduler.snapshot(), FairAdmissionSnapshot::default());

        let mut age_limits = scheduler_limits();
        age_limits.max_queue_age = std::time::Duration::from_millis(20);
        let age_scheduler = FairAdmissionScheduler::new(age_limits).expect("age scheduler");
        let age_active = age_scheduler
            .acquire("tenant-active", 1)
            .await
            .expect("age-test active permit");
        assert_eq!(
            age_scheduler.acquire("tenant-waiting", 1).await.err(),
            Some(FairAdmissionError::QueueExpired)
        );
        assert_eq!(age_scheduler.snapshot().queued, 0);
        drop(age_active);
        assert_eq!(age_scheduler.snapshot(), FairAdmissionSnapshot::default());
    }

    #[tokio::test]
    async fn connector_event_ingress_verifies_lease_tenant_channel_and_idempotency() {
        let registry = Arc::new(InMemoryConnectorRegistry::default());
        let connector_type_id = ConnectorTypeId::trusted("ctype_event_test");
        let version_id = ConnectorVersionId::trusted("cver_event_test_v1");
        let instance_id = ConnectorInstanceId::trusted("cinst_event_test_acme");
        let replica_id = ConnectorReplicaId::trusted("crepl_event_test_one");
        registry
            .put_connector_type(ConnectorType {
                id: connector_type_id.clone(),
                name: "Event test".to_owned(),
                owner: "AIP conformance".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");
        let host_key = Arc::new(signing_key_from_seed([31; 32]));
        let mut host_principal = Principal::new(
            PrincipalId::trusted("service:connector:event-test"),
            PrincipalKind::Service,
        );
        host_principal.trust_domain = Some("connectors.test".to_owned());
        let host_signer = CallbackSigner {
            principal: host_principal.clone(),
            signing_key: host_key.clone(),
        };
        let capability_id = CapabilityId::trusted("cap:test:event-stream");
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: host_principal.clone(),
            capabilities: vec![Capability {
                id: capability_id.clone(),
                name: "Event stream test".to_owned(),
                kind: CapabilityKind::Tool,
                input_schema: json!({ "type": "object" }),
                output_schema: Some(json!({ "type": "object" })),
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
            channels: vec![json!({ "id": "orders.updated" })],
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        let manifest_digest =
            digest_json(&serde_json::to_value(&manifest).expect("manifest value"))
                .expect("manifest digest");
        registry
            .admit_version(ConnectorVersion {
                id: version_id.clone(),
                connector_type_id: connector_type_id.clone(),
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest: manifest.clone(),
                manifest_digest: manifest_digest.clone(),
                attestation: ArtifactAttestation {
                    artifact_digest: format!("sha256:{}", "1".repeat(64)),
                    schema_bundle_digest: schema_bundle_digest(&manifest)
                        .expect("schema bundle digest"),
                    sbom_digest: format!("sha256:{}", "2".repeat(64)),
                    provenance_digest: format!("sha256:{}", "3".repeat(64)),
                    conformance_report_digest: format!("sha256:{}", "4".repeat(64)),
                    vulnerability_report_digest: format!("sha256:{}", "5".repeat(64)),
                    license_report_digest: format!("sha256:{}", "6".repeat(64)),
                    signature_ref: "sigstore:event-test".to_owned(),
                    signer_identity: "https://fulcio.example/identity/event-test".to_owned(),
                    owner: "AIP conformance".to_owned(),
                    supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
                    sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
                    conformance_status: ArtifactCheckStatus::Passed,
                    vulnerability_policy_status: ArtifactCheckStatus::Passed,
                    license_policy_status: ArtifactCheckStatus::Passed,
                    revocation_status: ArtifactCheckStatus::Passed,
                },
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
        registry
            .put_instance(ConnectorInstance {
                id: instance_id.clone(),
                connector_type_id,
                version_id: version_id.clone(),
                tenant_id: "tenant-acme".to_owned(),
                config_revision: 1,
                secret_provider_ref: "vault://tenant-acme/event-test".to_owned(),
                status: ConnectorInstanceStatus::Enabled,
            })
            .await
            .expect("connector instance");
        let mut replica = ConnectorReplica {
            id: replica_id.clone(),
            instance_id: instance_id.clone(),
            version_id: version_id.clone(),
            endpoint: "https://event-test.invalid/aip/v1/messages".to_owned(),
            peer_principal_id: host_principal.id.clone(),
            peer_principal_kind: host_principal.kind,
            peer_did: did_key_from_verifying_key(&host_key.verifying_key()),
            trust_domain: "connectors.test".to_owned(),
            transport_profile: ProfileId::from("aip.native.http.v1"),
            topology: Default::default(),
            status: ConnectorReplicaStatus::Ready,
            lease_expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            capacity: 4,
            active_assignments: 0,
            health_revision: 1,
            last_control_request_id: None,
            last_control_request_digest: None,
        };
        registry
            .put_replica(replica.clone())
            .await
            .expect("connector replica");
        registry
            .put_binding(CapabilityBinding {
                tenant_id: "tenant-acme".to_owned(),
                capability_id: capability_id.clone(),
                instance_id: instance_id.clone(),
                priority: 0,
                policy_revision: 1,
                credential_revision_ref: None,
                quota_policy_ref: None,
                enabled: true,
            })
            .await
            .expect("connector binding");
        let daemon_key = Arc::new(signing_key_from_seed([32; 32]));
        let daemon_signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:getaip:server:event-ingress"),
                PrincipalKind::Service,
            ),
            signing_key: daemon_key.clone(),
        };
        let event_log = EventLog::default();
        let stream_sink = Arc::new(RecordingStreamSink::default());
        let ingress = ConnectorEventIngress::new(
            registry.clone(),
            event_log.clone(),
            daemon_signer.clone(),
            ConnectorEventIngressLimits::default(),
        )
        .expect("event ingress")
        .with_stream_callbacks(registry.clone(), stream_sink.clone());
        let request_at = |event: Event, lease_sequence: u64, sent_at: OffsetDateTime| {
            let mut envelope = Envelope::new(MessageBody::EventStream(EventStream {
                events: vec![event],
                next_cursor: None,
            }));
            envelope.sent_at = sent_at;
            envelope.to = Some(daemon_signer.principal.clone());
            envelope.security = Some(json!({
                "connector_event": {
                    "tenant_id": "tenant-acme",
                    "instance_id": instance_id,
                    "replica_id": replica_id,
                    "version_id": version_id,
                    "manifest_digest": manifest_digest,
                    "lease_sequence": lease_sequence,
                    "channel_id": "orders.updated"
                }
            }));
            sign_native_envelope(envelope, &host_signer).expect("signed connector event")
        };
        let request = |event: Event, lease_sequence: u64| {
            request_at(event, lease_sequence, OffsetDateTime::now_utc())
        };
        let mut event = Event::new("orders.updated");
        // A connector archive must preserve source chronology. Transport
        // freshness is established by the independently signed envelope.
        event.occurred_at = OffsetDateTime::UNIX_EPOCH;
        event.data = Some(json!({ "provider_order_id": "order-17" }));
        let signed = request(event.clone(), 1);
        let response = ingress.handle(&signed).await.expect("accepted event");
        assert_eq!(
            verify_native_envelope_signature(&response).expect("daemon response signature"),
            did_key_from_verifying_key(&daemon_key.verifying_key())
        );
        ingress.handle(&signed).await.expect("idempotent replay");
        replica.health_revision = 2;
        replica.lease_expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        registry
            .put_replica(replica)
            .await
            .expect("renewed connector replica");
        ingress
            .handle(&request(event.clone(), 2))
            .await
            .expect("idempotent replay after lease renewal");
        ingress
            .handle(&request(event.clone(), 1))
            .await
            .expect("durably queued replay from the prior heartbeat revision");
        let stale_transport = ingress
            .handle(&request_at(
                Event::new("orders.updated"),
                2,
                OffsetDateTime::now_utc() - Duration::hours(25),
            ))
            .await
            .expect_err("stale signed transport envelope");
        assert_eq!(stale_transport.code, "connector_event.invalid");
        assert!(stale_transport.message.contains("envelope timestamp"));
        let stored = event_log
            .stream(&EventStreamRequest {
                cursor: None,
                limit: Some(10),
                kinds: Vec::new(),
            })
            .await
            .expect("stored events");
        assert_eq!(stored.events.len(), 1);
        assert_eq!(
            stored.events[0]
                .data
                .as_ref()
                .and_then(|data| data.pointer("/identity/tenant/id"))
                .and_then(serde_json::Value::as_str),
            Some("tenant-acme")
        );
        let mut conflict = event;
        conflict.data = Some(json!({ "provider_order_id": "different" }));
        let conflict = ingress
            .handle(&request(conflict, 2))
            .await
            .expect_err("event id collision");
        assert_eq!(conflict.code, "connector_event.idempotency_conflict");
        let stale = ingress
            .handle(&request(Event::new("orders.updated"), 0))
            .await
            .expect_err("stale lease sequence");
        assert_eq!(stale.code, "connector_event.not_authorized");

        let stream_action_id = ActionId::new();
        let assignment = registry
            .resolve(RouteResolutionRequest {
                action_id: stream_action_id.clone(),
                capability_id,
                tenant_id: "tenant-acme".to_owned(),
                topology: Default::default(),
            })
            .await
            .expect("stream route assignment");
        let chunk = StreamChunk {
            action_id: stream_action_id,
            sequence: 1,
            kind: StreamChunkKind::Progress,
            data: Some(json!({ "progress": 25 })),
            part: None,
        };
        let callback_request = |route: serde_json::Value| {
            let mut envelope = Envelope::new(MessageBody::StreamChunk(chunk.clone()));
            envelope.to = Some(daemon_signer.principal.clone());
            envelope.security = Some(json!({ "connector_callback": route }));
            sign_native_envelope(envelope, &host_signer).expect("signed stream callback")
        };
        let route = connector_route_metadata(&assignment, Some(ActionMode::Streaming), None)
            .expect("route metadata");
        ingress
            .handle(&callback_request(route.clone()))
            .await
            .expect("authenticated stream callback");
        assert_eq!(
            stream_sink.chunks.lock().await.as_slice(),
            std::slice::from_ref(&chunk)
        );
        let mut tampered = route;
        tampered["fence_token"] = json!("route_tampered");
        let denied = ingress
            .handle(&callback_request(tampered))
            .await
            .expect_err("tampered route must fail");
        assert_eq!(denied.code, "connector_event.not_authorized");
    }

    #[test]
    fn connector_event_replay_equivalence_survives_delivery_and_actor_migration() {
        let provider_actor = Principal::new(
            PrincipalId::trusted("agent:provider:order-17"),
            PrincipalKind::Agent,
        );
        let mut retained = Event::new("orders.updated");
        retained.actor = Some(provider_actor.clone());
        retained.data = Some(json!({
            "provider_order_id": "order-17",
            "identity": { "tenant": { "id": "tenant-acme" } },
            "aip_connector": {
                "instance_id": "cinst_orders_acme",
                "replica_id": "crepl_orders_old_a",
                "version_id": "cver_orders_1_0_0_old",
                "channel_id": "orders.updated",
                "lease_sequence": 17
            }
        }));
        let mut candidate = retained.clone();
        candidate.actor = Some(Principal::new(
            PrincipalId::trusted("service:connector-host:orders-new-b"),
            PrincipalKind::Service,
        ));
        let candidate_data = candidate
            .data
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("candidate data");
        candidate_data.insert(
            "upstream_actor".to_owned(),
            serde_json::to_value(provider_actor).expect("provider actor"),
        );
        candidate_data.insert(
            "aip_connector".to_owned(),
            json!({
                "instance_id": "cinst_orders_acme",
                "replica_id": "crepl_orders_new_b",
                "version_id": "cver_orders_1_0_1_new",
                "channel_id": "orders.updated",
                "lease_sequence": 204
            }),
        );

        assert!(connector_event_replay_equivalent(&retained, &candidate));

        let mut changed_payload = candidate.clone();
        changed_payload
            .data
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("changed payload data")
            .insert("provider_order_id".to_owned(), json!("order-18"));
        assert!(!connector_event_replay_equivalent(
            &retained,
            &changed_payload
        ));

        let mut changed_instance = candidate;
        changed_instance
            .data
            .as_mut()
            .and_then(|data| data.get_mut("aip_connector"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("changed instance provenance")
            .insert("instance_id".to_owned(), json!("cinst_orders_other"));
        assert!(!connector_event_replay_equivalent(
            &retained,
            &changed_instance
        ));
    }

    #[tokio::test]
    async fn native_dispatcher_exchanges_signed_aip_with_pinned_peer() {
        let request_signing_key = Arc::new(signing_key_from_seed([11_u8; 32]));
        let request_signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:test-central-getaip-server"),
                PrincipalKind::Service,
            ),
            signing_key: request_signing_key.clone(),
        };
        let peer_signing_key = Arc::new(signing_key_from_seed([29_u8; 32]));
        let peer_did = did_key_from_verifying_key(&peer_signing_key.verifying_key());
        let peer_signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:test-native-connector-host"),
                PrincipalKind::Service,
            ),
            signing_key: peer_signing_key,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let app = Router::new()
            .route("/aip/v1/messages", post(native_peer))
            .with_state(NativePeerState {
                signer: peer_signer.clone(),
                expected_request_did: did_key_from_verifying_key(
                    &request_signing_key.verifying_key(),
                ),
                expected_stream_callback: Some(
                    "https://central.test/aip/v1/connector-callbacks".to_owned(),
                ),
            });
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("native peer server");
        });
        let mut policy = GatewayCallbackPolicy {
            allow_http: true,
            allow_private_networks: true,
            ..GatewayCallbackPolicy::default()
        };
        policy.allowed_hosts = HashSet::from(["127.0.0.1".to_owned()]);
        let dispatcher = NativeAipHttpDispatcher::new(request_signer, policy, 0)
            .with_stream_callback_target(
                Url::parse("https://central.test/aip/v1/connector-callbacks")
                    .expect("callback URL"),
            )
            .expect("stream callback target");
        let action = {
            let mut action = Action::new(
                CapabilityId::trusted("cap:test:native-remote"),
                json!({ "amount": 42 }),
            );
            action.mode = Some(ActionMode::Async);
            action
        };
        let assignment = RouteAssignment {
            action_id: action.id.clone(),
            capability_id: action.capability_id.clone(),
            tenant_id: "tenant-acme".to_owned(),
            instance_id: ConnectorInstanceId::trusted("cinst_native_test"),
            replica_id: ConnectorReplicaId::trusted("crepl_native_test"),
            endpoint: format!("http://{address}/aip/v1/messages"),
            peer_principal_id: peer_signer.principal.id,
            peer_principal_kind: peer_signer.principal.kind,
            peer_did,
            trust_domain: "connectors.test".to_owned(),
            transport_profile: ProfileId::from(NATIVE_HTTP_PROFILE),
            topology: Default::default(),
            version_id: ConnectorVersionId::trusted("cver_native_test"),
            manifest_digest: format!("sha256:{}", "7".repeat(64)),
            catalog_revision: aip_connector_registry::CatalogRevision(9),
            binding_policy_revision: 5,
            credential_revision_ref: Some("credential-revision-3".to_owned()),
            quota_policy_ref: Some("quota:native-test".to_owned()),
            replica_health_revision: 13,
            fence_token: "route_native_test".to_owned(),
            assigned_at: OffsetDateTime::now_utc(),
            admission: aip_connector_registry::AdmissionReservation::default(),
        };
        let result = dispatcher
            .invoke(&assignment, action, &execution_context())
            .await
            .expect("native AIP result");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|value| value.get("native_aip")),
            Some(&json!(true))
        );
        let mut streaming = Action::new(
            CapabilityId::trusted("cap:test:native-remote"),
            json!({ "amount": 43 }),
        );
        streaming.mode = Some(ActionMode::Streaming);
        streaming.callback = Some(Callback {
            profile: ProfileId::from(NATIVE_HTTP_PROFILE),
            target: "https://client.example/callback".to_owned(),
            metadata: Some(json!({ "secret": "must-not-reach-host" })),
        });
        let mut streaming_assignment = assignment;
        streaming_assignment.action_id = streaming.id.clone();
        let result = dispatcher
            .invoke(&streaming_assignment, streaming, &execution_context())
            .await
            .expect("native streaming AIP result");
        assert_eq!(result.status, ActionResultStatus::Completed);
        server.abort();
    }
}
