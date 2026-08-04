//! Product-neutral process host for one immutable AIP connector artifact.
//!
//! A host serves exactly one logical connector instance and one immutable
//! connector version. It accepts signed native AIP envelopes, keeps provider
//! secrets inside the connector process, renews a bounded registry lease, and
//! drains without changing the central `getaip-server` binary.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_auth::{
    CredentialHandle, StaticTrustedIdentityResolver, TrustedIdentityBinding, VerifiedTenant,
};
use aip_connector::{Connector, ConnectorContext, FrozenConnector, FrozenConnectorHandler};
use aip_connector_registry::{
    ConnectorInstanceStatus, ConnectorRegistryAdmin, ConnectorRegistryReader, ConnectorReplica,
    ConnectorReplicaId, ConnectorReplicaStatus, ConnectorTopology, ConnectorTypeId,
    ConnectorVersionId, ConnectorVersionStatus, RegistryError, digest_json,
    validate_artifact_attestation,
};
use aip_core::{
    Action, ApprovalDecisionKind, Callback, CapabilityId, CapabilityKind, CredentialRef, Envelope,
    ErrorBody, ErrorCategory, Event, EventStream, ExternalAccountRef, IdentityContext, Manifest,
    MessageBody, MessageId, MessageReference, Principal, ProfileId, ProtocolError,
};
use aip_crypto::{
    did_key_from_verifying_key, sign_value, verify_value, verifying_key_from_did_key,
};
use aip_gateway::{
    CallbackSigner, Gateway, GatewayCallbackDispatcher, GatewayCallbackPolicy, GatewayError,
    GatewayPolicy, NATIVE_HTTP_PROFILE, sign_native_envelope, verify_native_envelope_signature,
};
use aip_runtime::{
    ActionHandler, ApprovalRecord, ApprovalStatus, CallbackDispatcher, ProfileStateCasOutcome,
    ProfileStateEntry, ProfileStateStore, ReplayStore, Runtime, RuntimeError,
    RuntimeRecoveryConfig, RuntimeRecoveryReport, RuntimeResult, RuntimeStoreDurability,
    RuntimeStores,
};
use aip_schema::{SchemaName, SchemaRegistry};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    future::{Future, IntoFuture},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, RwLock, Semaphore, watch},
    task::JoinHandle,
};
use url::{Host, Url};

/// Default maximum canonical manifest size accepted by a connector host.
pub const DEFAULT_MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
/// Default maximum capability definitions accepted from one connector.
pub const DEFAULT_MAX_CAPABILITIES: usize = 512;
/// Default maximum native AIP request body size.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// Default connector-host lease lifetime.
pub const DEFAULT_LEASE_TTL_MS: u64 = 30_000;
/// Default connector-host heartbeat interval.
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 10_000;
/// Default maximum graceful drain duration.
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 30_000;
/// Default maximum duration of one connector-local health probe.
pub const DEFAULT_HEALTH_PROBE_TIMEOUT_MS: u64 = 2_000;
/// Exact internal HTTP path used for connector-host lifecycle operations.
pub const CONNECTOR_HOST_CONTROL_PATH: &str = "/aip/v1/connector-control";
/// Maximum signed connector-host control request or response size.
pub const MAX_CONNECTOR_HOST_CONTROL_BYTES: usize = 64 * 1024;

const CONNECTOR_HOST_CONTROL_TTL_MS: i64 = 30_000;
const CONNECTOR_HOST_CONTROL_CLOCK_SKEW_MS: i64 = 5_000;
const CONNECTOR_EVENT_OUTBOX_PREFIX: &str = "aip.connector.event_outbox.v1";
const CONNECTOR_EVENT_OUTBOX_MAX_PENDING: usize = 10_000;
const CONNECTOR_EVENT_OUTBOX_BATCH_LIMIT: usize = 100;
const CONNECTOR_EVENT_OUTBOX_LEASE_MS: i64 = 30_000;
const CONNECTOR_EVENT_OUTBOX_SCAN_LIMIT: usize = 100;

/// Non-secret credential revision policy evaluated before provider side effects.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRevisionPolicy {
    /// Revision used for newly assigned actions.
    pub current_revision_ref: Option<String>,
    /// Older pinned revisions accepted during an explicit overlap window.
    pub accepted_previous_revisions: BTreeSet<String>,
    /// Revisions denied immediately even if they were previously pinned.
    pub revoked_revisions: BTreeSet<String>,
}

impl CredentialRevisionPolicy {
    /// Validates bounded opaque references and contradictory policy entries.
    pub fn validate(&self) -> Result<(), ConnectorHostError> {
        for revision in self
            .current_revision_ref
            .iter()
            .chain(self.accepted_previous_revisions.iter())
            .chain(self.revoked_revisions.iter())
        {
            if revision.trim().is_empty() || revision.len() > 256 {
                return Err(ConnectorHostError::Configuration(
                    "credential revision references must contain 1 to 256 bytes".to_owned(),
                ));
            }
        }
        if self.current_revision_ref.as_ref().is_some_and(|revision| {
            self.revoked_revisions.contains(revision)
                || self.accepted_previous_revisions.contains(revision)
        }) || self
            .accepted_previous_revisions
            .iter()
            .any(|revision| self.revoked_revisions.contains(revision))
        {
            return Err(ConnectorHostError::Configuration(
                "credential revision policy contains overlapping current, previous, or revoked entries"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns whether a pinned revision is accepted by this validated policy.
    ///
    /// Callers must invoke [`Self::validate`] after deserialization and before
    /// using this predicate. The connector host's built-in providers enforce
    /// that ordering and fail closed when policy reload fails.
    #[must_use]
    pub fn authorizes_revision(&self, revision: Option<&str>) -> bool {
        match revision {
            Some(revision) if self.revoked_revisions.contains(revision) => false,
            Some(revision) => {
                self.current_revision_ref.as_deref() == Some(revision)
                    || self.accepted_previous_revisions.contains(revision)
            }
            None => {
                self.current_revision_ref.is_none() && self.accepted_previous_revisions.is_empty()
            }
        }
    }
}

/// Bounded non-secret coordinates supplied to credential revision policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRevisionCheck {
    /// Verified tenant fixed by the connector instance.
    pub tenant_id: String,
    /// Admitted logical connector instance.
    pub instance_id: aip_connector_registry::ConnectorInstanceId,
    /// Capability about to execute.
    pub capability_id: CapabilityId,
    /// Revision pinned by the durable route assignment.
    pub pinned_revision_ref: Option<String>,
}

/// Deployment-owned credential rotation and revocation authority.
#[async_trait]
pub trait CredentialRevisionProvider: Send + Sync {
    /// Authorizes one pinned revision immediately before a provider side effect.
    async fn authorize(
        &self,
        check: &CredentialRevisionCheck,
    ) -> Result<(), CredentialRevisionProviderError>;
}

/// Credential revision authority failure classification.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CredentialRevisionProviderError {
    /// The pinned revision is not accepted by current rotation policy.
    #[error("pinned credential revision is not authorized")]
    Denied,
    /// The revision authority could not make a reliable decision.
    #[error("credential revision authority is unavailable: {0}")]
    Unavailable(String),
}

/// Mutable non-secret provider for local deployments and conformance tests.
#[derive(Clone, Debug)]
pub struct StaticCredentialRevisionProvider {
    policy: Arc<RwLock<CredentialRevisionPolicy>>,
}

impl StaticCredentialRevisionProvider {
    /// Creates a provider from a validated initial policy.
    pub fn new(policy: CredentialRevisionPolicy) -> Result<Self, ConnectorHostError> {
        policy.validate()?;
        Ok(Self {
            policy: Arc::new(RwLock::new(policy)),
        })
    }

    /// Atomically replaces rotation and revocation policy without exposing material.
    pub async fn replace_policy(
        &self,
        policy: CredentialRevisionPolicy,
    ) -> Result<(), ConnectorHostError> {
        policy.validate()?;
        *self.policy.write().await = policy;
        Ok(())
    }
}

#[async_trait]
impl CredentialRevisionProvider for StaticCredentialRevisionProvider {
    async fn authorize(
        &self,
        check: &CredentialRevisionCheck,
    ) -> Result<(), CredentialRevisionProviderError> {
        if self
            .policy
            .read()
            .await
            .authorizes_revision(check.pinned_revision_ref.as_deref())
        {
            Ok(())
        } else {
            Err(CredentialRevisionProviderError::Denied)
        }
    }
}

/// Resource and lifecycle bounds enforced by every connector-host process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorHostLimits {
    /// Maximum canonical manifest size.
    pub max_manifest_bytes: usize,
    /// Maximum capabilities in one immutable connector version.
    pub max_capabilities: usize,
    /// Maximum native AIP request body size.
    pub max_request_bytes: usize,
    /// Maximum local in-flight actions for this replica.
    pub max_in_flight: u32,
    /// Registry lease lifetime.
    pub lease_ttl_ms: u64,
    /// Lease renewal interval.
    pub heartbeat_interval_ms: u64,
    /// Maximum graceful drain duration.
    pub drain_timeout_ms: u64,
    /// Maximum duration of one connector-local health probe.
    pub health_probe_timeout_ms: u64,
}

impl Default for ConnectorHostLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_capabilities: DEFAULT_MAX_CAPABILITIES,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_in_flight: 32,
            lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
            heartbeat_interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
            drain_timeout_ms: DEFAULT_DRAIN_TIMEOUT_MS,
            health_probe_timeout_ms: DEFAULT_HEALTH_PROBE_TIMEOUT_MS,
        }
    }
}

impl ConnectorHostLimits {
    fn validate(&self) -> Result<(), ConnectorHostError> {
        if self.max_manifest_bytes == 0
            || self.max_capabilities == 0
            || self.max_request_bytes == 0
            || self.max_in_flight == 0
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host resource limits must be greater than zero".to_owned(),
            ));
        }
        if !(1_000..=300_000).contains(&self.lease_ttl_ms) {
            return Err(ConnectorHostError::Configuration(
                "connector-host lease TTL must be between 1000 and 300000 milliseconds".to_owned(),
            ));
        }
        if self.heartbeat_interval_ms == 0
            || self.heartbeat_interval_ms.saturating_mul(2) > self.lease_ttl_ms
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host heartbeat interval must be non-zero and at most half the lease TTL"
                    .to_owned(),
            ));
        }
        if self.drain_timeout_ms == 0 || self.drain_timeout_ms > 300_000 {
            return Err(ConnectorHostError::Configuration(
                "connector-host drain timeout must be between 1 and 300000 milliseconds".to_owned(),
            ));
        }
        if self.health_probe_timeout_ms == 0 || self.health_probe_timeout_ms > 30_000 {
            return Err(ConnectorHostError::Configuration(
                "connector-host health probe timeout must be between 1 and 30000 milliseconds"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Immutable deployment identity and registry coordinates for one host replica.
#[derive(Clone)]
pub struct ConnectorHostConfig {
    /// Connector implementation type.
    pub connector_type_id: ConnectorTypeId,
    /// Admitted immutable connector version.
    pub version_id: ConnectorVersionId,
    /// Logical tenant-owned connector instance.
    pub instance_id: aip_connector_registry::ConnectorInstanceId,
    /// Concrete process replica.
    pub replica_id: ConnectorReplicaId,
    /// Public native AIP message endpoint advertised to the registry.
    pub public_endpoint: Url,
    /// Fixed verified tenant owned by this connector instance.
    pub tenant: VerifiedTenant,
    /// Optional opaque credential handle resolved only inside this process.
    pub credential: Option<CredentialHandle>,
    /// Fixed provider-account boundary owned by this connector instance.
    ///
    /// This deployment identity is projected into the trusted action identity
    /// so account-scoped idempotency never depends on caller-supplied data.
    pub external_account: Option<ExternalAccountRef>,
    /// Opaque credential revision loaded for newly assigned actions.
    pub credential_revision_ref: Option<String>,
    /// Expected non-secret instance configuration revision.
    pub config_revision: u64,
    /// Expected opaque secret-provider reference.
    pub secret_provider_ref: String,
    /// Exact immutable connector artifact digest.
    pub artifact_digest: String,
    /// Connector-host response identity and signing key.
    pub host_signer: CallbackSigner,
    /// Central gateway principal trusted to submit signed native AIP actions.
    pub gateway_principal: Principal,
    /// Central gateway signing DID.
    pub gateway_did: String,
    /// Trust domain shared by the route assignment and this host.
    pub trust_domain: String,
    /// Indexed deployment region, zone, and capacity class.
    pub topology: ConnectorTopology,
    /// Permit plaintext HTTP only for a loopback public endpoint.
    pub allow_insecure_loopback_http: bool,
    /// Resource and lifecycle bounds.
    pub limits: ConnectorHostLimits,
}

/// Fixed central callback destination and outbound policy for streamed chunks.
///
/// This is deployment configuration, not connector product configuration. The
/// callback target is shared by the fleet and the signer must be the same host
/// identity used for native AIP responses.
#[derive(Clone, Debug)]
pub struct ConnectorHostCallbackConfig {
    /// Exact central ingress endpoint for connector stream callbacks.
    pub target: Url,
    /// SSRF, timeout, response-size, and signing policy for callback delivery.
    pub policy: GatewayCallbackPolicy,
}

/// Fixed central destination for connector-owned provider events.
#[derive(Clone, Debug)]
pub struct ConnectorHostEventConfig {
    /// Exact central ingress ending in `/aip/v1/connector-events`.
    pub target: Url,
    /// SSRF, timeout, response-size, and signing policy.
    pub policy: GatewayCallbackPolicy,
}

impl ConnectorHostEventConfig {
    async fn validate(&self, host_signer: &CallbackSigner) -> Result<(), ConnectorHostError> {
        if !matches!(self.target.scheme(), "http" | "https")
            || self.target.host_str().is_none()
            || self.target.username() != ""
            || self.target.password().is_some()
            || self.target.query().is_some()
            || self.target.fragment().is_some()
            || self.target.path() != "/aip/v1/connector-events"
        {
            return Err(ConnectorHostError::Configuration(
                "connector event target must be an absolute HTTP(S) URL ending exactly in /aip/v1/connector-events without credentials, query, or fragment"
                    .to_owned(),
            ));
        }
        let signer = self.policy.signer.as_ref().ok_or_else(|| {
            ConnectorHostError::Configuration(
                "connector event policy requires the host signer".to_owned(),
            )
        })?;
        if signer.principal != host_signer.principal
            || signer.signing_key.verifying_key() != host_signer.signing_key.verifying_key()
        {
            return Err(ConnectorHostError::Configuration(
                "connector event signer must equal the native host signer".to_owned(),
            ));
        }
        self.policy
            .validate_destination(self.target.as_str())
            .await
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))
    }
}

trait ConnectorHostEventRouteState: Send + Sync {
    fn event_route(&self, channel_id: &str) -> Result<Value, ConnectorHostError>;
    fn event_recipient(&self) -> Principal;
    fn event_publish_ready(&self) -> bool;
}

/// Signed publisher used only by product-owned webhook ingress routes.
#[derive(Clone)]
pub struct ConnectorHostEventPublisher {
    inner: Arc<ConnectorHostEventPublisherInner>,
}

/// Result of accepting a provider event into the durable connector outbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorEventPublishOutcome {
    /// The central AIP ingress acknowledged the batch before the call returned.
    CentrallyAcknowledged,
    /// The batch is durable locally and the background publisher owns delivery.
    DurablyQueued,
}

impl ConnectorEventPublishOutcome {
    /// Stable diagnostic label suitable for webhook acknowledgement bodies.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CentrallyAcknowledged => "centrally_acknowledged",
            Self::DurablyQueued => "durably_queued",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConnectorEventOutboxRecord {
    channel_id: String,
    events: Vec<Event>,
    created_at_ms: i64,
    attempts: u32,
    next_attempt_at_ms: i64,
    lease_owner: Option<String>,
    lease_expires_at_ms: i64,
    last_error: Option<String>,
}

struct ConnectorHostEventPublisherInner {
    state: Arc<dyn ConnectorHostEventRouteState>,
    target: Url,
    dispatcher: GatewayCallbackDispatcher,
    profile_state: ProfileStateStore,
    namespace: String,
    worker_id: String,
    wake: Notify,
}

impl fmt::Debug for ConnectorHostEventPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorHostEventPublisher")
            .field("target", &self.inner.target)
            .field("namespace", &self.inner.namespace)
            .finish_non_exhaustive()
    }
}

impl ConnectorHostEventPublisher {
    /// Durably enqueues and immediately attempts one bounded existing-AIP event batch.
    ///
    /// A successful return proves central acknowledgement. An error after the
    /// local enqueue is safe: the shared background worker retains the exact
    /// batch and retries it after lease recovery or a transient network fault.
    /// A crash after central acknowledgement but before local deletion may
    /// resend the same event ids; the central event log deduplicates them.
    /// Provider-originated actors are projected to `data.upstream_actor` before
    /// persistence. The authenticated central ingress owns the protocol-level
    /// `event.actor` field and binds it to the connector-host signing identity.
    pub async fn publish(
        &self,
        channel_id: &str,
        events: Vec<Event>,
    ) -> Result<(), ConnectorHostError> {
        let key = self.enqueue_batch(channel_id, events).await?;
        let delivered = self.inner.deliver_key(&key).await?;
        self.inner.wake.notify_one();
        if delivered {
            Ok(())
        } else {
            Err(ConnectorHostError::Server(
                "connector event batch is durably queued but not yet centrally acknowledged"
                    .to_owned(),
            ))
        }
    }

    /// Durably accepts a provider event batch and opportunistically publishes it.
    ///
    /// A successful return proves that the exact normalized batch is present in
    /// durable connector state or was already acknowledged by central AIP. A
    /// transient central failure or a concurrent publisher lease returns
    /// [`ConnectorEventPublishOutcome::DurablyQueued`]; the background worker
    /// continues delivery without requiring the provider to retry. Errors are
    /// reserved for failures before durable local acceptance.
    pub async fn enqueue(
        &self,
        channel_id: &str,
        events: Vec<Event>,
    ) -> Result<ConnectorEventPublishOutcome, ConnectorHostError> {
        let key = self.enqueue_batch(channel_id, events).await?;
        let outcome = match self.inner.deliver_key(&key).await {
            Ok(true) => ConnectorEventPublishOutcome::CentrallyAcknowledged,
            Ok(false) | Err(_) => ConnectorEventPublishOutcome::DurablyQueued,
        };
        self.inner.wake.notify_one();
        Ok(outcome)
    }

    async fn enqueue_batch(
        &self,
        channel_id: &str,
        mut events: Vec<Event>,
    ) -> Result<String, ConnectorHostError> {
        if events.is_empty() || events.len() > CONNECTOR_EVENT_OUTBOX_BATCH_LIMIT {
            return Err(ConnectorHostError::Configuration(
                "connector event publication requires 1 to 100 events".to_owned(),
            ));
        }
        self.inner.state.event_route(channel_id)?;
        normalize_connector_events_for_publication(&mut events)?;
        for event in &events {
            aip_runtime::validate_event_record_size(event)?;
        }
        self.inner.enqueue(channel_id, events).await
    }

    /// Returns the current pending durable batches for bounded diagnostics.
    pub async fn pending_batches(&self) -> Result<usize, ConnectorHostError> {
        self.inner
            .profile_state
            .list(&self.inner.namespace, None)
            .await
            .map(|entries| entries.len())
            .map_err(ConnectorHostError::from)
    }
}

impl ConnectorHostEventPublisherInner {
    async fn enqueue(
        &self,
        channel_id: &str,
        events: Vec<Event>,
    ) -> Result<String, ConnectorHostError> {
        let batch = json!({ "channel_id": channel_id, "events": events });
        let key = digest_json(&batch)?.replace(':', "_");
        if self
            .profile_state
            .get(&self.namespace, &key)
            .await?
            .is_some()
        {
            return Ok(key);
        }
        let pending = self.profile_state.list(&self.namespace, None).await?;
        if pending.len() >= CONNECTOR_EVENT_OUTBOX_MAX_PENDING {
            return Err(ConnectorHostError::Server(
                "connector event outbox reached its bounded pending-batch capacity".to_owned(),
            ));
        }
        let record = ConnectorEventOutboxRecord {
            channel_id: channel_id.to_owned(),
            events: serde_json::from_value(batch["events"].clone()).map_err(|error| {
                ConnectorHostError::Server(format!(
                    "connector event batch encoding failed: {error}"
                ))
            })?,
            created_at_ms: now_ms(),
            attempts: 0,
            next_attempt_at_ms: now_ms(),
            lease_owner: None,
            lease_expires_at_ms: 0,
            last_error: None,
        };
        match self
            .profile_state
            .create(
                &self.namespace,
                &key,
                serde_json::to_value(record).map_err(|error| {
                    ConnectorHostError::Server(format!(
                        "connector event outbox encoding failed: {error}"
                    ))
                })?,
            )
            .await?
        {
            ProfileStateCasOutcome::Applied(_) | ProfileStateCasOutcome::Conflict(Some(_)) => {
                Ok(key)
            }
            ProfileStateCasOutcome::Conflict(None) => Err(ConnectorHostError::Server(
                "connector event outbox create conflicted without a current record".to_owned(),
            )),
        }
    }

    async fn deliver_key(&self, key: &str) -> Result<bool, ConnectorHostError> {
        let Some((entry, record)) = self.claim(key).await? else {
            return self
                .profile_state
                .get(&self.namespace, key)
                .await
                .map(|entry| entry.is_none())
                .map_err(ConnectorHostError::from);
        };
        let result = self.dispatch(&record).await;
        match result {
            Ok(()) => {
                if !self
                    .profile_state
                    .delete(&self.namespace, key, entry.revision)
                    .await?
                {
                    self.wake.notify_one();
                }
                Ok(true)
            }
            Err(error) => {
                self.release_after_failure(key, entry, record, &error)
                    .await?;
                Err(error)
            }
        }
    }

    async fn claim(
        &self,
        key: &str,
    ) -> Result<Option<(ProfileStateEntry, ConnectorEventOutboxRecord)>, ConnectorHostError> {
        for _ in 0..32 {
            let Some(entry) = self.profile_state.get(&self.namespace, key).await? else {
                return Ok(None);
            };
            let mut record = decode_outbox_record(&entry)?;
            let now = now_ms();
            if record.next_attempt_at_ms > now || record.lease_expires_at_ms > now {
                return Ok(None);
            }
            record.lease_owner = Some(self.worker_id.clone());
            record.lease_expires_at_ms = now.saturating_add(CONNECTOR_EVENT_OUTBOX_LEASE_MS);
            let value = serde_json::to_value(&record).map_err(|error| {
                ConnectorHostError::Server(format!(
                    "connector event outbox claim encoding failed: {error}"
                ))
            })?;
            match self
                .profile_state
                .compare_and_set(&self.namespace, key, Some(entry.revision), value)
                .await?
            {
                ProfileStateCasOutcome::Applied(claimed) => return Ok(Some((claimed, record))),
                ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
            }
        }
        Err(ConnectorHostError::Server(
            "connector event outbox claim remained contended after 32 attempts".to_owned(),
        ))
    }

    async fn dispatch(
        &self,
        record: &ConnectorEventOutboxRecord,
    ) -> Result<(), ConnectorHostError> {
        if !self.state.event_publish_ready() {
            return Err(ConnectorHostError::ControlPlane(
                "connector event publication requires an active ready replica lease".to_owned(),
            ));
        }
        let route = self.state.event_route(&record.channel_id)?;
        let mut events = record.events.clone();
        // Records written by hosts predating actor normalization must remain
        // recoverable after an upgrade. Reapply the idempotent projection at
        // dispatch time so the central ingress can authenticate the host as
        // the AIP event actor while preserving provider identity as data.
        normalize_connector_events_for_publication(&mut events)?;
        let mut envelope = Envelope::new(MessageBody::EventStream(EventStream {
            events,
            next_cursor: None,
        }));
        envelope.to = Some(self.state.event_recipient());
        envelope.security = Some(json!({ "connector_event": route }));
        self.dispatcher
            .dispatch(
                &Callback {
                    profile: ProfileId::from(NATIVE_HTTP_PROFILE),
                    target: self.target.to_string(),
                    metadata: None,
                },
                envelope,
            )
            .await
            .map_err(|error| ConnectorHostError::Server(error.to_string()))
    }

    async fn release_after_failure(
        &self,
        key: &str,
        entry: ProfileStateEntry,
        mut record: ConnectorEventOutboxRecord,
        error: &ConnectorHostError,
    ) -> Result<(), ConnectorHostError> {
        record.attempts = record.attempts.saturating_add(1);
        record.lease_owner = None;
        record.lease_expires_at_ms = 0;
        record.last_error = Some(bounded_detail(error.to_string()));
        let exponent = record.attempts.min(6);
        let base_ms = 1_000_i64.saturating_mul(1_i64 << exponent);
        let jitter_ms = i64::from(OsRng.next_u32() % 1_000);
        record.next_attempt_at_ms = now_ms()
            .saturating_add(base_ms.min(60_000))
            .saturating_add(jitter_ms);
        let value = serde_json::to_value(record).map_err(|encode_error| {
            ConnectorHostError::Server(format!(
                "connector event outbox retry encoding failed: {encode_error}"
            ))
        })?;
        let _ = self
            .profile_state
            .compare_and_set(&self.namespace, key, Some(entry.revision), value)
            .await?;
        self.wake.notify_one();
        Ok(())
    }
}

fn normalize_connector_events_for_publication(
    events: &mut [Event],
) -> Result<(), ConnectorHostError> {
    for event in events {
        let data = event.data.get_or_insert_with(|| json!({}));
        let data = data.as_object_mut().ok_or_else(|| {
            ConnectorHostError::Configuration(
                "connector event data must be a JSON object before central publication".to_owned(),
            )
        })?;
        let Some(upstream_actor) = event.actor.take() else {
            continue;
        };
        let upstream_actor = serde_json::to_value(upstream_actor).map_err(|error| {
            ConnectorHostError::Configuration(format!(
                "connector event upstream actor could not be encoded: {error}"
            ))
        })?;
        match data.get("upstream_actor") {
            Some(existing) if existing != &upstream_actor => {
                return Err(ConnectorHostError::Configuration(
                    "connector event upstream_actor conflicts with its provider actor".to_owned(),
                ));
            }
            Some(_) => {}
            None => {
                data.insert("upstream_actor".to_owned(), upstream_actor);
            }
        }
    }
    Ok(())
}

fn decode_outbox_record(
    entry: &ProfileStateEntry,
) -> Result<ConnectorEventOutboxRecord, ConnectorHostError> {
    let record = serde_json::from_value::<ConnectorEventOutboxRecord>(entry.value.clone())
        .map_err(|error| {
            ConnectorHostError::Server(format!(
                "connector event outbox record `{}` is invalid: {error}",
                entry.key
            ))
        })?;
    if record.channel_id.trim().is_empty()
        || record.channel_id.len() > 256
        || record.events.is_empty()
        || record.events.len() > CONNECTOR_EVENT_OUTBOX_BATCH_LIMIT
        || record.attempts > 1_000_000
    {
        return Err(ConnectorHostError::Server(format!(
            "connector event outbox record `{}` violates bounded invariants",
            entry.key
        )));
    }
    Ok(record)
}

fn spawn_event_outbox_worker(inner: &Arc<ConnectorHostEventPublisherInner>) {
    let inner = Arc::downgrade(inner);
    tokio::spawn(async move {
        connector_event_outbox_loop(inner).await;
    });
}

async fn connector_event_outbox_loop(inner: Weak<ConnectorHostEventPublisherInner>) {
    loop {
        let Some(publisher) = inner.upgrade() else {
            break;
        };
        if let Ok(entries) = publisher
            .profile_state
            .list(&publisher.namespace, None)
            .await
        {
            for entry in entries.into_iter().take(CONNECTOR_EVENT_OUTBOX_SCAN_LIMIT) {
                let _ = publisher.deliver_key(&entry.key).await;
            }
        }
        let delay_ms = 750_u64.saturating_add(u64::from(OsRng.next_u32() % 500));
        tokio::select! {
            () = publisher.wake.notified() => {}
            () = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
        }
    }
}

impl ConnectorHostCallbackConfig {
    async fn validate(&self, host_signer: &CallbackSigner) -> Result<(), ConnectorHostError> {
        if !matches!(self.target.scheme(), "http" | "https")
            || self.target.host_str().is_none()
            || self.target.username() != ""
            || self.target.password().is_some()
            || self.target.query().is_some()
            || self.target.fragment().is_some()
            || self.target.path() != "/aip/v1/connector-callbacks"
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host callback target must be an absolute HTTP(S) URL ending exactly in /aip/v1/connector-callbacks without credentials, query, or fragment"
                    .to_owned(),
            ));
        }
        let signer = self.policy.signer.as_ref().ok_or_else(|| {
            ConnectorHostError::Configuration(
                "connector-host callback policy requires the host signer".to_owned(),
            )
        })?;
        if signer.principal != host_signer.principal
            || signer.signing_key.verifying_key() != host_signer.signing_key.verifying_key()
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host callback signer must equal the native host signer".to_owned(),
            ));
        }
        self.policy
            .validate_destination(self.target.as_str())
            .await
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))
    }
}

#[derive(Clone)]
struct ConnectorHostCallbackDispatcher {
    target: String,
    inner: GatewayCallbackDispatcher,
}

#[async_trait]
impl CallbackDispatcher for ConnectorHostCallbackDispatcher {
    async fn dispatch(&self, callback: &Callback, mut envelope: Envelope) -> RuntimeResult<()> {
        if callback.profile.as_str() != NATIVE_HTTP_PROFILE || callback.target != self.target {
            return Err(RuntimeError::Authorization(
                "connector-host callback does not match the configured central ingress".to_owned(),
            ));
        }
        if !matches!(envelope.body, MessageBody::StreamChunk(_)) {
            return Err(RuntimeError::Authorization(
                "connector-host callback ingress accepts only stream chunks".to_owned(),
            ));
        }
        let route = callback
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("connector_callback"))
            .cloned()
            .ok_or_else(|| {
                RuntimeError::Authorization(
                    "connector-host callback is missing its pinned route".to_owned(),
                )
            })?;
        let recipient = callback
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("connector_callback_recipient"))
            .cloned()
            .ok_or_else(|| {
                RuntimeError::Authorization(
                    "connector-host callback is missing its central recipient".to_owned(),
                )
            })?;
        let recipient: Principal = serde_json::from_value(recipient).map_err(|error| {
            RuntimeError::Authorization(format!(
                "connector-host callback central recipient is invalid: {error}"
            ))
        })?;
        envelope.to = Some(recipient);
        envelope.security = Some(json!({ "connector_callback": route }));
        self.inner.dispatch(callback, envelope).await
    }
}

impl fmt::Debug for ConnectorHostConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorHostConfig")
            .field("connector_type_id", &self.connector_type_id)
            .field("version_id", &self.version_id)
            .field("instance_id", &self.instance_id)
            .field("replica_id", &self.replica_id)
            .field("public_endpoint", &self.public_endpoint)
            .field("tenant_id", &self.tenant.tenant.id)
            .field("config_revision", &self.config_revision)
            .field(
                "credential_revision_ref",
                &self.credential_revision_ref.as_ref().map(|_| "[OPAQUE]"),
            )
            .field("secret_provider_ref", &"[OPAQUE]")
            .field("artifact_digest", &self.artifact_digest)
            .field("host_signer", &self.host_signer)
            .field("gateway_principal", &self.gateway_principal)
            .field("gateway_did", &self.gateway_did)
            .field("trust_domain", &self.trust_domain)
            .field("topology", &self.topology)
            .field(
                "allow_insecure_loopback_http",
                &self.allow_insecure_loopback_http,
            )
            .field("limits", &self.limits)
            .finish()
    }
}

impl ConnectorHostConfig {
    fn validate(&self) -> Result<(), ConnectorHostError> {
        self.limits.validate()?;
        self.tenant
            .validate()
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))?;
        require_sha256("artifact digest", &self.artifact_digest)?;
        if self.config_revision == 0 {
            return Err(ConnectorHostError::Configuration(
                "connector-host config revision must be greater than zero".to_owned(),
            ));
        }
        if self.credential.is_some() != self.credential_revision_ref.is_some() {
            return Err(ConnectorHostError::Configuration(
                "connector-host credential handle and revision reference must be configured together"
                    .to_owned(),
            ));
        }
        if let Some(revision) = self.credential_revision_ref.as_deref()
            && (revision.trim().is_empty() || revision.len() > 256)
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host credential revision reference must contain 1 to 256 bytes"
                    .to_owned(),
            ));
        }
        if let Some(credential_tenant) = self
            .credential
            .as_ref()
            .and_then(CredentialHandle::tenant_id)
            && credential_tenant != self.tenant.tenant.id
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host credential tenant does not match the instance tenant".to_owned(),
            ));
        }
        if let Some(external_account) = self.external_account.as_ref()
            && (external_account.id.trim().is_empty()
                || external_account.id.len() > 512
                || external_account.system.trim().is_empty()
                || external_account.system.len() > 128)
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host external account id/system must contain 1 to 512/128 bytes"
                    .to_owned(),
            ));
        }
        if self.secret_provider_ref.trim().is_empty() || self.trust_domain.trim().is_empty() {
            return Err(ConnectorHostError::Configuration(
                "connector-host secret reference and trust domain must be non-empty".to_owned(),
            ));
        }
        if self.host_signer.principal.trust_domain.as_deref() != Some(self.trust_domain.as_str()) {
            return Err(ConnectorHostError::Configuration(
                "connector-host signing principal must carry the configured trust domain"
                    .to_owned(),
            ));
        }
        verifying_key_from_did_key(&self.gateway_did)
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))?;
        let endpoint = &self.public_endpoint;
        if endpoint.host_str().is_none()
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/aip/v1/messages"
        {
            return Err(ConnectorHostError::Configuration(
                "connector-host endpoint must be an absolute URL ending exactly in /aip/v1/messages without credentials, query, or fragment"
                    .to_owned(),
            ));
        }
        let loopback_host = url_host_is_loopback(endpoint);
        match endpoint.scheme() {
            "https" => {}
            "http" if self.allow_insecure_loopback_http && loopback_host => {}
            _ => {
                return Err(ConnectorHostError::Configuration(
                    "connector-host endpoint requires HTTPS except for explicitly enabled loopback development"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Binds a connector's semantic manifest identity to one deployment principal.
///
/// The returned manifest is the exact replica-independent document that must be
/// qualified, admitted, and published by every process running the same
/// immutable connector version. The signing principal's trust domain becomes
/// part of that document, but its DID does not: a DID identifies one replica
/// key and is bound separately through [`ConnectorReplica::peer_did`]. This
/// separation permits independent key rotation and horizontal scaling without
/// changing the admitted version digest.
///
/// A connector may leave `trust_domain` and `did` unset in its source manifest,
/// or pin them to the same deployment values. It cannot replace any other
/// principal field or claim a conflicting trust domain or DID.
pub fn bind_manifest_to_host_principal(
    mut manifest: Manifest,
    signing_principal: &Principal,
) -> Result<Manifest, ConnectorHostError> {
    if manifest.agent.id != signing_principal.id
        || manifest.agent.kind != signing_principal.kind
        || manifest.agent.display_name != signing_principal.display_name
        || manifest.agent.external_refs != signing_principal.external_refs
        || manifest.agent.delegated_authority != signing_principal.delegated_authority
        || manifest.agent.auth_context != signing_principal.auth_context
        || manifest
            .agent
            .trust_domain
            .as_ref()
            .is_some_and(|trust_domain| {
                Some(trust_domain) != signing_principal.trust_domain.as_ref()
            })
        || manifest
            .agent
            .did
            .as_ref()
            .is_some_and(|did| Some(did) != signing_principal.did.as_ref())
    {
        return Err(ConnectorHostError::Configuration(
            "connector manifest agent identity must match the connector-host signing principal"
                .to_owned(),
        ));
    }

    manifest.agent = signing_principal.clone();
    manifest.agent.did = None;
    Ok(manifest)
}

/// Bounded host registration presented to the trusted connector control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorHostRegistration {
    /// Complete replica identity proposed for admission.
    pub replica: ConnectorReplica,
    /// Canonical manifest digest observed by the running host.
    pub manifest_digest: String,
    /// Immutable artifact digest observed by the running host.
    pub artifact_digest: String,
    /// Tenant expected by this single-instance host.
    pub tenant_id: String,
    /// Non-secret configuration revision loaded by this host.
    pub config_revision: u64,
    /// Opaque secret-provider reference loaded by this host.
    pub secret_provider_ref: String,
    /// Number of capability contracts loaded into the process.
    pub capability_count: u32,
}

/// Bounded heartbeat sent by a registered connector-host replica.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorHostHeartbeat {
    /// Registered replica.
    pub replica_id: ConnectorReplicaId,
    /// Last lease sequence observed by the host.
    pub previous_sequence: u64,
    /// Current local in-flight execution count.
    pub in_flight: u32,
    /// Whether the connector's own health probe is ready.
    pub connector_ready: bool,
}

/// Graceful lifecycle transition requested by a connector host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorHostTransition {
    /// Registered replica.
    pub replica_id: ConnectorReplicaId,
    /// Last lease sequence observed by the host.
    pub previous_sequence: u64,
}

/// Lease granted by the trusted connector control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorHostLease {
    /// Monotonic replica health revision.
    pub sequence: u64,
    /// Absolute lease expiry.
    pub expires_at: OffsetDateTime,
}

/// Connector-host registration and heartbeat abstraction.
#[async_trait]
pub trait ConnectorHostControlPlane: Send + Sync {
    /// Idempotently verifies the admitted version and creates the replica lease.
    async fn register_once(
        &self,
        request_id: MessageId,
        registration: ConnectorHostRegistration,
    ) -> Result<ConnectorHostLease, ConnectorHostError>;

    /// Idempotently renews one bounded replica lease.
    async fn heartbeat_once(
        &self,
        request_id: MessageId,
        heartbeat: ConnectorHostHeartbeat,
    ) -> Result<ConnectorHostLease, ConnectorHostError>;

    /// Idempotently stops new assignments while retaining pinned work.
    async fn drain_once(
        &self,
        request_id: MessageId,
        transition: ConnectorHostTransition,
    ) -> Result<ConnectorHostLease, ConnectorHostError>;

    /// Idempotently marks a drained or failed process offline.
    async fn offline_once(
        &self,
        request_id: MessageId,
        transition: ConnectorHostTransition,
    ) -> Result<(), ConnectorHostError>;

    /// Verifies the admitted version and instance, then creates the replica lease.
    async fn register(
        &self,
        registration: ConnectorHostRegistration,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        self.register_once(MessageId::new(), registration).await
    }

    /// Renews one bounded replica lease.
    async fn heartbeat(
        &self,
        heartbeat: ConnectorHostHeartbeat,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        self.heartbeat_once(MessageId::new(), heartbeat).await
    }

    /// Stops new assignments while retaining pinned work.
    async fn drain(
        &self,
        transition: ConnectorHostTransition,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        self.drain_once(MessageId::new(), transition).await
    }

    /// Marks a drained or failed process offline.
    async fn offline(&self, transition: ConnectorHostTransition) -> Result<(), ConnectorHostError> {
        self.offline_once(MessageId::new(), transition).await
    }
}

/// Direct registry-backed control plane used by trusted colocated deployments.
///
/// Remote deployments can implement [`ConnectorHostControlPlane`] over an
/// authenticated control-plane API without changing connector-host lifecycle.
#[derive(Clone)]
pub struct RegistryConnectorHostControlPlane {
    registry: Arc<dyn ConnectorRegistryAdmin>,
    lease_ttl_ms: u64,
}

impl fmt::Debug for RegistryConnectorHostControlPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryConnectorHostControlPlane")
            .field("lease_ttl_ms", &self.lease_ttl_ms)
            .finish_non_exhaustive()
    }
}

impl RegistryConnectorHostControlPlane {
    /// Creates a direct trusted control plane around a durable registry.
    pub fn new(
        registry: Arc<dyn ConnectorRegistryAdmin>,
        lease_ttl_ms: u64,
    ) -> Result<Self, ConnectorHostError> {
        if !(1_000..=300_000).contains(&lease_ttl_ms) {
            return Err(ConnectorHostError::Configuration(
                "registry connector-host lease TTL must be between 1000 and 300000 milliseconds"
                    .to_owned(),
            ));
        }
        Ok(Self {
            registry,
            lease_ttl_ms,
        })
    }

    fn lease_expiry(&self) -> OffsetDateTime {
        canonical_control_time(
            OffsetDateTime::now_utc()
                + time::Duration::milliseconds(self.lease_ttl_ms.min(i64::MAX as u64) as i64),
        )
    }

    async fn transition_replica(
        &self,
        request_id: &MessageId,
        request_digest: &str,
        transition: ConnectorHostTransition,
        status: ConnectorReplicaStatus,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        for _ in 0..4 {
            let mut replica = self
                .registry
                .connector_replica(&transition.replica_id)
                .await?
                .ok_or_else(|| {
                    ConnectorHostError::Admission(format!(
                        "connector replica `{}` is not registered",
                        transition.replica_id
                    ))
                })?;
            if replica.last_control_request_id.as_ref() == Some(request_id) {
                if replica.last_control_request_digest.as_deref() != Some(request_digest) {
                    return Err(ConnectorHostError::Admission(
                        "connector-host lifecycle request id was reused with a different payload"
                            .to_owned(),
                    ));
                }
                if replica.status != status
                    || transition
                        .previous_sequence
                        .checked_add(1)
                        .is_none_or(|sequence| sequence != replica.health_revision)
                {
                    return Err(ConnectorHostError::Admission(
                        "connector-host lifecycle replay does not match the committed transition"
                            .to_owned(),
                    ));
                }
                return Ok(ConnectorHostLease {
                    sequence: replica.health_revision,
                    expires_at: replica.lease_expires_at,
                });
            }
            if replica.health_revision != transition.previous_sequence {
                return Err(ConnectorHostError::Admission(
                    "connector-host transition lost its lease-sequence fence".to_owned(),
                ));
            }
            replica.status = status;
            replica.health_revision = replica.health_revision.saturating_add(1);
            replica.last_control_request_id = Some(request_id.clone());
            replica.last_control_request_digest = Some(request_digest.to_owned());
            replica.lease_expires_at = if status == ConnectorReplicaStatus::Offline {
                canonical_control_time(OffsetDateTime::now_utc())
            } else {
                self.lease_expiry()
            };
            match self.registry.put_replica(replica.clone()).await {
                Ok(()) => {
                    return Ok(ConnectorHostLease {
                        sequence: replica.health_revision,
                        expires_at: replica.lease_expires_at,
                    });
                }
                Err(RegistryError::Conflict(_)) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ConnectorHostError::ControlPlane(
            "replica lifecycle update exceeded its bounded conflict retry budget".to_owned(),
        ))
    }
}

#[async_trait]
impl ConnectorHostControlPlane for RegistryConnectorHostControlPlane {
    async fn register_once(
        &self,
        request_id: MessageId,
        registration: ConnectorHostRegistration,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        let request_digest = lifecycle_request_digest(&request_id, "register", &registration)?;
        let version = self
            .registry
            .connector_version(&registration.replica.version_id)
            .await?
            .ok_or_else(|| {
                ConnectorHostError::Admission(format!(
                    "connector version `{}` is not admitted",
                    registration.replica.version_id
                ))
            })?;
        if version.status != ConnectorVersionStatus::Active {
            return Err(ConnectorHostError::Admission(
                "connector version is not active for new replicas".to_owned(),
            ));
        }
        validate_artifact_attestation(&version.attestation, &version.manifest)?;
        if version.manifest_digest != registration.manifest_digest
            || version.attestation.artifact_digest != registration.artifact_digest
        {
            return Err(ConnectorHostError::Admission(
                "running connector artifact or manifest digest does not match the admitted version"
                    .to_owned(),
            ));
        }
        let instance = self
            .registry
            .connector_instance(&registration.replica.instance_id)
            .await?
            .ok_or_else(|| {
                ConnectorHostError::Admission(format!(
                    "connector instance `{}` is not registered",
                    registration.replica.instance_id
                ))
            })?;
        if version.connector_type_id != instance.connector_type_id {
            return Err(ConnectorHostError::Admission(
                "connector instance type does not match the admitted version".to_owned(),
            ));
        }
        if instance.status != ConnectorInstanceStatus::Enabled
            || instance.version_id != registration.replica.version_id
            || instance.tenant_id != registration.tenant_id
            || instance.config_revision != registration.config_revision
            || instance.secret_provider_ref != registration.secret_provider_ref
        {
            return Err(ConnectorHostError::Admission(
                "running connector-host instance configuration does not match the enabled registry record"
                    .to_owned(),
            ));
        }
        let expected_capabilities =
            u32::try_from(version.manifest.capabilities.len()).map_err(|_| {
                ConnectorHostError::Admission("admitted capability count exceeds u32".to_owned())
            })?;
        if expected_capabilities != registration.capability_count {
            return Err(ConnectorHostError::Admission(
                "running connector-host capability count does not match the admitted version"
                    .to_owned(),
            ));
        }
        let proposed_replica = registration.replica;
        if proposed_replica.status != ConnectorReplicaStatus::Ready
            || proposed_replica.active_assignments != 0
            || proposed_replica.health_revision != 0
            || proposed_replica.last_control_request_id.is_some()
            || proposed_replica.last_control_request_digest.is_some()
        {
            return Err(ConnectorHostError::Admission(
                "a connector-host registration proposal must be ready with zero active assignments, health revision zero, and no committed lifecycle request"
                    .to_owned(),
            ));
        }
        if version.manifest.agent.id != proposed_replica.peer_principal_id
            || version.manifest.agent.kind != proposed_replica.peer_principal_kind
        {
            return Err(ConnectorHostError::Admission(
                "connector-host peer principal does not match the admitted manifest agent"
                    .to_owned(),
            ));
        }
        for _ in 0..4 {
            let mut replica = proposed_replica.clone();
            replica.health_revision = match self.registry.connector_replica(&replica.id).await? {
                Some(existing) => {
                    if existing.last_control_request_id.as_ref() == Some(&request_id) {
                        if existing.last_control_request_digest.as_deref()
                            != Some(request_digest.as_str())
                        {
                            return Err(ConnectorHostError::Admission(
                                "connector-host registration request id was reused with a different payload"
                                    .to_owned(),
                            ));
                        }
                        if existing.status != ConnectorReplicaStatus::Ready {
                            return Err(ConnectorHostError::Admission(
                                "connector-host registration replay does not match the committed state"
                                    .to_owned(),
                            ));
                        }
                        return Ok(ConnectorHostLease {
                            sequence: existing.health_revision,
                            expires_at: existing.lease_expires_at,
                        });
                    }
                    let lease_expired = existing.lease_expires_at <= OffsetDateTime::now_utc();
                    let clean_offline = existing.status == ConnectorReplicaStatus::Offline
                        && existing.active_assignments == 0;
                    if !clean_offline && !lease_expired {
                        return Err(ConnectorHostError::Admission(
                            "an existing connector-host replica may re-register only after a clean offline transition or lease expiry"
                                .to_owned(),
                        ));
                    }
                    if existing.active_assignments > replica.capacity {
                        return Err(ConnectorHostError::Admission(
                            "connector-host recovery capacity is below its durable active assignment count"
                                .to_owned(),
                        ));
                    }
                    // A hard-killed process cannot settle its routes or mark
                    // itself offline. Once its lease expires, the same
                    // immutable replica identity may take over after durable
                    // runtime recovery. Preserve registry-owned reservations;
                    // their original action fences remain valid until each
                    // recovered attempt settles exactly once.
                    replica.active_assignments = existing.active_assignments;
                    existing.health_revision.checked_add(1).ok_or_else(|| {
                        ConnectorHostError::Admission(
                            "connector-host replica health revision is exhausted".to_owned(),
                        )
                    })?
                }
                None => 1,
            };
            replica.lease_expires_at = self.lease_expiry();
            replica.last_control_request_id = Some(request_id.clone());
            replica.last_control_request_digest = Some(request_digest.clone());
            match self.registry.put_replica(replica.clone()).await {
                Ok(()) => {
                    return Ok(ConnectorHostLease {
                        sequence: replica.health_revision,
                        expires_at: replica.lease_expires_at,
                    });
                }
                Err(RegistryError::Conflict(_)) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ConnectorHostError::ControlPlane(
            "replica registration exceeded its bounded conflict retry budget".to_owned(),
        ))
    }

    async fn heartbeat_once(
        &self,
        request_id: MessageId,
        heartbeat: ConnectorHostHeartbeat,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        let request_digest = lifecycle_request_digest(&request_id, "heartbeat", &heartbeat)?;
        let replica = self
            .registry
            .connector_replica(&heartbeat.replica_id)
            .await?
            .ok_or_else(|| {
                ConnectorHostError::Admission(format!(
                    "connector replica `{}` is not registered",
                    heartbeat.replica_id
                ))
            })?;
        if heartbeat.in_flight > replica.capacity {
            return Err(ConnectorHostError::Admission(
                "connector-host heartbeat reports in-flight work above admitted capacity"
                    .to_owned(),
            ));
        }
        if !heartbeat.connector_ready {
            return self
                .transition_replica(
                    &request_id,
                    &request_digest,
                    ConnectorHostTransition {
                        replica_id: heartbeat.replica_id,
                        previous_sequence: heartbeat.previous_sequence,
                    },
                    ConnectorReplicaStatus::Offline,
                )
                .await;
        }
        self.transition_replica(
            &request_id,
            &request_digest,
            ConnectorHostTransition {
                replica_id: heartbeat.replica_id,
                previous_sequence: heartbeat.previous_sequence,
            },
            ConnectorReplicaStatus::Ready,
        )
        .await
    }

    async fn drain_once(
        &self,
        request_id: MessageId,
        transition: ConnectorHostTransition,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        let request_digest = lifecycle_request_digest(&request_id, "drain", &transition)?;
        self.transition_replica(
            &request_id,
            &request_digest,
            transition,
            ConnectorReplicaStatus::Draining,
        )
        .await
    }

    async fn offline_once(
        &self,
        request_id: MessageId,
        transition: ConnectorHostTransition,
    ) -> Result<(), ConnectorHostError> {
        let request_digest = lifecycle_request_digest(&request_id, "offline", &transition)?;
        self.transition_replica(
            &request_id,
            &request_digest,
            transition,
            ConnectorReplicaStatus::Offline,
        )
        .await
        .map(|_| ())
    }
}

fn canonical_control_time(value: OffsetDateTime) -> OffsetDateTime {
    let milliseconds = value.unix_timestamp_nanos().div_euclid(1_000_000);
    OffsetDateTime::from_unix_timestamp_nanos(milliseconds.saturating_mul(1_000_000))
        .unwrap_or(value)
}

fn lifecycle_request_digest<T>(
    request_id: &MessageId,
    operation: &'static str,
    payload: &T,
) -> Result<String, ConnectorHostError>
where
    T: Serialize,
{
    let payload = serde_json::to_value(payload)
        .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
    digest_json(&json!({
        "request_id": request_id,
        "operation": operation,
        "payload": payload,
    }))
    .map_err(ConnectorHostError::from)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
enum ConnectorHostControlCommand {
    Register(Box<ConnectorHostRegistration>),
    Heartbeat(ConnectorHostHeartbeat),
    Drain(ConnectorHostTransition),
    Offline(ConnectorHostTransition),
}

impl ConnectorHostControlCommand {
    fn replica_id(&self) -> &ConnectorReplicaId {
        match self {
            Self::Register(registration) => &registration.replica.id,
            Self::Heartbeat(heartbeat) => &heartbeat.replica_id,
            Self::Drain(transition) | Self::Offline(transition) => &transition.replica_id,
        }
    }

    fn request_digest(&self, request_id: &MessageId) -> Result<String, ConnectorHostError> {
        match self {
            Self::Register(registration) => {
                lifecycle_request_digest(request_id, "register", registration.as_ref())
            }
            Self::Heartbeat(heartbeat) => {
                lifecycle_request_digest(request_id, "heartbeat", heartbeat)
            }
            Self::Drain(transition) => lifecycle_request_digest(request_id, "drain", transition),
            Self::Offline(transition) => {
                lifecycle_request_digest(request_id, "offline", transition)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConnectorHostControlRequest {
    request_id: MessageId,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    signer_did: String,
    command: ConnectorHostControlCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedConnectorHostControlRequest {
    request: ConnectorHostControlRequest,
    signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ConnectorHostControlOutcome {
    Lease {
        lease: ConnectorHostLease,
    },
    Offline,
    Rejected {
        code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConnectorHostControlResponse {
    request_id: MessageId,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    signer_did: String,
    outcome: ConnectorHostControlOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedConnectorHostControlResponse {
    response: ConnectorHostControlResponse,
    signature: String,
}

struct ConnectorHostControlPlaneHttpState {
    control_plane: Arc<dyn ConnectorHostControlPlane>,
    registry: Arc<dyn ConnectorRegistryReader>,
    replay: ReplayStore,
    signer: CallbackSigner,
    signer_did: String,
}

/// Authenticated narrow HTTP service for connector-host lifecycle operations.
///
/// The service exposes only registration, heartbeat, drain, and offline
/// transitions. Remote hosts never receive a registry administrator or direct
/// database credential. Every replica identity, including its signing DID,
/// must be pre-provisioned in the registry in the offline state.
#[derive(Clone)]
pub struct ConnectorHostControlPlaneHttpService {
    state: Arc<ConnectorHostControlPlaneHttpState>,
}

impl fmt::Debug for ConnectorHostControlPlaneHttpService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorHostControlPlaneHttpService")
            .field("signer_did", &self.state.signer_did)
            .finish_non_exhaustive()
    }
}

impl ConnectorHostControlPlaneHttpService {
    /// Creates a lifecycle service around a narrow control-plane implementation
    /// and a read-only registry identity view.
    #[must_use]
    pub fn new<R>(
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        registry: Arc<R>,
        replay: ReplayStore,
        signer: CallbackSigner,
    ) -> Self
    where
        R: ConnectorRegistryReader + 'static,
    {
        let signer_did = did_key_from_verifying_key(&signer.signing_key.verifying_key());
        Self {
            state: Arc::new(ConnectorHostControlPlaneHttpState {
                control_plane,
                registry,
                replay,
                signer,
                signer_did,
            }),
        }
    }

    /// Creates a bounded router that can be mounted by the central daemon.
    pub fn router(&self) -> Router {
        Router::new()
            .route(CONNECTOR_HOST_CONTROL_PATH, post(connector_host_control))
            .layer(DefaultBodyLimit::max(MAX_CONNECTOR_HOST_CONTROL_BYTES))
            .with_state(self.state.clone())
    }
}

/// Signed HTTP client that gives a connector host only narrow lifecycle access.
#[derive(Clone)]
pub struct HttpConnectorHostControlPlane {
    endpoint: Url,
    client: reqwest::Client,
    host_signer: CallbackSigner,
    host_did: String,
    control_plane_did: String,
}

impl fmt::Debug for HttpConnectorHostControlPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpConnectorHostControlPlane")
            .field("endpoint", &self.endpoint)
            .field("host_did", &self.host_did)
            .field("control_plane_did", &self.control_plane_did)
            .finish_non_exhaustive()
    }
}

impl HttpConnectorHostControlPlane {
    /// Creates a fixed-destination client with redirects disabled and bounded
    /// request and response time.
    pub fn new(
        endpoint: Url,
        host_signer: CallbackSigner,
        control_plane_did: String,
        allow_insecure_loopback_http: bool,
        request_timeout_ms: u64,
    ) -> Result<Self, ConnectorHostError> {
        Self::new_with_tls_ca(
            endpoint,
            host_signer,
            control_plane_did,
            allow_insecure_loopback_http,
            request_timeout_ms,
            None,
        )
    }

    /// Creates a fixed-destination client with one additional private-PKI root.
    ///
    /// Public roots remain enabled and certificate and hostname verification
    /// remain mandatory. The extra root is intended for enterprise ingress or
    /// service-mesh TLS, not for bypassing transport authentication.
    pub fn new_with_tls_ca(
        endpoint: Url,
        host_signer: CallbackSigner,
        control_plane_did: String,
        allow_insecure_loopback_http: bool,
        request_timeout_ms: u64,
        tls_ca_certificate_pem: Option<&[u8]>,
    ) -> Result<Self, ConnectorHostError> {
        validate_control_endpoint(&endpoint, allow_insecure_loopback_http)?;
        if !(1..=30_000).contains(&request_timeout_ms) {
            return Err(ConnectorHostError::Configuration(
                "connector control-plane timeout must be between 1 and 30000 milliseconds"
                    .to_owned(),
            ));
        }
        verifying_key_from_did_key(&control_plane_did)
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(request_timeout_ms));
        if let Some(pem) = tls_ca_certificate_pem {
            if pem.is_empty() || pem.len() > 1024 * 1024 {
                return Err(ConnectorHostError::Configuration(
                    "connector control-plane TLS CA must contain 1 byte to 1 MiB".to_owned(),
                ));
            }
            let certificate = reqwest::Certificate::from_pem(pem).map_err(|error| {
                ConnectorHostError::Configuration(format!(
                    "connector control-plane TLS CA is invalid: {error}"
                ))
            })?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder
            .build()
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))?;
        let host_did = did_key_from_verifying_key(&host_signer.signing_key.verifying_key());
        Ok(Self {
            endpoint,
            client,
            host_signer,
            host_did,
            control_plane_did,
        })
    }

    fn signed_request(
        &self,
        request_id: MessageId,
        command: ConnectorHostControlCommand,
    ) -> Result<SignedConnectorHostControlRequest, ConnectorHostError> {
        let issued_at = OffsetDateTime::now_utc();
        let request = ConnectorHostControlRequest {
            request_id,
            issued_at,
            expires_at: issued_at + time::Duration::milliseconds(CONNECTOR_HOST_CONTROL_TTL_MS),
            signer_did: self.host_did.clone(),
            command,
        };
        let value = serde_json::to_value(&request)
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
        let signature = sign_value(&value, &self.host_signer.signing_key)
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
        Ok(SignedConnectorHostControlRequest { request, signature })
    }

    async fn invoke_once(
        &self,
        request_id: MessageId,
        command: ConnectorHostControlCommand,
    ) -> Result<ConnectorHostControlOutcome, ConnectorHostError> {
        let request = self.signed_request(request_id.clone(), command)?;
        let body = serde_json::to_vec(&request)
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
        if body.len() > MAX_CONNECTOR_HOST_CONTROL_BYTES {
            return Err(ConnectorHostError::Configuration(
                "signed connector control-plane request exceeds the maximum size".to_owned(),
            ));
        }
        match self.send_signed_body(&request_id, &body).await {
            Err(ConnectorHostError::ControlPlane(_)) => {
                self.send_signed_body(&request_id, &body).await
            }
            outcome => outcome,
        }
    }

    async fn send_signed_body(
        &self,
        request_id: &MessageId,
        body: &[u8],
    ) -> Result<ConnectorHostControlOutcome, ConnectorHostError> {
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CONNECTOR_HOST_CONTROL_BYTES as u64)
        {
            return Err(ConnectorHostError::ControlPlane(
                "connector control-plane response exceeds the maximum size".to_owned(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_CONNECTOR_HOST_CONTROL_BYTES {
                return Err(ConnectorHostError::ControlPlane(
                    "connector control-plane response exceeds the maximum size".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let signed: SignedConnectorHostControlResponse = serde_json::from_slice(&body)
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
        if &signed.response.request_id != request_id {
            return Err(ConnectorHostError::Admission(
                "connector control-plane response request id does not match".to_owned(),
            ));
        }
        if signed.response.signer_did != self.control_plane_did {
            return Err(ConnectorHostError::Admission(
                "connector control-plane response signer is not trusted".to_owned(),
            ));
        }
        validate_control_window(signed.response.issued_at, signed.response.expires_at)?;
        let key = verifying_key_from_did_key(&self.control_plane_did)
            .map_err(|error| ConnectorHostError::Admission(error.to_string()))?;
        let value = serde_json::to_value(&signed.response)
            .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
        verify_value(&value, &signed.signature, &key).map_err(|_| {
            ConnectorHostError::Admission(
                "connector control-plane response signature is invalid".to_owned(),
            )
        })?;
        match signed.response.outcome {
            ConnectorHostControlOutcome::Rejected {
                message,
                retryable: true,
                ..
            } => Err(ConnectorHostError::ControlPlane(message)),
            ConnectorHostControlOutcome::Rejected { message, .. } => {
                Err(ConnectorHostError::Admission(message))
            }
            outcome => Ok(outcome),
        }
    }
}

#[async_trait]
impl ConnectorHostControlPlane for HttpConnectorHostControlPlane {
    async fn register_once(
        &self,
        request_id: MessageId,
        registration: ConnectorHostRegistration,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        match self
            .invoke_once(
                request_id,
                ConnectorHostControlCommand::Register(Box::new(registration)),
            )
            .await?
        {
            ConnectorHostControlOutcome::Lease { lease } => Ok(lease),
            _ => Err(ConnectorHostError::ControlPlane(
                "connector registration returned an unexpected outcome".to_owned(),
            )),
        }
    }

    async fn heartbeat_once(
        &self,
        request_id: MessageId,
        heartbeat: ConnectorHostHeartbeat,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        match self
            .invoke_once(
                request_id,
                ConnectorHostControlCommand::Heartbeat(heartbeat),
            )
            .await?
        {
            ConnectorHostControlOutcome::Lease { lease } => Ok(lease),
            _ => Err(ConnectorHostError::ControlPlane(
                "connector heartbeat returned an unexpected outcome".to_owned(),
            )),
        }
    }

    async fn drain_once(
        &self,
        request_id: MessageId,
        transition: ConnectorHostTransition,
    ) -> Result<ConnectorHostLease, ConnectorHostError> {
        match self
            .invoke_once(request_id, ConnectorHostControlCommand::Drain(transition))
            .await?
        {
            ConnectorHostControlOutcome::Lease { lease } => Ok(lease),
            _ => Err(ConnectorHostError::ControlPlane(
                "connector drain returned an unexpected outcome".to_owned(),
            )),
        }
    }

    async fn offline_once(
        &self,
        request_id: MessageId,
        transition: ConnectorHostTransition,
    ) -> Result<(), ConnectorHostError> {
        match self
            .invoke_once(request_id, ConnectorHostControlCommand::Offline(transition))
            .await?
        {
            ConnectorHostControlOutcome::Offline => Ok(()),
            _ => Err(ConnectorHostError::ControlPlane(
                "connector offline transition returned an unexpected outcome".to_owned(),
            )),
        }
    }
}

async fn connector_host_control(
    State(state): State<Arc<ConnectorHostControlPlaneHttpState>>,
    Json(signed): Json<SignedConnectorHostControlRequest>,
) -> Response {
    let request_id = signed.request.request_id.clone();
    let outcome = process_connector_host_control(&state, signed).await;
    let (status, outcome) = match outcome {
        Ok(outcome) => (StatusCode::OK, outcome),
        Err(error) => {
            let (code, retryable, status) = match error {
                ConnectorHostError::Admission(_) | ConnectorHostError::Configuration(_) => {
                    ("connector_control.rejected", false, StatusCode::FORBIDDEN)
                }
                _ => (
                    "connector_control.unavailable",
                    true,
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
            };
            (
                status,
                ConnectorHostControlOutcome::Rejected {
                    code: code.to_owned(),
                    message: bounded_detail(error.to_string()),
                    retryable,
                },
            )
        }
    };
    match signed_control_response(&state, request_id, outcome) {
        Ok(response) => (status, Json(response)).into_response(),
        Err(error) => unsigned_input_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connector_control.response_signing",
            error.to_string(),
        ),
    }
}

async fn process_connector_host_control(
    state: &ConnectorHostControlPlaneHttpState,
    signed: SignedConnectorHostControlRequest,
) -> Result<ConnectorHostControlOutcome, ConnectorHostError> {
    validate_control_window(signed.request.issued_at, signed.request.expires_at)?;
    let replica_id = signed.request.command.replica_id();
    let expected = state
        .registry
        .connector_replica(replica_id)
        .await?
        .ok_or_else(|| {
            ConnectorHostError::Admission(format!(
                "connector replica `{replica_id}` is not pre-provisioned"
            ))
        })?;
    if signed.request.signer_did != expected.peer_did {
        return Err(ConnectorHostError::Admission(
            "connector control request signer does not match the pre-provisioned replica"
                .to_owned(),
        ));
    }
    let key = verifying_key_from_did_key(&expected.peer_did)
        .map_err(|error| ConnectorHostError::Admission(error.to_string()))?;
    let value = serde_json::to_value(&signed.request)
        .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
    verify_value(&value, &signed.signature, &key).map_err(|_| {
        ConnectorHostError::Admission("connector control request signature is invalid".to_owned())
    })?;
    let request_id = signed.request.request_id.clone();
    let request_digest = signed.request.command.request_digest(&request_id)?;
    let first_seen = state
        .replay
        .claim(
            signed.request.request_id.as_str(),
            signed.request.expires_at,
        )
        .await
        .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
    if !first_seen
        && (expected.last_control_request_id.as_ref() != Some(&request_id)
            || expected.last_control_request_digest.as_deref() != Some(request_digest.as_str()))
    {
        return Err(ConnectorHostError::Admission(
            "connector control request id was already consumed by another lifecycle state"
                .to_owned(),
        ));
    }
    match signed.request.command {
        ConnectorHostControlCommand::Register(registration) => state
            .control_plane
            .register_once(request_id, *registration)
            .await
            .map(|lease| ConnectorHostControlOutcome::Lease { lease }),
        ConnectorHostControlCommand::Heartbeat(heartbeat) => state
            .control_plane
            .heartbeat_once(request_id, heartbeat)
            .await
            .map(|lease| ConnectorHostControlOutcome::Lease { lease }),
        ConnectorHostControlCommand::Drain(transition) => state
            .control_plane
            .drain_once(request_id, transition)
            .await
            .map(|lease| ConnectorHostControlOutcome::Lease { lease }),
        ConnectorHostControlCommand::Offline(transition) => state
            .control_plane
            .offline_once(request_id, transition)
            .await
            .map(|()| ConnectorHostControlOutcome::Offline),
    }
}

fn signed_control_response(
    state: &ConnectorHostControlPlaneHttpState,
    request_id: MessageId,
    outcome: ConnectorHostControlOutcome,
) -> Result<SignedConnectorHostControlResponse, ConnectorHostError> {
    let issued_at = OffsetDateTime::now_utc();
    let response = ConnectorHostControlResponse {
        request_id,
        issued_at,
        expires_at: issued_at + time::Duration::milliseconds(CONNECTOR_HOST_CONTROL_TTL_MS),
        signer_did: state.signer_did.clone(),
        outcome,
    };
    let value = serde_json::to_value(&response)
        .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
    let signature = sign_value(&value, &state.signer.signing_key)
        .map_err(|error| ConnectorHostError::ControlPlane(error.to_string()))?;
    Ok(SignedConnectorHostControlResponse {
        response,
        signature,
    })
}

fn validate_control_window(
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), ConnectorHostError> {
    let now = OffsetDateTime::now_utc();
    let maximum_future = now + time::Duration::milliseconds(CONNECTOR_HOST_CONTROL_CLOCK_SKEW_MS);
    if issued_at > maximum_future || expires_at <= now || expires_at <= issued_at {
        return Err(ConnectorHostError::Admission(
            "connector control message is expired or outside the accepted clock skew".to_owned(),
        ));
    }
    if expires_at - issued_at > time::Duration::milliseconds(CONNECTOR_HOST_CONTROL_TTL_MS) {
        return Err(ConnectorHostError::Admission(
            "connector control message lifetime exceeds the maximum".to_owned(),
        ));
    }
    Ok(())
}

fn validate_control_endpoint(
    endpoint: &Url,
    allow_insecure_loopback_http: bool,
) -> Result<(), ConnectorHostError> {
    if endpoint.host_str().is_none()
        || endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != CONNECTOR_HOST_CONTROL_PATH
    {
        return Err(ConnectorHostError::Configuration(
            "connector control-plane endpoint must be absolute, use the exact control path, and contain no credentials, query, or fragment"
                .to_owned(),
        ));
    }
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure_loopback_http && url_host_is_loopback(endpoint) => {
            Ok(())
        }
        _ => Err(ConnectorHostError::Configuration(
            "connector control-plane endpoint requires HTTPS except for explicitly enabled loopback development"
                .to_owned(),
        )),
    }
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Connector-host construction, admission, transport, or lifecycle failure.
#[derive(Debug, Error)]
pub enum ConnectorHostError {
    /// Invalid deployment configuration.
    #[error("connector-host configuration failed: {0}")]
    Configuration(String),
    /// Connector discovery or readiness failed.
    #[error("connector-host connector failed: {0}")]
    Connector(String),
    /// The running artifact did not match an admitted version or instance.
    #[error("connector-host admission failed: {0}")]
    Admission(String),
    /// Registry or control-plane operation failed.
    #[error("connector-host control plane failed: {0}")]
    ControlPlane(String),
    /// Native AIP gateway construction failed.
    #[error("connector-host gateway failed: {0}")]
    Gateway(String),
    /// HTTP serving failed.
    #[error("connector-host server failed: {0}")]
    Server(String),
}

impl From<RegistryError> for ConnectorHostError {
    fn from(error: RegistryError) -> Self {
        Self::ControlPlane(error.to_string())
    }
}

impl From<GatewayError> for ConnectorHostError {
    fn from(error: GatewayError) -> Self {
        Self::Gateway(error.to_string())
    }
}

impl From<RuntimeError> for ConnectorHostError {
    fn from(error: RuntimeError) -> Self {
        Self::Server(format!(
            "durable connector-host runtime state failed: {error}"
        ))
    }
}

#[derive(Default)]
struct ConnectorHostMetrics {
    requests_total: AtomicU64,
    rejected_total: AtomicU64,
    heartbeat_failures_total: AtomicU64,
    lease_recovery_attempts_total: AtomicU64,
    lease_recoveries_total: AtomicU64,
    in_flight: AtomicU64,
}

#[derive(Clone)]
struct PendingLeaseRecovery {
    request_id: MessageId,
    registration: ConnectorHostRegistration,
}

struct ConnectorHostState<C> {
    config: ConnectorHostConfig,
    callback_target: Option<String>,
    connector: Arc<C>,
    gateway: Gateway,
    runtime: Runtime,
    recovery: ConnectorHostRecoverySummary,
    manifest: Manifest,
    manifest_digest: String,
    control_plane: Arc<dyn ConnectorHostControlPlane>,
    credential_revisions: Arc<dyn CredentialRevisionProvider>,
    capacity: Arc<Semaphore>,
    draining: AtomicBool,
    connector_ready: AtomicBool,
    storage_ready: AtomicBool,
    lease_sequence: AtomicU64,
    lease_expires_at_ms: AtomicI64,
    pending_lease_recovery: Mutex<Option<PendingLeaseRecovery>>,
    metrics: ConnectorHostMetrics,
}

impl<C> ConnectorHostEventRouteState for ConnectorHostState<C>
where
    C: Send + Sync,
{
    fn event_route(&self, channel_id: &str) -> Result<Value, ConnectorHostError> {
        if channel_id.trim().is_empty() || channel_id.len() > 256 {
            return Err(ConnectorHostError::Configuration(
                "connector event channel id must contain 1 to 256 bytes".to_owned(),
            ));
        }
        let declared = self.manifest.channels.iter().any(|channel| match channel {
            Value::String(value) => value == channel_id,
            Value::Object(value) => {
                value
                    .get("id")
                    .or_else(|| value.get("channel_id"))
                    .and_then(Value::as_str)
                    == Some(channel_id)
            }
            _ => false,
        });
        if !declared {
            return Err(ConnectorHostError::Admission(format!(
                "connector event channel `{channel_id}` is not declared by the admitted manifest"
            )));
        }
        Ok(json!({
            "tenant_id": self.config.tenant.tenant.id,
            "instance_id": self.config.instance_id,
            "replica_id": self.config.replica_id,
            "version_id": self.config.version_id,
            "manifest_digest": self.manifest_digest,
            "lease_sequence": self.lease_sequence.load(Ordering::Acquire),
            "channel_id": channel_id
        }))
    }

    fn event_recipient(&self) -> Principal {
        self.config.gateway_principal.clone()
    }

    fn event_publish_ready(&self) -> bool {
        !self.draining.load(Ordering::Acquire)
            && self.lease_valid()
            && self.storage_ready.load(Ordering::Acquire)
            && self.connector_ready.load(Ordering::Acquire)
    }
}

/// Bounded, non-secret evidence from connector-host runtime recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectorHostRecoverySummary {
    /// Time at which recovery started.
    pub recovered_at: OffsetDateTime,
    /// Pending approvals retained for operator or human continuation.
    pub pending_approvals: usize,
    /// Transactions retained for reconciliation.
    pub recoverable_transactions: usize,
    /// Queued actions completed during recovery.
    pub queued_results: usize,
    /// Delegations completed during recovery.
    pub delegation_results: usize,
    /// Callback deliveries resumed during recovery.
    pub callback_deliveries: usize,
}

impl ConnectorHostRecoverySummary {
    fn from_report(report: &RuntimeRecoveryReport) -> Self {
        Self {
            recovered_at: report.recovered_at,
            pending_approvals: report.pending_approvals.len(),
            recoverable_transactions: report.recoverable_transactions.len(),
            queued_results: report.queued_results.len(),
            delegation_results: report.delegation_results.len(),
            callback_deliveries: report.callback_deliveries.len(),
        }
    }
}

impl<C> ConnectorHostState<C> {
    fn lease_valid(&self) -> bool {
        self.lease_expires_at_ms.load(Ordering::Acquire) > now_ms()
    }

    fn apply_lease(&self, lease: &ConnectorHostLease) -> Result<(), ConnectorHostError> {
        self.lease_sequence.store(lease.sequence, Ordering::Release);
        self.lease_expires_at_ms.store(
            datetime_ms(lease.expires_at).map_err(ConnectorHostError::ControlPlane)?,
            Ordering::Release,
        );
        Ok(())
    }

    fn transition(&self) -> ConnectorHostTransition {
        ConnectorHostTransition {
            replica_id: self.config.replica_id.clone(),
            previous_sequence: self.lease_sequence.load(Ordering::Acquire),
        }
    }
}

/// Running product-neutral host for one frozen connector instance.
pub struct ConnectorHost<C> {
    state: Arc<ConnectorHostState<C>>,
}

impl<C> fmt::Debug for ConnectorHost<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorHost")
            .field("config", &self.state.config)
            .field("manifest_digest", &self.state.manifest_digest)
            .finish_non_exhaustive()
    }
}

impl<C> ConnectorHost<C>
where
    C: FrozenConnector + 'static,
{
    /// Builds a fail-closed native AIP host without opening a listener.
    pub async fn build(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        stores: RuntimeStores,
    ) -> Result<Self, ConnectorHostError> {
        let credential_revisions = Arc::new(StaticCredentialRevisionProvider::new(
            CredentialRevisionPolicy {
                current_revision_ref: config.credential_revision_ref.clone(),
                ..CredentialRevisionPolicy::default()
            },
        )?);
        Self::build_with_credential_revision_provider(
            config,
            connector,
            control_plane,
            stores,
            credential_revisions,
        )
        .await
    }

    /// Builds a host with a deployment-owned rotation and revocation authority.
    pub async fn build_with_credential_revision_provider(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        stores: RuntimeStores,
        credential_revisions: Arc<dyn CredentialRevisionProvider>,
    ) -> Result<Self, ConnectorHostError> {
        Self::build_internal(
            config,
            connector,
            control_plane,
            Runtime::with_stores(stores),
            credential_revisions,
            None,
            true,
        )
        .await
    }

    /// Builds a host with authenticated stream delivery to one fixed central
    /// callback ingress.
    pub async fn build_with_callbacks(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        stores: RuntimeStores,
        callbacks: ConnectorHostCallbackConfig,
    ) -> Result<Self, ConnectorHostError> {
        let credential_revisions = Arc::new(StaticCredentialRevisionProvider::new(
            CredentialRevisionPolicy {
                current_revision_ref: config.credential_revision_ref.clone(),
                ..CredentialRevisionPolicy::default()
            },
        )?);
        Self::build_internal(
            config,
            connector,
            control_plane,
            Runtime::with_stores(stores),
            credential_revisions,
            Some(callbacks),
            true,
        )
        .await
    }

    /// Builds a host with deployment-owned credential revision policy and
    /// authenticated stream delivery to one fixed central callback ingress.
    pub async fn build_with_credential_revision_provider_and_callbacks(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        stores: RuntimeStores,
        credential_revisions: Arc<dyn CredentialRevisionProvider>,
        callbacks: ConnectorHostCallbackConfig,
    ) -> Result<Self, ConnectorHostError> {
        Self::build_internal(
            config,
            connector,
            control_plane,
            Runtime::with_stores(stores),
            credential_revisions,
            Some(callbacks),
            true,
        )
        .await
    }

    /// Builds a production host from an explicitly composed durable runtime.
    ///
    /// This constructor is intended for trusted embedders that install
    /// process-local runtime extensions such as bounded execution-checkpoint
    /// telemetry. It performs the same durability, storage-readiness,
    /// admission, recovery, and connector checks as the standard production
    /// constructors. Passing an ephemeral runtime is rejected.
    pub async fn build_with_runtime_extensions(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        runtime: Runtime,
        credential_revisions: Arc<dyn CredentialRevisionProvider>,
        callbacks: Option<ConnectorHostCallbackConfig>,
    ) -> Result<Self, ConnectorHostError> {
        Self::build_internal(
            config,
            connector,
            control_plane,
            runtime,
            credential_revisions,
            callbacks,
            true,
        )
        .await
    }

    /// Builds an explicitly ephemeral host for tests or local development.
    ///
    /// The method is absent from normal production builds. Enabling the
    /// `development-in-memory` feature is an auditable decision and the
    /// resulting host reports `ephemeral` durability in readiness output.
    #[cfg(any(test, feature = "development-in-memory"))]
    pub async fn build_in_memory_for_development(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
    ) -> Result<Self, ConnectorHostError> {
        let credential_revisions = Arc::new(StaticCredentialRevisionProvider::new(
            CredentialRevisionPolicy {
                current_revision_ref: config.credential_revision_ref.clone(),
                ..CredentialRevisionPolicy::default()
            },
        )?);
        Self::build_internal(
            config,
            connector,
            control_plane,
            Runtime::new(),
            credential_revisions,
            None,
            false,
        )
        .await
    }

    #[cfg(test)]
    async fn build_in_memory_for_test_with_credential_revision_provider(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        credential_revisions: Arc<dyn CredentialRevisionProvider>,
    ) -> Result<Self, ConnectorHostError> {
        Self::build_internal(
            config,
            connector,
            control_plane,
            Runtime::new(),
            credential_revisions,
            None,
            false,
        )
        .await
    }

    async fn build_internal(
        config: ConnectorHostConfig,
        connector: C,
        control_plane: Arc<dyn ConnectorHostControlPlane>,
        runtime: Runtime,
        credential_revisions: Arc<dyn CredentialRevisionProvider>,
        callbacks: Option<ConnectorHostCallbackConfig>,
        require_durable: bool,
    ) -> Result<Self, ConnectorHostError> {
        config.validate()?;
        if require_durable && !runtime.store_durability().is_durable() {
            return Err(ConnectorHostError::Configuration(
                "production connector hosts require durable RuntimeStores; process-local memory is available only through the explicit development constructor"
                    .to_owned(),
            ));
        }
        probe_runtime_storage(&runtime, config.limits.health_probe_timeout_ms).await?;
        if let Some(callbacks) = callbacks.as_ref() {
            callbacks.validate(&config.host_signer).await?;
        }
        let connector = Arc::new(connector);
        let discovery_context = connector_context(&config);
        let mut manifest = connector
            .discover(&discovery_context)
            .await
            .map_err(|error| ConnectorHostError::Connector(error.to_string()))?;
        manifest = bind_manifest_to_host_principal(manifest, &config.host_signer.principal)?;
        if manifest.capabilities.len() > config.limits.max_capabilities {
            return Err(ConnectorHostError::Configuration(format!(
                "connector manifest has {} capabilities; host limit is {}",
                manifest.capabilities.len(),
                config.limits.max_capabilities
            )));
        }
        let manifest_value = serde_json::to_value(&manifest)
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))?;
        let manifest_bytes = aip_crypto::canonical_json_bytes(&manifest_value)
            .map_err(|error| ConnectorHostError::Configuration(error.to_string()))?;
        if manifest_bytes.len() > config.limits.max_manifest_bytes {
            return Err(ConnectorHostError::Configuration(format!(
                "connector manifest is {} bytes; host limit is {}",
                manifest_bytes.len(),
                config.limits.max_manifest_bytes
            )));
        }
        let manifest_digest = digest_json(&manifest_value)?;
        let mut handlers = HashMap::<CapabilityId, Arc<dyn ActionHandler>>::new();
        for capability in &manifest.capabilities {
            if capability.kind == CapabilityKind::Resource {
                continue;
            }
            let handler: Arc<dyn ActionHandler> = Arc::new(FrozenConnectorHandler::new(
                connector.clone(),
                capability.clone(),
            ));
            if handlers.insert(capability.id.clone(), handler).is_some() {
                return Err(ConnectorHostError::Configuration(format!(
                    "connector manifest contains duplicate capability `{}`",
                    capability.id
                )));
            }
        }
        // The host never trusts `Action.identity` from the wire directly. It
        // resolves the authenticated central gateway to the tenant and opaque
        // credential fixed by this deployment, then projects that verified
        // state back into the action seen by the connector. This is essential
        // because the runtime deliberately replaces payload identity claims
        // with the resolver result before invoking a handler.
        let resolved_identity = IdentityContext {
            tenant: Some(config.tenant.tenant.clone()),
            external_account: config.external_account.clone(),
            external_user: None,
            human_actor: None,
            service_account: Some(config.gateway_principal.clone()),
            acted_on_behalf_of: None,
            credential_ref: config.credential.as_ref().map(|credential| CredentialRef {
                id: credential.id().to_owned(),
                issuer: credential.issuer().to_owned(),
                scopes: credential.scopes().iter().cloned().collect(),
            }),
            oauth: None,
        };
        let resolver = StaticTrustedIdentityResolver::new([TrustedIdentityBinding {
            principal_id: config.gateway_principal.id.clone(),
            tenant: Some(config.tenant.clone()),
            credential: config.credential.clone(),
            identity: Some(resolved_identity),
            revision: config.config_revision,
            revoked: false,
            expires_at: None,
        }]);
        let callback_target = callbacks
            .as_ref()
            .map(|callbacks| callbacks.target.to_string());
        let gateway = if let Some(callbacks) = callbacks {
            Gateway::with_policy_runtime_callback_and_handlers(
                manifest.clone(),
                GatewayPolicy::default(),
                runtime.clone(),
                ConnectorHostCallbackDispatcher {
                    target: callbacks.target.to_string(),
                    inner: GatewayCallbackDispatcher::with_policy(
                        aip_transport_sse::SseTransport::new(),
                        callbacks.policy,
                    ),
                },
                handlers,
            )
            .await?
        } else {
            Gateway::with_policy_runtime_callback_and_handlers(
                manifest.clone(),
                GatewayPolicy::default(),
                runtime.clone(),
                GatewayCallbackDispatcher::default(),
                handlers,
            )
            .await?
        }
        .with_identity_resolver(Arc::new(resolver));
        gateway
            .register_trusted_signer(config.gateway_did.clone(), config.gateway_principal.clone())
            .await;
        gateway.register_connector_arc(connector.clone()).await;
        let recovery_report = runtime
            .recover_runtime_state(RuntimeRecoveryConfig::default())
            .await
            .map_err(|error| {
                ConnectorHostError::Admission(format!(
                    "durable runtime recovery failed before replica registration: {error}"
                ))
            })?;
        validate_recovery_report(&recovery_report)?;
        let recovery = ConnectorHostRecoverySummary::from_report(&recovery_report);
        let capacity = Arc::new(Semaphore::new(
            usize::try_from(config.limits.max_in_flight).map_err(|_| {
                ConnectorHostError::Configuration(
                    "connector-host in-flight limit exceeds usize".to_owned(),
                )
            })?,
        ));
        Ok(Self {
            state: Arc::new(ConnectorHostState {
                config,
                callback_target,
                connector,
                gateway,
                runtime,
                recovery,
                manifest,
                manifest_digest,
                control_plane,
                credential_revisions,
                capacity,
                draining: AtomicBool::new(false),
                connector_ready: AtomicBool::new(false),
                storage_ready: AtomicBool::new(true),
                lease_sequence: AtomicU64::new(0),
                lease_expires_at_ms: AtomicI64::new(0),
                pending_lease_recovery: Mutex::new(None),
                metrics: ConnectorHostMetrics::default(),
            }),
        })
    }

    /// Returns the immutable manifest served by this host.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.state.manifest
    }

    /// Returns the canonical manifest digest used during control-plane admission.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.state.manifest_digest
    }

    /// Returns the durability contract enforced for this host runtime.
    #[must_use]
    pub fn runtime_store_durability(&self) -> RuntimeStoreDurability {
        self.state.runtime.store_durability()
    }

    /// Returns bounded evidence produced before the replica became ready.
    #[must_use]
    pub fn recovery_summary(&self) -> &ConnectorHostRecoverySummary {
        &self.state.recovery
    }

    /// Creates a signed publisher for product-owned provider event ingress.
    pub async fn event_publisher(
        &self,
        config: ConnectorHostEventConfig,
    ) -> Result<ConnectorHostEventPublisher, ConnectorHostError> {
        config.validate(&self.state.config.host_signer).await?;
        let namespace = format!(
            "{CONNECTOR_EVENT_OUTBOX_PREFIX}.{}",
            self.state.config.instance_id
        );
        if namespace.len() > 255 {
            return Err(ConnectorHostError::Configuration(
                "connector event outbox namespace exceeds the runtime storage limit".to_owned(),
            ));
        }
        let inner = Arc::new(ConnectorHostEventPublisherInner {
            state: self.state.clone(),
            target: config.target,
            dispatcher: GatewayCallbackDispatcher::with_policy(
                aip_transport_sse::SseTransport::new(),
                config.policy,
            ),
            profile_state: self.state.runtime.profile_state.clone(),
            namespace,
            worker_id: self.state.config.replica_id.to_string(),
            wake: Notify::new(),
        });
        spawn_event_outbox_worker(&inner);
        Ok(ConnectorHostEventPublisher { inner })
    }

    /// Creates the bounded native AIP router for this host.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/health", get(host_health))
            .route("/ready", get(host_ready::<C>))
            .route("/metrics", get(host_metrics::<C>))
            .route("/aip/v1/manifest", get(host_manifest::<C>))
            .route("/aip/v1/messages", post(host_message::<C>))
            .layer(DefaultBodyLimit::max(
                self.state.config.limits.max_request_bytes,
            ))
            .with_state(self.state.clone())
    }

    /// Registers the running immutable artifact and activates its bounded lease.
    pub async fn register(&self) -> Result<ConnectorHostLease, ConnectorHostError> {
        probe_runtime_storage(
            &self.state.runtime,
            self.state.config.limits.health_probe_timeout_ms,
        )
        .await?;
        self.state.storage_ready.store(true, Ordering::Release);
        let (ready, detail) = probe_connector_health(&self.state).await;
        if !ready {
            return Err(ConnectorHostError::Connector(detail));
        }
        self.state.connector_ready.store(true, Ordering::Release);
        let lease = self
            .state
            .control_plane
            .register(connector_host_registration(&self.state)?)
            .await?;
        self.state.apply_lease(&lease)?;
        Ok(lease)
    }

    /// Begins local and registry draining without stopping the listener.
    pub async fn begin_drain(&self) -> Result<ConnectorHostLease, ConnectorHostError> {
        self.state.draining.store(true, Ordering::Release);
        let lease = self
            .state
            .control_plane
            .drain(self.state.transition())
            .await?;
        self.state.apply_lease(&lease)?;
        Ok(lease)
    }

    /// Serves until the caller's shutdown future resolves, then drains and marks the replica offline.
    pub async fn serve_until<F>(
        self,
        listener: TcpListener,
        shutdown: F,
    ) -> Result<(), ConnectorHostError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.serve_with_router_until(listener, Router::new(), shutdown)
            .await
    }

    /// Serves the common native AIP surface plus product-owned ingress routes.
    ///
    /// Additional routes are intended for authenticated provider webhooks.
    /// They remain in the product host and never expand the central `getaip-server`
    /// router. Axum rejects duplicate routes during composition, protecting the
    /// host's health, readiness, metrics, manifest, and native message paths.
    pub async fn serve_with_router_until<F>(
        self,
        listener: TcpListener,
        additional_routes: Router,
        shutdown: F,
    ) -> Result<(), ConnectorHostError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.register().await?;
        let (heartbeat_stop, heartbeat_stop_rx) = watch::channel(false);
        let heartbeat = spawn_heartbeat(self.state.clone(), heartbeat_stop_rx);
        let (server_stop, server_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let router = self.router().merge(additional_routes);
        let server = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = server_stop_rx.await;
            })
            .into_future();
        tokio::pin!(server);
        tokio::pin!(shutdown);
        let mut drain_result = None;
        let server_result = tokio::select! {
            result = &mut server => result,
            () = &mut shutdown => {
                drain_result = Some(self.begin_drain().await.map(|_| ()));
                wait_for_drain(&self.state).await;
                let _ = server_stop.send(());
                server.await
            }
        };
        let _ = heartbeat_stop.send(true);
        let heartbeat_result = heartbeat.await;
        let offline_result = self
            .state
            .control_plane
            .offline(self.state.transition())
            .await;
        let mut failures = Vec::new();
        if let Err(error) = server_result {
            failures.push(format!("HTTP server: {error}"));
        }
        if let Err(error) = heartbeat_result {
            failures.push(format!("heartbeat worker: {error}"));
        }
        if let Some(Err(error)) = drain_result {
            failures.push(format!("registry drain: {error}"));
        }
        if let Err(error) = offline_result {
            failures.push(format!("registry offline transition: {error}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ConnectorHostError::Server(failures.join("; ")))
        }
    }
}

fn spawn_heartbeat<C>(
    state: Arc<ConnectorHostState<C>>,
    mut stop: watch::Receiver<bool>,
) -> JoinHandle<()>
where
    C: Connector + 'static,
{
    tokio::spawn(async move {
        let heartbeat_interval_ms = state.config.limits.heartbeat_interval_ms;
        let initial_delay = heartbeat_initial_delay(heartbeat_interval_ms, OsRng.next_u64());
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + initial_delay,
            Duration::from_millis(heartbeat_interval_ms),
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if state.draining.load(Ordering::Acquire) {
                        continue;
                    }
                    let (connector_ready, _) = probe_connector_health(&state).await;
                    let (storage_ready, _) = runtime_storage_health(
                        &state.runtime,
                        state.config.limits.health_probe_timeout_ms,
                    )
                    .await;
                    state
                        .connector_ready
                        .store(connector_ready, Ordering::Release);
                    state.storage_ready.store(storage_ready, Ordering::Release);
                    let in_flight = u32::try_from(state.metrics.in_flight.load(Ordering::Acquire))
                        .unwrap_or(u32::MAX);
                    if renew_or_recover_host_lease(
                        &state,
                        connector_ready && storage_ready,
                        in_flight,
                    )
                    .await
                    .is_err()
                    {
                        state
                            .metrics
                            .heartbeat_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    })
}

fn connector_host_registration<C>(
    state: &ConnectorHostState<C>,
) -> Result<ConnectorHostRegistration, ConnectorHostError> {
    let capability_count = u32::try_from(state.manifest.capabilities.len()).map_err(|_| {
        ConnectorHostError::Configuration("capability count exceeds u32".to_owned())
    })?;
    let host_did =
        did_key_from_verifying_key(&state.config.host_signer.signing_key.verifying_key());
    let proposed_expiry = OffsetDateTime::now_utc()
        + time::Duration::milliseconds(state.config.limits.lease_ttl_ms.min(i64::MAX as u64) as i64);
    Ok(ConnectorHostRegistration {
        replica: ConnectorReplica {
            id: state.config.replica_id.clone(),
            instance_id: state.config.instance_id.clone(),
            version_id: state.config.version_id.clone(),
            endpoint: state.config.public_endpoint.to_string(),
            peer_principal_id: state.config.host_signer.principal.id.clone(),
            peer_principal_kind: state.config.host_signer.principal.kind,
            peer_did: host_did,
            trust_domain: state.config.trust_domain.clone(),
            transport_profile: aip_core::ProfileId::from(NATIVE_HTTP_PROFILE),
            topology: state.config.topology.clone(),
            status: ConnectorReplicaStatus::Ready,
            lease_expires_at: proposed_expiry,
            capacity: state.config.limits.max_in_flight,
            active_assignments: 0,
            health_revision: 0,
            last_control_request_id: None,
            last_control_request_digest: None,
        },
        manifest_digest: state.manifest_digest.clone(),
        artifact_digest: state.config.artifact_digest.clone(),
        tenant_id: state.config.tenant.tenant.id.clone(),
        config_revision: state.config.config_revision,
        secret_provider_ref: state.config.secret_provider_ref.clone(),
        capability_count,
    })
}

async fn renew_or_recover_host_lease<C>(
    state: &ConnectorHostState<C>,
    ready: bool,
    in_flight: u32,
) -> Result<(), ConnectorHostError> {
    if !state.lease_valid() {
        if !ready {
            return Ok(());
        }
        return recover_expired_host_lease(state).await;
    }

    let lease = state
        .control_plane
        .heartbeat(ConnectorHostHeartbeat {
            replica_id: state.config.replica_id.clone(),
            previous_sequence: state.lease_sequence.load(Ordering::Acquire),
            in_flight,
            connector_ready: ready,
        })
        .await?;
    state.apply_lease(&lease)
}

async fn recover_expired_host_lease<C>(
    state: &ConnectorHostState<C>,
) -> Result<(), ConnectorHostError> {
    state
        .metrics
        .lease_recovery_attempts_total
        .fetch_add(1, Ordering::Relaxed);
    let pending = {
        let mut pending = state.pending_lease_recovery.lock().await;
        if pending.is_none() {
            *pending = Some(PendingLeaseRecovery {
                request_id: MessageId::new(),
                registration: connector_host_registration(state)?,
            });
        }
        pending.as_ref().cloned().ok_or_else(|| {
            ConnectorHostError::ControlPlane(
                "connector-host lease recovery state was not initialized".to_owned(),
            )
        })?
    };

    match state
        .control_plane
        .register_once(pending.request_id.clone(), pending.registration)
        .await
    {
        Ok(lease) => {
            state.apply_lease(&lease)?;
            *state.pending_lease_recovery.lock().await = None;
            state
                .metrics
                .lease_recoveries_total
                .fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(error @ ConnectorHostError::Admission(_))
        | Err(error @ ConnectorHostError::Configuration(_)) => {
            // A rejected request is consumed by the replay guard but did not
            // commit a lease. A later attempt therefore needs a fresh request
            // identity. The registry still enforces immutable identity,
            // capacity, and live-lease fencing before allowing takeover.
            *state.pending_lease_recovery.lock().await = None;
            Err(error)
        }
        Err(error) => {
            // Keep the exact request and registration payload across an
            // ambiguous transport/control-plane failure. If the server
            // committed before the response was lost, the next attempt is an
            // idempotent replay instead of a second lifecycle mutation.
            Err(error)
        }
    }
}

/// Spreads the first lease renewal across a bounded window around the normal
/// heartbeat interval. The upper bound remains below the lease TTL because
/// validated host configuration limits the base interval to half the TTL.
fn heartbeat_initial_delay(base_interval_ms: u64, random_sample: u64) -> Duration {
    let lower_bound_ms = base_interval_ms.saturating_mul(3) / 4;
    let window_ms = base_interval_ms / 2;
    let offset_ms = random_sample % window_ms.saturating_add(1);
    Duration::from_millis(lower_bound_ms.saturating_add(offset_ms))
}

async fn wait_for_drain<C>(state: &ConnectorHostState<C>) {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(state.config.limits.drain_timeout_ms);
    while state.metrics.in_flight.load(Ordering::Acquire) > 0
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn probe_connector_health<C>(state: &ConnectorHostState<C>) -> (bool, String)
where
    C: Connector + 'static,
{
    let result = tokio::time::timeout(
        Duration::from_millis(state.config.limits.health_probe_timeout_ms),
        state.connector.health(&connector_context(&state.config)),
    )
    .await;
    match result {
        Ok(Ok(health)) => (health.ready, bounded_detail(health.detail)),
        Ok(Err(error)) => (false, bounded_detail(error.to_string())),
        Err(_) => (
            false,
            format!(
                "connector health probe exceeded {} milliseconds",
                state.config.limits.health_probe_timeout_ms
            ),
        ),
    }
}

fn connector_context(config: &ConnectorHostConfig) -> ConnectorContext {
    ConnectorContext {
        tenant_id: Some(config.tenant.tenant.id.clone()),
        metadata: std::collections::BTreeMap::from([
            (
                "connector_instance_id".to_owned(),
                config.instance_id.to_string(),
            ),
            (
                "connector_replica_id".to_owned(),
                config.replica_id.to_string(),
            ),
            (
                "config_revision".to_owned(),
                config.config_revision.to_string(),
            ),
        ]),
    }
}

async fn runtime_storage_health(runtime: &Runtime, timeout_ms: u64) -> (bool, &'static str) {
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        runtime.storage_health.check(),
    )
    .await
    {
        Ok(Ok(())) => (true, "durable runtime storage is readable and writable"),
        Ok(Err(_)) => (false, "durable runtime storage readiness check failed"),
        Err(_) => (false, "durable runtime storage readiness check timed out"),
    }
}

async fn probe_runtime_storage(
    runtime: &Runtime,
    timeout_ms: u64,
) -> Result<(), ConnectorHostError> {
    let (ready, detail) = runtime_storage_health(runtime, timeout_ms).await;
    if ready {
        Ok(())
    } else {
        Err(ConnectorHostError::Admission(detail.to_owned()))
    }
}

fn validate_recovery_report(report: &RuntimeRecoveryReport) -> Result<(), ConnectorHostError> {
    if report.queued_errors.is_empty() && report.delegation_errors.is_empty() {
        return Ok(());
    }
    Err(ConnectorHostError::Admission(format!(
        "durable runtime recovery produced {} queued-action error(s) and {} delegation error(s); replica admission is blocked",
        report.queued_errors.len(),
        report.delegation_errors.len()
    )))
}

async fn host_health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "protocol": "AIP",
        "version": "1.0",
        "service": "aip-connector-host"
    }))
}

async fn host_ready<C>(State(state): State<Arc<ConnectorHostState<C>>>) -> Response
where
    C: Connector + 'static,
{
    let draining = state.draining.load(Ordering::Acquire);
    let lease_valid = state.lease_valid();
    let (storage_ready, storage_detail) =
        runtime_storage_health(&state.runtime, state.config.limits.health_probe_timeout_ms).await;
    state.storage_ready.store(storage_ready, Ordering::Release);
    let (connector_ready, detail) = probe_connector_health(&state).await;
    state
        .connector_ready
        .store(connector_ready, Ordering::Release);
    let ready = !draining && lease_valid && storage_ready && connector_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "lease_valid": lease_valid,
            "draining": draining,
            "runtime": {
                "durability": state.runtime.store_durability(),
                "ready": storage_ready,
                "detail": storage_detail,
                "recovery": state.recovery
            },
            "connector": {
                "ready": connector_ready,
                "detail": detail
            }
        })),
    )
        .into_response()
}

async fn host_manifest<C>(State(state): State<Arc<ConnectorHostState<C>>>) -> Json<Manifest> {
    Json(state.manifest.clone())
}

async fn host_metrics<C>(State(state): State<Arc<ConnectorHostState<C>>>) -> Response {
    let ready = !state.draining.load(Ordering::Acquire)
        && state.lease_valid()
        && state.storage_ready.load(Ordering::Acquire)
        && state.connector_ready.load(Ordering::Acquire);
    let body = format!(
        concat!(
            "# TYPE aip_connector_host_ready gauge\n",
            "aip_connector_host_ready {}\n",
            "# TYPE aip_connector_host_storage_ready gauge\n",
            "aip_connector_host_storage_ready {}\n",
            "# TYPE aip_connector_host_in_flight gauge\n",
            "aip_connector_host_in_flight {}\n",
            "# TYPE aip_connector_host_requests_total counter\n",
            "aip_connector_host_requests_total {}\n",
            "# TYPE aip_connector_host_rejected_total counter\n",
            "aip_connector_host_rejected_total {}\n",
            "# TYPE aip_connector_host_heartbeat_failures_total counter\n",
            "aip_connector_host_heartbeat_failures_total {}\n",
            "# TYPE aip_connector_host_lease_recovery_attempts_total counter\n",
            "aip_connector_host_lease_recovery_attempts_total {}\n",
            "# TYPE aip_connector_host_lease_recoveries_total counter\n",
            "aip_connector_host_lease_recoveries_total {}\n"
        ),
        u8::from(ready),
        u8::from(state.storage_ready.load(Ordering::Relaxed)),
        state.metrics.in_flight.load(Ordering::Relaxed),
        state.metrics.requests_total.load(Ordering::Relaxed),
        state.metrics.rejected_total.load(Ordering::Relaxed),
        state
            .metrics
            .heartbeat_failures_total
            .load(Ordering::Relaxed),
        state
            .metrics
            .lease_recovery_attempts_total
            .load(Ordering::Relaxed),
        state.metrics.lease_recoveries_total.load(Ordering::Relaxed),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn host_message<C>(
    State(state): State<Arc<ConnectorHostState<C>>>,
    Json(payload): Json<Value>,
) -> Response
where
    C: FrozenConnector + 'static,
{
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    if let Err(error) = SchemaRegistry::new().validate_json(SchemaName::Envelope, &payload) {
        state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        return unsigned_input_error(
            StatusCode::BAD_REQUEST,
            "schema.envelope.invalid",
            error.to_string(),
        );
    }
    let envelope = match serde_json::from_value::<Envelope>(payload) {
        Ok(envelope) => envelope,
        Err(error) => {
            state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
            return unsigned_input_error(
                StatusCode::BAD_REQUEST,
                "envelope.decode.invalid",
                error.to_string(),
            );
        }
    };
    let action_request = matches!(envelope.body, MessageBody::Action(_));
    if let Err(error) = verify_configured_gateway(&state, &envelope) {
        state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        return signed_error_response(&state, &envelope, StatusCode::UNAUTHORIZED, error);
    }
    let route = match validate_pinned_route(&state, &envelope) {
        Ok(route) => route,
        Err(error) => {
            state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
            return signed_error_response(&state, &envelope, StatusCode::FORBIDDEN, error);
        }
    };
    if action_request
        && (state.draining.load(Ordering::Acquire)
            || !state.lease_valid()
            || !state.connector_ready.load(Ordering::Acquire))
    {
        state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        return signed_error_response(
            &state,
            &envelope,
            StatusCode::SERVICE_UNAVAILABLE,
            ProtocolError {
                code: "connector_host.not_ready".to_owned(),
                message: "connector host is draining or its lease is not valid".to_owned(),
                category: ErrorCategory::Temporary,
                retryable: Some(true),
                retry_after_ms: Some(state.config.limits.heartbeat_interval_ms),
                details: None,
                source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
            },
        );
    }
    let permit = if action_request {
        match state.capacity.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
                return signed_error_response(
                    &state,
                    &envelope,
                    StatusCode::TOO_MANY_REQUESTS,
                    ProtocolError {
                        code: "connector_host.capacity".to_owned(),
                        message: "connector host local concurrency capacity is exhausted"
                            .to_owned(),
                        category: ErrorCategory::Temporary,
                        retryable: Some(true),
                        retry_after_ms: Some(100),
                        details: None,
                        source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
                    },
                );
            }
        }
    } else {
        None
    };
    if let Some(check) = route.credential_check
        && let Err(error) = state.credential_revisions.authorize(&check).await
    {
        state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        let (status, error) = credential_revision_protocol_error(error);
        return signed_error_response(&state, &envelope, status, error);
    }
    if let Some(authorization) = route.approval_authorization
        && let Err(error) = import_approval_authorization(&state.runtime, authorization).await
    {
        state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        let (status, error) = approval_authorization_protocol_error(error);
        return signed_error_response(&state, &envelope, status, error);
    }
    if action_request {
        state.metrics.in_flight.fetch_add(1, Ordering::AcqRel);
    }
    let result = state.gateway.handle_envelope(envelope.clone()).await;
    if action_request {
        state.metrics.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
    drop(permit);
    match result {
        Ok(mut response) => {
            correlate_response(&mut response, &envelope);
            match sign_native_envelope(response, &state.config.host_signer) {
                Ok(response) => (StatusCode::OK, Json(response)).into_response(),
                Err(error) => unsigned_input_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "connector_host.response_signing",
                    error.to_string(),
                ),
            }
        }
        Err(error) => {
            state.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
            let (status, protocol) = gateway_protocol_error(error);
            signed_error_response(&state, &envelope, status, protocol)
        }
    }
}

struct PinnedRouteValidation {
    credential_check: Option<CredentialRevisionCheck>,
    approval_authorization: Option<ApprovalRecord>,
}

fn verify_configured_gateway<C>(
    state: &ConnectorHostState<C>,
    envelope: &Envelope,
) -> Result<(), ProtocolError> {
    let signer_did = verify_native_envelope_signature(envelope)
        .map_err(|_| route_error("connector-host request signature is invalid"))?;
    let expected = &state.config.gateway_principal;
    let sender = envelope
        .from
        .as_ref()
        .ok_or_else(|| route_error("connector-host request sender is missing"))?;
    if signer_did != state.config.gateway_did
        || sender.id != expected.id
        || sender.kind != expected.kind
        || sender
            .trust_domain
            .as_ref()
            .is_none_or(|domain| Some(domain) != expected.trust_domain.as_ref())
        || sender
            .did
            .as_ref()
            .is_some_and(|did| did != &state.config.gateway_did)
    {
        return Err(route_error(
            "connector-host request signer does not match the configured central gateway",
        ));
    }
    Ok(())
}

fn validate_pinned_route<C>(
    state: &ConnectorHostState<C>,
    envelope: &Envelope,
) -> Result<PinnedRouteValidation, ProtocolError> {
    let recipient_matches = envelope.to.as_ref().is_some_and(|recipient| {
        let host = &state.config.host_signer.principal;
        recipient.id == host.id
            && recipient.kind == host.kind
            && recipient
                .trust_domain
                .as_ref()
                .is_none_or(|value| Some(value) == host.trust_domain.as_ref())
            && recipient
                .did
                .as_ref()
                .is_none_or(|value| Some(value) == host.did.as_ref())
    });
    if !recipient_matches {
        return Err(route_error(
            "connector-host request recipient does not match this host",
        ));
    }
    let route = envelope
        .security
        .as_ref()
        .and_then(|security| security.get("connector_route"))
        .ok_or_else(|| route_error("connector-host request is missing its pinned route"))?;
    let matches = route.get("tenant_id").and_then(Value::as_str)
        == Some(state.config.tenant.tenant.id.as_str())
        && route.get("instance_id").and_then(Value::as_str)
            == Some(state.config.instance_id.as_str())
        && route.get("replica_id").and_then(Value::as_str)
            == Some(state.config.replica_id.as_str())
        && route.get("version_id").and_then(Value::as_str)
            == Some(state.config.version_id.as_str())
        && route.get("manifest_digest").and_then(Value::as_str)
            == Some(state.manifest_digest.as_str());
    if !matches {
        return Err(route_error(
            "connector-host request route does not match its admitted instance, replica, version, tenant, or manifest",
        ));
    }
    let mut approval_authorization = None;
    let coordinates = match &envelope.body {
        MessageBody::Action(action) => {
            let action_matches = route.get("action_id").and_then(Value::as_str)
                == Some(action.id.as_str())
                && route.get("capability_id").and_then(Value::as_str)
                    == Some(action.capability_id.as_str());
            if !action_matches {
                return Err(route_error(
                    "connector-host request action or capability does not match its pinned route",
                ));
            }
            approval_authorization = validate_route_approval_authorization(state, action, route)?;
            if action.mode == Some(aip_core::ActionMode::Streaming) {
                let callback_target = state.callback_target.as_deref().ok_or_else(|| {
                    route_error("connector-host stream callbacks are not configured")
                })?;
                let callback = action.callback.as_ref().ok_or_else(|| {
                    route_error("connector-host streaming action is missing its central callback")
                })?;
                let callback_recipient = callback
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("connector_callback_recipient"))
                    .cloned()
                    .and_then(|recipient| serde_json::from_value::<Principal>(recipient).ok());
                if route.get("original_mode") != Some(&json!(aip_core::ActionMode::Streaming))
                    || callback.profile.as_str() != NATIVE_HTTP_PROFILE
                    || callback.target != callback_target
                    || callback
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.get("connector_callback"))
                        != Some(route)
                    || callback_recipient.as_ref() != envelope.from.as_ref()
                {
                    return Err(route_error(
                        "connector-host streaming callback does not match its pinned route and configured central ingress",
                    ));
                }
            } else if action.callback.is_some() {
                return Err(route_error(
                    "connector-host non-streaming action must not receive an external callback",
                ));
            }
            Some(action.capability_id.clone())
        }
        MessageBody::Cancel(cancel) => match &cancel.target {
            aip_core::CancelTarget::Action(action_id) => {
                if route.get("action_id").and_then(Value::as_str) != Some(action_id.as_str()) {
                    return Err(route_error(
                        "connector-host cancellation does not match its pinned action route",
                    ));
                }
                let capability_id = route
                    .get("capability_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| route_error("connector-host route is missing capability id"))?;
                Some(CapabilityId::parse(capability_id).map_err(|_| {
                    route_error("connector-host route contains an invalid capability id")
                })?)
            }
            aip_core::CancelTarget::Session(_) => {
                return Err(route_error(
                    "connector-host accepts only action-scoped cancellation",
                ));
            }
        },
        _ => None,
    };
    let Some(capability_id) = coordinates else {
        if route.get("approval_authorization").is_some() {
            return Err(route_error(
                "connector-host approval authorization is valid only for an action",
            ));
        }
        return Ok(PinnedRouteValidation {
            credential_check: None,
            approval_authorization: None,
        });
    };
    let pinned_revision_ref = match route.get("credential_revision_ref") {
        Some(Value::String(revision)) => Some(revision.clone()),
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(route_error(
                "connector-host route contains an invalid credential revision reference",
            ));
        }
    };
    Ok(PinnedRouteValidation {
        credential_check: Some(CredentialRevisionCheck {
            tenant_id: state.config.tenant.tenant.id.clone(),
            instance_id: state.config.instance_id.clone(),
            capability_id,
            pinned_revision_ref,
        }),
        approval_authorization,
    })
}

fn validate_route_approval_authorization<C>(
    state: &ConnectorHostState<C>,
    action: &Action,
    route: &Value,
) -> Result<Option<ApprovalRecord>, ProtocolError> {
    let encoded = route.get("approval_authorization");
    let Some(decision) = action.approval.as_ref() else {
        if encoded.is_some() {
            return Err(route_error(
                "connector-host route carries unused approval authorization",
            ));
        }
        return Ok(None);
    };
    let encoded = encoded.ok_or_else(|| {
        route_error("connector-host approved action is missing gateway authorization evidence")
    })?;
    let record = serde_json::from_value::<ApprovalRecord>(encoded.clone())
        .map_err(|_| route_error("connector-host approval authorization is malformed"))?;
    let request_tenant = record
        .request
        .identity
        .as_ref()
        .and_then(|identity| identity.tenant.as_ref());
    if decision.decision != ApprovalDecisionKind::Approved
        || record.status != ApprovalStatus::Approved
        || record.decision.as_ref() != Some(decision)
        || record.request.id != decision.approval_id
        || record.request.action_id != action.id
        || record.request.capability_id != action.capability_id
        || request_tenant.map(|tenant| tenant.id.as_str())
            != Some(state.config.tenant.tenant.id.as_str())
        || decision.policy_hash.as_deref() != record.request.policy_hash.as_deref()
    {
        return Err(route_error(
            "connector-host approval authorization does not match the action, tenant, policy, or terminal decision",
        ));
    }

    record.validate_importable_authorization().map_err(|_| {
        route_error("connector-host approval authorization cannot reproduce its approved policy")
    })?;
    Ok(Some(record))
}

async fn import_approval_authorization(
    runtime: &Runtime,
    authorization: ApprovalRecord,
) -> RuntimeResult<()> {
    runtime
        .approvals
        .import_terminal_authorization(authorization)
        .await
}

fn approval_authorization_protocol_error(error: RuntimeError) -> (StatusCode, ProtocolError) {
    let unavailable = matches!(error, RuntimeError::Storage(_));
    (
        if unavailable {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        },
        ProtocolError {
            code: if unavailable {
                "connector_host.approval_authorization_unavailable"
            } else {
                "connector_host.approval_authorization_conflict"
            }
            .to_owned(),
            message: if unavailable {
                "connector-host approval authorization journal is unavailable"
            } else {
                "connector-host approval authorization conflicts with durable state"
            }
            .to_owned(),
            category: if unavailable {
                ErrorCategory::Temporary
            } else {
                ErrorCategory::Auth
            },
            retryable: Some(unavailable),
            retry_after_ms: unavailable.then_some(1_000),
            details: None,
            source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
        },
    )
}

fn credential_revision_protocol_error(
    error: CredentialRevisionProviderError,
) -> (StatusCode, ProtocolError) {
    match error {
        CredentialRevisionProviderError::Denied => (
            StatusCode::FORBIDDEN,
            ProtocolError {
                code: "connector_host.credential_revision_denied".to_owned(),
                message: error.to_string(),
                category: ErrorCategory::Auth,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
            },
        ),
        CredentialRevisionProviderError::Unavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ProtocolError {
                code: "connector_host.credential_revision_unavailable".to_owned(),
                message: error.to_string(),
                category: ErrorCategory::Temporary,
                retryable: Some(true),
                retry_after_ms: Some(1_000),
                details: None,
                source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
            },
        ),
    }
}

fn route_error(message: &str) -> ProtocolError {
    ProtocolError {
        code: "connector_host.route_mismatch".to_owned(),
        message: message.to_owned(),
        category: ErrorCategory::Auth,
        retryable: Some(false),
        retry_after_ms: None,
        details: None,
        source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
    }
}

fn signed_error_response<C>(
    state: &ConnectorHostState<C>,
    request: &Envelope,
    status: StatusCode,
    error: ProtocolError,
) -> Response {
    let mut response = Envelope::new(MessageBody::Error(ErrorBody { error }));
    correlate_response(&mut response, request);
    match sign_native_envelope(response, &state.config.host_signer) {
        Ok(response) => (status, Json(response)).into_response(),
        Err(error) => unsigned_input_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connector_host.response_signing",
            error.to_string(),
        ),
    }
}

fn correlate_response(response: &mut Envelope, request: &Envelope) {
    response.session_id.clone_from(&request.session_id);
    response.correlation_id.clone_from(&request.correlation_id);
    response.in_response_to = Some(MessageReference::Message(request.message_id.clone()));
    response.to.clone_from(&request.from);
}

fn gateway_protocol_error(error: GatewayError) -> (StatusCode, ProtocolError) {
    match error {
        GatewayError::Policy(error) => (StatusCode::FORBIDDEN, *error),
        GatewayError::MissingSender | GatewayError::Signature(_) => (
            StatusCode::UNAUTHORIZED,
            ProtocolError {
                code: "connector_host.authentication".to_owned(),
                message: bounded_detail(error.to_string()),
                category: ErrorCategory::Auth,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
            },
        ),
        GatewayError::Replay(_) => (
            StatusCode::CONFLICT,
            ProtocolError {
                code: "connector_host.replay".to_owned(),
                message: bounded_detail(error.to_string()),
                category: ErrorCategory::Policy,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
            },
        ),
        GatewayError::Runtime(_)
        | GatewayError::UnsupportedMessage
        | GatewayError::NoCompatibleProfile => (
            StatusCode::BAD_GATEWAY,
            ProtocolError {
                code: "connector_host.execution".to_owned(),
                message: bounded_detail(error.to_string()),
                category: ErrorCategory::Connector,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": "aip-connector-host" }))),
            },
        ),
    }
}

fn unsigned_input_error(status: StatusCode, code: &str, message: String) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": bounded_detail(message),
                "category": "permanent",
                "retryable": false
            }
        })),
    )
        .into_response()
}

fn bounded_detail(mut detail: String) -> String {
    detail.truncate(1_024);
    detail
}

fn require_sha256(label: &str, value: &str) -> Result<(), ConnectorHostError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ConnectorHostError::Configuration(format!(
            "{label} must be a sha256 digest"
        )));
    }
    Ok(())
}

fn datetime_ms(value: OffsetDateTime) -> Result<i64, String> {
    i64::try_from(value.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "connector-host lease timestamp exceeds i64 milliseconds".to_owned())
}

fn now_ms() -> i64 {
    datetime_ms(OffsetDateTime::now_utc()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        CONNECTOR_HOST_CONTROL_PATH, ConnectorEventPublishOutcome, ConnectorHost,
        ConnectorHostCallbackDispatcher, ConnectorHostConfig, ConnectorHostControlCommand,
        ConnectorHostControlOutcome, ConnectorHostControlPlane,
        ConnectorHostControlPlaneHttpService, ConnectorHostError, ConnectorHostEventConfig,
        ConnectorHostHeartbeat, ConnectorHostLease, ConnectorHostLimits, ConnectorHostRegistration,
        ConnectorHostTransition, CredentialRevisionPolicy, HttpConnectorHostControlPlane,
        RegistryConnectorHostControlPlane, StaticCredentialRevisionProvider,
        heartbeat_initial_delay, normalize_connector_events_for_publication, now_ms,
        renew_or_recover_host_lease,
    };
    use aip_auth::{AuthorityMembership, CredentialHandle, VerifiedTenant};
    use aip_connector::{
        Connector, ConnectorContext, ConnectorError, ConnectorResult, FrozenConnector,
    };
    use aip_connector_registry::{
        ActionTargetResolver, ArtifactAttestation, ArtifactCheckStatus, CapabilityBinding,
        ConnectorInstance, ConnectorInstanceId, ConnectorInstanceStatus, ConnectorRegistryAdmin,
        ConnectorRegistryReader, ConnectorReplica, ConnectorReplicaId, ConnectorReplicaStatus,
        ConnectorType, ConnectorTypeId, ConnectorVersion, ConnectorVersionId,
        ConnectorVersionStatus, InMemoryConnectorRegistry, RouteResolutionRequest, RouteSettlement,
        RouteTopologyPreference, schema_bundle_digest,
    };
    use aip_core::{
        Action, ActionId, ActionResult, ActionResultStatus, ApprovalDecision, ApprovalDecisionKind,
        ApprovalId, ApprovalPolicy, ApprovalRequest, ApproverSelector, Binding, Callback,
        Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
        CompensationMode, DataContract, DataSensitivity, Envelope, ErrorCategory, Event,
        ExecutionContract, ExpectedCompletionMode, ExternalAccountRef,
        IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope,
        IdempotencyRequirement, IdentityContext, Manifest, MessageBody, MessageId, MessagePart,
        MessageReference, Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError,
        RetrySafety, SideEffect, StreamChunk, StreamChunkKind, TenantRef,
    };
    use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed};
    use aip_discovery::CapabilityImplementationSupport;
    use aip_gateway::{
        CallbackSigner, GatewayCallbackDispatcher, GatewayCallbackPolicy, NATIVE_HTTP_PROFILE,
        sign_native_envelope, verify_native_envelope_signature,
    };
    use aip_runtime::{
        ActionExecutionContext, ApprovalRecord, ApprovalStatus, CallbackDispatcher, ReplayStore,
        VerifiedApprovalDecision,
    };
    use async_trait::async_trait;
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, StatusCode},
        routing::post,
    };
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet, HashSet},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };
    use time::OffsetDateTime;
    use tokio::sync::Mutex;
    use tower::ServiceExt;
    use url::Url;

    #[derive(Clone)]
    struct EchoConnector {
        manifest: Manifest,
    }

    #[async_trait]
    impl Connector for EchoConnector {
        fn id(&self) -> &str {
            "echo"
        }

        async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<Manifest> {
            Ok(self.manifest.clone())
        }

        fn map_error(&self, error: &ConnectorError) -> aip_core::ProtocolError {
            ProtocolError {
                code: "connector.echo".to_owned(),
                message: error.to_string(),
                category: ErrorCategory::Connector,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: None,
            }
        }
    }

    #[async_trait]
    impl FrozenConnector for EchoConnector {
        fn implementation_support(
            &self,
            _capability: &Capability,
        ) -> CapabilityImplementationSupport {
            CapabilityImplementationSupport {
                invocation: true,
                cancellation: true,
                retry: true,
                ..CapabilityImplementationSupport::default()
            }
        }

        async fn invoke_typed(
            &self,
            action: Action,
            context: ActionExecutionContext,
        ) -> Result<ActionResult, aip_connector::ConnectorFailure> {
            let tenant = context
                .tenant
                .as_ref()
                .map(|tenant| tenant.tenant.id.clone())
                .unwrap_or_default();
            let action_tenant = action
                .identity
                .as_ref()
                .and_then(|identity| identity.tenant.as_ref())
                .map(|tenant| tenant.id.clone());
            let service_account = action
                .identity
                .as_ref()
                .and_then(|identity| identity.service_account.as_ref())
                .map(|principal| principal.id.to_string());
            let external_account = action
                .identity
                .as_ref()
                .and_then(|identity| identity.external_account.as_ref())
                .map(|account| format!("{}:{}", account.system, account.id));
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Completed,
                output: Some(json!({
                    "tenant": tenant,
                    "action_tenant": action_tenant,
                    "service_account": service_account,
                    "external_account": external_account,
                    "input": action.input
                })),
                message: vec![MessagePart::text("echo completed")],
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }
    }

    #[derive(Default)]
    struct RecordingControlPlane {
        registrations: Mutex<Vec<ConnectorHostRegistration>>,
        transitions: Mutex<Vec<String>>,
    }

    #[derive(Default)]
    struct LeaseRecoveryControlPlane {
        registration_request_ids: Mutex<Vec<MessageId>>,
        registrations: Mutex<Vec<ConnectorHostRegistration>>,
        registration_calls: AtomicU64,
    }

    #[derive(Clone, Default)]
    struct CallbackReceiverState {
        envelopes: Arc<Mutex<Vec<Envelope>>>,
    }

    #[derive(Clone, Default)]
    struct FlakyEventReceiverState {
        attempts: Arc<AtomicU64>,
        envelopes: Arc<Mutex<Vec<Envelope>>>,
    }

    async fn receive_connector_callback(
        State(state): State<CallbackReceiverState>,
        Json(envelope): Json<Envelope>,
    ) -> StatusCode {
        state.envelopes.lock().await.push(envelope);
        StatusCode::OK
    }

    async fn receive_connector_event(
        State(state): State<FlakyEventReceiverState>,
        Json(envelope): Json<Envelope>,
    ) -> StatusCode {
        if state.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        state.envelopes.lock().await.push(envelope);
        StatusCode::OK
    }

    #[async_trait]
    impl ConnectorHostControlPlane for RecordingControlPlane {
        async fn register_once(
            &self,
            _request_id: MessageId,
            registration: ConnectorHostRegistration,
        ) -> Result<ConnectorHostLease, ConnectorHostError> {
            self.registrations.lock().await.push(registration);
            Ok(ConnectorHostLease {
                sequence: 1,
                expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
            })
        }

        async fn heartbeat_once(
            &self,
            _request_id: MessageId,
            _heartbeat: ConnectorHostHeartbeat,
        ) -> Result<ConnectorHostLease, ConnectorHostError> {
            Ok(ConnectorHostLease {
                sequence: 2,
                expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
            })
        }

        async fn drain_once(
            &self,
            _request_id: MessageId,
            _transition: ConnectorHostTransition,
        ) -> Result<ConnectorHostLease, ConnectorHostError> {
            self.transitions.lock().await.push("draining".to_owned());
            Ok(ConnectorHostLease {
                sequence: 3,
                expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
            })
        }

        async fn offline_once(
            &self,
            _request_id: MessageId,
            _transition: ConnectorHostTransition,
        ) -> Result<(), ConnectorHostError> {
            self.transitions.lock().await.push("offline".to_owned());
            Ok(())
        }
    }

    #[async_trait]
    impl ConnectorHostControlPlane for LeaseRecoveryControlPlane {
        async fn register_once(
            &self,
            request_id: MessageId,
            registration: ConnectorHostRegistration,
        ) -> Result<ConnectorHostLease, ConnectorHostError> {
            self.registration_request_ids.lock().await.push(request_id);
            self.registrations.lock().await.push(registration);
            let call = self.registration_calls.fetch_add(1, Ordering::SeqCst);
            match call {
                1 => Err(ConnectorHostError::ControlPlane(
                    "simulated ambiguous control-plane failure".to_owned(),
                )),
                3 => Err(ConnectorHostError::Admission(
                    "simulated consumed registration rejection".to_owned(),
                )),
                _ => Ok(ConnectorHostLease {
                    sequence: call.saturating_add(1),
                    expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
                }),
            }
        }

        async fn heartbeat_once(
            &self,
            _request_id: MessageId,
            _heartbeat: ConnectorHostHeartbeat,
        ) -> Result<ConnectorHostLease, ConnectorHostError> {
            Err(ConnectorHostError::Admission(
                "simulated stale heartbeat fence".to_owned(),
            ))
        }

        async fn drain_once(
            &self,
            _request_id: MessageId,
            _transition: ConnectorHostTransition,
        ) -> Result<ConnectorHostLease, ConnectorHostError> {
            Err(ConnectorHostError::ControlPlane(
                "unused drain operation".to_owned(),
            ))
        }

        async fn offline_once(
            &self,
            _request_id: MessageId,
            _transition: ConnectorHostTransition,
        ) -> Result<(), ConnectorHostError> {
            Err(ConnectorHostError::ControlPlane(
                "unused offline operation".to_owned(),
            ))
        }
    }

    fn capability() -> Capability {
        Capability {
            id: CapabilityId::trusted("cap:test:echo"),
            name: "echo".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({ "type": "object" }),
            output_schema: Some(json!({ "type": "object" })),
            description: Some("Echoes one tenant-scoped input".to_owned()),
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: vec![Binding {
                profile: ProfileId::from("aip.native.http.v1"),
                metadata: Default::default(),
            }],
            requires_human_approval: Some(false),
            contract: Some(CapabilityContract {
                side_effects: vec![SideEffect::Read],
                idempotency: IdempotencyContract {
                    requirement: IdempotencyRequirement::Optional,
                    collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
                    key_scope: IdempotencyKeyScope::Capability,
                    ttl_ms: None,
                },
                execution: ExecutionContract {
                    supports_sync: true,
                    supports_async: false,
                    supports_streaming: false,
                    supports_cancel: true,
                    supports_retry: true,
                    expected_completion: ExpectedCompletionMode::Sync,
                    retry_safety: RetrySafety::Safe,
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
                transaction: None,
                compensation: Some(CompensationContract {
                    mode: CompensationMode::NotRequired,
                    compensation_capability_id: None,
                    compensation_window_ms: None,
                    requires_approval: false,
                }),
            }),
        }
    }

    fn test_identity() -> IdentityContext {
        IdentityContext {
            tenant: Some(TenantRef {
                id: "tenant-acme".to_owned(),
                system: Some("test".to_owned()),
            }),
            external_account: None,
            external_user: None,
            human_actor: None,
            service_account: None,
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        }
    }

    fn approved_authorization(action: &mut Action, requester: &Principal) -> ApprovalRecord {
        let approver = Principal::new(
            PrincipalId::trusted("human:test-connector-approver"),
            PrincipalKind::Human,
        );
        let policy_hash = "a".repeat(64);
        let policy = ApprovalPolicy {
            required: true,
            reason: Some("connector-host authorization test".to_owned()),
            approver_selector: ApproverSelector::Principal {
                id: approver.id.clone(),
            },
            ttl_ms: Some(60_000),
            evidence_requirements: Vec::new(),
            delegated_authority: None,
            rule: None,
            minimum_distinct_principals: 1,
            separation_of_duties: aip_core::SeparationOfDuties::default(),
            policy_version: Some("connector-host-test/v1".to_owned()),
        };
        let now = OffsetDateTime::now_utc();
        let request = ApprovalRequest {
            id: ApprovalId::new(),
            action_id: action.id.clone(),
            capability_id: action.capability_id.clone(),
            requester: requester.clone(),
            subject: requester.clone(),
            approver_selector: policy.approver_selector.clone(),
            reason: "connector-host authorization test".to_owned(),
            evidence: Vec::new(),
            expires_at: Some(now + time::Duration::minutes(1)),
            policy_decision_id: Some(format!("policy:{}", action.id)),
            identity: action.identity.clone(),
            policy_snapshot: Some(policy),
            policy_hash: Some(policy_hash.clone()),
            operator: Some(requester.clone()),
            risk: None,
            governed_value: None,
        };
        let decision = ApprovalDecision {
            approval_id: request.id.clone(),
            decision: ApprovalDecisionKind::Approved,
            approver: approver.clone(),
            decided_at: now,
            reason: Some("approved for connector-host test".to_owned()),
            constraints: Vec::new(),
            evidence: Vec::new(),
            decision_id: Some(format!("decision:{}", request.id)),
            policy_hash: Some(policy_hash),
            authority_path: Vec::new(),
            target_decision_id: None,
        };
        let mut record = ApprovalRecord {
            request,
            status: ApprovalStatus::Pending,
            decision: None,
            decisions: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        record
            .apply_verified_decision(VerifiedApprovalDecision {
                decision,
                authority: AuthorityMembership {
                    principal_id: approver.id,
                    tenant_id: Some("tenant-acme".to_owned()),
                    roles: BTreeSet::new(),
                    groups: BTreeSet::new(),
                    tenant_policies: BTreeSet::new(),
                    external_systems: BTreeSet::new(),
                    delegated_scopes: Vec::new(),
                    revision: 1,
                    expires_at: None,
                    revoked: false,
                },
                evidence_hash: "b".repeat(64),
                recorded_at: now,
            })
            .expect("approved authorization");
        action.approval.clone_from(&record.decision);
        record
    }

    async fn host() -> (
        ConnectorHost<EchoConnector>,
        CallbackSigner,
        Arc<RecordingControlPlane>,
        Arc<StaticCredentialRevisionProvider>,
    ) {
        host_with_identity([7; 32], "crepl_echo_one").await
    }

    async fn host_with_identity(
        host_seed: [u8; 32],
        replica_id: &str,
    ) -> (
        ConnectorHost<EchoConnector>,
        CallbackSigner,
        Arc<RecordingControlPlane>,
        Arc<StaticCredentialRevisionProvider>,
    ) {
        let host_key = Arc::new(signing_key_from_seed(host_seed));
        let gateway_key = Arc::new(signing_key_from_seed([9; 32]));
        let mut host_principal = Principal::new(
            PrincipalId::trusted("service:connector:echo"),
            PrincipalKind::Service,
        );
        host_principal.trust_domain = Some("test.local".to_owned());
        host_principal.did = Some(did_key_from_verifying_key(&host_key.verifying_key()));
        let mut gateway_principal = Principal::new(
            PrincipalId::trusted("service:getaip:server:fleet"),
            PrincipalKind::Service,
        );
        gateway_principal.trust_domain = Some("test.local".to_owned());
        gateway_principal.did = Some(did_key_from_verifying_key(&gateway_key.verifying_key()));
        let host_signer = CallbackSigner {
            principal: host_principal.clone(),
            signing_key: host_key,
        };
        let gateway_signer = CallbackSigner {
            principal: gateway_principal.clone(),
            signing_key: gateway_key.clone(),
        };
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: host_principal,
            capabilities: vec![capability()],
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: vec![json!({ "id": "test-events" })],
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        let control_plane = Arc::new(RecordingControlPlane::default());
        let credential_revisions = Arc::new(
            StaticCredentialRevisionProvider::new(CredentialRevisionPolicy {
                current_revision_ref: Some("credential-v1".to_owned()),
                ..CredentialRevisionPolicy::default()
            })
            .expect("credential revisions"),
        );
        let host = ConnectorHost::build_in_memory_for_test_with_credential_revision_provider(
            ConnectorHostConfig {
                connector_type_id: ConnectorTypeId::trusted("ctype_echo"),
                version_id: ConnectorVersionId::trusted("cver_echo_v1"),
                instance_id: ConnectorInstanceId::trusted("cinst_echo_acme"),
                replica_id: ConnectorReplicaId::parse(replica_id).expect("replica id"),
                public_endpoint: Url::parse("http://127.0.0.1:43123/aip/v1/messages")
                    .expect("host endpoint"),
                tenant: VerifiedTenant {
                    tenant: TenantRef {
                        id: "tenant-acme".to_owned(),
                        system: Some("test".to_owned()),
                    },
                    membership_id: "connector-instance-acme".to_owned(),
                    roles: BTreeSet::new(),
                    groups: BTreeSet::new(),
                    verified_at: OffsetDateTime::now_utc(),
                    expires_at: None,
                },
                credential: Some(
                    CredentialHandle::new(
                        "credential-handle-echo",
                        "test-vault",
                        BTreeSet::from(["*".to_owned()]),
                        Some("tenant-acme".to_owned()),
                        None,
                    )
                    .expect("credential handle"),
                ),
                external_account: Some(ExternalAccountRef {
                    id: "account-acme".to_owned(),
                    system: "echo".to_owned(),
                }),
                credential_revision_ref: Some("credential-v1".to_owned()),
                config_revision: 1,
                secret_provider_ref: "secret://tenant-acme/echo".to_owned(),
                artifact_digest: format!("sha256:{}", "1".repeat(64)),
                host_signer,
                gateway_principal,
                gateway_did: did_key_from_verifying_key(&gateway_key.verifying_key()),
                trust_domain: "test.local".to_owned(),
                topology: Default::default(),
                allow_insecure_loopback_http: true,
                limits: ConnectorHostLimits {
                    max_in_flight: 2,
                    ..ConnectorHostLimits::default()
                },
            },
            EchoConnector { manifest },
            control_plane.clone(),
            credential_revisions.clone(),
        )
        .await
        .expect("connector host");
        (host, gateway_signer, control_plane, credential_revisions)
    }

    async fn post_host_envelope(
        host: &ConnectorHost<EchoConnector>,
        envelope: Envelope,
    ) -> StatusCode {
        host.router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&envelope).expect("request JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("host response")
            .status()
    }

    #[test]
    fn heartbeat_initial_delay_is_bounded_and_distributes_replicas() {
        let lower = heartbeat_initial_delay(10_000, 0);
        let upper = heartbeat_initial_delay(10_000, 5_000);
        let wrapped = heartbeat_initial_delay(10_000, 5_001);

        assert_eq!(lower, Duration::from_millis(7_500));
        assert_eq!(upper, Duration::from_millis(12_500));
        assert_eq!(wrapped, lower);
        assert!(lower < upper);
    }

    #[tokio::test]
    async fn expired_host_lease_recovers_idempotently_and_preserves_fencing() {
        let (mut host, _, _, _) = host().await;
        let control_plane = Arc::new(LeaseRecoveryControlPlane::default());
        Arc::get_mut(&mut host.state)
            .expect("unshared host state")
            .control_plane = control_plane.clone();

        let initial = host.register().await.expect("initial host registration");
        assert_eq!(initial.sequence, 1);
        host.state
            .lease_expires_at_ms
            .store(now_ms().saturating_sub(1), Ordering::Release);

        let ambiguous = renew_or_recover_host_lease(&host.state, true, 0)
            .await
            .expect_err("first recovery response is ambiguous");
        assert!(matches!(ambiguous, ConnectorHostError::ControlPlane(_)));
        renew_or_recover_host_lease(&host.state, true, 0)
            .await
            .expect("ambiguous recovery replays the same request");
        assert_eq!(host.state.lease_sequence.load(Ordering::Acquire), 3);

        host.state
            .lease_expires_at_ms
            .store(now_ms().saturating_sub(1), Ordering::Release);
        let rejected = renew_or_recover_host_lease(&host.state, true, 0)
            .await
            .expect_err("rejected recovery must remain fail closed");
        assert!(matches!(rejected, ConnectorHostError::Admission(_)));
        renew_or_recover_host_lease(&host.state, true, 0)
            .await
            .expect("a rejected request is replaced by a fresh fenced request");
        assert_eq!(host.state.lease_sequence.load(Ordering::Acquire), 5);

        host.state
            .lease_expires_at_ms
            .store(now_ms().saturating_sub(1), Ordering::Release);
        renew_or_recover_host_lease(&host.state, false, 0)
            .await
            .expect("an unhealthy host remains offline without re-registering");

        let request_ids = control_plane.registration_request_ids.lock().await;
        assert_eq!(request_ids.len(), 5);
        assert_ne!(request_ids[0], request_ids[1]);
        assert_eq!(request_ids[1], request_ids[2]);
        assert_ne!(request_ids[2], request_ids[3]);
        assert_ne!(request_ids[3], request_ids[4]);
        drop(request_ids);
        let registrations = control_plane.registrations.lock().await;
        assert_eq!(registrations[1], registrations[2]);
        assert_eq!(
            host.state
                .metrics
                .lease_recovery_attempts_total
                .load(Ordering::Relaxed),
            4
        );
        assert_eq!(
            host.state
                .metrics
                .lease_recoveries_total
                .load(Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn host_stream_callback_is_pinned_routed_and_signed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("callback listener");
        let address = listener.local_addr().expect("callback address");
        let receiver = CallbackReceiverState::default();
        let app = Router::new()
            .route(
                "/aip/v1/connector-callbacks",
                post(receive_connector_callback),
            )
            .with_state(receiver.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("callback server");
        });
        let signing_key = Arc::new(signing_key_from_seed([41; 32]));
        let mut principal = Principal::new(
            PrincipalId::trusted("service:connector:stream-test"),
            PrincipalKind::Service,
        );
        principal.trust_domain = Some("connectors.test".to_owned());
        let signer = CallbackSigner {
            principal,
            signing_key: signing_key.clone(),
        };
        let policy = GatewayCallbackPolicy {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            allow_http: true,
            allow_private_networks: true,
            signer: Some(signer.clone()),
            ..GatewayCallbackPolicy::default()
        };
        let target = format!("http://{address}/aip/v1/connector-callbacks");
        let dispatcher = ConnectorHostCallbackDispatcher {
            target: target.clone(),
            inner: GatewayCallbackDispatcher::with_policy(
                aip_transport_sse::SseTransport::new(),
                policy,
            ),
        };
        let action_id = ActionId::parse("act_test_stream_callback").expect("action id");
        let route = json!({
            "action_id": action_id,
            "capability_id": "cap:test:echo",
            "tenant_id": "tenant-acme",
            "instance_id": "cinst_echo_acme",
            "replica_id": "crepl_echo_one",
            "version_id": "cver_echo_v1",
            "manifest_digest": format!("sha256:{}", "1".repeat(64)),
            "catalog_revision": 1,
            "binding_policy_revision": 1,
            "credential_revision_ref": "credential-v1",
            "quota_policy_ref": null,
            "replica_health_revision": 1,
            "fence_token": "route_test_stream",
            "original_mode": "streaming"
        });
        let central_recipient = Principal::new(
            PrincipalId::trusted("service:getaip:server:stream-ingress"),
            PrincipalKind::Service,
        );
        let callback = Callback {
            profile: ProfileId::from(NATIVE_HTTP_PROFILE),
            target: target.clone(),
            metadata: Some(json!({
                "connector_callback": route.clone(),
                "connector_callback_recipient": central_recipient
            })),
        };
        dispatcher
            .dispatch(
                &callback,
                Envelope::new(MessageBody::StreamChunk(StreamChunk {
                    action_id: action_id.clone(),
                    sequence: 1,
                    kind: StreamChunkKind::Progress,
                    data: Some(json!({ "progress": 50 })),
                    part: None,
                })),
            )
            .await
            .expect("signed connector callback");
        let received = receiver.envelopes.lock().await;
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0]
                .security
                .as_ref()
                .and_then(|security| security.get("connector_callback")),
            Some(&route)
        );
        assert_eq!(received[0].to.as_ref(), Some(&central_recipient));
        assert_eq!(
            verify_native_envelope_signature(&received[0]).expect("callback signature"),
            did_key_from_verifying_key(&signing_key.verifying_key())
        );
        drop(received);
        let mut wrong_target = callback;
        wrong_target.target = format!("http://{address}/other");
        let denied = dispatcher
            .dispatch(
                &wrong_target,
                Envelope::new(MessageBody::StreamChunk(StreamChunk {
                    action_id,
                    sequence: 2,
                    kind: StreamChunkKind::Done,
                    data: None,
                    part: None,
                })),
            )
            .await
            .expect_err("callback target must be pinned");
        assert!(matches!(
            denied,
            aip_runtime::RuntimeError::Authorization(_)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn event_outbox_recovers_transient_central_failure_without_provider_retry() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("event listener");
        let address = listener.local_addr().expect("event address");
        let receiver = FlakyEventReceiverState::default();
        let app = Router::new()
            .route("/aip/v1/connector-events", post(receive_connector_event))
            .with_state(receiver.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("event server");
        });
        let (host, _, _, _) = host().await;
        host.register().await.expect("register event host");
        let target =
            Url::parse(&format!("http://{address}/aip/v1/connector-events")).expect("event target");
        let publisher = host
            .event_publisher(ConnectorHostEventConfig {
                target,
                policy: GatewayCallbackPolicy {
                    allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
                    allow_http: true,
                    allow_private_networks: true,
                    signer: Some(host.state.config.host_signer.clone()),
                    ..GatewayCallbackPolicy::default()
                },
            })
            .await
            .expect("event publisher");
        let mut event = Event::new("test.connector.event");
        let upstream_actor = Principal::new(
            PrincipalId::parse("service:provider:webhook").expect("provider principal"),
            PrincipalKind::Service,
        );
        event.actor = Some(upstream_actor.clone());
        event.data = Some(json!({ "delivery_id": "provider-delivery-1" }));
        publisher
            .publish("test-events", vec![event.clone()])
            .await
            .expect_err("first central request is intentionally unavailable");
        assert_eq!(
            publisher.pending_batches().await.expect("pending outbox"),
            1
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if !receiver.envelopes.lock().await.is_empty()
                && publisher.pending_batches().await.expect("drained outbox") == 0
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "durable event outbox did not retry within its bounded backoff"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(receiver.attempts.load(Ordering::SeqCst) >= 2);
        let envelopes = receiver.envelopes.lock().await;
        assert_eq!(envelopes.len(), 1);
        let MessageBody::EventStream(stream) = &envelopes[0].body else {
            panic!("expected event stream");
        };
        assert_eq!(stream.events[0].id, event.id);
        assert!(stream.events[0].actor.is_none());
        assert_eq!(
            stream.events[0]
                .data
                .as_ref()
                .and_then(|value| value.get("upstream_actor")),
            Some(&serde_json::to_value(upstream_actor).expect("upstream actor value"))
        );
        assert_eq!(
            envelopes[0]
                .security
                .as_ref()
                .and_then(|value| value.pointer("/connector_event/channel_id"))
                .and_then(Value::as_str),
            Some("test-events")
        );
        server.abort();
    }

    #[tokio::test]
    async fn durable_event_acceptance_hides_transient_central_failure_from_provider() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("event listener");
        let address = listener.local_addr().expect("event address");
        let receiver = FlakyEventReceiverState::default();
        let app = Router::new()
            .route("/aip/v1/connector-events", post(receive_connector_event))
            .with_state(receiver.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("event server");
        });
        let (host, _, _, _) = host().await;
        host.register().await.expect("register event host");
        let target =
            Url::parse(&format!("http://{address}/aip/v1/connector-events")).expect("event target");
        let publisher = host
            .event_publisher(ConnectorHostEventConfig {
                target,
                policy: GatewayCallbackPolicy {
                    allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
                    allow_http: true,
                    allow_private_networks: true,
                    signer: Some(host.state.config.host_signer.clone()),
                    ..GatewayCallbackPolicy::default()
                },
            })
            .await
            .expect("event publisher");
        let mut event = Event::new("test.connector.durable_acceptance");
        event.data = Some(json!({ "delivery_id": "provider-delivery-durable" }));

        assert_eq!(
            publisher
                .enqueue("test-events", vec![event])
                .await
                .expect("durable provider acceptance"),
            ConnectorEventPublishOutcome::DurablyQueued
        );
        assert_eq!(
            publisher.pending_batches().await.expect("pending outbox"),
            1
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if !receiver.envelopes.lock().await.is_empty()
                && publisher.pending_batches().await.expect("drained outbox") == 0
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "durably accepted event did not reach central ingress"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        server.abort();
    }

    #[test]
    fn connector_event_actor_projection_is_idempotent_and_fails_closed_on_conflict() {
        let actor = Principal::new(
            PrincipalId::parse("contact:provider:42").expect("provider principal"),
            PrincipalKind::Contact,
        );
        let actor_value = serde_json::to_value(&actor).expect("actor value");
        let mut event = Event::new("test.connector.event");
        event.actor = Some(actor.clone());
        event.data = Some(json!({ "provider_event_id": "event-42" }));

        normalize_connector_events_for_publication(std::slice::from_mut(&mut event))
            .expect("first projection");
        assert!(event.actor.is_none());
        assert_eq!(
            event
                .data
                .as_ref()
                .and_then(|value| value.get("upstream_actor")),
            Some(&actor_value)
        );
        normalize_connector_events_for_publication(std::slice::from_mut(&mut event))
            .expect("idempotent projection");

        let mut conflicting = Event::new("test.connector.event");
        conflicting.actor = Some(actor);
        conflicting.data = Some(json!({
            "upstream_actor": {
                "id": "contact:provider:other",
                "kind": "contact"
            }
        }));
        let conflict =
            normalize_connector_events_for_publication(std::slice::from_mut(&mut conflicting))
                .expect_err("conflicting actor provenance must fail closed");
        assert!(matches!(conflict, ConnectorHostError::Configuration(_)));

        let mut scalar_data = Event::new("test.connector.event");
        scalar_data.data = Some(json!("invalid"));
        let scalar =
            normalize_connector_events_for_publication(std::slice::from_mut(&mut scalar_data))
                .expect_err("non-object event data must fail locally");
        assert!(matches!(scalar, ConnectorHostError::Configuration(_)));
    }

    #[tokio::test]
    async fn immutable_version_digest_is_stable_across_independently_keyed_replicas() {
        let (first, _, first_control, _) = host_with_identity([7; 32], "crepl_echo_one").await;
        let (second, _, second_control, _) = host_with_identity([17; 32], "crepl_echo_two").await;

        assert_eq!(first.manifest_digest(), second.manifest_digest());
        assert_eq!(first.manifest(), second.manifest());
        assert!(first.manifest().agent.did.is_none());

        first.register().await.expect("register first replica");
        second.register().await.expect("register second replica");
        let first_registrations = first_control.registrations.lock().await;
        let second_registrations = second_control.registrations.lock().await;
        assert_ne!(
            first_registrations[0].replica.peer_did, second_registrations[0].replica.peer_did,
            "replica keys must remain independent even though their admitted manifest is shared"
        );
    }

    #[tokio::test]
    async fn host_registers_exact_artifact_and_executes_signed_tenant_action() {
        let (host, gateway_signer, control_plane, _) = host().await;
        host.register().await.expect("register host");
        let mut action = Action::new(CapabilityId::trusted("cap:test:echo"), json!({ "x": 1 }));
        action.identity = Some(test_identity());
        let action_id = action.id.clone();
        let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
        envelope.from = Some(gateway_signer.principal.clone());
        envelope.to = Some(host.manifest().agent.clone());
        envelope.security = Some(json!({
            "connector_route": {
                "action_id": action_id,
                "capability_id": "cap:test:echo",
                "tenant_id": "tenant-acme",
                "instance_id": "cinst_echo_acme",
                "replica_id": "crepl_echo_one",
                "version_id": "cver_echo_v1",
                "manifest_digest": host.manifest_digest()
                ,"credential_revision_ref": "credential-v1"
            }
        }));
        let envelope = sign_native_envelope(envelope, &gateway_signer).expect("sign request");
        let request_message_id = envelope.message_id.clone();
        let request_session_id = envelope.session_id.clone();
        let request_correlation_id = envelope.correlation_id.clone();
        let request_from = envelope.from.clone();
        let response = host
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&envelope).expect("request JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("host response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let response: Envelope = serde_json::from_slice(&body).expect("response envelope");
        assert_eq!(
            response.in_response_to,
            Some(MessageReference::Message(request_message_id))
        );
        assert_eq!(response.session_id, request_session_id);
        assert_eq!(response.correlation_id, request_correlation_id);
        assert_eq!(response.to, request_from);
        verify_native_envelope_signature(&response).expect("verified host response");
        let MessageBody::ActionResult(result) = response.body else {
            panic!("expected action result")
        };
        assert_eq!(result.action_id, action_id);
        assert_eq!(
            result.output.as_ref().and_then(|value| value.get("tenant")),
            Some(&Value::String("tenant-acme".to_owned()))
        );
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|value| value.get("action_tenant")),
            Some(&Value::String("tenant-acme".to_owned()))
        );
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|value| value.get("service_account")),
            Some(&Value::String("service:getaip:server:fleet".to_owned()))
        );
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|value| value.get("external_account")),
            Some(&Value::String("echo:account-acme".to_owned()))
        );
        let registrations = control_plane.registrations.lock().await;
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].manifest_digest, host.manifest_digest());
        assert_eq!(registrations[0].capability_count, 1);
    }

    #[tokio::test]
    async fn host_imports_only_gateway_signed_matching_approval_authorization() {
        let (host, gateway_signer, _, _) = host().await;
        host.register().await.expect("register host");
        let mut action = Action::new(
            CapabilityId::trusted("cap:test:echo"),
            json!({ "governed": true }),
        );
        action.identity = Some(test_identity());
        let authorization = approved_authorization(&mut action, &gateway_signer.principal);
        let signed_request = |authorization: Option<&ApprovalRecord>| {
            let mut route = json!({
                "action_id": action.id,
                "capability_id": action.capability_id,
                "tenant_id": "tenant-acme",
                "instance_id": "cinst_echo_acme",
                "replica_id": "crepl_echo_one",
                "version_id": "cver_echo_v1",
                "manifest_digest": host.manifest_digest(),
                "credential_revision_ref": "credential-v1"
            });
            if let Some(authorization) = authorization {
                route.as_object_mut().expect("route object").insert(
                    "approval_authorization".to_owned(),
                    serde_json::to_value(authorization).expect("authorization JSON"),
                );
            }
            let mut envelope = Envelope::new(MessageBody::Action(Box::new(action.clone())));
            envelope.from = Some(gateway_signer.principal.clone());
            envelope.to = Some(host.manifest().agent.clone());
            envelope.security = Some(json!({ "connector_route": route }));
            sign_native_envelope(envelope, &gateway_signer).expect("sign request")
        };

        assert_eq!(
            post_host_envelope(&host, signed_request(None)).await,
            StatusCode::FORBIDDEN,
            "an approved action without central durable evidence must fail closed"
        );

        let mut tampered = authorization.clone();
        tampered
            .request
            .identity
            .as_mut()
            .expect("authorization identity")
            .tenant = Some(TenantRef {
            id: "tenant-other".to_owned(),
            system: Some("test".to_owned()),
        });
        assert_eq!(
            post_host_envelope(&host, signed_request(Some(&tampered))).await,
            StatusCode::FORBIDDEN,
            "even gateway-signed evidence must match the pinned tenant and action"
        );

        assert_eq!(
            post_host_envelope(&host, signed_request(Some(&authorization))).await,
            StatusCode::OK
        );
        assert_eq!(
            host.state
                .runtime
                .approvals
                .get(&authorization.request.id)
                .await
                .expect("approval journal")
                .as_ref(),
            Some(&authorization)
        );
        host.state
            .runtime
            .approvals
            .import_terminal_authorization(authorization)
            .await
            .expect("exact authorization replay is idempotent");
    }

    #[tokio::test]
    async fn host_rejects_cross_instance_route_and_stops_new_work_while_draining() {
        let (host, gateway_signer, _, _) = host().await;
        host.register().await.expect("register host");
        let request = |instance_id: &str| {
            let mut action = Action::new(CapabilityId::trusted("cap:test:echo"), json!({}));
            action.identity = Some(test_identity());
            let action_id = action.id.clone();
            let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
            envelope.from = Some(gateway_signer.principal.clone());
            envelope.to = Some(host.manifest().agent.clone());
            envelope.security = Some(json!({
                "connector_route": {
                    "action_id": action_id,
                    "capability_id": "cap:test:echo",
                    "tenant_id": "tenant-acme",
                    "instance_id": instance_id,
                    "replica_id": "crepl_echo_one",
                    "version_id": "cver_echo_v1",
                    "manifest_digest": host.manifest_digest()
                    ,"credential_revision_ref": "credential-v1"
                }
            }));
            sign_native_envelope(envelope, &gateway_signer).expect("sign request")
        };
        let wrong = request("cinst_other");
        let wrong_response = host
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&wrong).expect("JSON")))
                    .expect("request"),
            )
            .await
            .expect("wrong route response");
        assert_eq!(wrong_response.status(), StatusCode::FORBIDDEN);

        host.begin_drain().await.expect("begin drain");
        let draining = request("cinst_echo_acme");
        let draining_response = host
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&draining).expect("request JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("draining response");
        assert_eq!(draining_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn host_enforces_credential_overlap_and_immediate_revocation() {
        let (host, gateway_signer, _, credential_revisions) = host().await;
        host.register().await.expect("register host");
        let request = |revision: &str| {
            let mut action = Action::new(CapabilityId::trusted("cap:test:echo"), json!({}));
            action.identity = Some(test_identity());
            let action_id = action.id.clone();
            let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
            envelope.from = Some(gateway_signer.principal.clone());
            envelope.to = Some(host.manifest().agent.clone());
            envelope.security = Some(json!({
                "connector_route": {
                    "action_id": action_id,
                    "capability_id": "cap:test:echo",
                    "tenant_id": "tenant-acme",
                    "instance_id": "cinst_echo_acme",
                    "replica_id": "crepl_echo_one",
                    "version_id": "cver_echo_v1",
                    "manifest_digest": host.manifest_digest(),
                    "credential_revision_ref": revision
                }
            }));
            sign_native_envelope(envelope, &gateway_signer).expect("sign request")
        };
        assert_eq!(
            post_host_envelope(&host, request("credential-v1")).await,
            StatusCode::OK
        );
        credential_revisions
            .replace_policy(CredentialRevisionPolicy {
                current_revision_ref: Some("credential-v2".to_owned()),
                accepted_previous_revisions: BTreeSet::from(["credential-v1".to_owned()]),
                revoked_revisions: BTreeSet::new(),
            })
            .await
            .expect("overlap policy");
        assert_eq!(
            post_host_envelope(&host, request("credential-v1")).await,
            StatusCode::OK
        );
        credential_revisions
            .replace_policy(CredentialRevisionPolicy {
                current_revision_ref: Some("credential-v2".to_owned()),
                accepted_previous_revisions: BTreeSet::new(),
                revoked_revisions: BTreeSet::from(["credential-v1".to_owned()]),
            })
            .await
            .expect("revocation policy");
        assert_eq!(
            post_host_envelope(&host, request("credential-v1")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post_host_envelope(&host, request("credential-v2")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn registry_control_plane_fences_stale_heartbeats_and_expires_offline_lease() {
        let (host, gateway_signer, _, _) = host().await;
        let registry = InMemoryConnectorRegistry::default();
        registry
            .put_connector_type(ConnectorType {
                id: host.state.config.connector_type_id.clone(),
                name: "Echo fixture".to_owned(),
                owner: "AIP conformance".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");
        registry
            .admit_version(ConnectorVersion {
                id: host.state.config.version_id.clone(),
                connector_type_id: host.state.config.connector_type_id.clone(),
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest: host.manifest().clone(),
                manifest_digest: host.manifest_digest().to_owned(),
                attestation: ArtifactAttestation {
                    artifact_digest: host.state.config.artifact_digest.clone(),
                    schema_bundle_digest: schema_bundle_digest(host.manifest())
                        .expect("schema bundle digest"),
                    sbom_digest: format!("sha256:{}", "2".repeat(64)),
                    provenance_digest: format!("sha256:{}", "3".repeat(64)),
                    conformance_report_digest: format!("sha256:{}", "4".repeat(64)),
                    vulnerability_report_digest: format!("sha256:{}", "5".repeat(64)),
                    license_report_digest: format!("sha256:{}", "6".repeat(64)),
                    signature_ref: "sigstore:test-host".to_owned(),
                    signer_identity: "https://fulcio.example/identity/test-host".to_owned(),
                    owner: "AIP conformance".to_owned(),
                    supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
                    sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
                    conformance_status: ArtifactCheckStatus::Passed,
                    vulnerability_policy_status: ArtifactCheckStatus::Passed,
                    license_policy_status: ArtifactCheckStatus::Passed,
                    revocation_status: ArtifactCheckStatus::Passed,
                },
                implementation_support: BTreeMap::from([(
                    CapabilityId::trusted("cap:test:echo"),
                    CapabilityImplementationSupport {
                        invocation: true,
                        cancellation: true,
                        retry: true,
                        ..CapabilityImplementationSupport::default()
                    },
                )]),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("connector version");
        registry
            .put_instance(ConnectorInstance {
                id: host.state.config.instance_id.clone(),
                connector_type_id: host.state.config.connector_type_id.clone(),
                version_id: host.state.config.version_id.clone(),
                tenant_id: host.state.config.tenant.tenant.id.clone(),
                config_revision: host.state.config.config_revision,
                secret_provider_ref: host.state.config.secret_provider_ref.clone(),
                status: ConnectorInstanceStatus::Enabled,
            })
            .await
            .expect("connector instance");
        let control_plane =
            RegistryConnectorHostControlPlane::new(Arc::new(registry.clone()), 30_000)
                .expect("registry control plane");
        let registration = ConnectorHostRegistration {
            replica: ConnectorReplica {
                id: host.state.config.replica_id.clone(),
                instance_id: host.state.config.instance_id.clone(),
                version_id: host.state.config.version_id.clone(),
                endpoint: host.state.config.public_endpoint.to_string(),
                peer_principal_id: host.state.config.host_signer.principal.id.clone(),
                peer_principal_kind: host.state.config.host_signer.principal.kind,
                peer_did: did_key_from_verifying_key(
                    &host.state.config.host_signer.signing_key.verifying_key(),
                ),
                trust_domain: host.state.config.trust_domain.clone(),
                transport_profile: ProfileId::from("aip.native.http.v1"),
                topology: host.state.config.topology.clone(),
                status: ConnectorReplicaStatus::Ready,
                lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
                capacity: host.state.config.limits.max_in_flight,
                active_assignments: 0,
                health_revision: 0,
                last_control_request_id: None,
                last_control_request_digest: None,
            },
            manifest_digest: host.manifest_digest().to_owned(),
            artifact_digest: host.state.config.artifact_digest.clone(),
            tenant_id: host.state.config.tenant.tenant.id.clone(),
            config_revision: host.state.config.config_revision,
            secret_provider_ref: host.state.config.secret_provider_ref.clone(),
            capability_count: 1,
        };
        let registration_request_id = MessageId::new();
        let first = control_plane
            .register_once(registration_request_id.clone(), registration.clone())
            .await
            .expect("register replica");
        assert_eq!(first.sequence, 1);
        let replayed_registration = control_plane
            .register_once(registration_request_id, registration.clone())
            .await
            .expect("replay committed registration");
        assert_eq!(replayed_registration, first);
        let over_capacity = control_plane
            .heartbeat(ConnectorHostHeartbeat {
                replica_id: host.state.config.replica_id.clone(),
                previous_sequence: first.sequence,
                in_flight: host.state.config.limits.max_in_flight + 1,
                connector_ready: true,
            })
            .await
            .expect_err("over-capacity heartbeat");
        assert!(matches!(over_capacity, ConnectorHostError::Admission(_)));
        let heartbeat = ConnectorHostHeartbeat {
            replica_id: host.state.config.replica_id.clone(),
            previous_sequence: first.sequence,
            in_flight: 0,
            connector_ready: true,
        };
        let heartbeat_request_id = MessageId::new();
        let second = control_plane
            .heartbeat_once(heartbeat_request_id.clone(), heartbeat.clone())
            .await
            .expect("renew lease");
        assert_eq!(second.sequence, 2);
        let replayed_heartbeat = control_plane
            .heartbeat_once(heartbeat_request_id.clone(), heartbeat.clone())
            .await
            .expect("replay committed heartbeat");
        assert_eq!(replayed_heartbeat, second);
        let request_id_collision = control_plane
            .heartbeat_once(
                heartbeat_request_id,
                ConnectorHostHeartbeat {
                    connector_ready: false,
                    ..heartbeat.clone()
                },
            )
            .await
            .expect_err("same request id with a different payload must fail closed");
        assert!(matches!(
            request_id_collision,
            ConnectorHostError::Admission(_)
        ));
        let stale = control_plane
            .heartbeat(heartbeat)
            .await
            .expect_err("stale heartbeat");
        assert!(matches!(stale, ConnectorHostError::Admission(_)));
        control_plane
            .offline(ConnectorHostTransition {
                replica_id: host.state.config.replica_id.clone(),
                previous_sequence: second.sequence,
            })
            .await
            .expect("offline transition");
        let offline = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("replica read")
            .expect("registered replica");
        assert_eq!(offline.status, ConnectorReplicaStatus::Offline);
        assert!(offline.lease_expires_at <= OffsetDateTime::now_utc());
        let restarted = control_plane
            .register(registration.clone())
            .await
            .expect("re-register offline replica after process restart");
        assert_eq!(restarted.sequence, 4);
        let ready = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("restarted replica read")
            .expect("restarted replica");
        assert_eq!(ready.status, ConnectorReplicaStatus::Ready);
        assert_eq!(ready.health_revision, restarted.sequence);

        registry
            .put_binding(CapabilityBinding {
                tenant_id: "tenant-acme".to_owned(),
                capability_id: CapabilityId::trusted("cap:test:echo"),
                instance_id: host.state.config.instance_id.clone(),
                priority: 0,
                policy_revision: 1,
                credential_revision_ref: Some("credential-v1".to_owned()),
                quota_policy_ref: None,
                enabled: true,
            })
            .await
            .expect("tenant binding for crash takeover");
        let active_assignment = registry
            .resolve(RouteResolutionRequest {
                action_id: ActionId::parse("act_test_crash_takeover")
                    .expect("crash takeover action id"),
                capability_id: CapabilityId::trusted("cap:test:echo"),
                tenant_id: "tenant-acme".to_owned(),
                topology: RouteTopologyPreference::default(),
            })
            .await
            .expect("reserve one active assignment");
        let live_takeover = control_plane
            .register(registration.clone())
            .await
            .expect_err("a live replica must fence a concurrent process");
        assert!(matches!(live_takeover, ConnectorHostError::Admission(_)));

        let mut expired = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("expired replica read")
            .expect("expired replica");
        assert_eq!(expired.active_assignments, 1);
        expired.lease_expires_at = OffsetDateTime::now_utc() - time::Duration::milliseconds(1);
        expired.health_revision += 1;
        registry
            .put_replica(expired)
            .await
            .expect("expire the hard-killed process lease");
        let takeover = control_plane
            .register(registration.clone())
            .await
            .expect("same immutable replica takes over after lease expiry");
        assert_eq!(takeover.sequence, 6);
        let recovered = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("recovered replica read")
            .expect("recovered replica");
        assert_eq!(recovered.status, ConnectorReplicaStatus::Ready);
        assert_eq!(recovered.active_assignments, 1);
        assert_eq!(recovered.health_revision, takeover.sequence);
        registry
            .settle(&active_assignment, RouteSettlement::Completed)
            .await
            .expect("settle recovered assignment exactly once");
        control_plane
            .offline(ConnectorHostTransition {
                replica_id: host.state.config.replica_id.clone(),
                previous_sequence: takeover.sequence,
            })
            .await
            .expect("prepare offline identity for remote lifecycle");

        let service = ConnectorHostControlPlaneHttpService::new(
            Arc::new(control_plane.clone()),
            Arc::new(registry.clone()),
            ReplayStore::default(),
            gateway_signer.clone(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("control listener");
        let address = listener.local_addr().expect("control address");
        let server =
            tokio::spawn(axum::serve(listener, service.router().into_make_service()).into_future());
        let endpoint = Url::parse(&format!("http://{address}{CONNECTOR_HOST_CONTROL_PATH}"))
            .expect("control endpoint");
        let untrusted = HttpConnectorHostControlPlane::new(
            endpoint.clone(),
            CallbackSigner {
                principal: host.state.config.host_signer.principal.clone(),
                signing_key: Arc::new(signing_key_from_seed([99_u8; 32])),
            },
            did_key_from_verifying_key(&gateway_signer.signing_key.verifying_key()),
            true,
            5_000,
        )
        .expect("untrusted remote control client fixture");
        let untrusted_error = untrusted
            .register(registration.clone())
            .await
            .expect_err("untrusted replica signing key must fail closed");
        assert!(matches!(untrusted_error, ConnectorHostError::Admission(_)));
        let still_offline = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("rejected replica read")
            .expect("rejected replica");
        assert_eq!(still_offline.status, ConnectorReplicaStatus::Offline);
        assert_eq!(still_offline.health_revision, 7);
        let remote = HttpConnectorHostControlPlane::new(
            endpoint,
            host.state.config.host_signer.clone(),
            did_key_from_verifying_key(&gateway_signer.signing_key.verifying_key()),
            true,
            5_000,
        )
        .expect("remote control client");
        let remote_registration_request_id = MessageId::new();
        let signed_registration = remote
            .signed_request(
                remote_registration_request_id.clone(),
                ConnectorHostControlCommand::Register(Box::new(registration)),
            )
            .expect("signed registration fixture");
        let signed_registration_body =
            serde_json::to_vec(&signed_registration).expect("serialized registration fixture");
        let remote_registration_outcome = remote
            .send_signed_body(&remote_registration_request_id, &signed_registration_body)
            .await
            .expect("signed remote registration");
        let remote_registered = match remote_registration_outcome {
            ConnectorHostControlOutcome::Lease { lease } => lease,
            _ => panic!("remote registration returned an unexpected outcome"),
        };
        assert_eq!(remote_registered.sequence, 8);
        let replayed_registration = remote
            .send_signed_body(&remote_registration_request_id, &signed_registration_body)
            .await
            .expect("exact registration replay after a lost response");
        assert_eq!(
            replayed_registration,
            ConnectorHostControlOutcome::Lease {
                lease: remote_registered.clone()
            }
        );
        let remote_heartbeat_command = ConnectorHostHeartbeat {
            replica_id: host.state.config.replica_id.clone(),
            previous_sequence: remote_registered.sequence,
            in_flight: 0,
            connector_ready: true,
        };
        let remote_heartbeat_request_id = MessageId::new();
        let signed_heartbeat = remote
            .signed_request(
                remote_heartbeat_request_id.clone(),
                ConnectorHostControlCommand::Heartbeat(remote_heartbeat_command.clone()),
            )
            .expect("signed heartbeat fixture");
        let signed_heartbeat_body =
            serde_json::to_vec(&signed_heartbeat).expect("serialized heartbeat fixture");
        let first_wire_outcome = remote
            .send_signed_body(&remote_heartbeat_request_id, &signed_heartbeat_body)
            .await
            .expect("first signed remote heartbeat");
        let remote_heartbeat = match first_wire_outcome {
            ConnectorHostControlOutcome::Lease { lease } => lease,
            _ => panic!("remote heartbeat returned an unexpected outcome"),
        };
        assert_eq!(remote_heartbeat.sequence, 9);
        let replayed_wire_outcome = remote
            .send_signed_body(&remote_heartbeat_request_id, &signed_heartbeat_body)
            .await
            .expect("exact wire replay after a lost response");
        assert_eq!(
            replayed_wire_outcome,
            ConnectorHostControlOutcome::Lease {
                lease: remote_heartbeat.clone()
            }
        );
        let changed_heartbeat = remote
            .signed_request(
                remote_heartbeat_request_id,
                ConnectorHostControlCommand::Heartbeat(ConnectorHostHeartbeat {
                    connector_ready: false,
                    ..remote_heartbeat_command.clone()
                }),
            )
            .expect("changed signed heartbeat fixture");
        let changed_heartbeat_body =
            serde_json::to_vec(&changed_heartbeat).expect("changed heartbeat body");
        let collision = remote
            .send_signed_body(
                &changed_heartbeat.request.request_id,
                &changed_heartbeat_body,
            )
            .await
            .expect_err("same wire request id with changed payload must fail closed");
        assert!(matches!(collision, ConnectorHostError::Admission(_)));
        let stale_remote = remote
            .heartbeat(remote_heartbeat_command)
            .await
            .expect_err("new remote request with stale lease fence must fail closed");
        assert!(matches!(stale_remote, ConnectorHostError::Admission(_)));
        let remote_draining = remote
            .drain(ConnectorHostTransition {
                replica_id: host.state.config.replica_id.clone(),
                previous_sequence: remote_heartbeat.sequence,
            })
            .await
            .expect("signed remote drain");
        assert_eq!(remote_draining.sequence, 10);
        remote
            .offline(ConnectorHostTransition {
                replica_id: host.state.config.replica_id.clone(),
                previous_sequence: remote_draining.sequence,
            })
            .await
            .expect("signed remote offline transition");
        let remote_offline = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("remote offline replica read")
            .expect("remote offline replica");
        assert_eq!(remote_offline.status, ConnectorReplicaStatus::Offline);
        assert_eq!(remote_offline.health_revision, 11);
        let historical_registration_replay = remote
            .send_signed_body(&remote_registration_request_id, &signed_registration_body)
            .await
            .expect_err("an older registration cannot be replayed after later lifecycle states");
        assert!(matches!(
            historical_registration_replay,
            ConnectorHostError::Admission(_)
        ));
        let recovered_from_offline = remote
            .heartbeat(ConnectorHostHeartbeat {
                replica_id: host.state.config.replica_id.clone(),
                previous_sequence: remote_offline.health_revision,
                in_flight: 0,
                connector_ready: true,
            })
            .await
            .expect("a healthy signed heartbeat must restore an offline replica");
        assert_eq!(recovered_from_offline.sequence, 12);
        let remote_recovered = registry
            .connector_replica(&host.state.config.replica_id)
            .await
            .expect("recovered remote replica read")
            .expect("recovered remote replica");
        assert_eq!(remote_recovered.status, ConnectorReplicaStatus::Ready);
        assert!(remote_recovered.lease_expires_at > OffsetDateTime::now_utc());
        server.abort();
        let _ = server.await;
    }
}
