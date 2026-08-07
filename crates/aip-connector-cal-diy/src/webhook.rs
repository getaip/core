//! Authenticated Cal.diy webhook ingestion.

use aip_connector::ConnectorSecret;
use aip_core::{
    Envelope, Event, EventId, EventStream, MessageBody, Principal, PrincipalId, PrincipalKind,
};
use aip_runtime::{ProfileStateCasOutcome, ProfileStateStore};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

const REPLAY_RETENTION_SECONDS: i64 = 86_400;
const REPLAY_CAPACITY: usize = 20_000;
const MAX_BODY_BYTES: usize = 1_048_576;
const MAX_EVENT_AGE_SECONDS: i64 = 86_400;
const MAX_FUTURE_SKEW_SECONDS: i64 = 300;
/// Only webhook payload version implemented by the referenced Cal.diy checkout.
pub const CAL_DIY_WEBHOOK_VERSION: &str = "2021-10-20";

/// Standard Cal.diy webhook body emitted when no custom payload template is configured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalDiyWebhook {
    /// Cal.diy webhook trigger, such as `BOOKING_CREATED`.
    #[serde(rename = "triggerEvent")]
    pub trigger_event: String,
    /// Provider event creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Trigger-specific provider payload.
    pub payload: Value,
}

/// Exact signed webhook delivery accepted by the connector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalDiyWebhookDelivery {
    /// Deployment-owned subscription id used to select the HMAC secret.
    pub subscription_id: String,
    /// `X-Cal-Signature-256` header value.
    pub signature: String,
    /// `X-Cal-Webhook-Version` header value, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_version: Option<String>,
    /// Original request body, byte-for-byte as received.
    pub raw_body: String,
    /// Trusted ingress receipt timestamp in Unix seconds.
    pub received_at: i64,
}

/// Webhook authenticity or replay failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CalDiyWebhookError {
    /// The signature is not a valid SHA-256 hex digest.
    #[error("Cal.diy webhook signature is not a 64-character SHA-256 hex digest")]
    InvalidSignatureEncoding,
    /// HMAC verification failed.
    #[error("Cal.diy webhook signature verification failed")]
    InvalidSignature,
    /// The signed body is not a standard Cal.diy JSON payload.
    #[error("invalid Cal.diy webhook payload: {0}")]
    InvalidPayload(String),
    /// The delivery is too large for the configured ingestion boundary.
    #[error("Cal.diy webhook body exceeds the 1 MiB ingestion limit")]
    BodyTooLarge,
    /// The unsigned webhook version header is absent or unsupported.
    #[error("unsupported Cal.diy webhook version `{0}`")]
    UnsupportedVersion(String),
    /// The signed event timestamp is stale or implausibly far in the future.
    #[error("Cal.diy webhook event timestamp is outside the accepted window")]
    TimestampSkew,
    /// No secret exists for the trusted subscription selector.
    #[error("unknown Cal.diy webhook subscription")]
    UnknownSubscription,
    /// Deployment secret lookup failed without exposing secret material.
    #[error("Cal.diy webhook secret resolver failed: {0}")]
    SecretResolver(String),
    /// The exact signed delivery was already accepted.
    #[error("Cal.diy webhook delivery `{0}` is a replay")]
    Replay(String),
    /// Durable replay fencing failed.
    #[error("Cal.diy webhook replay store failed: {0}")]
    ReplayStore(String),
    /// A stable AIP principal id could not be constructed.
    #[error("Cal.diy webhook identity mapping failed: {0}")]
    Identity(String),
}

/// Deployment-owned webhook secret lookup boundary.
#[async_trait]
pub trait CalDiyWebhookSecretResolver: Send + Sync {
    /// Resolves one opaque secret reference without exposing it in protocol state.
    async fn resolve(&self, secret_ref: &str) -> Result<Option<ConnectorSecret>, String>;
}

/// Static in-memory secret resolver for one process.
#[derive(Clone, Default)]
pub struct StaticCalDiyWebhookSecrets {
    secrets: Arc<BTreeMap<String, ConnectorSecret>>,
}

impl std::fmt::Debug for StaticCalDiyWebhookSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticCalDiyWebhookSecrets")
            .field("secret_refs", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl StaticCalDiyWebhookSecrets {
    /// Creates a resolver from opaque references and protected secret material.
    pub fn new(
        entries: impl IntoIterator<Item = (String, ConnectorSecret)>,
    ) -> Result<Self, String> {
        let mut secrets = BTreeMap::new();
        for (secret_ref, secret) in entries {
            if !valid_webhook_secret_ref(&secret_ref) || secret.is_empty() {
                return Err(
                    "webhook secret references must be bounded URL-segment-safe identifiers and values must be non-empty"
                        .to_owned(),
                );
            }
            if secrets.insert(secret_ref, secret).is_some() {
                return Err("duplicate webhook secret reference".to_owned());
            }
        }
        Ok(Self {
            secrets: Arc::new(secrets),
        })
    }
}

#[async_trait]
impl CalDiyWebhookSecretResolver for StaticCalDiyWebhookSecrets {
    async fn resolve(&self, secret_ref: &str) -> Result<Option<ConnectorSecret>, String> {
        Ok(self.secrets.get(secret_ref).cloned())
    }
}

/// Atomic replay-observation boundary for signed Cal.diy webhooks.
///
/// The authoritative deduplication boundary is the AIP event log, keyed by the
/// deterministic event id produced from the signed delivery digest. Returning
/// the same event for a provider retry prevents a crash between replay-state
/// admission and event persistence from losing the event permanently.
#[async_trait]
pub trait CalDiyWebhookReplayStore: Send + Sync {
    /// Records one digest exactly once and removes expired entries atomically.
    ///
    /// `false` means the digest was seen before; it is not an ingestion error.
    async fn admit(
        &self,
        digest: &str,
        accepted_at: i64,
        cutoff: i64,
        capacity: usize,
    ) -> Result<bool, String>;
}

/// Process-local replay store for tests and ephemeral deployments.
#[derive(Debug, Default)]
pub struct InMemoryCalDiyWebhookReplayStore {
    deliveries: Mutex<BTreeMap<String, i64>>,
}

/// Cluster-safe Cal.diy webhook replay store backed by runtime profile state.
///
/// The scope must be unique per connector instance. PostgreSQL-backed runtime
/// stores provide atomic compare-and-set across every replica, so two hosts
/// cannot admit the same signed delivery concurrently.
#[derive(Clone)]
pub struct ProfileStateCalDiyWebhookReplayStore {
    state: ProfileStateStore,
    scope: String,
}

impl std::fmt::Debug for ProfileStateCalDiyWebhookReplayStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProfileStateCalDiyWebhookReplayStore")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ProfileStateCalDiyWebhookReplayStore {
    /// Creates a shared replay fence for one logical connector instance.
    pub fn new(state: ProfileStateStore, scope: impl Into<String>) -> Result<Self, String> {
        let scope = scope.into();
        if scope.trim().is_empty() || scope.len() > 1_024 || scope.contains('\0') {
            return Err(
                "Cal.diy webhook replay scope must contain 1 to 1024 bytes without NUL".to_owned(),
            );
        }
        Ok(Self { state, scope })
    }
}

#[async_trait]
impl CalDiyWebhookReplayStore for ProfileStateCalDiyWebhookReplayStore {
    async fn admit(
        &self,
        digest: &str,
        accepted_at: i64,
        cutoff: i64,
        capacity: usize,
    ) -> Result<bool, String> {
        const NAMESPACE: &str = "aip.connector.cal_diy.webhook_replay.v1";
        for _ in 0..32 {
            let current = self
                .state
                .get(NAMESPACE, &self.scope)
                .await
                .map_err(|error| error.to_string())?;
            let mut deliveries = current
                .as_ref()
                .map(|entry| serde_json::from_value::<BTreeMap<String, i64>>(entry.value.clone()))
                .transpose()
                .map_err(|error| format!("decode Cal.diy webhook replay state: {error}"))?
                .unwrap_or_default();
            if deliveries.contains_key(digest) {
                return Ok(false);
            }
            if !admit_delivery(&mut deliveries, digest, accepted_at, cutoff, capacity) {
                return Ok(false);
            }
            match self
                .state
                .compare_and_set(
                    NAMESPACE,
                    &self.scope,
                    current.as_ref().map(|entry| entry.revision),
                    serde_json::to_value(deliveries)
                        .map_err(|error| format!("encode Cal.diy webhook replay state: {error}"))?,
                )
                .await
                .map_err(|error| error.to_string())?
            {
                ProfileStateCasOutcome::Applied(_) => return Ok(true),
                ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
            }
        }
        Err("Cal.diy webhook replay state remained contended after 32 attempts".to_owned())
    }
}

#[async_trait]
impl CalDiyWebhookReplayStore for InMemoryCalDiyWebhookReplayStore {
    async fn admit(
        &self,
        digest: &str,
        accepted_at: i64,
        cutoff: i64,
        capacity: usize,
    ) -> Result<bool, String> {
        let mut deliveries = self.deliveries.lock().await;
        Ok(admit_delivery(
            &mut deliveries,
            digest,
            accepted_at,
            cutoff,
            capacity,
        ))
    }
}

/// Durable single-process replay store using atomic file replacement.
///
/// A multi-replica deployment must provide a database-backed implementation
/// with a unique digest constraint instead of sharing this file.
#[derive(Debug)]
pub struct FileCalDiyWebhookReplayStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileCalDiyWebhookReplayStore {
    /// Creates a durable replay store at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// Returns the replay-state path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl CalDiyWebhookReplayStore for FileCalDiyWebhookReplayStore {
    async fn admit(
        &self,
        digest: &str,
        accepted_at: i64,
        cutoff: i64,
        capacity: usize,
    ) -> Result<bool, String> {
        let _guard = self.lock.lock().await;
        let mut deliveries = match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, i64>>(&bytes)
                .map_err(|error| format!("decode replay state: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(format!("read replay state: {error}")),
        };
        if !admit_delivery(&mut deliveries, digest, accepted_at, cutoff, capacity) {
            return Ok(false);
        }
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| format!("create replay-state directory: {error}"))?;
        }
        let temporary = self.path.with_extension("tmp");
        let encoded = serde_json::to_vec(&deliveries)
            .map_err(|error| format!("encode replay state: {error}"))?;
        tokio::fs::write(&temporary, encoded)
            .await
            .map_err(|error| format!("write replay state: {error}"))?;
        tokio::fs::rename(&temporary, &self.path)
            .await
            .map_err(|error| format!("replace replay state: {error}"))?;
        Ok(true)
    }
}

/// Verifies `X-Cal-Signature-256` against the exact raw request body.
pub fn verify_cal_diy_webhook(
    secret: &[u8],
    signature: &str,
    raw_body: &[u8],
) -> Result<(), CalDiyWebhookError> {
    if signature.len() != 64 {
        return Err(CalDiyWebhookError::InvalidSignatureEncoding);
    }
    let supplied =
        hex::decode(signature).map_err(|_| CalDiyWebhookError::InvalidSignatureEncoding)?;
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| CalDiyWebhookError::InvalidSignature)?;
    mac.update(raw_body);
    let expected = mac.finalize().into_bytes();
    if expected.len() != supplied.len()
        || !constant_time_eq::constant_time_eq(expected.as_slice(), &supplied)
    {
        return Err(CalDiyWebhookError::InvalidSignature);
    }
    Ok(())
}

/// Verifies, replay-observes, and maps one signed Cal.diy webhook delivery.
///
/// Duplicate deliveries intentionally return the same deterministic event.
/// Callers must append it to an idempotent AIP event log before acknowledging
/// the provider delivery.
pub async fn ingest_cal_diy_webhook(
    secret_resolver: &dyn CalDiyWebhookSecretResolver,
    replay_store: &dyn CalDiyWebhookReplayStore,
    delivery: CalDiyWebhookDelivery,
) -> Result<Vec<Envelope>, CalDiyWebhookError> {
    if delivery.raw_body.len() > MAX_BODY_BYTES {
        return Err(CalDiyWebhookError::BodyTooLarge);
    }
    let version = delivery
        .webhook_version
        .as_deref()
        .ok_or_else(|| CalDiyWebhookError::UnsupportedVersion("missing".to_owned()))?;
    if version != CAL_DIY_WEBHOOK_VERSION {
        return Err(CalDiyWebhookError::UnsupportedVersion(version.to_owned()));
    }
    if !valid_webhook_secret_ref(&delivery.subscription_id) {
        return Err(CalDiyWebhookError::UnknownSubscription);
    }
    let secret = secret_resolver
        .resolve(&delivery.subscription_id)
        .await
        .map_err(CalDiyWebhookError::SecretResolver)?
        .ok_or(CalDiyWebhookError::UnknownSubscription)?;
    verify_cal_diy_webhook(
        secret.expose_bytes(),
        &delivery.signature,
        delivery.raw_body.as_bytes(),
    )?;
    let digest = webhook_digest(
        &delivery.subscription_id,
        version,
        &delivery.signature,
        delivery.raw_body.as_bytes(),
    );
    let now = delivery.received_at;
    let webhook = parse_webhook(&delivery.raw_body, delivery.received_at)?;
    let event = event_from_webhook(
        webhook,
        digest.clone(),
        delivery.subscription_id,
        version.to_owned(),
        delivery.received_at,
    )?;
    let _new_delivery = replay_store
        .admit(
            &digest,
            now,
            now.saturating_sub(REPLAY_RETENTION_SECONDS),
            REPLAY_CAPACITY,
        )
        .await
        .map_err(CalDiyWebhookError::ReplayStore)?;
    Ok(vec![Envelope::new(MessageBody::EventStream(EventStream {
        events: vec![event],
        next_cursor: Some(digest),
    }))])
}

pub(crate) fn valid_webhook_secret_ref(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

/// Maps a verified Cal.diy webhook to one native AIP event record.
pub fn event_from_webhook(
    webhook: CalDiyWebhook,
    delivery_digest: String,
    subscription_id: String,
    webhook_version: String,
    received_at: i64,
) -> Result<Event, CalDiyWebhookError> {
    let actor = Principal::new(
        PrincipalId::parse("service:cal_diy:webhook")
            .map_err(|error| CalDiyWebhookError::Identity(error.to_string()))?,
        PrincipalKind::Service,
    );
    let occurred_at = OffsetDateTime::parse(
        &webhook.created_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|error| CalDiyWebhookError::InvalidPayload(error.to_string()))?;
    let delta = received_at.saturating_sub(occurred_at.unix_timestamp());
    if !(-MAX_FUTURE_SKEW_SECONDS..=MAX_EVENT_AGE_SECONDS).contains(&delta) {
        return Err(CalDiyWebhookError::TimestampSkew);
    }
    let event_id = EventId::parse(format!("evt_cal_diy_{delivery_digest}"))
        .map_err(|error| CalDiyWebhookError::Identity(error.to_string()))?;
    let kind = event_kind(&webhook.trigger_event)?;
    Ok(Event {
        id: event_id,
        kind: kind.to_owned(),
        occurred_at,
        session_id: None,
        action_id: None,
        correlation_id: None,
        actor: Some(actor),
        data: Some(json!({
        "triggerEvent": webhook.trigger_event,
        "createdAt": webhook.created_at,
        "payload": webhook.payload,
        "webhookVersion": webhook_version,
            "subscriptionId": subscription_id,
            "deliveryDigest": delivery_digest,
            "timestampProvenance": "signed_body"
        })),
    })
}

fn parse_webhook(raw_body: &str, received_at: i64) -> Result<CalDiyWebhook, CalDiyWebhookError> {
    let value = serde_json::from_str::<Value>(raw_body)
        .map_err(|error| CalDiyWebhookError::InvalidPayload(error.to_string()))?;
    if value.get("payload").is_some() {
        return serde_json::from_value(value)
            .map_err(|error| CalDiyWebhookError::InvalidPayload(error.to_string()));
    }
    let mut object = value.as_object().cloned().ok_or_else(|| {
        CalDiyWebhookError::InvalidPayload("webhook body must be a JSON object".to_owned())
    })?;
    let trigger_event = object
        .remove("triggerEvent")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| CalDiyWebhookError::InvalidPayload("missing triggerEvent".to_owned()))?;
    let created_at = object
        .remove("createdAt")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| {
            OffsetDateTime::from_unix_timestamp(received_at)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
    Ok(CalDiyWebhook {
        trigger_event,
        created_at,
        payload: Value::Object(object),
    })
}

fn webhook_digest(
    subscription_id: &str,
    version: &str,
    signature: &str,
    raw_body: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subscription_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(version.as_bytes());
    hasher.update(b"\0");
    hasher.update(signature.to_ascii_lowercase().as_bytes());
    hasher.update(b"\0");
    hasher.update(raw_body);
    hex::encode(hasher.finalize())
}

fn event_kind(trigger: &str) -> Result<&'static str, CalDiyWebhookError> {
    match trigger {
        "BOOKING_CREATED" => Ok("cal_diy.booking.created"),
        "BOOKING_PAYMENT_INITIATED" => Ok("cal_diy.booking.payment_initiated"),
        "BOOKING_PAID" => Ok("cal_diy.booking.paid"),
        "BOOKING_RESCHEDULED" => Ok("cal_diy.booking.rescheduled"),
        "BOOKING_REQUESTED" => Ok("cal_diy.booking.requested"),
        "BOOKING_CANCELLED" => Ok("cal_diy.booking.cancelled"),
        "BOOKING_REJECTED" => Ok("cal_diy.booking.rejected"),
        "BOOKING_NO_SHOW_UPDATED" => Ok("cal_diy.booking.no_show_updated"),
        "FORM_SUBMITTED" => Ok("cal_diy.form.submitted"),
        "MEETING_ENDED" => Ok("cal_diy.meeting.ended"),
        "MEETING_STARTED" => Ok("cal_diy.meeting.started"),
        "RECORDING_READY" => Ok("cal_diy.recording.ready"),
        "RECORDING_TRANSCRIPTION_GENERATED" => Ok("cal_diy.recording.transcription_generated"),
        "OOO_CREATED" => Ok("cal_diy.out_of_office.created"),
        "AFTER_HOSTS_CAL_VIDEO_NO_SHOW" => Ok("cal_diy.meeting.host_no_show"),
        "AFTER_GUESTS_CAL_VIDEO_NO_SHOW" => Ok("cal_diy.meeting.guest_no_show"),
        "FORM_SUBMITTED_NO_EVENT" => Ok("cal_diy.form.submitted_without_event"),
        "DELEGATION_CREDENTIAL_ERROR" => Ok("cal_diy.delegation.credential_error"),
        "WRONG_ASSIGNMENT_REPORT" => Ok("cal_diy.booking.wrong_assignment_reported"),
        other => Err(CalDiyWebhookError::InvalidPayload(format!(
            "unsupported triggerEvent `{other}`"
        ))),
    }
}

fn admit_delivery(
    deliveries: &mut BTreeMap<String, i64>,
    digest: &str,
    accepted_at: i64,
    cutoff: i64,
    capacity: usize,
) -> bool {
    deliveries.retain(|_, timestamp| *timestamp >= cutoff);
    if deliveries.contains_key(digest) {
        return false;
    }
    while deliveries.len() >= capacity {
        let Some(oldest) = deliveries
            .iter()
            .min_by_key(|(_, timestamp)| **timestamp)
            .map(|(digest, _)| digest.clone())
        else {
            break;
        };
        deliveries.remove(&oldest);
    }
    deliveries.insert(digest.to_owned(), accepted_at);
    true
}

#[cfg(test)]
mod tests {
    use super::{
        CAL_DIY_WEBHOOK_VERSION, CalDiyWebhookDelivery, CalDiyWebhookError,
        FileCalDiyWebhookReplayStore, InMemoryCalDiyWebhookReplayStore, StaticCalDiyWebhookSecrets,
        ingest_cal_diy_webhook, verify_cal_diy_webhook,
    };
    use aip_connector::ConnectorSecret;
    use aip_core::MessageBody;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::sync::Arc;
    use time::OffsetDateTime;

    fn body(trigger: &str, timestamp: i64) -> String {
        let created_at = OffsetDateTime::from_unix_timestamp(timestamp)
            .expect("timestamp")
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC3339");
        serde_json::json!({
            "triggerEvent": trigger,
            "createdAt": created_at,
            "payload": { "uid": "booking-1", "attendees": [{ "email": "a@example.test" }] }
        })
        .to_string()
    }

    fn signature(secret: &[u8], body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn resolver(secret: &[u8]) -> StaticCalDiyWebhookSecrets {
        StaticCalDiyWebhookSecrets::new([(
            "subscription-1".to_owned(),
            ConnectorSecret::new(secret),
        )])
        .expect("resolver")
    }

    fn delivery(secret: &[u8], body: String, received_at: i64) -> CalDiyWebhookDelivery {
        CalDiyWebhookDelivery {
            subscription_id: "subscription-1".to_owned(),
            signature: signature(secret, &body),
            webhook_version: Some(CAL_DIY_WEBHOOK_VERSION.to_owned()),
            raw_body: body,
            received_at,
        }
    }

    #[test]
    fn verifies_exact_raw_body_hmac() {
        let raw = r#"{"triggerEvent":"BOOKING_CREATED"}"#;
        let secret = b"webhook-secret";
        let signed = signature(secret, raw);
        verify_cal_diy_webhook(secret, &signed, raw.as_bytes()).expect("valid HMAC");
        assert_eq!(
            verify_cal_diy_webhook(secret, &signed, format!("{raw} ").as_bytes()),
            Err(CalDiyWebhookError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_malformed_signature() {
        assert_eq!(
            verify_cal_diy_webhook(b"secret", "abcd", b"{}"),
            Err(CalDiyWebhookError::InvalidSignatureEncoding)
        );
    }

    #[tokio::test]
    async fn maps_verified_delivery_to_native_event_stream() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let secret = b"webhook-secret";
        let envelopes = ingest_cal_diy_webhook(
            &resolver(secret),
            &InMemoryCalDiyWebhookReplayStore::default(),
            delivery(secret, body("BOOKING_CREATED", now), now),
        )
        .await
        .expect("ingestion");
        let MessageBody::EventStream(stream) = &envelopes[0].body else {
            panic!("expected event stream");
        };
        assert_eq!(stream.events[0].kind, "cal_diy.booking.created");
        assert_eq!(
            stream.events[0]
                .data
                .as_ref()
                .and_then(|value| value.pointer("/payload/uid")),
            Some(&serde_json::json!("booking-1"))
        );
    }

    #[tokio::test]
    async fn replay_returns_the_same_deterministic_event() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let secret = b"webhook-secret";
        let replay = Arc::new(InMemoryCalDiyWebhookReplayStore::default());
        let delivery = delivery(secret, body("BOOKING_CANCELLED", now), now);
        let first = ingest_cal_diy_webhook(&resolver(secret), replay.as_ref(), delivery.clone())
            .await
            .expect("first delivery");
        let mut alternate_hex_case = delivery;
        alternate_hex_case.signature = alternate_hex_case.signature.to_ascii_uppercase();
        let duplicate =
            ingest_cal_diy_webhook(&resolver(secret), replay.as_ref(), alternate_hex_case)
                .await
                .expect("duplicate delivery should remain persistable");
        assert_eq!(first[0].body, duplicate[0].body);
    }

    #[tokio::test]
    async fn file_replay_store_survives_reconstruction() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let secret = b"webhook-secret";
        let path = std::env::temp_dir().join(format!(
            "aip-cal-diy-webhook-{}-{}.json",
            std::process::id(),
            now
        ));
        let delivery = delivery(secret, body("BOOKING_RESCHEDULED", now), now);
        let first = ingest_cal_diy_webhook(
            &resolver(secret),
            &FileCalDiyWebhookReplayStore::new(&path),
            delivery.clone(),
        )
        .await
        .expect("first delivery");
        let duplicate = ingest_cal_diy_webhook(
            &resolver(secret),
            &FileCalDiyWebhookReplayStore::new(&path),
            delivery,
        )
        .await
        .expect("duplicate delivery should remain persistable after restart");
        assert_eq!(first[0].body, duplicate[0].body);
        let _ = tokio::fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn rejects_wrong_subscription_and_version() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let secret = b"webhook-secret";
        let mut unknown = delivery(secret, body("BOOKING_CREATED", now), now);
        unknown.subscription_id = "other".to_owned();
        assert_eq!(
            ingest_cal_diy_webhook(
                &resolver(secret),
                &InMemoryCalDiyWebhookReplayStore::default(),
                unknown,
            )
            .await,
            Err(CalDiyWebhookError::UnknownSubscription)
        );
        let mut wrong_version = delivery(secret, body("BOOKING_CREATED", now), now);
        wrong_version.webhook_version = Some("2099-01-01".to_owned());
        assert!(matches!(
            ingest_cal_diy_webhook(
                &resolver(secret),
                &InMemoryCalDiyWebhookReplayStore::default(),
                wrong_version,
            )
            .await,
            Err(CalDiyWebhookError::UnsupportedVersion(_))
        ));
    }

    #[tokio::test]
    async fn rejects_stale_signed_event_timestamp() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let secret = b"webhook-secret";
        assert_eq!(
            ingest_cal_diy_webhook(
                &resolver(secret),
                &InMemoryCalDiyWebhookReplayStore::default(),
                delivery(secret, body("BOOKING_CREATED", now - 90_000), now),
            )
            .await,
            Err(CalDiyWebhookError::TimestampSkew)
        );
    }

    #[test]
    fn static_resolver_rejects_non_routeable_secret_references() {
        for invalid in [
            String::new(),
            " leading".to_owned(),
            "contains/slash".to_owned(),
            "a".repeat(129),
        ] {
            assert!(
                StaticCalDiyWebhookSecrets::new([(invalid, ConnectorSecret::new("secret"),)])
                    .is_err()
            );
        }
    }
}
