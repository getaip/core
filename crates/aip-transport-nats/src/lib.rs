//! Native NATS subject, header, and request/reply binding for AIP.
//!
//! This crate keeps NATS-specific behavior at the transport boundary. AIP
//! envelopes are encoded as JSON `TransportMessage` frames, while NATS subjects
//! and headers carry routing metadata for operators and subscribers.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{CorrelationId, Envelope, MessageType};
use aip_transport::{
    RawFrame, RequestReplyTransport, StreamingTransport, Transport, TransportError,
    TransportMessage, TransportResult, decode_json, encode_json,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;

/// Native NATS profile id.
pub const PROFILE_ID: &str = "aip.native.nats.v1";

/// Username/password authentication for a NATS connection.
///
/// The password is intentionally excluded from serialization and debug output.
/// Deployments should load it from a process-external secret source and attach
/// it to [`NatsTransportConfig`] only at connection time.
#[derive(Clone, PartialEq, Eq)]
pub struct NatsAuthentication {
    username: String,
    password: String,
}

impl NatsAuthentication {
    /// Creates username/password authentication.
    pub fn user_password(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, NatsTransportError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty() {
            return Err(NatsTransportError::Configuration(
                "NATS username must not be empty".to_owned(),
            ));
        }
        if password.is_empty() {
            return Err(NatsTransportError::Configuration(
                "NATS password must not be empty".to_owned(),
            ));
        }
        Ok(Self { username, password })
    }
}

impl fmt::Debug for NatsAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsAuthentication")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Subject components for the native NATS profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatsSubject {
    /// Trust domain.
    pub trust_domain: String,
    /// Service name.
    pub service: String,
    /// Service API version.
    pub version: String,
    /// AIP message type.
    pub message_type: MessageType,
}

impl NatsSubject {
    /// Creates a canonical request/reply subject.
    #[must_use]
    pub fn subject(&self) -> String {
        format!(
            "aip.v1.{}.{}.{}.{}",
            sanitize(&self.trust_domain),
            sanitize(&self.service),
            sanitize(&self.version),
            sanitize(self.message_type.as_str())
        )
    }

    /// Creates a service-wide subscription subject for all AIP message types.
    ///
    /// Daemons use this wildcard subject to receive every native message family
    /// for one trust-domain/service/version tuple while preserving the exact
    /// message type in headers and envelope payloads.
    #[must_use]
    pub fn service_wildcard_subject(&self) -> String {
        service_wildcard_subject(&self.trust_domain, &self.service, &self.version)
    }

    /// Creates a correlation-scoped stream subject.
    #[must_use]
    pub fn stream_subject(&self, correlation_id: &CorrelationId) -> String {
        format!(
            "aip.v1.{}.{}.{}.stream.{}",
            sanitize(&self.trust_domain),
            sanitize(&self.service),
            sanitize(&self.version),
            sanitize(correlation_id.as_str())
        )
    }
}

/// NATS transport configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NatsTransportConfig {
    /// NATS server URL.
    pub server_url: String,
    /// Base subject used for fire-and-forget publish operations.
    pub subject: NatsSubject,
    /// Optional queue group used by queue subscriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_group: Option<String>,
    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Runtime-only NATS authentication.
    #[serde(skip)]
    pub authentication: Option<NatsAuthentication>,
}

impl NatsTransportConfig {
    /// Creates a configuration for a NATS server and base AIP subject.
    #[must_use]
    pub fn new(server_url: impl Into<String>, subject: NatsSubject) -> Self {
        Self {
            server_url: server_url.into(),
            subject,
            queue_group: None,
            request_timeout_ms: default_request_timeout_ms(),
            authentication: None,
        }
    }

    /// Returns the configured request timeout.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

/// Error returned by NATS-specific helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NatsTransportError {
    /// Connection configuration is invalid.
    #[error("invalid NATS configuration: {0}")]
    Configuration(String),
    /// Header name or value failed validation.
    #[error("invalid NATS header: {0}")]
    Header(String),
    /// Message did not contain a valid AIP transport frame.
    #[error("invalid AIP frame: {0}")]
    Frame(String),
}

/// Native NATS transport for AIP envelopes.
#[derive(Clone)]
pub struct NatsTransport {
    client: async_nats::Client,
    config: NatsTransportConfig,
    subscriptions: Arc<Mutex<BTreeMap<String, async_nats::Subscriber>>>,
}

impl NatsTransport {
    /// Connects to NATS using the supplied configuration.
    pub async fn connect(config: NatsTransportConfig) -> TransportResult<Self> {
        let options = match &config.authentication {
            Some(authentication) => async_nats::ConnectOptions::with_user_and_password(
                authentication.username.clone(),
                authentication.password.clone(),
            ),
            None => async_nats::ConnectOptions::new(),
        };
        let client = options
            .connect(config.server_url.clone())
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))?;
        Ok(Self {
            client,
            config,
            subscriptions: Arc::default(),
        })
    }

    /// Creates a transport from an existing `async_nats::Client`.
    #[must_use]
    pub fn from_client(client: async_nats::Client, config: NatsTransportConfig) -> Self {
        Self {
            client,
            config,
            subscriptions: Arc::default(),
        }
    }

    /// Returns the underlying NATS client.
    #[must_use]
    pub fn client(&self) -> &async_nats::Client {
        &self.client
    }

    /// Returns the configured fire-and-forget subject.
    #[must_use]
    pub fn subject(&self) -> String {
        self.config.subject.subject()
    }

    /// Publishes a request and waits for one response.
    pub async fn request_on(
        &self,
        subject: impl Into<String>,
        message: TransportMessage,
    ) -> TransportResult<TransportMessage> {
        let frame = encode_json(&message)?;
        let response = self
            .client
            .send_request(
                subject.into(),
                async_nats::Request::new()
                    .headers(nats_headers_for_envelope(&message.envelope)?)
                    .timeout(Some(self.config.request_timeout()))
                    .payload(frame.payload),
            )
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))?;
        transport_message_from_nats(response).await
    }

    /// Subscribes to a subject and returns the underlying NATS subscriber.
    pub async fn subscribe_subject(
        &self,
        subject: impl Into<String>,
    ) -> TransportResult<async_nats::Subscriber> {
        self.client
            .subscribe(subject.into())
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))
    }

    /// Subscribes to every message type for the configured service.
    pub async fn subscribe_service(&self) -> TransportResult<async_nats::Subscriber> {
        self.subscribe_subject(self.config.subject.service_wildcard_subject())
            .await
    }

    /// Subscribes to every message type for the configured service with a queue group.
    pub async fn queue_subscribe_service(
        &self,
        queue_group: impl Into<String>,
    ) -> TransportResult<async_nats::Subscriber> {
        self.queue_subscribe_subject(
            self.config.subject.service_wildcard_subject(),
            queue_group.into(),
        )
        .await
    }

    /// Publishes a response to a concrete NATS reply subject.
    pub async fn respond_to(
        &self,
        reply_subject: async_nats::Subject,
        message: TransportMessage,
    ) -> TransportResult<()> {
        let frame = encode_json(&message)?;
        self.client
            .publish_with_headers(
                reply_subject,
                nats_headers_for_envelope(&message.envelope)?,
                frame.payload,
            )
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))
    }

    /// Subscribes to a subject using a NATS queue group.
    pub async fn queue_subscribe_subject(
        &self,
        subject: impl Into<String>,
        queue_group: impl Into<String>,
    ) -> TransportResult<async_nats::Subscriber> {
        self.client
            .queue_subscribe(subject.into(), queue_group.into())
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))
    }

    /// Receives and decodes the next message from a subscriber.
    pub async fn next_message(
        subscriber: &mut async_nats::Subscriber,
    ) -> TransportResult<Option<TransportMessage>> {
        match subscriber.next().await {
            Some(message) => transport_message_from_nats(message).await.map(Some),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn publish(&self, message: TransportMessage) -> TransportResult<()> {
        let frame = encode_json(&message)?;
        self.client
            .publish_with_headers(
                self.subject(),
                nats_headers_for_envelope(&message.envelope)?,
                frame.payload,
            )
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))
    }
}

#[async_trait]
impl RequestReplyTransport for NatsTransport {
    async fn request(&self, message: TransportMessage) -> TransportResult<TransportMessage> {
        self.request_on(self.subject(), message).await
    }
}

#[async_trait]
impl StreamingTransport for NatsTransport {
    async fn subscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()> {
        let subject = self.config.subject.stream_subject(correlation_id);
        let subscriber = if let Some(queue_group) = &self.config.queue_group {
            self.queue_subscribe_subject(subject.clone(), queue_group.clone())
                .await?
        } else {
            self.subscribe_subject(subject.clone()).await?
        };
        self.subscriptions
            .lock()
            .map_err(|error| TransportError::Connection(error.to_string()))?
            .insert(correlation_id.to_string(), subscriber);
        Ok(())
    }

    async fn unsubscribe(&self, correlation_id: &CorrelationId) -> TransportResult<()> {
        self.subscriptions
            .lock()
            .map_err(|error| TransportError::Connection(error.to_string()))?
            .remove(correlation_id.as_str());
        Ok(())
    }
}

/// Builds standard NATS headers for an envelope.
pub fn nats_headers_for_envelope(envelope: &Envelope) -> TransportResult<async_nats::HeaderMap> {
    let mut headers = async_nats::HeaderMap::new();
    insert_header(&mut headers, "AIP-Version", &envelope.aip_version)?;
    insert_header(
        &mut headers,
        "AIP-Message-Type",
        envelope.message_type.as_str(),
    )?;
    insert_header(
        &mut headers,
        "AIP-Message-Id",
        &envelope.message_id.to_string(),
    )?;
    if let Some(session_id) = &envelope.session_id {
        insert_header(&mut headers, "AIP-Session-Id", &session_id.to_string())?;
    }
    if let Some(correlation_id) = &envelope.correlation_id {
        insert_header(
            &mut headers,
            "AIP-Correlation-Id",
            &correlation_id.to_string(),
        )?;
    }
    Ok(headers)
}

/// Creates a service-wide wildcard subject for daemon subscriptions.
#[must_use]
pub fn service_wildcard_subject(
    trust_domain: impl AsRef<str>,
    service: impl AsRef<str>,
    version: impl AsRef<str>,
) -> String {
    format!(
        "aip.v1.{}.{}.{}.>",
        sanitize(trust_domain.as_ref()),
        sanitize(service.as_ref()),
        sanitize(version.as_ref())
    )
}

/// Decodes a NATS message into an AIP transport message.
pub async fn transport_message_from_nats(
    message: async_nats::Message,
) -> TransportResult<TransportMessage> {
    let metadata = metadata_from_headers(message.headers.as_ref());
    decode_json(&RawFrame {
        payload: message.payload.clone(),
        metadata: metadata.clone(),
    })
    .or_else(|transport_error| {
        serde_json::from_slice::<Envelope>(&message.payload)
            .map(|envelope| TransportMessage { envelope, metadata })
            .map_err(|envelope_error| {
                TransportError::Codec(format!(
                    "expected TransportMessage or Envelope JSON: {transport_error}; {envelope_error}"
                ))
            })
    })
}

fn metadata_from_headers(headers: Option<&async_nats::HeaderMap>) -> BTreeMap<String, String> {
    headers.map_or_else(BTreeMap::new, |headers| {
        headers
            .iter()
            .filter_map(|(name, values)| {
                values
                    .iter()
                    .next()
                    .map(|value| (name.to_string().to_ascii_lowercase(), value.to_string()))
            })
            .collect()
    })
}

fn sanitize(value: &str) -> String {
    value.replace(['.', ' ', '/', '\\'], "_")
}

fn insert_header(
    headers: &mut async_nats::HeaderMap,
    name: &str,
    value: &str,
) -> TransportResult<()> {
    let name = async_nats::HeaderName::from_str(name)
        .map_err(|error| TransportError::Codec(error.to_string()))?;
    let value = async_nats::HeaderValue::from_str(value)
        .map_err(|error| TransportError::Codec(error.to_string()))?;
    headers.insert(name, value);
    Ok(())
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::{
        NatsAuthentication, NatsSubject, NatsTransportConfig, nats_headers_for_envelope,
        service_wildcard_subject, transport_message_from_nats,
    };
    use aip_core::{Envelope, ManifestRequest, MessageBody, MessageType, ProfileId};

    #[test]
    fn subject_uses_aip_v1_prefix() {
        let subject = NatsSubject {
            trust_domain: "example.com".to_owned(),
            service: "gateway".to_owned(),
            version: "v1".to_owned(),
            message_type: MessageType::Action,
        };
        assert_eq!(
            subject.subject(),
            "aip.v1.example_com.gateway.v1.aip_core_v1_action"
        );
    }

    #[test]
    fn headers_include_required_aip_metadata() {
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: vec![ProfileId::from("aip.native.nats.v1")],
            filter: None,
        }));
        let headers = nats_headers_for_envelope(&envelope).expect("headers");

        assert_eq!(
            headers
                .get("AIP-Version")
                .map(async_nats::HeaderValue::to_string)
                .as_deref(),
            Some("1.0")
        );
        assert_eq!(
            headers
                .get("AIP-Message-Type")
                .map(async_nats::HeaderValue::to_string)
                .as_deref(),
            Some("aip.discovery.v1.manifest_request")
        );
    }

    #[test]
    fn service_wildcard_subject_sanitizes_routing_components() {
        assert_eq!(
            service_wildcard_subject("local.example", "aip daemon", "v1"),
            "aip.v1.local_example.aip_daemon.v1.>"
        );
    }

    #[test]
    fn authentication_is_redacted_and_omitted_from_serialized_config() {
        let secret = "nats-password-that-must-not-leak";
        let authentication =
            NatsAuthentication::user_password("getaip-server", secret).expect("authentication");
        assert!(!format!("{authentication:?}").contains(secret));

        let mut config = NatsTransportConfig::new(
            "nats://127.0.0.1:4222",
            NatsSubject {
                trust_domain: "local".to_owned(),
                service: "gateway".to_owned(),
                version: "v1".to_owned(),
                message_type: MessageType::Action,
            },
        );
        config.authentication = Some(authentication);

        let encoded = serde_json::to_string(&config).expect("serialized config");
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("authentication"));
    }

    #[tokio::test]
    async fn raw_envelope_payload_decodes_as_transport_message() {
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: vec![ProfileId::from("aip.native.nats.v1")],
            filter: None,
        }));
        let payload = serde_json::to_vec(&envelope).expect("json");
        let length = payload.len();
        let message = async_nats::Message {
            subject: async_nats::Subject::from_static("aip.v1.local.gateway.v1.test"),
            reply: None,
            payload: payload.into(),
            headers: None,
            status: None,
            description: None,
            length,
        };
        let decoded = transport_message_from_nats(message).await.expect("decoded");
        assert_eq!(decoded.envelope.message_id, envelope.message_id);
    }
}
