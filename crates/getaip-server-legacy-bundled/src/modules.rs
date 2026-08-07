//! Migration-only local module factories for the formerly bundled products.

use aip_connector::{
    Connector, ConnectorContext, ConnectorError, FrozenConnector, FrozenConnectorHandler,
    InboundConnector,
};
use aip_connector_cal_diy::{CONNECTOR_ID as CAL_DIY_CONNECTOR_ID, CalDiyConnector};
use aip_connector_enterprise_sandbox::{
    CONNECTOR_ID as ENTERPRISE_SANDBOX_CONNECTOR_ID, EnterpriseSandboxConnector,
};
use aip_connector_hermes_agent::{
    CONNECTOR_ID as HERMES_CONNECTOR_ID, HermesAgentConnector, HermesAgentEndpoint,
    HermesOperatorPolicy, RuntimeHermesDelegatedResultResolver,
};
use aip_connector_support_sandbox::{
    CONNECTOR_ID as SUPPORT_SANDBOX_CONNECTOR_ID, SupportSandboxConnector,
};
use aip_core::{CapabilityKind, Envelope, ErrorBody, ErrorCategory, MessageBody, ProtocolError};
use aip_runtime::Runtime;
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use getaip_server::{
    DaemonHttpMount, DaemonHttpRoute, DaemonModuleError, DaemonModuleFactory, DaemonServices,
    LocalModuleDescriptor, PreparedDaemonModule,
};
use serde_json::{Value, json};
use std::sync::Arc;

const CAL_DIY_WEBHOOK_MAX_BODY_BYTES: usize = 1_048_576;

fn module_error(code: &'static str, error: impl std::fmt::Display) -> DaemonModuleError {
    DaemonModuleError::new(code, error.to_string())
}

fn add_frozen_handlers<C>(
    mut module: PreparedDaemonModule,
    connector: Arc<C>,
) -> Result<PreparedDaemonModule, DaemonModuleError>
where
    C: FrozenConnector + Connector + 'static,
{
    for capability in module
        .manifest
        .capabilities
        .iter()
        .filter(|capability| capability.kind != CapabilityKind::Resource)
        .cloned()
        .collect::<Vec<_>>()
    {
        module = module.with_handler(
            capability.clone(),
            Arc::new(FrozenConnectorHandler::new(connector.clone(), capability)),
        )?;
    }
    Ok(module.with_connector_arc(connector))
}

/// Required Hermes migration module.
#[derive(Clone)]
pub struct HermesModuleFactory {
    endpoints: Vec<HermesAgentEndpoint>,
    policy: HermesOperatorPolicy,
}

impl HermesModuleFactory {
    #[must_use]
    pub fn new(endpoints: Vec<HermesAgentEndpoint>, policy: HermesOperatorPolicy) -> Self {
        Self { endpoints, policy }
    }
}

#[async_trait]
impl DaemonModuleFactory for HermesModuleFactory {
    fn descriptor(&self) -> LocalModuleDescriptor {
        LocalModuleDescriptor::required_static(HERMES_CONNECTOR_ID)
    }

    async fn prepare(
        &self,
        services: &DaemonServices,
    ) -> Result<PreparedDaemonModule, DaemonModuleError> {
        let stores = services.runtime_stores();
        let resolver_runtime = Runtime::with_stores(stores.clone());
        let connector = HermesAgentConnector::new(self.endpoints.clone())
            .map_err(|error| module_error("aip.server.module.hermes.create", error))?
            .with_operator_policy(self.policy.clone())
            .map_err(|error| module_error("aip.server.module.hermes.policy", error))?
            .with_profile_state_store(stores.profile_state)
            .with_approval_store(stores.approvals)
            .with_delegated_result_resolver(RuntimeHermesDelegatedResultResolver::new(
                &resolver_runtime,
            ));
        let manifest = connector
            .discover_manifest()
            .map_err(|error| module_error("aip.server.module.hermes.manifest", error))?;
        let connector = Arc::new(connector);
        let module = add_frozen_handlers(
            PreparedDaemonModule::new(self.descriptor(), manifest),
            connector.clone(),
        )?;
        Ok(module.with_delegation_router_arc(connector))
    }
}

/// Required Cal.diy migration module.
#[derive(Clone)]
pub struct CalDiyModuleFactory {
    connector: CalDiyConnector,
}

impl CalDiyModuleFactory {
    #[must_use]
    pub fn new(connector: CalDiyConnector) -> Self {
        Self { connector }
    }
}

#[async_trait]
impl DaemonModuleFactory for CalDiyModuleFactory {
    fn descriptor(&self) -> LocalModuleDescriptor {
        LocalModuleDescriptor::required_static(CAL_DIY_CONNECTOR_ID)
    }

    async fn prepare(
        &self,
        services: &DaemonServices,
    ) -> Result<PreparedDaemonModule, DaemonModuleError> {
        let stores = services.runtime_stores();
        let connector = Arc::new(
            self.connector
                .clone()
                .with_profile_state_store(stores.profile_state),
        );
        let manifest = connector
            .discover_manifest()
            .map_err(|error| module_error("aip.server.module.cal_diy.manifest", error))?;
        let module = add_frozen_handlers(
            PreparedDaemonModule::new(self.descriptor(), manifest),
            connector.clone(),
        )?;
        let state = CalWebhookState {
            connector,
            events: stores.events,
        };
        let router = Router::new()
            .route(
                "/connectors/cal-diy/webhooks/{subscription_id}",
                post(handle_cal_diy_webhook)
                    .layer(DefaultBodyLimit::max(CAL_DIY_WEBHOOK_MAX_BODY_BYTES)),
            )
            .with_state(state);
        let mount = DaemonHttpMount::new(
            vec![DaemonHttpRoute::new(
                "POST",
                "/connectors/cal-diy/webhooks/{subscription_id}",
            )?],
            router,
        )?;
        Ok(module.with_http_mount(mount))
    }
}

/// Required support sandbox migration module.
#[derive(Clone)]
pub struct SupportSandboxModuleFactory {
    database_url: String,
}

impl SupportSandboxModuleFactory {
    #[must_use]
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
        }
    }
}

#[async_trait]
impl DaemonModuleFactory for SupportSandboxModuleFactory {
    fn descriptor(&self) -> LocalModuleDescriptor {
        LocalModuleDescriptor::required_static(SUPPORT_SANDBOX_CONNECTOR_ID)
    }

    async fn prepare(
        &self,
        _services: &DaemonServices,
    ) -> Result<PreparedDaemonModule, DaemonModuleError> {
        let connector = Arc::new(
            SupportSandboxConnector::connect(&self.database_url)
                .await
                .map_err(|error| {
                    module_error("aip.server.module.support_sandbox.connect", error)
                })?,
        );
        let manifest = connector
            .discover_manifest()
            .map_err(|error| module_error("aip.server.module.support_sandbox.manifest", error))?;
        add_frozen_handlers(
            PreparedDaemonModule::new(self.descriptor(), manifest),
            connector,
        )
    }
}

/// Required enterprise sandbox migration module.
#[derive(Clone)]
pub struct EnterpriseSandboxModuleFactory {
    database_url: String,
}

impl EnterpriseSandboxModuleFactory {
    #[must_use]
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
        }
    }
}

#[async_trait]
impl DaemonModuleFactory for EnterpriseSandboxModuleFactory {
    fn descriptor(&self) -> LocalModuleDescriptor {
        LocalModuleDescriptor::required_static(ENTERPRISE_SANDBOX_CONNECTOR_ID)
    }

    async fn prepare(
        &self,
        _services: &DaemonServices,
    ) -> Result<PreparedDaemonModule, DaemonModuleError> {
        let connector = Arc::new(
            EnterpriseSandboxConnector::connect(&self.database_url)
                .await
                .map_err(|error| {
                    module_error("aip.server.module.enterprise_sandbox.connect", error)
                })?,
        );
        let manifest = connector.discover_manifest().map_err(|error| {
            module_error("aip.server.module.enterprise_sandbox.manifest", error)
        })?;
        add_frozen_handlers(
            PreparedDaemonModule::new(self.descriptor(), manifest),
            connector,
        )
    }
}

#[derive(Clone)]
struct CalWebhookState {
    connector: Arc<CalDiyConnector>,
    events: aip_runtime::EventLog,
}

async fn handle_cal_diy_webhook(
    State(state): State<CalWebhookState>,
    Path(subscription_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(signature) = webhook_header(&headers, "x-cal-signature-256") else {
        return webhook_error_response(
            StatusCode::UNAUTHORIZED,
            "connector.cal_diy.webhook_auth",
            "Cal.diy webhook authentication failed",
            ErrorCategory::Auth,
            false,
        );
    };
    let Some(webhook_version) = webhook_header(&headers, "x-cal-webhook-version") else {
        return webhook_error_response(
            StatusCode::BAD_REQUEST,
            "connector.cal_diy.webhook_policy",
            "Cal.diy webhook version header is required",
            ErrorCategory::Policy,
            false,
        );
    };
    let raw_body = match String::from_utf8(body.to_vec()) {
        Ok(raw_body) => raw_body,
        Err(_) => {
            return webhook_error_response(
                StatusCode::BAD_REQUEST,
                "connector.cal_diy.webhook_invalid_payload",
                "Cal.diy webhook body must be valid UTF-8 JSON",
                ErrorCategory::Permanent,
                false,
            );
        }
    };
    let payload = match serde_json::from_slice::<Value>(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return webhook_error_response(
                StatusCode::BAD_REQUEST,
                "connector.cal_diy.webhook_invalid_payload",
                "Cal.diy webhook body must be valid JSON",
                ErrorCategory::Permanent,
                false,
            );
        }
    };
    let mut context = ConnectorContext::default();
    context
        .metadata
        .insert("subscription_id".to_owned(), subscription_id);
    context.metadata.insert("signature".to_owned(), signature);
    context
        .metadata
        .insert("webhook_version".to_owned(), webhook_version);
    context.metadata.insert("raw_body".to_owned(), raw_body);
    let envelopes = match state.connector.ingest(&context, payload).await {
        Ok(envelopes) => envelopes,
        Err(error) => return connector_error_response(error),
    };
    for envelope in envelopes {
        let MessageBody::EventStream(stream) = envelope.body else {
            return webhook_error_response(
                StatusCode::BAD_GATEWAY,
                "connector.cal_diy.webhook_invalid_mapping",
                "Cal.diy webhook connector returned an invalid mapping",
                ErrorCategory::Connector,
                false,
            );
        };
        for event in stream.events {
            if state.events.append(event).await.is_err() {
                return webhook_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "connector.cal_diy.webhook_persistence",
                    "Cal.diy webhook event persistence is temporarily unavailable",
                    ErrorCategory::Temporary,
                    true,
                );
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

fn webhook_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn connector_error_response(error: ConnectorError) -> Response {
    let ConnectorError::Failure(failure) = error else {
        return webhook_error_response(
            StatusCode::BAD_REQUEST,
            "connector.cal_diy.webhook_invalid",
            "Cal.diy webhook delivery was rejected",
            ErrorCategory::Permanent,
            false,
        );
    };
    let status = match failure.category {
        ErrorCategory::Auth => StatusCode::UNAUTHORIZED,
        ErrorCategory::Policy | ErrorCategory::Permanent | ErrorCategory::Economic => {
            StatusCode::BAD_REQUEST
        }
        ErrorCategory::Temporary => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCategory::Connector | ErrorCategory::Transport => StatusCode::BAD_GATEWAY,
    };
    let message = match failure.category {
        ErrorCategory::Auth => "Cal.diy webhook authentication failed",
        ErrorCategory::Temporary => "Cal.diy webhook processing is temporarily unavailable",
        _ => "Cal.diy webhook delivery was rejected",
    };
    webhook_error_response(
        status,
        &failure.code,
        message,
        failure.category,
        failure.retryable,
    )
}

fn webhook_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    category: ErrorCategory,
    retryable: bool,
) -> Response {
    (
        status,
        Json(Envelope::new(MessageBody::Error(ErrorBody {
            error: ProtocolError {
                code: code.to_owned(),
                message: message.to_owned(),
                category,
                retryable: Some(retryable),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(
                    json!({ "component": "aip.server.cal_diy.webhook" }),
                )),
            },
        }))),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{CalDiyModuleFactory, HermesModuleFactory};
    use aip_connector::ConnectorSecret;
    use aip_connector_cal_diy::{
        CAL_DIY_WEBHOOK_VERSION, CalDiyConnector, InMemoryCalDiyWebhookReplayStore,
        StaticCalDiyWebhookSecrets,
    };
    use aip_connector_hermes_agent::{HermesAgentEndpoint, HermesOperatorPolicy};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        response::Response,
    };
    use getaip_server::{AipDaemon, AipDaemonConfig, AipDaemonDeployment};
    use hmac::{Hmac, Mac};
    use serde_json::{Value, json};
    use sha2::Sha256;
    use std::sync::Arc;
    use tower::util::ServiceExt;

    async fn webhook_error_snapshot(response: Response) -> Value {
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("webhook error body");
        let body: Value = serde_json::from_slice(&bytes).expect("webhook error JSON");
        json!({
            "status": status,
            "code": body.pointer("/body/error/error/code"),
            "message": body.pointer("/body/error/error/message"),
            "category": body.pointer("/body/error/error/category"),
            "retryable": body.pointer("/body/error/error/retryable"),
            "component": body.pointer("/body/error/error/source/component")
        })
    }

    #[tokio::test]
    async fn cal_module_preserves_manifest_readiness_and_signed_webhook() {
        let webhook_secret = b"cal-diy-webhook-test-secret";
        let connector = CalDiyConnector::new(
            "http://127.0.0.1:9",
            "primary-account",
            b"cal-diy-test-token",
        )
        .expect("Cal.diy connector")
        .with_webhook_security(
            Arc::new(
                StaticCalDiyWebhookSecrets::new([(
                    "subscription-one".to_owned(),
                    ConnectorSecret::new(webhook_secret),
                )])
                .expect("webhook secrets"),
            ),
            Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
        );
        let daemon = AipDaemon::new_with_deployment(
            AipDaemonConfig {
                allow_insecure_development: true,
                require_signed_envelopes: false,
                ..AipDaemonConfig::default()
            },
            AipDaemonDeployment::default().with_module_factory(CalDiyModuleFactory::new(connector)),
        )
        .await
        .expect("daemon");
        assert!(
            daemon
                .manifest()
                .capabilities
                .iter()
                .any(|capability| { capability.id.as_str() == "cap:cal_diy:profile.get" })
        );

        let created_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("timestamp");
        let raw_body = serde_json::to_vec(&json!({
            "triggerEvent": "BOOKING_CREATED",
            "createdAt": created_at,
            "payload": { "uid": "booking-module-test" }
        }))
        .expect("webhook body");
        let mut mac = Hmac::<Sha256>::new_from_slice(webhook_secret).expect("HMAC key");
        mac.update(&raw_body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let router = daemon.router();
        let error_fixtures: Value =
            serde_json::from_str(include_str!("../tests/fixtures/cal-webhook-errors.json"))
                .expect("valid Cal webhook error fixture");
        let missing_signature = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connectors/cal-diy/webhooks/subscription-one")
                    .header("content-type", "application/json")
                    .body(Body::from(raw_body.clone()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            webhook_error_snapshot(missing_signature).await,
            error_fixtures["missing_signature"]
        );
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connectors/cal-diy/webhooks/subscription-one")
                    .header("content-type", "application/json")
                    .header("x-cal-signature-256", signature.clone())
                    .header("x-cal-webhook-version", CAL_DIY_WEBHOOK_VERSION)
                    .body(Body::from(raw_body.clone()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let duplicate = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connectors/cal-diy/webhooks/subscription-one")
                    .header("content-type", "application/json")
                    .header("x-cal-signature-256", signature)
                    .header("x-cal-webhook-version", CAL_DIY_WEBHOOK_VERSION)
                    .body(Body::from(raw_body.clone()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);
        let forged = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connectors/cal-diy/webhooks/subscription-one")
                    .header("content-type", "application/json")
                    .header("x-cal-signature-256", "00".repeat(32))
                    .header("x-cal-webhook-version", CAL_DIY_WEBHOOK_VERSION)
                    .body(Body::from(raw_body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            webhook_error_snapshot(forged).await,
            error_fixtures["forged_signature"]
        );
    }

    #[tokio::test]
    async fn hermes_module_preserves_bundled_manifest_capabilities() {
        let endpoint = HermesAgentEndpoint::new(
            "hermes-one",
            "http://localhost:8642",
            Some("key".to_owned()),
        )
        .expect("endpoint");
        let daemon = AipDaemon::new_with_deployment(
            AipDaemonConfig::default(),
            AipDaemonDeployment::default().with_module_factory(HermesModuleFactory::new(
                vec![endpoint],
                HermesOperatorPolicy::default(),
            )),
        )
        .await
        .expect("daemon");
        let ids = daemon
            .manifest()
            .capabilities
            .iter()
            .map(|capability| capability.id.as_str())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"cap:hermes_agent:hermes-one:health"));
        assert!(ids.contains(&"cap:hermes_agent:hermes-one:chat"));
        assert!(ids.contains(&"cap:hermes_agent:hermes-one:operator"));
        let manifest_json = serde_json::to_value(daemon.manifest()).expect("manifest JSON");
        assert_eq!(
            manifest_json
                .pointer("/extensions/connectors/hermes-agent/capability_count")
                .and_then(Value::as_u64),
            Some(35)
        );
    }
}
