//! Provider-boundary contract tests for the Cal.diy AIP connector.

#![allow(clippy::expect_used, clippy::panic)]

use aip_connector::{ConnectorContext, ConnectorError, ConnectorSecret, OutboundConnector};
use aip_connector_cal_diy::{
    CalDiyConnector, CalDiyWebhookDestinationPolicy, InMemoryCalDiyWebhookReplayStore,
    StaticCalDiyWebhookSecrets,
};
use aip_core::{Action, CapabilityId};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{net::TcpListener, sync::Mutex};

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    path: String,
    query: Option<String>,
    headers: HeaderMap,
    body: Value,
}

#[derive(Clone, Default)]
struct ProviderState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    fail_booking_create: Arc<AtomicBool>,
}

async fn provider(
    State(state): State<ProviderState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> impl IntoResponse {
    let body = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({ "invalid": true }))
    };
    state.requests.lock().await.push(CapturedRequest {
        method: method.clone(),
        path: uri.path().to_owned(),
        query: uri.query().map(ToOwned::to_owned),
        headers,
        body: body.clone(),
    });
    if method == Method::POST
        && uri.path() == "/v2/bookings"
        && state.fail_booking_create.load(Ordering::SeqCst)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({
                "status": "error",
                "error": { "code": "INTERNAL_SERVER_ERROR" }
            })),
        );
    }
    let response = match (method, uri.path()) {
        (Method::GET, "/v2/me") => json!({
            "status": "success",
            "data": { "id": 1, "username": "aip" }
        }),
        (Method::POST, "/v2/bookings") => json!({
            "status": "success",
            "data": { "uid": "booking-1", "metadata": body.get("metadata") }
        }),
        (Method::POST, "/v2/webhooks") => json!({
            "status": "success",
            "data": { "id": "webhook-1", "secret": body.get("secret") }
        }),
        _ => json!({ "status": "success", "data": body }),
    };
    (StatusCode::OK, axum::Json(response))
}

async fn start_provider(state: ProviderState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let app = Router::new()
        .route("/{*path}", any(provider))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider server");
    });
    (format!("http://{address}"), task)
}

fn booking_action(input: Value, idempotency_key: &str) -> Action {
    let mut action = Action::new(CapabilityId::trusted("cap:cal_diy:booking.create"), input);
    action.idempotency_key = Some(idempotency_key.to_owned());
    action
}

fn minimal_booking_input(start: &str) -> Value {
    json!({
        "start": start,
        "eventTypeId": 42,
        "attendee": {
            "name": "Ava",
            "email": "ava@example.test",
            "timeZone": "UTC"
        }
    })
}

#[tokio::test]
async fn booking_create_is_versioned_correlated_and_connector_idempotent() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector =
        CalDiyConnector::new(&base_url, "account-1", "cal_test_key").expect("connector");
    let input = json!({
        "start": "2050-01-01T10:00:00Z",
        "eventTypeId": 42,
        "attendee": {
            "name": "Ava",
            "email": "ava@example.test",
            "timeZone": "UTC"
        }
    });
    let first = connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(input.clone(), "booking-key-1"),
        )
        .await
        .expect("first invocation");
    let second = connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(input, "booking-key-1"),
        )
        .await
        .expect("deduplicated invocation");
    assert_eq!(first.output, second.output);

    let requests = state.requests.lock().await;
    let booking_requests = requests
        .iter()
        .filter(|request| request.path == "/v2/bookings")
        .collect::<Vec<_>>();
    assert_eq!(booking_requests.len(), 1);
    let request = booking_requests[0];
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request
            .headers
            .get("cal-api-version")
            .and_then(|value| value.to_str().ok()),
        Some("2024-08-13")
    );
    assert_eq!(
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer cal_test_key")
    );
    assert!(request.body.pointer("/metadata/aip_action_id").is_some());
    assert!(request.body.pointer("/metadata/aip_operation_id").is_some());
    assert!(
        request
            .body
            .pointer("/metadata/aip_idempotency_hash")
            .is_some()
    );
    server.abort();
}

#[tokio::test]
async fn idempotency_collision_is_rejected_before_second_provider_call() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(minimal_booking_input("2050-01-01T10:00:00Z"), "same-key"),
        )
        .await
        .expect("first invocation");
    let error = connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(minimal_booking_input("2050-01-02T10:00:00Z"), "same-key"),
        )
        .await
        .expect_err("collision must fail");
    assert!(error.to_string().contains("collided"));
    assert_eq!(state.requests.lock().await.len(), 1);
    server.abort();
}

#[tokio::test]
async fn ambiguous_server_failure_is_fenced_for_reconciliation() {
    let state = ProviderState::default();
    state.fail_booking_create.store(true, Ordering::SeqCst);
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    let input = minimal_booking_input("2050-01-01T10:00:00Z");
    let first = connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(input.clone(), "uncertain-key"),
        )
        .await
        .expect_err("provider 500 must fail");
    let ConnectorError::Failure(first) = first else {
        panic!("expected typed connector failure");
    };
    assert!(first.uncertain_outcome);
    assert!(!first.retryable);
    assert!(first.provider_operation.is_some());

    let second = connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(input, "uncertain-key"),
        )
        .await
        .expect_err("uncertain retry must be fenced");
    let ConnectorError::Failure(second) = second else {
        panic!("expected typed connector failure");
    };
    assert!(second.message.contains("requires reconciliation"));
    assert_eq!(second.provider_operation, first.provider_operation);
    assert_eq!(state.requests.lock().await.len(), 1);
    server.abort();
}

#[tokio::test]
async fn webhook_secret_reference_is_resolved_and_never_returned() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let secrets = StaticCalDiyWebhookSecrets::new([(
        "webhook-secret-1".to_owned(),
        ConnectorSecret::new("raw-provider-secret"),
    )])
    .expect("secret resolver");
    let connector = CalDiyConnector::new(&base_url, "account-1", "token")
        .expect("connector")
        .with_webhook_destination_policy(
            CalDiyWebhookDestinationPolicy::from_prefixes([
                "https://aip.example.test/connectors/cal-diy/webhooks/",
            ])
            .expect("webhook destination policy"),
        )
        .with_webhook_security(
            Arc::new(secrets),
            Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
        );
    let mut action = Action::new(
        CapabilityId::trusted("cap:cal_diy:webhook.create"),
        json!({
            "active": true,
            "subscriberUrl": "https://aip.example.test/connectors/cal-diy/webhooks/webhook-secret-1",
            "triggers": ["BOOKING_CREATED"],
            "webhook_secret_ref": "webhook-secret-1"
        }),
    );
    action.idempotency_key = Some("webhook-key".to_owned());
    let result = connector
        .invoke(&ConnectorContext::default(), action)
        .await
        .expect("webhook creation");
    assert_eq!(
        result
            .output
            .as_ref()
            .and_then(|output| output.pointer("/data/secret")),
        Some(&json!("[REDACTED]"))
    );
    let requests = state.requests.lock().await;
    let request = requests.last().expect("captured request");
    assert_eq!(
        request.body.get("secret"),
        Some(&json!("raw-provider-secret"))
    );
    assert!(request.body.get("webhook_secret_ref").is_none());
    assert_eq!(request.body.get("version"), Some(&json!("2021-10-20")));
    server.abort();
}

#[tokio::test]
async fn connection_calendar_create_partitions_path_query_and_json_body() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    let mut action = Action::new(
        CapabilityId::trusted("cap:cal_diy:calendar.connection.event.create"),
        json!({
            "connection_id": 73,
            "calendarId": "team/calendar@example.test",
            "title": "AIP calendar contract",
            "start": { "time": "2050-01-01T10:00:00Z", "timeZone": "UTC" },
            "end": { "time": "2050-01-01T10:30:00Z", "timeZone": "UTC" },
            "attendees": [{ "email": "ava@example.test", "name": "Ava" }]
        }),
    );
    action.idempotency_key = Some("calendar-create-key".to_owned());
    connector
        .invoke(&ConnectorContext::default(), action)
        .await
        .expect("calendar event creation");

    let requests = state.requests.lock().await;
    let request = requests.last().expect("captured request");
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path, "/v2/calendars/connections/73/events");
    let query = request.query.as_deref().expect("calendarId query");
    assert!(query.contains("calendarId=team%2Fcalendar%40example.test"));
    assert_eq!(
        request.body.get("title"),
        Some(&json!("AIP calendar contract"))
    );
    assert!(request.body.get("connection_id").is_none());
    assert!(request.body.get("calendarId").is_none());
    server.abort();
}

#[tokio::test]
async fn invalid_action_input_is_rejected_before_provider_dispatch() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    let error = connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(json!({ "start": "2050-01-01T10:00:00Z" }), "invalid-key"),
        )
        .await
        .expect_err("invalid booking input must fail locally");
    assert!(
        error
            .to_string()
            .contains("published `booking.create` schema")
    );
    assert!(state.requests.lock().await.is_empty());
    server.abort();
}

#[tokio::test]
async fn semantically_identical_reordered_input_reuses_the_idempotent_result() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    let first: Value = serde_json::from_str(
        r#"{"start":"2050-01-01T10:00:00Z","eventTypeId":42,"attendee":{"name":"Ava","email":"ava@example.test","timeZone":"UTC"}}"#,
    )
    .expect("first input");
    let reordered: Value = serde_json::from_str(
        r#"{"attendee":{"timeZone":"UTC","email":"ava@example.test","name":"Ava"},"eventTypeId":42,"start":"2050-01-01T10:00:00Z"}"#,
    )
    .expect("reordered input");

    connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(first, "canonical-key"),
        )
        .await
        .expect("first invocation");
    connector
        .invoke(
            &ConnectorContext::default(),
            booking_action(reordered, "canonical-key"),
        )
        .await
        .expect("canonical duplicate");

    assert_eq!(state.requests.lock().await.len(), 1);
    server.abort();
}

#[tokio::test]
async fn private_link_routes_use_the_unversioned_controller_default() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    connector
        .invoke(
            &ConnectorContext::default(),
            Action::new(
                CapabilityId::trusted("cap:cal_diy:event_type.private_link.list"),
                json!({ "event_type_id": 42 }),
            ),
        )
        .await
        .expect("private-link list");

    let requests = state.requests.lock().await;
    let request = requests.last().expect("captured private-link request");
    assert_eq!(request.path, "/v2/event-types/42/private-links");
    assert_eq!(
        request
            .headers
            .get("cal-api-version")
            .and_then(|value| value.to_str().ok()),
        Some("2024-04-15")
    );
    server.abort();
}

#[tokio::test]
async fn reservation_unknown_fields_are_rejected_before_provider_dispatch() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token").expect("connector");
    let mut action = Action::new(
        CapabilityId::trusted("cap:cal_diy:slot.reservation.create"),
        json!({
            "eventTypeId": 42,
            "slotStart": "2050-01-01T10:00:00Z",
            "unexpected": "must-not-reach-Cal.diy"
        }),
    );
    action.idempotency_key = Some("invalid-reservation".to_owned());
    connector
        .invoke(&ConnectorContext::default(), action)
        .await
        .expect_err("unknown reservation fields must fail locally");
    assert!(state.requests.lock().await.is_empty());
    server.abort();
}

#[tokio::test]
async fn webhook_destination_must_bind_the_configured_ingress_selector() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let secrets = StaticCalDiyWebhookSecrets::new([(
        "bookings".to_owned(),
        ConnectorSecret::new("provider-webhook-secret"),
    )])
    .expect("secret resolver");
    let connector = CalDiyConnector::new(&base_url, "account-1", "token")
        .expect("connector")
        .with_webhook_destination_policy(
            CalDiyWebhookDestinationPolicy::from_prefixes([
                "https://aip.example.test/connectors/cal-diy/webhooks/",
            ])
            .expect("webhook destination policy"),
        )
        .with_webhook_security(
            Arc::new(secrets),
            Arc::new(InMemoryCalDiyWebhookReplayStore::default()),
        );
    let mut action = Action::new(
        CapabilityId::trusted("cap:cal_diy:webhook.create"),
        json!({
            "active": true,
            "subscriberUrl": "https://aip.example.test/connectors/cal-diy/webhooks/different",
            "triggers": ["BOOKING_CREATED"],
            "webhook_secret_ref": "bookings"
        }),
    );
    action.idempotency_key = Some("mismatched-webhook".to_owned());
    let error = connector
        .invoke(&ConnectorContext::default(), action)
        .await
        .expect_err("mismatched webhook selector must fail");
    assert!(error.to_string().contains("prefix allowlist"));
    let mut rotation = Action::new(
        CapabilityId::trusted("cap:cal_diy:webhook.update"),
        json!({
            "webhook_id": "webhook-1",
            "webhook_secret_ref": "bookings"
        }),
    );
    rotation.idempotency_key = Some("unbound-webhook-rotation".to_owned());
    let error = connector
        .invoke(&ConnectorContext::default(), rotation)
        .await
        .expect_err("unbound secret rotation must fail");
    assert!(error.to_string().contains("rotation requires"));
    assert!(state.requests.lock().await.is_empty());
    server.abort();
}

#[tokio::test]
async fn provider_responses_are_streamed_through_a_deployment_owned_size_bound() {
    let state = ProviderState::default();
    let (base_url, server) = start_provider(state.clone()).await;
    let connector = CalDiyConnector::new(&base_url, "account-1", "token")
        .expect("connector")
        .with_max_response_bytes(16)
        .expect("response limit");
    let error = connector
        .invoke(
            &ConnectorContext::default(),
            Action::new(CapabilityId::trusted("cap:cal_diy:profile.get"), json!({})),
        )
        .await
        .expect_err("oversized provider response must be rejected");
    assert!(error.to_string().contains("size limit"));
    assert_eq!(state.requests.lock().await.len(), 1);
    server.abort();
}
