//! Deterministic, credential-checking upstream fixture for product-fleet qualification.
//!
//! The binary exercises real connector HTTP clients, TLS routing, credential
//! isolation, request shaping, and response handling. It is deliberately not a
//! provider emulator and cannot replace qualification against pinned upstream
//! product builds. Every accepted request is retained as a bounded, redacted
//! audit record so the Docker gate can prove the exact route and headers used.

#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_AUDIT_RECORDS: usize = 10_000;

#[derive(Debug, Parser)]
#[command(name = "aip-product-upstream-fixture", version, about)]
struct Args {
    /// Internal listener address. TLS terminates at the qualification edge.
    #[arg(long, default_value = "0.0.0.0:8095")]
    bind: SocketAddr,
    /// Cal.diy bearer-token file.
    #[arg(long)]
    cal_token_file: PathBuf,
    /// Hermes API-server key file.
    #[arg(long)]
    hermes_token_file: PathBuf,
    /// Chatwoot API-token file.
    #[arg(long)]
    chatwoot_token_file: PathBuf,
    /// Dify app API-key file.
    #[arg(long)]
    dify_app_token_file: PathBuf,
    /// Dify Knowledge API-key file.
    #[arg(long)]
    dify_knowledge_token_file: PathBuf,
    /// Twenty workspace API-token file.
    #[arg(long)]
    twenty_token_file: PathBuf,
}

#[derive(Clone)]
struct FixtureState {
    credentials: Arc<Credentials>,
    audit: Arc<Mutex<VecDeque<AuditRecord>>>,
}

struct Credentials {
    cal: Vec<u8>,
    hermes: Vec<u8>,
    chatwoot: Vec<u8>,
    dify_app: Vec<u8>,
    dify_knowledge: Vec<u8>,
    twenty: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
struct AuditRecord {
    observed_at_unix_ms: u128,
    product: String,
    method: String,
    path_and_query: String,
    request_bytes: usize,
    request_sha256: String,
    authorization_present: bool,
    idempotency_key_present: bool,
    status: u16,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    let state = FixtureState {
        credentials: Arc::new(Credentials {
            cal: read_secret(&args.cal_token_file)?,
            hermes: read_secret(&args.hermes_token_file)?,
            chatwoot: read_secret(&args.chatwoot_token_file)?,
            dify_app: read_secret(&args.dify_app_token_file)?,
            dify_knowledge: read_secret(&args.dify_knowledge_token_file)?,
            twenty: read_secret(&args.twenty_token_file)?,
        }),
        audit: Arc::new(Mutex::new(VecDeque::new())),
    };
    let app = Router::new()
        .route("/ready", get(ready))
        .route("/__fixture/audit", get(audit))
        .fallback(provider)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .map_err(|error| format!("cannot bind product fixture: {error}"))?;
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("product fixture stopped: {error}"))
}

async fn ready() -> Json<Value> {
    Json(json!({ "status": "ready" }))
}

async fn audit(State(state): State<FixtureState>) -> Json<Value> {
    let records = state
        .audit
        .lock()
        .map_or_else(|_| Vec::new(), |records| records.iter().cloned().collect());
    Json(json!({ "records": records }))
}

async fn provider(
    State(state): State<FixtureState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let product = headers
        .get("x-aip-fixture-product")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    let status_and_body = match authorize(product, &headers, &state.credentials, uri.path()) {
        Ok(()) => fixture_response(product, &method, &uri, &headers, &body),
        Err(status) => (status, json!({ "error": "fixture authentication failed" })),
    };
    record_request(
        &state,
        product,
        &method,
        &uri,
        &headers,
        &body,
        status_and_body.0,
    );
    (status_and_body.0, Json(status_and_body.1)).into_response()
}

fn authorize(
    product: &str,
    headers: &HeaderMap,
    credentials: &Credentials,
    path: &str,
) -> Result<(), StatusCode> {
    if product == "hermes" && path == "/health" {
        return Ok(());
    }
    let (header_name, prefix, expected) = match product {
        "cal-diy" => (
            "authorization",
            b"Bearer ".as_slice(),
            credentials.cal.as_slice(),
        ),
        "hermes" => (
            "authorization",
            b"Bearer ".as_slice(),
            credentials.hermes.as_slice(),
        ),
        "chatwoot" => (
            "api_access_token",
            b"".as_slice(),
            credentials.chatwoot.as_slice(),
        ),
        "dify" if is_dify_knowledge_path(path) => (
            "authorization",
            b"Bearer ".as_slice(),
            credentials.dify_knowledge.as_slice(),
        ),
        "dify" => (
            "authorization",
            b"Bearer ".as_slice(),
            credentials.dify_app.as_slice(),
        ),
        "twenty" => (
            "authorization",
            b"Bearer ".as_slice(),
            credentials.twenty.as_slice(),
        ),
        _ => return Err(StatusCode::NOT_FOUND),
    };
    let supplied = headers
        .get(header_name)
        .map(|value| value.as_bytes())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut wanted = Vec::with_capacity(prefix.len() + expected.len());
    wanted.extend_from_slice(prefix);
    wanted.extend_from_slice(expected);
    if !constant_time_eq::constant_time_eq(supplied, &wanted) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn fixture_response(
    product: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> (StatusCode, Value) {
    let path = uri.path();
    match (product, method.as_str(), path) {
        ("cal-diy", "GET", "/v2/me") => (
            StatusCode::OK,
            json!({ "status": "success", "data": { "id": 42, "email": "qualification@example.invalid" } }),
        ),
        ("cal-diy", "PATCH", "/v2/me") if valid_idempotent_json_request(headers, body, "name") => (
            StatusCode::OK,
            json!({ "status": "success", "data": { "id": 42, "name": "Qualification Operator" } }),
        ),
        ("cal-diy", "PATCH", "/v2/me") => invalid_mutation_request(),
        ("hermes", "GET", "/health") => (
            StatusCode::OK,
            json!({ "status": "ok", "platform": "api", "version": "qualification" }),
        ),
        ("hermes", "GET", "/health/detailed") => (
            StatusCode::OK,
            json!({ "status": "ok", "cron_available": true }),
        ),
        ("hermes", "GET", "/v1/models") => (
            StatusCode::OK,
            json!({ "object": "list", "data": [{ "id": "qualification-model", "object": "model" }] }),
        ),
        ("hermes", "GET", "/api/jobs") => (StatusCode::OK, json!({ "jobs": [] })),
        ("hermes", "POST", "/api/jobs")
            if valid_idempotent_json_request(headers, body, "schedule") =>
        {
            (
                StatusCode::CREATED,
                json!({ "id": "abcdef123456", "name": "Qualification Job", "enabled": true }),
            )
        }
        ("hermes", "POST", "/api/jobs") => invalid_mutation_request(),
        ("chatwoot", "GET", "/api/v1/accounts/42") => (
            StatusCode::OK,
            json!({ "id": 42, "name": "Qualification Account" }),
        ),
        ("chatwoot", "GET", "/api/v1/accounts/42/agents") => (
            StatusCode::OK,
            json!({ "payload": [{ "id": 7, "name": "Qualification Agent" }] }),
        ),
        ("chatwoot", "POST", "/api/v1/accounts/42/conversations")
            if valid_idempotent_json_request(headers, body, "source_id") =>
        {
            (
                StatusCode::OK,
                json!({ "id": 9001, "status": "open", "source_id": "qualification-source" }),
            )
        }
        ("chatwoot", "POST", "/api/v1/accounts/42/conversations") => invalid_mutation_request(),
        ("dify", "GET", "/v1/parameters") => (
            StatusCode::OK,
            json!({ "opening_statement": "qualification", "user_input_form": [] }),
        ),
        ("dify", "GET", "/v1/datasets") => (
            StatusCode::OK,
            json!({ "data": [], "has_more": false, "limit": 1, "total": 0 }),
        ),
        ("dify", "POST", "/v1/datasets")
            if valid_idempotent_json_request(headers, body, "name") =>
        {
            (
                StatusCode::CREATED,
                json!({ "id": "dataset-qualification", "name": "Qualification Dataset" }),
            )
        }
        ("dify", "POST", "/v1/datasets") => invalid_mutation_request(),
        ("twenty", "HEAD", "/rest/open-api/core") => (StatusCode::OK, json!({})),
        ("twenty", "GET", "/rest/metadata/objects") => (
            StatusCode::OK,
            json!({
                "data": [{
                    "id": "11111111-1111-4111-8111-111111111111",
                    "nameSingular": "person",
                    "namePlural": "people"
                }]
            }),
        ),
        ("twenty", "GET", "/rest/people") => (
            StatusCode::OK,
            json!({ "data": [], "pageInfo": { "hasNextPage": false } }),
        ),
        ("twenty", "POST", "/rest/people")
            if valid_idempotent_json_request(headers, body, "id") =>
        {
            let record = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
            (StatusCode::CREATED, json!({ "data": record }))
        }
        ("twenty", "POST", "/rest/people") => invalid_mutation_request(),
        _ => (
            StatusCode::NOT_FOUND,
            json!({ "error": "unimplemented fixture route" }),
        ),
    }
}

fn invalid_mutation_request() -> (StatusCode, Value) {
    (
        StatusCode::BAD_REQUEST,
        json!({ "error": "qualification mutation requires idempotency and expected JSON" }),
    )
}

fn valid_idempotent_json_request(headers: &HeaderMap, body: &[u8], required_field: &str) -> bool {
    if headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|object| object.contains_key(required_field))
}

fn is_dify_knowledge_path(path: &str) -> bool {
    path == "/v1/datasets"
        || path.starts_with("/v1/datasets/")
        || path.starts_with("/v1/tags")
        || path.starts_with("/v1/indexing-estimate")
}

fn record_request(
    state: &FixtureState,
    product: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    status: StatusCode,
) {
    let record = AuditRecord {
        observed_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis()),
        product: product.to_owned(),
        method: method.to_string(),
        path_and_query: uri
            .path_and_query()
            .map_or_else(|| uri.path().to_owned(), ToString::to_string),
        request_bytes: body.len(),
        request_sha256: hex::encode(Sha256::digest(body)),
        authorization_present: headers.contains_key("authorization")
            || headers.contains_key("api_access_token"),
        idempotency_key_present: headers.contains_key("idempotency-key"),
        status: status.as_u16(),
    };
    if let Ok(mut records) = state.audit.lock() {
        if records.len() == MAX_AUDIT_RECORDS {
            records.pop_front();
        }
        records.push_back(record.clone());
    }
    if let Ok(encoded) = serde_json::to_string(&record) {
        println!("{encoded}");
    }
}

fn read_secret(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect secret `{}`: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "secret `{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!("secret `{}` must have mode 0600", path.display()));
        }
    }
    if metadata.len() == 0 || metadata.len() > MAX_SECRET_BYTES as u64 {
        return Err(format!(
            "secret `{}` must contain 1 to {MAX_SECRET_BYTES} bytes",
            path.display()
        ));
    }
    let value = fs::read(path)
        .map_err(|error| format!("cannot read secret `{}`: {error}", path.display()))?;
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    let trimmed = &value[start..end];
    if trimmed.is_empty() {
        return Err(format!("secret `{}` is empty", path.display()));
    }
    Ok(trimmed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{Credentials, authorize, fixture_response, is_dify_knowledge_path};
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};

    fn credentials() -> Credentials {
        Credentials {
            cal: b"cal".to_vec(),
            hermes: b"hermes".to_vec(),
            chatwoot: b"chatwoot".to_vec(),
            dify_app: b"dify-app".to_vec(),
            dify_knowledge: b"dify-knowledge".to_vec(),
            twenty: b"twenty".to_vec(),
        }
    }

    #[test]
    fn product_credentials_are_isolated_and_compared_by_exact_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer cal"));
        assert!(authorize("cal-diy", &headers, &credentials(), "/v2/me").is_ok());
        assert_eq!(
            authorize("hermes", &headers, &credentials(), "/v1/models"),
            Err(StatusCode::UNAUTHORIZED)
        );

        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer dify-knowledge"),
        );
        assert!(authorize("dify", &headers, &credentials(), "/v1/datasets").is_ok());
        assert_eq!(
            authorize("dify", &headers, &credentials(), "/v1/parameters"),
            Err(StatusCode::UNAUTHORIZED)
        );

        headers.insert("authorization", HeaderValue::from_static("Bearer twenty"));
        assert!(authorize("twenty", &headers, &credentials(), "/rest/people").is_ok());
    }

    #[test]
    fn fixture_accepts_only_the_frozen_qualification_routes() {
        let uri = Uri::from_static("/api/jobs?include_disabled=true");
        let headers = HeaderMap::new();
        let (status, body) = fixture_response("hermes", &Method::GET, &uri, &headers, b"");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["jobs"], serde_json::json!([]));

        let (status, _) = fixture_response(
            "hermes",
            &Method::POST,
            &Uri::from_static("/api/jobs"),
            &headers,
            b"{}",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(is_dify_knowledge_path("/v1/datasets/example/documents"));
        assert!(!is_dify_knowledge_path("/v1/parameters"));

        let (status, _) = fixture_response(
            "twenty",
            &Method::HEAD,
            &Uri::from_static("/rest/open-api/core"),
            &headers,
            b"",
        );
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn qualification_mutations_require_idempotency_and_expected_json_shape() {
        let uri = Uri::from_static("/api/jobs");
        let mut headers = HeaderMap::new();
        let (status, _) = fixture_response(
            "hermes",
            &Method::POST,
            &uri,
            &headers,
            br#"{"name":"Qualification Job","schedule":"0 * * * *"}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);

        headers.insert(
            "idempotency-key",
            HeaderValue::from_static("qualification-job-v1"),
        );
        let (status, body) = fixture_response(
            "hermes",
            &Method::POST,
            &uri,
            &headers,
            br#"{"name":"Qualification Job","schedule":"0 * * * *"}"#,
        );
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["id"], "abcdef123456");
    }
}
