//! Production daemon smoke check for Hermes Agent through AIP HTTP.
//!
//! This binary validates the deployed path:
//! external client -> `getaip-server` HTTP -> AIP gateway/runtime -> Hermes connector ->
//! Hermes Agent -> OpenRouter-compatible chat response.

#![forbid(unsafe_code)]

use aip_connector_hermes_agent::PROFILE_ID;
use aip_core::{
    Action, ActionResult, ActionResultStatus, CapabilityId, Envelope, Handshake, HandshakeStatus,
    Manifest, MessageBody, Principal, PrincipalId, PrincipalKind, ProfileId, SessionId,
};
use clap::Parser;
use reqwest::{
    Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{env, process::ExitCode};

#[derive(Debug, Parser)]
#[command(
    name = "getaip-server-hermes-chat-smoke",
    about = "Validate Hermes Agent chat through a deployed getaip-server HTTP endpoint."
)]
struct Args {
    /// Base URL of the deployed AIP daemon.
    #[arg(long = "getaip-server-url", default_value = "http://127.0.0.1:18080")]
    server_url: String,
    /// Bearer token enforced by the native AIP HTTP edge.
    #[arg(long = "native-bearer-token")]
    native_bearer_token: Option<String>,
    /// Hermes endpoint id configured in getaip-server, for example `hermes-1`.
    #[arg(long = "endpoint-id", required = true)]
    endpoint_ids: Vec<String>,
    /// OpenRouter model id passed through Hermes.
    #[arg(long, default_value = "cohere/north-mini-code:free")]
    model: String,
    /// Prompt template. `{endpoint_id}` is replaced per endpoint.
    #[arg(
        long,
        default_value = "Reply exactly with {endpoint_id}_GETAIP_SERVER_PATH_OK and nothing else."
    )]
    prompt: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    let server_url = Url::parse(&args.server_url).map_err(|error| error.to_string())?;
    let native_bearer_token = args
        .native_bearer_token
        .or_else(|| env::var("GETAIP_SERVER_NATIVE_BEARER_TOKEN").ok());
    let client = native_http_client(native_bearer_token.as_deref())?;
    let manifest = get_manifest(&client, &server_url).await?;
    let checker = Principal::new(
        PrincipalId::parse("agent:getaip:server:hermes-production-smoke")
            .map_err(|error| error.to_string())?,
        PrincipalKind::Agent,
    );

    let mut endpoint_reports = Vec::with_capacity(args.endpoint_ids.len());
    for endpoint_id in &args.endpoint_ids {
        endpoint_reports.push(
            run_endpoint_check(
                &client,
                &server_url,
                &manifest,
                checker.clone(),
                endpoint_id,
                &args.model,
                &args.prompt,
            )
            .await?,
        );
    }

    let report = json!({
        "status": "ok",
        "server_url": server_url.as_str(),
        "model": args.model,
        "daemon": {
            "agent": manifest.agent,
            "capability_count": manifest.capabilities.len(),
            "profiles": manifest.profiles
        },
        "endpoints": endpoint_reports
    });
    let rendered = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn native_http_client(bearer_token: Option<&str>) -> Result<reqwest::Client, String> {
    let mut headers = HeaderMap::new();
    if let Some(token) = bearer_token.filter(|token| !token.trim().is_empty()) {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| format!("invalid native bearer token: {error}"))?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|error| error.to_string())
}

async fn run_endpoint_check(
    client: &reqwest::Client,
    server_url: &Url,
    manifest: &Manifest,
    checker: Principal,
    endpoint_id: &str,
    model: &str,
    prompt_template: &str,
) -> Result<EndpointReport, String> {
    let health_capability_id = capability_id(endpoint_id, "health")?;
    let chat_capability_id = capability_id(endpoint_id, "chat")?;
    ensure_manifest_capability(manifest, &health_capability_id)?;
    ensure_manifest_capability(manifest, &chat_capability_id)?;

    let handshake = handshake(
        client,
        server_url,
        checker.clone(),
        vec![health_capability_id.clone(), chat_capability_id.clone()],
    )
    .await?;
    let health = run_action(
        client,
        server_url,
        checker.clone(),
        handshake.session_id.clone(),
        health_capability_id.clone(),
        json!({}),
    )
    .await?;
    let prompt = prompt_template.replace("{endpoint_id}", endpoint_id);
    let chat = run_action(
        client,
        server_url,
        checker,
        handshake.session_id.clone(),
        chat_capability_id.clone(),
        json!({
            "model": model,
            "prompt": prompt
        }),
    )
    .await?;
    let content = chat_content(&chat)?;
    if content.trim()
        != prompt
            .replace("Reply exactly with ", "")
            .replace(" and nothing else.", "")
    {
        return Err(format!(
            "endpoint `{endpoint_id}` returned unexpected chat content `{content}`"
        ));
    }

    Ok(EndpointReport {
        endpoint_id: endpoint_id.to_owned(),
        handshake,
        health: action_report(health_capability_id, health)?,
        chat: ChatReport {
            capability_id: chat_capability_id.to_string(),
            action_id: chat.action_id.to_string(),
            status: format!("{:?}", chat.status),
            content,
            raw_model: chat
                .output
                .as_ref()
                .and_then(|output| output.get("model"))
                .cloned(),
            usage: chat
                .output
                .as_ref()
                .and_then(|output| output.get("usage"))
                .cloned(),
        },
    })
}

async fn get_manifest(client: &reqwest::Client, server_url: &Url) -> Result<Manifest, String> {
    let url = server_url
        .join("/aip/v1/manifest")
        .map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "manifest request failed with HTTP {status}: {body}"
        ));
    }
    serde_json::from_str(&body).map_err(|error| format!("manifest decode failed: {error}: {body}"))
}

async fn handshake(
    client: &reqwest::Client,
    server_url: &Url,
    checker: Principal,
    requested_capabilities: Vec<CapabilityId>,
) -> Result<HandshakeReport, String> {
    let mut envelope = Envelope::new(MessageBody::Handshake(Handshake {
        client: checker.clone(),
        purpose: "deployed getaip-server Hermes Agent production path smoke verification"
            .to_owned(),
        requested_capabilities,
        profiles: vec![
            ProfileId::from("aip.native.http.v1"),
            ProfileId::from(PROFILE_ID),
        ],
        auth: None,
        compliance_required: Vec::new(),
        heartbeat: None,
        encryption: None,
        billing: None,
    }));
    envelope.from = Some(checker);
    let response = post_envelope(client, server_url, envelope).await?;
    match response.body {
        MessageBody::HandshakeResponse(body) if body.status == HandshakeStatus::Accepted => {
            Ok(HandshakeReport {
                status: "accepted".to_owned(),
                session_id: body.session_id,
                agreed_profiles: body
                    .agreed_profiles
                    .into_iter()
                    .map(|profile| profile.to_string())
                    .collect(),
                agreed_capabilities: body
                    .agreed_capabilities
                    .into_iter()
                    .map(|capability| capability.to_string())
                    .collect(),
            })
        }
        MessageBody::HandshakeResponse(body) => {
            Err(format!("handshake was not accepted: {:?}", body.status))
        }
        other => Err(format!(
            "unexpected handshake response: {:?}",
            other.message_type()
        )),
    }
}

async fn run_action(
    client: &reqwest::Client,
    server_url: &Url,
    checker: Principal,
    session_id: Option<SessionId>,
    capability_id: CapabilityId,
    input: Value,
) -> Result<ActionResult, String> {
    let action = Action::new(capability_id.clone(), input);
    let action_id = action.id.to_string();
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
    envelope.from = Some(checker);
    envelope.session_id = session_id;
    let response = post_envelope(client, server_url, envelope).await?;
    let result = match response.body {
        MessageBody::ActionResult(result) => result,
        MessageBody::Error(error) => {
            return Err(format!(
                "action `{action_id}` for `{capability_id}` returned AIP error: {}",
                error.error.message
            ));
        }
        other => {
            return Err(format!(
                "unexpected action response for `{capability_id}`: {:?}",
                other.message_type()
            ));
        }
    };
    if result.status != ActionResultStatus::Completed {
        return Err(format!(
            "action `{action_id}` for `{capability_id}` did not complete: {:?}",
            result.status
        ));
    }
    Ok(result)
}

async fn post_envelope(
    client: &reqwest::Client,
    server_url: &Url,
    envelope: Envelope,
) -> Result<Envelope, String> {
    let url = server_url
        .join("/aip/v1/messages")
        .map_err(|error| error.to_string())?;
    let response = client
        .post(url)
        .json(&envelope)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("AIP message failed with HTTP {status}: {body}"));
    }
    serde_json::from_str(&body)
        .map_err(|error| format!("AIP response decode failed: {error}: {body}"))
}

fn capability_id(endpoint_id: &str, operation: &str) -> Result<CapabilityId, String> {
    CapabilityId::parse(format!("cap:hermes_agent:{endpoint_id}:{operation}"))
        .map_err(|error| error.to_string())
}

fn ensure_manifest_capability(
    manifest: &Manifest,
    capability_id: &CapabilityId,
) -> Result<(), String> {
    if manifest
        .capabilities
        .iter()
        .any(|capability| &capability.id == capability_id)
    {
        Ok(())
    } else {
        Err(format!(
            "daemon manifest does not expose required capability `{capability_id}`"
        ))
    }
}

fn action_report(
    capability_id: CapabilityId,
    result: ActionResult,
) -> Result<ActionReport, String> {
    Ok(ActionReport {
        capability_id: capability_id.to_string(),
        action_id: result.action_id.to_string(),
        status: format!("{:?}", result.status),
        output: result
            .output
            .ok_or_else(|| format!("action `{}` returned no output", result.action_id))?,
    })
}

fn chat_content(result: &ActionResult) -> Result<String, String> {
    let output = result
        .output
        .as_ref()
        .ok_or_else(|| format!("chat action `{}` returned no output", result.action_id))?;
    output
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .filter(|content| !content.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("chat action `{}` returned empty content", result.action_id))
}

#[derive(Debug, Serialize)]
struct EndpointReport {
    endpoint_id: String,
    handshake: HandshakeReport,
    health: ActionReport,
    chat: ChatReport,
}

#[derive(Clone, Debug, Serialize)]
struct HandshakeReport {
    status: String,
    session_id: Option<SessionId>,
    agreed_profiles: Vec<String>,
    agreed_capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ActionReport {
    capability_id: String,
    action_id: String,
    status: String,
    output: Value,
}

#[derive(Debug, Serialize)]
struct ChatReport {
    capability_id: String,
    action_id: String,
    status: String,
    content: String,
    raw_model: Option<Value>,
    usage: Option<Value>,
}
