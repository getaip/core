//! AIP chat smoke check for one Hermes Agent endpoint.

#![forbid(unsafe_code)]

use aip_connector::FrozenConnectorHandler;
use aip_connector_hermes_agent::{
    HermesAgentConnector, HermesAgentEndpoint, HermesHealth, PROFILE_ID,
};
use aip_core::{
    Action, ActionResultStatus, CapabilityId, CapabilityKind, Envelope, Handshake, HandshakeStatus,
    MessageBody, Principal, PrincipalId, PrincipalKind, ProfileId,
};
use aip_gateway::Gateway;
use aip_runtime::ActionHandler;
use clap::Parser;
use serde_json::{Value, json};
use std::{collections::HashMap, process::ExitCode, sync::Arc, time::Duration};
use tokio::time::{Instant, sleep};

#[derive(Debug, Parser)]
#[command(
    name = "aip-hermes-chat-smoke",
    about = "Validate Hermes Agent chat through AIP handshake and action flow."
)]
struct Args {
    #[arg(
        long = "agent",
        value_name = "ID=URL",
        required = true,
        help = "Hermes endpoint, for example hermes-1=http://127.0.0.1:18642"
    )]
    agent: String,
    #[arg(
        long = "api-key",
        value_name = "TOKEN",
        required = true,
        help = "Bearer token configured as API_SERVER_KEY on the Hermes endpoint"
    )]
    api_key: String,
    #[arg(
        long = "model",
        value_name = "MODEL",
        required = true,
        help = "OpenRouter model id passed through Hermes"
    )]
    model: String,
    #[arg(
        long = "prompt",
        value_name = "TEXT",
        default_value = "Reply exactly with AIP_HERMES_OPENROUTER_OK and nothing else."
    )]
    prompt: String,
    #[arg(
        long = "timeout-seconds",
        default_value_t = 120,
        help = "Maximum time to wait for Hermes readiness"
    )]
    timeout_seconds: u64,
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
    let endpoint = parse_endpoint(&args.agent, Some(args.api_key))?;
    let endpoint_id = endpoint.id.clone();
    let health_capability_id = endpoint
        .health_capability_id()
        .map_err(|error| error.to_string())?;
    let chat_capability_id = endpoint
        .chat_capability_id()
        .map_err(|error| error.to_string())?;
    let connector = HermesAgentConnector::new(vec![endpoint]).map_err(|error| error.to_string())?;
    let manifest = connector
        .discover_manifest()
        .map_err(|error| error.to_string())?;
    let connector = Arc::new(connector);
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
    let gateway = Gateway::local_development_with_handlers(manifest, handlers)
        .await
        .map_err(|error| error.to_string())?;
    gateway.register_connector((*connector).clone()).await;

    let health = wait_for_health(
        &connector,
        &endpoint_id,
        Duration::from_secs(args.timeout_seconds),
    )
    .await?;
    let checker = Principal::new(
        PrincipalId::parse("agent:aip:hermes-chat-smoke").map_err(|error| error.to_string())?,
        PrincipalKind::Agent,
    );
    let handshake = handshake(
        &gateway,
        checker.clone(),
        vec![health_capability_id, chat_capability_id.clone()],
    )
    .await?;
    let chat = run_chat_action(
        &gateway,
        checker,
        chat_capability_id,
        &args.model,
        &args.prompt,
    )
    .await?;

    let report = json!({
        "status": "ok",
        "endpoint_id": endpoint_id,
        "model": args.model,
        "handshake": handshake,
        "health": health,
        "chat": chat
    });
    let rendered = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn parse_endpoint(spec: &str, api_key: Option<String>) -> Result<HermesAgentEndpoint, String> {
    let (id, url) = spec
        .split_once('=')
        .ok_or_else(|| format!("agent `{spec}` must be formatted as ID=URL"))?;
    HermesAgentEndpoint::new(id, url, api_key).map_err(|error| error.to_string())
}

async fn wait_for_health(
    connector: &HermesAgentConnector,
    endpoint_id: &str,
    timeout: Duration,
) -> Result<HermesHealth, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let last_error = match connector.health(endpoint_id).await {
            Ok(health) if health.status == "ok" => return Ok(health),
            Ok(health) => format!(
                "endpoint `{}` returned health status `{}`",
                health.endpoint_id, health.status
            ),
            Err(error) => error.to_string(),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Hermes endpoint `{endpoint_id}`: {last_error}"
            ));
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn handshake(
    gateway: &Gateway,
    checker: Principal,
    requested_capabilities: Vec<CapabilityId>,
) -> Result<Value, String> {
    let mut envelope = Envelope::new(MessageBody::Handshake(Handshake {
        client: checker.clone(),
        purpose: "hermes-agent AIP chat smoke verification".to_owned(),
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
    let response = gateway
        .handle_envelope(envelope)
        .await
        .map_err(|error| error.to_string())?;
    match response.body {
        MessageBody::HandshakeResponse(body) if body.status == HandshakeStatus::Accepted => {
            Ok(json!({
                "status": "accepted",
                "session_id": body.session_id,
                "agreed_profiles": body.agreed_profiles,
                "agreed_capabilities": body.agreed_capabilities
            }))
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

async fn run_chat_action(
    gateway: &Gateway,
    checker: Principal,
    capability_id: CapabilityId,
    model: &str,
    prompt: &str,
) -> Result<Value, String> {
    let action = Action::new(
        capability_id.clone(),
        json!({
            "model": model,
            "prompt": prompt
        }),
    );
    let action_id = action.id.to_string();
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
    envelope.from = Some(checker);
    let response = gateway
        .handle_envelope(envelope)
        .await
        .map_err(|error| error.to_string())?;
    let result = match response.body {
        MessageBody::ActionResult(result) => result,
        other => {
            return Err(format!(
                "unexpected chat response: {:?}",
                other.message_type()
            ));
        }
    };
    if result.status != ActionResultStatus::Completed {
        return Err(format!(
            "AIP chat action `{action_id}` for `{capability_id}` did not complete: {:?}",
            result.status
        ));
    }
    let output = result
        .output
        .ok_or_else(|| format!("AIP chat action `{action_id}` returned no output"))?;
    if output
        .get("hermes")
        .and_then(|hermes| hermes.get("failed"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(format!(
            "Hermes chat action `{action_id}` failed: {}",
            output
                .get("hermes")
                .and_then(|hermes| hermes.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        ));
    }
    let content = output
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if content.trim().is_empty() {
        return Err(format!(
            "Hermes chat action `{action_id}` completed but returned empty content"
        ));
    }
    Ok(json!({
        "capability_id": capability_id,
        "action_id": action_id,
        "status": result.status,
        "content": content,
        "raw_model": output.get("model"),
        "usage": output.get("usage")
    }))
}
