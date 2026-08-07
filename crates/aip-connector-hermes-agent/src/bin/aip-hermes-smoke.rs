//! Docker-friendly AIP smoke check for two or more Hermes Agent instances.

#![forbid(unsafe_code)]

use aip_connector::FrozenConnectorHandler;
use aip_connector_hermes_agent::{
    HermesAgentConnector, HermesAgentEndpoint, HermesHealth, PROFILE_ID,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, CapabilityId, CapabilityKind, Envelope, Handshake,
    HandshakeStatus, MessageBody, Principal, PrincipalId, PrincipalKind, ProfileId,
};
use aip_gateway::Gateway;
use aip_runtime::ActionHandler;
use clap::Parser;
use serde_json::{Value, json};
use std::{collections::HashMap, process::ExitCode, sync::Arc, time::Duration};
use tokio::time::{Instant, sleep};

#[derive(Debug, Parser)]
#[command(
    name = "aip-hermes-smoke",
    about = "Validate Hermes Agent endpoints through AIP handshake and action flow."
)]
struct Args {
    #[arg(
        long = "agent",
        value_name = "ID=URL",
        required = true,
        help = "Hermes endpoint, for example hermes-a=http://hermes-a:8642"
    )]
    agents: Vec<String>,
    #[arg(
        long = "api-key",
        value_name = "TOKEN",
        help = "Bearer token shared by all protected Hermes routes"
    )]
    api_key: Option<String>,
    #[arg(
        long = "timeout-seconds",
        default_value_t = 120,
        help = "Maximum time to wait for every Hermes health endpoint"
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
    let endpoints = args
        .agents
        .iter()
        .map(|spec| parse_endpoint(spec, args.api_key.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let connector = HermesAgentConnector::new(endpoints).map_err(|error| error.to_string())?;
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

    let direct_health =
        wait_for_all_health(&connector, Duration::from_secs(args.timeout_seconds)).await?;
    let checker = Principal::new(
        PrincipalId::parse("agent:aip:hermes-smoke").map_err(|error| error.to_string())?,
        PrincipalKind::Agent,
    );
    let requested_capabilities = connector
        .endpoints()
        .values()
        .map(HermesAgentEndpoint::health_capability_id)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;

    let handshake = handshake(&gateway, checker.clone(), requested_capabilities.clone()).await?;
    let aip_results = run_health_actions(&gateway, checker, requested_capabilities).await?;
    let report = json!({
        "status": "ok",
        "handshake": handshake,
        "direct_health": direct_health,
        "aip_results": aip_results
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

async fn wait_for_all_health(
    connector: &HermesAgentConnector,
    timeout: Duration,
) -> Result<Vec<HermesHealth>, String> {
    let mut results = Vec::new();
    for endpoint_id in connector.endpoints().keys() {
        results.push(wait_for_health(connector, endpoint_id, timeout).await?);
    }
    Ok(results)
}

async fn wait_for_health(
    connector: &HermesAgentConnector,
    endpoint_id: &str,
    timeout: Duration,
) -> Result<HermesHealth, String> {
    let deadline = Instant::now() + timeout;
    let mut last_error: String;
    loop {
        match connector.health(endpoint_id).await {
            Ok(health) if health.status == "ok" => return Ok(health),
            Ok(health) => {
                last_error = format!(
                    "endpoint `{}` returned health status `{}`",
                    health.endpoint_id, health.status
                );
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }
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
        purpose: "hermes-agent AIP smoke verification".to_owned(),
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

async fn run_health_actions(
    gateway: &Gateway,
    checker: Principal,
    capability_ids: Vec<CapabilityId>,
) -> Result<Vec<Value>, String> {
    let mut results = Vec::new();
    for capability_id in capability_ids {
        let action = Action::new(capability_id.clone(), json!({}));
        let action_id = action.id.to_string();
        let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
        envelope.from = Some(checker.clone());
        let response = gateway
            .handle_envelope(envelope)
            .await
            .map_err(|error| error.to_string())?;
        let result = match response.body {
            MessageBody::ActionResult(result) => result,
            other => {
                return Err(format!(
                    "unexpected action response: {:?}",
                    other.message_type()
                ));
            }
        };
        if result.status != ActionResultStatus::Completed {
            return Err(format!(
                "AIP action `{action_id}` for `{capability_id}` did not complete: {:?}",
                result.status
            ));
        }
        results.push(action_result_json(capability_id, result));
    }
    Ok(results)
}

fn action_result_json(capability_id: CapabilityId, result: ActionResult) -> Value {
    json!({
        "capability_id": capability_id,
        "action_id": result.action_id,
        "status": result.status,
        "output": result.output
    })
}
