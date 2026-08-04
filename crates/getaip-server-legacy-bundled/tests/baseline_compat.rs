//! Compatibility fixtures captured from the last bundled `getaip-server` baseline.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]

use aip_crypto::canonical_json_bytes;
use aip_mcp_client::{McpClient, McpClientConfig, McpStdioClientTransport};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{process::Command, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command as TokioCommand,
};

#[derive(Debug, Deserialize)]
struct Baseline {
    source_commit: String,
    help_sha256: String,
    default_tools_sha256: String,
    default_tool_names: Vec<String>,
    required_flags: Vec<String>,
}

fn baseline() -> Baseline {
    serde_json::from_str(include_str!("fixtures/baseline.json")).expect("valid baseline fixture")
}

fn normalize_string(value: &mut Value, current: &str, baseline: &str) {
    match value {
        Value::String(text) if text == current => baseline.clone_into(text),
        Value::Array(values) => {
            for value in values {
                normalize_string(value, current, baseline);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                normalize_string(value, current, baseline);
            }
        }
        _ => {}
    }
}

fn normalize_object_key(value: &mut Value, current: &str, baseline: &str) {
    match value {
        Value::Array(values) => {
            for value in values {
                normalize_object_key(value, current, baseline);
            }
        }
        Value::Object(values) => {
            if let Some(value) = values.remove(current) {
                assert!(
                    !values.contains_key(baseline),
                    "baseline key already exists while normalizing `{current}`"
                );
                values.insert(baseline.to_owned(), value);
            }
            for value in values.values_mut() {
                normalize_object_key(value, current, baseline);
            }
        }
        _ => {}
    }
}

#[test]
fn migration_binary_preserves_every_baseline_cli_flag() {
    let baseline = baseline();
    assert_eq!(
        baseline.source_commit,
        "034a520608eea44e6b14e61c34734bd402d989c0"
    );
    assert_eq!(baseline.help_sha256.len(), 64);
    let output = Command::new(env!("CARGO_BIN_EXE_getaip-server-legacy-bundled"))
        .arg("--help")
        .output()
        .expect("migration help process");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for flag in baseline.required_flags {
        assert!(help.contains(&flag), "migration help omitted `{flag}`");
    }
}

#[tokio::test]
async fn migration_binary_preserves_default_tools_list() {
    let baseline = baseline();
    let transport = McpStdioClientTransport::spawn(
        env!("CARGO_BIN_EXE_getaip-server-legacy-bundled"),
        &["--mcp-stdio".to_owned()],
    )
    .expect("spawn migration MCP process")
    .with_request_timeout(Duration::from_secs(10));
    let client = McpClient::new(
        McpClientConfig::new("getaip-server-migration-baseline-tools"),
        Arc::new(transport),
    );
    client.initialize().await.expect("initialize migration MCP");
    let mut tools = client.list_tools().await.expect("migration tools/list");
    let pre_v2_health_name = baseline
        .default_tool_names
        .last()
        .expect("pre-v2 health tool name")
        .clone();
    for tool in &mut tools {
        if tool.name == "getaip_server_health" {
            tool.name.clone_from(&pre_v2_health_name);
        }
    }
    let names = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(names, baseline.default_tool_names);
    let mut value = serde_json::to_value(&tools).expect("serialize migration tools/list");
    let pre_v2_manifest: Value =
        serde_json::from_str(include_str!("fixtures/default-manifest.json"))
            .expect("valid pre-v2 manifest fixture");
    let pre_v2_health_capability = pre_v2_manifest
        .pointer("/capabilities/0/id")
        .and_then(Value::as_str)
        .expect("pre-v2 health capability id");
    normalize_string(
        &mut value,
        "cap:aip:server:health",
        pre_v2_health_capability,
    );
    // The public MCP extension namespace intentionally moved to GetAIP's
    // owned domain. Normalize that single key back to the captured baseline
    // so this compatibility fixture continues to prove that nothing else in
    // the default tools contract changed.
    let pre_getaip_meta_key = ["io", "aip", "dev/aip"].join(".");
    normalize_object_key(
        &mut value,
        aip_profile_mcp::AIP_META_KEY,
        &pre_getaip_meta_key,
    );
    let bytes = canonical_json_bytes(&value).expect("canonical migration tools/list");
    let digest = hex::encode(Sha256::digest(bytes));
    assert_eq!(digest, baseline.default_tools_sha256);
}

#[tokio::test]
async fn migration_binary_preserves_normalized_default_readiness() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness probe");
    let address = probe.local_addr().expect("read readiness probe address");
    drop(probe);
    let mut child = TokioCommand::new(env!("CARGO_BIN_EXE_getaip-server-legacy-bundled"))
        .args([
            "--bind",
            &address.to_string(),
            "--allow-insecure-development",
        ])
        .kill_on_drop(true)
        .spawn()
        .expect("spawn migration readiness process");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("migration readiness listener");

    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect migration readiness endpoint");
    stream
        .write_all(
            format!(
                "GET /ready HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write readiness request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("readiness response timeout")
        .expect("read readiness response");
    child
        .kill()
        .await
        .expect("stop migration readiness process");
    let response = String::from_utf8(response).expect("UTF-8 readiness response");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("HTTP readiness body");
    let mut actual: Value = serde_json::from_str(body).expect("readiness JSON");
    let supervisor = actual
        .pointer_mut("/supervisor")
        .and_then(Value::as_object_mut)
        .expect("readiness supervisor");
    supervisor.remove("last_worker_success_at");
    supervisor.remove("worker_cycles");
    // Module readiness is an additive migration diagnostic. Removing it here
    // proves that every pre-split readiness field remains byte-for-byte
    // equivalent after dynamic values are normalized.
    actual
        .as_object_mut()
        .expect("readiness object")
        .remove("modules");
    let expected: Value = serde_json::from_str(include_str!("fixtures/default-ready.json"))
        .expect("valid readiness fixture");
    assert_eq!(actual, expected);
}

#[test]
fn migration_binary_preserves_the_default_manifest() {
    let expected: Value = serde_json::from_str(include_str!("fixtures/default-manifest.json"))
        .expect("valid manifest fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_getaip-server-legacy-bundled"))
        .arg("--print-manifest")
        .output()
        .expect("migration manifest process");
    assert!(output.status.success());
    let mut actual: Value = serde_json::from_slice(&output.stdout).expect("manifest JSON");
    for pointer in [
        "/agent/id",
        "/capabilities/0/id",
        "/capabilities/0/bindings/1/name",
    ] {
        let pre_v2_value = expected
            .pointer(pointer)
            .expect("pre-v2 implementation name")
            .clone();
        *actual
            .pointer_mut(pointer)
            .expect("renamed implementation field") = pre_v2_value;
    }
    assert_eq!(actual, expected);
}
