//! Cross-process MCP compatibility tests for the migration daemon binary.

#![forbid(unsafe_code)]

use aip_mcp_client::{McpClient, McpClientConfig, McpHttpClientTransport, McpStdioClientTransport};
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::{net::TcpStream, process::Command};

#[tokio::test]
async fn migration_stdio_is_a_real_external_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let binary = env!("CARGO_BIN_EXE_getaip-server-legacy-bundled");
    let transport = McpStdioClientTransport::spawn(binary, &["--mcp-stdio".to_owned()])?
        .with_request_timeout(Duration::from_secs(10));
    let client = McpClient::new(
        McpClientConfig::new("getaip-server-legacy-stdio-e2e"),
        Arc::new(transport),
    );
    aip_mcp_conformance::run_client_conformance(&client)
        .await
        .ensure_success()?;
    Ok(())
}

#[tokio::test]
async fn migration_http_is_a_real_external_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = probe.local_addr()?;
    drop(probe);
    let mut child = Command::new(env!("CARGO_BIN_EXE_getaip-server-legacy-bundled"))
        .args([
            "--bind",
            &address.to_string(),
            "--allow-insecure-development",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    let client = McpClient::new(
        McpClientConfig::new("getaip-server-legacy-http-e2e"),
        Arc::new(McpHttpClientTransport::new(format!(
            "http://{address}/mcp"
        ))?),
    );
    let result = aip_mcp_conformance::run_client_conformance(&client)
        .await
        .ensure_success();
    child.kill().await?;
    result?;
    Ok(())
}
