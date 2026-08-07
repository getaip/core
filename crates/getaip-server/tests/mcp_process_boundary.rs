//! Cross-process MCP interoperability tests for the production daemon binary.

#![forbid(unsafe_code)]

use aip_mcp_client::{McpClient, McpClientConfig, McpHttpClientTransport, McpStdioClientTransport};
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::{net::TcpStream, process::Command};

#[tokio::test]
async fn getaip_server_stdio_is_a_real_external_mcp_server()
-> Result<(), Box<dyn std::error::Error>> {
    let binary = env!("CARGO_BIN_EXE_getaip-server");
    let transport = McpStdioClientTransport::spawn(binary, &["--mcp-stdio".to_owned()])?
        .with_request_timeout(Duration::from_secs(10));
    let client = McpClient::new(
        McpClientConfig::new("getaip-server-stdio-e2e"),
        Arc::new(transport),
    );

    let report = aip_mcp_conformance::run_client_conformance(&client).await;
    report.ensure_success()?;
    Ok(())
}

#[tokio::test]
async fn getaip_server_streamable_http_is_a_real_external_mcp_server()
-> Result<(), Box<dyn std::error::Error>> {
    const START_ATTEMPTS: usize = 8;

    for _ in 0..START_ATTEMPTS {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = probe.local_addr()?;
        drop(probe);
        let mut child = Command::new(env!("CARGO_BIN_EXE_getaip-server"))
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
        let ready = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if child.try_wait()?.is_some() {
                    return std::io::Result::Ok(false);
                }
                if TcpStream::connect(address).await.is_ok() {
                    return std::io::Result::Ok(true);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        match ready {
            Ok(Ok(true)) if child.try_wait()?.is_none() => {}
            Ok(Ok(_)) => continue,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                let _ = child.kill().await;
                return Err("getaip-server HTTP process did not open its listener".into());
            }
        }
        let transport = McpHttpClientTransport::new(format!("http://{address}/mcp"))?;
        let client = McpClient::new(
            McpClientConfig::new("getaip-server-http-e2e"),
            Arc::new(transport),
        );
        let result = aip_mcp_conformance::run_client_conformance(&client)
            .await
            .ensure_success();
        let exited = child.try_wait()?.is_some();
        if !exited {
            child.kill().await?;
        }
        match (result, exited) {
            (Ok(()), false) => return Ok(()),
            (_, true) => continue,
            (Err(error), false) => return Err(error.into()),
        }
    }

    Err(format!(
        "getaip-server HTTP process exited before owning its listener after {START_ATTEMPTS} attempts"
    )
    .into())
}
