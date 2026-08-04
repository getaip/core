//! Standalone least-privilege connector lifecycle control-plane entrypoint.

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    if let Err(error) = aip_connector_control_plane::run().await {
        let rendered = serde_json::json!({
            "code": "aip_connector_control_plane.failed",
            "message": error.to_string(),
        });
        eprintln!("{rendered}");
        std::process::exit(1);
    }
}
