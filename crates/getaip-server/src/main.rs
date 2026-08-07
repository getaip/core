//! Product-neutral `getaip-server` daemon entrypoint.

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    if let Err(error) = getaip_server::cli::run().await {
        match serde_json::to_string(&error) {
            Ok(rendered) => eprintln!("{rendered}"),
            Err(render_error) => {
                eprintln!("{{\"code\":\"aip.server.render_error\",\"message\":\"{render_error}\"}}")
            }
        }
        std::process::exit(1);
    }
}
