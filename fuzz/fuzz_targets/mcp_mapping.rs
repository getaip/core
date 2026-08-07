#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let request = aip_profile_mcp::JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(1),
            method: "tools/call".to_owned(),
            params: Some(value),
        };
        let _ = aip_profile_mcp::action_from_tools_call(&request);
    }
});
