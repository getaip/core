#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let registry = aip_schema::SchemaRegistry::new();
        let _ = registry.validate_json(aip_schema::SchemaName::Envelope, &value);
        let _ = registry.validate_json(aip_schema::SchemaName::Manifest, &value);
    }
});
