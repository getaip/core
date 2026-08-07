#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    if let Ok(signature) = aip_profile_webhook::sign(b"secret", "delivery", timestamp, data) {
        let headers = aip_profile_webhook::WebhookHeaders {
            delivery: "delivery".to_owned(),
            timestamp,
            signature,
            source_system: "fuzz".to_owned(),
            event_type: "event".to_owned(),
        };
        let _ = aip_profile_webhook::verify(b"secret", &headers, data, 300);
    }
});
