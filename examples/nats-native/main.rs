//! Native NATS binding example.

use aip::{
    Envelope, ManifestRequest, MessageBody, MessageType,
    transport::nats::{NatsSubject, nats_headers_for_envelope},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subject = NatsSubject {
        trust_domain: "local.test".to_owned(),
        service: "gateway".to_owned(),
        version: "v1".to_owned(),
        message_type: MessageType::ManifestRequest,
    };
    let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
        profiles: Vec::new(),
        filter: None,
    }));
    let headers = nats_headers_for_envelope(&envelope)?;
    println!("subject={}", subject.subject());
    println!("header_count={}", headers.len());
    Ok(())
}
