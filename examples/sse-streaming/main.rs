//! SSE streaming binding example.

use aip::{
    ActionId, ActionResult, ActionResultStatus, CorrelationId, Envelope, MessageBody,
    transport::{Transport, TransportMessage, sse::SseTransport},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = SseTransport::new();
    let correlation_id = CorrelationId::new();
    let mut envelope = Envelope::new(MessageBody::ActionResult(ActionResult {
        action_id: ActionId::new(),
        status: ActionResultStatus::Completed,
        output: None,
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }));
    envelope.correlation_id = Some(correlation_id.clone());
    transport.publish(TransportMessage::new(envelope)).await?;

    for event in transport.events_since(&correlation_id, None).await? {
        print!("{}", event.render());
    }
    Ok(())
}
