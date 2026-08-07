//! Ignored qualification test for an isolated live Cal.diy deployment.

use aip_connector::{Connector, ConnectorContext, OutboundConnector};
use aip_connector_cal_diy::CalDiyConnector;
use aip_core::{Action, CapabilityId};
use serde_json::{Value, json};
use std::env;

#[tokio::test]
#[ignore = "requires an isolated live Cal.diy deployment and a reversible future slot"]
async fn live_cal_diy_reservation_round_trip_uses_the_aip_connector()
-> Result<(), Box<dyn std::error::Error>> {
    let base_url = required_env("AIP_E2E_CAL_DIY_URL")?;
    let api_key = required_env("AIP_E2E_CAL_DIY_API_KEY")?;
    let event_type_id = required_env("AIP_E2E_CAL_DIY_EVENT_TYPE_ID")?.parse::<i64>()?;
    let slot_start = required_env("AIP_E2E_CAL_DIY_SLOT_START")?;
    let connector = CalDiyConnector::new(base_url, "live-qualification", api_key)?;
    let context = ConnectorContext::default();

    let health = connector.health(&context).await?;
    if !health.ready {
        return Err("Cal.diy connector health probe was not ready".into());
    }

    let reservation_key = format!(
        "live-slot-reservation-{}",
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let mut reserve = Action::new(
        CapabilityId::trusted("cap:cal_diy:slot.reservation.create"),
        json!({
            "eventTypeId": event_type_id,
            "slotStart": slot_start,
            "slotDuration": env::var("AIP_E2E_CAL_DIY_SLOT_DURATION_MINUTES")
                .ok()
                .map(|value| value.parse::<u64>())
                .transpose()?
                .unwrap_or(30),
            "reservationDuration": 5
        }),
    );
    reserve.idempotency_key = Some(reservation_key.clone());
    let first = connector.invoke(&context, reserve.clone()).await?;
    let duplicate = connector.invoke(&context, reserve).await?;
    if first.output != duplicate.output {
        return Err("duplicate reservation did not return the stored terminal output".into());
    }
    let reservation_uid = first
        .output
        .as_ref()
        .and_then(|output| output.pointer("/data/reservationUid"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("Cal.diy reservation response omitted data.reservationUid")?
        .to_owned();

    let mut release = Action::new(
        CapabilityId::trusted("cap:cal_diy:slot.reservation.delete"),
        json!({ "reservation_uid": reservation_uid }),
    );
    release.idempotency_key = Some(format!("{reservation_key}-release"));
    connector.invoke(&context, release).await?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("required environment variable `{name}` is missing").into())
}
