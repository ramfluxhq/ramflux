// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing display subscription works for staged recipients without ordinary admission.
use crate::bus::{state::LocalBusConnectionState, supervisor::Supervisor};
use crate::custody::pairing::PAIRING_EVENT_TOPIC as TOPIC;
use crate::custody::pairing::{PairingEventSubscription, pairing_event_stream};
use crate::{LocalBusFrame, SdkError};
pub(in crate::bus) fn requested(request: &LocalBusFrame) -> bool {
    request
        .body
        .get("topics")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|topics| topics.iter().any(|topic| topic.as_str() == Some(TOPIC)))
}
fn refused() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
impl Supervisor {
    pub(in crate::bus) async fn subscribe_pairing_stream(
        &self,
        request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<(), SdkError> {
        let topics =
            request.body.get("topics").and_then(serde_json::Value::as_array).ok_or_else(refused)?;
        if topics.len() != 1
            || topics.first().and_then(serde_json::Value::as_str) != Some(TOPIC)
            || !self.config.pairing.as_ref().is_some_and(|config| config.enabled)
        {
            return Err(refused());
        }
        let account = request.account_id.as_deref().ok_or_else(refused)?;
        let stream = pairing_event_stream(&self.config.data_root, account)?;
        let (floor, head) = stream.bounds()?;
        let cursor = match request.body.get("since_seq") {
            None => head.saturating_sub(1).max(floor),
            Some(value) => value.as_u64().ok_or_else(refused)?,
        };
        stream.page(cursor)?;
        connection
            .outbound
            .send(crate::bus::io::local_bus_response(
                &request,
                serde_json::json!({"subscribed":true,"floor_seq":floor,"head_seq":head}),
            ))
            .await
            .map_err(|_| refused())?;
        let outbound = connection.outbound.clone();
        let task = tokio::task::spawn_local(deliver(stream, request, outbound, cursor));
        self.replace_backup_stream(connection.connection_id, task);
        Ok(())
    }
}
async fn deliver(
    stream: PairingEventSubscription,
    request: LocalBusFrame,
    outbound: crate::bus::outbound::LocalBusOutbound,
    mut cursor: u64,
) {
    let signal = stream.signal();
    loop {
        let changed = signal.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let Ok(page) = stream.page(cursor) else {
            crate::bus::subscription::lagged(&outbound, &request, cursor);
            return;
        };
        for (sequence, event) in page {
            if outbound.capacity() <= 1 {
                crate::bus::subscription::lagged(&outbound, &request, cursor);
                return;
            }
            let Ok(body) = serde_json::to_value(event) else { return };
            let mut frame = crate::bus::io::local_bus_event(&request, "", "device", TOPIC, body);
            frame.seq = Some(sequence);
            if outbound.try_send(frame).is_err() {
                return;
            }
            cursor = sequence;
        }
        tokio::select! { () = outbound.closed() => return, () = &mut changed => {} }
    }
}
