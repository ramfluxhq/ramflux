// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_a2i(socket: PathBuf, command: A2iCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        A2iAction::Append(append) => {
            let request = LocalBusA2iAppendRequest {
                event_id: append.event,
                event_type: append.event_type,
                source_device_id: append.source_device,
                target_device_id: append.target_device,
                control_domain: append.control_domain,
                action: append.action,
                subject_base64: ramflux_protocol::encode_base64url(append.subject.as_bytes()),
                created_at: append.created_at.unwrap_or_else(rf_now_unix_timestamp),
                target_delivery_id: append.target_delivery,
            };
            print_json(&bus.request(Some(append.account), "a2i", "a2i.append", &request).await?)
        }
        A2iAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "a2i", "a2i.list_pending", &serde_json::json!({}))
                .await?,
        ),
        A2iAction::Ack(ack) => {
            let request = LocalBusA2iAcknowledgeRequest { event_id: ack.event };
            print_json(&bus.request(Some(ack.account), "a2i", "a2i.acknowledge", &request).await?)
        }
    }
}
