// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Metadata-only projection from durable outbox keys into account event journals.
use crate::prelude::*;
use serde_json::{Value, json};
mod project;
pub(super) use project::project;

pub(super) fn frame(
    request: &LocalBusFrame,
    account: &str,
    event: ramflux_storage::JournalEvent,
) -> LocalBusFrame {
    let mut frame = local_bus_event(request, account, "stream", &event.topic, event.body);
    frame.seq = Some(event.seq);
    frame.at = Some(event.at);
    frame.frame_id = format!("event_{}", event.seq);
    frame
}
pub(super) fn field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}
pub(super) fn metadata(value: &Value, fields: &[&str]) -> Value {
    let mut result = serde_json::Map::new();
    for name in fields {
        if let Some(value) = value.get(name) {
            result.insert((*name).to_owned(), value.clone());
        }
    }
    Value::Object(result)
}
pub(super) fn retention(db: &AccountDb) -> Result<(), SdkError> {
    let count = env_u64("RAMFLUX_EVENT_MAX_COUNT", 10_000)?.clamp(1, 1_000_000);
    let age = env_u64("RAMFLUX_EVENT_MAX_AGE_SECONDS", 604_800)?;
    db.retain_journal(
        now_unix_timestamp(),
        u32::try_from(count)
            .map_err(|_| SdkError::LocalBus("journal count out of range".to_owned()))?,
        age,
    )?;
    Ok(())
}
fn env_u64(key: &str, default: u64) -> Result<u64, SdkError> {
    std::env::var(key).map_or(Ok(default), |value| {
        value.parse().map_err(|_| SdkError::LocalBus(format!("invalid {key}")))
    })
}

pub(super) fn capture_events(
    client: &RamfluxClient,
    events: &[LocalBusFrame],
) -> Result<(), SdkError> {
    for event in events {
        if event.method.starts_with("ramflux.a2ui.") {
            let mut body = metadata(
                &event.body,
                &[
                    "surface_id",
                    "component_id",
                    "permission",
                    "source_device_id",
                    "target_device_id",
                    "accepted",
                    "success",
                    "status",
                    "approval_id",
                    "conversation_id",
                    "context_id",
                ],
            );
            let id = ramflux_crypto::blake3_256_base64url(
                "ramflux.stream.a2ui.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &event.method,
                    &body,
                    event.body.get("nonce"),
                    event.body.get("created_at"),
                ))?,
            );
            body["action_id"] = json!(id);
            client.account_db()?.persist_actor_state(
                &format!("stream/a2ui/{id}"),
                &json!({"topic":event.method,"body":body}),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{capture_events, project};
    use crate::prelude::*;
    #[test]
    fn projected_rows_exclude_message_content_tool_arguments_and_a2ui_payloads()
    -> Result<(), SdkError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let root = std::env::temp_dir()
            .join(format!("ramflux-journal-metadata-{}-{now}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.create_identity_root("a", [3; 32]);
        client.create_device_branch("a", "device", 1, [4; 32]);
        client.open_account_index(&root)?;
        client.create_account("a", "commitment")?;
        client.unlock_account("a", b"secret")?;
        client.send_direct_message(
            "private-conversation",
            "message",
            "a",
            b"FORBIDDEN_MESSAGE_CONTENT",
        )?;
        client.account_db()?.persist_client_record("approval","approval",&serde_json::json!({"id":"approval","approval_id":"approval","event_type":"mcp.approval.request","details":{"arguments":{"text":"FORBIDDEN_TOOL_ARGUMENT"}}}))?;
        client.account_db()?.persist_actor_state(
            "attachment/reference/remote",
            &serde_json::json!({"access_grant":"PRIVATE_GRANT","key_slot":"PRIVATE_SLOT"}),
        )?;
        client.account_db()?.persist_client_record(
            "object",
            "remote",
            &serde_json::json!({
                "owner":"peer","size":42,"access_grant":"PRIVATE_GRANT","key_slot":"PRIVATE_SLOT"
            }),
        )?;
        client.account_db()?.persist_actor_state(
            "attachment/fetch/remote",
            &serde_json::json!({
                "object_id":"remote","transfer_state":"retrying","operation_id":"fetch-op",
                "last_error":null,"attempts":2
            }),
        )?;
        let event = LocalBusFrame {
            kind: LocalBusFrameKind::Event,
            ..LocalBusFrame::request(
                "a2ui",
                Some("a".to_owned()),
                "a2ui",
                "ramflux.a2ui.action_submitted",
                serde_json::json!({"surface_id":"surface","payload":{"text":"FORBIDDEN_A2UI_PAYLOAD"}}),
            )
        };
        capture_events(&client, &[event])?;
        let mut topics = BTreeSet::new();
        for entry in client.account_db()?.pending_outbox(256)? {
            for (topic, body, _) in project(&client, &entry)? {
                if topic == "object.transfer.progress" {
                    assert_eq!(body["id"], "remote");
                    assert_eq!(body["transfer_state"], "retrying");
                }
                topics.insert(topic);
                let encoded = serde_json::to_string(&body)?;
                for forbidden in [
                    "FORBIDDEN_MESSAGE_CONTENT",
                    "FORBIDDEN_TOOL_ARGUMENT",
                    "FORBIDDEN_A2UI_PAYLOAD",
                    "encrypted_body",
                    "arguments",
                    "object_content_key",
                    "PRIVATE_",
                    "access_grant",
                    "key_slot",
                ] {
                    assert!(!encoded.contains(forbidden));
                }
            }
        }
        assert!(topics.contains("message.updated"));
        assert!(topics.contains("object.transfer.progress"));
        assert!(topics.contains("mcp.approval.request"));
        assert!(topics.contains("ramflux.a2ui.action_submitted"));
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod receipt_topics {
    use super::project;
    use crate::prelude::*;
    #[test]
    fn authenticated_message_metadata_preserves_received_topics_with_scoped_receipts()
    -> Result<(), SdkError> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let root = std::env::temp_dir()
            .join(format!("ramflux-received-topic-{}-{suffix}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("a", "a")?;
        client.unlock_account("a", b"secret")?;
        client.send_direct_message("thread", "received", "peer", b"PRIVATE_BODY")?;
        client.account_db()?.persist_actor_state("routed/message-metadata/received",&serde_json::json!({"kind":"direct","conversation_id":"thread","group_id":null,"message_id":"received"}))?;
        let mut events = Vec::new();
        for entry in client.account_db()?.pending_outbox(100)? {
            events.extend(project(&client, &entry)?);
        }
        assert!(events.iter().any(|(topic, _, _)| topic == "message.received"));
        assert!(!serde_json::to_string(&events)?.contains("PRIVATE_BODY"));
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
