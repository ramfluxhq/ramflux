// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[test]
fn offline_retention_default_and_strict_range() -> TestResult {
    assert_eq!(content_ttl(&AccountConfig::default()), 604_800);
    for value in [3_599, 604_801] {
        assert!(matches!(validate(value), Err(SdkError::InvalidOfflineRetention(v)) if v == value));
        assert!(
            serde_json::from_value::<AccountConfig>(serde_json::json!({
                "offline_retention_secs":value
            }))
            .is_err()
        );
    }
    for value in [3_600, 604_800] {
        validate(value)?;
    }
    Ok(())
}

#[tokio::test]
async fn offline_retention_persists_across_account_reopen() -> TestResult {
    let mut fixture = Fixture::new("ttl-reopen").await?;
    assert_eq!(fixture.client.offline_retention_secs()?, 604_800);
    fixture.client.set_offline_retention_secs(14_400)?;
    assert!(fixture.client.set_offline_retention_secs(3_599).is_err());
    drop(fixture.client.active_account_db.take());
    fixture.client.unlock_account("ttl-reopen", b"native fixture data passphrase")?;
    assert_eq!(fixture.client.offline_retention_secs()?, 14_400);
    Ok(())
}

#[tokio::test]
async fn offline_two_hours_dm_and_group_survive_reconnect() -> TestResult {
    let fixture = Fixture::new("ttl-offline").await?;
    let now = crate::time::now_unix_timestamp();
    let inbox =
        std::sync::Arc::new(std::sync::Mutex::new(ramflux_node_core::OpaqueDeviceInbox::new()));
    let mut engine = crate::GatewaySessionEngine::with_test_transport(
        fixture.config.clone(),
        Box::new(MailboxTransport { inbox: inbox.clone(), now, reply: None }),
    );
    for (id, conversation) in [("dm-message", "dm"), ("group-message", "group")] {
        let message = crate::GatewayDirectMessage {
            conversation_id: conversation.into(),
            message_id: id.into(),
            envelope_id: id.into(),
            source_principal_id: fixture.config.principal_id.clone(),
            sender_id: fixture.config.device_id.clone(),
            recipient_device_id: None,
            recipient_principal_commitment: None,
            target_delivery_id: "offline-recipient".into(),
            encrypted_body: b"retained encrypted content".to_vec(),
            created_at: now,
            ttl: 3_600, // Legacy caller value must not override the account retention.
        };
        fixture.client.submit_direct_message_via_gateway(&mut engine, message).await?;
    }
    // This is the real server mailbox's clock-aware reconnect read, without a sleep.
    let inbox = inbox.lock().map_err(|_| "mailbox poisoned")?;
    let received = inbox.pull_live_after("offline-recipient", 0, 10, now + 2 * 3_600);
    assert_eq!(received.len(), 2, "both content envelopes must survive two offline hours");
    assert_eq!(received[0].envelope.envelope_id, "dm-message");
    assert_eq!(received[1].envelope.envelope_id, "group-message");
    assert!(inbox.pull_live_after("offline-recipient", 0, 10, now + 604_800).is_empty());
    Ok(())
}

#[test]
fn content_ttl_inventory_has_no_short_content_literals() -> TestResult {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in [
        "bus/dispatch/task_transport.rs",
        "bus/dispatch/task_transport/prepared.rs",
        "bus/dispatch/group.rs",
        "bus/own_device_copy/background.rs",
        "bus/couriers/surface.rs",
        "client/object.rs",
        "client/own_device_copy.rs",
        "bus/dispatch/surface_transport.rs",
        "bus/dispatch/surface.rs",
        "client/own_device_sync.rs",
        "client/a2i.rs",
        "client/federation.rs",
        "client/contact_requests/delivery.rs",
        "client/contact_requests/delivery/background.rs",
        "bus/shared_group_sync/requests.rs",
        "bus/shared_group_sync/requests/background.rs",
        "bus/shared_group_sync/outbox/delivery.rs",
        "bus/shared_group_sync/outbox/background.rs",
        "client/surface/own_history.rs",
    ] {
        let text = std::fs::read_to_string(root.join(file))?;
        let production = text.split("#[cfg(test)]").next().ok_or("missing source")?;
        assert!(production.contains("content_ttl()"), "missing configured retention: {file}");
        for literal in ["ttl: 300,", "ttl: 600,", "ttl: 3600,", "ttl: 3_600,"] {
            assert!(!production.contains(literal), "short content TTL in {file}: {literal}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn offline_retention_bus_config_round_trip_and_typed_error() -> TestResult {
    use crate::prelude::*;
    use std::sync::{Arc, atomic::AtomicBool};
    let root = crate::custody::tests::Root::new()?;
    let account = crate::bus::runtime_tests::account(
        &root.0,
        "ttl-bus",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let mut daemon = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.0.join("bus.sock"), root.0.join("data")),
        accounts: BTreeMap::from([("ttl-bus".into(), account)]),
        active_account_id: Some("ttl-bus".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let request = |method: &str, value| {
        LocalBusFrame::request(
            "ttl",
            Some("ttl-bus".into()),
            "ramflux.sdk.v1",
            method,
            serde_json::json!({"offline_retention_secs":value}),
        )
    };
    for value in [3_599, 604_801] {
        let frame = request("account.config.set", value);
        let error =
            crate::bus::dispatch::account::dispatch_account_bus_request(&frame, &mut daemon)
                .await
                .err()
                .ok_or("invalid retention accepted")?;
        assert_eq!(crate::bus::io::local_bus_error_code(&error), "InvalidOfflineRetention");
    }
    let set = request("account.config.set", 7_200);
    crate::bus::dispatch::account::dispatch_account_bus_request(&set, &mut daemon).await?;
    let get = request("account.config.get", 0);
    let result =
        crate::bus::dispatch::account::dispatch_account_bus_request(&get, &mut daemon).await?;
    assert_eq!(result.response_body["offline_retention_secs"], 7_200);
    Ok(())
}

struct MailboxTransport {
    inbox: std::sync::Arc<std::sync::Mutex<ramflux_node_core::OpaqueDeviceInbox>>,
    now: i64,
    reply: Option<crate::prelude::GatewayServerFrame>,
}
impl ramflux_transport::GatewaySessionFrameSink for MailboxTransport {
    fn send_frame<'a>(
        &'a mut self,
        frame: &'a [u8],
    ) -> ramflux_transport::GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            let decoded: crate::prelude::GatewayClientFrame = serde_json::from_slice(frame)
                .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))?;
            let crate::prelude::GatewayClientFrame::Submit { submit } = decoded else {
                return Err(ramflux_transport::TransportError::Quic(
                    "expected content submit".into(),
                ));
            };
            let entry = self
                .inbox
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("mailbox poisoned".into()))?
                .append_at(submit.envelope, self.now);
            self.reply = Some(crate::prelude::GatewayServerFrame::Deliver {
                entry: crate::GatewayInboxEntry {
                    forwarded: false,
                    inbox_seq: entry.inbox_seq,
                    target_delivery_id: entry.target_delivery_id,
                    envelope: entry.envelope,
                },
            });
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for MailboxTransport {
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn recv_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            serde_json::to_vec(
                &self.reply.take().ok_or_else(|| {
                    ramflux_transport::TransportError::Quic("missing reply".into())
                })?,
            )
            .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))
        })
    }
}
