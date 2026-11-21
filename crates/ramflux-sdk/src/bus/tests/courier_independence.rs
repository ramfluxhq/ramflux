// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A receipt's owned network phase can hang or fail while real receive and sibling copy advance.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{Started, command, controls, start};
use crate::bus::delivery_receipts::test_hooks::{Hook, Registration, register};
use crate::prelude::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct Rig {
    started: Started,
    reader: AccountDb,
    gateway: Arc<Mutex<super::fixture::Gateway>>,
    hook: Arc<Hook>,
    _registration: Registration,
    receive_hold: Arc<GatewayHold>,
    later: Vec<GatewayInboxEntry>,
    later_message: String,
    peer_root: String,
    message: String,
    wire: String,
    sibling: String,
}
async fn rig() -> Case<Rig> {
    let mut fixture = Box::pin(Fixture::new("courier-receipt-independence")).await?;
    fixture.inbound().await?;
    let entry = fixture.gateway.lock().map_err(|_| "gateway")?.inbox[0].clone();
    let (route, _) = fixture
        .source
        .client
        .preview_inbound_route(&entry, "device-sender")?
        .ok_or("direct route")?;
    let wire = entry.envelope.envelope_id.clone();
    let (registration, hook) = register(wire.clone());
    fixture.inbound().await?;
    let receive_hold = Arc::new(GatewayHold::default());
    let later = {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.ack_hold = Some(Arc::clone(&receive_hold));
        let mut later = gateway.inbox.split_off(2);
        for entry in &mut later {
            entry.inbox_seq += 2;
        }
        later
    };
    let later_message = fixture
        .source
        .client
        .preview_inbound_route(&later[0], "device-sender")?
        .ok_or("later direct route")?
        .0
        .message_id;
    let sibling = fixture.sibling.client.owned_device_identity()?.device_id().to_owned();
    let peer_root = fixture.peer.client.owned_device_identity()?.root_commitment().to_owned();
    let reader = fixture.source.client.account_db()?.open_reader()?;
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    Ok(Rig {
        started,
        reader,
        gateway,
        hook,
        _registration: registration,
        receive_hold,
        later,
        later_message,
        peer_root,
        message: route.message_id,
        wire,
        sibling,
    })
}
async fn send(started: &Started, peer: &str, id: &str) -> Case<String> {
    let response = started.actor.request(command("message.submit",json!({
        "conversation_id":started.conversation,"message_id":id,"envelope_id":id,
        "source_principal_id":"sender","sender_id":"device-sender",
        "recipient_device_id":"device-peer","recipient_principal_commitment":peer,
        "target_delivery_id":ramflux_protocol::qualified_device_id(peer, "device-peer")?,"encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"other couriers keep progressing"),
        "created_at":now_unix_timestamp(),"ttl":600,
    }))).await?;
    Ok(response.body["message_id"].as_str().ok_or("allocated message identity")?.into())
}
fn receipt(reader: &AccountDb, wire: &str) -> Case<Option<(String, Value)>> {
    for key in reader.actor_state_keys(crate::client::delivery_receipts::PREFIX)? {
        if let Some(row) = reader.load_actor_state::<Value>(&key)?
            && row["wire_message"] == wire
        {
            return Ok(Some((key, row)));
        }
    }
    Ok(None)
}
fn pending_summary(reader: &AccountDb) -> Case<Vec<Value>> {
    reader.actor_state_keys("own-history/pending/")?.into_iter().take(8).map(|key| {
        let row = reader.load_actor_state::<Value>(&key)?.ok_or("pending work")?;
        Ok(json!({"owner":row["owner"],"target":row["target"],"sealed":!row["envelope"].is_null(),"attempts":row["attempts"]}))
    }).collect()
}
async fn progress(rig: &Rig, outgoing: &str) -> Case {
    let snapshot = || -> Case<(usize, bool, bool)> {
        let acked = rig.gateway.lock().map_err(|_| "gateway")?.acked.len();
        let mut copied = false;
        for key in rig.reader.actor_state_keys("own-history/staged/")? {
            let encoded = key.strip_prefix("own-history/staged/").ok_or("staged prefix")?;
            let (_, target, _, owner, _): (
                ramflux_protocol::message::QualifiedDevice,
                ramflux_protocol::message::QualifiedDevice,
                String,
                Vec<u8>,
                Vec<u8>,
            ) = serde_json::from_slice(&ramflux_protocol::decode_base64url(encoded)?)?;
            if target.device_id == rig.sibling
                && ramflux_protocol::encode_base64url(owner) == outgoing
            {
                let staging: String = rig.reader.load_actor_state(&key)?.ok_or("staged binding")?;
                copied =
                    !rig.reader.actor_state_exists(&format!("own-history/pending/{staging}"))?;
            }
        }
        let stored = rig
            .reader
            .direct_message_by_id(&rig.later_message)?
            .is_some_and(|message| !message.deleted);
        Ok((acked, copied, stored))
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (acked, copied, stored) = snapshot()?;
            if acked >= 3 && copied && stored {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| {
        snapshot().map_or_else(
            |error| format!("progress: {error}"),
            |(acked, copied, stored)| {
                format!("progress: acked={acked} copied={copied} stored={stored}; outgoing={outgoing}; staged={:?}; pending={:?}; captures={:?}",
                    rig.reader.actor_state_keys("own-history/staged/"),
                    pending_summary(&rig.reader),
                    rig.reader.actor_state_keys("own-history/capture/"))
            },
        )
    })?
}
#[tokio::test(flavor = "current_thread")]
async fn couriers_are_independent_when_receipt_network_hangs_then_fails() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case(false)))))
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn stale_receipt_apply_drops_a_network_result_after_its_message_is_deleted() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case(true)))))
        .await
}
async fn case(erase: bool) -> Case {
    let mut rig = Box::pin(rig()).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !rig.hook.has_entered() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "receipt network did not enter")?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !rig.receive_hold.seen.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "inbox ACK did not enter hold (seen={} acked={})",
            rig.receive_hold.seen.load(std::sync::atomic::Ordering::SeqCst),
            rig.gateway.lock().map_or(0, |g| g.acked.len())
        )
    })?;
    let (key, before) = receipt(&rig.reader, &rig.wire)?.ok_or("prepared receipt")?;
    // Finish the initial range's control preparation before timing new work. Its final ACK
    // stays held so the receive run cannot finish before the new range is injected.
    let initial_control = Arc::new(GatewayHold::default());
    rig.gateway.lock().map_err(|_| "gateway")?.ack_hold = Some(Arc::clone(&initial_control));
    rig.receive_hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !initial_control.seen.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "initial-range ACK did not enter hold")?;
    assert_eq!(rig.gateway.lock().map_err(|_| "gateway")?.acked.len(), 1);
    // The new inbox range and outbound command arrive only after the receipt is held.
    rig.gateway.lock().map_err(|_| "gateway")?.inbox.extend(std::mem::take(&mut rig.later));
    if let Some(handle) = rig.started.actor.connection_for_test() {
        handle.redrive_receive();
    }
    initial_control.release.notify_one();
    controls(&rig.started.actor).await?;
    let outgoing = send(&rig.started, &rig.peer_root, &format!("{}-outgoing", rig.wire)).await?;
    progress(&rig, &outgoing).await?;
    assert!(!rig.hook.has_applied(), "receipt must remain held while other work completes");
    if erase {
        rig.started.actor.request(command("message.delete",json!({
            "conversation_id":rig.started.conversation,"message_id":rig.message,"delete_scope":"local",
            "operation_id":format!("{}-delete",rig.wire),
        }))).await?;
        assert!(receipt(&rig.reader, &rig.wire)?.is_none());
    }
    rig.hook.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !rig.hook.has_applied() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    if erase {
        assert!(
            rig.reader.load_actor_state::<Value>(&key)?.is_none(),
            "stale receipt result must not recreate its deleted row"
        );
    } else {
        let failed = rig.reader.load_actor_state::<Value>(&key)?.ok_or("retry receipt")?;
        assert_eq!(failed["attempts"].as_u64(), before["attempts"].as_u64().map(|n| n + 1));
        assert!(failed["next_at"].as_i64().is_some_and(|at| at > now_unix_timestamp()));
        controls(&rig.started.actor).await?;
        send(&rig.started, &rig.peer_root, &format!("{}-after-failure", rig.wire)).await?;
    }
    rig.started.actor.stop().await?;
    let root = rig.started.root.clone();
    drop(rig.started.actor);
    rig.started.router.await?;
    drop(rig.reader);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
