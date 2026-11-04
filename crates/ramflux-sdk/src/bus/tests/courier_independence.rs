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
    copy: String,
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
    let copy =
        crate::bus::own_device_copy::copy_id(&fixture.source.client, &format!("{wire}-outgoing"))?;
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
        copy,
    })
}
async fn send(started: &Started, peer: &str, id: &str) -> Case {
    started.actor.request(command("message.submit",json!({
        "conversation_id":"healthy","message_id":id,"envelope_id":id,
        "source_principal_id":"sender","sender_id":"device-sender",
        "recipient_device_id":"device-peer","recipient_principal_commitment":peer,
        "target_delivery_id":"peer","encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"other couriers keep progressing"),
        "created_at":now_unix_timestamp(),"ttl":600,
    }))).await?;
    Ok(())
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
async fn progress(rig: &Rig) -> Case {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let acked = rig.gateway.lock().map_err(|_| "gateway")?.acked.len();
            let copied = rig
                .reader
                .load_actor_state::<Value>(&format!("own-device/status/{}", rig.copy))?
                .is_some_and(|row| row["state"] == "submitted");
            let stored = rig
                .reader
                .direct_message_by_id(&rig.later_message)?
                .is_some_and(|message| !message.deleted);
            if acked == 4 && copied && stored {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
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
    tokio::time::timeout(Duration::from_secs(10), rig.hook.entered.notified()).await?;
    tokio::time::timeout(Duration::from_secs(10), rig.receive_hold.entered.notified()).await?;
    let (key, before) = receipt(&rig.reader, &rig.wire)?.ok_or("prepared receipt")?;
    // Finish the initial range's control preparation before timing new work. Its final ACK
    // stays held so the receive run cannot finish before the new range is injected.
    let initial_control = Arc::new(GatewayHold::default());
    rig.gateway.lock().map_err(|_| "gateway")?.ack_hold = Some(Arc::clone(&initial_control));
    rig.receive_hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), initial_control.entered.notified()).await?;
    assert_eq!(rig.gateway.lock().map_err(|_| "gateway")?.acked.len(), 1);
    // The new inbox range and outbound command arrive only after the receipt is held.
    rig.gateway.lock().map_err(|_| "gateway")?.inbox.extend(std::mem::take(&mut rig.later));
    initial_control.release.notify_one();
    controls(&rig.started.actor).await?;
    send(&rig.started, &rig.peer_root, &format!("{}-outgoing", rig.wire)).await?;
    progress(&rig).await?;
    assert!(!rig.hook.has_applied(), "receipt must remain held while other work completes");
    if erase {
        rig.started.actor.request(command("message.delete",json!({
            "conversation_id":"healthy","message_id":rig.message,"delete_scope":"own_devices",
            "tombstone_id":format!("{}-delete",rig.wire),
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
