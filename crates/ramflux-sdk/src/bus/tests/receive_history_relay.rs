// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-history GETs and relay ACKs run off-writer with durable boundaries between them.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use super::receive_history::{history_bundle, history_entry};
use super::relay_fixture::{Observe, Relay, Step};
use crate::own_device_sync::SdkOwnDeviceSyncEnvelope;
use crate::prelude::*;
use serde_json::json;
use std::{rc::Rc, sync::Arc};

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_history_relay_keeps_the_writer_available_and_acks_only_durable_pages() -> Case
{
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-own-history-relay")).await?;
    let reader = Rc::new(fixture.source.client.account_db()?.open_reader()?);
    let observe: Observe = Rc::new(move |step, index, _| {
        if step == Step::Get && index > 0 {
            let transfer = reader
                .object_transfer("history-object", Some(OBJECT_TRANSFER_DOWNLOAD))?
                .ok_or("GET preceded prior chunk checkpoint")?;
            assert!(
                transfer.completed_chunks.contains(&(index - 1)),
                "GET {index} preceded its durable predecessor"
            );
        }
        if step == Step::Ack {
            assert!(
                reader.load_object::<EncryptedObject>("history-object")?.is_some(),
                "ACK preceded durable verified object"
            );
            assert_eq!(
                reader
                    .object_transfer("history-object", Some(OBJECT_TRANSFER_DOWNLOAD))?
                    .ok_or("verified transfer")?
                    .state,
                "complete"
            );
            assert_eq!(
                reader.actor_state_keys("attachment/ack/")?.len(),
                usize::try_from(index)?,
                "ACK {index} preceded the prior durable ACK confirmation"
            );
        }
        Ok(())
    });
    let relay = Relay::start(observe).await?;
    let (sync, total) = prepare(&mut fixture, &relay)?;
    let hold = Arc::new(GatewayHold::default());
    relay.state.lock().map_err(|_| "relay")?.hold = Some((Step::Get, 0, Arc::clone(&hold)));
    let entry = history_entry(&fixture, sync)?;
    fixture.gateway.lock().map_err(|_| "gateway")?.inbox.push(entry);
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified())
        .await
        .map_err(|_| "history relay GET not entered")?;
    controls(&started.actor).await?;
    assert!(gateway.lock().map_err(|_| "gateway")?.acked.is_empty());
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let errors = relay.state.lock().map_err(|_| "relay")?.errors.clone();
            if !errors.is_empty() {
                return Err(format!("relay errors: {errors:?}").into());
            }
            if gateway.lock().map_err(|_| "gateway")?.acked.len() == 1 {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "history relay import not acknowledged")??;
    {
        let state = relay.state.lock().map_err(|_| "relay")?;
        assert_eq!(state.errors.len(), 0, "{:?}", state.errors);
        for kind in [Step::Get, Step::Ack] {
            assert_eq!(
                state.requests.iter().filter(|(step, _)| *step == kind).count(),
                usize::try_from(total)?
            );
        }
    }
    let response = started
        .actor
        .request(command("message.read", json!({"conversation_id":"history-thread"})))
        .await?;
    let messages = response.body["messages"].as_array().ok_or("history messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["body_utf8"], "history transport stays responsive");
    let wall = std::time::Instant::now();
    started.actor.stop().await?;
    assert!(wall.elapsed() < Duration::from_secs(1));
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    drop(relay);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
pub(super) fn prepare(
    fixture: &mut Fixture,
    relay: &Relay,
) -> Case<(SdkOwnDeviceSyncEnvelope, u32)> {
    let now = now_unix_timestamp();
    let root = fixture.source.client.owned_device_identity()?.root_commitment().to_owned();
    let object = fixture.sibling.client.put_encrypted_object(
        "history-object",
        &serde_json::to_vec(&history_bundle(&root, now))?,
    )?;
    let key =
        zeroize::Zeroizing::new(fixture.sibling.client.object_store.object_key(&object.object_id)?);
    let manifest = relay.seed(&object, &key, 128)?;
    let mut options = parse_relay_transfer_options(Some(relay.endpoint.clone()), None, None)?
        .ok_or("relay options")?;
    options.token_provider =
        RelayTokenProvider::LocalMint { relay_service_key: b"history-relay-key".to_vec() };
    fixture.source.client.node_relay_options = Some(options.clone());
    let slot_conversation = crate::own_device_sync::own_device_sync_slot_conversation_id(
        "history-snapshot",
        &object.object_id,
        "device-sender",
    );
    let mut sender = ramflux_crypto::DmSession::initiator(
        [31; 32],
        dm_device_id_hash("device-sibling"),
        dm_device_id_hash("device-sender"),
        [33; 32],
    )?;
    let receiver = ramflux_crypto::DmSession::recipient(
        [31; 32],
        dm_device_id_hash("device-sender"),
        dm_device_id_hash("device-sibling"),
        [33; 32],
    )?;
    fixture.source.client.persist_dm_session(
        &slot_conversation,
        "initial-history-slot",
        "recv",
        &receiver,
    )?;
    let cipher = sender.encrypt(
        key.as_ref(),
        &object_key_slot_associated_data(&object.object_id, &slot_conversation, "device-sender"),
    )?;
    let mut sync =
        crate::client::own_device_sync::tests::envelope("device-sibling", "device-sender");
    sync.principal_commitment = root;
    sync.snapshot_id = "history-snapshot".into();
    sync.created_at = now;
    sync.expires_at = now + 600;
    sync.history_ref = crate::client::own_device_sync::own_device_history_ref(
        &object,
        &manifest,
        &relay.endpoint,
        &options,
        fixture.sibling.client.device_branch.as_ref().ok_or("sibling branch")?,
        &fixture.source.client.owned_device_identity()?,
        slot_conversation,
        None,
        cipher,
        u64::try_from(now)?,
    )?;
    fixture
        .source
        .client
        .account_db()?
        .persist_actor_state("own-contact/last-refresh", &(now + 600))?;
    Ok((sync, manifest.total_chunks))
}
