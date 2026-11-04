// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A routed history page refreshes sibling authority without occupying the account writer.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::client::routed::{Route, SendMaterial};
use crate::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_history_manifest_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-own-history-manifest")).await?;
    let entry = cached_history(&mut fixture)?;
    let root = fixture.source.client.owned_device_identity()?.root_commitment().to_owned();
    fixture
        .source
        .client
        .account_db()?
        .persist_actor_state("own-contact/last-refresh", &(now_unix_timestamp() + 600))?;
    let hold = Arc::new(GatewayHold::default());
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.inbox.push(entry);
        gateway.manifest_hold = Some((root, Arc::clone(&hold)));
    }
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified())
        .await
        .map_err(|_| "history manifest not held")?;
    controls(&started.actor).await?;
    assert!(gateway.lock().map_err(|_| "gateway")?.acked.is_empty());
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if gateway.lock().map_err(|_| "gateway")?.acked.len() == 1 {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "history entry not acknowledged")??;
    let response = started
        .actor
        .request(command("message.read", json!({"conversation_id":"history-thread"})))
        .await?;
    let messages = response.body["messages"].as_array().ok_or("history messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["message_id"], "history-message");
    assert_eq!(messages[0]["body_utf8"], "history transport stays responsive");
    let wall = std::time::Instant::now();
    started.actor.stop().await?;
    assert!(wall.elapsed() < Duration::from_secs(1));
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn cached_history(fixture: &mut Fixture) -> Case<GatewayInboxEntry> {
    let root = fixture.source.client.owned_device_identity()?.root_commitment().to_owned();
    let now = now_unix_timestamp();
    let bundle = history_bundle(&root, now);
    let object = fixture
        .source
        .client
        .put_encrypted_object("history-object", &serde_json::to_vec(&bundle)?)?;
    let mut sync =
        crate::client::own_device_sync::tests::envelope("device-sibling", "device-sender");
    sync.principal_commitment = root;
    sync.snapshot_id = "history-snapshot".into();
    sync.created_at = now;
    sync.expires_at = now + 600;
    sync.history_ref.object_id.clone_from(&object.object_id);
    sync.history_ref.manifest_hash.clone_from(&object.manifest_hash);
    sync.history_ref.plaintext_hash.clone_from(&object.plaintext_hash);
    sync.history_ref.key_slot.object_id.clone_from(&object.object_id);
    sync.history_ref.key_slot.conversation_id =
        crate::own_device_sync::own_device_sync_slot_conversation_id(
            &sync.snapshot_id,
            &object.object_id,
            "device-sender",
        );
    history_entry(fixture, sync)
}

pub(super) fn history_bundle(root: &str, now: i64) -> serde_json::Value {
    let body: &[u8] = b"history transport stays responsive";
    json!({
        "schema":"ramflux.sdk.own_device_history_bundle.v1","version":1,
        "principal_commitment":root,"source_device_id":"device-sibling","target_device_id":"device-sender","snapshot_id":"history-snapshot",
        "messages":[{"conversation_id":"history-thread","message_id":"history-message","sender_id":"sender","encrypted_body":[17,18],"metadata":MessageMetadata::default(),"deleted":false,"is_own":false,"created_at":now}],
        "contents":{"history-message":body},"dm_sessions":[],"groups":[],"sender_key_distributions_base64":[],
    })
}

pub(super) fn history_entry(
    fixture: &Fixture,
    mut sync: crate::own_device_sync::SdkOwnDeviceSyncEnvelope,
) -> Case<GatewayInboxEntry> {
    let now = sync.created_at;
    let sibling = &fixture.sibling.client;
    sync.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sibling.device_branch.as_ref().ok_or("sibling branch")?,
        &crate::own_device_sync::own_device_sync_signing_body(&sync),
    )?;
    let config = fixture.source.gateway_config.clone().with_account_identity(sibling)?;
    let mut message = GatewayDirectMessage {
        conversation_id: "history-control".into(),
        message_id: "incoming-history".into(),
        envelope_id: "incoming-history".into(),
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: Some("device-sender".into()),
        recipient_principal_commitment: Some(sync.principal_commitment.clone()),
        target_delivery_id: "sender".into(),
        encrypted_body: Vec::new(),
        created_at: now,
        ttl: 600,
    };
    let packet = sibling.seal_routed_prepared(
        &config,
        &message,
        &serde_json::to_vec(&sync)?,
        Route::control(),
        SendMaterial { manifest: None, bundle: None },
    )?;
    message.encrypted_body = serde_json::to_vec(&packet)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "sender".into(),
        envelope: gateway_direct_message_envelope(&config, &message, None)?,
    })
}
