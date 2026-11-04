// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair recovery and its encrypted reply never hold the writer over a gateway wait.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{controls, start};
use crate::client::routed::SendMaterial;
use crate::prelude::*;
use std::sync::Arc;

#[tokio::test(flavor = "current_thread")]
async fn background_pair_reset_retries_without_inbound_traffic() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(retry()))))
        .await
}
async fn retry() -> Case {
    let fixture = Box::pin(Fixture::new("receive-reset-independent")).await?;
    let local = fixture.source.client.owned_device_identity()?;
    let remote = fixture.peer.client.owned_device_identity()?;
    assert!(fixture.source.client.begin_pair_recovery(
        &local,
        &remote,
        now_unix_timestamp() - 61
    )?);
    let reader = fixture.source.client.account_db()?.open_reader()?;
    let key = format!("dm-pair/reset-work/{}", RamfluxClient::pair_key(&local, &remote)?);
    let hold = Arc::new(GatewayHold::default());
    fixture.gateway.lock().map_err(|_| "gateway")?.prekey_hold = Some(Arc::clone(&hold));
    let gateway = Arc::clone(&fixture.gateway);
    let mut started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    controls(&started.actor).await?;
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.inbox.len(), 0);
    hold.release.notify_one();
    let envelope = submitted(&gateway).await?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = started.peer().client.open_routed(&entry, "device-peer")?;
    let body: serde_json::Value = serde_json::from_slice(&opened.body)?;
    assert_eq!(body["type"], "pair.session.reset.v1");
    let work: serde_json::Value = reader.load_actor_state(&key)?.ok_or("reset work")?;
    assert_eq!(work["attempts"], 2);
    assert!(work["next_at"].as_i64().is_some_and(|next| next > now_unix_timestamp()));
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.acked.len(), 0);
    finish(Box::new(started)).await
}

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_reset_prekey_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(recovery()))))
        .await
}
async fn recovery() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-reset-prekey")).await?;
    fixture.inbound().await?;
    let local = fixture.source.client.owned_device_identity()?;
    let remote = fixture.peer.client.owned_device_identity()?;
    let (session, _) = fixture.source.client.active_pair(&local, &remote)?.ok_or("pair")?;
    fixture
        .source
        .client
        .account_db()?
        .remove_actor_state(&format!("dm-pair/session/{}", session.session_id))?;
    let hold = Arc::new(GatewayHold::default());
    fixture.gateway.lock().map_err(|_| "gateway")?.prekey_hold = Some(Arc::clone(&hold));
    let gateway = Arc::clone(&fixture.gateway);
    let mut started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    controls(&started.actor).await?;
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.sent.len(), 0);
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.acked.len(), 0);
    hold.release.notify_one();
    let envelope = submitted(&gateway).await?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = started.peer().client.open_routed(&entry, "device-peer")?;
    let body: serde_json::Value = serde_json::from_slice(&opened.body)?;
    assert_eq!(body["type"], "pair.session.reset.v1");
    finish(Box::new(started)).await
}

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_reset_reply_follows_commit_and_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(reply()))))
        .await
}
async fn reply() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-reset-reply")).await?;
    let entry = incoming_reset(&mut fixture)?;
    let committed = fixture.source.client.authenticated_committed_key(&entry)?;
    let reader = fixture.source.client.account_db()?.open_reader()?;
    let hold = Arc::new(GatewayHold::default());
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.inbox.push(entry);
        gateway.submit_hold = Some(Arc::clone(&hold));
    }
    let gateway = Arc::clone(&fixture.gateway);
    let mut started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    assert!(reader.actor_state_exists(&committed)?, "commit precedes reset reply transport");
    controls(&started.actor).await?;
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.acked.len(), 0);
    hold.release.notify_one();
    let envelope = submitted(&gateway).await?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = started.peer().client.open_routed(&entry, "device-peer")?;
    let body: serde_json::Value = serde_json::from_slice(&opened.body)?;
    assert_eq!(body["type"], "pair.session.reset.ack.v1");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if gateway.lock().map_err(|_| "gateway")?.acked.len() == 1 {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    finish(Box::new(started)).await
}
fn incoming_reset(fixture: &mut Fixture) -> Case<GatewayInboxEntry> {
    let source = &fixture.source.client;
    let remote = fixture.peer.client.owned_device_identity()?;
    let mut message = GatewayDirectMessage {
        conversation_id: "healthy".into(),
        message_id: "reset-trigger".into(),
        envelope_id: "reset-trigger".into(),
        source_principal_id: "sender".into(),
        sender_id: "sender".into(),
        recipient_device_id: Some(remote.device_id().to_owned()),
        recipient_principal_commitment: Some(remote.root_commitment().to_owned()),
        target_delivery_id: "peer".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 300,
    };
    let packet = source.seal_routed_prepared(
        &fixture.source.gateway_config,
        &message,
        b"recovery trigger",
        crate::client::routed::Route::direct(),
        SendMaterial { manifest: None, bundle: None },
    )?;
    message.encrypted_body = serde_json::to_vec(&packet)?;
    let trigger = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "peer".into(),
        envelope: gateway_direct_message_envelope(&fixture.source.gateway_config, &message, None)?,
    };
    let peer = &fixture.peer.client;
    let config = &fixture.peer.gateway_config;
    let draft = peer.prepare_pair_recovery_draft(config, &trigger)?.ok_or("reset draft")?;
    let request = peer.pair_control_material_request(config, &draft)?;
    assert!(request.root.is_none());
    assert!(request.prekey.is_some());
    let identity = fixture.source.client.owned_device_identity()?;
    let bundle = fixture.source.client.load_x3dh_private_state(&identity)?.bundle;
    let envelope = peer
        .seal_pair_control_prepared(
            config,
            draft,
            SendMaterial { manifest: None, bundle: Some(bundle) },
        )?
        .ok_or("reset envelope")?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "sender".into(),
        envelope,
    })
}
async fn submitted(
    gateway: &Arc<std::sync::Mutex<super::fixture::Gateway>>,
) -> Case<ramflux_protocol::Envelope> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(envelope) = gateway.lock().map_err(|_| "gateway")?.sent.first().cloned() {
                return Ok(envelope);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?
}
async fn finish(started: Box<super::receive_ack::Started>) -> Case {
    let wall = std::time::Instant::now();
    started.actor.stop().await?;
    assert!(wall.elapsed() < Duration::from_secs(1));
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
