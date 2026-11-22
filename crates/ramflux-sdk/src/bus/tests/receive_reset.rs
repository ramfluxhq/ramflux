// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair recovery and its encrypted reply never hold the writer over a gateway wait.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{controls, start};
use crate::client::identity_authority::HeadUse;
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
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.prekey_hold = Some(Arc::clone(&hold));
        gateway.prekey_hold_target =
            Some(fixture.source.client.root_qualified_device_lookup(remote.storage_key())?);
    }
    let gateway = Arc::clone(&fixture.gateway);
    let mut started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await.map_err(|_| {
        format!(
            "reset prekey not held; work={:?}; manifest_requests={:?}",
            reader.load_actor_state::<serde_json::Value>(&key),
            gateway.lock().map_err(|_| "gateway").map(|state| state.manifest_requests.clone())
        )
    })?;
    controls(&started.actor).await?;
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.inbox.len(), 0);
    hold.release.notify_one();
    let envelope =
        submitted(&gateway, started.peer().client.owned_device_identity()?.storage_key())
            .await
            .map_err(|error| {
                format!(
                    "reset submit absent after prekey release: {error}; work={:?}",
                    reader.load_actor_state::<serde_json::Value>(&key)
                )
            })?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = started.peer().client.open_routed(&entry, "device-peer")?;
    assert_reset_kind(&opened.body, false)?;
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
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.prekey_hold = Some(Arc::clone(&hold));
        gateway.prekey_hold_target =
            Some(fixture.source.client.root_qualified_device_lookup(remote.storage_key())?);
    }
    let gateway = Arc::clone(&fixture.gateway);
    let mut started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    controls(&started.actor).await?;
    let peer_target = started.peer().client.owned_device_identity()?.storage_key().to_owned();
    {
        let state = gateway.lock().map_err(|_| "gateway")?;
        // The account sibling can receive its own copy without the peer prekey.
        assert!(
            state.sent.iter().all(|envelope| envelope.target_delivery_id != peer_target),
            "pair reset reached the gateway while its prekey fetch was held"
        );
        assert!(state.acked.is_empty(), "inbound was acked while its prekey fetch was held");
    }
    hold.release.notify_one();
    let envelope =
        submitted(&gateway, started.peer().client.owned_device_identity()?.storage_key()).await?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = started.peer().client.open_routed(&entry, "device-peer")?;
    assert_reset_kind(&opened.body, false)?;
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
    let committed =
        fixture.source.client.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?;
    let reader = fixture.source.client.account_db()?.open_reader()?;
    let hold = Arc::new(GatewayHold::default());
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.inbox.push(entry);
        gateway.submit_hold = Some(Arc::clone(&hold));
        gateway.submit_hold_target =
            Some(fixture.peer.client.owned_device_identity()?.storage_key().into());
    }
    let gateway = Arc::clone(&fixture.gateway);
    let mut started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    assert!(reader.actor_state_exists(&committed)?, "commit precedes reset reply transport");
    controls(&started.actor).await?;
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.acked.len(), 0);
    hold.release.notify_one();
    let envelope =
        submitted(&gateway, started.peer().client.owned_device_identity()?.storage_key()).await?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = started.peer().client.open_routed(&entry, "device-peer")?;
    assert_reset_kind(&opened.body, true)?;
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
        conversation_id: super::fixture::direct_conversation(source)?,
        message_id: "reset-trigger".into(),
        envelope_id: "reset-trigger".into(),
        source_principal_id: "sender".into(),
        sender_id: source.owned_device_identity()?.device_id().into(),
        recipient_device_id: Some(remote.device_id().to_owned()),
        recipient_principal_commitment: Some(remote.root_commitment().to_owned()),
        target_delivery_id: remote.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 300,
    };
    let content = ramflux_protocol::message::Content {
        value: Some(ramflux_protocol::message::content::Value::Message(
            ramflux_protocol::message::Message {
                text: "recovery trigger".into(),
                ..Default::default()
            },
        )),
    };
    let prepared = source.prepare_authored_content(&mut message, None, &content)?;
    let packet = source.seal_generated_routed_prepared(
        &fixture.source.sealing_config()?,
        &message,
        &prepared.wire,
        crate::client::routed::Route::direct(),
        SendMaterial { manifest: None, bundle: None },
    )?;
    message.encrypted_body = serde_json::to_vec(&packet)?;
    let trigger = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: remote.storage_key().into(),
        envelope: crate::dm::gateway_generated_envelope_from_sealed(
            &fixture.source.sealing_config()?,
            &mut message,
            packet,
        )?,
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
            &fixture.peer.sealing_config()?,
            draft,
            SendMaterial { manifest: None, bundle: Some(bundle) },
        )?
        .ok_or("reset envelope")?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    })
}
async fn submitted(
    gateway: &Arc<std::sync::Mutex<super::fixture::Gateway>>,
    target: &str,
) -> Case<ramflux_protocol::Envelope> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(envelope) = gateway
                .lock()
                .map_err(|_| "gateway")?
                .sent
                .iter()
                .find(|envelope| envelope.target_delivery_id == target)
                .cloned()
            {
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

fn assert_reset_kind(exact: &[u8], ack: bool) -> Case {
    use ramflux_protocol::message as g;
    let (_, content) = RamfluxClient::decode_generated_inner(exact)?;
    let Some(g::content::Value::Control(control)) = content.value else {
        return Err("typed reset Control required".into());
    };
    assert!(
        matches!(
            (&control.payload, ack),
            (Some(g::control::Payload::Reset(_)), false)
                | (Some(g::control::Payload::ResetAck(_)), true)
        ),
        "pair recovery must send the correct generated reset kind"
    );
    Ok(())
}
