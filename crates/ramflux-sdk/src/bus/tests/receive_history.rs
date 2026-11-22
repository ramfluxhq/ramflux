// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A generated history page refreshes sibling authority without occupying the writer.
use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::client::native_test_support::bus;
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
    let (entry, logical) = cached_history(&mut fixture).await?;
    *fixture.source.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    let root = fixture.source.client.owned_device_identity()?.root_commitment().to_owned();
    assert_eq!(fixture.source.client.inbound_device_manifest_request(&entry)?, Some(root.clone()));
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
    .map_err(|_| "generated history entry not acknowledged")??;
    let response = started
        .actor
        .request(command(
            "message.read",
            json!({"conversation_id":started.conversation,"read_model":true}),
        ))
        .await?;
    let messages = response.body["messages"].as_array().ok_or("history messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["id"], logical);
    assert_eq!(messages[0]["text"], "history transport stays responsive");
    started.actor.stop().await?;
    started.router.await?;
    Ok(())
}

async fn cached_history(fixture: &mut Fixture) -> Case<(GatewayInboxEntry, String)> {
    let peer = &fixture.peer.client;
    let sibling = &fixture.sibling.client;
    bus::seed_pair(peer, sibling)?;
    let peer_config = bus::config_for(peer, &fixture.source.gateway_config)?;
    let sibling_config = bus::config_for(sibling, &fixture.source.gateway_config)?;
    let scope = super::fixture::direct_conversation(peer)?;
    let target = sibling.owned_device_identity()?;
    let mut message = GatewayDirectMessage {
        conversation_id: scope,
        message_id: "history-original".into(),
        envelope_id: "history-original".into(),
        source_principal_id: peer_config.principal_id.clone(),
        sender_id: peer_config.device_id.clone(),
        recipient_device_id: Some(target.device_id().into()),
        recipient_principal_commitment: Some(target.root_commitment().into()),
        target_delivery_id: target.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let content = ramflux_protocol::message::Content {
        value: Some(ramflux_protocol::message::content::Value::Message(
            ramflux_protocol::message::Message {
                text: "history transport stays responsive".into(),
                ..Default::default()
            },
        )),
    };
    let prepared = peer.prepare_authored_content(&mut message, None, &content)?;
    let logical = message.message_id.clone();
    let sealed = peer.seal_generated_routed_prepared(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&peer_config)?,
        &message,
        &prepared.wire,
        Route::from_inner(&prepared.wire)?,
        SendMaterial { manifest: None, bundle: None },
    )?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&peer_config)?,
        &mut message,
        sealed,
    )?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    bus::receive_copy(&mut fixture.sibling.client, &sibling_config, &entry).await?;
    let sibling = &fixture.sibling.client;
    let built = sibling
        .build_generated_history_page(&[64; 32], 0, &[0; 32], None)?
        .ok_or("history page with real first-hand evidence")?;
    let (identity, exact) = sibling.encode_generated_history_page(&built)?;
    let target = fixture.source.client.owned_device_identity()?;
    let mut message = GatewayDirectMessage {
        conversation_id: identity.conversation_id,
        message_id: ramflux_protocol::encode_base64url(identity.id),
        envelope_id: "incoming-history".into(),
        source_principal_id: sibling_config.principal_id.clone(),
        sender_id: sibling_config.device_id.clone(),
        recipient_device_id: Some(target.device_id().into()),
        recipient_principal_commitment: Some(target.root_commitment().into()),
        target_delivery_id: target.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let sealed = sibling.seal_generated_routed_prepared(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&sibling_config)?,
        &message,
        &exact,
        Route::from_inner(&exact)?,
        SendMaterial { manifest: None, bundle: None },
    )?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&sibling_config)?,
        &mut message,
        sealed,
    )?;
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        },
        logical,
    ))
}
