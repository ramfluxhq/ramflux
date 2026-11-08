// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An incoming sibling copy refreshes authority without occupying the local writer.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::client::own_device_copy::OwnMessageInput;
use crate::client::routed::SendMaterial;
use crate::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_own_copy_manifest_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let fixture = Box::pin(Fixture::new("receive-own-copy-manifest")).await?;
    let entry = own_copy(&fixture)?;
    let root = fixture.source.client.owned_device_identity()?.root_commitment().to_owned();
    assert_eq!(
        fixture.source.client.own_device_receive_manifest_request(&entry)?,
        Some(root.clone())
    );
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
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    controls(&started.actor).await?;
    assert_eq!(gateway.lock().map_err(|_| "gateway")?.acked.len(), 0);
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if gateway.lock().map_err(|_| "gateway")?.acked.len() == 1 {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let response = started
        .actor
        .request(command("message.read", json!({"conversation_id":"healthy"})))
        .await?;
    let messages = response.body["messages"].as_array().ok_or("messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["body_utf8"], "sibling author stays responsive");
    let wall = std::time::Instant::now();
    started.actor.stop().await?;
    assert!(wall.elapsed() < Duration::from_secs(1));
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn own_copy(fixture: &Fixture) -> Case<GatewayInboxEntry> {
    let sibling = &fixture.sibling.client;
    let identity = sibling.owned_device_identity()?;
    let mut config = fixture.source.gateway_config.clone().with_account_identity(sibling)?;
    config.device_id = identity.device_id().to_owned();
    let manifest = serde_json::from_value(
        fixture
            .gateway
            .lock()
            .map_err(|_| "gateway")?
            .manifests
            .get(identity.root_commitment())
            .cloned()
            .ok_or("manifest")?,
    )?;
    let mut body = b"ramflux.own_sent_message.v1\n".to_vec();
    body.extend(serde_json::to_vec(&json!({
        "envelope_id":"incoming-sibling-envelope", "message_id":"incoming-sibling-message",
        "sender_id":"sender", "original_recipients":[], "ciphertext_hash":null,
        "context":{"conversation_id":"healthy","participants":["sender","peer"],"group":null,"friend":null},
        "authored_at":now_unix_timestamp(),
        "body_base64":ramflux_protocol::encode_base64url(b"sibling author stays responsive"),
    }))?);
    let draft = sibling
        .prepare_own_copy_draft(
            &config,
            OwnMessageInput {
                id: "incoming-sibling-envelope",
                created_at: now_unix_timestamp(),
                conversation: "healthy",
                group: None,
                body: &body,
            },
            manifest,
        )?
        .ok_or("copy draft")?;
    let requests = sibling.own_copy_material_requests(&config, &draft)?;
    assert_eq!(requests.len(), 1);
    assert!(requests.iter().all(|request| request.root.is_none() && request.prekey.is_none()));
    let packet = sibling.seal_own_copy_prepared(
        &config,
        draft,
        requests.into_iter().map(|_| SendMaterial { manifest: None, bundle: None }).collect(),
    )?;
    let encrypted_body = packet.bytes()?;
    let message = GatewayDirectMessage {
        conversation_id: packet.id.clone(),
        message_id: packet.id.clone(),
        envelope_id: packet.id,
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: None,
        recipient_principal_commitment: None,
        target_delivery_id: "sender".into(),
        encrypted_body,
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let mut envelope = gateway_direct_message_envelope(&config, &message, None)?;
    envelope.delivery_class = ramflux_protocol::DeliveryClass::SelfDeviceControl;
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sibling.device_branch.as_ref().ok_or("sibling branch")?,
        &envelope,
    )?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "sender".into(),
        envelope,
    })
}
