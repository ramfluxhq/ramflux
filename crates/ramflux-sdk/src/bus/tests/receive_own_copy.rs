// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An incoming sibling copy refreshes authority without occupying the local writer.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::client::own_device_copy::OwnMessageInput;
use crate::client::routed::SendMaterial;
use crate::prelude::*;
use prost::Message as _;
use ramflux_protocol::message as g;
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
    *fixture.source.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    let entry = own_copy(&fixture)?;
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
        .request(command(
            "message.read",
            json!({"conversation_id":started.conversation,"read_model":true}),
        ))
        .await?;
    let messages = response.body["messages"].as_array().ok_or("messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["text"], "sibling author stays responsive");
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
    let config = crate::client::native_test_support::bus::config_for(
        sibling,
        &fixture.source.gateway_config,
    )?;
    let conversation = super::fixture::direct_conversation(sibling)?;
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
    let event = sibling.allocate_generated_identity(
        &conversation,
        u64::try_from(now_unix_timestamp())?.saturating_mul(1000),
        false,
    )?;
    let id = ramflux_protocol::encode_base64url(&event.id);
    let exact = RamfluxClient::encode_generated_inner(
        event,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "sibling author stays responsive".into(),
                ..Default::default()
            })),
        },
    )?;
    let body = g::OwnSentMessage {
        envelope_id: "incoming-sibling-envelope".into(),
        message_id: id,
        sender_id: identity.device_id().into(),
        original_recipients: vec![],
        ciphertext_digest: None,
        context: Some(g::OwnContext {
            conversation_id: conversation.clone(),
            participants: vec![
                config.principal_id.clone(),
                fixture.peer.gateway_config.principal_id.clone(),
            ],
            group: None,
            friend: None,
        }),
        authored_at: Some(now_unix_timestamp()),
        exact_inner: exact,
    }
    .encode_to_vec();
    let draft = sibling
        .prepare_own_copy_draft(
            &config,
            OwnMessageInput {
                payload_kind: crate::client::own_device_copy::OwnPayloadKind::Sent,
                id: "incoming-sibling-envelope",
                created_at: now_unix_timestamp(),
                conversation: &conversation,
                group: None,
                body: &body,
            },
            manifest,
        )?
        .ok_or("copy draft")?;
    let requests = sibling.own_copy_material_requests(&config, &draft)?;
    assert_eq!(requests.len(), 1);
    assert!(requests.iter().all(|request| request.root.is_none() && request.prekey.is_none()));
    let envelopes = sibling.seal_own_copy_generated(
        &config,
        draft,
        requests.into_iter().map(|_| SendMaterial { manifest: None, bundle: None }).collect(),
    )?;
    let [(_, envelope)] = envelopes.as_slice() else {
        return Err("test: one sibling envelope required".into());
    };
    let envelope = envelope.clone();
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    })
}
