// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-group authority refresh leaves the real account writer available.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::prelude::*;
use prost::Message as _;
use serde_json::json;
use std::sync::Arc;

#[allow(clippy::expect_used)]
fn expect_no_timeout<T>(result: Result<T, tokio::time::error::Elapsed>) -> T {
    result.expect("actor stop hung")
}

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_group_manifest_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-group-directory")).await?;
    let entry = group_entry(&mut fixture)?;
    let root = fixture.peer.client.owned_device_identity()?.root_commitment().to_owned();
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
        .request(command("group.members", json!({"group_id":"receive-group"})))
        .await?;
    assert_eq!(response.body["members"], json!(["device-peer", "device-sender", "device-sibling"]));
    assert_eq!(response.body["member_roster"].as_array().ok_or("roster")?.len(), 2);
    assert_eq!(response.body["name"], "Received group");
    expect_no_timeout(tokio::time::timeout(Duration::from_secs(10), started.actor.stop()).await)?;
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn group_entry(fixture: &mut Fixture) -> Case<GatewayInboxEntry> {
    let member = fixture
        .source
        .client
        .fixture_group_actor("sender")
        .map_err(|error| format!("member actor: {error}"))?
        .identity;
    fixture
        .peer
        .client
        .fixture_group_create(
            "receive-group",
            "receive-group-thread",
            Some("Received group".into()),
            "peer",
        )
        .map_err(|error| format!("group create: {error}"))?;
    let state = fixture
        .peer
        .client
        .fixture_group_change(
            "receive-group",
            "peer",
            ramflux_protocol::GroupStateChange::Add {
                member,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )
        .map_err(|error| format!("group change: {error}"))?;
    let body = fixture
        .peer
        .client
        .shared_group_packet(&state, true)
        .map_err(|error| format!("group packet: {error}"))?;
    let identity = ramflux_protocol::message::Inner::decode(body.as_slice())?
        .identity
        .ok_or("group identity")?;
    let target = fixture.source.client.owned_device_identity()?;
    let config = &fixture.peer.gateway_config;
    let mut message = GatewayDirectMessage {
        conversation_id: identity.conversation_id,
        message_id: ramflux_protocol::encode_base64url(identity.id),
        envelope_id: "incoming-group-state".into(),
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: Some(target.device_id().into()),
        recipient_principal_commitment: Some(target.root_commitment().into()),
        target_delivery_id: fixture.source.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let sealed = fixture.peer.client.seal_generated_routed_prepared(
        config,
        &message,
        &body,
        crate::client::routed::Route::from_inner(&body)?,
        crate::client::routed::SendMaterial { manifest: None, bundle: None },
    )?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(config, &mut message, sealed)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    })
}
