// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-group authority refresh leaves the real account writer available.

use super::fixture::{Case, Fixture, GatewayHold};
use super::receive_ack::{command, controls, start};
use crate::bus::dispatch::task_transport::{Target, seal};
use crate::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_group_manifest_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let _trace = tracing::subscriber::set_default(ReceiveTrace);
    let mut fixture = Box::pin(Fixture::new("receive-group-directory")).await?;
    let entry = Box::pin(group_entry(&mut fixture)).await?;
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
    match tokio::time::timeout(Duration::from_secs(10), started.actor.stop()).await {
        Ok(result) => result?,
        Err(_) => panic!("actor stop hung"),
    }
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) async fn group_entry(fixture: &mut Fixture) -> Case<GatewayInboxEntry> {
    let member = fixture
        .source
        .client
        .owned_group_actor("sender")
        .map_err(|error| format!("member actor: {error}"))?
        .identity;
    fixture
        .peer
        .client
        .shared_group_create(
            "receive-group",
            "receive-group-thread",
            Some("Received group".into()),
            "peer",
        )
        .map_err(|error| format!("group create: {error}"))?;
    let state = fixture
        .peer
        .client
        .shared_group_change(
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
    let target = Target {
        device: "device-sender".into(),
        identity: fixture.source.client.owned_device_identity()?,
        delivery: "sender".into(),
        federation: None,
        own: false,
    };
    let mut engine = fixture.peer.session_client().await?;
    let delivery = seal(
        &fixture.peer,
        &mut engine,
        &target,
        "receive-group-thread",
        &body,
        crate::client::routed::Route::group_control("receive-group"),
    )
    .await?;
    fixture.peer.install_test_session(engine);
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "sender".into(),
        envelope: delivery.envelope,
    })
}

struct ReceiveTrace;
impl tracing::Subscriber for ReceiveTrace {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("ramflux_sdk") && *metadata.level() <= tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Reason;
        impl tracing::field::Visit for Reason {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if matches!(field.name(), "message" | "reason") {
                    eprintln!("receive group {}={value:?}", field.name());
                }
            }
        }
        event.record(&mut Reason);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_legacy_join_manifest_keeps_local_mutations_available() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            legacy_join_case(),
        ))))
        .await
}
async fn legacy_join_case() -> Case {
    let _trace = tracing::subscriber::set_default(ReceiveTrace);
    let mut fixture = Box::pin(Fixture::new("receive-legacy-group-directory")).await?;
    let (entry, root) = Box::pin(legacy_join_entry(&mut fixture)).await?;
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
        .map_err(|_| "legacy manifest hold was not entered")?;
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
    .map_err(|_| "legacy inbox entry was not acknowledged after manifest release")??;
    let response = started
        .actor
        .request(command("group.members", json!({"group_id":"receive-legacy"})))
        .await?;
    assert_eq!(response.body["group_epoch"], 3);
    assert!(
        response.body["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|id| id == "device-joined"))
    );
    started.actor.stop().await?;
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn legacy_join_entry(fixture: &mut Fixture) -> Case<(GatewayInboxEntry, String)> {
    let joined = crate::bus::runtime_tests::account(
        &fixture.root.join("joined"),
        "joined",
        None,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let manifest =
        crate::client::identity_authority::test_support::public_manifest(&joined.client)?;
    let root = fixture.peer.client.owned_device_identity()?.root_commitment().to_owned();
    for client in [&fixture.source.client, &fixture.peer.client] {
        client.create_group(
            "receive-legacy",
            fixture.peer.client.owned_device_identity()?.storage_key(),
        )?;
        client.add_group_member(
            "receive-legacy",
            fixture.source.client.owned_device_identity()?.storage_key(),
            "member",
        )?;
    }
    fixture.peer.client.persist_identity_directory(&manifest)?;
    fixture.peer.client.add_group_member(
        "receive-legacy",
        joined.client.owned_device_identity()?.storage_key(),
        "member",
    )?;
    let event = fixture.peer.client.create_signed_group_member_join_event(
        "receive-legacy",
        "device-peer",
        "device-joined",
        "member",
        &root,
    )?;
    let joined_root = manifest.principal_commitment.clone();
    fixture
        .gateway
        .lock()
        .map_err(|_| "gateway")?
        .manifests
        .insert(manifest.principal_commitment.clone(), serde_json::to_value(manifest)?);
    let wrapper = crate::group::SdkGroupControlEnvelope {
        schema: "ramflux.sdk.group_control.v1".into(),
        version: 1,
        event,
    };
    let target = Target {
        device: "device-sender".into(),
        identity: fixture.source.client.owned_device_identity()?,
        delivery: "sender".into(),
        federation: None,
        own: false,
    };
    let mut engine = fixture.peer.session_client().await?;
    let delivery = seal(
        &fixture.peer,
        &mut engine,
        &target,
        "receive-legacy-thread",
        &serde_json::to_vec(&wrapper)?,
        crate::client::routed::Route::group_control("receive-legacy"),
    )
    .await?;
    fixture.peer.install_test_session(engine);
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "sender".into(),
            envelope: delivery.envelope,
        },
        joined_root,
    ))
}
