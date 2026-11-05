// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-state sender-key controls must use the conversation authenticated by their snapshot.
use super::*;
use crate::bus::runtime_tests;
use crate::client::identity_authority::HeadUse;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn sender_key_snapshot_uses_signed_group_conversation_instead_of_legacy_control_thread()
-> TestResult {
    let root = runtime_tests::root("group-distribution-route");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { mut peers, config, directory, .. } =
        super::dm_tests::peer_fixture_devices(&root, &mut source, &["device-peer"]).await?;
    source.gateway_config = config.clone();
    source.target_delivery_id = config.target_delivery_id.clone();
    source.client.shared_group_create(
        "group",
        "signed-thread",
        None,
        &config.target_delivery_id,
    )?;
    let peer = peers.first_mut().ok_or("peer fixture")?;
    let member = peer.client.owned_group_actor("device-peer")?.identity;
    let state = source.client.shared_group_change(
        "group",
        &config.target_delivery_id,
        ramflux_protocol::group_state::GroupStateChange::Add {
            member,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let source_root = source.client.owned_device_identity()?.root_commitment().to_owned();
    peer.client.establish_friend_link("consent", "peer", &source_root)?;
    peer.client.accept_shared_group_state(&state, "device-peer")?;
    let route = source
        .client
        .shared_group_member_routes(&state)?
        .into_iter()
        .find(|route| route.member_id == "device-peer")
        .ok_or("peer route")?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(crate::bus::dispatch::surface_transport::fixture::RecordingGateway::new(
            captured.clone(),
        )),
    ));
    super::super::group::dispatch_group_sender_key_distribution(&mut source, "group", route, None)
        .await?;
    let envelope =
        captured.lock().map_err(|_| "capture lock")?.first().cloned().ok_or("distribution")?;
    let entry = GatewayInboxEntry {
        inbox_seq: 42,
        target_delivery_id: envelope.target_delivery_id.clone(),
        forwarded: false,
        envelope,
    };
    let mut receiver_config = config;
    receiver_config.principal_id = "peer".into();
    receiver_config.device_id = "device-peer".into();
    receiver_config.target_delivery_id = "device-peer".into();
    let opened = peer.client.open_routed(&entry, "device-peer")?;
    assert_eq!(
        opened.routing.conversation_id,
        state.view().conversation_id,
        "sender-key snapshot route must match its signed conversation"
    );
    let mut receiver = GatewaySessionEngine::with_test_transport(
        receiver_config.with_account_identity(&peer.client)?,
        Box::new(crate::bus::dispatch::surface_transport::fixture::RecordingGateway::new(
            Arc::default(),
        )),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    peer.client.apply_routed_entry(&mut receiver, &pool, &entry, false).await?;
    assert!(peer.client.committed_routing(HeadUse::NewAuthorization, &entry)?.is_some());
    directory.abort();
    drop((source, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
