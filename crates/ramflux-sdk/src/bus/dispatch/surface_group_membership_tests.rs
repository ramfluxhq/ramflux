// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A sibling's shared root does not make it a member of a peer-authored group.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

#[tokio::test]
async fn group_surface_reaches_a_peer_sibling_only_after_its_device_joins()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-peer-membership");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let mut peer =
        super::dm_tests::peer_fixture_devices(&root, &mut source, &["device-peer-one"]).await?;
    let first_actor = peer.peers[0].client.fixture_group_actor("device-peer-one")?;
    let first = first_actor.identity;
    let first_target = peer.peers[0].client.owned_device_identity()?.storage_key().to_owned();
    let conversation = "group-thread";
    source.client.fixture_group_create("group", conversation, None, "sender")?;
    source.client.fixture_group_change(
        "group",
        "sender",
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: first,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let first_config = peer.config.clone();
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        first_config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    let create = super::dm_tests::create_carrier_in(&source.client, conversation)?;
    assert_eq!(send(&mut source, &create).await?["delivery_state"], "submitted");
    let targets = |envelopes: &[ramflux_protocol::Envelope]| {
        envelopes
            .iter()
            .map(|e| e.target_delivery_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        targets(&captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        std::collections::BTreeSet::from([first_target.clone()]),
        "a peer device that has not joined the certified root is not a group target",
    );
    captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    // The peer root now enrols a second device; the sender learns the new certified roster.
    let joined = Box::pin(crate::client::native_test_support::bus::sibling(
        &mut peer.peers[0],
        "device-peer-two",
        "device-peer-two",
    ))
    .await?;
    let second_target = joined.client.owned_device_identity()?.storage_key().to_owned();
    source.client.persist_observed_identity_directory_now(&super::fixture::manifest(
        &peer.peers[0].client,
    )?)?;
    crate::client::native_test_support::bus::seed_pair(&source.client, &joined.client)?;
    // The directory now serves the enlarged roster; serving the old one would be a rollback.
    let updated_root = root.join("updated-directory");
    std::fs::create_dir_all(&updated_root)?;
    let own = super::fixture::manifest(&source.client)?;
    let peer_manifest = super::fixture::manifest(&peer.peers[0].client)?;
    let (address, updated_directory) = super::fixture::directory(
        &updated_root,
        BTreeMap::from([
            (own.principal_commitment.clone(), serde_json::to_value(own)?),
            (peer_manifest.principal_commitment.clone(), serde_json::to_value(peer_manifest)?),
        ]),
    )
    .await?;
    let mut updated_config = peer.config.clone();
    updated_config.gateway_addr = address;
    updated_config.tcp_gateway_addr = Some(address);
    updated_config.ca_cert = updated_root.join("ca.pem");
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        updated_config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    let append = super::own_tests::append(&source.client, &create, 2)?;
    assert_eq!(send(&mut source, &append).await?["delivery_state"], "submitted");
    assert_eq!(
        targets(&captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        std::collections::BTreeSet::from([first_target, second_target]),
        "text routing delivers the delta to both devices once the second joined the certified root",
    );
    peer.directory.abort();
    updated_directory.abort();
    drop((peer.peers, joined, source));
    Ok(())
}
