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
    let peer = super::dm_tests::peer_fixture(&root, &mut source).await?;
    let mut manifest = super::fixture::manifest(&peer.peers[0].client)?;
    manifest.devices.extend(super::fixture::manifest(&peer.peers[1].client)?.devices);
    for device in &mut manifest.devices {
        device.target_delivery_id.clone_from(&device.device_id);
    }
    crate::client::identity_authority::test_support::sign_manifest(
        peer.peers[0].client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut manifest,
        2,
    )?;
    source.client.persist_identity_directory(&manifest)?;
    source.client.create_group("group", "device-sender")?;
    source.client.add_group_member(
        "group",
        peer.peers[0].client.owned_device_identity()?.storage_key(),
        "member",
    )?;
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        peer.config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    let create = super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["delivery_state"], "submitted");
    let targets = |envelopes: &[ramflux_protocol::Envelope]| {
        envelopes
            .iter()
            .map(|e| e.target_delivery_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        targets(&captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        std::collections::BTreeSet::from(["device-peer-one".into()]),
        "a registered peer sibling is not implicitly a group member",
    );
    captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    source.client.add_group_member(
        "group",
        peer.peers[1].client.owned_device_identity()?.storage_key(),
        "member",
    )?;
    let append = super::own_tests::append(&source.client, &create, 2)?;
    assert_eq!(send(&mut source, &append).await?["delivery_state"], "submitted");
    assert_eq!(
        targets(&captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
        std::collections::BTreeSet::from(["device-peer-one".into(), "device-peer-two".into()]),
        "normal text routing delivers the delta to both explicitly joined peer devices",
    );
    peer.directory.abort();
    drop(peer.peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
