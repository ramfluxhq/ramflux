// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 peer authority and sender-key interoperability regressions.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn peer_accepts_native_owner_snapshot_and_decrypts_its_group_key() -> TestResult {
    let owner = Fixture::with_device("native-group-owner", "owner-device").await?;
    let peer = Fixture::with_device("native-group-peer", "peer-device").await?;
    owner.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&owner.manifest)?;

    let owner_primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("owner native account")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "native-group",
        "native-thread",
        Some("Native peers".into()),
        &owner.config.target_delivery_id,
        Some(&owner_primary),
    )?;
    let peer_actor = peer.client.owned_group_actor(&peer.config.target_delivery_id)?;
    let state = owner.client.shared_group_change_with_primary(
        "native-group",
        &owner.config.target_delivery_id,
        GroupStateChange::Add {
            member: peer_actor.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&owner_primary),
    )?;
    assert!(group_actor_matches_manifest(&owner.manifest, state.creator()));
    let routes = owner.client.shared_group_member_routes(&state)?;
    let peer_route = routes
        .iter()
        .find(|route| route.member_id == peer.config.device_id)
        .ok_or("native peer route")?;
    assert_eq!(
        peer_route.member_principal_commitment.as_deref(),
        Some(peer.manifest.principal_commitment.as_str())
    );
    assert!(peer_route.device_signing_public_key.is_some());
    assert!(peer_route.target_delivery_id.is_some());
    assert!(peer.client.accept_shared_group_state(&state, &peer.config.target_delivery_id)?);

    let distribution =
        owner.client.export_group_sender_key_distribution("native-group", "owner-device")?;
    peer.client.import_group_sender_key_distribution(&distribution)?;
    let encrypted = owner.client.encrypt_group_message(
        "native-group",
        "owner-device",
        b"native group key works",
    )?;
    peer.client.send_direct_message(
        "native-thread",
        "native-message",
        "owner-device",
        &encrypted,
    )?;
    assert_eq!(
        peer.client.decrypt_group_message("native-thread", "native-message")?,
        b"native group key works"
    );
    Ok(())
}

#[tokio::test]
async fn native_manifest_rejects_foreign_certificate_and_wrong_self_signing_key() -> TestResult {
    let owner = Fixture::with_device("native-source-owner", "owner-device").await?;
    let foreign = Fixture::with_device("native-source-foreign", "foreign-device").await?;
    let actor = owner.client.owned_group_actor(&owner.config.target_delivery_id)?;
    assert!(group_actor_matches_manifest(&owner.manifest, &actor));

    let mut foreign_certificate = actor.clone();
    foreign_certificate.native_authority.as_mut().ok_or("native authority")?.master_certificate =
        foreign
            .manifest
            .custody
            .as_ref()
            .ok_or("foreign custody manifest")?
            .publication
            .record
            .body
            .master_certificate
            .clone();
    assert!(!group_actor_matches_manifest(&owner.manifest, &foreign_certificate));

    let mut wrong_key = actor;
    wrong_key.root_public_key = foreign
        .manifest
        .custody
        .as_ref()
        .ok_or("foreign custody manifest")?
        .publication
        .record
        .body
        .master_certificate
        .body
        .self_signing_public_key
        .clone();
    assert!(!group_actor_matches_manifest(&owner.manifest, &wrong_key));
    Ok(())
}
