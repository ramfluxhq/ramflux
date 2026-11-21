// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 peer authority and sender-key interoperability regressions.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test(flavor = "current_thread")]
async fn peer_accepts_native_owner_snapshot_and_decrypts_its_group_key() -> TestResult {
    crate::client::native_test_support::watchdog::within(peer_accepts_native_owner_snapshot_body())
        .await?
}
async fn peer_accepts_native_owner_snapshot_body() -> TestResult {
    let owner = Fixture::with_device("native-group-owner", "owner-device").await?;
    let mut peer = Fixture::with_device("native-group-peer", "peer-device").await?;
    owner.client.persist_observed_identity_directory_now(&peer.manifest)?;
    peer.client.persist_observed_identity_directory_now(&owner.manifest)?;

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

    let snapshot = owner
        .client
        .shared_group_packet_for_recipient(&state, &peer.client.owned_device_identity()?)?;
    let directory = crate::client::native_test_support::directory::Directory::new(vec![
        owner.manifest.clone(),
        peer.manifest.clone(),
    ])
    .await?;
    directory.configure(&mut peer);
    peer.receive(owner.seal_inner_to(&peer, &snapshot)?, 1).await?;
    assert!(directory.requests() > 0, "native snapshot must refresh genuine issuer authority");
    let identity = owner.client.allocate_generated_identity(
        "native-thread",
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let logical = ramflux_protocol::encode_base64url(&identity.id);
    let exact = owner.client.encrypt_generated_group_inner(
        "native-group",
        &owner.config.device_id,
        identity,
        &ramflux_protocol::message::Message {
            text: "native group key works".into(),
            ..Default::default()
        },
    )?;
    let envelope = owner.seal_inner_to(&peer, &exact)?;
    let entry = GatewayInboxEntry {
        envelope,
        forwarded: false,
        inbox_seq: 2,
        target_delivery_id: peer.config.target_delivery_id.clone(),
    };
    assert_incomplete_authority_refuses(
        &peer,
        &owner.manifest.principal_commitment,
        &logical,
        &entry,
    )?;
    peer.receive(entry.envelope, 2).await?;
    assert_native_projection(&peer, &owner, &logical, &exact)
}

fn assert_native_projection(
    peer: &Fixture,
    owner: &Fixture,
    logical: &str,
    exact: &[u8],
) -> TestResult {
    assert_eq!(
        peer.client.account_db()?.message_content(logical)?,
        Some(exact.to_vec()),
        "group receive must retain exact authenticated wire bytes"
    );
    let page = peer.client.generated_message_page("native-thread", None, 10)?;
    let row = page.messages.first().ok_or("native group projection")?;
    let author = row
        .identity
        .as_ref()
        .and_then(|identity| identity.author.as_ref())
        .ok_or("native group author")?;
    assert_eq!(
        author.account_anchor, owner.manifest.principal_commitment,
        "reader must retain the qualified native author"
    );
    assert_eq!(
        author.device_id, owner.config.device_id,
        "reader must retain the actual author device"
    );
    let Some(ramflux_protocol::message::message_update::State::Content(content)) =
        row.state.as_ref()
    else {
        return Err("native group content missing".into());
    };
    assert!(
        matches!(content.value.as_ref(), Some(ramflux_protocol::message::content::Value::Message(value)) if value.text == "native group key works"),
        "reader must project actual group decryption"
    );
    Ok(())
}

fn assert_incomplete_authority_refuses(
    peer: &Fixture,
    anchor: &str,
    logical: &str,
    entry: &GatewayInboxEntry,
) -> TestResult {
    let db = peer.client.account_db()?;
    let cache_key = format!("identity/custody/{anchor}");
    let retained =
        db.load_actor_state::<serde_json::Value>(&cache_key)?.ok_or("retained sender authority")?;
    db.remove_actor_state(&cache_key)?;
    assert!(
        peer.client.open_routed(entry, &peer.config.device_id).is_err(),
        "a roster and sender key must not replace current native sender authority"
    );
    assert!(
        peer.client.account_db()?.message_content(logical)?.is_none(),
        "authority refusal must not project the group message"
    );
    db.persist_actor_state(&cache_key, &retained)?;
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
