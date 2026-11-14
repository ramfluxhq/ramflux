// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-contact Root hints are lookup context, never an alternative trust anchor.
use super::*;
use crate::client::identity_authority::HeadUse;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn first_contact_fetches_only_the_hinted_root_manifest_and_verifies_the_chain() -> TestResult
{
    first_use_discovery(false, false).await
}
#[tokio::test]
async fn group_pin_omitted_from_bounded_history_fetches_root_and_restores_pin_on_first_use()
-> TestResult {
    first_use_discovery(true, false).await
}
#[tokio::test]
async fn a_bad_deferred_pin_does_not_reject_an_authenticated_first_message() -> TestResult {
    first_use_discovery(true, true).await
}
async fn first_use_discovery(lazy_group: bool, mismatched_pin: bool) -> TestResult {
    use crate::client::native_test_support::{Fixture as Native, directory::Directory, watchdog};
    watchdog::within(async {
        let sender = Native::with_principal("discovery-source", "alice", "alice").await?;
        let mut receiver = Native::with_principal("discovery-target", "bob", "bob").await?;
        sender.accept_peer(&receiver)?;
        let (entry, exact) = native_discovery_message(&sender, &receiver)?;
        let mut malformed = entry.clone();
        malformed
            .envelope
            .ext
            .ext
            .insert("source_root_commitment".into(), serde_json::json!("../../admin"));
        assert!(
            matches!(receiver.client.ensure_inbound_device(&receiver.config, &malformed).await,
            Err(SdkError::InboundRejected(reason)) if reason.ends_with("invalid sender root hint"))
        );
        assert!(receiver.client.ensure_inbound_device(&receiver.config, &entry).await.is_err());
        assert!(
            receiver
                .client
                .device_identity_for_root(&sender.client.own_account_anchor()?, "alice")
                .is_err()
        );
        if lazy_group {
            prepare_native_group_hint(&sender, &receiver, mismatched_pin)?;
        } else {
            receiver.client.establish_friend_link(
                "accepted-root",
                &receiver.client.own_account_anchor()?,
                &sender.client.own_account_anchor()?,
            )?;
        }
        let directory = Directory::new(vec![sender.manifest.clone()]).await?;
        directory.configure(&mut receiver);
        receiver.client.ensure_inbound_device(&receiver.config, &entry).await?;
        assert_eq!(directory.requests(), 1, "first use must fetch exactly the hinted native root");
        assert_eq!(
            receiver.client.authenticated_device_identity(HeadUse::NewAuthorization, &entry)?,
            sender.client.owned_device_identity()?
        );
        if lazy_group {
            receiver.client.require_group_sender_pin(
                "group",
                "alice",
                &sender.client.owned_device_identity()?,
            )?;
            assert_eq!(
                receiver
                    .client
                    .account_db()?
                    .group_member_device_key("group", &sender.client.owned_device_identity()?)?,
                Some(
                    sender
                        .manifest
                        .devices
                        .first()
                        .ok_or("sender device")?
                        .branch_public_key
                        .clone()
                )
            );
            assert_eq!(
                receiver.client.account_db()?.actor_state_usage("own-group/pending-pins/")?.0,
                0
            );
        }
        let opened = receiver.client.open_routed(&entry, "bob")?;
        assert_eq!(
            opened.body.as_slice(),
            exact,
            "native proof lookup lost the original generated Inner"
        );
        Ok(())
    })
    .await?
}

fn prepare_native_group_hint(
    sender: &crate::client::native_test_support::Fixture,
    receiver: &crate::client::native_test_support::Fixture,
    mismatched: bool,
) -> TestResult {
    let primary = sender
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native owner")?
        .group_primary(sender.vault.as_ref())?;
    sender.client.shared_group_create_with_primary(
        "group",
        "discovery-group-thread",
        None,
        &sender.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = sender.client.shared_group_change_with_primary(
        "group",
        &sender.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: receiver
                .client
                .owned_group_actor(&receiver.config.target_delivery_id)?
                .identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    receiver.client.accept_shared_group_state(&state, &receiver.config.target_delivery_id)?;
    // A bounded backup hint is not public authority, including when its copied key is wrong.
    let pin = crate::own_device_sync::SdkOwnDeviceGroupMemberPin {
        group_id: "group".into(),
        device_id: "alice".into(),
        signing_public_key: if mismatched {
            ramflux_protocol::encode_base64url([7; 32])
        } else {
            sender.manifest.devices.first().ok_or("sender device")?.branch_public_key.clone()
        },
        principal_id: Some("alice".into()),
        principal_commitment: Some(sender.client.own_account_anchor()?),
    };
    assert!(
        receiver.client.restore_own_member_pin(&pin).is_err(),
        "an unproven backup hint authenticated a device"
    );
    receiver.client.park_own_group_pin(&pin)?;
    assert!(receiver.client.pending_own_group_names_root(
        "alice",
        &sender.client.own_account_anchor()?,
        "alice"
    )?);
    assert!(!receiver.client.pending_own_group_names_root(
        "mallory",
        &sender.client.own_account_anchor()?,
        "alice"
    )?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn signed_root_hint_cannot_override_an_existing_verified_owner() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let (sender, receiver, mut entry) = Box::pin(native_hint_entry()).await?;
        assert_eq!(
            receiver.client.authenticated_envelope_sender(HeadUse::NewAuthorization, &entry)?,
            "alice"
        );
        entry.envelope.ext.ext.insert(
            "source_root_commitment".into(),
            serde_json::json!(ramflux_protocol::encode_base64url([44; 32])),
        );
        entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            sender.client.device_branch.as_ref().ok_or("native branch")?,
            &entry.envelope,
        )?;
        ramflux_node_core::check_entry_bound(&entry.envelope)?;
        assert!(
            receiver
                .client
                .authenticated_envelope_sender(HeadUse::NewAuthorization, &entry)
                .is_err(),
            "a valid branch signature cannot replace the pinned account root"
        );
        assert_eq!(
            receiver
                .client
                .account_db()?
                .client_record("identity", "alice")?
                .ok_or("verified root")?["contact_identity_commitment"],
            sender.client.own_account_anchor()?
        );
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn a_non_string_signed_root_hint_is_rejected_before_manifest_discovery() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let (_, receiver, mut entry) = Box::pin(native_hint_entry()).await?;
        entry.envelope.ext.ext.insert("source_root_commitment".into(), serde_json::json!(true));
        assert!(matches!(receiver.client.ensure_inbound_device(&receiver.config, &entry).await,
            Err(SdkError::InboundRejected(reason)) if reason.ends_with("invalid sender root hint")));
        Ok(())
    }).await?
}

#[test]
fn saved_group_root_selects_proof_material_but_never_authenticates_an_unproven_device() -> TestResult
{
    let sender = Fixture::new("alice", 81)?;
    let staging = Fixture::new("bob", 82)?;
    let receiver = Fixture::new("bob", 82)?;
    let entry = seal(&sender, &staging, message("group-proof", "group-thread"), b"body")?;
    let identity = sender.client.owned_device_identity()?;
    let public = ramflux_protocol::encode_base64url(
        sender
            .client
            .device_branch
            .as_ref()
            .ok_or("branch")?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    receiver.client.create_group("g", "bob")?;
    let db = receiver.client.account_db()?;
    db.add_group_member("g", "alice", "member")?;
    db.persist_group_member_device_key("g", &identity, &public)?;
    db.bind_group_member_key_identity(
        "g",
        &identity,
        "alice",
        identity.root_commitment(),
        &public,
    )?;
    assert!(receiver.client.device_identity_for_root(identity.root_commitment(), "alice").is_err());
    assert!(receiver.client.inbound_relationship_names_root(
        "alice",
        identity.root_commitment(),
        "alice"
    )?);
    assert!(!receiver.client.inbound_relationship_names_root(
        "mallory",
        identity.root_commitment(),
        "alice"
    )?);
    assert!(
        receiver.client.authenticated_device_identity(HeadUse::NewAuthorization, &entry).is_err()
    );
    let manifest = crate::client::identity_authority::test_support::manifest(&sender.client)?;
    receiver.client.persist_root_verified_directory(&manifest)?;
    assert_eq!(
        receiver.client.authenticated_device_identity(HeadUse::NewAuthorization, &entry)?,
        identity
    );
    let mut forged = entry;
    forged.envelope.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(
        receiver.client.authenticated_device_identity(HeadUse::NewAuthorization, &forged).is_err()
    );
    Ok(())
}

#[test]
fn deferred_group_authority_cannot_reactivate_after_the_snapshot_epoch_changes() -> TestResult {
    let sender = Fixture::new("alice", 91)?;
    let receiver = Fixture::new("bob", 101)?;
    let manifest = crate::client::identity_authority::test_support::manifest(&sender.client)?;
    let db = receiver.client.account_db()?;
    db.upsert_group_local_membership_snapshot("group", 1, 1024, "all", "bob", "owner", 1)?;
    db.upsert_group_member_snapshot("group", "alice", "member", 1)?;
    let pin = crate::own_device_sync::SdkOwnDeviceGroupMemberPin {
        group_id: "group".into(),
        device_id: "alice".into(),
        signing_public_key: manifest.devices[0].branch_public_key.clone(),
        principal_id: Some("alice".into()),
        principal_commitment: Some(manifest.principal_commitment.clone()),
    };
    receiver.client.park_own_group_pin(&pin)?;
    assert!(receiver.client.pending_own_group_names_root(
        "alice",
        &manifest.principal_commitment,
        "alice"
    )?);
    db.upsert_group_local_membership_snapshot("group", 2, 1024, "all", "bob", "owner", 1)?;
    assert!(!receiver.client.pending_own_group_names_root(
        "alice",
        &manifest.principal_commitment,
        "alice"
    )?);
    receiver.client.finish_lazy_own_group_pins("alice", &manifest.principal_commitment, "alice")?;
    assert_eq!(db.actor_state_usage("own-group/pending-pins/")?.0, 0);
    assert!(db.group_member_identity_metadata("group", "alice")?.is_none());
    Ok(())
}

#[test]
fn a_mismatched_deferred_pin_is_dropped_without_poisoning_authenticated_traffic() -> TestResult {
    let sender = Fixture::new("alice", 91)?;
    let receiver = Fixture::new("bob", 101)?;
    let manifest = crate::client::identity_authority::test_support::manifest(&sender.client)?;
    let db = receiver.client.account_db()?;
    db.upsert_group_local_membership_snapshot("group", 1, 1024, "all", "bob", "owner", 1)?;
    db.upsert_group_member_snapshot("group", "alice", "member", 1)?;
    let pin = crate::own_device_sync::SdkOwnDeviceGroupMemberPin {
        group_id: "group".into(),
        device_id: "alice".into(),
        signing_public_key: ramflux_protocol::encode_base64url([7; 32]),
        principal_id: Some("alice".into()),
        principal_commitment: Some(manifest.principal_commitment.clone()),
    };
    receiver.client.park_own_group_pin(&pin)?;
    receiver.client.persist_identity_directory(&manifest)?;
    for _ in 0..2 {
        receiver.client.finish_lazy_own_group_pins(
            "alice",
            &manifest.principal_commitment,
            "alice",
        )?;
    }
    assert_eq!(db.actor_state_usage("own-group/pending-pins/")?.0, 0);
    assert!(db.group_member_identity_metadata("group", "alice")?.is_none());
    let skipped = db.list_actor_states::<serde_json::Value>("own-device/restore-skip/")?;
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["reason"], "deferred_pin_key_mismatch");
    receiver.client.trusted_device(
        HeadUse::NewAuthorization,
        &receiver.client.device_identity_for_root(&manifest.principal_commitment, "alice")?,
    )?;
    Ok(())
}

async fn native_hint_entry() -> crate::client::native_test_support::TestResult<(
    crate::client::native_test_support::Fixture,
    crate::client::native_test_support::Fixture,
    GatewayInboxEntry,
)> {
    use crate::client::native_test_support::Fixture as Native;
    let sender = Native::with_principal("hint-source", "alice", "alice").await?;
    let receiver = Native::with_principal("hint-target", "bob", "bob").await?;
    sender.accept_peer(&receiver)?;
    receiver.accept_peer(&sender)?;
    let (entry, _) = native_discovery_message(&sender, &receiver)?;
    Ok((sender, receiver, entry))
}

fn native_discovery_message(
    sender: &crate::client::native_test_support::Fixture,
    receiver: &crate::client::native_test_support::Fixture,
) -> crate::client::native_test_support::TestResult<(GatewayInboxEntry, Vec<u8>)> {
    use ramflux_protocol::message as g;
    let conversation = g::dm_scope::derive(
        &sender.client.own_account_anchor()?,
        &receiver.client.own_account_anchor()?,
    )?;
    let identity = sender.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "first native root discovery".into(),
                erasure_nonce: ramflux_crypto::random_32()?.to_vec(),
                ..Default::default()
            })),
        },
    )?;
    let envelope = sender.seal_inner_to(receiver, &exact)?;
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: receiver.config.target_delivery_id.clone(),
            envelope,
        },
        exact,
    ))
}
