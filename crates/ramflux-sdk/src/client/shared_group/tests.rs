// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-state convergence, first-message keys, names and removal through SDK group APIs.
use super::*;
use std::path::{Path, PathBuf};
pub(super) fn temp_root(label: &str) -> Result<PathBuf, SdkError> {
    Ok(std::env::temp_dir().join(format!(
        "ramflux-group-{label}-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    )))
}
pub(super) fn person(
    root: &Path,
    principal: &str,
    device: &str,
    root_seed: u8,
    device_seed: u8,
) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root(principal, [root_seed; 32]);
    client.create_device_branch(principal, device, 1, [device_seed; 32]);
    client.open_account_index(root)?;
    let actor = client.owned_group_actor(&format!("target-{device}"))?;
    client.create_account("acct", &actor.identity.root_commitment)?;
    client.unlock_account("acct", b"shared-group-test")?;
    Ok(client)
}
#[test]
fn three_devices_converge_and_each_first_group_message_reaches_the_other_members()
-> Result<(), SdkError> {
    let root = temp_root("sdk")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let peer = person(&root.join("peer"), "agent", "agent", 21, 22)?;
    let sibling = person(&root.join("sibling"), "owner", "laptop", 11, 32)?;
    let mut own = crate::client::identity_authority::test_support::public_manifest(&owner)?;
    own.devices.extend(
        crate::client::identity_authority::test_support::public_manifest(&sibling)?.devices,
    );
    crate::client::identity_authority::test_support::sign_manifest(
        owner.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut own,
        2,
    )?;
    let remote = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    for client in [&owner, &peer, &sibling] {
        client.persist_identity_directory(&own)?;
        client.persist_identity_directory(&remote)?;
    }
    owner.shared_group_create("group", "thread", Some("Checklist".into()), "target-owner")?;
    let peer_actor = peer.owned_group_actor("target-agent")?;
    let sibling_actor = sibling.owned_group_actor("target-laptop")?;
    let second = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: peer_actor.identity.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.accept_shared_group_state(&second, "target-agent")?;
    let third = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: sibling_actor.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let recovered = decode_packet(&packet_bytes(&third)?)?.ok_or(SdkError::IdentityRootMissing)?;
    peer.accept_shared_group_state(&recovered, "target-agent")?;
    sibling.accept_shared_group_state(&recovered, "target-laptop")?;
    let expected = owner.group_state("group")?;
    assert_eq!(expected.group_epoch, 3);
    assert_eq!(expected.members.len(), 3);
    assert_eq!(peer.group_state("group")?, expected);
    assert_eq!(sibling.group_state("group")?, expected);
    for (sender, device) in [(&owner, "owner"), (&peer, "agent"), (&sibling, "laptop")] {
        let distribution = sender.export_group_sender_key_distribution("group", device)?;
        let message = sender.encrypt_group_message("group", device, device.as_bytes())?;
        for (receiver, other) in [(&owner, "owner"), (&peer, "agent"), (&sibling, "laptop")] {
            if device == other {
                continue;
            }
            receiver.import_group_sender_key_distribution(&distribution)?;
            let id = format!("first-{device}");
            receiver.send_direct_message("thread", &id, device, &message)?;
            assert_eq!(receiver.decrypt_group_message("thread", &id)?, device.as_bytes());
        }
    }
    let renamed = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::SetName { name: "Reviewed".into() },
    )?;
    for (client, target) in [(&peer, "target-agent"), (&sibling, "target-laptop")] {
        client.accept_shared_group_state(&renamed, target)?;
        assert_eq!(
            client
                .account_db()?
                .client_record("conversation", "thread")?
                .ok_or(SdkError::IdentityRootMissing)?["title"],
            "Reviewed"
        );
        assert_eq!(
            client.shared_group_metadata("group")?.ok_or(SdkError::IdentityRootMissing)?["name_epoch"],
            4
        );
    }
    let removed = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Remove {
            root_commitment: peer_actor.identity.root_commitment,
            device_id: "agent".into(),
        },
    )?;
    peer.accept_shared_group_state(&removed, "target-agent")?;
    sibling.accept_shared_group_state(&removed, "target-laptop")?;
    assert!(!peer.group_state("group")?.members.contains("agent"));
    assert!(peer.encrypt_group_message("group", "agent", b"forbidden").is_err());
    let fresh = owner.export_group_sender_key_distribution("group", "owner")?;
    assert!(peer.import_group_sender_key_distribution(&fresh).is_err());
    drop((owner, peer, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn readonly_group_metadata_does_not_need_private_root_material() -> Result<(), SdkError> {
    let root = temp_root("reader")?;
    let owner = person(&root, "owner", "owner", 11, 12)?;
    owner.shared_group_create("group", "thread", Some("Checklist".into()), "target-owner")?;
    let before = owner.shared_group_metadata("group")?;
    let mut reader = RamfluxClient::new();
    reader.active_account_db = Some(owner.account_db()?.open_reader()?);
    assert_eq!(reader.shared_group_metadata("group")?, before);
    drop((reader, owner));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn one_bootstrap_packet_supplies_the_first_key_and_replays_do_not_reset_the_receiver()
-> Result<(), SdkError> {
    let root = temp_root("bootstrap")?;
    let owner = person(&root.join("owner"), "owner", "owner", 41, 42)?;
    let peer = person(&root.join("peer"), "peer", "peer", 51, 52)?;
    let own = crate::client::identity_authority::test_support::public_manifest(&owner)?;
    let remote = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    for client in [&owner, &peer] {
        client.persist_identity_directory(&own)?;
        client.persist_identity_directory(&remote)?;
    }
    owner.shared_group_create("group", "thread", Some("Checklist".into()), "target-owner")?;
    let peer_actor = peer.owned_group_actor("target-peer")?;
    let state = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: peer_actor.identity.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let bytes = owner.shared_group_packet(&state, true)?;
    let decoded = decode_packet(&bytes)?.ok_or(SdkError::IdentityRootMissing)?;
    peer.establish_friend_link("creator-consent", "peer", &own.principal_commitment)?;
    let prepared = peer.prepare_shared_group_payload(decoded, &bytes)?;
    assert!(peer.apply_prepared_shared_group(&prepared, "target-peer")?);
    let encrypted =
        owner.encrypt_group_message("group", "owner", b"first without a separate distribution")?;
    peer.send_direct_message("thread", "first", "owner", &encrypted)?;
    assert_eq!(
        peer.decrypt_group_message("thread", "first")?,
        b"first without a separate distribution"
    );
    let source = peer.device_identity_for_root(&own.principal_commitment, "owner")?;
    let before = serde_json::to_value(peer.load_group_sender_key_state(
        "group",
        &source,
        state.view().epoch,
        "recv",
    )?)?;
    assert!(!peer.apply_prepared_shared_group(&prepared, "target-peer")?);
    assert_eq!(
        serde_json::to_value(peer.load_group_sender_key_state(
            "group",
            &source,
            state.view().epoch,
            "recv"
        )?)?,
        before
    );
    let next = owner.encrypt_group_message("group", "owner", b"second after bootstrap replay")?;
    peer.send_direct_message("thread", "second", "owner", &next)?;
    assert_eq!(peer.decrypt_group_message("thread", "second")?, b"second after bootstrap replay");
    let mut poisoned: Value = serde_json::from_slice(&bytes)?;
    let payload = ramflux_protocol::decode_base64url(
        poisoned["distribution_base64"].as_str().ok_or(SdkError::IdentityRootMissing)?,
    )
    .map_err(|_| invalid("distribution encoding"))?;
    let mut distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&payload)?;
    distribution.sender_key_seed = [99; 32];
    poisoned["distribution_base64"] =
        json!(ramflux_protocol::encode_base64url(serde_json::to_vec(&distribution)?));
    let poisoned = serde_json::to_vec(&poisoned)?;
    let changed = peer.prepare_shared_group_payload(state.clone(), &poisoned)?;
    assert!(peer.apply_prepared_shared_group(&changed, "target-peer").is_err());
    let removed = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Remove {
            root_commitment: peer_actor.identity.root_commitment,
            device_id: "peer".into(),
        },
    )?;
    let bytes = owner.shared_group_packet(&removed, false)?;
    assert!(
        serde_json::from_slice::<Value>(&bytes)?.get("distribution_base64").is_none(),
        "removed recipients never receive the new epoch key"
    );
    let prepared = peer.prepare_shared_group_payload(removed, &bytes)?;
    assert!(peer.apply_prepared_shared_group(&prepared, "target-peer")?);
    assert!(peer.load_group_sender_key_state("group", &source, 3, "recv").is_err());
    assert!(peer.encrypt_group_message("group", "peer", b"not a member").is_err());
    drop((owner, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_group_implicit_sibling_can_send_and_own_history_keeps_signed_names()
-> Result<(), SdkError> {
    let root = temp_root("implicit-sibling")?;
    let owner = person(&root.join("owner"), "owner", "phone", 61, 62)?;
    let peer = person(&root.join("peer"), "peer", "phone", 71, 72)?;
    let sibling = person(&root.join("sibling"), "owner", "laptop", 61, 82)?;
    let mut own = crate::client::identity_authority::test_support::public_manifest(&owner)?;
    own.devices.extend(
        crate::client::identity_authority::test_support::public_manifest(&sibling)?.devices,
    );
    crate::client::identity_authority::test_support::sign_manifest(
        owner.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut own,
        2,
    )?;
    let remote = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    for client in [&owner, &peer, &sibling] {
        client.persist_identity_directory(&own)?;
        client.persist_identity_directory(&remote)?;
    }
    owner.shared_group_create("group", "thread", Some("Signed title".into()), "target-phone")?;
    let state = owner.shared_group_change(
        "group",
        "target-phone",
        GroupStateChange::Add {
            member: peer.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.accept_shared_group_state(&state, "target-phone")?;
    let routes = owner.group_member_routes("group")?;
    assert_eq!(routes.len(), 3, "both same-name roots and the implicit sibling need routes");
    let roots = routes
        .iter()
        .filter(|route| route.member_id == "phone")
        .filter_map(|route| route.member_principal_commitment.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(roots.len(), 2);
    let sibling_id = peer.device_identity_for_root(&own.principal_commitment, "laptop")?;
    assert!(peer.account_db()?.group_member_key_binding("group", &sibling_id)?.is_none());
    peer.require_group_sender_pin("group", "owner", &sibling_id)?;
    assert!(peer.account_db()?.group_member_key_binding("group", &sibling_id)?.is_some());
    // The own-device wrapper's role/name claims cannot replace the enclosed signed state.
    let mut bundle = owner.own_device_history_bundle(
        &own.principal_commitment,
        "phone",
        "laptop",
        "snapshot",
    )?;
    bundle.groups[0].local_role = "bot".into();
    bundle.groups[0].group_epoch += 1;
    assert!(sibling.restore_own_groups(&bundle)?.is_empty(), "mismatched wrapper isolated");
    bundle.groups[0].group_epoch -= 1;
    let floors = sibling.restore_own_groups(&bundle)?;
    assert_eq!(floors.get("group"), Some(&1));
    assert_eq!(
        sibling.group_state("group")?.roles.get("laptop").map(String::as_str),
        Some("owner")
    );
    assert_eq!(sibling.group_state("group")?.group_epoch, 2, "no explicit sibling join");
    assert_eq!(
        sibling
            .account_db()?
            .client_record("conversation", "thread")?
            .ok_or(StorageError::GroupPermissionDenied)?["title"],
        "Signed title"
    );
    let distribution = sibling.export_group_sender_key_distribution("group", "laptop")?;
    peer.import_group_key_for_identity(&distribution, &sibling_id, false)?;
    let encrypted = sibling.encrypt_group_message("group", "laptop", b"implicit first message")?;
    let envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&encrypted)?;
    assert_eq!(
        peer.decrypt_group_envelope_for_identity(&envelope, "first-sibling", &sibling_id)?,
        b"implicit first message"
    );
    // Both roots use the same literal device name, but independent key/counter namespaces.
    let owner_id = peer.device_identity_for_root(&own.principal_commitment, "phone")?;
    let distribution = owner.export_group_sender_key_distribution("group", "phone")?;
    peer.import_group_key_for_identity(&distribution, &owner_id, false)?;
    let encrypted = owner.encrypt_group_message("group", "phone", b"same-name root-qualified")?;
    let envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&encrypted)?;
    assert_eq!(
        peer.decrypt_group_envelope_for_identity(&envelope, "first-owner", &owner_id)?,
        b"same-name root-qualified"
    );
    drop((owner, peer, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "head_scope_tests.rs"]
mod head_scope_tests;

#[path = "fork_tests.rs"]
mod fork_tests;

#[test]
fn r5_contact_forwarding_cannot_adopt_a_stranger_group_or_override_decline() -> Result<(), SdkError>
{
    let root = temp_root("r5-consent")?;
    let stranger = person(&root.join("stranger"), "stranger", "phone", 11, 12)?;
    let contact = person(&root.join("contact"), "contact", "phone", 21, 22)?;
    let user = person(&root.join("user"), "user", "phone", 31, 32)?;
    stranger.shared_group_create("g", "t", None, "target-phone")?;
    stranger.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::Add {
            member: contact.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let state = stranger.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::Add {
            member: user.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let contact_root = contact.owned_device_identity()?.root_commitment().to_owned();
    user.establish_friend_link("friend", "user", &contact_root)?;
    let forwarded = ramflux_crypto::resign_group_state_snapshot(
        contact.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &contact.owned_group_actor("target-phone")?,
        &state,
    )?;
    assert!(user.group_snapshot_requires_consent(&forwarded)?);
    let packet = packet_bytes(&forwarded)?;
    user.hold_group_invitation(&forwarded, &packet)?;
    user.decide_group_invitation("g", false, "target-phone")?;
    assert!(user.group_snapshot_requires_consent(&forwarded).is_err());
    let prepared = user.prepare_shared_group_payload(forwarded, &packet)?;
    assert!(user.apply_prepared_shared_group(&prepared, "target-phone").is_err());
    assert!(user.account_db()?.shared_group_state("g")?.is_none());
    assert!(user.account_db()?.client_record("conversation", "t")?.is_none());
    drop((stranger, contact, user));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn r5_removed_requester_flood_is_not_stored_and_other_groups_keep_capacity() -> Result<(), SdkError>
{
    use ramflux_crypto::{GroupChangeRequestInput, sign_group_change_request};
    let root = temp_root("r5-requests")?;
    let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
    let removed = person(&root.join("removed"), "removed", "phone", 21, 22)?;
    let admin = person(&root.join("admin"), "admin", "phone", 31, 32)?;
    let victim = person(&root.join("victim"), "victim", "phone", 41, 42)?;
    for person in [&owner, &removed, &admin, &victim] {
        owner.persist_identity_directory(
            &crate::client::identity_authority::test_support::public_manifest(person)?,
        )?;
    }
    owner.shared_group_create("g", "t", None, "target-phone")?;
    owner.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::Add {
            member: removed.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    owner.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::Add {
            member: admin.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    let before = owner.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::Add {
            member: victim.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    owner.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::Remove {
            root_commitment: removed.owned_device_identity()?.root_commitment().into(),
            device_id: "phone".into(),
        },
    )?;
    for index in 0..80 {
        let request = sign_group_change_request(
            removed.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &removed.owned_group_actor("target-phone")?,
            &before,
            GroupChangeRequestInput {
                request_id: format!("flood-{index}"),
                change: GroupStateChange::SetName { name: "spam".into() },
                now: now_unix_timestamp(),
            },
        )?;
        assert!(owner.insert_group_request(&request, true).is_err());
    }
    assert!(owner.group_change_records()?.is_empty());
    let removal = sign_group_change_request(
        admin.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &admin.owned_group_actor("target-phone")?,
        &before,
        GroupChangeRequestInput {
            request_id: "admin-removal".into(),
            change: GroupStateChange::Remove {
                root_commitment: victim.owned_device_identity()?.root_commitment().into(),
                device_id: "phone".into(),
            },
            now: now_unix_timestamp(),
        },
    )?;
    owner.insert_group_request(&removal, true)?;
    assert_eq!(
        owner.process_group_request(&removal, "target-phone")?.status,
        ramflux_protocol::GroupChangeStatus::Applied
    );

    owner.shared_group_create("other", "other-thread", None, "target-phone")?;
    let other = owner
        .account_db()?
        .shared_group_state("other")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let request = sign_group_change_request(
        owner.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &owner.owned_group_actor("target-phone")?,
        &other,
        GroupChangeRequestInput {
            request_id: "legitimate-removal".into(),
            change: GroupStateChange::SetName { name: "legitimate".into() },
            now: now_unix_timestamp(),
        },
    )?;
    owner.insert_group_request(&request, true)?;
    assert_eq!(owner.group_change_records()?.len(), 2);
    drop((owner, removed, admin, victim));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn r5_processed_results_still_count_toward_the_source_partition() -> Result<(), SdkError> {
    let root = temp_root("r5-result-pool")?;
    let owner = person(&root, "owner", "phone", 11, 12)?;
    owner.shared_group_create("g", "t", None, "target-phone")?;
    let state =
        owner.account_db()?.shared_group_state("g")?.ok_or(StorageError::GroupPermissionDenied)?;
    for index in 0..65 {
        let request = ramflux_crypto::sign_group_change_request(
            owner.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &owner.owned_group_actor("target-phone")?,
            &state,
            ramflux_crypto::GroupChangeRequestInput {
                request_id: format!("processed-{index}"),
                change: GroupStateChange::SetName { name: "name".into() },
                now: now_unix_timestamp(),
            },
        )?;
        let result = owner.insert_group_request(&request, true);
        if index == 64 {
            assert!(result.is_err());
        } else {
            result?;
            let mut row = owner
                .group_change_record(&request, true)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            row.local_status = "result_ready".into();
            owner.persist_group_request(&row)?;
        }
    }
    assert_eq!(owner.group_change_records()?.len(), 64);
    drop(owner);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r5_group_aliases_follow_message_deletion_and_pending_expiry() -> Result<(), SdkError> {
    let root = temp_root("r5-alias")?;
    let owner = person(&root, "owner", "phone", 11, 12)?;
    owner.shared_group_create("g", "t", None, "target-phone")?;
    let (canonical, _) = owner.qualify_outgoing_group_message("g", "logical")?;
    owner.send_direct_message("t", &canonical, "phone", b"body")?;
    owner.account_db()?.delete_direct_message("t", &canonical, "local", "delete")?;
    assert_eq!(owner.outgoing_group_logical_id(&canonical)?, None);
    let (pending, _) = owner.qualify_outgoing_group_message("g", "pending")?;
    let alias_key = format!("group-message/alias/{pending}");
    let mut row: serde_json::Value =
        owner.account_db()?.load_actor_state(&alias_key)?.ok_or(SdkError::IdentityRootMissing)?;
    row["expires_at"] = serde_json::json!(0);
    owner.account_db()?.persist_actor_state(&alias_key, &row)?;
    owner.qualify_outgoing_group_message("g", "next")?;
    assert_eq!(owner.outgoing_group_logical_id(&pending)?, None);
    drop(owner);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r5_successor_transfer_chain_replaces_an_offline_members_higher_epoch_projection()
-> Result<(), SdkError> {
    let root = temp_root("r5-transfer-projection")?;
    let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
    let laptop = person(&root.join("laptop"), "owner", "laptop", 11, 32)?;
    let bob = person(&root.join("bob"), "bob", "phone", 21, 22)?;
    let observer = person(&root.join("observer"), "observer", "phone", 41, 42)?;
    owner.shared_group_create("g", "t", None, "target-phone")?;
    for member in [&bob, &observer] {
        owner.shared_group_change(
            "g",
            "target-phone",
            GroupStateChange::Add {
                member: member.owned_group_actor("target-phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
    }
    let base =
        owner.account_db()?.shared_group_state("g")?.ok_or(StorageError::GroupPermissionDenied)?;
    let mut fork = base.clone();
    for index in 0..5 {
        fork = ramflux_crypto::advance_group_state(
            laptop.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            laptop.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &laptop.owned_group_actor("target-laptop")?,
            &fork,
            GroupStateChange::SetName { name: format!("fork-{index}") },
        )?;
    }
    observer.accept_shared_group_state(&fork, "target-phone")?;
    let transfer = owner.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::TransferOwnership { creator: bob.owned_group_actor("target-phone")? },
    )?;
    bob.accept_shared_group_state(&transfer, "target-phone")?;
    let successor = bob.shared_group_change(
        "g",
        "target-phone",
        GroupStateChange::SetName { name: "successor".into() },
    )?;
    assert!(successor.view().epoch < fork.view().epoch);
    assert!(observer.accept_shared_group_state(&successor, "target-phone")?);
    assert_eq!(
        observer
            .account_db()?
            .shared_group_state("g")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .creator(),
        successor.creator()
    );
    assert!(!observer.accept_shared_group_state(&fork, "target-phone")?);
    drop((owner, laptop, bob, observer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r5_legacy_nonmember_results_are_pruned_on_new_admission() -> Result<(), SdkError> {
    let root = temp_root("r5-old-result")?;
    let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
    let outsider = person(&root.join("outsider"), "outsider", "phone", 21, 22)?;
    let base = owner.shared_group_create("g", "t", None, "target-phone")?;
    // Reconstruct a row admitted by the former receive path, using a genuine
    // root-certified outsider and a creator-signed refusal.
    let mut request = ramflux_protocol::GroupChangeRequest {
        schema: ramflux_protocol::group_state::GROUP_CHANGE_REQUEST_DOMAIN.into(),
        group_id: "g".into(),
        genesis_hash: base.genesis_hash()?,
        base_epoch: 1,
        creator_root: owner.owned_device_identity()?.root_commitment().into(),
        request_id: "old-outsider".into(),
        actor: outsider.owned_group_actor("target-phone")?,
        change: GroupStateChange::SetName { name: "spam".into() },
        issued_at: now_unix_timestamp(),
        expires_at: now_unix_timestamp() + 86400,
        signature: String::new(),
    };
    let mut body = serde_json::to_value(&request)?;
    body.as_object_mut().ok_or(SdkError::IdentityRootMissing)?.remove("signature");
    request.signature = ramflux_crypto::sign_with_device_branch(
        outsider.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &body,
    )?;
    ramflux_crypto::verify_group_change_request(&request, now_unix_timestamp())?;
    // Retention reads stored rows; wire verification remains mandatory on new admission.
    let result = ramflux_crypto::sign_group_change_result(
        owner.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &owner.owned_group_actor("target-phone")?,
        &request,
        &base,
        ramflux_protocol::GroupChangeStatus::PermissionDenied,
        now_unix_timestamp(),
    )?;
    owner.persist_group_request(&super::requests::RequestRecord {
        request,
        incoming: true,
        result: Some(result),
        local_status: "result_ready".into(),
        expires_at: now_unix_timestamp() + 86400,
        next_at: 0,
        delivered: BTreeSet::new(),
        federation: None,
    })?;
    owner.shared_group_create("other", "other-thread", None, "target-phone")?;
    let request = owner.stage_group_change_request(
        "other",
        "target-phone",
        GroupStateChange::SetName { name: "legitimate".into() },
        None,
    )?;
    let rows = owner.group_change_records()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request, request);
    drop((owner, outsider));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
