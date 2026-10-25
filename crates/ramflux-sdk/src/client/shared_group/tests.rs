// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-state convergence, first-message keys, names and removal through SDK group APIs.
use super::*;
use std::path::{Path, PathBuf};
fn temp_root(label: &str) -> Result<PathBuf, SdkError> {
    Ok(std::env::temp_dir().join(format!(
        "ramflux-group-{label}-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    )))
}
fn person(
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
