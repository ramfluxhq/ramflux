// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-group ciphertext authenticates the content head even when a sender reuses a seed.
use super::*;
#[test]
fn shared_group_same_epoch_forks_cannot_exchange_ciphertext_under_a_retagged_head()
-> Result<(), SdkError> {
    let root = temp_root("head-aad")?;
    let left = person(&root.join("left"), "owner", "owner", 31, 32)?;
    let right = person(&root.join("right"), "owner", "owner", 31, 32)?;
    let receiver_left = person(&root.join("receiver-left"), "peer", "peer", 41, 42)?;
    let receiver_right = person(&root.join("receiver-right"), "peer", "peer", 41, 42)?;
    let owner_manifest = crate::client::identity_authority::test_support::public_manifest(&left)?;
    let peer_manifest =
        crate::client::identity_authority::test_support::public_manifest(&receiver_left)?;
    for client in [&left, &right, &receiver_left, &receiver_right] {
        client.persist_identity_directory(&owner_manifest)?;
        client.persist_identity_directory(&peer_manifest)?;
    }
    let mut states = Vec::new();
    for (client, name) in [(&left, "left"), (&right, "right")] {
        client.shared_group_create("group", "thread", Some("base".into()), "target-owner")?;
        client.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::Add {
                member: receiver_left.owned_group_actor("target-peer")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        states.push(client.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::SetName { name: name.into() },
        )?);
    }
    assert_eq!(states[0].view().epoch, states[1].view().epoch);
    assert_ne!(states[0].snapshot().state_hash, states[1].snapshot().state_hash);
    receiver_left.accept_shared_group_state(&states[0], "target-peer")?;
    receiver_right.accept_shared_group_state(&states[1], "target-peer")?;
    let distribution = left.export_group_sender_key_distribution("group", "owner")?;
    receiver_left.import_group_sender_key_distribution(&distribution)?;
    // Deliberately register the same secret under the other authorized head: AEAD must still separate it.
    let mut reused: SdkGroupSenderKeyDistribution = serde_json::from_slice(&distribution)?;
    reused.group_state_hash = Some(states[1].snapshot().state_hash.clone());
    receiver_right.import_group_sender_key_distribution(&serde_json::to_vec(&reused)?)?;
    let encrypted = left.encrypt_group_message("group", "owner", b"first branch message")?;
    let mut envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&encrypted)?;
    let source =
        receiver_left.device_identity_for_root(&owner_manifest.principal_commitment, "owner")?;
    assert_eq!(
        receiver_left.decrypt_group_envelope_for_identity(&envelope, "left-message", &source)?,
        b"first branch message"
    );
    envelope.group_state_hash = Some(states[1].snapshot().state_hash.clone());
    assert!(matches!(
        receiver_right.decrypt_group_envelope_for_identity(&envelope, "retagged", &source),
        Err(SdkError::Crypto(CryptoError::AeadFailed))
    ));
    envelope.group_state_hash = None;
    assert!(
        receiver_right.decrypt_group_envelope_for_identity(&envelope, "headless", &source).is_err()
    );
    drop((left, right, receiver_left, receiver_right));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
