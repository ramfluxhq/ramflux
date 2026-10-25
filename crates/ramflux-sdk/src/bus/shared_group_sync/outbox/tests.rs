// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Removal privacy boundaries and retry budgets across coalesced group mutations.
use super::*;
use ramflux_protocol::group_state::{GroupStateChange, SharedGroupRole};

#[test]
fn shared_group_queue_freezes_removed_recipients_without_resetting_outage_backoff()
-> Result<(), SdkError> {
    let root = std::env::temp_dir().join(format!(
        "rf-group-queue-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let mut client = RamfluxClient::new();
    client.create_identity_root("owner", [11; 32]);
    client.create_device_branch("owner", "owner", 1, [12; 32]);
    client.open_account_index(&root)?;
    client.create_account("account", "owner")?;
    client.unlock_account("account", b"queue-test")?;
    let peer_root = ramflux_crypto::create_identity_root("peer", [21; 32]);
    let peer_branch = ramflux_crypto::create_device_branch("peer", "phone", 1, [22; 32]);
    let peer = ramflux_crypto::certify_group_state_actor(&peer_root, &peer_branch, "target-peer")?;
    let first = client.shared_group_create(
        "group",
        "thread",
        Some("Public title".into()),
        "target-owner",
    )?;
    let second = client.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    enqueue(&client, &second, Some(&first))?;
    let db = client.account_db()?;
    let id = key("group");
    let mut intent: Intent =
        db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    intent.attempt = 4;
    intent.next_at = now_unix_timestamp() + 50;
    let next_at = intent.next_at;
    let expires_at = intent.expires_at;
    db.persist_actor_state(&id, &intent)?;
    let removed = client.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "phone".into(),
        },
    )?;
    enqueue(&client, &removed, Some(&second))?;
    let renamed = client.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::SetName { name: "Private subsequent title".into() },
    )?;
    enqueue(&client, &renamed, Some(&removed))?;
    let intent: Intent = db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(intent.attempt, 4);
    assert_eq!(intent.next_at, next_at);
    assert_eq!(intent.expires_at, expires_at);
    assert_eq!(db.list_actor_states::<Intent>(PREFIX)?.len(), 1);
    for device in ["phone", "unknown-sibling"] {
        let snapshot =
            recipient_snapshot(&intent, &renamed, &peer.identity.root_commitment, device)
                .ok_or(StorageError::GroupPermissionDenied)?;
        assert_eq!(snapshot.epoch, removed.view().epoch);
        assert_eq!(
            ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?.view().name.as_deref(),
            Some("Public title")
        );
    }
    let owned = client.owned_device_identity()?;
    assert_eq!(
        recipient_snapshot(&intent, &renamed, owned.root_commitment(), "owner")
            .ok_or(StorageError::GroupPermissionDenied)?
            .epoch,
        renamed.view().epoch
    );
    let rejoined = client.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    enqueue(&client, &rejoined, Some(&renamed))?;
    let intent: Intent = db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(
        recipient_snapshot(&intent, &rejoined, &peer.identity.root_commitment, "phone")
            .ok_or(StorageError::GroupPermissionDenied)?
            .epoch,
        rejoined.view().epoch
    );
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
