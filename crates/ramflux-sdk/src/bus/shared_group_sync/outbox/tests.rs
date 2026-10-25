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

#[test]
fn shared_group_revoked_membership_discards_the_pending_broadcast() -> Result<(), SdkError> {
    use std::sync::{Arc, atomic::AtomicBool};
    let root = crate::bus::runtime_tests::root("group-revoked-outbox");
    let account = crate::bus::runtime_tests::account(
        &root.join("member"),
        "member",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let mut owner = RamfluxClient::new();
    owner.create_identity_root("owner", [21; 32]);
    owner.create_device_branch("owner", "owner", 1, [22; 32]);
    owner.open_account_index(root.join("owner"))?;
    owner.create_account("owner", "owner")?;
    owner.unlock_account("owner", b"group-owner")?;
    owner.shared_group_create("group", "thread", None, "owner-target")?;
    let local = account.client.owned_group_actor("target")?;
    let joined = owner.shared_group_change(
        "group",
        "owner-target",
        GroupStateChange::Add { member: local.identity.clone(), role: SharedGroupRole::Member },
    )?;
    account.client.accept_shared_group_state(&joined, "target")?;
    let outgoing = ramflux_crypto::resign_group_state_snapshot(
        account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &local,
        &joined,
    )?;
    enqueue(&account.client, &outgoing, None)?;
    let id = key("group");
    let mut intent = account
        .client
        .account_db()?
        .load_actor_state::<Intent>(&id)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let removed = owner.shared_group_change(
        "group",
        "owner-target",
        GroupStateChange::Remove {
            root_commitment: local.identity.root_commitment,
            device_id: local.identity.device_id,
        },
    )?;
    account.client.accept_shared_group_state(&removed, "target")?;
    assert!(prepare_intent(&account.client, &mut intent, "target")?.is_none());
    assert!(!account.client.account_db()?.actor_state_exists(&id)?);
    drop((account, owner));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn shared_group_bad_snapshot_does_not_prevent_another_group_getting_its_turn()
-> Result<(), SdkError> {
    use std::sync::{Arc, atomic::AtomicBool};
    let root = crate::bus::runtime_tests::root("group-isolated-outbox");
    let mut account =
        crate::bus::runtime_tests::account(&root, "owner", None, Arc::new(AtomicBool::new(false)))?;
    account.client.shared_group_create("a-bad", "bad-thread", None, "target")?;
    account.client.shared_group_create("z-good", "good-thread", None, "target")?;
    let bad = key("a-bad");
    let good = key("z-good");
    let mut intent = account
        .client
        .account_db()?
        .load_actor_state::<Intent>(&bad)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    intent.snapshot.signature = "invalid".into();
    account.client.account_db()?.persist_actor_state(&bad, &intent)?;
    assert_eq!(flush(&mut account).await?, 0);
    let bad = account
        .client
        .account_db()?
        .load_actor_state::<Intent>(&bad)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(bad.attempt, 1);
    assert!(!bad.round_active);
    assert_eq!(flush(&mut account).await?, 0);
    let good = account
        .client
        .account_db()?
        .load_actor_state::<Intent>(&good)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(good.attempt, 1, "one invalid group cannot abort the next group's turn");
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_group_device_removal_keeps_its_boundary_when_the_root_is_removed_later()
-> Result<(), SdkError> {
    let root = crate::bus::runtime_tests::root("group-removal-boundary");
    let account = crate::bus::runtime_tests::account(
        &root,
        "owner",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let client = &account.client;
    let peer = ramflux_crypto::certify_group_state_actor(
        &ramflux_crypto::create_identity_root("peer", [21; 32]),
        &ramflux_crypto::create_device_branch("peer", "phone", 1, [22; 32]),
        "phone-target",
    )?;
    client.shared_group_create("group", "thread", Some("Original name".into()), "target")?;
    client.shared_group_change(
        "group",
        "target",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let device_removed = client.shared_group_change(
        "group",
        "target",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "tablet".into(),
        },
    )?;
    client.shared_group_change(
        "group",
        "target",
        GroupStateChange::SetName { name: "Only remaining devices see this".into() },
    )?;
    let root_removed = client.shared_group_change(
        "group",
        "target",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "phone".into(),
        },
    )?;
    let intent = client
        .account_db()?
        .load_actor_state::<Intent>(&key("group"))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let tablet =
        recipient_snapshot(&intent, &root_removed, &peer.identity.root_commitment, "tablet")
            .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(tablet.epoch, device_removed.view().epoch);
    assert_eq!(
        ramflux_crypto::verify_group_state_snapshot(tablet.clone())?.view().name.as_deref(),
        Some("Original name")
    );
    assert_eq!(
        recipient_snapshot(&intent, &root_removed, &peer.identity.root_commitment, "phone")
            .ok_or(StorageError::GroupPermissionDenied)?
            .epoch,
        root_removed.view().epoch
    );
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_group_coalescing_during_round_eight_keeps_the_existing_retry_window()
-> Result<(), SdkError> {
    let root = crate::bus::runtime_tests::root("group-final-round");
    let account = crate::bus::runtime_tests::account(
        &root,
        "owner",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    account.client.shared_group_create("group", "thread", Some("Before".into()), "target")?;
    let id = key("group");
    let db = account.client.account_db()?;
    let mut intent =
        db.load_actor_state::<Intent>(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    intent.attempt = 8;
    intent.round_active = true;
    intent.next_at = now_unix_timestamp() + 10;
    let deadline = intent.expires_at;
    let next = intent.next_at;
    db.persist_actor_state(&id, &intent)?;
    account.client.shared_group_change(
        "group",
        "target",
        GroupStateChange::SetName { name: "During final round".into() },
    )?;
    let coalesced =
        db.load_actor_state::<Intent>(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(coalesced.attempt, 8, "coalescing cannot create a new eight-round budget");
    assert!(coalesced.round_active);
    assert_eq!(coalesced.expires_at, deadline);
    assert_eq!(coalesced.next_at, next);
    assert_eq!(coalesced.snapshot.epoch, 2);
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
