// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Removal privacy boundaries and retry budgets across coalesced group mutations.
use super::*;
use crate::GatewaySessionEngine;
use crate::bus::dispatch::surface_transport::fixture::RecordingGateway;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::Fixture as Native;
use ramflux_protocol::group_state::{GroupStateChange, SharedGroupRole};
use std::sync::{Arc, Mutex};

/// Runs one native fixture future to completion on a fresh current-thread runtime.
fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, SdkError>>,
) -> Result<T, SdkError> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(future)
}

/// One native account whose only device is `device`, held as a public-bus fixture.
async fn native_account(id: &str, device: &str) -> Result<LocalBusAccountState, SdkError> {
    let fixture = Native::with_device(id, device)
        .await
        .map_err(|error| SdkError::LocalBus(error.to_string()))?;
    Ok(fixture.into_bus())
}

/// The same native account with a recording gateway, so `flush` can drive its session.
async fn native_flush_account(id: &str, device: &str) -> Result<LocalBusAccountState, SdkError> {
    let mut account = native_account(id, device).await?;
    let gateway = RecordingGateway::new(Arc::new(Mutex::new(Vec::new())));
    account.install_test_session(GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(gateway),
    ));
    Ok(account)
}

fn native_person(id: &str, device: &str) -> Result<LocalBusAccountState, SdkError> {
    block_on(native_account(id, device))
}

#[test]
fn shared_group_queue_freezes_removed_recipients_without_resetting_outage_backoff()
-> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    let peer_account = native_person("peer", "phone")?;
    let peer = peer_account.client.fixture_group_actor("phone")?;
    let first = owner.client.fixture_group_create(
        "group",
        "thread",
        Some("Public title".into()),
        "owner",
    )?;
    let second = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    enqueue(&owner.client, &second, Some(&first))?;
    let db = owner.client.account_db()?;
    let id = key("group");
    let mut intent: Intent =
        db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    intent.attempt = 4;
    intent.next_at = now_unix_timestamp() + 50;
    let next_at = intent.next_at;
    let expires_at = intent.expires_at;
    db.persist_actor_state(&id, &intent)?;
    let removed = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "phone".into(),
        },
    )?;
    enqueue(&owner.client, &removed, Some(&second))?;
    let renamed = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::SetName { name: "Private subsequent title".into() },
    )?;
    enqueue(&owner.client, &renamed, Some(&removed))?;
    let intent: Intent = db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(intent.attempt, 4);
    assert_eq!(intent.next_at, next_at);
    assert_eq!(intent.expires_at, expires_at);
    assert_eq!(db.list_actor_states::<Intent>(PREFIX)?.len(), 1);
    for device in ["phone", "unknown-sibling"] {
        let snapshot = recipient_snapshot(
            &owner.client,
            &intent,
            &renamed,
            &peer.identity.root_commitment,
            device,
        )?
        .ok_or(StorageError::GroupPermissionDenied)?;
        assert_eq!(snapshot.epoch, removed.view().epoch);
        assert_eq!(
            ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?.view().name.as_deref(),
            Some("Public title")
        );
    }
    let owner_identity = owner.client.owned_device_identity()?;
    assert_eq!(
        recipient_snapshot(
            &owner.client,
            &intent,
            &renamed,
            owner_identity.root_commitment(),
            "owner"
        )?
        .ok_or(StorageError::GroupPermissionDenied)?
        .epoch,
        renamed.view().epoch
    );
    let rejoined = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    enqueue(&owner.client, &rejoined, Some(&renamed))?;
    let intent: Intent = db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(
        recipient_snapshot(
            &owner.client,
            &intent,
            &rejoined,
            &peer.identity.root_commitment,
            "phone"
        )?
        .ok_or(StorageError::GroupPermissionDenied)?
        .epoch,
        rejoined.view().epoch
    );
    drop((owner, peer_account));
    Ok(())
}

#[test]
fn shared_group_revoked_membership_discards_the_pending_broadcast() -> Result<(), SdkError> {
    let account = native_person("member", "member")?;
    let owner = native_person("owner", "owner")?;
    owner.client.fixture_group_create("group", "thread", None, "owner")?;
    let local = account.client.fixture_group_actor("member")?;
    let joined = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add { member: local.identity.clone(), role: SharedGroupRole::Member },
    )?;
    account.client.fixture_accept_group_state(&joined, "member")?;
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
    let removed = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Remove {
            root_commitment: local.identity.root_commitment,
            device_id: local.identity.device_id,
        },
    )?;
    account.client.fixture_accept_group_state(&removed, "member")?;
    assert!(prepare_intent(&account.client, &mut intent, "member")?.is_none());
    assert!(!account.client.account_db()?.actor_state_exists(&id)?);
    drop((account, owner));
    Ok(())
}

#[tokio::test]
async fn shared_group_bad_snapshot_does_not_prevent_another_group_getting_its_turn()
-> Result<(), SdkError> {
    let mut account = native_flush_account("owner", "owner").await?;
    account.client.fixture_group_create("a-bad", "bad-thread", None, "owner")?;
    account.client.fixture_group_create("z-good", "good-thread", None, "owner")?;
    let bad = key("a-bad");
    let good = key("z-good");
    let proof_key = format!("group-state/{}", ramflux_protocol::encode_base64url("a-bad"));
    let mut proof: GroupStateSnapshot = account
        .client
        .account_db()?
        .load_actor_state(&proof_key)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    proof.signature = "invalid".into();
    account.client.account_db()?.persist_actor_state(&proof_key, &proof)?;
    assert_eq!(flush(&mut account).await?, 0);
    let bad = account
        .client
        .account_db()?
        .load_actor_state::<Intent>(&bad)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(bad.attempt, 1);
    assert_eq!(flush(&mut account).await?, 0);
    let good = account
        .client
        .account_db()?
        .load_actor_state::<Intent>(&good)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(good.attempt, 1, "one invalid group cannot abort the next group's turn");
    drop(account);
    Ok(())
}

#[test]
fn shared_group_device_removal_keeps_its_boundary_when_the_root_is_removed_later()
-> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    let peer_account = native_person("peer", "phone")?;
    let peer = peer_account.client.fixture_group_actor("phone")?;
    let client = &owner.client;
    client.fixture_group_create("group", "thread", Some("Original name".into()), "owner")?;
    client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let device_removed = client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "tablet".into(),
        },
    )?;
    client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::SetName { name: "Only remaining devices see this".into() },
    )?;
    let root_removed = client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "phone".into(),
        },
    )?;
    let intent = client
        .account_db()?
        .load_actor_state::<Intent>(&key("group"))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let tablet = recipient_snapshot(
        client,
        &intent,
        &root_removed,
        &peer.identity.root_commitment,
        "tablet",
    )?
    .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(tablet.epoch, device_removed.view().epoch);
    assert_eq!(
        ramflux_crypto::verify_group_state_snapshot(tablet.clone())?.view().name.as_deref(),
        Some("Original name")
    );
    assert_eq!(
        recipient_snapshot(
            client,
            &intent,
            &root_removed,
            &peer.identity.root_commitment,
            "phone"
        )?
        .ok_or(StorageError::GroupPermissionDenied)?
        .epoch,
        root_removed.view().epoch
    );
    drop((owner, peer_account));
    Ok(())
}

#[test]
fn shared_group_coalescing_during_round_eight_keeps_the_existing_retry_window()
-> Result<(), SdkError> {
    let account = native_person("owner", "owner")?;
    account.client.fixture_group_create("group", "thread", Some("Before".into()), "owner")?;
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
    account.client.fixture_group_change(
        "group",
        "owner",
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
    Ok(())
}

#[test]
fn shared_group_same_head_coalescing_preserves_device_delivery_progress() -> Result<(), SdkError> {
    let account = native_person("owner", "owner")?;
    let state = account.client.fixture_group_create("group", "thread", None, "owner")?;
    let db = account.client.account_db()?;
    let id = key("group");
    let mut intent: Intent =
        db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    let recipient = ("root".into(), "phone".into());
    intent.delivered.insert(recipient.clone());
    db.persist_actor_state(&id, &intent)?;
    enqueue(&account.client, &state, None)?;
    let same: Intent = db.load_actor_state(&id)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert!(same.delivered.contains(&recipient));
    let wire = serde_json::to_value(same)?;
    assert!(wire["snapshot"].get("operations").is_none());
    assert!(wire["snapshot"].get("checkpoint").is_none());
    drop(account);
    Ok(())
}

#[tokio::test]
async fn shared_group_remove_commits_above_recovery_capacity_and_is_selected_first()
-> Result<(), SdkError> {
    let mut account = native_flush_account("owner", "owner").await?;
    for index in 0..40 {
        account.client.fixture_group_create(
            &format!("group-{index:02}"),
            &format!("thread-{index}"),
            None,
            "owner",
        )?;
    }
    let peer_account = native_account("peer", "phone").await?;
    let peer = peer_account.client.fixture_group_actor("phone")?;
    account.client.fixture_group_change(
        "group-39",
        "owner",
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let removed = account.client.fixture_group_change(
        "group-39",
        "owner",
        GroupStateChange::Remove {
            root_commitment: peer.identity.root_commitment.clone(),
            device_id: "phone".into(),
        },
    )?;
    assert_eq!(
        account
            .client
            .account_db()?
            .shared_group_state("group-39")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view(),
        removed.view()
    );
    assert_eq!(account.client.account_db()?.list_actor_states::<Intent>(PREFIX)?.len(), 40);
    // No gateway is needed: the progress pointer proves selection before the transport fails.
    let _ = flush(&mut account).await;
    assert_eq!(
        account.client.account_db()?.load_actor_state::<String>(DRIVER_PROGRESS)?.as_deref(),
        Some(key("group-39").as_str())
    );
    let mut intent: Intent = account
        .client
        .account_db()?
        .load_actor_state(&key("group-39"))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    intent.attempt = 8;
    intent.round_active = false;
    intent.next_at = 0;
    let deadline = intent.terminal[0].expires_at;
    account.client.account_db()?.persist_actor_state(&key("group-39"), &intent)?;
    assert_eq!(flush(&mut account).await?, 0);
    let retained: Intent = account
        .client
        .account_db()?
        .load_actor_state(&key("group-39"))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(retained.terminal[0].expires_at, deadline);
    assert!(retained.expires_at > now_unix_timestamp() + 6 * 86400);
    assert!(account.client.account_db()?.actor_state_exists(&boundary_key("group-39"))?);
    drop((account, peer_account));
    Ok(())
}
