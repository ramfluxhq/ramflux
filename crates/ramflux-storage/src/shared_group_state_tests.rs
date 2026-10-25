// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared group bootstrap, root-qualified projections, atomicity and title retention.
use super::test_db;
use crate::StorageError;
use ramflux_crypto::{
    DeviceBranch, VerifiedGroupState, advance_group_state, certify_group_state_actor,
    create_device_branch, create_group_state, create_identity_root,
};
use ramflux_protocol::group_state::{GroupStateActor, GroupStateChange, SharedGroupRole};
use serde_json::json;
fn person(
    principal: &str,
    device: &str,
    seed: u8,
) -> Result<(ramflux_crypto::IdentityRoot, DeviceBranch, GroupStateActor), StorageError> {
    let root = create_identity_root(principal, [seed; 32]);
    let branch = create_device_branch(principal, device, 1, [seed + 1; 32]);
    let actor = certify_group_state_actor(&root, &branch, &format!("target-{device}"))?;
    Ok((root, branch, actor))
}
fn owned_device(
    principal: &str,
    device: &str,
    seed: u8,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
        &create_identity_root(principal, [seed; 32]),
        &create_device_branch(principal, device, 1, [seed + 1; 32]),
    )?)
}

fn create(
    root: &ramflux_crypto::IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
) -> Result<VerifiedGroupState, StorageError> {
    Ok(create_group_state(
        root,
        branch,
        actor,
        ramflux_crypto::GroupStateCreateInput {
            group_id: "group",
            conversation_id: "thread",
            max_members: 200,
            new_member_history: "no_history",
            name: Some("Checklist".into()),
            now: 1000,
        },
    )?)
}
#[test]
fn full_state_projects_all_three_members_and_the_same_epoch_and_name() -> Result<(), StorageError> {
    let (owner_root, owner, a) = person("owner", "phone", 10)?;
    let (_, _, b) = person("peer", "phone", 20)?;
    let (_, _, sibling) = person("owner", "laptop", 10)?;
    let state = create(&owner_root, &owner, &a)?;
    let second = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &state,
        GroupStateChange::Add { member: b.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let third = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &second,
        GroupStateChange::Add { member: sibling.identity.clone(), role: SharedGroupRole::Member },
    )?;
    for (name, local) in [("owner", a), ("peer", b), ("sibling", sibling)] {
        let (root, db) = test_db(&format!("group-complete-{name}"))?;
        assert!(db.commit_shared_group_state(&third, &local)?);
        assert!(!db.commit_shared_group_state(&third, &local)?, "replay has no new epoch");
        assert_eq!(db.group_state("group")?.members.len(), 3);
        assert_eq!(db.group_state("group")?.group_epoch, 3);
        assert_eq!(
            db.shared_group_state("group")?.ok_or(StorageError::GroupPermissionDenied)?.view(),
            third.view()
        );
        assert_eq!(
            db.client_record("conversation", "thread")?
                .ok_or(StorageError::GroupPermissionDenied)?["title"],
            "Checklist"
        );
        let owner_key = third
            .member_storage_key(
                &third
                    .view()
                    .members
                    .iter()
                    .find(|m| m.identity.principal_id == "owner" && m.identity.device_id == "phone")
                    .ok_or(StorageError::GroupPermissionDenied)?
                    .identity,
            )?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let peer_key = third
            .member_storage_key(
                &third
                    .view()
                    .members
                    .iter()
                    .find(|m| m.identity.principal_id == "peer")
                    .ok_or(StorageError::GroupPermissionDenied)?
                    .identity,
            )?
            .ok_or(StorageError::GroupPermissionDenied)?;
        assert_ne!(owner_key, peer_key, "copied device names have independent pins");
        assert_ne!(
            db.group_member_device_key("group", &owned_device("owner", "phone", 10)?)?,
            db.group_member_device_key("group", &owned_device("peer", "phone", 20)?)?
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn sibling_inherits_membership_and_a_later_removal_cannot_be_reversed_by_replay()
-> Result<(), StorageError> {
    let (owner_root, owner, a) = person("owner", "owner", 10)?;
    let (_, _, sibling) = person("owner", "laptop", 10)?;
    let state = create(&owner_root, &owner, &a)?;
    let (root, db) = test_db("group-sibling-removal")?;
    db.commit_shared_group_state(&state, &sibling)?;
    let id = owned_device("owner", "laptop", 10)?;
    assert_eq!(db.group_member_role("group", &id)?.as_deref(), Some("owner"));
    let joined = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &state,
        GroupStateChange::Add { member: sibling.identity.clone(), role: SharedGroupRole::Member },
    )?;
    db.commit_shared_group_state(&joined, &sibling)?;
    assert_eq!(db.group_member_joined_epoch("group", &id)?, Some(2));
    let removed = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &joined,
        GroupStateChange::Remove {
            root_commitment: sibling.identity.root_commitment.clone(),
            device_id: "laptop".into(),
        },
    )?;
    db.commit_shared_group_state(&removed, &sibling)?;
    assert!(db.group_member_role("group", &id)?.is_none());
    assert!(!db.commit_shared_group_state(&joined, &sibling)?);
    assert!(db.group_member_role("group", &id)?.is_none());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn a_conflicting_thread_rolls_back_the_proof_roster_and_all_pins() -> Result<(), StorageError> {
    let (owner_root, owner, a) = person("owner", "owner", 10)?;
    let state = create(&owner_root, &owner, &a)?;
    let (root, db) = test_db("group-conflicting-thread")?;
    db.persist_client_record("conversation", "thread", &json!({"kind":"direct","title":"Keep"}))?;
    assert!(db.commit_shared_group_state(&state, &a).is_err());
    assert!(db.group_snapshot_epoch("group")?.is_none());
    assert!(db.shared_group_state("group")?.is_none());
    let id = owned_device("owner", "owner", 10)?;
    assert!(db.group_member_device_key("group", &id)?.is_none());
    assert_eq!(
        db.client_record("conversation", "thread")?.ok_or(StorageError::GroupPermissionDenied)?["title"],
        "Keep"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_legacy_snapshot_mutators_cannot_change_the_signed_projection() -> Result<(), StorageError>
{
    let (owner_root, owner, actor) = person("owner", "owner", 10)?;
    let state = create(&owner_root, &owner, &actor)?;
    let (root, db) = test_db("shared-legacy-snapshot")?;
    db.commit_shared_group_state(&state, &actor)?;
    assert!(db.create_group("group", "forged").is_err());
    assert!(db.add_group_member("group", "forged", "owner").is_err());
    assert!(
        db.upsert_group_local_membership_snapshot(
            "group",
            99,
            1000,
            "no_history",
            "forged",
            "owner",
            1
        )
        .is_err()
    );
    assert!(db.upsert_group_member_snapshot("group", "forged", "owner", 1).is_err());
    assert_eq!(db.group_state("group")?.members.len(), 1);
    assert_eq!(
        db.shared_group_state("group")?.ok_or(StorageError::GroupPermissionDenied)?.view(),
        state.view()
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn shared_legacy_retirement_cannot_retire_a_signed_member() -> Result<(), StorageError> {
    let (owner_root, owner, actor) = person("owner", "owner", 10)?;
    let state = create(&owner_root, &owner, &actor)?;
    let (root, db) = test_db("shared-legacy-retirement")?;
    db.commit_shared_group_state(&state, &actor)?;
    let key =
        state.member_storage_key(&actor.identity)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert!(db.retire_group_snapshot_member("group", &key, 1).is_err());
    assert_eq!(db.group_state("group")?.members.len(), 1);
    assert_eq!(
        db.group_member_role("group", &owned_device("owner", "owner", 10)?)?.as_deref(),
        Some("owner")
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn active_group_key_scopes_and_device_diagnostics_have_hard_bounds() -> Result<(), StorageError> {
    use crate::ProjectionStore;
    let (root, db) = test_db("group-retention")?;
    for index in 0..80 {
        let checkpoint = format!("group_sender_key:v3/{index}");
        db.set_projection_checkpoint(&checkpoint, "event")?;
        db.retain_group_key_checkpoint("group-root-device-recv", &checkpoint)?;
    }
    assert!(db.projection_checkpoint("group_sender_key:v3/0")?.is_none());
    assert!(db.projection_checkpoint("group_sender_key:v3/15")?.is_none());
    assert!(db.projection_checkpoint("group_sender_key:v3/16")?.is_some());
    assert!(db.projection_checkpoint("group_sender_key:v3/79")?.is_some());
    assert!(db.retain_group_key_checkpoint("scope", "dm_session:private").is_err());
    for index in 0..30 {
        db.append_group_journal(
            &format!("group-device/{index}"),
            "group.state.delivery_failed",
            &json!({"root_commitment":"root","device_id":"phone"}),
            1000 + index,
            "group/root/phone",
        )?;
    }
    let retained: u64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='group.state.delivery_failed'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retained, 8);
    let pruned: u64 = db.connection.query_row(
        "SELECT pruned_through FROM runtime_journal_bounds WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    assert!(pruned > 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
