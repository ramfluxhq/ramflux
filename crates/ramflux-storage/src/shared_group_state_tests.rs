// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared group bootstrap, root-qualified projections, atomicity and title retention.
use super::test_db;
use crate::StorageError;
use ramflux_crypto::{
    DeviceBranch, VerifiedGroupState, advance_group_state, certify_group_state_actor,
    create_device_branch, create_identity_root, sign_group_state_operation,
    sign_group_state_snapshot,
};
use ramflux_protocol::group_state::{GroupStateActor, GroupStateChange, SharedGroupRole};
use serde_json::json;
fn person(
    principal: &str,
    device: &str,
    seed: u8,
) -> Result<(DeviceBranch, GroupStateActor), StorageError> {
    let root = create_identity_root(principal, [seed; 32]);
    let branch = create_device_branch(principal, device, 1, [seed + 1; 32]);
    let actor = certify_group_state_actor(&root, &branch, &format!("target-{device}"))?;
    Ok((branch, actor))
}
fn create(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
) -> Result<VerifiedGroupState, StorageError> {
    let operation = sign_group_state_operation(
        branch,
        actor,
        "group",
        1,
        None,
        GroupStateChange::Create {
            conversation_id: "thread".into(),
            max_members: 1000,
            new_member_history: "no_history".into(),
            name: Some("Checklist".into()),
        },
    )?;
    Ok(sign_group_state_snapshot(branch, actor, vec![operation])?)
}
#[test]
fn full_state_projects_all_three_members_and_the_same_epoch_and_name() -> Result<(), StorageError> {
    let (owner, a) = person("owner", "phone", 10)?;
    let (_, b) = person("peer", "phone", 20)?;
    let (_, sibling) = person("owner", "laptop", 10)?;
    let state = create(&owner, &a)?;
    let second = advance_group_state(
        &owner,
        &a,
        &state,
        GroupStateChange::Add { member: b.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let third = advance_group_state(
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
            db.group_member_device_key("group", &owner_key)?,
            db.group_member_device_key("group", &peer_key)?
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn sibling_inherits_membership_and_a_later_removal_cannot_be_reversed_by_replay()
-> Result<(), StorageError> {
    let (owner, a) = person("owner", "owner", 10)?;
    let (_, sibling) = person("owner", "laptop", 10)?;
    let state = create(&owner, &a)?;
    let (root, db) = test_db("group-sibling-removal")?;
    db.commit_shared_group_state(&state, &sibling)?;
    let id =
        state.member_storage_key(&sibling.identity)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(db.group_member_role("group", &id)?.as_deref(), Some("owner"));
    let joined = advance_group_state(
        &owner,
        &a,
        &state,
        GroupStateChange::Add { member: sibling.identity.clone(), role: SharedGroupRole::Member },
    )?;
    db.commit_shared_group_state(&joined, &sibling)?;
    assert_eq!(db.group_member_joined_epoch("group", &id)?, Some(2));
    let removed = advance_group_state(
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
    let (owner, a) = person("owner", "owner", 10)?;
    let state = create(&owner, &a)?;
    let (root, db) = test_db("group-conflicting-thread")?;
    db.persist_client_record("conversation", "thread", &json!({"kind":"direct","title":"Keep"}))?;
    assert!(db.commit_shared_group_state(&state, &a).is_err());
    assert!(db.group_snapshot_epoch("group")?.is_none());
    assert!(db.shared_group_state("group")?.is_none());
    let id = state.member_storage_key(&a.identity)?.ok_or(StorageError::GroupPermissionDenied)?;
    assert!(db.group_member_device_key("group", &id)?.is_none());
    assert_eq!(
        db.client_record("conversation", "thread")?.ok_or(StorageError::GroupPermissionDenied)?["title"],
        "Keep"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
