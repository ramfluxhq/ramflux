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

#[test]
fn r6_receiver_removal_floor_survives_a_snapshot_without_exclusions_and_allows_later_readd()
-> Result<(), StorageError> {
    let (owner_root, owner, a) = person("owner", "owner-phone", 10)?;
    let (_, _, member) = person("removed", "removed-phone", 20)?;
    let initial = create(&owner_root, &owner, &a)?;
    let joined = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &initial,
        GroupStateChange::Add { member: member.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let removed = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &joined,
        GroupStateChange::Remove {
            root_commitment: member.identity.root_commitment.clone(),
            device_id: member.identity.device_id.clone(),
        },
    )?;
    let (root, db) = test_db("sticky-group-removal")?;
    db.commit_shared_group_state(&joined, &a)?;
    db.commit_shared_group_state(&removed, &a)?;
    // A full snapshot can omit a departed root's expired wire exclusions.
    let mut pruned = initial;
    for index in 0..3 {
        pruned = advance_group_state(
            &owner_root,
            &owner,
            &a,
            &pruned,
            GroupStateChange::SetName { name: format!("pruned-{index}") },
        )?;
    }
    assert_eq!(pruned.view().excluded, []);
    db.commit_shared_group_state(&pruned, &a)?;
    let mut old_branch = joined;
    for index in 0..3 {
        old_branch = advance_group_state(
            &owner_root,
            &owner,
            &a,
            &old_branch,
            GroupStateChange::SetName { name: format!("old-{index}") },
        )?;
    }
    assert!(old_branch.view().epoch > pruned.view().epoch);
    assert!(db.commit_shared_group_state(&old_branch, &a).is_err());
    assert_eq!(
        db.shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .snapshot()
            .state_hash,
        pruned.snapshot().state_hash
    );
    let active:u64=db.connection.query_row("SELECT count(*) FROM shared_group_member_projection WHERE group_id='group' AND root_commitment=?1 AND active=1",rusqlite::params![member.identity.root_commitment],|row|row.get(0))?;
    assert_eq!(active, 0);
    // Upgrading an r5 store can recover the floor from its inactive verified projection.
    db.remove_actor_state(&format!(
        "group-state/removal-floors/{}",
        ramflux_protocol::encode_base64url("group")
    ))?;
    assert!(db.commit_shared_group_state(&old_branch, &a).is_err());
    let readded = advance_group_state(
        &owner_root,
        &owner,
        &a,
        &pruned,
        GroupStateChange::Add { member: member.identity.clone(), role: SharedGroupRole::Member },
    )?;
    assert!(db.commit_shared_group_state(&readded, &a)?);
    assert_eq!(
        db.shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view()
            .effective_role(&member.identity.root_commitment, &member.identity.device_id),
        Some(SharedGroupRole::Member)
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_merge_selects_signed_group_state_and_preserves_removal_floors_in_both_directions()
-> Result<(), StorageError> {
    let (owner_root, owner, actor) = person("owner", "phone", 10)?;
    let (_, _, member) = person("removed", "phone", 20)?;
    let initial = create(&owner_root, &owner, &actor)?;
    let joined = advance_group_state(
        &owner_root,
        &owner,
        &actor,
        &initial,
        GroupStateChange::Add { member: member.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let removed = advance_group_state(
        &owner_root,
        &owner,
        &actor,
        &joined,
        GroupStateChange::Remove {
            root_commitment: member.identity.root_commitment.clone(),
            device_id: member.identity.device_id.clone(),
        },
    )?;
    let pruned = renamed_branch(&owner_root, &owner, &actor, initial, "Restored", 3)?;
    let unsafe_branch = renamed_branch(&owner_root, &owner, &actor, joined.clone(), "Unsafe", 5)?;
    for incoming_newer in [false, true] {
        let (root, source) = test_db(&format!("backup-shared-source-{incoming_newer}"))?;
        let (local_root, local) = test_db(&format!("backup-shared-live-{incoming_newer}"))?;
        let (newer, older) = if incoming_newer { (&source, &local) } else { (&local, &source) };
        older.commit_shared_group_state(&joined, &actor)?;
        newer.commit_shared_group_state(&joined, &actor)?;
        newer.commit_shared_group_state(&removed, &actor)?;
        newer.commit_shared_group_state(&pruned, &actor)?;
        // Exercise the upgrade path: the old inactive verified projection still fences re-admission.
        newer.remove_actor_state(&format!(
            "group-state/removal-floors/{}",
            ramflux_protocol::encode_base64url("group")
        ))?;
        let incoming = root.join("incoming.db");
        let snapshot = source.write_backup_snapshot(&incoming)?;
        let target = local_root.join("merged.db");
        let saved = local.write_backup_snapshot(&target)?;
        let mut merged = crate::BackupDatabase::open(&target, &saved.key)?;
        merged.merge_backup_with_group_actor(&incoming, &snapshot.key, Some(&actor), || Ok(()))?;
        let state: Vec<u8> = merged.db.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
            rusqlite::params![format!(
                "group-state/{}",
                ramflux_protocol::encode_base64url("group")
            )],
            |r| r.get(0),
        )?;
        assert_eq!(
            serde_json::from_slice::<ramflux_protocol::GroupStateSnapshot>(&state)?,
            *pruned.snapshot()
        );
        let (epoch,active):(u64,u64) = merged.db.query_row("SELECT group_epoch,(SELECT count(*) FROM shared_group_member_projection WHERE group_id='group' AND active=1) FROM group_projection WHERE group_id='group'",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!((epoch, active), (pruned.view().epoch, 1));
        let removed_active:u64=merged.db.query_row("SELECT count(*) FROM shared_group_member_projection WHERE group_id='group' AND root_commitment=?1 AND active=1",rusqlite::params![member.identity.root_commitment],|r|r.get(0))?;
        assert_eq!(removed_active, 0);
        let title:Vec<u8>=merged.db.query_row("SELECT state_json FROM runtime_actor_state WHERE state_kind='directory/conversation/thread'",[],|r|r.get(0))?;
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&title)?["title"], "Restored-2");
        // A newer archive on the removed member's stale line must fail atomically.
        let (bad_root, bad) = test_db(&format!("backup-shared-bad-{incoming_newer}"))?;
        bad.commit_shared_group_state(&unsafe_branch, &actor)?;
        let bad_path = bad_root.join("bad.db");
        let bad_snapshot = bad.write_backup_snapshot(&bad_path)?;
        assert!(
            merged
                .merge_backup_with_group_actor(
                    &bad_path,
                    &bad_snapshot.key,
                    Some(&actor),
                    || Ok(())
                )
                .is_err()
        );
        let after: Vec<u8> = merged.db.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
            rusqlite::params![format!(
                "group-state/{}",
                ramflux_protocol::encode_base64url("group")
            )],
            |r| r.get(0),
        )?;
        assert_eq!(state, after);
        merged.check_integrity()?;
        drop((merged, source, local, bad));
        for path in [root, local_root, bad_root] {
            std::fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

#[test]
fn backup_merge_cannot_replace_a_later_live_head_with_a_stale_owner_transfer()
-> Result<(), StorageError> {
    let (owner_root, owner, actor) = person("owner", "phone", 10)?;
    let (_, peer_branch, peer) = person("peer", "phone", 20)?;
    let initial = create(&owner_root, &owner, &actor)?;
    let joined = advance_group_state(
        &owner_root,
        &owner,
        &actor,
        &initial,
        GroupStateChange::Add { member: peer.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let acceptance = ramflux_crypto::accept_group_transfer(
        &peer_branch,
        &peer,
        &joined,
        &ramflux_protocol::encode_base64url([77; 32]),
        joined.snapshot().issued_at,
    )?;
    let transfer = advance_group_state(
        &owner_root,
        &owner,
        &actor,
        &joined,
        GroupStateChange::TransferOwnership {
            creator: peer.clone(),
            acceptance: Box::new(acceptance),
        },
    )?;
    let mut live = joined;
    for index in 0..3 {
        live = advance_group_state(
            &owner_root,
            &owner,
            &actor,
            &live,
            GroupStateChange::SetName { name: format!("Current-{index}") },
        )?;
    }
    let (root, source) = test_db("backup-stale-transfer-source")?;
    let (local_root, local) = test_db("backup-stale-transfer-local")?;
    source.commit_shared_group_state(&transfer, &actor)?;
    local.commit_shared_group_state(&live, &actor)?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let target = local_root.join("merged.db");
    let saved = local.write_backup_snapshot(&target)?;
    let mut merged = crate::BackupDatabase::open(&target, &saved.key)?;
    merged.merge_backup_with_group_actor(&incoming, &snapshot.key, Some(&actor), || Ok(()))?;
    let selected: Vec<u8> = merged.db.query_row(
        "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
        rusqlite::params![format!("group-state/{}", ramflux_protocol::encode_base64url("group"))],
        |r| r.get(0),
    )?;
    assert_eq!(
        serde_json::from_slice::<ramflux_protocol::GroupStateSnapshot>(&selected)?,
        *live.snapshot()
    );
    let role: String = merged.db.query_row(
        "SELECT role FROM group_projection WHERE group_id='group'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(role, "owner");
    drop((merged, source, local));
    for path in [root, local_root] {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn renamed_branch(
    root: &ramflux_crypto::IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    mut state: VerifiedGroupState,
    prefix: &str,
    count: usize,
) -> Result<VerifiedGroupState, StorageError> {
    for index in 0..count {
        state = advance_group_state(
            root,
            branch,
            actor,
            &state,
            GroupStateChange::SetName { name: format!("{prefix}-{index}") },
        )?;
    }
    Ok(state)
}
