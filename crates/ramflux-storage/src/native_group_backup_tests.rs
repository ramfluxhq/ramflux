// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native data-only group restore preserves verified snapshots without certifying a local actor.
use super::{create, person, test_db};
use crate::{AccountBackupSnapshot, AccountDb, BackupDatabase, StorageError};
use ramflux_protocol::{GroupStateChange, SharedGroupRole};
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn copies(
    source: &AccountDb,
    target: &AccountDb,
    root: &Path,
) -> TestResult<(BackupDatabase, AccountBackupSnapshot, PathBuf)> {
    let incoming = root.join("incoming.db");
    let archive = source.write_backup_snapshot(&incoming)?;
    BackupDatabase::open(&incoming, &archive.key)?.sanitize_native_backup()?;
    let output = root.join("merged.db");
    let local = target.write_backup_snapshot(&output)?;
    Ok((BackupDatabase::open(&output, &local.key)?, archive, incoming))
}

#[test]
fn native_backup_fresh_group_restores_state_members_and_removal_floors() -> TestResult {
    let (root, source) = test_db("native-backup-group-source")?;
    let (target_root, target) = test_db("native-backup-group-target")?;
    let (identity, branch, actor) = person("owner", "phone", 10)?;
    let (_, _, member) = person("removed", "phone", 20)?;
    let initial = create(&identity, &branch, &actor)?;
    let joined = ramflux_crypto::advance_group_state(
        &identity,
        &branch,
        &actor,
        &initial,
        GroupStateChange::Add { member: member.identity.clone(), role: SharedGroupRole::Member },
    )?;
    let removed = ramflux_crypto::advance_group_state(
        &identity,
        &branch,
        &actor,
        &joined,
        GroupStateChange::Remove {
            root_commitment: member.identity.root_commitment.clone(),
            device_id: member.identity.device_id.clone(),
        },
    )?;
    for state in [&initial, &joined, &removed] {
        source.commit_shared_group_state(state, &actor)?;
    }
    let (mut merged, archive, incoming) = copies(&source, &target, &root)?;
    merged.merge_native_backup(&incoming, &archive.key, || Ok(()))?;
    let bytes: Vec<u8> = merged.db.query_row(
        "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
        [format!("group-state/{}", ramflux_protocol::encode_base64url("group"))],
        |r| r.get(0),
    )?;
    assert_eq!(
        serde_json::from_slice::<ramflux_protocol::GroupStateSnapshot>(&bytes)?,
        *removed.snapshot()
    );
    let (epoch, members, floors, local_actor): (u64, u64, u64, u64) = merged.db.query_row(
        "SELECT group_epoch,(SELECT count(*) FROM shared_group_member_projection WHERE group_id='group' AND active=1),(SELECT count(*) FROM shared_group_removal_floor WHERE group_id='group'),(SELECT count(*) FROM runtime_actor_state WHERE state_kind='directory/group-local/group') FROM group_projection WHERE group_id='group'",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    assert_eq!(epoch, removed.view().epoch);
    assert_eq!(members, 1);
    assert!(floors > 0);
    assert_eq!(local_actor, 0, "data restore must not invent a local actor");
    merged.check_integrity()?;
    drop((merged, source, target));
    std::fs::remove_dir_all(root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}

#[test]
fn native_backup_differing_group_genesis_is_still_rejected() -> TestResult {
    let (root, source) = test_db("native-backup-foreign-source")?;
    let (target_root, target) = test_db("native-backup-foreign-target")?;
    let (identity, branch, actor) = person("source", "phone", 10)?;
    let (other_identity, other_branch, other_actor) = person("target", "phone", 20)?;
    let incoming_state = create(&identity, &branch, &actor)?;
    let local_state = create(&other_identity, &other_branch, &other_actor)?;
    source.commit_shared_group_state(&incoming_state, &actor)?;
    target.commit_shared_group_state(&local_state, &other_actor)?;
    let (mut merged, archive, incoming) = copies(&source, &target, &root)?;
    assert!(matches!(
        merged.merge_native_backup(&incoming, &archive.key, || Ok(())),
        Err(StorageError::AuthorizationRejected)
    ));
    let bytes: Vec<u8> = merged.db.query_row(
        "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
        [format!("group-state/{}", ramflux_protocol::encode_base64url("group"))],
        |r| r.get(0),
    )?;
    assert_eq!(
        serde_json::from_slice::<ramflux_protocol::GroupStateSnapshot>(&bytes)?,
        *local_state.snapshot()
    );
    drop((merged, source, target));
    std::fs::remove_dir_all(root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}

#[test]
fn non_native_backup_with_a_group_still_requires_a_local_actor() -> TestResult {
    let (root, source) = test_db("full-backup-group-source")?;
    let (target_root, target) = test_db("full-backup-group-target")?;
    let (identity, branch, actor) = person("owner", "phone", 10)?;
    source.commit_shared_group_state(&create(&identity, &branch, &actor)?, &actor)?;
    let (mut merged, archive, incoming) = copies(&source, &target, &root)?;
    assert!(matches!(
        merged.merge_backup(&incoming, &archive.key, || Ok(())),
        Err(StorageError::AuthorizationRejected)
    ));
    let groups: u64 =
        merged.db.query_row("SELECT count(*) FROM group_projection", [], |r| r.get(0))?;
    assert_eq!(groups, 0);
    drop((merged, source, target));
    std::fs::remove_dir_all(root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}
