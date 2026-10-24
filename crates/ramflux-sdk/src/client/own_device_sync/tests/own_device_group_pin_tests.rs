// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restoring a same-root sibling keeps source and target device pins distinct.
use super::*;
#[test]
fn own_device_history_restores_member_pins_before_sender_keys_without_conflating_siblings()
-> Result<(), SdkError> {
    let (source, source_root) =
        client_with_account("group-pins-source", "principal_sync", "source_device_sync")?;
    let (mut target, target_root) =
        client_with_account("group-pins-target", "principal_sync", "target_device_sync")?;
    target.create_device_branch("principal_sync", "target_device_sync", 1, [0x53; 32]);
    source.create_group("sync_group", "source_device_sync")?;
    let encrypted = source.encrypt_group_message(
        "sync_group",
        "source_device_sync",
        b"approved group history",
    )?;
    source.send_direct_message("sync_group", "group_history", "source_device_sync", &encrypted)?;
    let history = source.own_device_history_bundle(
        "principal_sync",
        "source_device_sync",
        "target_device_sync",
        "snapshot_sync",
    )?;
    let result = target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert_eq!(result.imported_sender_keys, 1);
    assert_eq!(result.imported_messages, 1);
    let source_public = ramflux_protocol::encode_base64url(
        source
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    let target_public = ramflux_protocol::encode_base64url(
        target
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    assert_ne!(source_public, target_public);
    assert_eq!(
        target.account_db()?.group_member_device_key("sync_group", "source_device_sync")?,
        Some(source_public)
    );
    assert_eq!(
        target.account_db()?.group_member_device_key("sync_group", "target_device_sync")?,
        Some(target_public)
    );
    assert_eq!(
        target.decrypt_group_message("sync_group", "group_history")?,
        b"approved group history"
    );
    drop(source);
    drop(target);
    std::fs::remove_dir_all(source_root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}

#[test]
fn conflicting_own_device_member_pins_skip_unsafe_history_and_preserve_local_membership()
-> Result<(), SdkError> {
    let (source, source_root) =
        client_with_account("group-pin-conflict-source", "principal_sync", "source_device_sync")?;
    let (mut target, target_root) =
        client_with_account("group-pin-conflict-target", "principal_sync", "target_device_sync")?;
    target.create_device_branch("principal_sync", "target_device_sync", 1, [0x53; 32]);
    source.create_group("sync_group", "source_device_sync")?;
    let encrypted =
        source.encrypt_group_message("sync_group", "source_device_sync", b"snapshot message")?;
    source.send_direct_message(
        "sync_group",
        "snapshot_message",
        "source_device_sync",
        &encrypted,
    )?;
    let history = source.own_device_history_bundle(
        "principal_sync",
        "source_device_sync",
        "target_device_sync",
        "snapshot_sync",
    )?;
    let db = target.account_db()?;
    db.upsert_group_local_membership_snapshot(
        "sync_group",
        5,
        64,
        "all",
        "target_device_sync",
        "owner",
        1,
    )?;
    db.upsert_group_member_snapshot("sync_group", "source_device_sync", "member", 1)?;
    let existing_key = ramflux_protocol::encode_base64url(
        target
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    db.persist_group_member_device_key("sync_group", "source_device_sync", &existing_key)?;
    source.send_direct_message("dm", "safe-direct", "source_device_sync", b"safe")?;
    let mut history = history;
    history.groups[0].group_epoch = 5;
    history.messages.extend(source.direct_messages("dm")?);
    let imported = target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert_eq!(imported.imported_messages, 1);
    assert!(target.direct_message_by_id("safe-direct")?.is_some());
    assert_ne!(
        db.list_actor_states::<serde_json::Value>("own-device/restore-skip/")?,
        Vec::<serde_json::Value>::new()
    );
    assert_eq!(target.group_state("sync_group")?.group_epoch, 5);
    assert_eq!(db.group_member_device_key("sync_group", "source_device_sync")?, Some(existing_key));
    assert!(target.direct_message_by_id("snapshot_message")?.is_none());
    drop(source);
    drop(target);
    std::fs::remove_dir_all(source_root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}
