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
