// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-qualified group control replay; historical name-only rows never grant a new identity.
use crate::{StorageError, database::Connection};
pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS root_group_control_event_seen (
            group_id TEXT NOT NULL,
            actor_identity TEXT NOT NULL,
            event_id TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            actor_device_id TEXT NOT NULL,
            target_member_id TEXT NOT NULL,
            previous_epoch INTEGER NOT NULL,
            new_group_epoch INTEGER NOT NULL,
            applied_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, actor_identity, event_id)
        );
        CREATE TABLE IF NOT EXISTS root_group_invite_identity (
            group_id TEXT NOT NULL,
            invite_id TEXT NOT NULL,
            expected_root TEXT NOT NULL,
            device_name TEXT NOT NULL,
            PRIMARY KEY(group_id, invite_id)
        );",
    )?;
    Ok(())
}
