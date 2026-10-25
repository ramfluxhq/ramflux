// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed group-authorized roster claims, separate from device-set authentication.
use crate::{StorageError, database::Connection};

pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS shared_group_member_projection (
        group_id TEXT NOT NULL,
        root_commitment TEXT NOT NULL,
        device_id TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        declared_signing_key TEXT NOT NULL,
        current_signing_key TEXT NOT NULL,
        target_delivery_id TEXT NOT NULL,
        role TEXT NOT NULL,
        joined_epoch INTEGER NOT NULL,
        active INTEGER NOT NULL,
        PRIMARY KEY(group_id,root_commitment,device_id)
    );
    CREATE INDEX IF NOT EXISTS shared_group_member_discovery
        ON shared_group_member_projection(principal_id,device_id,root_commitment) WHERE active=1;",
    )?;
    Ok(())
}
