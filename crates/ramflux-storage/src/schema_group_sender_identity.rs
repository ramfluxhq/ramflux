// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical name-only group counters never satisfy root-qualified replay lookups.
use crate::{StorageError, database::Connection};
pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS group_sender_identity_upgrade(singleton INTEGER PRIMARY KEY CHECK(singleton=1))")?;
    if connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM group_sender_identity_upgrade)",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(());
    }
    let transaction = connection.immediate_transaction()?;
    connection.execute_batch("CREATE TABLE IF NOT EXISTS legacy_group_sender_key_counter_seen AS SELECT * FROM group_sender_key_counter_seen WHERE 0; INSERT INTO legacy_group_sender_key_counter_seen SELECT * FROM group_sender_key_counter_seen; DELETE FROM group_sender_key_counter_seen; UPDATE projection_checkpoint SET projection_name='legacy/group_sender_key/'||projection_name WHERE substr(projection_name,1,17)='group_sender_key:'; INSERT INTO group_sender_identity_upgrade VALUES(1);")?;
    transaction.commit()?;
    Ok(())
}
