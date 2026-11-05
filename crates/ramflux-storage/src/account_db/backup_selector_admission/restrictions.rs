// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed, input-qualified group deletion restrictions for restore candidates.
use rusqlite::Connection;

pub(super) fn prepare(db: &Connection) -> rusqlite::Result<()> {
    // Capture before union. Incoming restrictions never become target authority.
    db.execute_batch("CREATE TABLE main.backup_group_delete(side TEXT NOT NULL,message_id TEXT NOT NULL,copy_id TEXT NOT NULL,PRIMARY KEY(side,message_id,copy_id)); CREATE INDEX main.backup_group_delete_copy ON backup_group_delete(side,copy_id);")?;
    for schema in ["main", "incoming"] {
        db.execute_batch(&format!("INSERT INTO main.backup_group_delete SELECT '{schema}',message_id,'group:'||group_id||':'||message_id FROM {schema}.group_message_tombstone_projection;"))?;
    }
    Ok(())
}

pub(super) fn queries(schema: &str, bindings: &str) -> [String; 2] {
    [
        format!(
            "SELECT EXISTS(SELECT 1 FROM {schema}.direct_message_projection WHERE message_id=?1 AND deleted=1) OR EXISTS(SELECT 1 FROM {schema}.message_tombstone_projection WHERE message_id=?1) OR EXISTS(SELECT 1 FROM main.backup_group_delete WHERE side='{schema}' AND message_id=?1)"
        ),
        format!(
            "SELECT EXISTS(SELECT 1 FROM ({bindings}) b WHERE b.message_id=?1 AND EXISTS(SELECT 1 FROM main.backup_group_delete t WHERE t.side='{schema}' AND t.copy_id=b.copy_id))"
        ),
    ]
}
