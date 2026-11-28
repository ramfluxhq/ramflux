// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed, input-qualified message deletion restrictions for restore candidates.
use rusqlite::Connection;

pub(super) fn prepare(db: &Connection) -> rusqlite::Result<()> {
    // Capture before union. Incoming restrictions never become target authority.
    db.execute_batch("CREATE TABLE main.backup_message_delete(side TEXT NOT NULL,message_id TEXT NOT NULL,PRIMARY KEY(side,message_id));")?;
    for schema in ["main", "incoming"] {
        db.execute_batch(&format!("INSERT INTO main.backup_message_delete SELECT '{schema}',message_id FROM {schema}.message_tombstone_projection UNION SELECT '{schema}',message_id FROM {schema}.direct_message_projection WHERE deleted=1;"))?;
    }
    Ok(())
}

pub(super) fn query(schema: &str) -> String {
    format!(
        "SELECT EXISTS(SELECT 1 FROM main.backup_message_delete WHERE side='{schema}' AND message_id=?1)"
    )
}
