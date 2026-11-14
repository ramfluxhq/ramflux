// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private snapshot compaction preserves rowid-addressed erasure ownership by stable keys.
use rusqlite::{Connection, params};
use std::fmt::Write as _;
struct LocatorTable {
    kind: String,
    table: String,
    keys: Vec<String>,
    lookup: bool,
}
fn identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn exists(db: &Connection, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )
}

/// The caller owns a private, unpublished, quiescent encrypted candidate with search stripped.
/// Mapping work contains only IDs, is encrypted in main, and is removed before publication.
pub(crate) fn compact(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("PRAGMA temp_store=MEMORY;")?;
    if !exists(db, "message_footprint")? {
        return db.execute_batch("VACUUM; DROP TABLE IF EXISTS local_search_compaction_pending;");
    }
    let tables = locator_tables(db)?;
    db.execute_batch("CREATE TABLE local_search_compaction_map(kind TEXT NOT NULL,message_id TEXT NOT NULL,keys TEXT NOT NULL,PRIMARY KEY(kind,message_id,keys));")?;
    for (index, table) in tables.iter().enumerate() {
        capture(db, table)?;
        if table.lookup {
            db.execute_batch(&format!(
                "CREATE INDEX {} ON {}({});",
                identifier(&format!("local_search_compaction_lookup_{index}")),
                identifier(&table.table),
                table.keys.iter().map(|key| identifier(key)).collect::<Vec<_>>().join(",")
            ))?;
        }
    }
    // VACUUM copies table contents but may renumber implicit rowids. Never leave old locators.
    db.execute_batch("VACUUM; BEGIN IMMEDIATE;")?;
    let rewritten = (|| {
        for (index, table) in tables.iter().enumerate() {
            relocate(db, table)?;
            if table.lookup {
                db.execute_batch(&format!(
                    "DROP INDEX {};",
                    identifier(&format!("local_search_compaction_lookup_{index}"))
                ))?;
            }
        }
        db.execute_batch("DROP TABLE local_search_compaction_map; DROP TABLE IF EXISTS local_search_compaction_pending; COMMIT;")
    })();
    if rewritten.is_err() {
        let _ = db.execute_batch("ROLLBACK");
    }
    rewritten
}
fn locator_tables(db: &Connection) -> rusqlite::Result<Vec<LocatorTable>> {
    let mut statement=db.prepare("SELECT DISTINCT CASE WHEN length(CAST(kind AS BLOB))<=128 THEN kind END FROM message_footprint ORDER BY kind LIMIT 257")?;
    let kinds = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if kinds.len() > 256 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut output = Vec::new();
    for kind in kinds {
        let table = match kind.as_str() {
            "archived_actor" => "backup_archived_actor_state",
            "archived_event" => "backup_archived_local_event",
            // Only these footprint producers use implicit rowids (see footprint/schema.rs).
            // In particular raw_inner_evidence uses a message ID despite matching a table name.
            "runtime_message_content"
            | "rejected_inbox_projection"
            | "conversation_unread_marker"
            | "group_message_tombstone_projection"
            | "message_projection"
            | "receipt_projection"
            | "group_pending_undecrypted"
            | "root_group_sender_key_counter_seen"
            | "group_sender_key_counter_seen"
            | "contact_message_request"
            | "conversation_read_state"
            | "conversation_delivery_state" => kind.as_str(),
            "raw_envelope_log:envelope_id"
            | "outbox_queue:envelope_id"
            | "ack_state:envelope_id"
            | "nack_state:envelope_id"
            | "cursor_checkpoint:last_envelope_id"
            | "device_inbox_cursor:last_envelope_id"
            | "event_causal_dependency:event_id"
            | "event_causal_dependency:depends_on_event_id"
            | "projection_checkpoint:last_event_id" => {
                kind.split(':').next().ok_or(rusqlite::Error::InvalidQuery)?
            }
            _ => continue,
        };
        if !exists(db, table)? {
            continue;
        }
        let mut columns =
            db.prepare("SELECT name,pk FROM pragma_table_info(?1) ORDER BY pk LIMIT 129")?;
        let mut keys = Vec::new();
        let mut total = 0;
        for row in
            columns.query_map([table], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        {
            let (name, primary) = row?;
            total += 1;
            if total > 128 || name.len() > 128 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if primary > 0 {
                keys.push(name);
            }
        }
        // Archived event variants share the same logical source/event ownership. Retain the
        // union of owners for every variant rather than assigning an arbitrary renumbered row.
        let lookup = keys.is_empty() && table == "backup_archived_local_event";
        if lookup {
            keys = vec!["source".into(), "event_id".into()];
        }
        if keys.is_empty() || keys.len() > 16 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        output.push(LocatorTable { kind: kind.clone(), table: table.into(), keys, lookup });
    }
    Ok(output)
}
fn key_expression(table: &LocatorTable) -> String {
    let parts =
        table.keys.iter().map(|key| format!("t.{}", identifier(key))).collect::<Vec<_>>().join(",");
    format!("json_array({parts})")
}
fn capture(db: &Connection, table: &LocatorTable) -> rusqlite::Result<()> {
    let keys = key_expression(table);
    let sql = format!(
        "INSERT OR IGNORE INTO local_search_compaction_map SELECT f.kind,f.message_id,CASE WHEN length(CAST({keys} AS BLOB))<=8192 THEN {keys} END FROM message_footprint f CROSS JOIN {} t ON t.rowid=CAST(f.locator AS INTEGER) AND CAST(t.rowid AS TEXT)=f.locator WHERE f.kind=?1",
        identifier(&table.table)
    );
    db.execute(&sql, [&table.kind])?;
    Ok(())
}
fn relocate(db: &Connection, table: &LocatorTable) -> rusqlite::Result<()> {
    let mut predicate = String::new();
    for (index, key) in table.keys.iter().enumerate() {
        if index > 0 {
            predicate.push_str(" AND ");
        }
        write!(predicate, "t.{}=json_extract(m.keys,'$[{index}]')", identifier(key))
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
    }
    db.execute("DELETE FROM message_footprint WHERE kind=?1", [&table.kind])?;
    db.execute(&format!("INSERT OR IGNORE INTO message_footprint SELECT m.message_id,m.kind,CAST(t.rowid AS TEXT) FROM local_search_compaction_map m CROSS JOIN {} t ON {predicate} WHERE m.kind=?1",identifier(&table.table)),[&table.kind])?;
    let missing:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM local_search_compaction_map m WHERE m.kind=?1 AND NOT EXISTS(SELECT 1 FROM {} t JOIN message_footprint f ON f.message_id=m.message_id AND f.kind=m.kind AND f.locator=CAST(t.rowid AS TEXT) WHERE {predicate}))",identifier(&table.table)),params![table.kind],|r|r.get(0))?;
    if missing {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
