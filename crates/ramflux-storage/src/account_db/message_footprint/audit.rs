// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-and-audit scan for envelope copies that carry no ownership footprint.
use rusqlite::{Connection, params};
use serde_json::Value;

/// (table, locator SQL, footprint kind, JSON column). Absent tables are skipped.
const STORES: [(&str, &str, &str, &str); 4] = [
    ("runtime_actor_state", "t.state_kind", "actor", "state_json"),
    ("local_event_log", "t.event_id", "event", "event_body"),
    ("backup_archived_actor_state", "CAST(t.rowid AS TEXT)", "archived_actor", "state_json"),
    ("backup_archived_local_event", "CAST(t.rowid AS TEXT)", "archived_event", "event_body"),
];

/// Lists up to `limit` rows (`table:locator`) holding a complete envelope at a fixed path
/// without a `message_footprint` row at their locator.
///
/// # Errors
/// Returns SQLite errors.
pub(crate) fn unregistered_envelope_copies(
    db: &Connection,
    limit: usize,
) -> rusqlite::Result<Vec<String>> {
    let mut found = Vec::new();
    if limit == 0 {
        return Ok(found);
    }
    for (table, locator, kind, column) in STORES {
        if !super::schema::exists(db, table)? {
            continue;
        }
        let mut query = db.prepare(&format!(
            "SELECT {locator},CAST(t.{column} AS BLOB) FROM {table} t WHERE NOT EXISTS(
               SELECT 1 FROM message_footprint f WHERE f.kind=?1 AND f.locator={locator})"
        ))?;
        let rows = query.query_map(params![kind], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (key, body) = row?;
            let holds = serde_json::from_slice::<Value>(&body)
                .is_ok_and(|value| super::value_holds_envelope(&value));
            if holds {
                found.push(format!("{table}:{key}"));
                if found.len() >= limit {
                    return Ok(found);
                }
            }
        }
    }
    Ok(found)
}
