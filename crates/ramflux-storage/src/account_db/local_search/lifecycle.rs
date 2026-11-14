// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Privacy mutations and archives never retain or import search derivatives.
use rusqlite::Connection;

pub(crate) fn is_namespace(name: &str) -> bool {
    name.get(.."local_search_".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("local_search_"))
}

pub(crate) fn purge_message(db: &Connection, message: &str) -> rusqlite::Result<()> {
    if !super::schema::exists(db)? {
        return Ok(());
    }
    db.execute("DELETE FROM local_search_doc WHERE message_id=?1", [message])?;
    db.execute("DELETE FROM local_search_dirty WHERE kind=1 AND source_key=?1", [message])?;
    db.execute("UPDATE local_search_state SET revision=revision+1,canonical_revision=canonical_revision+1,coverage='lagging'",[])?;
    Ok(())
}

pub(crate) fn retire_locator(db: &Connection, locator: &str) -> rusqlite::Result<()> {
    if super::schema::exists(db)? {
        db.execute("DELETE FROM local_search_doc WHERE doc_id=CAST(?1 AS INTEGER)", [locator])?;
    }
    Ok(())
}

/// Strips every table/shadow/trigger in the namespace, including unknown cache revisions.
/// The caller owns a private encrypted candidate and compacts it before publication.
pub(crate) fn strip(db: &Connection) -> rusqlite::Result<bool> {
    let count:u64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE lower(name) GLOB 'local_search_*' AND type IN('table','trigger','index','view')",[],|row|row.get(0))?;
    if count == 0 {
        strip_footprints(db)?;
        return Ok(false);
    }
    if count > 128 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    for _ in 0..128 {
        let mut statement=db.prepare("SELECT CASE WHEN length(name)<=1024 THEN name ELSE NULL END,type FROM sqlite_schema WHERE lower(name) GLOB 'local_search_*' AND type IN('table','trigger','index','view') ORDER BY CASE WHEN type='trigger' THEN 0 WHEN type='view' THEN 1 WHEN type='index' THEN 2 WHEN sql LIKE 'CREATE VIRTUAL TABLE%' THEN 3 ELSE 4 END,name LIMIT 1")?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else { break };
        let name: Option<String> = row.get(0)?;
        let name = name.ok_or(rusqlite::Error::InvalidQuery)?;
        let kind: String = row.get(1)?;
        drop(rows);
        drop(statement);
        let name = name.replace('"', "\"\"");
        let command = match kind.as_str() {
            "trigger" => "DROP TRIGGER",
            "index" => "DROP INDEX",
            "view" => "DROP VIEW",
            _ => "DROP TABLE",
        };
        db.execute_batch(&format!("{command} IF EXISTS \"{name}\";"))?;
    }
    let remaining:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'local_search_*' AND type IN('table','trigger','index','view'))",[],|row|row.get(0))?;
    if remaining {
        return Err(rusqlite::Error::InvalidQuery);
    }
    strip_footprints(db)?;
    // A private archive copy may pass through more than one sanitizer before publication.
    // Carry compaction responsibility across those copies, never archive search authority.
    db.execute_batch("CREATE TABLE local_search_compaction_pending(singleton INTEGER PRIMARY KEY CHECK(singleton=1)); INSERT INTO local_search_compaction_pending VALUES(1);")?;
    Ok(true)
}

fn strip_footprints(db: &Connection) -> rusqlite::Result<()> {
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='message_footprint' COLLATE NOCASE)",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        db.execute("DELETE FROM message_footprint WHERE lower(kind) GLOB 'local_search_*'", [])?;
    }
    Ok(())
}

pub(crate) use super::compact::compact;
