// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable tables for registered raw-inner copies and private evidence.

use rusqlite::Connection;

pub(crate) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS raw_inner_owner(
    owner_id TEXT PRIMARY KEY,
    source_anchor TEXT NOT NULL,
    metadata BLOB NOT NULL CHECK(length(metadata)<=4096)
);
CREATE INDEX IF NOT EXISTS raw_inner_owner_source ON raw_inner_owner(source_anchor,owner_id);
CREATE TABLE IF NOT EXISTS raw_inner_copy(
    copy_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    copy_kind TEXT NOT NULL CHECK(copy_kind IN ('outer_inner','nested_group','history_container')),
    raw_digest BLOB NOT NULL CHECK(length(raw_digest)=32),
    raw_bytes BLOB NOT NULL,
    FOREIGN KEY(owner_id) REFERENCES raw_inner_owner(owner_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS raw_inner_copy_owner ON raw_inner_copy(owner_id,copy_id);
CREATE TRIGGER IF NOT EXISTS raw_inner_owner_cleanup AFTER DELETE ON raw_inner_copy BEGIN
    DELETE FROM raw_inner_owner WHERE owner_id=OLD.owner_id
      AND NOT EXISTS(SELECT 1 FROM raw_inner_copy WHERE owner_id=OLD.owner_id);
END;
CREATE TABLE IF NOT EXISTS raw_inner_evidence(
    message_id TEXT PRIMARY KEY,
    provenance BLOB NOT NULL CHECK(length(provenance)<=4096),
    report_opening BLOB NOT NULL CHECK(length(report_opening)<=524252)
);
";

pub(crate) fn install(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    Ok(())
}
