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
    attempted_decoder TEXT NOT NULL DEFAULT '',
    copy_metadata BLOB NOT NULL DEFAULT x'' CHECK(length(copy_metadata)<=4096),
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
    let has_attempt:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('raw_inner_copy') WHERE name='attempted_decoder')",[],|row|row.get(0))?;
    if !has_attempt {
        db.execute_batch(
            "ALTER TABLE raw_inner_copy ADD COLUMN attempted_decoder TEXT NOT NULL DEFAULT ''",
        )?;
    }
    let has_metadata:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('raw_inner_copy') WHERE name='copy_metadata')",[],|row|row.get(0))?;
    if !has_metadata {
        db.execute_batch("ALTER TABLE raw_inner_copy ADD COLUMN copy_metadata BLOB NOT NULL DEFAULT x'' CHECK(length(copy_metadata)<=4096)")?;
    }
    // An interrupted additive upgrade resumes this transfer on the next open. The original
    // owner metadata is never reassigned to a different received copy.
    let result=db.execute_batch("SAVEPOINT raw_copy_metadata; UPDATE raw_inner_copy SET copy_metadata=(SELECT metadata FROM raw_inner_owner o WHERE o.owner_id=raw_inner_copy.owner_id) WHERE length(copy_metadata)=0 AND EXISTS(SELECT 1 FROM raw_inner_owner o WHERE o.owner_id=raw_inner_copy.owner_id AND length(o.metadata)>0); UPDATE raw_inner_owner SET metadata=x'' WHERE length(metadata)>0; RELEASE raw_copy_metadata;");
    if result.is_err() {
        let _ = db.execute_batch("ROLLBACK TO raw_copy_metadata; RELEASE raw_copy_metadata;");
    }
    result?;
    Ok(())
}
