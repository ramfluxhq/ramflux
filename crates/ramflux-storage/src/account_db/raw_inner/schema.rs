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
    copy_kind TEXT NOT NULL CHECK(copy_kind IN ('outer_inner','nested_group','history_container','source_evidence')),
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
    // Copy every provenance value before clearing any owner. Each statement is atomic and
    // idempotent: a failed clear leaves both copies intact and a failed copy leaves the owner.
    // Open fails on either error; retry resumes without reassigning an existing copy's metadata.
    // A live caller's managed transaction also encloses both statements.
    db.execute_batch("UPDATE raw_inner_copy SET copy_metadata=(SELECT metadata FROM raw_inner_owner o WHERE o.owner_id=raw_inner_copy.owner_id) WHERE length(copy_metadata)=0 AND EXISTS(SELECT 1 FROM raw_inner_owner o WHERE o.owner_id=raw_inner_copy.owner_id AND length(o.metadata)>0)")?;
    db.execute_batch("UPDATE raw_inner_owner SET metadata=x'' WHERE length(metadata)>0")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_metadata_transfer_resumes_after_owner_clear_failure_without_reassigning_copies()
    -> Result<(), Box<dyn std::error::Error>> {
        let db = Connection::open_in_memory()?;
        install(&db)?;
        for (owner, metadata) in [("owner-a", "provenance-a"), ("owner-b", "provenance-b")] {
            db.execute(
                "INSERT INTO raw_inner_owner VALUES(?1,'root',?2)",
                rusqlite::params![owner, metadata.as_bytes()],
            )?;
        }
        for (id, owner, metadata) in [
            ("a-old", "owner-a", ""),
            ("a-new", "owner-a", "independent-copy"),
            ("b-old", "owner-b", ""),
        ] {
            db.execute("INSERT INTO raw_inner_copy(copy_id,owner_id,copy_kind,raw_digest,raw_bytes,copy_metadata) VALUES(?1,?2,'outer_inner',zeroblob(32),x'01',?3)",rusqlite::params![id,owner,metadata.as_bytes()])?;
        }
        db.execute_batch("CREATE TRIGGER fail_owner_clear BEFORE UPDATE OF metadata ON raw_inner_owner WHEN length(OLD.metadata)>0 BEGIN SELECT RAISE(ABORT,'injected owner clear failure'); END;")?;
        assert!(
            matches!(install(&db), Err(rusqlite::Error::SqliteFailure(_,Some(message))) if message=="injected owner clear failure")
        );
        let copies = || -> rusqlite::Result<Vec<(String, Vec<u8>)>> {
            db.prepare("SELECT copy_id,copy_metadata FROM raw_inner_copy ORDER BY copy_id")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        };
        let expected = vec![
            ("a-new".to_owned(), b"independent-copy".to_vec()),
            ("a-old".to_owned(), b"provenance-a".to_vec()),
            ("b-old".to_owned(), b"provenance-b".to_vec()),
        ];
        assert_eq!(copies()?, expected, "copy transfer must finish before owner clear");
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM raw_inner_owner WHERE length(metadata)>0",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            2
        );
        db.execute_batch("DROP TRIGGER fail_owner_clear")?;
        install(&db)?;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM raw_inner_owner WHERE length(metadata)>0",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            0
        );
        assert_eq!(copies()?, expected);
        install(&db)?;
        assert_eq!(copies()?, expected);
        Ok(())
    }
}
