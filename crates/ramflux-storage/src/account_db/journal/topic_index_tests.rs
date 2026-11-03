// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Upgrade plans remain indexed and failed runtime schema changes roll back index replacement.
use super::*;
use crate::{AccountDbKey, AccountIndex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn legacy_indexes(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute_batch(
        "DROP INDEX IF EXISTS runtime_journal_topic_seq;
        CREATE INDEX runtime_journal_topic ON runtime_journal(topic);
        CREATE INDEX runtime_journal_contact_topic ON runtime_journal(topic);",
    )?;
    Ok(())
}

#[test]
fn legacy_journal_upgrade_installs_topic_sequence_plan_idempotently() -> TestResult {
    let (root, db) = crate::tests::test_db("journal-topic-upgrade")?;
    legacy_indexes(&db)?;
    db.connection.execute_batch("WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
        INSERT INTO runtime_journal(at,topic,body_json,source_key) SELECT n,'conversation.changed',x'7b7d','unrelated:'||n FROM rows;
        UPDATE runtime_journal_bounds SET head_seq=10000;")?;
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    for _ in 0..2 {
        let mut plan =
            db.connection.prepare(&format!("EXPLAIN QUERY PLAN {LATEST_TOPIC_EVENT_SQL}"))?;
        let details = plan
            .query_map(params!["sync.status"], |r| r.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .join(" ");
        assert!(details.contains("runtime_journal_topic_seq"), "{details}");
        assert!(!details.contains("SCAN runtime_journal"), "{details}");
        assert!(!details.contains("TEMP B-TREE"), "{details}");
        assert!(db.latest_journal_event("sync.status")?.is_none());
        assert_eq!(
            db.latest_journal_event("conversation.changed")?.ok_or("missing event")?.seq,
            10000
        );
        let mut info = db.connection.prepare("PRAGMA index_info('runtime_journal_topic_seq')")?;
        let columns =
            info.query_map([], |r| r.get::<_, String>(2))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(columns, ["topic", "seq"]);
        assert_eq!(db.journal_bounds()?.head_seq, 10000);
        db.enable_runtime()?;
    }
    // Existing writer INSERT shapes automatically maintain the new SQLite index.
    db.connection.execute_batch("INSERT INTO runtime_journal(at,topic,body_json,source_key) VALUES(8,'sync.status',x'7b7d','legacy-writer');")?;
    assert_eq!(db.latest_journal_event("sync.status")?.ok_or("legacy write")?.seq, 10001);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn journal_index_replacement_rolls_back_when_later_schema_installation_fails() -> TestResult {
    let (root, db) = crate::tests::test_db("journal-topic-rollback")?;
    legacy_indexes(&db)?;
    // A later AFTER-trigger install must fail on this deliberately invalid legacy view.
    db.connection.execute_batch(
        "DROP TABLE direct_message_projection;
        CREATE VIEW direct_message_projection AS SELECT 0 AS deleted,'' AS message_id;",
    )?;
    assert!(db.install_journal_schema().is_err());
    assert_eq!(db.connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('runtime_journal_topic','runtime_journal_contact_topic')",
        [], |r| r.get::<_,u64>(0))?, 2);
    assert_eq!(db.connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='runtime_journal_topic_seq'",
        [], |r| r.get::<_,u64>(0))?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
