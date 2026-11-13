// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real keyed `AccountDb` fixtures; replacement work stays paused across privacy mutations.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, DirectMessageWrite, MessageMetadata};
use rusqlite::params;
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    directory: tempfile::TempDir,
    db: AccountDb,
    activation: SearchActivation,
    watch: std::sync::Arc<SearchWatch>,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let index = AccountIndex::open(directory.path())?;
        index.create_account("account", "principal")?;
        let db = AccountDb::open(&index, "account", &AccountDbKey::from_bytes([42; 32]))?;
        db.enable_runtime()?;
        let activation = SearchActivation::testing();
        let watch = db.search_prepare(&activation)?;
        Ok(Self { directory, db, activation, watch })
    }
    fn source(id: &str, text: &str) -> SearchSource {
        SearchSource {
            kind: SearchKind::Message,
            source_ref: id.into(),
            source_key: id.into(),
            conversation_id: "thread".into(),
            message_id: Some(id.into()),
            revision: 1,
            timestamp: 1,
            text: text.into(),
            dependencies: vec![SearchDependency {
                table: "runtime_message_content".into(),
                key: id.into(),
            }],
        }
    }
    fn insert(&self, id: &str, text: &str) -> TestResult {
        self.db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "thread",
            message_id: id,
            sender_id: "sender",
            encrypted_body: b"encrypted",
            metadata: &MessageMetadata::default(),
            created_at: 1,
        })?;
        self.db.store_message_content("thread", id, b"local-content")?;
        let control = SearchControl::new();
        let revision = self.db.search_revision(&self.activation, &control)?;
        self.db.search_replace(&self.activation, Self::source(id, text), revision, &control)?;
        Ok(())
    }
    fn hits(&self, text: &str) -> Result<Vec<SearchCandidate>, Box<dyn std::error::Error>> {
        let control = SearchControl::new();
        let query = compile_query(&SearchQuery::new("test", text), &control)?;
        Ok(self.db.search_candidates(
            &self.activation,
            &query,
            SearchKind::Message,
            i64::MAX,
            &control,
        )?)
    }
}

#[test]
fn local_search_cjk_and_normalization() -> TestResult {
    let f = Fixture::new()?;
    f.insert("message", "東京都 ＳＴＲＡＳＳＥ café 中文 catalog")?;
    for (query, expected) in [
        ("東京", 1),
        ("東京都", 1),
        ("中", 1),
        ("中文", 1),
        ("STRASSE", 1),
        ("cafe\u{301}", 1),
        ("cafe", 0),
        ("cat", 0),
        ("alpha OR beta", 0),
    ] {
        assert_eq!(
            f.hits(query)?.len(),
            expected,
            "keyed FTS exact-word/Unicode16 contract failed for {query}"
        );
    }
    f.insert("separated", "甲乙 乙丙")?;
    let control = SearchControl::new();
    let query = compile_query(&SearchQuery::new("test", "甲乙丙"), &control)?;
    let current = normalize_document("甲乙 乙丙", &control)?;
    assert!(
        !query.matches(&current, &control)?,
        "intersection must be authoritatively checked for contiguity"
    );
    Ok(())
}

#[test]
fn local_search_erase_removes_all_derivatives() -> TestResult {
    let f = Fixture::new()?;
    f.insert("victim", "oldcanary")?;
    f.insert("survivor", "unrelatedcanary")?;
    let stamp = f.watch.stamp();
    let cleared = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback = std::sync::Arc::clone(&cleared);
    let _registration = f.watch.register(
        "pending-reply".into(),
        stamp,
        std::sync::Arc::new(move || {
            callback.store(true, std::sync::atomic::Ordering::Release);
        }),
    )?;
    f.db.write_transaction::<_, crate::StorageError>(|| {
        f.db.connection.execute(
            "DELETE FROM runtime_message_content WHERE message_id=?1",
            params!["victim"],
        )?;
        Ok(())
    })?;
    assert!(
        cleared.load(std::sync::atomic::Ordering::Acquire),
        "committed mutation must clear pending replies before returning"
    );
    assert!(
        f.hits("oldcanary")?.is_empty(),
        "retired source terms must disappear with replacement indexing paused"
    );
    assert_eq!(f.hits("unrelatedcanary")?.len(), 1, "unrelated source must survive retirement");
    let remaining: i64 = f.db.connection.query_row(
        "SELECT count(*) FROM local_search_doc WHERE message_id='victim'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(remaining, 0, "retirement must remove all derived locators");
    f.insert("rollback", "rollbackcanary")?;
    let result = f.db.write_transaction::<_, crate::StorageError>(|| {
        f.db.connection
            .execute("DELETE FROM runtime_message_content WHERE message_id='rollback'", [])?;
        Err::<(), _>(crate::StorageError::AuthorizationRejected)
    });
    assert!(result.is_err(), "fixture must roll back the canonical mutation");
    assert_eq!(
        f.hits("rollbackcanary")?.len(),
        1,
        "failed canonical mutation must roll back its purge too"
    );
    Ok(())
}

#[test]
fn export_discards_search_namespace() -> TestResult {
    let f = Fixture::new()?;
    f.insert("message", "privatecanary")?;
    let destination = f.directory.path().join("snapshot.db");
    let snapshot = f.db.write_backup_snapshot(&destination)?;
    let backup = super::super::backup_database::BackupDatabase::open(&destination, &snapshot.key)?;
    let tables: i64 = backup.db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'local_search_*'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        tables, 0,
        "physical snapshot must strip unknown and current derived search namespace"
    );
    let footprints: i64 = backup.db.query_row(
        "SELECT count(*) FROM message_footprint WHERE kind=?1",
        params!["local_search_doc"],
        |r| r.get(0),
    )?;
    assert_eq!(footprints, 0, "archive must not retain derivative locators");
    assert_eq!(
        f.hits("privatecanary")?.len(),
        1,
        "export sanitization must not mutate the live writer"
    );
    Ok(())
}
