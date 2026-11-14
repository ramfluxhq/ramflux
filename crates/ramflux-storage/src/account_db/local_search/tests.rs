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
            expires_at: None,
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
    let excerpt = "🙂 cafe\u{301} Straße 東京都";
    let compiled = compile_query(
        &SearchQuery::new("highlights", "café STRASSE 東京都"),
        &SearchControl::new(),
    )?;
    let ranges = compiled.highlights(excerpt, &SearchControl::new())?;
    let pieces: Vec<&str> = ranges
        .iter()
        .map(|range| {
            excerpt
                .get(range.start as usize..range.end as usize)
                .ok_or("invalid highlight boundary")
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(
        pieces,
        vec!["cafe\u{301}", "Straße", "東京都"],
        "highlight bytes must enclose whole original graphemes after casefold expansion"
    );
    let excessive = "中".repeat(150);
    assert!(
        matches!(
            compile_query(&SearchQuery::new("over-terms", excessive), &SearchControl::new()),
            Err(SearchError::InvalidQuery)
        ),
        "derived terms must be bounded before deduplication or SQL"
    );
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
    let old_term = super::normalizer::encode_term('w', "oldcanary")?;
    let stored: bool = f.db.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_search_fts_data WHERE instr(block,CAST(?1 AS BLOB))>0)",
        params![old_term.expose()],
        |r| r.get(0),
    )?;
    assert!(
        stored,
        "fixture must demonstrate the reversible old term exists in a real FTS segment before purge"
    );
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
    let retained: bool = f.db.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_search_fts_data WHERE instr(block,CAST(?1 AS BLOB))>0)",
        params![old_term.expose()],
        |r| r.get(0),
    )?;
    assert!(
        !retained,
        "pinned FTS secure deletion must remove the old encoded term from current segment blocks, not merely hide its MATCH result"
    );
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
    f.db.connection.execute_batch("CREATE TABLE LoCaL_SeArCh_unknown_tokens(secret TEXT); INSERT INTO LoCaL_SeArCh_unknown_tokens VALUES('privatecanary'); CREATE VIEW LOCAL_SEARCH_unknown_view AS SELECT secret FROM LoCaL_SeArCh_unknown_tokens;")?;
    let destination = f.directory.path().join("snapshot.db");
    let snapshot = f.db.write_backup_snapshot(&destination)?;
    let backup = super::super::backup_database::BackupDatabase::open(&destination, &snapshot.key)?;
    let tables: i64 = backup.db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE lower(name) GLOB 'local_search_*'",
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

#[test]
fn local_search_old_backup_cannot_restore_erased_hit() -> TestResult {
    for native in [false, true] {
        restore_erasure_case(native)?;
    }
    Ok(())
}
fn restore_erasure_case(native: bool) -> TestResult {
    use super::super::backup_database::BackupDatabase;
    use crate::{BackupIndexInstall, WrappedAccountDbKey};
    let f = Fixture::new()?;
    f.insert("victim", "archivecanary")?;
    f.insert("survivor", "survivorcanary")?;
    let archive = f.directory.path().join("old.db");
    let old = f.db.write_backup_snapshot(&archive)?;
    let malicious = BackupDatabase::open(&archive, &old.key)?;
    malicious.db.execute_batch("CREATE TABLE LoCaL_SeArCh_untrusted_cache(secret TEXT);INSERT INTO LoCaL_SeArCh_untrusted_cache VALUES('archivecanary');")?;
    drop(malicious);
    f.db.delete_direct_message("thread", "victim", "me", "delete-victim")?;
    let merged_path = f.directory.path().join("merged.db");
    let snapshot = f.db.write_backup_snapshot(&merged_path)?;
    let mut merged = BackupDatabase::open(&merged_path, &snapshot.key)?;
    if native {
        merged.merge_native_backup(&archive, &old.key, || Ok(()))?;
    } else {
        merged.merge_backup_candidate(&archive, &old.key, || Ok(()))?;
    }
    let caches: i64 = merged.db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE lower(name) GLOB 'local_search_*'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        caches, 0,
        "neither full nor native merge may import archive-supplied search tables"
    );
    let erased: bool = merged.db.query_row(
        "SELECT deleted FROM direct_message_projection WHERE message_id='victim'",
        [],
        |r| r.get(0),
    )?;
    assert!(erased, "local deletion floor must dominate the older authenticated archive");
    let payloads: i64 = merged.db.query_row(
        "SELECT count(*) FROM runtime_message_content WHERE message_id='victim'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        payloads, 0,
        "restore must not retain a source from which erased terms could be rebuilt"
    );
    drop(merged);
    let Fixture { directory, db, activation, watch } = f;
    drop(db);
    drop(watch);
    let index = AccountIndex::open(directory.path())?;
    let (nonce, wrapped_key) = crate::wrap_with_vault_secret(&[9; 32], snapshot.key.bytes())?;
    index.install_backup_generation(&BackupIndexInstall {
        account_id: "account",
        principal_commitment: "principal",
        db_relative_path: "merged.db",
        object_relative_path: "objects",
        manifest_json: b"{}",
        wrapped_key: &WrappedAccountDbKey {
            key_wrapping_provider: "test-vault".into(),
            key_wrapping_ref: "test-key".into(),
            nonce,
            wrapped_key,
        },
    })?;
    assert!(
        !index.search_owner_admitted("account")?,
        "freshly installed archive generation must not inherit archive-controlled visibility admission"
    );
    index.admit_local_search_after_floor_validation(&activation, "account")?;
    assert!(
        index.search_owner_admitted("account")?,
        "only explicit local owner validation can grant this selected generation"
    );
    let reopened = AccountDb::open(&index, "account", &snapshot.key)?;
    let _watch = reopened.search_prepare(&activation)?;
    let control = SearchControl::new();
    let query = compile_query(&SearchQuery::new("after-restore", "archivecanary"), &control)?;
    assert!(
        reopened
            .search_candidates(&activation, &query, SearchKind::Message, i64::MAX, &control)?
            .is_empty(),
        "reopened restore must start with no resurrected archive tokens"
    );
    assert!(
        reopened.message_is_deleted("victim")?,
        "source deletion must remain sticky after account reopen"
    );
    Ok(())
}

#[test]
fn local_search_bounds_and_rebuild_races() -> TestResult {
    const DOCUMENTS: i64 = 100_000;
    let f = Fixture::new()?;
    f.db.connection.call(|db| {
        let transaction=db.unchecked_transaction()?;
        let mut docs=transaction.prepare("INSERT INTO local_search_doc(kind,source_ref,source_key,conversation_id,message_id,source_revision,timestamp,source_hash) VALUES(1,?1,?1,'thread',NULL,'1',1,zeroblob(32))")?;
        let mut tokens=transaction.prepare("INSERT INTO local_search_terms(doc_id,tokens) VALUES(?1,?2)")?;
        for number in 0..DOCUMENTS {
            let id=format!("source-{number:06}");docs.execute([id])?;
            tokens.execute(params![transaction.last_insert_rowid(),format!("k1 w636f6d6d6f6e w766f636162{number:016x}")])?;
        }
        drop(tokens);drop(docs);transaction.commit()
    })?;
    let control = SearchControl::new();
    let query = compile_query(&SearchQuery::new("bounded-common", "common"), &control)?;
    let candidates =
        f.db.search_candidates(&f.activation, &query, SearchKind::Message, i64::MAX, &control)?;
    assert_eq!(
        candidates.len(),
        MAX_CANDIDATES,
        "common-term lookup must bound candidates before authoritative hydration"
    );
    assert!(
        control.vm_steps() < MAX_VM_STEPS,
        "indexed descending rowid traversal must avoid corpus-wide sorting/VM work"
    );
    let stale = f.db.search_revision(&f.activation, &SearchControl::new())?;
    f.db.persist_client_record("conversation", "thread", &serde_json::json!({"title":"changed"}))?;
    assert!(
        matches!(
            f.db.search_replace(
                &f.activation,
                Fixture::source("racing", "mustnotpublish"),
                stale,
                &SearchControl::new()
            ),
            Err(SearchError::CursorStale)
        ),
        "canonical mutation must reject tokenization prepared under an older revision"
    );
    let cancelled = SearchControl::new();
    cancelled.cancel();
    assert!(
        matches!(
            f.db.search_candidates(
                &f.activation,
                &query,
                SearchKind::Message,
                i64::MAX,
                &cancelled
            ),
            Err(SearchError::Cancelled)
        ),
        "cancellation must be checked before entering the SQL queue"
    );
    f.db.connection.execute_batch("UPDATE local_search_state SET document_count=1000000;")?;
    let revision = f.db.search_revision(&f.activation, &SearchControl::new())?;
    assert!(
        matches!(
            f.db.search_replace(
                &f.activation,
                Fixture::source("over-quota", "mustnotpublish"),
                revision,
                &SearchControl::new()
            ),
            Err(SearchError::Capacity)
        ),
        "quota must stop new insertion without eviction"
    );
    let survivors: i64 =
        f.db.connection.query_row("SELECT count(*) FROM local_search_doc", [], |r| r.get(0))?;
    assert_eq!(survivors, DOCUMENTS, "quota refusal must preserve existing documents");
    // Existing dirty IDs overlap the first affected IDs: DISTINCT alone with a
    // remaining-capacity LIMIT would silently lose the rest of this work.
    f.db.connection.execute_batch("UPDATE local_search_state SET document_count=100000,rebuild_required=0,checkpoint_kind=2,coverage='complete'; DELETE FROM local_search_dirty; INSERT INTO local_search_dirty SELECT 1,source_key FROM local_search_doc ORDER BY source_key LIMIT 4000; INSERT INTO local_search_dependency SELECT 'object_erasure_fence','shared-fence',doc_id FROM local_search_doc WHERE doc_id<=5000; INSERT INTO object_erasure_fence(commitment) VALUES('shared-fence');")?;
    let (remaining, dirty, required): (i64, i64, bool) = f.db.connection.query_row("SELECT (SELECT count(*) FROM local_search_doc),(SELECT count(*) FROM local_search_dirty),rebuild_required FROM local_search_state", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    assert_eq!(
        remaining,
        DOCUMENTS - 5000,
        "shared erasure dependency must purge every affected derivative and preserve unrelated documents"
    );
    assert_eq!(dirty, 0, "overflow must collapse the bounded ID queue");
    assert!(required, "overlapping dirty IDs must never hide omitted rebuild work");

    Ok(())
}

#[test]
fn archive_compaction_preserves_erasure_locators() -> TestResult {
    use super::super::backup_database::BackupDatabase;
    let f = Fixture::new()?;
    f.insert("gap", "discardcanary")?;
    f.insert("victim", "victimcanary")?;
    f.insert("survivor", "survivorcanary")?;
    f.db.delete_direct_message("thread", "gap", "me", "delete-gap")?;
    f.db.connection.execute_batch("CREATE TABLE backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); INSERT INTO backup_archived_actor_state(rowid,source,state_kind,state_json) VALUES(9,'local','opaque-victim',x'7b2270726976617465223a226f70617175652d63616e617279227d'); INSERT INTO message_footprint VALUES('victim','archived_actor','9');")?;
    f.db.connection.execute_batch("INSERT INTO raw_inner_evidence VALUES('victim',x'00',x'01'); INSERT INTO message_footprint VALUES('victim','raw_inner_evidence','victim');")?;
    let destination = f.directory.path().join("compacted.db");
    let snapshot = f.db.write_backup_snapshot(&destination)?;
    let backup = BackupDatabase::open(&destination, &snapshot.key)?;
    let natural: bool = backup.db.query_row("SELECT EXISTS(SELECT 1 FROM message_footprint WHERE message_id='victim' AND kind='raw_inner_evidence' AND locator='victim')", [], |r| r.get(0))?;
    assert!(
        natural,
        "a natural message-ID locator must never be rewritten as an implicit rowid merely because its kind matches a table name"
    );
    let present: i64 = backup.db.query_row(
        "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind='opaque-victim'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(present, 1, "fixture must preserve the opaque owned copy before erasure");
    let aligned:bool=backup.db.query_row("SELECT EXISTS(SELECT 1 FROM message_footprint f JOIN backup_archived_actor_state a ON f.locator=CAST(a.rowid AS TEXT) WHERE f.message_id='victim' AND f.kind='archived_actor' AND a.state_kind='opaque-victim')",[],|r|r.get(0))?;
    assert!(
        aligned,
        "compaction must remap implicit-rowid erasure locators by stable source identity"
    );
    backup
        .db
        .execute("UPDATE direct_message_projection SET deleted=1 WHERE message_id='victim'", [])?;
    let opaque: i64 = backup.db.query_row(
        "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind='opaque-victim'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(opaque, 0, "erasure after export must remove the remapped opaque derivative");
    let survivor: i64 = backup.db.query_row(
        "SELECT count(*) FROM runtime_message_content WHERE message_id='survivor'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(survivor, 1, "rowid relocation must not redirect erasure onto an unrelated message");
    let namespace: i64 = backup.db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE lower(name) GLOB 'local_search_*'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        namespace, 0,
        "published snapshot must contain neither search nor compaction work tables"
    );
    Ok(())
}

#[test]
fn local_search_checkpoint_resumes_and_rejects_reset_races() -> TestResult {
    let f = Fixture::new()?;
    f.insert("first", "canary")?;
    f.insert("second", "canary")?;
    f.db.connection.execute_batch(
        "UPDATE local_search_state SET rebuild_required=1,checkpoint_kind=1,checkpoint='first';",
    )?;
    f.db.search_rebuild_reset(&f.activation, &SearchControl::new())?;
    let batch =
        f.db.search_rebuild_batch(&f.activation, &SearchControl::new())?
            .ok_or("resumable batch")?;
    assert_eq!(
        batch.checkpoint, "first",
        "a new maintenance lease must preserve the durable checkpoint"
    );
    assert_eq!(batch.keys, vec!["second"], "resume must use a strict source keyset");
    f.db.persist_client_record(
        "conversation",
        "thread",
        &serde_json::json!({"title":"racing reset"}),
    )?;
    assert!(
        matches!(
            f.db.search_rebuild_advance(
                &f.activation,
                batch,
                Some("second".into()),
                &SearchControl::new()
            ),
            Err(SearchError::CursorStale)
        ),
        "a canonical reset must reject the old checkpoint acknowledgement"
    );
    Ok(())
}

#[test]
fn local_search_corrupt_cache_is_discarded_without_canonical_loss() -> TestResult {
    let f = Fixture::new()?;
    f.insert("survivor", "repaircanary")?;
    let before = f.db.search_revision(&f.activation, &SearchControl::new())?;
    f.db.connection.execute_batch("DROP TABLE local_search_terms;")?;
    let _watch = f.db.search_prepare(&f.activation)?;
    let after = f.db.search_revision(&f.activation, &SearchControl::new())?;
    assert_ne!(before.epoch, after.epoch, "repair must publish a new derived-cache epoch");
    assert!(
        f.hits("repaircanary")?.is_empty(),
        "damaged cache must be discarded instead of serving old terms as fallback"
    );
    assert_eq!(
        f.db.message_content("survivor")?.as_deref(),
        Some(b"local-content".as_slice()),
        "cache repair must preserve the canonical source for authorized rebuild"
    );
    assert_eq!(
        f.db.search_index_status(&f.activation, &SearchControl::new())?.coverage,
        SearchCoverage::Building,
        "cache repair must report incomplete coverage until reconstruction"
    );
    Ok(())
}

#[test]
fn local_search_refuses_shadowed_page_accounting() -> TestResult {
    let f = Fixture::new()?;
    f.insert("survivor", "quotacanary")?;
    for schema in ["main", "temp"] {
        f.db.connection
            .execute_batch(&format!("CREATE TABLE {schema}.DbStAt(name TEXT,pgsize INTEGER);"))?;
        let control = SearchControl::new();
        let revision = f.db.search_revision(&f.activation, &control)?;
        assert!(
            matches!(
                f.db.search_replace(
                    &f.activation,
                    Fixture::source("survivor", "replacement"),
                    revision,
                    &control
                ),
                Err(SearchError::IndexUnavailable)
            ),
            "case-aliased schema objects must never impersonate the dbstat virtual module"
        );
        f.db.connection.execute_batch(&format!("DROP TABLE {schema}.DbStAt;"))?;
        assert_eq!(
            f.hits("quotacanary")?.len(),
            1,
            "unverified quota accounting must roll back replacement without eviction"
        );
    }
    Ok(())
}

#[test]
fn local_search_page_quota_counts_owned_implicit_indexes() -> TestResult {
    let f = Fixture::new()?;
    f.insert("owned", "quotacanary")?;
    let before = f.db.connection.call(|db| Ok(super::operations::index_bytes(db)))??;
    let named: u64 = f.db.connection.query_row(
        "SELECT COALESCE(sum(pgsize),0) FROM main.dbstat WHERE lower(name) GLOB 'local_search_*'",
        [],
        |r| r.get(0),
    )?;
    assert!(
        before > named,
        "quota must include the search tables' SQLite-generated unique/primary-key indexes, whose names do not start with the search prefix"
    );
    f.db.connection.execute_batch("CREATE TABLE quota_unrelated_account_data(bytes BLOB); INSERT INTO quota_unrelated_account_data VALUES(zeroblob(1048576));")?;
    let after = f.db.connection.call(|db| Ok(super::operations::index_bytes(db)))??;
    assert_eq!(
        before, after,
        "unrelated canonical B-tree pages must never be charged to the derived search quota"
    );
    Ok(())
}
