// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keyed writer transactions and bounded FTS candidate reads.
use super::*;
use crate::{AccountDb, EncryptionMode};
use rusqlite::{Connection, OptionalExtension as _, params};
use std::sync::Arc;
use std::time::Duration;

impl AccountDb {
    /// Installs derived tables only after a sealed activation decision.
    /// # Errors
    /// Refuses plaintext, incompatible engines, quotas and invalid account state.
    pub fn search_prepare(&self, activation: &SearchActivation) -> SearchResult<Arc<SearchWatch>> {
        if !activation.permits_owner(self)
            || self.mode != EncryptionMode::SqlCipher
            || self.is_query_only()?
        {
            return Err(SearchError::IndexUnavailable);
        }
        let epoch = i64::from_le_bytes(
            ramflux_crypto::random_32()
                .map_err(crate::StorageError::from)?
                .get(..8)
                .ok_or(SearchError::IndexUnavailable)?
                .try_into()
                .map_err(|_| SearchError::IndexUnavailable)?,
        ) & i64::MAX;
        self.connection.call(|db| Ok(super::schema::prepare(db)))??;
        let initialize = || {
            self.write_transaction(|| {
                self.connection.call(move |db| Ok(super::schema::initialize(db, epoch.max(1))))?
            })
        };
        if initialize().is_err() {
            // This cache is disposable. Repair only its reserved namespace, atomically;
            // inability to drop/recreate it remains a typed refusal, never stale fallback.
            self.write_transaction(|| {
                self.connection.call(move |db| {
                    super::lifecycle::strip(db)?;
                    db.execute_batch("DROP TABLE IF EXISTS local_search_compaction_pending;")?;
                    Ok(super::schema::initialize(db, epoch.max(1)))
                })?
            })?;
        }
        let watch = self.connection.observe_local_search(Arc::new(SearchWatch::default()));
        let refreshed = Arc::clone(&watch);
        self.connection.call(move |db| {
            refreshed.refresh(db);
            Ok(())
        })?;
        Ok(watch)
    }

    pub(crate) fn search_call<T: Send + 'static>(
        &self,
        control: &SearchControl,
        read: impl FnOnce(&Connection) -> SearchResult<T> + Send + 'static,
    ) -> SearchResult<T> {
        self.search_scope(control, || self.connection.call(move |db| Ok(read(db)))?)
    }
    pub(crate) fn search_write<T: Send + 'static>(
        &self,
        control: &SearchControl,
        write: impl FnOnce(&Connection) -> SearchResult<T> + Send + 'static,
    ) -> SearchResult<T> {
        self.search_scope(control, || {
            self.write_transaction(|| self.connection.call(move |db| Ok(write(db)))?)
        })
    }
    fn search_scope<T>(
        &self,
        control: &SearchControl,
        execute: impl FnOnce() -> SearchResult<T>,
    ) -> SearchResult<T> {
        control.check()?;
        let interrupt = control.clone();
        let setup = self.connection.call(move |db| {
            db.busy_timeout(Duration::ZERO)?;
            db.progress_handler(VM_CALLBACK_STEPS, Some(move || interrupt.vm_interrupt()))?;
            db.execute_batch("PRAGMA cache_size=-6144; PRAGMA temp_store=MEMORY;")
        });
        let result = match setup {
            Ok(()) => execute(),
            Err(error) => Err(error.into()),
        };
        let budget = control.check();
        let cleanup = self.connection.call(|db| {
            db.progress_handler(0, None::<fn() -> bool>)?;
            db.busy_timeout(Duration::from_secs(5))
        });
        cleanup?;
        budget?;
        result
    }

    /// # Errors
    /// Requires an installed compatible index and a bounded execution lease.
    pub fn search_revision(
        &self,
        _activation: &SearchActivation,
        control: &SearchControl,
    ) -> SearchResult<SearchIndexRevision> {
        self.search_call(control, revision)
    }

    /// Replaces one authorized source in the same keyed writer; stale preparation cannot publish.
    /// # Errors
    /// Refuses stale canonical versions, quotas and cancellation; failed writes roll back.
    pub fn search_replace(
        &self,
        _activation: &SearchActivation,
        source: SearchSource,
        expected: SearchIndexRevision,
        control: &SearchControl,
    ) -> SearchResult<()> {
        source.validate()?;
        let normalized = normalize_document(source.text.expose(), control)?;
        let control_inner = control.clone();
        self.search_write(control,move |db| {

            let current=revision(db)?;
            if current.epoch!=expected.epoch || current.canonical!=expected.canonical {return Err(SearchError::CursorStale);}
            db.execute("DELETE FROM local_search_doc WHERE kind=?1 AND source_ref=?2",params![source.kind.ordinal(),source.source_ref])?;
            let count:u64=db.query_row("SELECT document_count FROM local_search_state WHERE singleton=1",[],|r|r.get(0))?;
            if count>=MAX_DOCUMENTS || index_bytes(db)?>=MAX_INDEX_BYTES {return Err(SearchError::Capacity);}
            control_inner.check()?;
            db.execute("INSERT INTO local_search_doc(kind,source_ref,source_key,conversation_id,message_id,source_revision,timestamp,source_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![source.kind.ordinal(),source.source_ref,source.source_key,source.conversation_id,source.message_id,source.revision.to_string(),source.timestamp,source.fingerprint().as_slice()])?;
            let id=db.last_insert_rowid();
            let mut tokens=zeroize::Zeroizing::new(format!("k{} ",source.kind.ordinal()));
            tokens.push_str(normalized.tokens.expose());
            db.execute("INSERT INTO local_search_terms(doc_id,tokens) VALUES(?1,?2)",params![id,tokens.as_str()])?;
            for dependency in source.dependencies {
                control_inner.check()?;
                db.execute("INSERT OR IGNORE INTO local_search_dependency VALUES(?1,?2,?3)",params![dependency.table,dependency.key,id])?;
            }
            if normalized.truncated {db.execute("UPDATE local_search_state SET truncated=1",[])?;}
            if index_bytes(db)?>MAX_INDEX_BYTES {return Err(SearchError::Capacity);}
            control_inner.check()?;

            Ok(())
        })
    }

    /// Reads at most 128 postings in stable kind/rowid order. Scope checks follow hydration.
    /// # Errors
    /// Returns stale-index, deadline, cancellation or engine failures.
    pub fn search_candidates(
        &self,
        _activation: &SearchActivation,
        query: &CompiledQuery,
        kind: SearchKind,
        after: i64,
        control: &SearchControl,
    ) -> SearchResult<Vec<SearchCandidate>> {
        let expression = SearchText::from(format!(
            "\"k{}\" AND ({})",
            kind.ordinal(),
            query.expression.expose()
        ));
        self.search_call(control,move |db| {
            let mut statement=db.prepare("SELECT d.doc_id,d.kind,CASE WHEN length(CAST(d.source_ref AS BLOB))<=1024 THEN d.source_ref END,CASE WHEN length(CAST(d.source_key AS BLOB))<=256 THEN d.source_key END,CASE WHEN length(CAST(d.conversation_id AS BLOB))<=256 THEN d.conversation_id END,CASE WHEN length(CAST(d.message_id AS BLOB))<=256 THEN d.message_id END,substr(d.source_revision,1,21),d.timestamp,substr(d.source_hash,1,33) FROM local_search_fts CROSS JOIN local_search_doc d ON d.doc_id=local_search_fts.rowid WHERE local_search_fts MATCH ?1 AND local_search_fts.rowid<?2 ORDER BY local_search_fts.rowid DESC LIMIT 128")?;
            let mut rows=statement.query(params![expression.expose(),after])?;
            let mut output=Vec::new();
            while let Some(row)=rows.next()? {
                let revision:String=row.get(6)?;
                let hash:Vec<u8>=row.get(8)?;
                let candidate_kind=SearchKind::from_ordinal(row.get(1)?)?;
                if candidate_kind!=kind || revision.len()>20 {return Err(SearchError::IndexUnavailable);}
                output.push(SearchCandidate{doc_id:row.get(0)?,kind:candidate_kind,source_ref:row.get(2)?,source_key:row.get(3)?,conversation_id:row.get(4)?,message_id:row.get(5)?,source_revision:revision.parse().map_err(|_|SearchError::IndexUnavailable)?,timestamp:row.get(7)?,source_hash:hash.try_into().map_err(|_|SearchError::IndexUnavailable)?});
            }
            Ok(output)
        })
    }

    /// # Errors
    /// Refuses missing state and corrupt coverage counters.
    pub fn search_index_status(
        &self,
        _activation: &SearchActivation,
        control: &SearchControl,
    ) -> SearchResult<SearchIndexStatus> {
        self.search_call(control,|db| {
            let (coverage,count,truncated,quota):(String,u64,bool,bool)=db.query_row("SELECT coverage,document_count,truncated,quota_limited FROM local_search_state WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let coverage=match coverage.as_str(){"failed"=>SearchCoverage::Failed,_ if quota=>SearchCoverage::QuotaLimited,"building"=>SearchCoverage::Building,"lagging"=>SearchCoverage::Lagging,"complete" if truncated=>SearchCoverage::Truncated,"complete"=>SearchCoverage::Complete,_=>return Err(SearchError::IndexUnavailable)};
            Ok(SearchIndexStatus{coverage,indexed_documents:count,..SearchIndexStatus::disabled()})
        })
    }
}

pub(super) fn revision(db: &Connection) -> SearchResult<SearchIndexRevision> {
    db.query_row(
        "SELECT epoch,revision,canonical_revision FROM local_search_state WHERE singleton=1",
        [],
        |r| Ok(SearchIndexRevision { epoch: r.get(0)?, revision: r.get(1)?, canonical: r.get(2)? }),
    )
    .optional()?
    .ok_or(SearchError::IndexUnavailable)
}
fn index_bytes(db: &Connection) -> SearchResult<u64> {
    super::schema::verify_dbstat(db)?;
    db.query_row(
        "SELECT COALESCE(sum(pgsize),0) FROM main.dbstat WHERE name GLOB 'local_search_*'",
        [],
        |r| r.get(0),
    )
    .map_err(|_| SearchError::IndexUnavailable)
}
