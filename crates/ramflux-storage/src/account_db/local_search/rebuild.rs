// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resumable maintenance stores only source IDs and a format-bound keyset.
use super::*;
use crate::AccountDb;
use rusqlite::params;

pub struct SearchRebuildBatch {
    pub kind: SearchKind,
    pub keys: Vec<String>,
    pub checkpoint: String,
    pub canonical: SearchIndexRevision,
    pub dirty: bool,
}
impl AccountDb {
    /// # Errors
    /// Refuses missing indexes or interruption without disturbing privacy purges.
    pub fn search_rebuild_reset(
        &self,
        _activation: &SearchActivation,
        control: &SearchControl,
    ) -> SearchResult<()> {
        self.search_call(control,|db| {
            db.execute("UPDATE local_search_state SET rebuild_required=1,checkpoint_kind=0,checkpoint='',coverage='building',truncated=0,quota_limited=0,revision=revision+1",[])?;
            Ok(())
        })
    }
    /// # Errors
    /// Returns bounded work or completion, never an unbounded source list.
    pub fn search_rebuild_batch(
        &self,
        activation: &SearchActivation,
        control: &SearchControl,
    ) -> SearchResult<Option<SearchRebuildBatch>> {
        let (required,phase,checkpoint)=self.search_call(control,|db| {
            Ok(db.query_row("SELECT rebuild_required,checkpoint_kind,CASE WHEN length(CAST(checkpoint AS BLOB))<=256 THEN checkpoint END FROM local_search_state WHERE singleton=1",[],|r|Ok((r.get::<_,bool>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?)))?)
        })?;
        let canonical = self.search_revision(activation, control)?;
        if required && phase < 2 {
            let kind = SearchKind::from_ordinal(phase)?;
            let keys = self.search_source_keys(activation, kind, &checkpoint, control)?;
            return Ok(Some(SearchRebuildBatch {
                kind,
                keys,
                checkpoint,
                canonical,
                dirty: false,
            }));
        }
        self.search_call(control,move |db| {
            let mut statement=db.prepare("SELECT kind,CASE WHEN length(CAST(source_key AS BLOB))<=256 THEN source_key END FROM local_search_dirty ORDER BY kind,source_key LIMIT 1")?;
            let mut rows=statement.query([])?;
            if let Some(row)=rows.next()? {
                let kind=SearchKind::from_ordinal(row.get(0)?)?;
                return Ok(Some(SearchRebuildBatch{kind,keys:vec![row.get(1)?],checkpoint:String::new(),canonical,dirty:true}));
            }
            drop(rows);drop(statement);
            db.execute("UPDATE local_search_state SET coverage='complete',rebuild_required=0 WHERE singleton=1",[])?;
            Ok(None)
        })
    }
    /// Acknowledges only fully processed IDs against unchanged canonical input.
    /// # Errors
    /// Racing edits leave dirty work pending and refuse the stale checkpoint.
    pub fn search_rebuild_advance(
        &self,
        _activation: &SearchActivation,
        batch: SearchRebuildBatch,
        last: Option<String>,
        control: &SearchControl,
    ) -> SearchResult<()> {
        self.search_call(control,move |db| {
            let tx=db.unchecked_transaction()?;
            let current=super::operations::revision(&tx)?;
            if current.epoch!=batch.canonical.epoch || current.canonical!=batch.canonical.canonical {return Err(SearchError::CursorStale);}
            if batch.dirty {
                if let Some(key)=last {tx.execute("DELETE FROM local_search_dirty WHERE kind=?1 AND source_key=?2",params![batch.kind.ordinal(),key])?;}
            } else if let Some(key)=last {
                tx.execute("UPDATE local_search_state SET checkpoint=?1 WHERE checkpoint_kind=?2 AND checkpoint=?3",params![key,batch.kind.ordinal(),batch.checkpoint])?;
            } else if batch.keys.is_empty() {
                tx.execute("UPDATE local_search_state SET checkpoint_kind=checkpoint_kind+1,checkpoint='' WHERE checkpoint_kind=?1 AND checkpoint=?2",params![batch.kind.ordinal(),batch.checkpoint])?;
            }
            tx.commit()?;
            Ok(())
        })
    }
    /// # Errors
    /// Stores a partial-coverage marker after a quota refusal, without evicting documents.
    pub fn search_mark_partial(
        &self,
        _activation: &SearchActivation,
        quota: bool,
        control: &SearchControl,
    ) -> SearchResult<()> {
        self.search_call(control,move |db| {
            db.execute("UPDATE local_search_state SET quota_limited=max(quota_limited,?1),truncated=max(truncated,?2)",params![quota,!quota])?;
            Ok(())
        })
    }
}
