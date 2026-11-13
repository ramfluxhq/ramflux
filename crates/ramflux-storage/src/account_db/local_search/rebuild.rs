// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resumable maintenance stores only source IDs and a format-bound keyset.
use super::*;
use crate::AccountDb;
use rusqlite::{OptionalExtension as _, params};

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
        self.search_write(control,|db| {
            db.execute("UPDATE local_search_state SET checkpoint_kind=CASE WHEN rebuild_required=1 THEN checkpoint_kind ELSE 0 END,checkpoint=CASE WHEN rebuild_required=1 THEN checkpoint ELSE '' END,rebuild_required=1,coverage='building',truncated=CASE WHEN rebuild_required=1 THEN truncated ELSE 0 END,quota_limited=0,revision=revision+1",[])?;
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
        // Completion and the checkpoint/revision capture share one managed writer transaction.
        // A canonical change cannot reset the checkpoint between this decision and its revision.
        let batch = self.search_write(control, |db| {
            let (required, phase, checkpoint) = db.query_row(
                "SELECT rebuild_required,checkpoint_kind,CASE WHEN length(CAST(checkpoint AS BLOB))<=256 THEN checkpoint END FROM local_search_state WHERE singleton=1",
                [], |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)))?;
            let canonical = super::operations::revision(db)?;
            if required && phase < 2 {
                return Ok(Some(SearchRebuildBatch {kind: SearchKind::from_ordinal(phase)?, keys: Vec::new(), checkpoint, canonical, dirty: false}));
            }
            let next = db.query_row(
                "SELECT kind,CASE WHEN length(CAST(source_key AS BLOB))<=256 THEN source_key END FROM local_search_dirty ORDER BY kind,source_key LIMIT 1",
                [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))).optional()?;
            if let Some((kind, key)) = next {
                return Ok(Some(SearchRebuildBatch {kind: SearchKind::from_ordinal(kind)?, keys: vec![key], checkpoint: String::new(), canonical, dirty: true}));
            }
            db.execute("UPDATE local_search_state SET coverage='complete',rebuild_required=0 WHERE singleton=1", [])?;
            Ok(None)
        })?;
        let Some(mut batch) = batch else { return Ok(None) };
        if !batch.dirty {
            batch.keys =
                self.search_source_keys(activation, batch.kind, &batch.checkpoint, control)?;
        }
        Ok(Some(batch))
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
        self.search_write(control,move |db| {

            let current=super::operations::revision(db)?;
            if current.epoch!=batch.canonical.epoch || current.canonical!=batch.canonical.canonical {return Err(SearchError::CursorStale);}
            if batch.dirty {
                if let Some(key)=last {db.execute("DELETE FROM local_search_dirty WHERE kind=?1 AND source_key=?2",params![batch.kind.ordinal(),key])?;}
            } else if let Some(key)=last {
                let changed=db.execute("UPDATE local_search_state SET checkpoint=?1 WHERE rebuild_required=1 AND checkpoint_kind=?2 AND checkpoint=?3",params![key,batch.kind.ordinal(),batch.checkpoint])?;
                if changed!=1 {return Err(SearchError::CursorStale);}
            } else if batch.keys.is_empty() {
                let changed=db.execute("UPDATE local_search_state SET checkpoint_kind=checkpoint_kind+1,checkpoint='' WHERE rebuild_required=1 AND checkpoint_kind=?1 AND checkpoint=?2",params![batch.kind.ordinal(),batch.checkpoint])?;
                if changed!=1 {return Err(SearchError::CursorStale);}
            }

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
        self.search_write(control,move |db| {
            db.execute("UPDATE local_search_state SET quota_limited=max(quota_limited,?1),truncated=max(truncated,?2)",params![quota,!quota])?;
            Ok(())
        })
    }
}
