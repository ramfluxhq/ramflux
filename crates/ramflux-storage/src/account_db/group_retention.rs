// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Active group key scopes and diagnostic journals have independent bounded retention.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    /// Retains at most 64 active key-head checkpoints per group, sender and direction.
    /// Historical event bodies remain governed by account history retention.
    /// # Errors
    /// Rejects non-group checkpoints or returns database failures.
    pub fn retain_group_key_checkpoint(
        &self,
        scope: &str,
        checkpoint: &str,
    ) -> Result<(), StorageError> {
        if !checkpoint.starts_with("group_sender_key:v3/") {
            return Err(StorageError::GroupPermissionDenied);
        }
        self.write_transaction(|| {
            let id=format!("group-key/scopes/{scope}");
            let mut scopes: Vec<String>=self.load_actor_state(&id)?.unwrap_or_default();
            scopes.retain(|key| key!=checkpoint); scopes.push(checkpoint.into());
            while scopes.len()>64 {
                let old=scopes.remove(0);
                self.connection.execute("DELETE FROM projection_checkpoint WHERE projection_name=?1 AND projection_name LIKE 'group_sender_key:v3/%'",params![old])?;
            }
            self.persist_actor_state(&id,&scopes)
        })
    }
    /// Appends bounded diagnostics, retaining 8 rows per device/group subject and 4096 total.
    /// # Errors
    /// Rejects unrelated topics or returns journal/database errors.
    pub fn append_group_journal(
        &self,
        source: &str,
        topic: &str,
        body: &serde_json::Value,
        at: i64,
        subject: &str,
    ) -> Result<(), StorageError> {
        if !matches!(topic, "group.state.conflict" | "group.state.delivery_failed") {
            return Err(StorageError::GroupPermissionDenied);
        }
        self.write_transaction(|| {
            self.append_journal(source,topic,body,at,Some(subject))?;
            let subject_floor:Option<u64>=self.connection.query_row("SELECT seq FROM runtime_journal WHERE topic=?1 AND subject=?2 ORDER BY seq DESC LIMIT 1 OFFSET 8",params![topic,subject],|row|row.get(0)).optional()?;
            let global_floor:Option<u64>=self.connection.query_row("SELECT seq FROM runtime_journal WHERE topic IN ('group.state.conflict','group.state.delivery_failed') ORDER BY seq DESC LIMIT 1 OFFSET 4096",[],|row|row.get(0)).optional()?;
            let cutoff=at.saturating_sub(7*86400);
            let condition="topic IN ('group.state.conflict','group.state.delivery_failed') AND (at<?1 OR seq<=?2 OR (topic=?3 AND subject=?4 AND seq<=?5))";
            let floor:Option<u64>=self.connection.query_row(&format!("SELECT max(seq) FROM runtime_journal WHERE {condition}"),params![cutoff,global_floor.unwrap_or(0),topic,subject,subject_floor.unwrap_or(0)],|row|row.get(0))?;
            self.connection.execute(&format!("DELETE FROM runtime_journal WHERE {condition}"),params![cutoff,global_floor.unwrap_or(0),topic,subject,subject_floor.unwrap_or(0)])?;
            if let Some(floor)=floor {self.connection.execute("UPDATE runtime_journal_bounds SET pruned_through=max(pruned_through,?1) WHERE singleton=1",params![floor])?;}
            Ok(())
        })
    }
}
