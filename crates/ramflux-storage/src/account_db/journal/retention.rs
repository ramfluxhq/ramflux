// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retention never deletes unacknowledged safety/approval events.
use super::*;
impl AccountDb {
    /// Prunes ordinary/acknowledged events by count and age, preserving a durable gap watermark.
    /// Status/health transitions have a separate 128-event count budget and the same age bound.
    ///
    /// # Errors
    /// Returns SQL errors; the whole retention pass rolls back on failure.
    pub fn retain_journal(
        &self,
        now: i64,
        max_count: u32,
        max_age_seconds: u64,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let cutoff=now.saturating_sub(i64::try_from(max_age_seconds).unwrap_or(i64::MAX));
            let count_floor:Option<u64>=self.connection.query_row("SELECT seq FROM runtime_journal WHERE topic NOT IN ('sync.status','node.health') ORDER BY seq DESC LIMIT 1 OFFSET ?1",params![max_count],|row|row.get(0)).optional()?;
            let status_floor:Option<u64>=self.connection.query_row("SELECT seq FROM runtime_journal WHERE topic IN ('sync.status','node.health') ORDER BY seq DESC LIMIT 1 OFFSET 128",[],|row|row.get(0)).optional()?;
            let eligible="(sticky=0 OR acknowledged=1) AND (at<?1 OR (topic NOT IN ('sync.status','node.health') AND seq<=?2) OR (topic IN ('sync.status','node.health') AND seq<=?3))";
            let deleted:Option<u64>=self.connection.query_row(&format!("SELECT max(seq) FROM runtime_journal WHERE {eligible}"),params![cutoff,count_floor.unwrap_or(0),status_floor.unwrap_or(0)],|row|row.get(0))?;
            self.connection.execute(&format!("DELETE FROM message_footprint WHERE kind='journal' AND CAST(locator AS INTEGER) IN (SELECT seq FROM runtime_journal WHERE {eligible})"),params![cutoff,count_floor.unwrap_or(0),status_floor.unwrap_or(0)])?;
            self.connection.execute(&format!("DELETE FROM runtime_journal WHERE {eligible}"),params![cutoff,count_floor.unwrap_or(0),status_floor.unwrap_or(0)])?;
            if let Some(seq)=deleted {self.connection.execute("UPDATE runtime_journal_bounds SET pruned_through=max(pruned_through,?1) WHERE singleton=1",params![seq])?;}
            self.connection.execute("DELETE FROM runtime_outbox WHERE published=1",[])?;
            Ok(())
        })
    }
}
