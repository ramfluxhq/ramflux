// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opt-in statement work counters retain counts, never SQL parameters or account contents.

use crate::AccountDb;
use rusqlite::{Statement, StatementStatus, types::Value};
use std::sync::{Arc, Mutex};

/// Counts actual executed rows and SQLite VM steps on one observed account connection.
#[derive(Clone, Copy, Debug, Default)]
pub struct SqlWorkSnapshot {
    pub read_statements: u64,
    pub read_rows: u64,
    pub read_steps: u64,
    pub source_read_rows: u64,
    pub source_read_steps: u64,
    pub write_statements: u64,
    pub written_rows: u64,
    pub committed_state_reads: u64,
    pub committed_state_steps: u64,
    pub committed_prefix_reads: u64,
    pub ack_committed_prefix_reads: u64,
    pub committed_state_writes: u64,
}

#[derive(Clone, Copy, Default)]
enum Phase {
    #[default]
    Other,
    Source,
    Ack,
}

#[derive(Default)]
struct Observed {
    snapshot: SqlWorkSnapshot,
    phase: Phase,
}

/// A connection-local observer, available only with the integration-test feature.
#[derive(Clone, Default)]
pub struct SqlWorkProbe(Arc<Mutex<Observed>>);

/// Restores the preceding phase when a synchronous writer checkpoint finishes.
pub struct SqlWorkScope {
    probe: SqlWorkProbe,
    previous: Phase,
}
impl Drop for SqlWorkScope {
    fn drop(&mut self) {
        self.probe.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).phase =
            self.previous;
    }
}

impl SqlWorkProbe {
    #[must_use]
    pub fn snapshot(&self) -> SqlWorkSnapshot {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).snapshot
    }

    #[must_use]
    pub fn source_reads(&self) -> SqlWorkScope {
        self.phase(Phase::Source)
    }

    #[must_use]
    pub fn acknowledgements(&self) -> SqlWorkScope {
        self.phase(Phase::Ack)
    }

    fn phase(&self, phase: Phase) -> SqlWorkScope {
        let mut observed = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = observed.phase;
        observed.phase = phase;
        SqlWorkScope { probe: self.clone(), previous }
    }

    pub(crate) fn record_read(
        &self,
        statement: &Statement<'_>,
        committed: Option<bool>,
        rows: usize,
    ) {
        let steps =
            u64::try_from(statement.get_status(StatementStatus::VmStep)).unwrap_or(u64::MAX);
        let rows = u64::try_from(rows).unwrap_or(u64::MAX);
        let mut observed = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let phase = observed.phase;
        let counts = &mut observed.snapshot;
        counts.read_statements += 1;
        counts.read_rows += rows;
        counts.read_steps += steps;
        if matches!(phase, Phase::Source) {
            counts.source_read_rows += rows;
            counts.source_read_steps += steps;
        }
        if let Some(prefix) = committed {
            counts.committed_state_reads += rows;
            counts.committed_state_steps += steps;
            counts.committed_prefix_reads += u64::from(prefix);
            if matches!(phase, Phase::Ack) {
                counts.ack_committed_prefix_reads += u64::from(prefix);
            }
        }
    }

    pub(crate) fn record_write(
        &self,
        statement: &Statement<'_>,
        committed: Option<bool>,
        rows: usize,
    ) {
        let mut observed = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let counts = &mut observed.snapshot;
        counts.write_statements += 1;
        counts.written_rows += u64::try_from(rows).unwrap_or(u64::MAX);
        if committed.is_some() {
            counts.committed_state_writes += u64::try_from(rows).unwrap_or(u64::MAX);
        }
        // Cached statements retain their counters; reset them after every execution.
        statement.reset_status(StatementStatus::VmStep);
    }
}

pub(crate) fn committed_state(sql: &str, values: &[Value]) -> Option<bool> {
    if !sql.contains("runtime_actor_state") {
        return None;
    }
    let Value::Text(key) = values.first()? else { return None };
    key.starts_with("routed/committed/").then_some(key == "routed/committed/")
}

pub(crate) fn committed_state_write(sql: &str, values: &[Value]) -> Option<bool> {
    // Footprint writes can join this table without changing a committed receipt.
    let direct = [
        "INSERT INTO runtime_actor_state(",
        "UPDATE runtime_actor_state ",
        "DELETE FROM runtime_actor_state ",
    ]
    .iter()
    .any(|prefix| sql.trim_start().starts_with(prefix));
    if direct { committed_state(sql, values) } else { None }
}

impl AccountDb {
    /// Starts an integration-test work observation on this connection only.
    #[must_use]
    pub fn observe_sql_work(&self) -> SqlWorkProbe {
        self.connection.observe_work()
    }

    /// Marks a synchronous source checkpoint while an observer is installed.
    #[must_use]
    pub fn observe_source_reads(&self) -> Option<SqlWorkScope> {
        self.connection.work_probe().map(|probe| probe.source_reads())
    }

    /// Marks the synchronous durable ACK checkpoint while an observer is installed.
    #[must_use]
    pub fn observe_ack_work(&self) -> Option<SqlWorkScope> {
        self.connection.work_probe().map(|probe| probe.acknowledgements())
    }
}

#[cfg(test)]
mod tests {
    use super::{committed_state, committed_state_write};
    use rusqlite::types::Value;

    #[test]
    fn receipt_write_counts_exclude_footprint_joins_and_keep_prefix_reads() {
        let key = [Value::Text("routed/committed/entry".to_owned())];
        assert_eq!(
            committed_state_write(
                "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                &key,
            ),
            Some(false)
        );
        assert_eq!(
            committed_state_write(
                "INSERT INTO message_footprint SELECT f.message_id FROM runtime_actor_state a \
                 JOIN message_footprint f ON f.locator=a.state_kind WHERE a.state_kind=?1",
                &key,
            ),
            None
        );
        assert_eq!(
            committed_state(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind>=?1",
                &[Value::Text("routed/committed/".to_owned())],
            ),
            Some(true)
        );
    }
}
