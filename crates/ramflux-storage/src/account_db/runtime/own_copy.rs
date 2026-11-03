// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transactional own-copy counters, bounded retention and indexed retry admission.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;
mod schema;
#[cfg(test)]
mod tests;

const PREFIXES: [&str; 6] = [
    "own-device/message-receipt/",
    "own-device/status/",
    "own-device/committed-packet/",
    "own-device/send/",
    "own-device/context-delivered/",
    "surface/own_context_announced/",
];
const EXPIRED: &str = "SELECT state_kind FROM runtime_own_copy_state WHERE namespace=?1 AND expires_at<=?2 ORDER BY expires_at,state_kind LIMIT ?3";
const VICTIMS: &str = "SELECT state_kind FROM runtime_own_copy_state WHERE namespace=?1 ORDER BY completed DESC,expires_at,state_kind LIMIT ?2";
const DUE: &str = "SELECT state_kind FROM runtime_own_copy_state WHERE namespace='own-device/send/' AND next_attempt_at<=?1 ORDER BY next_attempt_at,state_kind LIMIT ?2";
const USAGE: &str = "SELECT rows,bytes FROM runtime_own_copy_usage WHERE namespace=?1";

impl AccountDb {
    /// Reads transactional own-copy row/byte counters without walking the namespace.
    /// # Errors
    /// Rejects other namespaces and returns SQLite errors.
    pub fn own_copy_actor_usage(&self, prefix: &str) -> Result<(u64, u64), StorageError> {
        if !PREFIXES.contains(&prefix) {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(self
            .connection
            .query_row(USAGE, params![prefix], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }

    /// Selects only due retries, terminal budgets and expired held copies through the due index.
    /// Legacy rows are indexed at schema installation and receive no fresh retry allowance.
    /// # Errors
    /// Returns SQLite errors.
    pub fn due_own_copy_keys(&self, now: i64, limit: u32) -> Result<Vec<String>, StorageError> {
        Ok(self
            .connection
            .prepare(DUE)?
            .query_map(params![now, limit.min(256)], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Performs one bounded cleanup statement across all delivery namespaces.
    /// Reserves a disposable receipt/status slot at the cap; live replay proofs are never evicted.
    /// Reads at most 16 expired rows and 17 cap candidates per namespace; deletes one live cap victim.
    /// # Errors
    /// Returns SQL errors atomically with the caller's new copy or status transition.
    pub fn maintain_own_copy_delivery(&self, now: i64, limit: u32) -> Result<(), StorageError> {
        if limit == 0 || limit > 32_768 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            let mut victims = std::collections::BTreeSet::<String>::new();
            for (prefix, budget) in [
                (PREFIXES[0], limit), (PREFIXES[1], limit), (PREFIXES[2], limit),
                (PREFIXES[4], 1024), (PREFIXES[5], 0),
            ] {
                let (rows, next): (u64, i64) = self.connection.query_row(
                    "SELECT rows,next_cleanup_at FROM runtime_own_copy_usage WHERE namespace=?1",
                    params![prefix], |row| Ok((row.get(0)?,row.get(1)?)),
                )?;
                if rows == 0 || (rows < u64::from(budget) && next > now) {
                    continue;
                }
                self.connection.execute("UPDATE runtime_own_copy_usage SET next_cleanup_at=?2 WHERE namespace=?1",params![prefix,now.saturating_add(1)])?;
                let mut query = self.connection.prepare(EXPIRED)?;
                let expired = query.query_map(params![prefix, now, 16], |row| row.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?;
                let remaining = expired.iter().fold(rows, |count, _| count.saturating_sub(1));
                victims.extend(expired);
                if prefix != PREFIXES[2] && remaining >= u64::from(budget) {
                    let candidates = self.connection.prepare(VICTIMS)?.query_map(params![prefix, 17], |row| row.get(0))?
                        .collect::<rusqlite::Result<Vec<String>>>()?;
                    if let Some(victim) = candidates.into_iter().find(|key| !victims.contains(key)) {
                        victims.insert(victim);
                    }
                }
            }
            if victims.is_empty() {
                return Ok(());
            }
            // One delete step per copy, including the indexed footprint/binding deletion triggers.
            self.connection.execute(
                "DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT value FROM json_each(?1))",
                params![serde_json::to_string(&victims)?],
            )?;
            Ok(())
        })
    }

    pub(super) fn retain_indexed_own_copy_states(
        &self,
        prefix: &str,
        now: i64,
        limit: u32,
    ) -> Result<bool, StorageError> {
        if !PREFIXES[..3].contains(&prefix) {
            return Ok(false);
        }
        self.write_transaction(|| {
            self.connection.execute(
                &format!("DELETE FROM runtime_actor_state WHERE state_kind IN ({EXPIRED})"),
                params![prefix, now, 32_768],
            )?;
            let excess = self.own_copy_actor_usage(prefix)?.0.saturating_sub(u64::from(limit));
            self.connection.execute(
                &format!("DELETE FROM runtime_actor_state WHERE state_kind IN ({VICTIMS})"),
                params![prefix, excess],
            )?;
            Ok::<_, StorageError>(())
        })?;
        Ok(true)
    }
}
