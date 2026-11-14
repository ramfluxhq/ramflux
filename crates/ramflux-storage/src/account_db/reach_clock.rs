// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Standalone durable UTC observations for reach operations; never nested in a fallible effect.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};
use std::time::Instant;

const KEY: &str = "reach/clock";
const MAX: u64 = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
fn invalid() -> StorageError {
    StorageError::Integrity("invalid reach clock observation or transaction boundary")
}
fn safe(time: u64) -> Result<u64, StorageError> {
    if time > MAX { Err(invalid()) } else { Ok(time) }
}

impl AccountDb {
    /// Commit a clock observation before entering an operation that may refuse or roll back.
    /// The monotonic projection advances while this account handle remains open.
    /// # Errors
    /// Refuses read-only/nested calls, unsafe UTC values and persistence failures.
    pub fn reach_fenced_now(&self, observed: u64) -> Result<u64, StorageError> {
        if !self.connection.is_autocommit()? || self.is_query_only()? {
            return Err(invalid());
        }
        safe(observed)?;
        let instant = Instant::now();
        let anchor = *self.reach_clock.borrow();
        let projected = match anchor {
            Some((start, base)) => Some(
                base.checked_add(
                    instant.checked_duration_since(start).ok_or_else(invalid)?.as_secs(),
                )
                .ok_or_else(invalid)?,
            ),
            None => None,
        };
        let transaction = self.connection.immediate_transaction()?;
        let previous = self.load_bounded_actor_state::<u64>(KEY, 32)?;
        let floor = safe(previous.unwrap_or(0))?;
        let now = safe(observed.max(floor).max(projected.unwrap_or(0)))?;
        if previous != Some(now) {
            self.persist_actor_state(KEY, &now)?;
        }
        transaction.commit()?;
        if anchor.is_none() || projected.is_none_or(|projected| now > projected) {
            *self.reach_clock.borrow_mut() = Some((instant, now));
        }
        Ok(now)
    }
}

fn read(connection: &Connection, incoming: bool) -> Result<Option<u64>, StorageError> {
    let sql = if incoming {
        "SELECT length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=32 THEN state_json ELSE NULL END FROM incoming.runtime_actor_state WHERE state_kind=?1"
    } else {
        "SELECT length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=32 THEN state_json ELSE NULL END FROM main.runtime_actor_state WHERE state_kind=?1"
    };
    let row: Option<(usize, Option<Vec<u8>>)> =
        connection.query_row(sql, params![KEY], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
    let Some((length, bytes)) = row else { return Ok(None) };
    if length > 32 {
        return Err(invalid());
    }
    Ok(Some(safe(serde_json::from_slice(&bytes.ok_or_else(invalid)?)?)?))
}

/// An encrypted merge can raise this floor, never replace it by an older observation.
pub(super) fn merge(connection: &Connection) -> Result<(), StorageError> {
    let local = read(connection, false)?;
    let incoming = read(connection, true)?;
    if let Some(now) = local.into_iter().chain(incoming).max() {
        connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",
            params![KEY, serde_json::to_vec(&now)?],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
