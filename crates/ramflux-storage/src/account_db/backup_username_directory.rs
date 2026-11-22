// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore signed observation restrictions before generic actor arbitration; no live intent import.
use super::backup_database::BackupDatabase;
use super::username_directory::{
    FLOOR_PREFIX, INTENT_PREFIX, MAX_ROOTS, NAME_PREFIX, UsernameStorageError, decode_floor,
    decode_name, encode,
};
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

fn refusal(error: UsernameStorageError) -> StorageError {
    match error {
        UsernameStorageError::Storage(error) => error,
        UsernameStorageError::Refused(_) => StorageError::AuthorizationRejected,
    }
}

fn point(db: &rusqlite::Connection, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
    Ok(db
        .query_row(
            "SELECT state_json FROM main.runtime_actor_state WHERE state_kind=?1",
            [key],
            |row| row.get(0),
        )
        .optional()?)
}

fn put(db: &rusqlite::Connection, key: &str, bytes: &[u8]) -> Result<(), StorageError> {
    db.execute("INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",
        params![key, bytes])?;
    Ok(())
}

fn bound_union(db: &rusqlite::Connection, prefix: &str, upper: &str) -> Result<(), StorageError> {
    let count: u64 = db.query_row("SELECT count(*) FROM (SELECT state_kind FROM main.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 UNION SELECT state_kind FROM incoming.runtime_actor_state r WHERE state_kind>=?1 AND state_kind<?2 AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid))",
        params![prefix, upper], |row| row.get(0))?;
    if count > MAX_ROOTS {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}

fn page(
    db: &rusqlite::Connection,
    prefix: &str,
    upper: &str,
    after: &str,
) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
    let mut statement = db.prepare("SELECT state_kind,state_json FROM incoming.runtime_actor_state r WHERE state_kind>=?1 AND state_kind<?2 AND state_kind>?3 AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid) ORDER BY state_kind LIMIT 128")?;
    Ok(statement
        .query_map(params![prefix, upper, after], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

impl BackupDatabase {
    pub(super) fn merge_username_restrictions(&self) -> Result<(), StorageError> {
        bound_union(&self.db, FLOOR_PREFIX, "username/floor0")?;
        bound_union(&self.db, NAME_PREFIX, "username/name-pin0")?;
        let mut after = String::new();
        loop {
            let rows = page(&self.db, FLOOR_PREFIX, "username/floor0", &after)?;
            if rows.is_empty() {
                break;
            }
            for (key, bytes) in rows {
                let incoming = decode_floor(&bytes).map_err(refusal)?;
                if key != format!("{FLOOR_PREFIX}{}", incoming.root()) {
                    return Err(StorageError::AuthorizationRejected);
                }
                let merged = match point(&self.db, &key)? {
                    Some(local) => decode_floor(&local)
                        .map_err(refusal)?
                        .restriction_union(&incoming)
                        .map_err(refusal)?,
                    None => incoming,
                };
                put(&self.db, &key, &encode(&merged).map_err(refusal)?)?;
                after = key;
            }
        }
        after.clear();
        loop {
            let rows = page(&self.db, NAME_PREFIX, "username/name-pin0", &after)?;
            if rows.is_empty() {
                break;
            }
            for (key, bytes) in rows {
                let incoming = decode_name(&bytes).map_err(refusal)?;
                if key != format!("{NAME_PREFIX}{}", incoming.binding.body.name) {
                    return Err(StorageError::AuthorizationRejected);
                }
                let merged = match point(&self.db, &key)? {
                    Some(local) => {
                        let mut local = decode_name(&local).map_err(refusal)?;
                        let conflict = local.conflicted
                            || incoming.conflicted
                            || local.binding.body.principal_commitment
                                != incoming.binding.body.principal_commitment
                            || local.binding.body.epoch == incoming.binding.body.epoch
                                && local.binding != incoming.binding;
                        if !conflict && incoming.binding.body.epoch > local.binding.body.epoch {
                            local = incoming;
                        }
                        local.conflicted = conflict;
                        local
                    }
                    None => incoming,
                };
                put(&self.db, &key, &encode(&merged).map_err(refusal)?)?;
                after = key;
            }
        }
        self.merge_username_candidates()?;
        // User restores never turn a saved operation into a live daemon outbox.
        self.db.execute(
            "DELETE FROM main.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2",
            params![INTENT_PREFIX, "username/intent0"],
        )?;
        Ok(())
    }
}
