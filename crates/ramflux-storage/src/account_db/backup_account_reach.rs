// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Merge only signed reach floors; archived pending sends never become live work.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use ramflux_protocol::account_reach::ReachRecord;
use rusqlite::{OptionalExtension, params};

fn decode(bytes: &[u8], key: &str) -> Result<ReachRecord, StorageError> {
    let record: ReachRecord = serde_json::from_slice(bytes)?;
    ramflux_crypto::account_reach::verify_reach_policy(&record.policy, &record.authority)
        .map_err(|_| StorageError::AuthorizationRejected)?;
    if key != format!("reach/floor/{}", record.policy.body.account_anchor) {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(record)
}

impl BackupDatabase {
    pub(super) fn merge_account_reach(&self) -> Result<(), StorageError> {
        self.db.execute("INSERT OR REPLACE INTO main.runtime_actor_state(state_kind,state_json) SELECT state_kind,state_json FROM incoming.runtime_actor_state r WHERE length(state_kind)<=128 AND state_kind>='reach/fence/' AND state_kind<'reach/fence0' AND CAST(state_json AS TEXT)='true' AND EXISTS(SELECT 1 FROM incoming.runtime_actor_state f WHERE f.state_kind='reach/floor/'||substr(r.state_kind,13)) AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid)", [])?;
        let mut after = String::new();
        loop {
            let mut statement = self.db.prepare("SELECT CASE WHEN length(state_kind)<=128 THEN state_kind END,CASE WHEN length(state_json)<=1048576 THEN state_json END FROM incoming.runtime_actor_state r WHERE state_kind> ?1 AND state_kind>='reach/floor/' AND state_kind<'reach/floor0' AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid) ORDER BY state_kind LIMIT 8")?;
            let rows = statement
                .query_map([&after], |row| {
                    Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.is_empty() {
                break;
            }
            for (key, bytes) in rows {
                let key = key.ok_or(StorageError::AuthorizationRejected)?;
                let bytes = bytes.ok_or(StorageError::AuthorizationRejected)?;
                let incoming = decode(&bytes, &key)?;
                let old: Option<Vec<u8>> = self
                    .db
                    .query_row(
                        "SELECT state_json FROM main.runtime_actor_state WHERE state_kind=?1",
                        [&key],
                        |row| row.get(0),
                    )
                    .optional()?;
                let selected = if let Some(old) = old {
                    let old = decode(&old, &key)?;
                    if old.policy.body.revision == incoming.policy.body.revision && old != incoming
                    {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    if old.policy.body.revision > incoming.policy.body.revision {
                        old
                    } else {
                        incoming
                    }
                } else {
                    incoming
                };
                self.db.execute("INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json", params![key, serde_json::to_vec(&selected)?])?;
                // An archived floor is not the home's current state: the restored account must
                // observe a live home reach read (the SDK clears this local marker) before it
                // exports a card or signs a reach change. The marker is not an archived range.
                self.db.execute(
                    "INSERT OR REPLACE INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                    params![
                        format!("reach/sync/{}", selected.policy.body.account_anchor),
                        serde_json::to_vec(&true)?
                    ],
                )?;
                after = key;
            }
        }
        self.db.execute("DELETE FROM main.runtime_actor_state WHERE (state_kind>='reach/outbox/' AND state_kind<'reach/outbox0') OR (state_kind>='reach/change/' AND state_kind<'reach/change0')", [])?;
        Ok(())
    }
}
