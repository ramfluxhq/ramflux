// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore staged public bytes as bounded inactive hints, including the target's uncertain work.
use super::{
    backup_database::BackupDatabase,
    username_candidates::{self as candidates, UsernameRecoveryCandidate},
    username_directory::UsernameStorageError,
};
use crate::StorageError;
use rusqlite::params;

fn refusal(error: UsernameStorageError) -> StorageError {
    match error {
        UsernameStorageError::Storage(error) => error,
        UsernameStorageError::Refused(_) => StorageError::AuthorizationRejected,
    }
}
#[derive(Clone, Copy)]
enum Source {
    TargetIntent,
    IncomingIntent,
    IncomingInactive,
}
impl Source {
    fn parts(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::TargetIntent => ("main", "username/intent/", "username/intent0"),
            Self::IncomingIntent => ("incoming", "username/intent/", "username/intent0"),
            Self::IncomingInactive => ("incoming", "username/inactive/", "username/inactive0"),
        }
    }
}
impl BackupDatabase {
    pub(super) fn merge_username_candidates(&self) -> Result<(), StorageError> {
        for source in [Source::TargetIntent, Source::IncomingIntent, Source::IncomingInactive] {
            self.merge_username_candidate_source(source)?;
        }
        Ok(())
    }
    fn merge_username_candidate_source(&self, source: Source) -> Result<(), StorageError> {
        let (schema, prefix, upper) = source.parts();
        let mut after = String::new();
        loop {
            // The schema is a closed local enum. Blob/key lengths are checked inside SQLite,
            // before allocating any archive-supplied value in the product process.
            let sql = format!(
                "SELECT CASE WHEN length(state_kind)<=128 THEN state_kind END,CASE WHEN length(state_json)<=131072 THEN state_json END FROM {schema}.runtime_actor_state r WHERE state_kind>=?1 AND state_kind<?2 AND state_kind>?3 AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='{schema}' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid) ORDER BY state_kind LIMIT 8"
            );
            let mut statement = self.db.prepare(&sql)?;
            let rows = statement
                .query_map(params![prefix, upper, after], |row| {
                    Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.is_empty() {
                break;
            }
            for (key, bytes) in rows {
                let key = key.ok_or(StorageError::AuthorizationRejected)?;
                let bytes = bytes.ok_or(StorageError::AuthorizationRejected)?;
                let root = key.strip_prefix(prefix).ok_or(StorageError::AuthorizationRejected)?;
                let incoming = if matches!(source, Source::IncomingInactive) {
                    candidates::decode_candidates(&bytes).map_err(refusal)?
                } else {
                    if bytes.len() > 16384 {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    vec![serde_json::from_slice::<UsernameRecoveryCandidate>(&bytes)?]
                };
                for candidate in &incoming {
                    candidate.validate_shape().map_err(refusal)?;
                    if candidate.root() != root {
                        return Err(StorageError::AuthorizationRejected);
                    }
                }
                candidates::retain(&self.db, &incoming).map_err(refusal)?;
                after = key;
            }
        }
        Ok(())
    }
}
