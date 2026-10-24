// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Nested atomic surface projections and bounded account-owned history reads.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Runs a surface update atomically inside or outside a receive transaction, without I/O.
    /// # Errors
    /// Rolls back all projection/receipt writes on any callback or SQLite failure.
    pub fn surface_transaction<T, E>(&self, write: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        self.connection
            .execute_batch("SAVEPOINT surface_projection")
            .map_err(StorageError::from)?;
        match write() {
            Ok(value) => {
                if let Err(error) = self.connection.execute_batch("RELEASE surface_projection") {
                    let _ = self.connection.execute_batch(
                        "ROLLBACK TO surface_projection; RELEASE surface_projection",
                    );
                    return Err(StorageError::from(error).into());
                }
                Ok(value)
            }
            Err(error) => {
                self.connection
                    .execute_batch("ROLLBACK TO surface_projection; RELEASE surface_projection")
                    .map_err(StorageError::from)?;
                Err(error)
            }
        }
    }
    /// Replaces an authenticated surface carrier with its validated text fallback.
    /// # Errors
    /// Returns database errors. Conversation identity must match the stored row.
    pub fn replace_surface_message_content(
        &self,
        conversation: &str,
        message: &str,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.connection.execute("INSERT INTO runtime_message_content(message_id,conversation_id,body) VALUES(?1,?2,?3) ON CONFLICT(message_id) DO UPDATE SET body=excluded.body WHERE runtime_message_content.conversation_id=excluded.conversation_id", params![message,conversation,body])?;
        Ok(())
    }
    /// Removes one private surface projection record inside the caller's transaction.
    /// # Errors
    /// Returns database failures; callers supply only account-owned surface keys.
    pub fn delete_surface_state(&self, key: &str) -> Result<(), StorageError> {
        if !key.starts_with("surface/") {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection
            .execute("DELETE FROM runtime_actor_state WHERE state_kind=?1", params![key])?;
        Ok(())
    }
    /// Retains bounded private surface history/actions, preserving the just-written record.
    /// # Errors
    /// Returns SQL errors or rejects a record that alone exceeds the caller's byte budget.
    /// Call inside `surface_transaction` so a failed budget check rolls back the write.
    pub fn prune_surface_records(
        &self,
        prefix: &str,
        max_rows: u32,
        max_bytes: u64,
        preserve: &str,
    ) -> Result<(), StorageError> {
        if !(prefix.starts_with("surface/history/")
            || prefix.starts_with("surface/actions/")
            || prefix.starts_with("surface/authored/"))
            || !preserve.starts_with(prefix)
            || max_rows == 0
            || max_bytes == 0
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let mut query=self.connection.prepare("SELECT state_kind,length(state_json) FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 ORDER BY json_extract(CAST(state_json AS TEXT),'$.version'),state_kind")?;
        let rows = query
            .query_map(params![prefix], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?.unsigned_abs()))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut count = rows.len();
        let mut bytes = rows.iter().try_fold(0u64, |sum, (_, size)| {
            sum.checked_add(*size).ok_or(StorageError::AuthorizationRejected)
        })?;
        let max_rows =
            usize::try_from(max_rows).map_err(|_| StorageError::AuthorizationRejected)?;
        for (key, size) in rows {
            if count <= max_rows && bytes <= max_bytes {
                break;
            }
            if key == preserve {
                continue;
            }
            self.delete_surface_state(&key)?;
            count -= 1;
            bytes -= size;
        }
        if count > max_rows || bytes > max_bytes {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(())
    }
    /// Reads bounded private records together with their exact account-owned keys.
    /// # Errors
    /// Returns database or decoding failures. At most 101 rows are returned.
    pub fn surface_record_page<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<(String, T)>, StorageError> {
        if !prefix.starts_with("surface/") {
            return Err(StorageError::AuthorizationRejected);
        }
        let mut query=self.connection.prepare("SELECT state_kind,state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 AND state_kind>?2 ORDER BY state_kind LIMIT ?3")?;
        query
            .query_map(params![prefix, after, limit.min(101)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .map(|row| {
                let (key, bytes) = row?;
                Ok((key, serde_json::from_slice(&bytes)?))
            })
            .collect()
    }
    /// Private actor-state history page; callers must enforce their account/conversation scope.
    /// # Errors
    /// Returns SQL/JSON errors; pages never exceed 101 rows.
    pub fn surface_history_page<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<T>, StorageError> {
        let mut query=self.connection.prepare("SELECT state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 AND state_kind>?2 ORDER BY state_kind LIMIT ?3")?;
        query
            .query_map(params![prefix, after, limit.min(101)], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(serde_json::from_slice(&row?)?))
            .collect()
    }
}

impl super::AccountDb {
    /// Reads recent surface rows in insertion order; updates preserve the row's original order.
    /// A `before` cursor pages towards older rows. Exporters reverse each page for oldest-first output.
    /// # Errors
    /// Rejects unrelated namespaces and returns database or decoding errors.
    pub fn surface_recent_records<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<(i64, T)>, crate::StorageError> {
        if !(prefix.starts_with("surface/") || prefix == "directory/surface/") {
            return Err(crate::StorageError::AuthorizationRejected);
        }
        let mut query=self.connection.prepare("SELECT rowid,state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 AND rowid<?2 ORDER BY rowid DESC LIMIT ?3")?;
        let rows = query
            .query_map(
                rusqlite::params![prefix, before.unwrap_or(i64::MAX), limit.min(129)],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|(id, bytes)| Ok((id, serde_json::from_slice(&bytes)?))).collect()
    }
}

impl AccountDb {
    /// Exportable state only, prioritizing this account's authorship over peer state.
    /// The opaque signed cursor preserves that priority across bounded pages.
    /// # Errors
    /// Returns database/JSON errors. Placeholder directory rows are never read.
    pub fn surface_export_records<T: serde::de::DeserializeOwned>(
        &self,
        owner: &str,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<(i64, T)>, StorageError> {
        let mut query = self.connection.prepare("SELECT export_order,state_json FROM (SELECT CASE WHEN json_extract(CAST(state_json AS TEXT),'$.author_principal_id')=?1 THEN rowid ELSE rowid-9223372036854775807 END AS export_order,state_json FROM runtime_actor_state WHERE substr(state_kind,1,14)='surface/state/') WHERE export_order<?2 ORDER BY export_order DESC LIMIT ?3")?;
        let rows = query
            .query_map(params![owner, before.unwrap_or(i64::MAX), limit.min(65)], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(order, bytes)| Ok((order, serde_json::from_slice(&bytes)?)))
            .collect()
    }
    /// Removes a transient directory entry that never acquired a validated checkpoint.
    /// # Errors
    /// Returns database failures.
    pub fn delete_surface_placeholder(&self, reference: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind=?1",
            params![format!("directory/surface/{reference}")],
        )?;
        Ok(())
    }
}
