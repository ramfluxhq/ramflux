// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use rusqlite::OptionalExtension;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub type StoredObjects<T> = (Vec<T>, BTreeMap<String, [u8; 32]>);

impl AccountDb {
    pub fn upsert_object<T>(&self, write: &ObjectWrite<'_, T>) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        self.connection.execute(
            "INSERT OR REPLACE INTO object_index (
                object_id, chunk_manifest_hash, object_created_group_key_epoch, object_state,
                total_cipher_size, chunk_count, created_at, updated_at, manifest_hash, nonce,
                ciphertext, plaintext_hash, tombstoned, backup_excluded, object_content_key,
                object_body
             ) VALUES (
                ?1, ?2, NULL, ?3, ?4, 1, ?5, ?5, ?2, ?6, ?7, ?8, ?9, ?10, ?11, ?12
             )",
            params![
                write.object_id,
                write.manifest_hash.as_bytes(),
                if write.tombstoned { "tombstoned" } else { "available" },
                i64::try_from(write.ciphertext.len()).unwrap_or(i64::MAX),
                write.updated_at,
                write.nonce,
                write.ciphertext,
                write.plaintext_hash,
                i64::from(write.tombstoned),
                i64::from(write.backup_excluded),
                write.content_key.map(<[u8; 32]>::as_slice),
                serde_json::to_vec(write.object)?
            ],
        )?;
        Ok(())
    }

    pub fn set_object_tombstoned(&self, object_id: &str) -> Result<(), StorageError> {
        let object_body = self
            .connection
            .query_row(
                "SELECT object_body FROM object_index WHERE object_id = ?1",
                params![object_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(object_body) = object_body else {
            return Ok(());
        };
        let mut body: serde_json::Value = serde_json::from_slice(&object_body)?;
        if let Some(object) = body.as_object_mut() {
            object.insert("tombstoned".to_owned(), serde_json::Value::Bool(true));
        }
        self.connection.execute(
            "UPDATE object_index
                SET tombstoned = 1, object_state = 'tombstoned', object_body = ?2
              WHERE object_id = ?1",
            params![object_id, serde_json::to_vec(&body)?],
        )?;
        Ok(())
    }

    pub fn load_objects<T>(&self) -> Result<StoredObjects<T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT object_id, object_body, object_content_key
               FROM object_index
              WHERE object_body IS NOT NULL
              ORDER BY object_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        let mut objects = Vec::new();
        let mut object_keys = BTreeMap::new();
        for row in rows {
            let (object_id, body, key) = row?;
            objects.push(serde_json::from_slice(&body)?);
            if let Some(key) = key {
                let key: [u8; 32] = key.try_into().map_err(|bad: Vec<u8>| {
                    StorageError::KeyWrappingFailed(format!(
                        "invalid object content key length for {object_id}: {}",
                        bad.len()
                    ))
                })?;
                object_keys.insert(object_id, key);
            }
        }
        Ok((objects, object_keys))
    }

    pub fn upsert_object_transfer(
        &self,
        write: &ObjectTransferWrite<'_>,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT INTO object_transfer_state (
                transfer_id, object_id, direction, peer_device_id, manifest_hash, relay_endpoint,
                resume_token, missing_chunk_bitmap, completed_chunk_bitmap, state, last_error,
                chunk_size, total_bytes, done_bytes, total_chunks, next_chunk_index, updated_at,
                expires_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
             )
             ON CONFLICT(transfer_id) DO UPDATE SET
                direction = excluded.direction,
                peer_device_id = excluded.peer_device_id,
                manifest_hash = excluded.manifest_hash,
                relay_endpoint = excluded.relay_endpoint,
                resume_token = excluded.resume_token,
                missing_chunk_bitmap = excluded.missing_chunk_bitmap,
                completed_chunk_bitmap = excluded.completed_chunk_bitmap,
                state = excluded.state,
                last_error = excluded.last_error,
                chunk_size = excluded.chunk_size,
                total_bytes = excluded.total_bytes,
                done_bytes = excluded.done_bytes,
                total_chunks = excluded.total_chunks,
                next_chunk_index = excluded.next_chunk_index,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at",
            params![
                write.transfer_id,
                write.object_id,
                write.direction,
                write.peer_device_id,
                write.manifest_hash.as_bytes(),
                write.relay_endpoint,
                write.resume_token,
                serde_json::to_vec(write.missing_chunks)?,
                serde_json::to_vec(write.completed_chunks)?,
                write.state,
                write.last_error,
                i64::try_from(write.chunk_size).unwrap_or(i64::MAX),
                i64::try_from(write.total_bytes).unwrap_or(i64::MAX),
                i64::try_from(write.done_bytes).unwrap_or(i64::MAX),
                i64::from(write.total_chunks),
                write.next_chunk_index.map(i64::from),
                write.updated_at,
                write.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn object_transfer(
        &self,
        object_id: &str,
        direction: Option<&str>,
    ) -> Result<Option<ObjectTransferRecord>, StorageError> {
        let mut query = String::from(
            "SELECT transfer_id, object_id, direction, peer_device_id, manifest_hash,
                    relay_endpoint, resume_token, missing_chunk_bitmap, completed_chunk_bitmap,
                    state, last_error, chunk_size, total_bytes, done_bytes, total_chunks,
                    next_chunk_index, updated_at, expires_at
               FROM object_transfer_state
              WHERE object_id = ?1",
        );
        if direction.is_some() {
            query.push_str(" AND direction = ?2");
        }
        query.push_str(" ORDER BY updated_at DESC LIMIT 1");
        let mut statement = self.connection.prepare(&query)?;
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ObjectTransferRecord> {
            let manifest_hash: Vec<u8> = row.get(4)?;
            let missing: Vec<u8> = row.get(7)?;
            let completed: Vec<u8> = row.get(8)?;
            let chunk_size: i64 = row.get(11)?;
            let total_bytes: i64 = row.get(12)?;
            let done_bytes: i64 = row.get(13)?;
            let total_chunks: i64 = row.get(14)?;
            let next_chunk_index: Option<i64> = row.get(15)?;
            Ok(ObjectTransferRecord {
                transfer_id: row.get(0)?,
                object_id: row.get(1)?,
                direction: row.get(2)?,
                peer_device_id: row.get(3)?,
                manifest_hash: String::from_utf8_lossy(&manifest_hash).into_owned(),
                relay_endpoint: row.get(5)?,
                resume_token: row.get(6)?,
                missing_chunks: serde_json::from_slice(&missing).unwrap_or_default(),
                completed_chunks: serde_json::from_slice(&completed).unwrap_or_default(),
                state: row.get(9)?,
                last_error: row.get(10)?,
                chunk_size: u64::try_from(chunk_size).unwrap_or(0),
                total_bytes: u64::try_from(total_bytes).unwrap_or(0),
                done_bytes: u64::try_from(done_bytes).unwrap_or(0),
                total_chunks: u32::try_from(total_chunks).unwrap_or(0),
                next_chunk_index: next_chunk_index.and_then(|value| u32::try_from(value).ok()),
                updated_at: row.get(16)?,
                expires_at: row.get(17)?,
            })
        };
        if let Some(direction) = direction {
            Ok(statement.query_row(params![object_id, direction], mapper).optional()?)
        } else {
            Ok(statement.query_row(params![object_id], mapper).optional()?)
        }
    }
}
