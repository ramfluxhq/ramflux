// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::row_mappers::object_share_grant_from_row;
use rusqlite::OptionalExtension;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub type StoredObject<T> = (T, Option<[u8; 32]>);

pub type StoredObjects<T> = (Vec<T>, BTreeMap<String, [u8; 32]>);
struct ObjectPayloadRow {
    row_id: i64,
    manifest: Option<String>,
    body: Vec<u8>,
    key: Option<Vec<u8>>,
}
#[derive(Default)]
struct ObjectKeyAccumulator(BTreeMap<String, [u8; 32]>);
impl Drop for ObjectKeyAccumulator {
    fn drop(&mut self) {
        for key in self.0.values_mut() {
            zeroize::Zeroize::zeroize(key);
        }
    }
}

impl AccountDb {
    pub fn upsert_object<T: Serialize>(
        &self,
        write: &ObjectWrite<'_, T>,
    ) -> Result<(), StorageError> {
        self.upsert_object_checked(write, false)
    }

    /// # Errors
    /// Replaces only the expected unowned identity; an erased wire id requires explicit absence.
    pub fn replace_object<T: Serialize>(
        &self,
        expected_manifest: Option<&str>,
        write: &ObjectWrite<'_, T>,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let previous: Option<Vec<u8>> = self.connection.query_row("SELECT manifest_hash FROM object_index WHERE object_id=?1", params![write.object_id], |row| row.get(0)).optional()?;
            if previous.as_deref() != expected_manifest.map(str::as_bytes) { return Err(StorageError::ObjectIdentityConflict); }
            let owned: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_retention_payload p JOIN object_retention_reference r USING(commitment) JOIN object_message_reference m USING(reference_hash) WHERE p.wire_id=?1 AND p.manifest_hash<>?2)", params![write.object_id,write.manifest_hash], |r| r.get(0))?;
            if owned { return Err(StorageError::ObjectIdentityConflict); }
            let verified = ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, write.ciphertext);
            if verified != write.manifest_hash { return Err(StorageError::ObjectIdentityConflict); }
            if let Some(expected) = expected_manifest {
                if expected == write.manifest_hash { return Err(StorageError::ObjectIdentityConflict); }
                self.retain_object(write.object_id, expected, super::object_retention::ObjectRetention::Standalone)?;
                let digest = ramflux_crypto::object_erasure_commitment(&self.principal_commitment, write.object_id, expected);
                self.connection.execute("INSERT INTO object_erasure_work VALUES(?1,?2,?3)", params![digest,write.object_id,expected])?;
                let sql = self.connection.call(|db| super::object_retention::payload_erasure_body(db))?;
                self.connection.execute_batch(&sql)?;
            }
            self.upsert_object_checked(write, true)?;
            self.connection.execute("INSERT INTO object_identity_replacement VALUES(?1) ON CONFLICT DO NOTHING",params![ramflux_crypto::object_erasure_commitment(&self.principal_commitment,write.object_id,write.manifest_hash)])?;
            self.retain_object(write.object_id, write.manifest_hash, super::object_retention::ObjectRetention::Standalone)
        })
    }

    fn upsert_object_checked<T>(
        &self,
        write: &ObjectWrite<'_, T>,
        replacement: bool,
    ) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        self.write_transaction(|| {
            self.check_object_identity(write.object_id, write.manifest_hash)?;
            let previous: Option<Vec<u8>> = self
                .connection
                .query_row(
                    "SELECT manifest_hash FROM object_index WHERE object_id=?1",
                    params![write.object_id],
                    |row| row.get(0),
                )
                .optional()?;
            if previous.is_none() && !replacement {
                let lookup = ramflux_crypto::object_erasure_lookup(
                    &self.principal_commitment,
                    write.object_id,
                );
                let retired: bool = self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1)",
                    params![lookup],
                    |r| r.get(0),
                )?;
                if retired {
                    return Err(StorageError::ObjectIdentityConflict);
                }
            }
            if previous
                .as_deref()
                .is_some_and(|previous| previous != write.manifest_hash.as_bytes())
            {
                return Err(StorageError::ObjectIdentityConflict);
            }
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
        })
    }

    pub fn set_object_tombstoned(&self, object_id: &str) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.check_object_access(object_id)?;
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
        })
    }

    pub fn record_object_share_grant(
        &self,
        write: &ObjectShareGrantWrite<'_>,
    ) -> Result<ObjectShareGrantRecord, StorageError> {
        self.write_transaction(|| {
            self.check_object_access(write.object_id)?;
            self.connection.execute(
                "INSERT INTO object_share_grant_projection (
                object_id, recipient_principal_id, recipient_principal_commitment,
                recipient_device_id, conversation_id, shared_at, revoked_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
             ON CONFLICT(object_id, recipient_principal_id) DO UPDATE SET
                recipient_principal_commitment = excluded.recipient_principal_commitment,
                recipient_device_id = excluded.recipient_device_id,
                conversation_id = excluded.conversation_id,
                shared_at = excluded.shared_at,
                revoked_at = NULL",
                params![
                    write.object_id,
                    write.recipient_principal_id,
                    write.recipient_principal_commitment,
                    write.recipient_device_id,
                    write.conversation_id,
                    write.shared_at,
                ],
            )?;
            self.object_share_grant(write.object_id, write.recipient_principal_id)?
                .ok_or_else(|| StorageError::MessageNotFound(write.object_id.to_owned()))
        })
    }

    pub fn object_share_grants_for_recipients(
        &self,
        recipient_principal_ids: &[&str],
    ) -> Result<Vec<ObjectShareGrantRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT object_id, recipient_principal_id, recipient_principal_commitment,
                    recipient_device_id, conversation_id, shared_at, revoked_at
               FROM object_share_grant_projection
              WHERE recipient_principal_id = ?1 AND revoked_at IS NULL
              ORDER BY shared_at ASC, object_id ASC",
        )?;
        let mut grants = Vec::new();
        for recipient_principal_id in recipient_principal_ids {
            let rows = statement
                .query_map(params![recipient_principal_id], object_share_grant_from_row)?;
            for row in rows {
                grants.push(row?);
            }
        }
        Ok(grants)
    }

    pub fn object_share_grant(
        &self,
        object_id: &str,
        recipient_principal_id: &str,
    ) -> Result<Option<ObjectShareGrantRecord>, StorageError> {
        self.check_object_access(object_id)?;
        Ok(self
            .connection
            .query_row(
                "SELECT object_id, recipient_principal_id, recipient_principal_commitment,
                        recipient_device_id, conversation_id, shared_at, revoked_at
                   FROM object_share_grant_projection
                  WHERE object_id = ?1 AND recipient_principal_id = ?2",
                params![object_id, recipient_principal_id],
                object_share_grant_from_row,
            )
            .optional()?)
    }

    pub fn revoke_object_share_grant(
        &self,
        object_id: &str,
        recipient_principal_id: &str,
        revoked_at: i64,
    ) -> Result<Option<ObjectShareGrantRecord>, StorageError> {
        self.connection.execute(
            "UPDATE object_share_grant_projection
                SET revoked_at = COALESCE(revoked_at, ?3)
              WHERE object_id = ?1 AND recipient_principal_id = ?2",
            params![object_id, recipient_principal_id, revoked_at],
        )?;
        self.object_share_grant(object_id, recipient_principal_id)
    }

    /// # Errors
    /// Returns an error if the object row, serialized body or content key is invalid.
    pub fn load_object<T: DeserializeOwned>(
        &self,
        object_id: &str,
    ) -> Result<Option<StoredObject<T>>, StorageError> {
        self.check_object_access(object_id)?;
        let row:Option<ObjectPayloadRow>=self.connection.query_row(
            "SELECT rowid,object_body,object_content_key,CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id=?1 AND object_body IS NOT NULL",
            params![object_id],|row|Ok(ObjectPayloadRow {row_id:row.get(0)?,manifest:row.get(3)?,body:row.get(1)?,key:row.get(2)?}),
        ).optional()?;
        row.map(|ObjectPayloadRow { row_id: rowid, body, key, manifest }| {
            let body = zeroize::Zeroizing::new(body);
            let key = key
                .map(|key| {
                    let key = zeroize::Zeroizing::new(key);
                    let value: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                        StorageError::KeyWrappingFailed("invalid object content key length".into())
                    })?;
                    Ok::<_, StorageError>(zeroize::Zeroizing::new(value))
                })
                .transpose()?;
            let object = super::object_payload::decode(&self.connection, rowid, &body)?;
            if let Some(manifest) = manifest {
                self.check_object_identity(object_id, &manifest)?;
            }
            Ok((object, key.as_deref().copied()))
        })
        .transpose()
    }

    /// # Errors
    /// Returns an error if the bounded persisted object cache page cannot be decoded.
    pub fn load_recent_objects<T: DeserializeOwned>(
        &self,
        limit: usize,
    ) -> Result<StoredObjects<T>, StorageError> {
        let mut statement = self.connection.prepare("SELECT object_id FROM object_index WHERE object_body IS NOT NULL AND length(ciphertext)<=1048576 ORDER BY updated_at DESC,object_id LIMIT ?1")?;
        let ids = statement
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut objects = Vec::with_capacity(ids.len());
        let mut keys = ObjectKeyAccumulator::default();
        for id in ids {
            if let Some((object, key)) = self.load_object::<T>(&id)? {
                objects.push(object);
                if let Some(key) = key {
                    keys.0.insert(id, key);
                }
            }
        }
        Ok((objects, std::mem::take(&mut keys.0)))
    }

    pub fn load_objects<T>(&self) -> Result<StoredObjects<T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT object_id FROM object_index WHERE object_body IS NOT NULL ORDER BY object_id",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut objects = Vec::new();
        let mut object_keys = ObjectKeyAccumulator::default();
        for id in ids {
            if let Some((object, key)) = self.load_object(&id)? {
                objects.push(object);
                if let Some(key) = key {
                    object_keys.0.insert(id, key);
                }
            }
        }
        Ok((objects, std::mem::take(&mut object_keys.0)))
    }

    pub fn upsert_object_transfer(
        &self,
        write: &ObjectTransferWrite<'_>,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.check_object_identity(write.object_id, write.manifest_hash)?;
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
        })
    }

    pub fn object_transfer(
        &self,
        object_id: &str,
        direction: Option<&str>,
    ) -> Result<Option<ObjectTransferRecord>, StorageError> {
        self.check_object_access(object_id)?;
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
        let mapper = |row: &crate::database::Row| -> rusqlite::Result<ObjectTransferRecord> {
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

    /// T25-A2 (OBJ-IPC-01): upsert the per-`object_id` reconciliation record. Single-statement,
    /// autocommitted + fsync-durable (`SQLite` FULL synchronous). `created_at` is preserved across
    /// updates (only set on first insert); every other column is overwritten from `write`.
    pub fn upsert_object_operation(
        &self,
        write: &ObjectOperationWrite<'_>,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            if let Some(manifest) = write.manifest_hash {
                self.check_object_identity(write.object_id, manifest)?;
            } else {
                self.check_object_access(write.object_id)?;
            }
            self.connection.execute(
                "INSERT INTO object_operation (
                object_id, operation_id, state, request_hash, manifest_hash, plaintext_hash,
                terminal_result, last_error, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(object_id) DO UPDATE SET
                operation_id = excluded.operation_id,
                state = excluded.state,
                request_hash = excluded.request_hash,
                manifest_hash = excluded.manifest_hash,
                plaintext_hash = excluded.plaintext_hash,
                terminal_result = excluded.terminal_result,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at",
                params![
                    write.object_id,
                    write.operation_id,
                    write.state,
                    write.request_hash.as_bytes(),
                    write.manifest_hash,
                    write.plaintext_hash,
                    write.terminal_result,
                    write.last_error,
                    write.created_at,
                    write.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    /// Reads the reconciliation record for `object_id`, if any.
    pub fn object_operation(
        &self,
        object_id: &str,
    ) -> Result<Option<ObjectOperationRecord>, StorageError> {
        self.check_object_access(object_id)?;
        Ok(self
            .connection
            .query_row(
                "SELECT object_id, operation_id, state, request_hash, manifest_hash,
                        plaintext_hash, terminal_result, last_error, created_at, updated_at
                   FROM object_operation
                  WHERE object_id = ?1",
                params![object_id],
                |row| {
                    let request_hash: Vec<u8> = row.get(3)?;
                    let terminal_result: Option<Vec<u8>> = row.get(6)?;
                    Ok(ObjectOperationRecord {
                        object_id: row.get(0)?,
                        operation_id: row.get(1)?,
                        state: row.get(2)?,
                        request_hash: String::from_utf8_lossy(&request_hash).into_owned(),
                        manifest_hash: row.get(4)?,
                        plaintext_hash: row.get(5)?,
                        terminal_result: terminal_result
                            .and_then(|bytes| serde_json::from_slice(&bytes).ok()),
                        last_error: row.get(7)?,
                        created_at: row.get(8)?,
                        updated_at: row.get(9)?,
                    })
                },
            )
            .optional()?)
    }

    /// T25-A2 (OBJ-IPC-01) P0-1: atomically commit the local object AND advance the operation
    /// record in ONE `SQLCipher` transaction. `immediate_transaction` opens a `BEGIN IMMEDIATE` on this
    /// connection; both single-statement writes run inside it and `commit()` issues one
    /// fsync-durable `COMMIT`. A crash between "no object" and "object durable" cannot happen — the
    /// object row and the `LocalCommitted` operation state become durable together or not at all.
    pub fn commit_object_local<T>(
        &self,
        object: &ObjectWrite<'_, T>,
        operation: &ObjectOperationWrite<'_>,
    ) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        let transaction = self.connection.immediate_transaction()?;
        self.retain_object(
            object.object_id,
            object.manifest_hash,
            super::object_retention::ObjectRetention::Standalone,
        )?;
        self.upsert_object(object)?;
        self.upsert_object_operation(operation)?;
        transaction.commit()?;
        Ok(())
    }
}
