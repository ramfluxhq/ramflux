// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private, worker-owned encrypted staging access and bounded attachment verification.

use crate::{AccountDbKey, BackupCounts, StorageError};
use rusqlite::params;
use std::path::Path;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BackupAttachmentVerification {
    pub verified: u64,
    pub mismatched: u64,
    pub missing: u64,
    pub unavailable_at_source: u64,
    pub local_missing_kept: u64,
}

pub struct BackupDatabase {
    pub(crate) db: rusqlite::Connection,
}
impl BackupDatabase {
    /// Opens a private snapshot or an owner-guarded generation for restore checks.
    /// Never use this worker handle as an active live account writer.
    /// # Errors
    /// Returns authentication, schema or I/O errors.
    pub fn open(path: &Path, key: &AccountDbKey) -> Result<Self, StorageError> {
        let db = rusqlite::Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(&format!("PRAGMA key=\"x'{}'\"; PRAGMA cache_size=-2048; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",key.sqlcipher_hex()))?;
        let fingerprint: String = db.query_row(
            "SELECT key_fingerprint FROM account_key_check WHERE singleton_id=1",
            [],
            |row| row.get(0),
        )?;
        if fingerprint != key.fingerprint() {
            return Err(StorageError::AccountKeyMismatch);
        }
        let opened = Self { db };
        opened.ensure_missing_manifest()?;
        opened.db.execute_batch(crate::schema_contact_requests::HELD_MESSAGE_FENCES)?;
        opened.db.execute_batch(crate::schema_contact_requests::CONSENT_DECISIONS)?;
        Ok(opened)
    }
    /// Copies a quiesced generation to a fresh encrypted private generation.
    /// # Errors
    /// Returns snapshot, encryption or filesystem errors.
    pub fn copy_to(&self, path: &Path, key: &AccountDbKey) -> Result<(), StorageError> {
        if path.exists() {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let parent = path.parent().ok_or(StorageError::AuthorizationRejected)?;
        let estimate: u64 = self.db.query_row(
            "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
            [],
            |r| r.get(0),
        )?;
        require_space(parent, estimate.saturating_add(20 * 1024 * 1024))?;
        let mut target = rusqlite::Connection::open(path)?;
        target.busy_timeout(std::time::Duration::from_secs(5))?;
        target.execute_batch(&format!(
            "PRAGMA key=\"x'{}'\"; PRAGMA synchronous=FULL; PRAGMA cache_size=-2048;",
            key.sqlcipher_hex()
        ))?;
        {
            let backup = rusqlite::backup::Backup::new(&self.db, &mut target)?;
            loop {
                match backup.step(128)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => {
                        require_space(parent, 2 * 1024 * 1024)?;
                    }
                    _ => return Err(StorageError::AuthorizationRejected),
                }
            }
        }
        target.execute(
            "UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1",
            params![key.fingerprint()],
        )?;
        drop(target);
        std::fs::File::open(path)?.sync_all()?;
        Ok(())
    }
    /// Enqueues ordinary read-model invalidations and a final restore event in commit order.
    /// # Errors
    /// Returns SQL errors in the private generation before it is selected.
    pub fn enqueue_restore_events(&self, account: &str, job: &str) -> Result<(), StorageError> {
        let tx = self.db.unchecked_transaction()?;
        self.db.execute_batch("INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json) SELECT 'runtime_actor_state','update',rowid,json_object('state_kind',state_kind) FROM runtime_actor_state WHERE state_kind LIKE 'directory/%'; INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json) SELECT 'direct_message_projection','update',rowid,json_object('conversation_id',conversation_id,'message_id',message_id) FROM direct_message_projection;")?;
        self.db.execute("INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json) VALUES('backup_restore','install',0,?1)",params![serde_json::to_string(&serde_json::json!({"local_account_id":account,"job_id":job}))?])?;
        tx.commit()?;
        Ok(())
    }
    /// Stores private restore metadata in encrypted account state.
    /// # Errors
    /// Returns SQL or serialization errors.
    pub fn put_state(&self, name: &str, value: &impl serde::Serialize) -> Result<(), StorageError> {
        self.db.execute(
            "INSERT OR REPLACE INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![name, serde_json::to_vec(value)?],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns SQLite corruption/integrity errors without installing any data.
    pub fn check_integrity(&self) -> Result<(), StorageError> {
        let result: String = self.db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(())
    }
    /// Re-encrypts verified staging with a fresh RAM-only key.
    /// # Errors
    /// Returns `SQLCipher` rekey or fingerprint update errors.
    pub fn rekey(&self, key: &AccountDbKey) -> Result<(), StorageError> {
        self.db.execute_batch(&format!("PRAGMA rekey=\"x'{}'\";", key.sqlcipher_hex()))?;
        self.db.execute(
            "UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1",
            params![key.fingerprint()],
        )?;
        Ok(())
    }
    /// # Errors
    /// Returns SQL errors; counts have no row limit.
    pub fn counts(&self) -> Result<BackupCounts, StorageError> {
        Ok(super::backup::read_counts(&self.db)?)
    }
    /// Authenticates every attachment and both hashes, streaming BLOBs in bounded buffers.
    /// # Errors
    /// Returns SQLite/I/O errors. Missing or corrupt files are counted, never omitted.
    pub fn verify_attachments(
        &self,
        progress: impl FnMut(u64, u64) -> Result<(), StorageError>,
    ) -> Result<BackupAttachmentVerification, StorageError> {
        self.verify_attachments_scope(false, progress)
    }
    pub(super) fn verify_attachments_scope(
        &self,
        archive_only: bool,
        mut progress: impl FnMut(u64, u64) -> Result<(), StorageError>,
    ) -> Result<BackupAttachmentVerification, StorageError> {
        let mut checks = BackupAttachmentVerification::default();
        let predicate = if archive_only {
            " AND EXISTS(SELECT 1 FROM incoming.object_index source WHERE source.object_id=object_index.object_id AND source.backup_excluded=0)"
        } else {
            ""
        };
        let mut statement=self.db.prepare(&format!("SELECT rowid,object_id,CAST(manifest_hash AS TEXT),plaintext_hash,object_content_key,length(ciphertext) FROM object_index WHERE backup_excluded=0{predicate} ORDER BY rowid"))?;
        let mut rows = statement.query([])?;
        let mut bytes = 0_u64;
        while let Some(row) = rows.next()? {
            let rowid: i64 = row.get(0)?;
            let id: String = row.get(1)?;
            let manifest: String = row.get(2)?;
            let plaintext: String = row.get(3)?;
            let key: Option<Vec<u8>> = row.get(4)?;
            let size: u64 = row.get(5)?;
            let Some(key) = key.filter(|key| key.len() == 32) else {
                checks.missing += 1;
                continue;
            };
            let key = zeroize::Zeroizing::new(key);
            let key = zeroize::Zeroizing::new(
                <[u8; 32]>::try_from(key.as_slice())
                    .map_err(|_| StorageError::AuthorizationRejected)?,
            );
            let mut blob = self.db.blob_open("main", "object_index", "ciphertext", rowid, true)?;
            let mut checked = ProgressBlob {
                inner: &mut blob,
                check: || progress(checks.verified + checks.mismatched + checks.missing, bytes),
            };
            if ramflux_crypto::object_verification::verify_object_stream(
                &mut checked,
                size,
                &key,
                &id,
                &manifest,
                &plaintext,
            )
            .is_ok()
            {
                checks.verified += 1;
            } else {
                checks.mismatched += 1;
            }
            bytes = bytes.saturating_add(size);
            progress(checks.verified + checks.mismatched + checks.missing, bytes)?;
        }
        let all_missing = self.missing_attachment_count()?;
        let (missing, approved) = if archive_only {
            self.install_missing_counts()?
        } else {
            (all_missing, self.approved_missing_count()?)
        };
        checks.missing += missing;
        checks.unavailable_at_source = approved;
        checks.local_missing_kept = all_missing.saturating_sub(missing);
        Ok(checks)
    }
}

pub(super) fn require_space(path: &Path, needed: u64) -> Result<(), StorageError> {
    if fs2::available_space(path)? < needed {
        return Err(std::io::Error::from(std::io::ErrorKind::StorageFull).into());
    }
    Ok(())
}

struct ProgressBlob<R, F> {
    inner: R,
    check: F,
}
impl<R: std::io::Read, F: FnMut() -> Result<(), StorageError>> std::io::Read
    for ProgressBlob<R, F>
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (self.check)().map_err(std::io::Error::other)?;
        self.inner.read(buf)
    }
}
