// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private, worker-owned encrypted staging access and bounded attachment verification.

use crate::{AccountDbKey, BackupCounts, StorageError};
use rusqlite::params;
use std::path::Path;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BackupAttachmentVerification {
    pub verified: u64,
    #[serde(default)]
    /// Payload-free tombstone records checked separately from verified ciphertext.
    pub placeholders_checked: u64,
    pub mismatched: u64,
    pub missing: u64,
    pub unavailable_at_source: u64,
    pub local_missing_kept: u64,
}

/// Validation boundary for a private restore generation, independent of its schema version.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupOpenMode {
    /// Authenticated input whose inherited legacy actors have not yet been normalized.
    PreNormalization,
    /// A completed generation; unresolved ownership is a hard error.
    Normalized,
}

/// Immutable observations from the first input open, before any row omission.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupInputObservation {
    pub counts: BackupCounts,
    pub unowned_legacy_actor_count: u64,
    pub schema_version: i64,
}

// Only an in-place live migration may preserve HKDF(live DB key) authority.
#[derive(Clone, Copy)]
enum MarkerAuthoritySource {
    LiveAccountKey,
    ArchiveInput,
    FreshArchiveInput,
}

pub struct BackupDatabase {
    pub(crate) db: rusqlite::Connection,
    original_input: BackupInputObservation,
    _generation_reader: Option<crate::account_generation::GenerationReadLease>,
}
#[derive(Clone, Copy)]
enum FullInputMode {
    PrivateCopy,
    SelectedRead,
}
impl BackupDatabase {
    /// Open only the receiver owner's freshly copied CURRENT-schema B database.
    /// This preserves B-local rows and MAC authority exactly: archive normalization
    /// belongs to imported archives and must not run on this own-device copy.
    pub(in crate::account_db) fn open_full_receiver_copy(
        path: &Path,
        key: &AccountDbKey,
    ) -> Result<Self, StorageError> {
        Self::open_full_input(path, key, FullInputMode::PrivateCopy)
    }
    /// Verify a selected live generation without changing its journal or taking a writer lock.
    pub(in crate::account_db) fn open_full_selected_read(
        path: &Path,
        key: &AccountDbKey,
    ) -> Result<Self, StorageError> {
        Self::open_full_input(path, key, FullInputMode::SelectedRead)
    }
    fn open_full_input(
        path: &Path,
        key: &AccountDbKey,
        mode: FullInputMode,
    ) -> Result<Self, StorageError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(StorageError::AuthorizationRejected);
        }
        let (flags, settings) = match mode {
            FullInputMode::PrivateCopy => (
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
            ),
            FullInputMode::SelectedRead => {
                (rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY, "PRAGMA query_only=ON; BEGIN;")
            }
        };
        let db = rusqlite::Connection::open_with_flags(
            path,
            flags | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let hex = zeroize::Zeroizing::new(key.sqlcipher_hex());
        let pragma = zeroize::Zeroizing::new(format!(
            "PRAGMA key=\"x'{}'\"; PRAGMA cache_size=-2048; {settings}",
            hex.as_str()
        ));
        // Only our private copy is normalized. A selected ordinary writer keeps its
        // existing WAL mode; recovery reads one stable transaction under observation.
        db.execute_batch(&pragma)?;
        crate::schema_generation::validate(&db)?;
        crate::schema_object_erasure::validate(&db)?;
        let fingerprint: String = db.query_row(
            "SELECT key_fingerprint FROM account_key_check WHERE singleton_id=1",
            [],
            |row| row.get(0),
        )?;
        if fingerprint != key.fingerprint() {
            return Err(StorageError::AccountKeyMismatch);
        }
        super::backup_native::full_transfer_snapshot_preflight(&db)?;
        let original_input = observation::capture(&db, false)?;
        Ok(Self { db, original_input, _generation_reader: None })
    }

    /// Opens a private snapshot or an owner-guarded generation for restore checks.
    /// Never use this worker handle as an active live account writer.
    /// # Errors
    /// Returns authentication, schema or I/O errors.
    pub fn open(path: &Path, key: &AccountDbKey) -> Result<Self, StorageError> {
        Self::open_restore_input(path, key, BackupOpenMode::Normalized)
    }

    /// Opens an owner-guarded live account before copying its generation for restore.
    /// The supplied key must be the live account key, never a snapshot or archive key.
    /// # Errors
    /// Returns authentication, schema, ownership or I/O errors.
    pub fn open_live_account(path: &Path, key: &AccountDbKey) -> Result<Self, StorageError> {
        Self::open_with_source(
            path,
            key,
            BackupOpenMode::Normalized,
            MarkerAuthoritySource::LiveAccountKey,
        )
    }

    /// Opens an owner-guarded live restore input before private normalization.
    /// # Errors
    /// Returns authentication, schema or I/O errors.
    #[doc(hidden)]
    pub fn open_live_restore_input(path: &Path, key: &AccountDbKey) -> Result<Self, StorageError> {
        Self::open_with_source(
            path,
            key,
            BackupOpenMode::PreNormalization,
            MarkerAuthoritySource::LiveAccountKey,
        )
    }

    /// Opens an internal candidate restore input with an explicit validation boundary.
    /// This does not normalize rows or select a generation for installation.
    /// # Errors
    /// Returns authentication, schema, ownership or I/O errors.
    #[doc(hidden)]
    pub fn open_restore_input(
        path: &Path,
        key: &AccountDbKey,
        mode: BackupOpenMode,
    ) -> Result<Self, StorageError> {
        Self::open_with_source(path, key, mode, MarkerAuthoritySource::ArchiveInput)
    }

    /// Opens a newly unpacked private archive, ignoring archive-supplied staging metadata.
    /// Later private reopens use the retained origin instead.
    /// # Errors
    /// Returns authentication, schema or storage errors.
    #[doc(hidden)]
    pub fn open_original_restore_input(
        path: &Path,
        key: &AccountDbKey,
        mode: BackupOpenMode,
    ) -> Result<Self, StorageError> {
        Self::open_with_source(path, key, mode, MarkerAuthoritySource::FreshArchiveInput)
    }

    fn open_with_source(
        path: &Path,
        key: &AccountDbKey,
        mode: BackupOpenMode,
        source: MarkerAuthoritySource,
    ) -> Result<Self, StorageError> {
        let generation_reader = if matches!(source, MarkerAuthoritySource::LiveAccountKey) {
            Some(crate::account_generation::GenerationReadLease::acquire(path)?)
        } else {
            None
        };
        let mut db = rusqlite::Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(&format!("PRAGMA key=\"x'{}'\"; PRAGMA cache_size=-2048; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",key.sqlcipher_hex()))?;
        crate::schema_generation::validate(&db)?;
        let fingerprint: String = db.query_row(
            "SELECT key_fingerprint FROM account_key_check WHERE singleton_id=1",
            [],
            |row| row.get(0),
        )?;
        if fingerprint != key.fingerprint() {
            return Err(StorageError::AccountKeyMismatch);
        }
        let input_version: i64 = db.query_row(
            "SELECT COALESCE(MAX(schema_version),0) FROM schema_migration",
            [],
            |r| r.get(0),
        )?;
        crate::schema_object_erasure::validate(&db)?;
        // P1's schema-only private upgrade never omits rows. Capture before any
        // candidate normalization and retain the input's original version.
        if matches!(source, MarkerAuthoritySource::FreshArchiveInput) {
            db.execute_batch("DROP TABLE IF EXISTS main.backup_input_origin;")?;
        }
        let original_input = observation::capture(
            &db,
            mode == BackupOpenMode::PreNormalization
                && matches!(
                    source,
                    MarkerAuthoritySource::ArchiveInput | MarkerAuthoritySource::FreshArchiveInput
                ),
        )?;
        if input_version < crate::schema_object_erasure::VERSION {
            let writer = crate::database::Connection::open(path)?;
            crate::encryption::apply_key(&writer, key)?;
            crate::schema_object_erasure::upgrade_private(&writer)?;
        }
        // Schema-only additive upgrade; never import physical segment progress.
        let segment_schema:bool=db.query_row("SELECT (SELECT count(*) FROM pragma_table_info('object_transfer_state') WHERE name IN ('segment_generation','segment_sequence','segment_manifest'))=3 AND EXISTS(SELECT 1 FROM sqlite_master WHERE name='object_segment_file')",[],|r|r.get(0))?;
        if !segment_schema {
            let writer = crate::database::Connection::open(path)?;
            crate::encryption::apply_key(&writer, key)?;
            crate::schema::ensure_object_transfer_state_columns(&writer)?;
        }
        #[cfg(test)]
        tests::after_upgrade()?;
        // An archive's enclosing key is never MAC authority. Record old keyed
        // markers as unmatched before minting fresh-install authority.
        match source {
            MarkerAuthoritySource::ArchiveInput | MarkerAuthoritySource::FreshArchiveInput => {
                super::mac_subkeys::initialize_archive(&mut db, key)?;
            }
            MarkerAuthoritySource::LiveAccountKey => {
                super::mac_subkeys::initialize(&mut db, key, false)?;
            }
        }
        db.execute_batch(crate::schema_large_segments::RETIREMENT_SCHEMA)?;
        db.execute_batch(super::event_counter::SCHEMA)?;
        super::message_footprint::install(&db)?;
        super::message_footprint::migration::complete(&db)?;
        if mode == BackupOpenMode::Normalized && original_input.unowned_legacy_actor_count > 0 {
            return Err(StorageError::ObjectOwnershipUnverified { schema_version: input_version });
        }
        super::attachment_retirement::recount_archive(&db)?;
        let opened = Self { db, original_input, _generation_reader: generation_reader };
        opened.ensure_missing_manifest()?;
        opened.db.execute_batch(crate::schema_contact_requests::HELD_MESSAGE_FENCES)?;
        opened.db.execute_batch(crate::schema_contact_requests::CONSENT_DECISIONS)?;
        Ok(opened)
    }
    /// Original authenticated counts and legacy classification, retained across private reopens.
    #[doc(hidden)]
    #[must_use]
    pub fn original_input(&self) -> &BackupInputObservation {
        &self.original_input
    }

    /// Reopens this input's private copy, retaining its original observations.
    /// The requested boundary is checked against the current rows, never the old count.
    /// Callers must supply this input's copy, rather than a different archive.
    /// # Errors
    /// Returns the same errors as `open_restore_input`.
    #[doc(hidden)]
    pub fn reopen_restore_input(
        &self,
        path: &Path,
        key: &AccountDbKey,
        mode: BackupOpenMode,
    ) -> Result<Self, StorageError> {
        let mut reopened = Self::open_restore_input(path, key, mode)?;
        reopened.original_input = self.original_input.clone();
        if mode == BackupOpenMode::PreNormalization {
            observation::retain(&reopened.db, self.original_input.schema_version)?;
        }
        Ok(reopened)
    }

    /// Carries already authenticated input metadata across a private stage open.
    #[doc(hidden)]
    #[must_use]
    pub fn retain_original_input(mut self, original: &BackupInputObservation) -> Self {
        self.original_input = original.clone();
        self
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
            "PRAGMA key=\"x'{}'\"; PRAGMA synchronous=FULL; PRAGMA cache_size=-2048; PRAGMA secure_delete=ON;",
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
        super::backup_selector_admission::drop_scratch(&target)?;
        target.execute(
            "UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1",
            params![key.fingerprint()],
        )?;
        super::receive::ledger_backup::sanitize_backup(&target)?;
        super::pairing::sanitize_backup(&target)?;
        drop(target);
        crate::sync_path::sync_path(path)?;
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
    /// Checks payloads and payload-free legacy placeholder records before normalization.
    /// Placeholder metadata counts as a checked record, never a verified payload.
    /// # Errors
    /// Returns the attachment verifier's storage and cancellation errors.
    #[doc(hidden)]
    pub fn verify_candidate_input_attachments(
        &self,
        progress: impl FnMut(u64, u64) -> Result<(), StorageError>,
    ) -> Result<BackupAttachmentVerification, StorageError> {
        let mut checks = self.verify_attachments(progress)?;
        let placeholders: u64 = self.db.query_row(
            "SELECT count(*) FROM object_index WHERE backup_excluded=0 AND tombstoned=1 AND length(ciphertext)=0 AND chunk_count=0",
            [], |r|r.get(0))?;
        checks.placeholders_checked = placeholders;
        Ok(checks)
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
        let mut statement=self.db.prepare(&format!("SELECT rowid,object_id,CAST(manifest_hash AS TEXT),plaintext_hash,object_content_key,length(ciphertext) FROM object_index WHERE backup_excluded=0 AND tombstoned=0{predicate} ORDER BY rowid"))?;
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

#[cfg(test)]
mod tests;

mod observation;

#[cfg(test)]
impl BackupDatabase {
    /// Measures only this restore worker's connection; reset also on error or unwind.
    pub(crate) fn measure_restore_vm_steps<T>(
        &mut self,
        operation: impl FnOnce(&rusqlite::Connection) -> T,
    ) -> (T, u64) {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        struct ResetProgress<'a>(&'a mut rusqlite::Connection);
        impl Drop for ResetProgress<'_> {
            fn drop(&mut self) {
                let _ = self.0.progress_handler(0, None::<fn() -> bool>);
            }
        }
        let steps = Arc::new(AtomicU64::new(0));
        let counter = steps.clone();
        let _ = self.db.progress_handler(
            1,
            Some(move || {
                counter.fetch_add(1, Ordering::Relaxed);
                false
            }),
        );
        let reset = ResetProgress(&mut self.db);
        let result = operation(&*reset.0);
        drop(reset);
        (result, steps.load(Ordering::Relaxed))
    }
}
