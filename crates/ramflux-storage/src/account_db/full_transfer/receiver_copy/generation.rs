// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! G1 database preparation. Object metadata and G2/G3 still belong to the SDK installer.
use super::{FullReceiverBaseCopy, FullTransferStage, wrong};
use crate::{AccountDbKey, AdoptionRow, BackupDatabase, StorageError};
use rusqlite::params;
mod incremental;
mod objects;
mod selection;
mod tail;
pub use selection::{
    FullGenerationRecoveryDraft, FullGenerationRecoveryWork, FullSelectedReceiverGeneration,
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Root-drained local work, with no original writer or network capability.
/// Uses only B's current key and a private qualified union; it cannot select paths.
pub struct FullReceiverDatabaseWork {
    copy: FullReceiverBaseCopy,
    key: AccountDbKey,
    path: PathBuf,
    adoption: AdoptionRow,
    guard: crate::FullLocalUnlockGuard,
    cancelled: Arc<AtomicBool>,
    input: Option<super::super::receiver_read::OwnedReceiverInput>,
}
/// A durable private database, still requiring actual verification in a fresh local loan.
/// Not a publication, selected generation, object-store proof or installed receipt.
pub struct FullPreparedReceiverDatabase(
    FullReceiverDatabaseWork,
    std::sync::Mutex<super::seal::FileSeal>,
);
impl FullReceiverBaseCopy {
    /// Bind a locally owned fresh generation path and adoption to this exact private union.
    /// Release the ordinary loan before running the returned bounded copy worker.
    /// # Errors
    /// Refuses changed B, missing DV, foreign adoption, unsafe paths or lost unlock.
    pub fn into_generation_database_work(
        mut self,
        stage: &FullTransferStage<'_>,
        path: PathBuf,
        adoption: AdoptionRow,
        now: u64,
    ) -> Result<FullReceiverDatabaseWork, StorageError> {
        self.require_materialization_stamp(stage)?;
        stage.verified_duplex(now)?;
        crate::account_db::pairing::journal::decode_adoption(&adoption)?;
        let record = stage.resume_record()?;
        let union = self.union.as_ref().ok_or_else(wrong)?;
        if adoption.account_id != stage.db.local_account_id
            || adoption.local_role != "primary"
            || adoption.local_ref
                != ramflux_protocol::canonical_json_bytes(&record.grant.destination_ref)?
            || adoption.full_generation_nonce.as_deref()
                != Some(ramflux_protocol::encode_base64url(union.generation_nonce).as_str())
            || adoption.full_initial_union_root.as_deref()
                != Some(ramflux_protocol::encode_base64url(union.chunks_root).as_str())
        {
            return Err(wrong());
        }
        let root = stage.db.account_index.root();
        let parent = path.parent().ok_or_else(wrong)?;
        let account = root.join("accounts").join(&stage.db.local_account_id);
        let name = parent
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_prefix("generation_"))
            .ok_or_else(wrong)?;
        super::super::stage::raw32(name)?;
        if parent.parent() != Some(account.as_path())
            || path.file_name().and_then(|value| value.to_str()) != Some("account.db")
            || std::fs::canonicalize(parent)? != parent
            || std::fs::symlink_metadata(&path).is_ok()
        {
            return Err(wrong());
        }
        self.retain_for_installation(stage, now)?;
        let input = stage.pin_receiver_read_input(&self.hash, now)?;
        Ok(FullReceiverDatabaseWork {
            copy: self,
            key: stage.db.current_key.clone(),
            path,
            adoption,
            guard: stage.db.full_local_unlock_guard()?,
            cancelled: stage.source_cancelled.clone(),
            input: Some(input),
        })
    }
}
impl FullReceiverDatabaseWork {
    fn live(&self) -> Result<(), StorageError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(StorageError::AuthorizationRejected);
        }
        self.guard.require_unlocked()
    }
    /// Copy in bounded encrypted pages using B's existing key, preserving all B-local rows.
    /// # Errors
    /// Refuses cancellation, original unlock loss, path reuse, insufficient space or I/O.
    pub fn prepare(mut self) -> Result<FullPreparedReceiverDatabase, StorageError> {
        self.live()?;
        let input = self.input.take().ok_or_else(wrong)?;
        self.copy.verify_input(&input)?;
        let source = BackupDatabase::open_full_receiver_copy(
            &self.copy.scratch.path.join("private.db"),
            &self.copy.key,
        )?;
        let mut target = super::super::stage::create_file(&self.path)?;
        std::io::Write::flush(&mut target)?;
        drop(target);
        let result = self.write(&source);
        if result.is_err() {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-journal"));
        }
        result?;
        drop(source);
        self.live()?;
        objects::prepare(&self.path)?;
        let seal = self.verify_prepared(&input)?;
        drop(input); // Release the stage owner before the next actual-writer request.
        Ok(FullPreparedReceiverDatabase(self, std::sync::Mutex::new(seal)))
    }
    fn write(&self, source: &BackupDatabase) -> Result<(), StorageError> {
        let parent = self.path.parent().ok_or_else(wrong)?;
        let estimate: u64 = source.db.query_row(
            "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
            [],
            |row| row.get(0),
        )?;
        crate::account_db::backup_database::require_space(
            parent,
            estimate.saturating_add(20 * 1024 * 1024),
        )?;
        let mut target = rusqlite::Connection::open(&self.path)?;
        let key = zeroize::Zeroizing::new(self.key.sqlcipher_hex());
        target.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key=\"x'{}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-2048; PRAGMA secure_delete=ON;",key.as_str())))?;
        {
            let backup = rusqlite::backup::Backup::new(&source.db, &mut target)?;
            loop {
                self.live()?;
                match backup.step(128)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => {
                        crate::account_db::backup_database::require_space(parent, 2 * 1024 * 1024)?;
                    }
                    _ => return Err(StorageError::PairingField("Busy")),
                }
            }
        }
        objects::require_supported(&target)?;
        let row = &self.adoption;
        let tx = target.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tail::seed(&tx, &self.copy, &self.adoption, || self.live())?;
        tx.execute(
            "UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1",
            params![self.key.fingerprint()],
        )?;
        tx.execute("INSERT INTO pairing_adoption(account_id,operation_id,record_hash,local_ref,local_role,branch_vault_ref,data_vault_ref,primary_vault_ref,full_generation_nonce,full_initial_union_root) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(account_id) DO UPDATE SET operation_id=excluded.operation_id,record_hash=excluded.record_hash,local_ref=excluded.local_ref,local_role=excluded.local_role,branch_vault_ref=excluded.branch_vault_ref,data_vault_ref=excluded.data_vault_ref,primary_vault_ref=excluded.primary_vault_ref,full_generation_nonce=excluded.full_generation_nonce,full_initial_union_root=excluded.full_initial_union_root",params![row.account_id,row.operation_id,row.record_hash,row.local_ref,row.local_role,row.branch_vault_ref,row.data_vault_ref,row.primary_vault_ref,row.full_generation_nonce,row.full_initial_union_root])?;
        tx.commit()?;
        drop(target);
        super::super::stage::sync_regular(&self.path)?;
        crate::sync_path::sync_path(parent)?;
        Ok(())
    }
}
impl FullPreparedReceiverDatabase {
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.0.path
    }
    /// Recheck actual prepared portable bytes and original B under its new short loan.
    /// This still grants no G2 selection, object-store completeness or publication.
    /// # Errors
    /// Refuses changed B, corrupt prepared rows, wrong key/adoption or lost work ownership.
    pub fn verify(&self, stage: &FullTransferStage<'_>) -> Result<(), StorageError> {
        let sealed = self.0.verify_prepared(stage)?;
        *self.1.lock().map_err(|_| wrong())? = sealed;
        Ok(())
    }
    pub(super) fn require_attested(
        &self,
        stage: &FullTransferStage<'_>,
    ) -> Result<(), StorageError> {
        self.0.live()?;
        self.0.copy.require_materialization_stamp(stage)?;
        self.1.lock().map_err(|_| wrong())?.require(&self.0.path)?;
        objects::verify(&self.0.path)?;
        self.0.copy.observation.require_current(stage.db)
    }
}
impl FullReceiverDatabaseWork {
    fn verify_prepared(
        &self,
        stage: &impl super::super::receiver_read::ReceiverInput,
    ) -> Result<super::seal::FileSeal, StorageError> {
        self.live()?;
        self.copy.verify_input(stage)?;
        let sealed = super::seal::FileSeal::capture(&self.path)?;
        let private = BackupDatabase::open_full_receiver_copy(&self.path, &self.key)?;
        objects::require_supported(&private.db)?;
        objects::verify(&self.path)?;
        let row = &self.adoption;
        let matches:bool=private.db.query_row("SELECT EXISTS(SELECT 1 FROM pairing_adoption WHERE account_id=?1 AND operation_id=?2 AND record_hash=?3 AND local_ref=?4 AND local_role=?5 AND branch_vault_ref=?6 AND data_vault_ref=?7 AND primary_vault_ref IS ?8 AND full_generation_nonce=?9 AND full_initial_union_root=?10)",params![row.account_id,row.operation_id,row.record_hash,row.local_ref,row.local_role,row.branch_vault_ref,row.data_vault_ref,row.primary_vault_ref,row.full_generation_nonce,row.full_initial_union_root],|row|row.get(0))?;
        if !matches {
            return Err(wrong());
        }
        super::super::receiver_materialization::Verification {
            directory: &self.copy.scratch.path,
            key: &self.copy.key,
            encoding: self.copy.union.as_ref().ok_or_else(wrong)?,
            owners: &self.copy.contributions.owners,
            private: &private,
            private_key: &self.key,
            stage,
        }
        .run()?;
        drop(private);
        sealed.require(&self.path)?;
        stage.require_target(&self.copy.observation)?;
        Ok(sealed)
    }
}
