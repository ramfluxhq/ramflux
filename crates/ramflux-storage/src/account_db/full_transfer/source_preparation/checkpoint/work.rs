// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-Issue copy and logical encoding with no ordinary database owner retained.
use super::{FullSourcePreparation, PreparedFullSource, StorageError, digest_identity};
use crate::account_db::full_transfer::{
    keys::FullSourceMetadataKey,
    source_owner::SourceContext,
    source_scalar::SourceGuard,
    stage::{context, sync_stage},
};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

/// A pinned local read cut plus independent encrypted preparation metadata. The
/// ordinary frontend keeps its writer; account lock/cancellation invalidates this work.
/// Run and drain it as one local blocking operation, never across a network wait.
pub struct FullSourcePreparationWork {
    connection: crate::database::Connection,
    _lock: std::fs::File,
    key: FullSourceMetadataKey,
    guard: SourceGuard,
    cut: crate::account_db::backup::FullTransferCut,
    directory: PathBuf,
    preparation_id: String,
    account: String,
    principal: String,
    database_path: PathBuf,
    cancelled: Arc<AtomicBool>,
}
impl FullSourcePreparation<'_> {
    /// Pin the actual source view and release the frontend's database borrow before
    /// copying pages or encoding logical records. No invitation or approval exists yet.
    /// # Errors
    /// Refuses a reused preparation, unsupported schema, lost unlock or unsafe I/O.
    pub fn into_encoding_work(self) -> Result<FullSourcePreparationWork, StorageError> {
        self.context()?.require_source_live()?;
        let used: bool =
            self.connection
                .query_row("SELECT EXISTS(SELECT 1 FROM source_cut)", [], |row| row.get(0))?;
        if used || self.prepared.is_some() {
            return Err(context());
        }
        let rules = crate::account_db::full_transfer::full_transfer_catalog();
        self.db.inspect_full_transfer_schema(rules)?.require_typed_owners(rules)?;
        let guard = SourceGuard::new(self.db, Some(self.cancelled.clone()));
        let key = self.key.source_job_key(guard.clone())?;
        let cut = self.db.pin_full_transfer_cut()?;
        guard.require()?;
        Ok(FullSourcePreparationWork {
            connection: self.connection,
            _lock: self.lock,
            key,
            guard,
            cut,
            directory: self.directory,
            preparation_id: self.preparation_id,
            account: self.db.local_account_id.clone(),
            principal: self.db.principal_commitment.clone(),
            database_path: self.db.path.clone(),
            cancelled: self.cancelled,
        })
    }
}
impl FullSourcePreparationWork {
    /// Copy, type-check and encode the pinned view using encrypted bounded spools.
    /// No ordinary data key/database or signing authority is exposed by the result.
    /// # Errors
    /// Refuses cancellation, account lock/selection change, unsupported rows or I/O.
    pub fn encode(self) -> Result<PreparedFullSource, StorageError> {
        self.guard.require()?;
        let snapshot_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let pending = self.directory.join("source-preparation-copy.db");
        let snapshot = self.cut.write_private_snapshot(&pending, self.cancelled.clone())?;
        let mut source = SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: self.guard.clone(),
            directory: &self.directory,
        };
        source.adopt_source_cut(0, &snapshot_id, &pending, snapshot)?;
        let (_, encoding) = source.encode_fixed_base_source(&snapshot_id, std::io::sink())?;
        let digest = digest_identity(
            &self.account,
            &self.principal,
            &self.preparation_id,
            &snapshot_id,
            &encoding,
        )?;
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS source_preparation_ready(singleton INTEGER PRIMARY KEY CHECK(singleton=1),digest BLOB NOT NULL CHECK(length(digest)=32));")?;
        self.connection.execute(
            "INSERT INTO source_preparation_ready VALUES(1,?1)",
            rusqlite::params![digest.as_slice()],
        )?;
        sync_stage(&self.directory)?;
        self.guard.require()?;
        Ok(PreparedFullSource {
            local_account_id: self.account,
            principal: self.principal,
            database_path: self.database_path,
            preparation_id: self.preparation_id,
            snapshot_id,
            encoding,
            digest,
            cancelled: self.cancelled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn pairing_full_source_off_loan_encoding_keeps_pinned_cut_and_ordinary_writer() -> TestResult {
        let (_root, db) = crate::tests::test_db("source-off-loan-cut")?;
        let source = db.prepare_full_transfer_source()?;
        let work = source.into_encoding_work()?;
        // The writer is usable after the short pin and before any bulk copy/encoding.
        db.connection
            .execute("UPDATE account_erasure_generation SET generation=9 WHERE singleton=1", [])?;
        let ready = work.encode()?;
        assert_eq!(
            ready.encoding().source_erasure_generation,
            0,
            "test: pre-Issue encoding silently recut after an ordinary source write"
        );
        assert_eq!(
            db.connection.query_row(
                "SELECT generation FROM account_erasure_generation WHERE singleton=1",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            9,
            "test: pinned preparation rolled back an ordinary source write"
        );
        assert!(
            db.pairing_live_rows()?.is_empty(),
            "test: data-only preparation created a pairing operation before Issue"
        );
        let reopened = db.open_full_source_preparation(&ready)?;
        assert_eq!(
            reopened.preparation_id(),
            ready.preparation_id,
            "test: off-loan output did not reopen under the original actual writer"
        );
        Ok(())
    }
    #[test]
    fn pairing_full_source_off_loan_encoding_refuses_cancelled_or_locked_writer() -> TestResult {
        let (_root, db) = crate::tests::test_db("source-off-loan-cancel")?;
        let source = db.prepare_full_transfer_source()?;
        let cancel = source.cancel_handle();
        let work = source.into_encoding_work()?;
        cancel.cancel();
        assert!(
            matches!(work.encode(), Err(StorageError::PairingField("Cancelled"))),
            "test: cancelled pre-Issue source copy encoded data"
        );
        let source = db.prepare_full_transfer_source()?;
        let work = source.into_encoding_work()?;
        drop(db);
        assert!(
            work.encode().is_err(),
            "test: pre-Issue source copy retained or resurrected a locked ordinary writer"
        );
        Ok(())
    }
}
