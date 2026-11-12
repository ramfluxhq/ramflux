// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data-only source preparation, before any invitation/SAS/data lease exists.
use super::{
    FullBaseSourceEncoding, FullStageKey,
    source_owner::SourceContext,
    stage::{create_file, stage_directory, sync_stage, write_new_atomic},
};
use crate::{AccountDb, StorageError, database::Connection};
use ramflux_crypto::custody::pairing::PairingRole;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::{
    cell::Cell,
    io::Write,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
/// One-way cancellation only; this holds neither a database owner nor a key/approval.
#[derive(Clone)]
pub struct FullSourcePreparationCancel(Arc<AtomicBool>);
impl FullSourcePreparationCancel {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Local source data owner only. It contains no resume record, token, confirmation,
/// branch signer or publication authority. An orphan cannot restore a data session.
/// The snapshot and logical spool stay encrypted with independent keys; the caller
/// must bind a separately attended full ceremony before any network data operation.
pub struct FullSourcePreparation<'db> {
    pub(super) connection: Connection,
    pub(super) _lock: std::fs::File,
    pub(super) key: FullStageKey<'db>,
    pub(super) db: &'db AccountDb,
    pub(super) directory: PathBuf,
    preparation_id: String,
    prepared: Option<(String, FullBaseSourceEncoding)>,
    cancelled: Arc<AtomicBool>,
    _serial: PhantomData<Cell<()>>,
}
impl AccountDb {
    /// Prepare private source storage before Issue, without inventing grant/resume operands.
    /// No token, lease, source signature or SAS approval is allocated/restored here.
    /// # Errors
    /// Refuses stale/locked accounts, unavailable entropy, unsafe files or failed durability.
    pub fn prepare_full_transfer_source(&self) -> Result<FullSourcePreparation<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        let id = Zeroizing::new(ramflux_crypto::random_32()?);
        let preparation_id = ramflux_protocol::encode_base64url(id.as_slice());
        let directory = stage_directory(self, &preparation_id, true)?;
        let (key, wrapped) = self.create_full_stage_key(&id, PairingRole::Initiator)?;
        let lock = create_file(&directory.join("stage.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        write_new_atomic(&directory, "stage.key", &wrapped.to_file_bytes()?)?;
        create_file(&directory.join("stage.db"))?.sync_all()?;
        let connection = key.open_metadata(&directory.join("stage.db"))?;
        connection.execute_batch(super::source_cut::SCHEMA)?;
        connection.execute_batch(super::source_scalar::SCHEMA)?;
        sync_stage(&directory)?;
        self.require_full_stage_unlock()?;
        Ok(FullSourcePreparation {
            connection,
            _lock: lock,
            key,
            db: self,
            directory,
            preparation_id,
            prepared: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            _serial: PhantomData,
        })
    }
}
impl FullSourcePreparation<'_> {
    /// Local progress identifier only, never a lease or authenticated stage reference.
    #[must_use]
    pub fn preparation_id(&self) -> &str {
        &self.preparation_id
    }
    /// Obtain a one-way cancellation handle without retaining the key or account owner.
    #[must_use]
    pub fn cancel_handle(&self) -> FullSourcePreparationCancel {
        FullSourcePreparationCancel(self.cancelled.clone())
    }
    fn context(&self) -> Result<SourceContext<'_>, StorageError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(StorageError::PairingField("Cancelled"));
        }
        self.key.require_live()?;
        Ok(SourceContext {
            connection: &self.connection,
            db: self.db,
            directory: &self.directory,
            cancelled: Some(self.cancelled.clone()),
        })
    }
    /// Pin and copy the base through the existing generation/writer owner. Cancellation
    /// reaches its bounded page-copy loop; the path is locally fixed, never peer supplied.
    /// # Errors
    /// Refuses a reused cut, unsupported live schema, cancellation or snapshot I/O failures.
    pub fn capture_base_cut(&mut self, snapshot_id: &str) -> Result<(), StorageError> {
        self.context()?.require_source_live()?;
        super::stage::raw32(snapshot_id)?;
        let reused: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM source_cut WHERE cut=0)",
            [],
            |row| row.get(0),
        )?;
        if reused {
            return Err(super::stage::context());
        }
        let rules = super::full_transfer_catalog();
        self.db.inspect_full_transfer_schema(rules)?.require_typed_owners(rules)?;
        let path = self.directory.join("source-preparation-copy.db");
        let snapshot = self
            .db
            .pin_full_transfer_cut()?
            .write_private_snapshot(&path, self.cancelled.clone())?;
        self.adopt_base_cut(snapshot_id, &path, snapshot)
    }
    /// Adopt the exact already-pinned private base snapshot. No snapshot bytes are portable.
    /// # Errors
    /// Refuses reused cuts, unsafe paths, invalid keys or unavailable ordinary unlock.
    pub fn adopt_base_cut(
        &self,
        snapshot_id: &str,
        path: &Path,
        snapshot: super::super::backup::AccountBackupSnapshot,
    ) -> Result<(), StorageError> {
        self.context()?.adopt_source_cut(0, snapshot_id, path, snapshot)
    }
    /// Encode supported families to a PRIVATE encrypted sink before bootstrap. The retained
    /// immutable counts/root are local data operands, not approval or a `DataVerified` receipt.
    /// # Errors
    /// Refuses missing/changed cuts, unsupported owners, generation changes or output failures.
    pub fn encode_fixed_base_source<W: Write + Send + 'static>(
        &mut self,
        snapshot_id: &str,
        writer: W,
    ) -> Result<(W, &FullBaseSourceEncoding), StorageError> {
        self.prepared = None;
        let (output, encoded) = self.context()?.encode_fixed_base_source(snapshot_id, writer)?;
        let (_, stored) = self.prepared.insert((snapshot_id.to_owned(), encoded));
        Ok((output, stored))
    }
}

mod checkpoint;
pub use checkpoint::PreparedFullSource;
