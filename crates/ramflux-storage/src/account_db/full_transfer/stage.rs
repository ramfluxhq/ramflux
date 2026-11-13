// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local encrypted metadata commits precede the account's data-only stage reference.
use super::{FullStageKey, WrappedFullStageKey};
use crate::{
    AccountDb, FULL_STAGE_REFERENCE_KIND, FullStageReference, StorageError, database::Connection,
};
use ramflux_crypto::custody::pairing::{FullResumeRecord, FullResumeTrust, PairingRole};
use ramflux_protocol::custody::pairing::{PairingWire, full_transfer::U64};
use rusqlite::params;
use std::{
    cell::Cell,
    fs,
    io::Write,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const SCHEMA: &str = "
CREATE TABLE stage(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL CHECK(schema_version=1),local_account_id TEXT NOT NULL,role INTEGER NOT NULL CHECK(role IN(0,1)),lease_expires_at INTEGER NOT NULL,record_digest BLOB NOT NULL CHECK(length(record_digest)=32));
CREATE TABLE resume(singleton INTEGER PRIMARY KEY CHECK(singleton=1),role INTEGER NOT NULL,transcript BLOB NOT NULL,th BLOB NOT NULL CHECK(length(th)=32),grant_bytes BLOB NOT NULL,lease BLOB NOT NULL,transfer_id TEXT NOT NULL,base_manifest_hash TEXT NOT NULL,base_record_hash TEXT NOT NULL);
CREATE TABLE manifest(direction INTEGER NOT NULL CHECK(direction IN(0,1)),cut INTEGER NOT NULL,manifest_hash TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN('base','delta','tail')),bytes BLOB NOT NULL,chunks_root TEXT NOT NULL,root_verified INTEGER NOT NULL DEFAULT 0 CHECK(root_verified IN(0,1)),verified INTEGER NOT NULL CHECK(verified IN(0,1)),PRIMARY KEY(direction,cut),UNIQUE(direction,manifest_hash));
CREATE TABLE chunk(direction INTEGER NOT NULL,manifest_hash TEXT NOT NULL,idx INTEGER NOT NULL,length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 262144),digest BLOB NOT NULL CHECK(length(digest)=32),file_durable INTEGER NOT NULL CHECK(file_durable=1),PRIMARY KEY(direction,manifest_hash,idx),FOREIGN KEY(direction,manifest_hash) REFERENCES manifest(direction,manifest_hash));";

/// Short local I/O owner. Drop before waiting on a relay or completing application lock.
/// Connection and exclusive file lock drop before the independent stage-key owner.
/// This owner confers no SAS approval, publication authority or endpoint tail admission.
pub struct FullTransferStage<'db> {
    pub(super) connection: Connection,
    pub(super) lock: fs::File,
    pub(super) key: FullStageKey<'db>,
    pub(super) db: &'db AccountDb,
    pub(super) directory: PathBuf,
    reference: FullStageReference,
    pub(super) source_cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    // One coordinator owns the local file/SQL commit order. A shared reference cannot
    // concurrently replace a manifest while another thread reads or receipts its slots.
    _serial: PhantomData<Cell<()>>,
}
impl AccountDb {
    #[cfg(test)]
    pub(crate) fn create_full_stage_for_test(
        &self,
        record: FullResumeRecord,
        expires_at: u64,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        self.create_full_stage_record(record, expires_at)
    }
    /// Durably create encrypted stage metadata and the exact SAS-base native floor
    /// before linking it in `pairing_live`.
    /// # Errors
    /// Refuses stale unlocks, reused paths, unsafe files, or any failed durable write.
    pub fn create_full_transfer_stage(
        &self,
        trust: &FullResumeTrust,
        sas_base: &ramflux_crypto::custody::VerifiedRecord,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        let record = trust.local_stage_record()?;
        super::native_floor::validate_sas_base(&record, sas_base)?;
        let mut stage = self.create_full_stage_record(record, trust.lease_expires_at())?;
        stage.observe_full_native_head(sas_base)?;
        Ok(stage)
    }
    fn create_full_stage_record(
        &self,
        record: FullResumeRecord,
        expires_at: u64,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        record.stage_digest()?;
        let transfer = raw32(&record.transfer_id)?;
        let directory = stage_directory(self, &record.transfer_id, true)?;
        let (key, wrapped) = self.create_full_stage_key(&transfer, record.role)?;
        let lock = create_file(&directory.join("stage.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        write_new_atomic(&directory, "stage.key", &wrapped.to_file_bytes()?)?;
        create_file(&directory.join("stage.db"))?.sync_all()?;
        let connection = key.open_metadata(&directory.join("stage.db"))?;
        let reference = initialize_record(&connection, &self.local_account_id, record, expires_at)?;
        sync_stage(&directory)?;
        self.require_full_stage_unlock()?;
        Ok(FullTransferStage {
            connection,
            lock,
            key,
            db: self,
            directory,
            reference,
            source_cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            _serial: PhantomData,
        })
    }
    /// Open only from this account's actual durable live row; caller-supplied references
    /// and orphan stage directories cannot restore a data session.
    /// # Errors
    /// Refuses absent/stale links, expiry, wrong role/digest/account, unsafe files or key failure.
    pub fn open_full_transfer_stage(
        &self,
        operation_id: &str,
        role: PairingRole,
        now: u64,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        let row = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation_id)
            .ok_or_else(context)?;
        row.validate()?;
        if matches!(row.phase.as_str(), "cancelled" | "expired" | "rejected" | "completed") {
            // Retained reconciliation material is not a fresh data opportunity. A separate
            // reconciliation-only owner must never mint HPKE/relay state from these rows.
            return Err(context());
        }
        let reference = row.full_stage_reference()?.ok_or_else(context)?;
        self.open_full_stage_reference(reference, role, now)
    }
    // Only account-linked production callers reach this decoder. Unit fixtures can
    // reopen their encrypted source spool without claiming admission or restored consent.
    pub(super) fn open_full_stage_reference(
        &self,
        reference: FullStageReference,
        role: PairingRole,
        now: u64,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        self.open_full_stage_reference_inner(reference, role, now, false)
    }
    pub(super) fn open_full_stage_reference_inner(
        &self,
        reference: FullStageReference,
        role: PairingRole,
        now: u64,
        reconciliation: bool,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        reference.validate().map_err(|_| context())?;
        if !reconciliation && reference.lease_expires_at.0 <= now {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        let directory = stage_directory(self, &reference.stage_id, false)?;
        let lock = open_regular(&directory.join("stage.lock"), true)?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        let wrapped = WrappedFullStageKey::from_file_bytes(&read_bounded(
            &directory.join("stage.key"),
            1024,
        )?)?;
        let key = self.open_full_stage_key(&raw32(&reference.stage_id)?, role, &wrapped)?;
        let path = directory.join("stage.db");
        drop(open_regular(&path, false)?);
        let connection = key.open_metadata(&path)?;
        let local = self.local_account_id.clone();
        let expected = raw32(&reference.record_digest)?;
        let expiry = reference.lease_expires_at.0;
        let valid: bool = connection.query_row(
            "SELECT schema_version=1 AND local_account_id=?1 AND role=?2 AND lease_expires_at=?3 AND record_digest=?4 FROM stage WHERE singleton=1",
            params![local, role_number(role), expiry, expected.as_slice()], |row| row.get(0),
        )?;
        if !valid {
            return Err(context());
        }
        connection.execute_batch(super::source_receipt::SCHEMA)?;
        connection.execute_batch(super::receiver_input::SCHEMA)?;
        connection.execute_batch(super::receiver_copy::application::SCHEMA)?;
        connection.execute_batch(super::reverse_application::SCHEMA)?;
        connection.execute_batch(super::union_encoding::SCHEMA)?;
        connection.execute_batch(super::source_scalar::SCHEMA)?;
        connection.execute_batch(super::native_floor::SCHEMA)?;
        connection.execute_batch(super::preservation::SCHEMA)?;
        connection.execute_batch(super::data_terminal::SCHEMA)?;
        if !reconciliation
            && connection.query_row("SELECT EXISTS(SELECT 1 FROM data_terminal)", [], |row| {
                row.get::<_, bool>(0)
            })?
        {
            return Err(context());
        }
        let stage = FullTransferStage {
            connection,
            lock,
            key,
            db: self,
            directory,
            reference,
            source_cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            _serial: PhantomData,
        };
        let record = stage.resume_record()?;
        if record.role != role {
            return Err(context());
        }
        stage.recover_forward_receipts()?;
        Ok(stage)
    }
}
impl FullTransferStage<'_> {
    /// The caller links this exact reference only after this creation call has committed/fsynced.
    #[must_use]
    pub const fn reference(&self) -> &FullStageReference {
        &self.reference
    }

    /// Retrieve only authenticated encrypted local operands, without private-key SQL Row copies.
    /// The crypto owner must still verify its independently pinned node and local branch.
    /// # Errors
    /// Refuses locked/stale owners, malformed columns, or any account-link digest mismatch.
    pub fn resume_record(&self) -> Result<FullResumeRecord, StorageError> {
        self.db.require_full_stage_unlock()?;
        let (role, transcript, th, grant, lease, transfer_id, base_manifest_hash, base_record_hash) =
            self.connection.call(|db| db.query_row(
                "SELECT role,transcript,th,grant_bytes,lease,transfer_id,base_manifest_hash,base_record_hash FROM resume WHERE singleton=1", [], |row| {
                    Ok((row.get::<_,u8>(0)?, Zeroizing::new(row.get::<_,Vec<u8>>(1)?),
                        row.get::<_,[u8;32]>(2)?, Zeroizing::new(row.get::<_,Vec<u8>>(3)?),
                        Zeroizing::new(row.get::<_,Vec<u8>>(4)?), row.get::<_,String>(5)?,
                        row.get::<_,String>(6)?, row.get::<_,String>(7)?))
                }))?;
        let record = FullResumeRecord {
            role: match role { 0 => PairingRole::Initiator, 1 => PairingRole::Responder, _ => return Err(context()) },
            transcript, th, grant: ramflux_protocol::custody::pairing::full_transfer::lease::DataGrant::from_wire_bytes(&grant).map_err(|_| context())?,
            lease, transfer_id, base_manifest_hash, base_record_hash,
        };
        if record.stage_digest()? != raw32(&self.reference.record_digest)?
            || record.transfer_id != self.reference.stage_id
        {
            return Err(context());
        }
        self.db.require_full_stage_unlock()?;
        Ok(record)
    }
}
pub(super) fn context() -> StorageError {
    StorageError::PairingField("WrongContext")
}
pub(super) fn raw32(value: &str) -> Result<[u8; 32], StorageError> {
    let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| context())?;
    if ramflux_protocol::encode_base64url(&bytes) != value {
        return Err(context());
    }
    bytes.try_into().map_err(|_| context())
}
const fn role_number(role: PairingRole) -> u8 {
    match role {
        PairingRole::Initiator => 0,
        PairingRole::Responder => 1,
    }
}
pub(super) fn stage_directory(
    db: &AccountDb,
    transfer: &str,
    create: bool,
) -> Result<PathBuf, StorageError> {
    raw32(transfer)?;
    if db.local_account_id.is_empty()
        || !db.local_account_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(context());
    }
    let mut path = db.account_index.root().to_owned();
    for component in ["custody_accounts", &db.local_account_id, "full-transfer", transfer] {
        path.push(component);
        if create {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => fs::File::open(path.parent().ok_or_else(context)?)?.sync_all()?,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::AlreadyExists
                            && component != transfer => {}
                    Err(error) => return Err(error.into()),
                }
            }
            #[cfg(not(unix))]
            return Err(context());
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(context());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(context());
            }
        }
    }
    Ok(path)
}
pub(super) fn create_file(path: &Path) -> Result<fs::File, StorageError> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
pub(super) fn open_regular(path: &Path, write: bool) -> Result<fs::File, StorageError> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(context());
    }
    let file = fs::OpenOptions::new().read(true).write(write).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let after = file.metadata()?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || after.nlink() != 1
            || after.permissions().mode() & 0o077 != 0
        {
            return Err(context());
        }
    }
    Ok(file)
}
pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    use std::io::Read as _;
    let file = open_regular(path, false)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(context());
    }
    Ok(bytes)
}
pub(super) fn write_new_atomic(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), StorageError> {
    let temporary = directory.join(format!("{name}.tmp"));
    let mut file = create_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, directory.join(name))?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
pub(super) fn sync_stage(directory: &Path) -> Result<(), StorageError> {
    open_regular(&directory.join("stage.db"), false)?.sync_all()?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

pub(super) fn initialize_record(
    connection: &Connection,
    local_account_id: &str,
    record: FullResumeRecord,
    expires_at: u64,
) -> Result<FullStageReference, StorageError> {
    let digest = record.stage_digest()?;
    let reference = FullStageReference {
        kind: FULL_STAGE_REFERENCE_KIND.into(),
        lease_expires_at: U64(expires_at),
        record_digest: ramflux_protocol::encode_base64url(digest),
        stage_id: record.transfer_id.clone(),
    };
    reference.validate().map_err(|_| context())?;
    let local = local_account_id.to_owned();
    let grant = Zeroizing::new(record.grant.to_wire_bytes().map_err(|_| context())?);
    let role = role_number(record.role);
    connection.call(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(super::source_cut::SCHEMA)?;
        tx.execute_batch(super::source_receipt::SCHEMA)?;
        tx.execute_batch(super::receiver_input::SCHEMA)?;
        tx.execute_batch(super::receiver_copy::application::SCHEMA)?;
        tx.execute_batch(super::reverse_application::SCHEMA)?;
        tx.execute_batch(super::union_encoding::SCHEMA)?;
        tx.execute_batch(super::source_scalar::SCHEMA)?;
        tx.execute_batch(super::native_floor::SCHEMA)?;
        tx.execute_batch(super::preservation::SCHEMA)?;
        tx.execute_batch(super::data_terminal::SCHEMA)?;
        tx.execute(
            "INSERT INTO stage VALUES(1,1,?1,?2,?3,?4)",
            params![local, role, expires_at, digest.as_slice()],
        )?;
        tx.execute(
            "INSERT INTO resume VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                role,
                record.transcript.as_slice(),
                record.th.as_slice(),
                grant.as_slice(),
                record.lease.as_slice(),
                record.transfer_id,
                record.base_manifest_hash,
                record.base_record_hash
            ],
        )?;
        tx.commit()
    })?;
    Ok(reference)
}

impl<'db> FullTransferStage<'db> {
    pub(super) fn finish_prepared_source(
        parts: super::source_preparation::SourceBindParts<'db>,
        record: FullResumeRecord,
        expires_at: u64,
        sas_base: &ramflux_crypto::custody::VerifiedRecord,
        manifest: &ramflux_protocol::custody::pairing::full_transfer::SourceManifest,
    ) -> Result<Self, StorageError> {
        let reference =
            initialize_record(&parts.connection, &parts.db.local_account_id, record, expires_at)?;
        let mut stage = Self {
            connection: parts.connection,
            lock: parts.lock,
            key: parts.key,
            db: parts.db,
            directory: parts.directory,
            reference,
            source_cancelled: parts.cancelled,
            _serial: PhantomData,
        };
        stage.observe_full_native_head(sas_base)?;
        stage.retain_source_manifest(manifest, super::full_transfer_catalog())?;
        sync_stage(&stage.directory)?;
        stage.source_context()?.require_source_live()?;
        Ok(stage)
    }
}
