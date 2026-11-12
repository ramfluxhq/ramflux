// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent immutable snapshot keys stay solely in encrypted device-local metadata.
use super::source_owner::SourceContext;
use super::stage::{FullTransferStage, context, open_regular, raw32};
use crate::{AccountDbKey, EncryptionMode, StorageError, database::Connection};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS source_cut(cut INTEGER PRIMARY KEY CHECK(cut BETWEEN 0 AND 9),snapshot_id TEXT NOT NULL UNIQUE,filename TEXT NOT NULL UNIQUE,snapshot_key BLOB NOT NULL CHECK(length(snapshot_key)=32),schema_generation INTEGER NOT NULL,erasure_generation INTEGER NOT NULL);";

impl SourceContext<'_> {
    /// Adopt an already pinned/copied A-private cut without recutting it after SAS. The
    /// local path is supplied by the trusted snapshot owner, never by a packet or manifest.
    /// Its independently generated encryption key is committed only inside encrypted stage
    /// SQL, never serialized through a generic row/JSON/vault or placed in transfer bytes.
    /// # Errors
    /// Refuses a wrong role/key, reused cut, unsafe path, invalid scope or lost unlock.
    pub fn adopt_source_cut(
        &self,
        cut: u64,
        snapshot_id: &str,
        private_path: &Path,
        snapshot: super::super::backup::AccountBackupSnapshot,
    ) -> Result<(), StorageError> {
        self.require_source_live()?;
        raw32(snapshot_id)?;
        if cut > 9 || !private_path.is_absolute() {
            return Err(context());
        }
        let reused: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM source_cut WHERE cut=?1 OR snapshot_id=?2)",
            rusqlite::params![cut, snapshot_id],
            |row| row.get(0),
        )?;
        if reused {
            return Err(context());
        }
        drop(open_regular(private_path, false)?);
        let input = open_snapshot(private_path, &snapshot.key)?;
        validate_snapshot(&input, &snapshot.key)?;
        let schema: u64 =
            input.query_row("SELECT max(schema_version) FROM schema_migration", [], |row| {
                row.get(0)
            })?;
        let erasure: u64 = input.query_row(
            "SELECT generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        drop(input);
        let filename = format!("source-{cut}-{snapshot_id}.db");
        let destination = self.directory.join(&filename);
        // Never overwrite an earlier immutable cut; hard-link then unlink also refuses
        // cross-volume inputs, keeping both stage paths within the same local owner.
        std::fs::hard_link(private_path, &destination)?;
        open_regular_linked(&destination)?.sync_all()?;
        std::fs::remove_file(private_path)?;
        drop(open_regular(&destination, false)?);
        std::fs::File::open(self.directory)?.sync_all()?;
        if let Some(parent) = private_path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        self.require_source_live()?;
        let snapshot_id = snapshot_id.to_owned();
        let key = Zeroizing::new(*snapshot.key.bytes());
        drop(snapshot); // Consume the job-owned independent key before leaving this local I/O scope.
        self.connection.call(move |db| {
            db.execute("INSERT INTO source_cut(cut,snapshot_id,filename,snapshot_key,schema_generation,erasure_generation) VALUES(?1,?2,?3,?4,?5,?6)",
                rusqlite::params![cut,snapshot_id,filename,key.as_slice(),schema,erasure])?;
            Ok(())
        })?;
        Ok(())
    }
    /// Inspect an exact saved immutable cut after ordinary unlock and local-reference recovery.
    /// The private key is scoped to this operation and erased before returning.
    /// # Errors
    /// Refuses a missing/changed cut or unavailable/stale unlocked stage owner.
    pub fn source_cut_estimated_bytes(
        &self,
        cut: u64,
        snapshot_id: &str,
    ) -> Result<u64, StorageError> {
        self.with_source_cut(cut, snapshot_id, |db| {
            Ok(db.query_row(
                "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
                [],
                |row| row.get(0),
            )?)
        })
    }
    /// Inspect the exact saved immutable source view against compiled declarations.
    /// This checks schema/counts only; typed logical encoding must still complete before Issue.
    /// # Errors
    /// Refuses a missing/stale cut, an incomplete catalog or changed schema.
    pub fn source_cut_schema(
        &self,
        cut: u64,
        snapshot_id: &str,
        rules: &'static [super::catalog::FamilyRule],
    ) -> Result<super::inventory::FullTransferSchema, StorageError> {
        self.with_source_cut(cut, snapshot_id, |input| super::inventory::inspect(input, rules))
    }
    pub(super) fn with_source_cut<T>(
        &self,
        cut: u64,
        snapshot_id: &str,
        read: impl FnOnce(&Connection) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.require_source_live()?;
        raw32(snapshot_id)?;
        if cut > 9 {
            return Err(context());
        }
        let snapshot_id = snapshot_id.to_owned();
        let expected = format!("source-{cut}-{snapshot_id}.db");
        // Direct worker closure avoids Parameters/Row clones of private key BLOBs.
        let (filename,bytes,schema,erasure) = self.connection.call(move |db| db.query_row(
            "SELECT filename,snapshot_key,schema_generation,erasure_generation FROM source_cut WHERE cut=?1 AND snapshot_id=?2",
            rusqlite::params![cut,snapshot_id], |row| Ok((row.get::<_,String>(0)?,Zeroizing::new(row.get::<_,Vec<u8>>(1)?),row.get::<_,u64>(2)?,row.get::<_,u64>(3)?)),
        ))?;
        if filename != expected {
            return Err(context());
        }
        let live_schema: u64 = self.guard.schema_generation()?;
        if live_schema != schema {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        let raw = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| context())?);
        let key = AccountDbKey::from_bytes(*raw);
        let path = self.directory.join(filename);
        drop(open_regular(&path, false)?);
        let input = open_snapshot(&path, &key)?;
        validate_snapshot(&input, &key)?;
        let current_schema: u64 =
            input.query_row("SELECT max(schema_version) FROM schema_migration", [], |row| {
                row.get(0)
            })?;
        let current_erasure: u64 = input.query_row(
            "SELECT generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if current_schema != schema || current_erasure != erasure {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        let output = read(&input)?;
        drop(input);
        drop(key);
        let live_schema: u64 = self.guard.schema_generation()?;
        if live_schema != schema {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        self.require_source_live()?;
        Ok(output)
    }
}
fn validate_snapshot(input: &Connection, key: &AccountDbKey) -> Result<(), StorageError> {
    let fingerprint: String = input.query_row(
        "SELECT key_fingerprint FROM account_key_check WHERE singleton_id=1",
        [],
        |row| row.get(0),
    )?;
    if fingerprint != key.fingerprint() {
        return Err(StorageError::AccountKeyMismatch);
    }
    Ok(())
}
fn open_snapshot(path: &Path, key: &AccountDbKey) -> Result<Connection, StorageError> {
    let input = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    crate::encryption::apply_key(&input, key)?;
    let mode = crate::encryption::current_encryption_mode(&input);
    if mode != EncryptionMode::SqlCipher && !super::super::insecure_test_sqlite_allowed() {
        return Err(StorageError::EncryptionUnavailable { mode });
    }
    input.execute_batch("PRAGMA query_only=ON; PRAGMA temp_store=MEMORY;")?;
    Ok(input)
}
fn open_regular_linked(path: &Path) -> Result<std::fs::File, StorageError> {
    // The new inode temporarily has exactly two local names during the no-clobber move.
    // Do not read/decrypt it through the ordinary owner until the old link is removed.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(context());
    }
    Ok(std::fs::File::open(path)?)
}

impl FullTransferStage<'_> {
    /// Adopt the exact private immutable cut under this stage's authenticated source role.
    /// # Errors
    /// Refuses wrong role/scope, changed paths/keys/generations or unavailable unlock.
    pub fn adopt_source_cut(
        &self,
        cut: u64,
        snapshot_id: &str,
        private_path: &Path,
        snapshot: super::super::backup::AccountBackupSnapshot,
    ) -> Result<(), StorageError> {
        self.source_context()?.adopt_source_cut(cut, snapshot_id, private_path, snapshot)
    }
    /// Measure the actual saved immutable source view without exposing its key.
    /// # Errors
    /// Refuses wrong role, missing/stale cuts, key corruption or unavailable unlock.
    pub fn source_cut_estimated_bytes(
        &self,
        cut: u64,
        snapshot_id: &str,
    ) -> Result<u64, StorageError> {
        self.source_context()?.source_cut_estimated_bytes(cut, snapshot_id)
    }
    /// Inspect the exact saved source schema/counts against compiled declarations.
    /// # Errors
    /// Refuses wrong role, missing/stale cuts, unsupported schema or unavailable unlock.
    pub fn source_cut_schema(
        &self,
        cut: u64,
        snapshot_id: &str,
        rules: &'static [super::catalog::FamilyRule],
    ) -> Result<super::inventory::FullTransferSchema, StorageError> {
        self.source_context()?.source_cut_schema(cut, snapshot_id, rules)
    }
    pub(super) fn with_source_cut<T>(
        &self,
        cut: u64,
        snapshot_id: &str,
        read: impl FnOnce(&Connection) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.source_context()?.with_source_cut(cut, snapshot_id, read)
    }
}
