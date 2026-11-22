// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retained cut state (design r3 M2 / audit A6). The stage database holds only
//! `(table, primary key, keyed digest)` and the digest key. The key is destroyed with
//! the stage. A missing set refuses; it is never treated as an empty account.
use super::FullTransferStage;
use crate::{AccountDbKey, StorageError};
use rusqlite::{OptionalExtension as _, params};
use std::path::Path;
use zeroize::{Zeroize as _, Zeroizing};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS retained_digest_key(singleton INTEGER PRIMARY KEY CHECK(singleton=1),mac_key BLOB NOT NULL CHECK(length(mac_key)=32),erasure_generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS retained_row(table_name TEXT NOT NULL,primary_key BLOB NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),PRIMARY KEY(table_name,primary_key));
CREATE TABLE IF NOT EXISTS retained_cut(singleton INTEGER PRIMARY KEY CHECK(singleton=1),present INTEGER NOT NULL CHECK(present=1));
CREATE TABLE IF NOT EXISTS retained_tail_applied(manifest_hash TEXT PRIMARY KEY,erasure_generation INTEGER NOT NULL);";

fn missing() -> StorageError {
    StorageError::PairingField("RetainedDigestMissing")
}

impl FullTransferStage<'_> {
    /// Drop the retained set when the account erasure generation has moved, and drop a
    /// partial set that has rows or a marker but no key.
    /// # Errors
    /// SQL errors. A stale set is removed and this returns `Ok`.
    pub(super) fn sweep_retained_digests(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        let stored: Option<i64> = self
            .connection
            .query_row(
                "SELECT erasure_generation FROM retained_digest_key WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let current = self.db.privacy_erasure_generation()?;
        let marked: Option<i64> = self
            .connection
            .query_row("SELECT erasure_generation FROM retained_tail_applied", [], |row| row.get(0))
            .optional()?;
        let orphan: bool = self.connection.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM retained_digest_key WHERE singleton=1 AND length(mac_key)=32) AND (EXISTS(SELECT 1 FROM retained_row) OR EXISTS(SELECT 1 FROM retained_cut))",
            [],
            |row| row.get(0),
        )?;
        let moved = stored.is_some_and(|generation| generation != current)
            || marked.is_some_and(|generation| generation != current);
        if moved || orphan {
            self.destroy_retained_digests()?;
        }
        if moved {
            self.connection.execute("DELETE FROM retained_tail_applied", [])?;
            super::stage::sync_stage(&self.directory)?;
        }
        Ok(())
    }

    /// Overwrite the digest key, then delete the set. The stage directory removal is the
    /// other half of destruction.
    /// # Errors
    /// SQL and fsync errors.
    pub(super) fn destroy_retained_digests(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        self.connection.call_immediate(|tx| {
            tx.execute(
                "UPDATE retained_digest_key SET mac_key=zeroblob(32) WHERE singleton=1",
                [],
            )?;
            tx.execute("DELETE FROM retained_digest_key", [])?;
            tx.execute("DELETE FROM retained_row", [])?;
            tx.execute("DELETE FROM retained_cut", [])?;
            Ok(())
        })?;
        super::stage::sync_stage(&self.directory)
    }

    /// The tail calls this. Absence, a wiped key, or a generation sweep is a refusal.
    /// # Errors
    /// `PairingField("RetainedDigestMissing")` when the set is not present; SQL errors.
    pub(super) fn require_retained_digests(&self) -> Result<(), StorageError> {
        self.sweep_retained_digests()?;
        let ready: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM retained_cut WHERE singleton=1) AND EXISTS(SELECT 1 FROM retained_digest_key WHERE singleton=1 AND length(mac_key)=32)",
            [],
            |row| row.get(0),
        )?;
        if ready {
            Ok(())
        } else {
            self.destroy_retained_digests()?;
            Err(missing())
        }
    }

    /// Replace the retained set with the keyed digests of this installed clean copy.
    /// Only the last installed cut stays.
    /// # Errors
    /// `RetainedDigestMissing` when the write does not leave a readable set; open and
    /// size refusals from the export; SQL errors.
    pub(super) fn retain_installed_export(
        &self,
        path: &Path,
        key: &AccountDbKey,
        expected_root: &str,
    ) -> Result<(), StorageError> {
        self.sweep_retained_digests()?;
        let generation = self.db.privacy_erasure_generation()?;
        retain_export_rows(
            &self.connection,
            &self.directory,
            path,
            key,
            expected_root,
            generation,
        )?;
        self.require_retained_digests()
    }

    /// The digest key, without creating one. Apply and the tail check use this.
    /// # Errors
    /// `RetainedDigestMissing` when the key row is absent or not 32 bytes.
    pub(super) fn load_retained_mac(&self) -> Result<Zeroizing<[u8; 32]>, StorageError> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT mac_key FROM retained_digest_key WHERE singleton=1 AND length(mac_key)=32",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(mut bytes) = stored else {
            return Err(missing());
        };
        let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| missing())?;
        bytes.zeroize();
        Ok(Zeroizing::new(key))
    }

    /// Hash already applied for this erasure generation, if the tail committed.
    /// # Errors
    /// SQL errors. More than one marker row is an error.
    pub(super) fn retained_tail_applied_hash(&self) -> Result<Option<String>, StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        self.connection
            .query_row("SELECT manifest_hash FROM retained_tail_applied", [], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }

    /// Record that this tail hash committed, then fsync the stage. The key set is separate.
    /// # Errors
    /// SQL and fsync errors. A second marker row fails rather than replacing the first.
    pub(super) fn mark_retained_tail_applied(&self, hash: &str) -> Result<(), StorageError> {
        let generation = self.db.privacy_erasure_generation()?;
        self.connection.execute(
            "INSERT INTO retained_tail_applied(manifest_hash,erasure_generation) VALUES(?1,?2)",
            params![hash, generation],
        )?;
        super::stage::sync_stage(&self.directory)
    }
}

fn load_or_create_key(
    connection: &crate::database::Connection,
) -> Result<Zeroizing<[u8; 32]>, StorageError> {
    let stored: Option<Vec<u8>> = connection
        .query_row(
            "SELECT mac_key FROM retained_digest_key WHERE singleton=1 AND length(mac_key)=32",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match stored {
        Some(mut bytes) => {
            let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| missing())?;
            bytes.zeroize();
            Ok(Zeroizing::new(key))
        }
        None => Ok(Zeroizing::new(ramflux_crypto::random_32()?)),
    }
}

fn write_set(
    connection: &crate::database::Connection,
    directory: &Path,
    mac: &[u8; 32],
    generation: i64,
    rows: Vec<crate::account_db::transfer_export::digest::RowDigest>,
) -> Result<(), StorageError> {
    let mac = Zeroizing::new(mac.to_vec());
    connection.call_immediate(move |tx| {
        tx.execute("DELETE FROM retained_row", [])?;
        tx.execute("DELETE FROM retained_cut", [])?;
        tx.execute(
            "INSERT INTO retained_digest_key(singleton,mac_key,erasure_generation) VALUES(1,?1,?2) ON CONFLICT(singleton) DO UPDATE SET erasure_generation=excluded.erasure_generation",
            params![mac.as_slice(), generation],
        )?;
        for row in &rows {
            tx.execute(
                "INSERT INTO retained_row(table_name,primary_key,digest) VALUES(?1,?2,?3)",
                params![row.table, &row.key, row.digest.as_slice()],
            )?;
        }
        tx.execute("INSERT INTO retained_cut(singleton,present) VALUES(1,1)", [])?;
        Ok(())
    })?;
    super::stage::sync_stage(directory)
}

/// Write the keyed digests of an installed clean copy. The caller supplies the erasure
/// generation. A live stage still sweeps before calling this.
/// # Errors
/// Open and size refusals from the export; SQL errors.
pub(super) fn retain_export_rows(
    connection: &crate::database::Connection,
    directory: &Path,
    path: &Path,
    key: &AccountDbKey,
    expected_root: &str,
    generation: i64,
) -> Result<(), StorageError> {
    connection.execute_batch(SCHEMA)?;
    let verified = crate::account_db::transfer_export::open_verified::VerifiedExport::open(
        path,
        key,
        expected_root,
    )?;
    verified.allow_row_read();
    let mac = load_or_create_key(connection)?;
    let mac_bytes: &[u8; 32] = &mac;
    let rows = crate::account_db::transfer_export::digest::rows(verified.connection(), mac_bytes)?;
    write_set(connection, directory, mac_bytes, generation, rows)
}

/// The digest set must be readable after a replay install. No live sweep: the generation
/// was pinned with the copy.
/// # Errors
/// `RetainedDigestMissing` when the set is absent. SQL errors.
pub(super) fn require_export_rows(
    connection: &crate::database::Connection,
    directory: &Path,
) -> Result<(), StorageError> {
    connection.execute_batch(SCHEMA)?;
    let ready: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM retained_cut WHERE singleton=1) AND EXISTS(SELECT 1 FROM retained_digest_key WHERE singleton=1 AND length(mac_key)=32)",
        [],
        |row| row.get(0),
    )?;
    if ready {
        Ok(())
    } else {
        destroy_export_rows(connection, directory)?;
        Err(missing())
    }
}

/// Overwrite and delete the digest set on this stage connection.
/// # Errors
/// SQL and fsync errors.
pub(super) fn destroy_export_rows(
    connection: &crate::database::Connection,
    directory: &Path,
) -> Result<(), StorageError> {
    connection.execute_batch(SCHEMA)?;
    connection.call_immediate(|tx| {
        tx.execute("UPDATE retained_digest_key SET mac_key=zeroblob(32) WHERE singleton=1", [])?;
        tx.execute("DELETE FROM retained_digest_key", [])?;
        tx.execute("DELETE FROM retained_row", [])?;
        tx.execute("DELETE FROM retained_cut", [])?;
        Ok(())
    })?;
    super::stage::sync_stage(directory)
}

/// Off-loan replay can retain an installed export without the live account loan.
pub(super) trait ExportRetain {
    /// # Errors
    /// `RetainedDigestMissing` when the set does not stay readable; open and SQL errors.
    fn retain_export_frame(
        &self,
        path: &Path,
        key: &AccountDbKey,
        expected_root: &str,
        generation: i64,
    ) -> Result<(), StorageError>;
    /// # Errors
    /// SQL and fsync errors.
    fn discard_retained_export(&self) -> Result<(), StorageError>;
}

impl ExportRetain for FullTransferStage<'_> {
    fn retain_export_frame(
        &self,
        path: &Path,
        key: &AccountDbKey,
        expected_root: &str,
        _generation: i64,
    ) -> Result<(), StorageError> {
        self.retain_installed_export(path, key, expected_root)
    }
    fn discard_retained_export(&self) -> Result<(), StorageError> {
        self.destroy_retained_digests()
    }
}
