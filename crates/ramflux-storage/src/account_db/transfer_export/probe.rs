// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration-only probes (feature `itest-transfer-probe`, never in production graphs): drive
//! A's export on a live account and B's hardened open plus clean copy on a file, without the
//! transfer channel. The transfer itself exports from the pinned source cut instead.
use super::builder::{self, Side};
use super::contract::export_contract_digest;
use super::open_verified::VerifiedExport;
use crate::{AccountDb, AccountDbKey, StorageError};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// What A's export probe wrote.
#[derive(Clone, Debug)]
pub struct ProbeExport {
    pub rows: u64,
    pub bytes: u64,
    pub framed_bytes: u64,
    pub contract_digest: [u8; 32],
    pub elapsed_ms: u64,
    pub tables: Vec<(&'static str, u64)>,
    /// Projected directory namespaces: prefix, row count, JSON key names (no values).
    pub directory: Vec<DirectoryKeys>,
    /// `runtime_account_identity.principal_commitment` of the exported account (public).
    pub root: String,
}

/// Key names written for one directory namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryKeys {
    pub prefix: &'static str,
    pub rows: u64,
    pub keys: Vec<String>,
}

/// What B's open probe verified and copied.
#[derive(Clone, Debug)]
pub struct ProbeOpen {
    pub rows: u64,
    pub bytes: u64,
    pub open_ms: u64,
    pub copy_ms: u64,
    pub tables: Vec<(&'static str, u64)>,
    /// Projected directory namespaces: prefix, row count, JSON key names (no values).
    pub directory: Vec<DirectoryKeys>,
}

fn millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl AccountDb {
    /// Export this unlocked account into a new canonical file at `target` under `key`,
    /// inside one read transaction of the live database, and apply the per-cut size limit.
    /// # Errors
    /// The builder's refusals, `PairingField("NoSpace")` over the limit, SQL and I/O errors.
    pub fn itest_transfer_export(
        &self,
        target: &Path,
        key: &AccountDbKey,
    ) -> Result<ProbeExport, StorageError> {
        let start = Instant::now();
        let path: PathBuf = target.to_owned();
        let key = key.clone();
        let built = self.connection.call(move |db| {
            let read = db.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
            let root: String = read.query_row(
                "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let built = builder::build(&read, Side::Account, &path, &key);
            read.finish()?;
            Ok((root, built))
        })?;
        let (root, built) = built;
        let built = match built {
            Ok(built) => built,
            Err(error) => {
                drop(std::fs::remove_file(target));
                return Err(error);
            }
        };
        let framed_bytes = super::require_cut_size(built.bytes, 0)?;
        let directory = directory_keys(&built);
        Ok(ProbeExport {
            rows: built.rows,
            bytes: built.bytes,
            framed_bytes,
            contract_digest: export_contract_digest()?,
            elapsed_ms: millis(start),
            tables: built.tables,
            directory,
            root,
        })
    }
}

/// Run `open_verified` on `file` and build B's clean copy at `target` under a fresh key.
/// # Errors
/// `TransferExportRefused(step)` naming the refusing step; SQL and I/O errors.
pub fn itest_transfer_open(
    file: &Path,
    key: &AccountDbKey,
    expected_root: &str,
    target: &Path,
) -> Result<ProbeOpen, StorageError> {
    let start = Instant::now();
    let verified = VerifiedExport::open(file, key, expected_root)?;
    let open_ms = millis(start);
    let copy_key = AccountDbKey::generate()?;
    let copy_start = Instant::now();
    let built = verified.clean_copy(target, &copy_key);
    drop(verified);
    let built = match built {
        Ok(built) => built,
        Err(error) => {
            drop(std::fs::remove_file(target));
            return Err(error);
        }
    };
    let directory = directory_keys(&built);
    Ok(ProbeOpen {
        rows: built.rows,
        bytes: built.bytes,
        open_ms,
        copy_ms: millis(copy_start),
        tables: built.tables,
        directory,
    })
}

fn directory_keys(built: &builder::Built) -> Vec<DirectoryKeys> {
    built
        .directory
        .iter()
        .map(|shape| DirectoryKeys {
            prefix: shape.prefix,
            rows: shape.rows,
            keys: shape.keys.clone(),
        })
        .collect()
}
