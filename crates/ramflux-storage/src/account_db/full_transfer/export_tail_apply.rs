// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Apply one export-census tail. The symmetric rule uses the retained digests.
//! Archiving stays off: this path never calls the backup archive writer.
//! `runtime_account_identity` is not exempt.
use super::export_tail::{self, SpilledExport};
use super::receiver_read::{OwnedReceiverInput, ReceiverInput};
use super::{FullScalarInputCounts, FullTailEndpoint};
use crate::StorageError;
use crate::account_db::transfer_export::digest::{self, ExportedRow, RowDigest};
use ramflux_protocol::custody::pairing::full_transfer::PREPUBLICATION_DELTA_STOP_BYTES;
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

type Key = (String, Vec<u8>);
type Digests = BTreeMap<Key, [u8; 32]>;

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
fn missing() -> StorageError {
    StorageError::PairingField("RetainedDigestMissing")
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}

struct Delete {
    sql: String,
    values: Vec<Value>,
}
struct Insert {
    sql: String,
    exists_sql: String,
    key_values: Vec<Value>,
    values: Vec<Value>,
}

/// Check the framed tail and its deletion section. Does not write the account.
/// # Errors
/// `RetainedDigestMissing` when the set or the key is absent; `ManifestMismatch` when
/// the section is not the retained keys absent from the tail file; `NoSpace` over 64 MiB.
pub(super) fn validate_export_tail(
    input: &OwnedReceiverInput,
    hash: &str,
) -> Result<FullScalarInputCounts, StorageError> {
    let manifest = input.forward_manifest(hash)?;
    let bytes = read_signed(&mut input.forward_reader(hash)?, manifest.manifest.total_bytes.0)?;
    let (spilled, deletion) =
        spill(input.directory(), hash, &bytes, &manifest.manifest.account_anchor)?;
    let tail = digest::primary_keys(spilled.verified.connection())?;
    require_present(input.stage_connection())?;
    let retained = load_keys(input.stage_connection())?;
    let tail_keys = key_set(tail.iter().map(|row| (row.table.to_owned(), row.key.clone())));
    require_section(&deletion, &retained, &tail_keys)?;
    Ok(FullScalarInputCounts {
        records: u64::try_from(tail.len()).map_err(|_| mismatch())?,
        encoded_bytes: manifest.manifest.total_bytes.0,
    })
}

/// Apply the tail as one immediate transaction on B's open account. The scratch copy is
/// only the read cut for the digest plan. The account stays WAL, the file is not renamed,
/// and the open connection stays usable. The keyed set is destroyed only after that commit.
/// A retry that finds this hash's marker destroys any leftover key and returns success.
/// # Errors
/// `RetainedDigestMissing` when the set is gone and this hash was not marked;
/// `ManifestMismatch` when the section or a row decision disagrees; `WrongContext`
/// when a different tail hash is already marked.
pub(super) fn apply_export_tail(
    endpoint: &FullTailEndpoint<'_>,
    hash: &str,
) -> Result<bool, StorageError> {
    match endpoint.stage.retained_tail_applied_hash()? {
        Some(existing) if existing == hash => {
            endpoint.stage.destroy_retained_digests()?;
            return Ok(true);
        }
        Some(_) => return Err(wrong()),
        None => {}
    }
    endpoint.stage.require_retained_digests()?;
    let manifest = endpoint.stage.forward_manifest(hash)?;
    let bytes =
        read_signed(&mut endpoint.stage.forward_reader(hash)?, manifest.manifest.total_bytes.0)?;
    let (spilled, deletion) =
        spill(&endpoint.stage.directory, hash, &bytes, &manifest.manifest.account_anchor)?;
    let mac = endpoint.stage.load_retained_mac()?;
    let mac_bytes: &[u8; 32] = &mac;
    let tail = digest::rows_with_values(spilled.verified.connection(), mac_bytes)?;
    let retained = load_digests(&endpoint.stage.connection)?;
    let tail_keys = key_set(tail.iter().map(|row| (row.table.to_owned(), row.key.clone())));
    require_section(&deletion, &retained_keys(&retained), &tail_keys)?;
    let job = CopyJob {
        directory: endpoint.stage.directory.clone(),
        live_path: endpoint.stage.db.path.clone(),
        key: endpoint.stage.db.current_key.clone(),
        mac,
        tail,
        retained,
    };
    endpoint.stage.db.connection.call(move |db| Ok(apply_on_copy(db, &job)))??;
    let parent = endpoint.stage.db.path.parent().ok_or_else(wrong)?;
    super::stage::sync_regular(&endpoint.stage.db.path)?;
    crate::sync_path::sync_path(parent)?;
    endpoint.stage.mark_retained_tail_applied(hash)?;
    endpoint.stage.destroy_retained_digests()?;
    Ok(true)
}

struct CopyJob {
    directory: std::path::PathBuf,
    live_path: std::path::PathBuf,
    key: crate::AccountDbKey,
    mac: zeroize::Zeroizing<[u8; 32]>,
    tail: Vec<ExportedRow>,
    retained: Digests,
}

fn apply_on_copy(live: &mut rusqlite::Connection, job: &CopyJob) -> Result<(), StorageError> {
    let copy = super::export_tail_swap::stage_copy(live, &job.directory, &job.key)?;
    let mac_bytes: &[u8; 32] = &job.mac;
    let current = digest_map(digest::rows(copy.after(), mac_bytes)?)?;
    let tail_keys = key_set(job.tail.iter().map(|row| (row.table.to_owned(), row.key.clone())));
    let (deletes, inserts) = plan(&job.tail, &job.retained, &current, &tail_keys)?;
    copy.commit_and_replace(live, &job.live_path, |tx| commit(tx, &deletes, &inserts))
}

fn spill(
    directory: &std::path::Path,
    hash: &str,
    bytes: &[u8],
    anchor: &str,
) -> Result<(SpilledExport, Vec<u8>), StorageError> {
    let split = export_tail::split_stream(bytes, true)?;
    let spilled =
        export_tail::open_spilled(directory, &temp_name(hash)?, &split.file, &split.key, anchor)?;
    Ok((spilled, split.deletion))
}

fn temp_name(hash: &str) -> Result<String, StorageError> {
    let safe = !hash.is_empty()
        && hash.len() <= 128
        && hash.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if safe { Ok(format!("export-tail-{hash}.db")) } else { Err(wrong()) }
}

fn read_signed(reader: &mut impl Read, total: u64) -> Result<Vec<u8>, StorageError> {
    if total > PREPUBLICATION_DELTA_STOP_BYTES {
        return Err(StorageError::PairingField("NoSpace"));
    }
    let len = usize::try_from(total).map_err(|_| StorageError::PairingField("NoSpace"))?;
    let mut buffer = vec![0_u8; len];
    let mut filled = 0_usize;
    while filled < len {
        let read = reader.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(mismatch());
        }
        filled = filled.saturating_add(read);
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? == 0 { Ok(buffer) } else { Err(mismatch()) }
}

fn require_present(connection: &crate::database::Connection) -> Result<(), StorageError> {
    connection.execute_batch(super::retained_digest::SCHEMA)?;
    let ready: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM retained_cut WHERE singleton=1) AND EXISTS(SELECT 1 FROM retained_digest_key WHERE singleton=1 AND length(mac_key)=32)",
        [],
        |row| row.get(0),
    )?;
    if ready { Ok(()) } else { Err(missing()) }
}

fn load_keys(connection: &crate::database::Connection) -> Result<BTreeSet<Key>, StorageError> {
    connection.call(|db| {
        let mut statement = db.prepare("SELECT table_name,primary_key FROM retained_row")?;
        let mut rows = statement.query([])?;
        let mut set = BTreeSet::new();
        while let Some(row) = rows.next()? {
            if set.len() == 1_048_576 {
                return Ok(Err(StorageError::PairingField("NoSpace")));
            }
            set.insert((row.get(0)?, row.get(1)?));
        }
        Ok(Ok(set))
    })?
}

fn load_digests(connection: &crate::database::Connection) -> Result<Digests, StorageError> {
    connection.call(|db| {
        let mut statement = db.prepare("SELECT table_name,primary_key,digest FROM retained_row")?;
        let mut rows = statement.query([])?;
        let mut map = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let digest: Vec<u8> = row.get(2)?;
            let digest: [u8; 32] =
                digest.as_slice().try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
            map.insert((row.get(0)?, row.get(1)?), digest);
        }
        Ok(Ok(map))
    })?
}

fn digest_map(rows: Vec<RowDigest>) -> Result<Digests, StorageError> {
    let mut map = BTreeMap::new();
    for row in rows {
        if map.insert((row.table.to_owned(), row.key), row.digest).is_some() {
            return Err(mismatch());
        }
    }
    Ok(map)
}

fn key_set(rows: impl Iterator<Item = Key>) -> BTreeSet<Key> {
    rows.collect()
}

fn retained_keys(retained: &Digests) -> BTreeSet<Key> {
    retained.keys().cloned().collect()
}

fn require_section(
    section: &[u8],
    retained: &BTreeSet<Key>,
    tail: &BTreeSet<Key>,
) -> Result<(), StorageError> {
    let expected: Vec<Key> = retained.difference(tail).cloned().collect();
    if super::export_deletion::decode(section)? == expected { Ok(()) } else { Err(mismatch()) }
}

fn plan(
    tail: &[ExportedRow],
    retained: &Digests,
    current: &Digests,
    tail_keys: &BTreeSet<Key>,
) -> Result<(Vec<Delete>, Vec<Insert>), StorageError> {
    let mut deletes = Vec::new();
    let mut inserts = Vec::new();
    for row in tail {
        let key = (row.table.to_owned(), row.key.clone());
        if write_row(retained.get(&key).copied(), current.get(&key).copied(), row.digest) {
            if current.contains_key(&key) {
                deletes.push(delete_of(row.table, &row.key)?);
            }
            inserts.push(insert_of(row)?);
        }
    }
    for key in retained.keys() {
        if tail_keys.contains(key) {
            continue;
        }
        let Some(old) = retained.get(key).copied() else { continue };
        if current.get(key).copied() == Some(old) {
            deletes.push(delete_of(&key.0, &key.1)?);
        }
    }
    Ok((deletes, inserts))
}

fn write_row(old: Option<[u8; 32]>, now: Option<[u8; 32]>, tail: [u8; 32]) -> bool {
    match (old, now) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(old), None) => old != tail,
        (Some(old), Some(now)) => now == old && old != tail,
    }
}

fn delete_of(table: &str, key: &[u8]) -> Result<Delete, StorageError> {
    let sql = digest::row_sql(table)?;
    Ok(Delete { sql: sql.delete_sql, values: digest::key_values(table, key)? })
}

fn insert_of(row: &ExportedRow) -> Result<Insert, StorageError> {
    let sql = digest::row_sql(row.table)?;
    Ok(Insert {
        sql: sql.insert,
        exists_sql: sql.exists_sql,
        key_values: digest::key_values(row.table, &row.key)?,
        values: row.values.clone(),
    })
}

fn commit(
    tx: &rusqlite::Transaction<'_>,
    deletes: &[Delete],
    inserts: &[Insert],
) -> Result<(), StorageError> {
    for delete in deletes {
        if tx.execute(&delete.sql, params_from_iter(delete.values.iter()))? != 1 {
            return Err(mismatch());
        }
    }
    for insert in inserts {
        let present: bool =
            tx.query_row(&insert.exists_sql, params_from_iter(insert.key_values.iter()), |row| {
                row.get(0)
            })?;
        if present {
            return Err(mismatch());
        }
        tx.execute(&insert.sql, params_from_iter(insert.values.iter()))?;
    }
    Ok(())
}
