// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-base contribution provenance and normalized private root. No DV or selection.
use super::{
    FullUnionEncoding, full_transfer_catalog, source_base::Rooted, source_scalar::compiled,
};
use crate::{AccountDbKey, BackupDatabase, StorageError};
use ramflux_protocol::custody::{
    DeviceRef,
    pairing::full_transfer::{RecordHeader, read_record_header},
};
use rusqlite::{Connection, params};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::{Zeroize as _, Zeroizing};

mod delta;
mod target;

pub(super) struct Contributions {
    pub(super) nonce: [u8; 32],
    pub(super) owners: [String; 2],
}
#[derive(Clone, Copy)]
pub(super) struct TargetRows<'a> {
    pub(super) current: &'a BackupDatabase,
    pub(super) schema: &'a super::FullTransferSchema,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn live(cancelled: &AtomicBool) -> Result<(), StorageError> {
    if cancelled.load(Ordering::Acquire) {
        Err(StorageError::PairingField("Cancelled"))
    } else {
        Ok(())
    }
}
struct Header(RecordHeader);
impl Drop for Header {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

pub(super) fn open(path: &Path, key: &AccountDbKey) -> Result<Connection, StorageError> {
    drop(super::stage::open_regular(path, true)?);
    let db = Connection::open(path)?;
    let hex = Zeroizing::new(key.sqlcipher_hex());
    let pragma = Zeroizing::new(format!(
        "PRAGMA key=\"x'{}'\"; PRAGMA cache_size=-2048; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
        hex.as_str()
    ));
    db.execute_batch(&pragma)?;
    super::union_encoding::require_existing_format(&db)?;
    Ok(db)
}

impl Contributions {
    pub(super) fn capture(
        path: &Path,
        key: &AccountDbKey,
        private: &BackupDatabase,
        owners: [&DeviceRef; 2],
        cancelled: &Arc<AtomicBool>,
        schema: &super::FullTransferSchema,
    ) -> Result<Self, StorageError> {
        let value = Self {
            nonce: ramflux_crypto::random_32()?,
            owners: [
                super::super::mac_subkeys::full::source_key(owners[0])?,
                super::super::mac_subkeys::full::source_key(owners[1])?,
            ],
        };
        super::stage::create_file(path)?.sync_all()?;
        let mut db = open(path, key)?;
        db.execute_batch(&super::union_encoding::schema())?;
        let tx = db.transaction()?;
        schema.require_typed_owners(full_transfer_catalog())?;
        for (family, rule) in schema.families.iter().zip(full_transfer_catalog()) {
            if family.source_rows.0 == 0
                || rule.disposition
                    != ramflux_protocol::custody::pairing::full_transfer::Disposition::Transfer
            {
                continue;
            }
            compiled(rule.id)?;
            let super::FamilySelector::Table(table) = rule.selector else {
                return Err(invalid());
            };
            let columns =
                rule.cells.iter().map(|c| format!("\"{}\"", c.name)).collect::<Vec<_>>().join(",");
            let mut statement =
                private.db.prepare(&format!("SELECT {columns} FROM \"{table}\""))?;
            let mut rows = statement.query([])?;
            let mut count = 0_u64;
            while let Some(row) = rows.next()? {
                live(cancelled)?;
                if rule.id == "sql/full_imported_mac_bundle" {
                    let original = super::super::mac_subkeys::full::decode_source_ref(
                        row.get_ref(0)?.as_str().map_err(|_| invalid())?.as_bytes(),
                    )?;
                    if original.account_anchor != owners[1].account_anchor {
                        return Err(invalid());
                    }
                }
                super::record_spool::Candidate::sql(
                    &private.db,
                    &tx,
                    rule,
                    row,
                    &owners[1].account_anchor,
                )?
                .retain_union(&value.nonce, &value.owners[1], false)?;
                count = count.checked_add(1).ok_or_else(invalid)?;
            }
            if count != family.source_rows.0 {
                return Err(invalid());
            }
        }
        live(cancelled)?;
        tx.commit()?;
        Ok(value)
    }
    pub(super) fn finish(
        &self,
        path: &Path,
        key: &AccountDbKey,
        private: &BackupDatabase,
        stage: &impl super::receiver_read::ReceiverInput,
        hash: &str,
    ) -> Result<FullUnionEncoding, StorageError> {
        stage.require_io()?;
        let mut db = open(path, key)?;
        let tx = db.transaction()?;
        tx.execute(
            "DELETE FROM full_union_record WHERE generation_nonce=?1 AND owner=?2",
            params![self.nonce.as_slice(), self.owners[0]],
        )?;
        let mut input = stage.forward_reader(hash)?;
        while let Some(header) = read_record_header(&mut input).map_err(|_| invalid())? {
            stage.require_io()?;
            let rule = compiled(&header.family)?;
            super::record_spool::Candidate::input(&tx, rule, header, &mut input)?.retain_union(
                &self.nonce,
                &self.owners[0],
                false,
            )?;
        }
        let encoding = self.root(&tx, private, stage)?;
        tx.commit()?;
        drop(db);
        crate::sync_path::sync_path(path)?;
        crate::sync_path::sync_path(path.parent().ok_or_else(invalid)?)?;
        Ok(encoding)
    }
    fn root(
        &self,
        tx: &Connection,
        private: &BackupDatabase,
        stage: &impl super::receiver_read::ReceiverInput,
    ) -> Result<FullUnionEncoding, StorageError> {
        super::monotonic::normalize(tx, &self.nonce, private, &self.owners)?;
        let guard = stage.source_guard();
        super::direct_union::normalize(tx, &self.nonce, private, &self.owners, &guard)?;
        let (records, total) = super::union_encoding::visit(
            tx,
            &self.nonce,
            &self.owners,
            &mut std::io::sink(),
            &guard,
        )?;
        let mut rooted = Rooted::new(std::io::sink(), total)?;
        if super::union_encoding::visit(tx, &self.nonce, &self.owners, &mut rooted, &guard)?
            != (records, total)
        {
            return Err(invalid());
        }
        let root = rooted.finish(total)?.1;
        tx.execute("INSERT INTO full_union_encoding(generation_nonce,records,total_bytes,chunks_root) VALUES(?1,?2,?3,?4) ON CONFLICT(generation_nonce) DO UPDATE SET records=excluded.records,total_bytes=excluded.total_bytes,chunks_root=excluded.chunks_root",params![self.nonce.as_slice(),records,total,root.as_slice()])?;
        stage.require_io()?;
        Ok(FullUnionEncoding {
            generation_nonce: self.nonce,
            records,
            total_bytes: total,
            chunks_root: root,
        })
    }
}

// Only explicitly registered content owners can remove an absent contribution. Excluded
// local execution, imported MAC denial capabilities and restrictions are never deleted here.
fn removable(family: &str) -> bool {
    family == super::direct_union::FAMILY
        || family == "sql/object_payload_dependency"
        || super::monotonic::owner(family).is_some_and(super::monotonic::Owner::removable)
}
fn remove_materialized(
    private: &BackupDatabase,
    header: &RecordHeader,
    cells: &super::fixed_union::Cells,
) -> Result<(), StorageError> {
    if let Some(owner) = super::monotonic::owner(&header.family) {
        owner.remove(&private.db, cells)
    } else if header.family == "sql/object_payload_dependency" {
        private.db.execute("DELETE FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2",params![cells.text(0)?,cells.text(1)?])?;
        Ok(())
    } else {
        Err(invalid())
    }
}
