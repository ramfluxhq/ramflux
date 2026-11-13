// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-base contribution provenance and normalized private root. No DV or selection.
use super::{
    FullUnionEncoding, full_transfer_catalog, source_base::Rooted, source_scalar::compiled,
};
use crate::{AccountDbKey, BackupDatabase, StorageError};
use ramflux_protocol::custody::{
    DeviceRef,
    pairing::full_transfer::{RecordHeader, read_record_header, write_record_header},
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

pub(super) struct Contributions {
    pub(super) nonce: [u8; 32],
    pub(super) owners: [String; 2],
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
    Ok(db)
}
fn retain(
    db: &Connection,
    nonce: &[u8; 32],
    owner: &str,
    bytes: &[u8],
) -> Result<(), StorageError> {
    if bytes.len() > 16384 {
        return Err(invalid());
    }
    let mut input = bytes;
    let header =
        Header(read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?);
    let rule = compiled(&header.0.family)?;
    super::copy_full_scalar_record(rule, &header.0, &mut input, &mut std::io::sink())?;
    if !input.is_empty() {
        return Err(invalid());
    }
    let changed = db.execute("INSERT INTO full_union_record(generation_nonce,owner,family,key,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record WHERE full_union_record.record=excluded.record", params![nonce.as_slice(),owner,header.0.family,header.0.key,bytes])?;
    if changed != 1 {
        return Err(StorageError::PairingField("TransferConflict"));
    }
    Ok(())
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
        db.execute_batch(super::union_encoding::SCHEMA)?;
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
                let mut record = Zeroizing::new(Vec::new());
                super::write_full_scalar_sql_row(rule, row, &mut *record)?;
                retain(&tx, &value.nonce, &value.owners[1], &record)?;
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
            let header = Header(header);
            let rule = compiled(&header.0.family)?;
            let mut record = Zeroizing::new(Vec::new());
            write_record_header(&mut *record, &header.0).map_err(|_| invalid())?;
            super::copy_full_scalar_record(rule, &header.0, &mut input, &mut *record)?;
            retain(&tx, &self.nonce, &self.owners[0], &record)?;
        }
        let encoding = self.root(&tx, private, stage)?;
        tx.commit()?;
        drop(db);
        std::fs::File::open(path)?.sync_all()?;
        std::fs::File::open(path.parent().ok_or_else(invalid)?)?.sync_all()?;
        Ok(encoding)
    }
    fn root(
        &self,
        tx: &Connection,
        private: &BackupDatabase,
        stage: &impl super::receiver_read::ReceiverInput,
    ) -> Result<FullUnionEncoding, StorageError> {
        // The only mutable fixed base owner is the declared erasure-generation maximum.
        // Both contribution records must describe the actual normalized prepared value.
        let rule = compiled("sql/account_erasure_generation")?;
        let mut normalized = Zeroizing::new(Vec::new());
        private.db.query_row(
            "SELECT singleton,generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |row| Ok(super::write_full_scalar_sql_row(rule, row, &mut *normalized)),
        )??;
        tx.execute("UPDATE full_union_record SET record=?1 WHERE generation_nonce=?2 AND family='sql/account_erasure_generation'",params![normalized.as_slice(),self.nonce.as_slice()])?;
        let guard = stage.source_guard();
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
