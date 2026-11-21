// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compare every qualified fixed contribution with actual private-generation records.
use super::{
    FullUnionEncoding, full_transfer_catalog,
    source_base::Rooted,
    source_scalar::{SourceGuard, compiled},
};
use crate::{AccountDbKey, BackupDatabase, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{RecordHeader, read_record_header};
use rusqlite::{Connection, params};
use std::path::Path;
use zeroize::Zeroize as _;

mod verification_file;

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
struct Header(RecordHeader);
impl Drop for Header {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

pub(super) struct Verification<'a, I: super::receiver_read::ReceiverInput> {
    pub(super) directory: &'a Path,
    pub(super) key: &'a AccountDbKey,
    pub(super) encoding: &'a FullUnionEncoding,
    pub(super) owners: &'a [String; 2],
    pub(super) private: &'a BackupDatabase,
    pub(super) private_key: &'a AccountDbKey,
    pub(super) stage: &'a I,
}
impl<I: super::receiver_read::ReceiverInput> Verification<'_, I> {
    pub(super) fn run(&self) -> Result<(), StorageError> {
        self.stage.require_io()?;
        let comparison = verification_file::VerificationFile::create(self.directory)?;
        let path = self.directory.join("contributions.db");
        let mut db = super::receiver_contributions::open(&path, self.key)?;
        comparison.attach(&db, self.key)?;
        let tx = db.transaction()?;
        let guard = self.stage.source_guard();
        self.verify_root(&tx, &guard)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS verifier.materialized_record(family TEXT NOT NULL,key TEXT NOT NULL COLLATE BINARY,record BLOB NOT NULL,seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN(0,1)),PRIMARY KEY(family,key)) WITHOUT ROWID; DELETE FROM verifier.materialized_record;")?;
        self.expected(&tx)?;
        self.actual(&tx)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM verifier.materialized_record WHERE seen=0)",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(mismatch());
        }
        self.stage.require_io()?;
        tx.commit()?;
        Ok(())
    }
    fn verify_root(&self, db: &Connection, guard: &SourceGuard) -> Result<(), StorageError> {
        let mut rooted = Rooted::new(std::io::sink(), self.encoding.total_bytes)?;
        let (records, total) = super::union_encoding::visit(
            db,
            &self.encoding.generation_nonce,
            self.owners,
            &mut rooted,
            guard,
        )?;
        if records != self.encoding.records
            || total != self.encoding.total_bytes
            || rooted.finish(total)?.1 != self.encoding.chunks_root
        {
            return Err(mismatch());
        }
        Ok(())
    }
    fn expected(&self, db: &Connection) -> Result<(), StorageError> {
        let mut statement = db.prepare("SELECT owner,family,key,rowid,length(record) FROM full_union_record WHERE generation_nonce=?1 ORDER BY owner COLLATE BINARY,family COLLATE BINARY,key COLLATE BINARY")?;
        let mut rows = statement.query(params![self.encoding.generation_nonce.as_slice()])?;
        while let Some(row) = rows.next()? {
            self.stage.require_io()?;
            let owner = row.get_ref(0)?.as_str().map_err(|_| mismatch())?;
            let rule = compiled(row.get_ref(1)?.as_str().map_err(|_| mismatch())?)?;
            let key = row.get_ref(2)?.as_str().map_err(|_| mismatch())?;
            let rowid = row.get::<_, i64>(3)?;
            let mut input = super::record_spool::checked_blob(
                db,
                "full_union_record",
                rowid,
                row.get(4)?,
                rule,
                key,
            )?;
            let header = Header(
                read_record_header(&mut input).map_err(|_| mismatch())?.ok_or_else(mismatch)?,
            );
            if owner == self.owners[0] && header.0.family == "sql/account_mac_bundle/portable" {
                let cells = super::fixed_union::Cells::read(
                    compiled(&header.0.family)?,
                    &header.0,
                    &mut input,
                )?;
                super::record_spool::expected_imported_mac(db,owner,&cells)?;
            } else if db.execute("INSERT INTO verifier.materialized_record(family,key,record) SELECT family,key,record FROM full_union_record WHERE rowid=?1 ON CONFLICT(family,key) DO UPDATE SET record=excluded.record WHERE verifier.materialized_record.record=excluded.record",[rowid])? != 1 {return Err(mismatch());}
        }
        Ok(())
    }
    fn actual(&self, db: &Connection) -> Result<(), StorageError> {
        let read = crate::database::Connection::open_with_flags(
            Path::new(self.private.db.path().ok_or_else(mismatch)?),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        crate::encryption::apply_key(&read, self.private_key)?;
        read.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
        let schema = super::inventory::inspect(&read, full_transfer_catalog())?;
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
                return Err(mismatch());
            };
            let columns = rule
                .cells
                .iter()
                .map(|cell| format!("\"{}\"", cell.name))
                .collect::<Vec<_>>()
                .join(",");
            let mut statement =
                self.private.db.prepare(&format!("SELECT {columns} FROM \"{table}\""))?;
            let mut rows = statement.query([])?;
            let mut count = 0_u64;
            while let Some(row) = rows.next()? {
                self.stage.require_io()?;
                super::record_spool::Comparison::sql(db, rule, row)?.mark()?;
                count = count.checked_add(1).ok_or_else(mismatch)?;
            }
            if count != family.source_rows.0 {
                return Err(mismatch());
            }
        }
        Ok(())
    }
}
