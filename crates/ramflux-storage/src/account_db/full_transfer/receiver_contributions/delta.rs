// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Successor records change only A's contribution; B's independent rows stay independent.
use super::*;
use ramflux_protocol::custody::pairing::full_transfer::RecordOp;
use rusqlite::OptionalExtension as _;

struct Pending<'a>(&'a mut BackupDatabase, bool);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.0.db.execute_batch("ROLLBACK");
        }
    }
}
impl Contributions {
    pub(in crate::account_db::full_transfer) fn advance(
        &self,
        path: &Path,
        key: &AccountDbKey,
        private: &mut BackupDatabase,
        stage: &FullTransferStage<'_>,
        hash: &str,
    ) -> Result<FullUnionEncoding, StorageError> {
        stage.require_io()?;
        let mut db = open(path, key)?;
        let tx = db.transaction()?;
        private.db.execute_batch("BEGIN IMMEDIATE")?;
        let mut pending = Pending(private, false);
        for restrictive in [true, false] {
            self.pass(&tx, pending.0, stage, hash, restrictive)?;
        }
        let encoding = self.root(&tx, pending.0, stage)?;
        // A possible private commit followed by a ledger failure leaves no usable proof.
        // The receiver clears its in-memory union before entering this operation; retry
        // replays the same immutable input and revalidates every resulting physical row.
        pending.0.db.execute_batch("COMMIT")?;
        pending.1 = true;
        tx.commit()?;
        drop(db);
        std::fs::File::open(path)?.sync_all()?;
        std::fs::File::open(path.parent().ok_or_else(invalid)?)?.sync_all()?;
        Ok(encoding)
    }
    fn pass(
        &self,
        tx: &Connection,
        private: &mut BackupDatabase,
        stage: &FullTransferStage<'_>,
        hash: &str,
        restrictive: bool,
    ) -> Result<(), StorageError> {
        let source = stage.resume_record()?.grant.source_ref;
        let mut input = stage.forward_reader(hash)?;
        while let Some(header) = read_record_header(&mut input).map_err(|_| invalid())? {
            stage.require_io()?;
            let header = Header(header);
            let rule = compiled(&header.0.family)?;
            if rule.restrictive != restrictive {
                super::super::copy_full_scalar_record(
                    rule,
                    &header.0,
                    &mut input,
                    &mut std::io::sink(),
                )?;
                continue;
            }
            let mut bytes = Zeroizing::new(Vec::new());
            write_record_header(&mut *bytes, &header.0).map_err(|_| invalid())?;
            let body = bytes.len();
            super::super::copy_full_scalar_record(rule, &header.0, &mut input, &mut *bytes)?;
            if header.0.op == RecordOp::Absent {
                // Union/max restrictions outlive their absence at A. Content may remove
                // only A's row and may never erase an independently retained B value.
                if !rule.restrictive {
                    self.absent(tx, private, &header.0)?;
                }
                continue;
            }
            private.apply_full_fixed_base_record(&source, &header.0, &mut &bytes[body..])?;
            if rule.id == "sql/account_erasure_generation" {
                tx.execute("INSERT INTO full_union_record(generation_nonce,owner,family,key,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record",params![self.nonce.as_slice(),self.owners[0],header.0.family,header.0.key,bytes.as_slice()])?;
            } else {
                retain(tx, &self.nonce, &self.owners[0], &bytes)?;
            }
        }
        Ok(())
    }
    fn absent(
        &self,
        tx: &Connection,
        private: &BackupDatabase,
        header: &RecordHeader,
    ) -> Result<(), StorageError> {
        // This is the currently declared nonrestrictive fixed owner. New owners must
        // supply their own deletion/rebuild semantics rather than a generic SQL fallback.
        if header.family != "sql/object_payload_dependency" {
            return Err(invalid());
        }
        let old:Option<Vec<u8>>=tx.query_row("SELECT record FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![self.nonce.as_slice(),self.owners[0],header.family,header.key],|r|r.get(0)).optional()?;
        let Some(old) = old.map(Zeroizing::new) else {
            return Ok(());
        };
        let mut input = old.as_slice();
        let original =
            Header(read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?);
        let cells = super::super::fixed_union::Cells::read(
            compiled(&header.family)?,
            &original.0,
            &mut input,
        )?;
        tx.execute("DELETE FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![self.nonce.as_slice(),self.owners[0],header.family,header.key])?;
        let retained:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM full_union_record WHERE generation_nonce=?1 AND family=?2 AND key=?3)",params![self.nonce.as_slice(),header.family,header.key],|r|r.get(0))?;
        if !retained {
            private.db.execute("DELETE FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2",params![cells.text(0)?,cells.text(1)?])?;
        }
        Ok(())
    }
}
