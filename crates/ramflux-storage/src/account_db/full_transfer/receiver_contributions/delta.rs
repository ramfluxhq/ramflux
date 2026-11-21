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
        stage: &impl super::super::receiver_read::ReceiverInput,
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
        crate::sync_path::sync_path(path)?;
        crate::sync_path::sync_path(path.parent().ok_or_else(invalid)?)?;
        Ok(encoding)
    }
    fn pass(
        &self,
        tx: &Connection,
        private: &mut BackupDatabase,
        stage: &impl super::super::receiver_read::ReceiverInput,
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
            if header.0.op == RecordOp::Absent {
                super::super::copy_full_scalar_record(
                    rule,
                    &header.0,
                    &mut input,
                    &mut std::io::sink(),
                )?;
                // Absence removes only this source's content contribution; independent
                // B rows and retained denials survive their own compiled owner rules.
                if !rule.restrictive {
                    self.absent(tx, private, &header.0)?;
                }
                continue;
            }
            let candidate = super::super::record_spool::Candidate::input(
                tx,
                rule,
                header.0.clone(),
                &mut input,
            )?;
            candidate.apply(private, &source)?;
            if super::removable(rule.id) {
                candidate.retain_original(&self.nonce, &self.owners[0])?;
            }
            candidate.retain_union(
                &self.nonce,
                &self.owners[0],
                super::super::monotonic::owner(rule.id).is_some(),
            )?;
        }
        Ok(())
    }
    fn absent(
        &self,
        tx: &Connection,
        private: &BackupDatabase,
        header: &RecordHeader,
    ) -> Result<(), StorageError> {
        if !super::removable(&header.family) {
            return Err(invalid());
        }
        let old:Option<Vec<u8>>=tx.query_row("SELECT coalesce(i.record,r.record) FROM full_union_record r LEFT JOIN full_union_input i USING(generation_nonce,owner,family,key) WHERE r.generation_nonce=?1 AND r.owner=?2 AND r.family=?3 AND r.key=?4",params![self.nonce.as_slice(),self.owners[0],header.family,header.key],|r|r.get(0)).optional()?;
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
        if super::super::contact_projection::retain_absent(&header.family, &cells)? {
            return Ok(());
        }
        tx.execute("DELETE FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![self.nonce.as_slice(),self.owners[0],header.family,header.key])?;
        tx.execute("DELETE FROM full_union_input WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![self.nonce.as_slice(),self.owners[0],header.family,header.key])?;
        let retained:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM full_union_record WHERE generation_nonce=?1 AND family=?2 AND key=?3)",params![self.nonce.as_slice(),header.family,header.key],|r|r.get(0))?;
        if !retained {
            super::remove_materialized(private, header, &cells)?;
        }
        Ok(())
    }
}
