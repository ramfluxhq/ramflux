// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refresh only B's changed qualified records; A's frozen ledger is never replayed.
use super::{Contributions, Header, invalid, open};
use crate::{AccountDbKey, BackupDatabase, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{Disposition, read_record_header};
use rusqlite::{Connection, params};
use std::path::Path;

impl Contributions {
    pub(in crate::account_db::full_transfer) fn rebase_target(
        &self,
        path: &Path,
        key: &AccountDbKey,
        private: &mut BackupDatabase,
        stage: &impl super::super::receiver_read::ReceiverInput,
        rows: super::TargetRows<'_>,
    ) -> Result<super::FullUnionEncoding, StorageError> {
        let mut db = open(path, key)?;
        let tx = db.transaction()?;
        tx.execute_batch(&format!("CREATE TABLE current_target(family TEXT NOT NULL,key TEXT NOT NULL,record BLOB NOT NULL {},PRIMARY KEY(family,key));", super::super::record_profile::sql_constraint()))?;
        Self::capture_target(&tx, rows.current, rows.schema, stage)?;
        self.remove_target_absences(&tx, private, stage)?;
        let content = super::super::full_transfer_catalog()
            .iter()
            .filter(|rule| !rule.restrictive)
            .map(|rule| format!("'{}'", rule.id))
            .collect::<Vec<_>>()
            .join(",");
        let mut query = tx.prepare(&format!("SELECT fresh.family,fresh.key,fresh.rowid,length(fresh.record) FROM current_target AS fresh LEFT JOIN full_union_record AS old ON old.generation_nonce=?1 AND old.owner=?2 AND old.family=fresh.family AND old.key=fresh.key WHERE old.record IS NOT fresh.record ORDER BY CASE WHEN fresh.family IN ({content}) THEN 1 ELSE 0 END,fresh.family,fresh.key"))?;
        let mut rows = query.query(params![self.nonce.as_slice(), self.owners[1]])?;
        let source = stage.resume_record()?.grant.destination_ref;
        while let Some(row) = rows.next()? {
            stage.require_io()?;
            let family = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
            let key = row.get_ref(1)?.as_str().map_err(|_| invalid())?;
            let rule = super::super::source_scalar::compiled(family)?;
            let mut input = super::super::record_spool::checked_blob(
                &tx,
                "current_target",
                row.get(2)?,
                row.get(3)?,
                rule,
                key,
            )?;
            let header =
                read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?;
            let candidate =
                super::super::record_spool::Candidate::input(&tx, rule, header, &mut input)?;
            drop(input);
            candidate.apply(private, &source)?;
            if super::removable(family) {
                candidate.retain_original(&self.nonce, &self.owners[1])?;
            }
            candidate.retain_union(&self.nonce, &self.owners[1], true)?;
        }
        drop(rows);
        drop(query);
        let encoding = self.root(&tx, private, stage)?;
        tx.execute_batch("DROP TABLE current_target;")?;
        tx.commit()?;
        drop(db);
        crate::sync_path::sync_path(path)?;
        Ok(encoding)
    }

    fn capture_target(
        target: &Connection,
        current: &BackupDatabase,
        schema: &super::super::FullTransferSchema,
        stage: &impl super::super::receiver_read::ReceiverInput,
    ) -> Result<(), StorageError> {
        let rules = super::super::full_transfer_catalog();
        schema.require_typed_owners(rules)?;
        for (family, rule) in schema.families.iter().zip(rules) {
            if family.source_rows.0 == 0 || rule.disposition != Disposition::Transfer {
                continue;
            }
            super::super::source_scalar::compiled(rule.id)?;
            let super::super::FamilySelector::Table(table) = rule.selector else {
                return Err(invalid());
            };
            let columns = rule
                .cells
                .iter()
                .map(|cell| format!("\"{}\"", cell.name))
                .collect::<Vec<_>>()
                .join(",");
            let mut query = current.db.prepare(&format!("SELECT {columns} FROM \"{table}\""))?;
            let mut rows = query.query([])?;
            let mut count = 0_u64;
            while let Some(row) = rows.next()? {
                stage.require_io()?;
                if rule.id == "sql/full_imported_mac_bundle" {
                    let original = super::super::super::mac_subkeys::full::decode_source_ref(
                        row.get_ref(0)?.as_str().map_err(|_| invalid())?.as_bytes(),
                    )?;
                    if original.account_anchor != stage.principal() {
                        return Err(invalid());
                    }
                }
                super::super::record_spool::Candidate::sql(
                    &current.db,
                    target,
                    rule,
                    row,
                    stage.principal(),
                )?
                .target()?;
                count = count.checked_add(1).ok_or_else(invalid)?;
            }
            if count != family.source_rows.0 {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn remove_target_absences(
        &self,
        tx: &Connection,
        private: &BackupDatabase,
        stage: &impl super::super::receiver_read::ReceiverInput,
    ) -> Result<(), StorageError> {
        let mut query=tx.prepare("SELECT coalesce(i.record,old.record) FROM full_union_record AS old LEFT JOIN full_union_input i USING(generation_nonce,owner,family,key) WHERE old.generation_nonce=?1 AND old.owner=?2 AND NOT EXISTS(SELECT 1 FROM current_target AS fresh WHERE fresh.family=old.family AND fresh.key=old.key)")?;
        let mut rows = query.query(params![self.nonce.as_slice(), self.owners[1]])?;
        while let Some(row) = rows.next()? {
            stage.require_io()?;
            let mut bytes = row.get_ref(0)?.as_blob().map_err(|_| invalid())?;
            let header =
                Header(read_record_header(&mut bytes).map_err(|_| invalid())?.ok_or_else(invalid)?);
            if !super::removable(&header.0.family) {
                continue;
            }
            if header.0.family == super::super::direct_union::FAMILY {
                super::super::direct_union::absent(
                    tx,
                    private,
                    &self.nonce,
                    &self.owners,
                    self.owners.get(1).ok_or_else(invalid)?,
                    &header.0,
                    &mut bytes,
                )?;
                continue;
            }
            let cells = super::super::fixed_union::Cells::read(
                super::super::source_scalar::compiled(&header.0.family)?,
                &header.0,
                &mut bytes,
            )?;
            if super::super::monotonic::retain_absent(&header.0.family, &cells)? {
                continue;
            }
            tx.execute("DELETE FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![self.nonce.as_slice(),self.owners[1],header.0.family,header.0.key])?;
            tx.execute("DELETE FROM full_union_input WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![self.nonce.as_slice(),self.owners[1],header.0.family,header.0.key])?;
            let retained:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM full_union_record WHERE generation_nonce=?1 AND family=?2 AND key=?3)",params![self.nonce.as_slice(),header.0.family,header.0.key],|row|row.get(0))?;
            if !retained {
                super::remove_materialized(private, &header.0, &cells)?;
            }
        }
        Ok(())
    }
}
