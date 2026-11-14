// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refresh only B's changed qualified records; A's frozen ledger is never replayed.
use super::{Contributions, Header, invalid, open};
use crate::{AccountDbKey, BackupDatabase, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{Disposition, read_record_header};
use rusqlite::{Connection, params};
use std::path::Path;
use zeroize::Zeroizing;

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
        tx.execute_batch("CREATE TEMP TABLE current_target(family TEXT NOT NULL,key TEXT NOT NULL,record BLOB NOT NULL CHECK(length(record)<=16384),PRIMARY KEY(family,key)) WITHOUT ROWID;")?;
        Self::capture_target(&tx, rows.current, rows.schema, stage)?;
        self.remove_target_absences(&tx, private, stage)?;
        let mut query = tx.prepare("SELECT fresh.record FROM current_target AS fresh LEFT JOIN full_union_record AS old ON old.generation_nonce=?1 AND old.owner=?2 AND old.family=fresh.family AND old.key=fresh.key WHERE old.record IS NOT fresh.record ORDER BY CASE WHEN fresh.family='sql/object_payload_dependency' THEN 1 ELSE 0 END,fresh.family,fresh.key")?;
        let mut rows = query.query(params![self.nonce.as_slice(), self.owners[1]])?;
        let source = stage.resume_record()?.grant.destination_ref;
        while let Some(row) = rows.next()? {
            stage.require_io()?;
            let bytes = row.get_ref(0)?.as_blob().map_err(|_| invalid())?;
            if bytes.len() > 16384 {
                return Err(invalid());
            }
            let mut input = bytes;
            let header =
                Header(read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?);
            private.apply_full_fixed_base_record(&source, &header.0, &mut input)?;
            tx.execute("INSERT INTO full_union_record(generation_nonce,owner,family,key,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record",params![self.nonce.as_slice(),self.owners[1],header.0.family,header.0.key,bytes])?;
        }
        drop(rows);
        drop(query);
        let encoding = self.root(&tx, private, stage)?;
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
                let mut bytes = Zeroizing::new(Vec::new());
                super::super::write_full_scalar_sql_row(rule, row, &mut *bytes)?;
                let header = Header(
                    read_record_header(&mut bytes.as_slice())
                        .map_err(|_| invalid())?
                        .ok_or_else(invalid)?,
                );
                target.execute(
                    "INSERT INTO current_target VALUES(?1,?2,?3)",
                    params![header.0.family, header.0.key, bytes.as_slice()],
                )?;
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
        let mut query=tx.prepare("SELECT old.record,old.key FROM full_union_record AS old WHERE old.generation_nonce=?1 AND old.owner=?2 AND old.family='sql/object_payload_dependency' AND NOT EXISTS(SELECT 1 FROM current_target AS fresh WHERE fresh.family=old.family AND fresh.key=old.key)")?;
        let mut rows = query.query(params![self.nonce.as_slice(), self.owners[1]])?;
        while let Some(row) = rows.next()? {
            stage.require_io()?;
            let mut bytes = row.get_ref(0)?.as_blob().map_err(|_| invalid())?;
            let header =
                Header(read_record_header(&mut bytes).map_err(|_| invalid())?.ok_or_else(invalid)?);
            let cells = super::super::fixed_union::Cells::read(
                super::super::source_scalar::compiled(&header.0.family)?,
                &header.0,
                &mut bytes,
            )?;
            let key = row.get_ref(1)?.as_str().map_err(|_| invalid())?;
            let retained:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family='sql/object_payload_dependency' AND key=?3)",params![self.nonce.as_slice(),self.owners[0],key],|row|row.get(0))?;
            if !retained {
                private.db.execute("DELETE FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2",params![cells.text(0)?,cells.text(1)?])?;
            }
        }
        drop(rows);
        drop(query);
        tx.execute("DELETE FROM full_union_record AS old WHERE generation_nonce=?1 AND owner=?2 AND family='sql/object_payload_dependency' AND NOT EXISTS(SELECT 1 FROM current_target AS fresh WHERE fresh.family=old.family AND fresh.key=old.key)",params![self.nonce.as_slice(),self.owners[1]])?;
        Ok(())
    }
}
