// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One exact-row resolver for monotonic denial families; no authorization or peer SQL.
use super::{
    FamilyRule, FamilySelector, fixed_union::Cells, full_transfer_catalog,
    write_full_scalar_sql_row,
};
use crate::{BackupDatabase, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{RecordHeader, read_record_header};
use rusqlite::{Connection, OptionalExtension as _, params, params_from_iter};
use zeroize::{Zeroize as _, Zeroizing};

#[derive(Clone, Copy)]
enum Merge {
    Maxima(&'static [usize]),
    EpochHash { epoch: usize, hash: usize, until: usize },
}
pub(super) struct Owner {
    family: &'static str,
    names: &'static [&'static str],
    merge: Merge,
}
static OWNERS: &[Owner] = &[
    Owner {
        family: "sql/account_erasure_generation",
        names: &["singleton", "generation"],
        merge: Merge::Maxima(&[1]),
    },
    Owner {
        family: "sql/contact_request_authority_floor",
        names: &["root", "epoch", "record_hash", "until"],
        merge: Merge::EpochHash { epoch: 1, hash: 2, until: 3 },
    },
    Owner {
        family: "sql/receive_erased_input",
        names: &["selector", "bundle_id", "expires_at"],
        merge: Merge::Maxima(&[2]),
    },
];
pub(super) fn owner(family: &str) -> Option<&'static Owner> {
    OWNERS.iter().find(|owner| owner.family == family)
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn conflict() -> StorageError {
    StorageError::PairingField("TransferConflict")
}
struct Header(RecordHeader);
impl Drop for Header {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

impl Owner {
    fn check(&self, rule: &FamilyRule) -> Result<(), StorageError> {
        rule.require_typed_codec()?;
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        if rule.id != self.family
            || !rule.restrictive
            || rule.cells.len() != self.names.len()
            || !matches!(rule.selector,FamilySelector::Table(value) if value==table)
            || rule.key.len() != 1
            || rule.key.first() != self.names.first()
            || rule.cells.iter().zip(self.names).any(|(cell, name)| cell.name != *name)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn resolve(&self, left: &Cells, right: &Cells) -> Result<Cells, StorageError> {
        let mut result = left.clone();
        match self.merge {
            Merge::Maxima(indices) => {
                for index in 0..self.names.len() {
                    if indices.contains(&index) {
                        result
                            .set_integer(index, left.integer(index)?.max(right.integer(index)?))?;
                    } else if left.bytes(index)? != right.bytes(index)? {
                        return Err(conflict());
                    }
                }
            }
            Merge::EpochHash { epoch, hash, until } => {
                if left.bytes(0)? != right.bytes(0)? {
                    return Err(conflict());
                }
                let a = left.integer(epoch)?;
                let b = right.integer(epoch)?;
                if a == b && left.bytes(hash)? != right.bytes(hash)? {
                    return Err(conflict());
                }
                if b > a {
                    result.copy_cell(epoch, right)?;
                    result.copy_cell(hash, right)?;
                }
                result.set_integer(until, left.integer(until)?.max(right.integer(until)?))?;
            }
        }
        Ok(result)
    }
    fn columns(&self) -> String {
        self.names.iter().map(|name| format!("\"{name}\"")).collect::<Vec<_>>().join(",")
    }
    fn decode(&self, rule: &FamilyRule, bytes: &[u8]) -> Result<Cells, StorageError> {
        self.check(rule)?;
        if bytes.len() > 262_144 {
            return Err(invalid());
        }
        let mut input = bytes;
        let header =
            Header(read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?);
        let value = Cells::read(rule, &header.0, &mut input)?;
        if !input.is_empty() {
            return Err(invalid());
        }
        Ok(value)
    }
    fn encode(
        &self,
        db: &Connection,
        rule: &FamilyRule,
        value: &Cells,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let select = self
            .names
            .iter()
            .enumerate()
            .map(|(index, name)| format!("?{} AS \"{name}\"", index + 1))
            .collect::<Vec<_>>()
            .join(",");
        let values =
            (0..self.names.len()).map(|index| value.value(index)).collect::<Result<Vec<_>, _>>()?;
        let mut bytes = Zeroizing::new(Vec::new());
        db.query_row(&format!("SELECT {select}"), params_from_iter(values), |row| {
            Ok(write_full_scalar_sql_row(rule, row, &mut *bytes))
        })??;
        Ok(bytes)
    }
    fn current(
        &self,
        db: &Connection,
        rule: &FamilyRule,
        key: &Cells,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        let column = self.names.first().ok_or_else(invalid)?;
        let sql = format!("SELECT {} FROM \"{table}\" WHERE \"{column}\" IS ?1", self.columns());
        let result = db
            .query_row(&sql, [key.value(0)?], |row| {
                let mut bytes = Zeroizing::new(Vec::new());
                Ok(write_full_scalar_sql_row(rule, row, &mut *bytes).map(|_| bytes))
            })
            .optional()?;
        result.transpose()
    }
    pub(super) fn apply(
        &self,
        db: &Connection,
        rule: &FamilyRule,
        incoming: &Cells,
    ) -> Result<(), StorageError> {
        self.check(rule)?;
        if self.family == super::input_denial::FAMILY {
            super::input_denial::require_bundle(db, incoming.text(1)?)?;
        }
        let merged = match self.current(db, rule, incoming)? {
            Some(bytes) => self.resolve(&self.decode(rule, &bytes)?, incoming)?,
            None => incoming.clone(),
        };
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        let key = self.names.first().ok_or_else(invalid)?;
        let placeholders =
            (1..=self.names.len()).map(|index| format!("?{index}")).collect::<Vec<_>>().join(",");
        let assignments = self
            .names
            .iter()
            .skip(1)
            .map(|name| format!("\"{name}\"=excluded.\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let values = (0..self.names.len())
            .map(|index| merged.value(index))
            .collect::<Result<Vec<_>, _>>()?;
        db.execute(&format!("INSERT INTO \"{table}\"({}) VALUES({placeholders}) ON CONFLICT(\"{key}\") DO UPDATE SET {assignments}",self.columns()),params_from_iter(values))?;
        Ok(())
    }
    fn normalize_key(
        &self,
        db: &Connection,
        nonce: &[u8; 32],
        private: &BackupDatabase,
        rule: &FamilyRule,
        key: &str,
    ) -> Result<(), StorageError> {
        let mut query=db.prepare("SELECT record FROM full_union_record WHERE generation_nonce=?1 AND family=?2 AND key=?3 ORDER BY owner")?;
        let mut rows = query.query(params![nonce.as_slice(), self.family, key])?;
        let mut expected = None;
        while let Some(row) = rows.next()? {
            let value = self.decode(rule, row.get_ref(0)?.as_blob().map_err(|_| invalid())?)?;
            expected = Some(match expected {
                Some(old) => self.resolve(&old, &value)?,
                None => value,
            });
        }
        let expected = expected.ok_or_else(invalid)?;
        let bytes = self.encode(db, rule, &expected)?;
        let actual = self.current(&private.db, rule, &expected)?.ok_or_else(conflict)?;
        if bytes.as_slice() != actual.as_slice() {
            return Err(conflict());
        }
        db.execute("UPDATE full_union_record SET record=?1 WHERE generation_nonce=?2 AND family=?3 AND key=?4",
            params![bytes.as_slice(),nonce.as_slice(),self.family,key])?;
        Ok(())
    }
}

pub(super) fn normalize(
    db: &Connection,
    nonce: &[u8; 32],
    private: &BackupDatabase,
) -> Result<(), StorageError> {
    for owner in OWNERS {
        let rule = full_transfer_catalog()
            .iter()
            .find(|rule| rule.id == owner.family)
            .ok_or_else(invalid)?;
        owner.check(rule)?;
        let mut query=db.prepare("SELECT DISTINCT key FROM full_union_record WHERE generation_nonce=?1 AND family=?2 ORDER BY key")?;
        let mut rows = query.query(params![nonce.as_slice(), owner.family])?;
        while let Some(row) = rows.next()? {
            owner.normalize_key(
                db,
                nonce,
                private,
                rule,
                row.get_ref(0)?.as_str().map_err(|_| invalid())?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
