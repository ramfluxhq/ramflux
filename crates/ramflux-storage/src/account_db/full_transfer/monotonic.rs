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
    Columns(&'static [Column]),
    Immutable,
    Decision { state: usize, stamp: usize },
    Denial { state: usize, until: usize },
    Maxima(&'static [usize]),
    EpochHash { epoch: usize, hash: usize, until: usize },
}
#[derive(Clone, Copy)]
enum Column {
    Keep,
    DenialTime,
    MinimumPositive,
    Exact,
    Maximum,
    EarliestOptional,
    Ranked(&'static [&'static str]),
}
const LINK_STATES: &[&str] = &["pending", "accepted", "rejected", "blocked", "removed"];
const REMOVE_SCOPES: &[&str] = &["me", "own_devices", "both"];
pub(super) struct Owner {
    family: &'static str,
    names: &'static [&'static str],
    keys: &'static [usize],
    restrictive: bool,
    merge: Merge,
}
static OWNERS: &[Owner] = &[
    Owner {
        family: "sql/account_erasure_generation",
        names: &["singleton", "generation"],
        restrictive: true,
        keys: &[0],
        merge: Merge::Maxima(&[1]),
    },
    Owner {
        family: "sql/contact_request_authority_floor",
        names: &["root", "epoch", "record_hash", "until"],
        restrictive: true,
        keys: &[0],
        merge: Merge::EpochHash { epoch: 1, hash: 2, until: 3 },
    },
    Owner {
        family: "sql/receive_erased_input",
        names: &["selector", "bundle_id", "expires_at"],
        restrictive: true,
        keys: &[0],
        merge: Merge::Maxima(&[2]),
    },
    Owner {
        family: "sql/contact_message_request_fence",
        names: &["sender_identity", "message_id"],
        restrictive: true,
        keys: &[0, 1],
        merge: Merge::Immutable,
    },
    Owner {
        family: "sql/contact_message_fence_retention",
        names: &["sender_identity", "message_id", "until"],
        restrictive: true,
        keys: &[0, 1],
        merge: Merge::Maxima(&[2]),
    },
    Owner {
        family: "sql/contact_request_retirement",
        names: &["root", "direction", "next_at"],
        restrictive: true,
        keys: &[0, 1],
        merge: Merge::Maxima(&[2]),
    },
    Owner {
        family: "sql/contact_request_fence",
        names: &["root", "state", "until"],
        restrictive: true,
        keys: &[0],
        merge: Merge::Denial { state: 1, until: 2 },
    },
    Owner {
        family: "sql/contact_link_decision",
        names: &["link_id", "state", "decided_at"],
        restrictive: true,
        keys: &[0],
        merge: Merge::Decision { state: 1, stamp: 2 },
    },
    Owner {
        family: "sql/contact_request_decision",
        names: &["root", "state", "decided_at"],
        restrictive: true,
        keys: &[0],
        merge: Merge::Decision { state: 1, stamp: 2 },
    },
    Owner {
        family: "sql/contact_request_delivery",
        names: &["request_id", "recipient_identity", "material_hash", "submitted_at"],
        restrictive: false,
        keys: &[0, 1],
        merge: Merge::Maxima(&[3]),
    },
    Owner {
        family: "sql/friend_link_projection",
        names: &[
            "link_id",
            "requester_id",
            "target_id",
            "state",
            "remove_scope",
            "blocked",
            "capability_revoked_at",
            "updated_at",
        ],
        restrictive: false,
        keys: &[0],
        merge: Merge::Columns(&[
            Column::Exact,
            Column::Exact,
            Column::Exact,
            Column::Ranked(LINK_STATES),
            Column::Ranked(REMOVE_SCOPES),
            Column::Maximum,
            Column::EarliestOptional,
            Column::Maximum,
        ]),
    },
    Owner {
        family: "sql/friend_projection",
        names: &[
            "link_id",
            "peer_principal_id",
            "link_state",
            "capability_id",
            "blocked_at",
            "removed_at",
            "updated_at",
        ],
        restrictive: false,
        keys: &[0],
        merge: Merge::Columns(&[
            Column::Exact,
            Column::Exact,
            Column::Ranked(LINK_STATES),
            Column::Exact,
            Column::EarliestOptional,
            Column::EarliestOptional,
            Column::Maximum,
        ]),
    },
    Owner {
        family: "sql/conversation_list_state",
        names: &[
            "conversation_id",
            "archived",
            "pin_order",
            "mute_until",
            "hidden_at",
            "cleared_at",
            "updated_at",
        ],
        restrictive: false,
        keys: &[0],
        merge: Merge::Columns(&[
            Column::Exact,
            Column::Keep,
            Column::Keep,
            Column::Keep,
            Column::DenialTime,
            Column::DenialTime,
            Column::Maximum,
        ]),
    },
    Owner {
        family: "sql/conversation_disappearing_policy",
        names: &["conversation_id", "timer_seconds", "countdown_mode", "scope", "updated_at"],
        restrictive: false,
        keys: &[0],
        merge: Merge::Columns(&[
            Column::Exact,
            Column::MinimumPositive,
            Column::Exact,
            Column::Exact,
            Column::Maximum,
        ]),
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

struct UnionContext<'a> {
    db: &'a Connection,
    nonce: &'a [u8; 32],
    preferred_owner: &'a str,
}
impl Owner {
    fn check(&self, rule: &FamilyRule) -> Result<(), StorageError> {
        rule.require_typed_codec()?;
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        if rule.id != self.family
            || rule.restrictive != self.restrictive
            || rule.cells.len() != self.names.len()
            || matches!(self.merge,Merge::Columns(columns) if columns.len()!=self.names.len())
            || !matches!(rule.selector,FamilySelector::Table(value) if value==table)
            || rule.key.len() != self.keys.len()
            || rule
                .key
                .iter()
                .zip(self.keys)
                .any(|(name, index)| self.names.get(*index) != Some(name))
            || rule.cells.iter().zip(self.names).any(|(cell, name)| cell.name != *name)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn resolve(&self, left: &Cells, right: &Cells) -> Result<Cells, StorageError> {
        let mut result = left.clone();
        for index in self.keys {
            if left.bytes(*index)? != right.bytes(*index)? {
                return Err(conflict());
            }
        }
        match self.merge {
            Merge::Columns(columns) => return merge_columns(columns, left, right),
            Merge::Immutable => {
                for index in 0..self.names.len() {
                    if left.bytes(index)? != right.bytes(index)? {
                        return Err(conflict());
                    }
                }
            }
            Merge::Decision { state, stamp } => {
                let rank = |value| match value {
                    "blocked" => Ok(2),
                    "declined" => Ok(1),
                    "lifted" => Ok(0),
                    _ => Err(invalid()),
                };
                let a = rank(left.text(state)?)?;
                let b = rank(right.text(state)?)?;
                // A transferred lift is historical data, not a fresh B consent action.
                // Keep the complete stronger decision; only equal states use stamp order.
                if b > a || b == a && right.integer(stamp)? > left.integer(stamp)? {
                    result.copy_cell(state, right)?;
                    result.copy_cell(stamp, right)?;
                }
            }
            Merge::Denial { state, until } => {
                // A block dominates a decline irrespective of untrusted wall-clock ordering.
                if right.text(state)? == "blocked" {
                    result.copy_cell(state, right)?;
                }
                let a = left.integer(until)?;
                let b = right.integer(until)?;
                result.set_integer(until, if a == 0 || b == 0 { 0 } else { a.max(b) })?;
            }
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
        if bytes.len() > super::fixed_union::MAX_METADATA_BYTES {
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
    pub(super) fn removable(&self) -> bool {
        !self.restrictive
    }
    pub(super) fn remove(&self, db: &Connection, value: &Cells) -> Result<(), StorageError> {
        if !self.removable() {
            return Err(invalid());
        }
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        let predicate = self
            .keys
            .iter()
            .enumerate()
            .map(|(position, index)| {
                self.names
                    .get(*index)
                    .map(|name| format!("\"{name}\" IS ?{}", position + 1))
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(" AND ");
        let values =
            self.keys.iter().map(|index| value.value(*index)).collect::<Result<Vec<_>, _>>()?;
        db.execute(
            &format!("DELETE FROM \"{table}\" WHERE {predicate}"),
            params_from_iter(values),
        )?;
        Ok(())
    }
    fn current(
        &self,
        db: &Connection,
        rule: &FamilyRule,
        key: &Cells,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        let predicate = self
            .keys
            .iter()
            .enumerate()
            .map(|(position, index)| {
                self.names
                    .get(*index)
                    .map(|name| format!("\"{name}\" IS ?{}", position + 1))
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(" AND ");
        let sql = format!("SELECT {} FROM \"{table}\" WHERE {predicate}", self.columns());
        let values =
            self.keys.iter().map(|index| key.value(*index)).collect::<Result<Vec<_>, _>>()?;
        let result = db
            .query_row(&sql, params_from_iter(values), |row| {
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
        self.store(db, &merged)?;
        if self.family == "sql/contact_link_decision" {
            super::contact_projection::apply_decision(db, &merged)?;
        }
        Ok(())
    }
    fn store(&self, db: &Connection, merged: &Cells) -> Result<(), StorageError> {
        let table = self.family.strip_prefix("sql/").ok_or_else(invalid)?;
        let keys = self
            .keys
            .iter()
            .map(|index| {
                self.names.get(*index).map(|name| format!("\"{name}\"")).ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        let placeholders =
            (1..=self.names.len()).map(|index| format!("?{index}")).collect::<Vec<_>>().join(",");
        let assignments = self
            .names
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.keys.contains(index))
            .map(|(_, name)| format!("\"{name}\"=excluded.\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let action = if assignments.is_empty() {
            "DO NOTHING".to_owned()
        } else {
            format!("DO UPDATE SET {assignments}")
        };
        let values = (0..self.names.len())
            .map(|index| merged.value(index))
            .collect::<Result<Vec<_>, _>>()?;
        db.execute(
            &format!(
                "INSERT INTO \"{table}\"({}) VALUES({placeholders}) ON CONFLICT({keys}) {action}",
                self.columns()
            ),
            params_from_iter(values),
        )?;
        Ok(())
    }
    fn normalize_key(
        &self,
        context: &UnionContext<'_>,
        private: &BackupDatabase,
        rule: &FamilyRule,
        key: &str,
    ) -> Result<(), StorageError> {
        let (db, nonce, preferred_owner) = (context.db, context.nonce, context.preferred_owner);
        let table = if self.restrictive { "full_union_record" } else { "full_union_input" };
        let mut query=db.prepare(&format!("SELECT record FROM {table} WHERE generation_nonce=?1 AND family=?2 AND key=?3 ORDER BY CASE WHEN owner=?4 THEN 0 ELSE 1 END,owner"))?;
        let mut rows = query.query(params![nonce.as_slice(), self.family, key, preferred_owner])?;
        let mut expected = None;
        while let Some(row) = rows.next()? {
            let value = self.decode(rule, row.get_ref(0)?.as_blob().map_err(|_| invalid())?)?;
            expected = Some(match expected {
                Some(old) => self.resolve(&old, &value)?,
                None => value,
            });
        }
        let mut expected = expected.ok_or_else(invalid)?;
        super::contact_projection::derive(&private.db, self.family, &mut expected)?;
        // Nonrestrictive rows are reconstructed from the retained original contributors.
        // Normalizing a previous union into B's original would otherwise preserve A's
        // metadata after an A-only absence. Restrictions deliberately stay monotonic.
        if !self.restrictive {
            self.store(&private.db, &expected)?;
        }
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

fn rank(value: &Cells, index: usize, values: &[&str]) -> Result<usize, StorageError> {
    if value.kind(index)? == ramflux_protocol::custody::pairing::full_transfer::CellType::Null {
        return Ok(0);
    }
    let text = value.text(index)?;
    values.iter().position(|state| *state == text).map(|rank| rank + 1).ok_or_else(invalid)
}
fn merge_columns(columns: &[Column], left: &Cells, right: &Cells) -> Result<Cells, StorageError> {
    let mut result = left.clone();
    for (index, column) in columns.iter().enumerate() {
        match column {
            Column::Keep => {}
            Column::DenialTime => {
                use ramflux_protocol::custody::pairing::full_transfer::CellType;
                if left.kind(index)? == CellType::Null
                    || right.kind(index)? != CellType::Null
                        && right.integer(index)? > left.integer(index)?
                {
                    result.copy_cell(index, right)?;
                }
            }
            Column::MinimumPositive => {
                let a = left.integer(index)?;
                let b = right.integer(index)?;
                result.set_integer(
                    index,
                    match (a, b) {
                        (0, value) | (value, 0) => value,
                        _ => a.min(b),
                    },
                )?;
            }
            Column::Exact => {
                if left.kind(index)? != right.kind(index)?
                    || left.bytes(index)? != right.bytes(index)?
                {
                    return Err(conflict());
                }
            }
            Column::Maximum => {
                result.set_integer(index, left.integer(index)?.max(right.integer(index)?))?;
            }
            Column::EarliestOptional => {
                use ramflux_protocol::custody::pairing::full_transfer::CellType;
                if left.kind(index)? == CellType::Null
                    || right.kind(index)? != CellType::Null
                        && right.integer(index)? < left.integer(index)?
                {
                    result.copy_cell(index, right)?;
                }
            }
            Column::Ranked(values) => {
                if rank(right, index, values)? > rank(left, index, values)? {
                    result.copy_cell(index, right)?;
                }
            }
        }
    }
    Ok(result)
}

pub(super) fn retain_absent(family: &str, value: &Cells) -> Result<bool, StorageError> {
    if let Some(owner) = owner(family)
        && let Merge::Columns(columns) = owner.merge
    {
        for (index, column) in columns.iter().enumerate() {
            if matches!(column, Column::DenialTime)
                && value.kind(index)?
                    != ramflux_protocol::custody::pairing::full_transfer::CellType::Null
                || matches!(column, Column::MinimumPositive) && value.integer(index)? > 0
            {
                return Ok(true);
            }
        }
    }
    super::contact_projection::retain_absent(family, value)
}

pub(super) fn normalize(
    db: &Connection,
    nonce: &[u8; 32],
    private: &BackupDatabase,
    owners: &[String; 2],
) -> Result<(), StorageError> {
    db.execute("INSERT OR IGNORE INTO full_union_input SELECT * FROM full_union_record WHERE generation_nonce=?1",[nonce.as_slice()])?;
    // A fence with no retained deadline must not acquire another device's expiry.
    // Retention rows without their own fence have no denial provenance either. Refuse
    // both inconsistent shapes rather than silently shortening a durable restriction.
    let incompatible: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM full_union_record t WHERE t.generation_nonce=?1 AND t.family='sql/contact_message_fence_retention' AND (
            NOT EXISTS(SELECT 1 FROM full_union_record f WHERE f.generation_nonce=t.generation_nonce AND f.owner=t.owner AND f.family='sql/contact_message_request_fence' AND f.key=t.key)
            OR EXISTS(SELECT 1 FROM full_union_record f WHERE f.generation_nonce=t.generation_nonce AND f.family='sql/contact_message_request_fence' AND f.key=t.key AND NOT EXISTS(SELECT 1 FROM full_union_record r WHERE r.generation_nonce=f.generation_nonce AND r.owner=f.owner AND r.family='sql/contact_message_fence_retention' AND r.key=f.key))))",
        [nonce.as_slice()], |row|row.get(0))?;
    if incompatible {
        return Err(conflict());
    }
    // DeviceRef byte order must never decide which user's existing B preferences win.
    let context = UnionContext { db, nonce, preferred_owner: owners.get(1).ok_or_else(invalid)? };
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
                &context,
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

#[cfg(test)]
mod conversation_tests;
