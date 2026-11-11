// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Schema/count preflight only: this cannot issue an invitation or certify logical rows.
use super::catalog::{CodecRule, FamilyRule, FamilySelector, full_census_hash};
use crate::{AccountDb, StorageError, database::Connection};
use ramflux_protocol::custody::pairing::full_transfer::{CellType, Family, U64};
use rusqlite::params;
use std::collections::BTreeSet;

/// Counts and schema commitment, before portable rows/bytes/root have been encoded.
/// Never use this object as `DataVerified` or a complete source-manifest permission.
pub struct FullTransferSchema {
    pub census_hash: [u8; 32],
    pub families: Vec<Family>,
}
impl FullTransferSchema {
    /// Check nonempty families against the exact same compiled declarations before logical
    /// encoding. Row validation/counts/roots and all native/SAS gates are still required.
    /// # Errors
    /// Refuses changed metadata or a family whose typed owner is not implemented.
    pub fn require_typed_owners(&self, rules: &[FamilyRule]) -> Result<(), StorageError> {
        if self.census_hash != full_census_hash(rules)? || self.families.len() != rules.len() {
            return Err(schema());
        }
        for (family, rule) in self.families.iter().zip(rules) {
            let expected = rule.manifest_family()?;
            if family.id != expected.id
                || family.rule_hash != expected.rule_hash
                || family.codec_version != expected.codec_version
                || family.restrictive != expected.restrictive
                || family.disposition != expected.disposition
            {
                return Err(schema());
            }
            if family.source_rows.0 > 0 {
                rule.require_typed_codec()?;
            }
        }
        Ok(())
    }
}
impl AccountDb {
    /// Inspect this actual unlocked selected source against the local compiled declarations.
    /// An incomplete catalog fails closed. The immutable-cut owner repeats this inspection
    /// inside its pinned read view; live preflight alone is not a snapshot commitment.
    /// # Errors
    /// Refuses unclassified tables, changed columns/types, unsupported actor owners or lock.
    pub fn inspect_full_transfer_schema(
        &self,
        rules: &'static [FamilyRule],
    ) -> Result<FullTransferSchema, StorageError> {
        self.require_full_stage_unlock()?;
        let output = inspect(&self.connection, rules)?;
        self.require_full_stage_unlock()?;
        Ok(output)
    }
}
pub(super) fn inspect(
    connection: &Connection,
    rules: &[FamilyRule],
) -> Result<FullTransferSchema, StorageError> {
    if rules.len() > 4096 {
        return Err(unsupported());
    }
    let census_hash = full_census_hash(rules)?;
    let declared: BTreeSet<&str> = rules
        .iter()
        .filter_map(|rule| match rule.selector {
            FamilySelector::Table(table) => Some(table),
            FamilySelector::ActorPrefix(_) => None,
        })
        .collect();
    let count: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    let long:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND length(CAST(name AS BLOB))>128)",[],|row|row.get(0))?;
    if long || count > declared.len() as u64 {
        return Err(unsupported());
    }
    let actual:BTreeSet<String>=connection.call(|db| {
        db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
            .query_map([],|row|row.get::<_,String>(0))?.collect()
    })?;
    if actual.iter().any(|table| !declared.contains(table.as_str())) {
        return Err(unsupported());
    }
    let mut families = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut family = rule.manifest_family()?;
        match rule.selector {
            FamilySelector::Table(table) if actual.contains(table) => {
                validate_columns(connection, table, rule)?;
                // Identifier comes only from the validated compiled declaration. No peer SQL,
                // names, filters or rowid are interpreted here.
                let sql = format!("SELECT count(*) FROM \"{table}\"");
                family.source_rows = U64(connection.query_row(&sql, [], |row| row.get(0))?);
            }
            FamilySelector::Table(_) => {} // An absent optional/history family has zero rows.
            FamilySelector::ActorPrefix(_) => return Err(unsupported()), // Owning typed projector required.
        }
        families.push(family);
    }
    Ok(FullTransferSchema { census_hash, families })
}
pub(super) fn validate_columns(
    connection: &Connection,
    table: &str,
    rule: &FamilyRule,
) -> Result<(), StorageError> {
    let too_many: bool = connection.query_row(
        "SELECT count(*)>256 OR coalesce(max(length(CAST(name AS BLOB))),0)>128 OR coalesce(max(length(CAST(type AS BLOB))),0)>32 FROM pragma_table_xinfo(?1)",
        params![table],
        |row| row.get(0),
    )?;
    if too_many {
        return Err(schema());
    }
    let query_table = table.to_owned();
    let columns: Vec<(String, String, bool, u32)> = connection.call(move |db| {
        db.prepare("SELECT name,type,\"notnull\",hidden FROM pragma_table_xinfo(?1) ORDER BY cid")?
            .query_map(params![query_table], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect()
    })?;
    if columns.len() != rule.codec.len() {
        return Err(schema());
    }
    for ((name, kind, not_null, hidden), field) in columns.iter().zip(rule.codec) {
        let expected_hidden = match field.codec {
            CodecRule::Generated { hidden, .. } => hidden,
            _ => 0,
        };
        if name != field.name || *not_null == field.nullable || *hidden != expected_hidden {
            return Err(schema());
        }
        let physical = match kind.to_ascii_uppercase().as_str() {
            "INTEGER" | "INT" => CellType::I64,
            "REAL" | "DOUBLE" | "FLOAT" => CellType::F64,
            "TEXT" => CellType::Utf8,
            "BLOB" => CellType::Bytes,
            _ => return Err(schema()),
        };
        if let CodecRule::Scalar { cell_type }
        | CodecRule::RequiresOwner { cell_type, .. }
        | CodecRule::Generated { cell_type, .. } = field.codec
        {
            if physical != cell_type {
                return Err(schema());
            }
        } else if let Some(cell) = rule.cells.iter().find(|cell| cell.name == field.name) {
            if physical != cell.cell_type {
                return Err(schema());
            }
        } else if !matches!(physical, CellType::Utf8 | CellType::Bytes) {
            return Err(schema());
        }
        if let CodecRule::Generated { expression, .. } = field.codec {
            let sql: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE name=?1 AND type='table'",
                params![table],
                |row| row.get(0),
            )?;
            if !compact_sql(&sql).contains(&compact_sql(expression)) {
                return Err(schema());
            }
        }
    }
    Ok(())
}
fn compact_sql(input: &str) -> String {
    let mut quote = None;
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        if let Some(open) = quote {
            output.push(character);
            if character == open {
                if chars.peek() == Some(&open) {
                    output.push(chars.next().unwrap_or(open));
                } else {
                    quote = None;
                }
            }
        } else if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
            output.push(character);
        } else if !character.is_ascii_whitespace() {
            output.push(character);
        }
    }
    output
}
fn unsupported() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn schema() -> StorageError {
    StorageError::PairingField("SchemaMismatch")
}
