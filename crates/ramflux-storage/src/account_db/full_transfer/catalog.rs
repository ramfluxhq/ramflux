// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compiled-only recursive codec declarations. No peer bytes can deserialize a rule.
//! Complete SQL-family assignments and typed projection owners must precede Issue.
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{CellType, Disposition, Family, U64};
use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeRule {
    Immutable,
    Revision,
    CursorMax,
    PreferLocal,
    RestrictUnion,
    InertHistory,
    ImportedBundle,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilySelector {
    Table(&'static str),
    ActorPrefix(&'static str),
}
#[derive(Clone, Copy, Serialize)]
pub struct CellRule {
    pub name: &'static str,
    pub nullable: bool,
    #[serde(rename = "type")]
    pub cell_type: CellType,
}
/// Every nested field has its own disposition and merge; there is no prefix default.
#[derive(Clone, Copy, Serialize)]
pub struct FieldRule {
    pub name: &'static str,
    pub nullable: bool,
    pub disposition: Disposition,
    pub merge: MergeRule,
    pub codec: CodecRule,
}
#[derive(Clone, Copy, Serialize)]
pub struct VariantRule {
    pub tag: &'static str,
    pub fields: &'static [FieldRule],
}
/// Descriptor only: interpretation is performed by the field's typed owner. `SignedExact`
/// forbids rewriting a signed document; a present excluded nested value makes it refuse.
#[derive(Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodecRule {
    Boolean,
    DecimalU64,
    EncodedBytes { decoded_bytes: Option<U64> },
    Enum { values: &'static [&'static str] },
    Scalar { cell_type: CellType },
    Object { fields: &'static [FieldRule] },
    Tagged { discriminator: &'static str, variants: &'static [VariantRule] },
    Array { element: &'static Self },
    SignedExact { body: &'static Self },
}
/// Exact OVP-08 + A5.M3 hash operands. All references originate in compiled constants.
/// Runtime row counts/lengths are absent; they never alter the schema commitment.
#[derive(Clone, Copy, Serialize)]
pub struct FamilyRule {
    pub cells: &'static [CellRule],
    pub codec_version: U64,
    pub disposition: Disposition,
    pub excluded: &'static [&'static str],
    pub id: &'static str,
    pub key: &'static [&'static str],
    pub merge: MergeRule,
    pub restrictive: bool,
    pub selector: FamilySelector,
    pub codec: &'static [FieldRule],
    pub key_grammar_version: U64,
    /// Declared JSON-pointer field paths for this exact restrictive projection. Not a wildcard
    /// or inference from the family name. Array elements use the explicit `*` segment.
    pub restrictive_projection: &'static [&'static str],
}
fn unsupported() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn schema() -> StorageError {
    StorageError::PairingField("SchemaMismatch")
}
fn identifier(value: &str, path: bool) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'_'
                || (path && matches!(byte, b'.' | b'/' | b'-'))
        })
}
impl FamilyRule {
    /// Validate the compiled declaration before hashing or using its SQL projection.
    /// # Errors
    /// Refuses incomplete/ambiguous cells, keys, exclusions or recursive descriptors.
    pub fn validate(&self) -> Result<(), StorageError> {
        if !identifier(self.id, true)
            || self.codec_version.0 == 0
            || self.key_grammar_version.0 != 1
        {
            return Err(unsupported());
        }
        match self.selector {
            FamilySelector::Table(table) => {
                if !identifier(table, false)
                    || !(self.id == format!("sql/{table}")
                        || self.id.starts_with(&format!("sql/{table}/")))
                {
                    return Err(unsupported());
                }
            }
            FamilySelector::ActorPrefix(prefix) => {
                if !identifier(prefix, true) || self.id != format!("actor/{prefix}") {
                    return Err(unsupported());
                }
            }
        }
        let mut remaining = 4096;
        validate_fields(self.codec, 0, &mut remaining)?;
        if self.cells.len() > 256 || self.excluded.len() > 256 || self.key.len() > 256 {
            return Err(unsupported());
        }
        if self.disposition == Disposition::Transfer && self.cells.is_empty() {
            return Err(unsupported());
        }
        if self.disposition != Disposition::Transfer
            && (!self.cells.is_empty() || !self.key.is_empty())
        {
            return Err(unsupported());
        }
        for (index, cell) in self.cells.iter().enumerate() {
            if !identifier(cell.name, false)
                || cell.cell_type == CellType::Null
                || self.cells[..index].iter().any(|earlier| earlier.name == cell.name)
            {
                return Err(unsupported());
            }
            let field =
                self.codec.iter().find(|field| field.name == cell.name).ok_or_else(unsupported)?;
            if field.disposition != Disposition::Transfer || field.nullable != cell.nullable {
                return Err(unsupported());
            }
            if let CodecRule::Scalar { cell_type } = field.codec {
                if cell_type != cell.cell_type {
                    return Err(unsupported());
                }
            } else if !matches!(cell.cell_type, CellType::Utf8 | CellType::Bytes) {
                return Err(unsupported());
            }
        }
        for (index, name) in self.excluded.iter().enumerate() {
            if !identifier(name, false)
                || self.excluded[..index].contains(name)
                || self.cells.iter().any(|cell| cell.name == *name)
            {
                return Err(unsupported());
            }
            let field =
                self.codec.iter().find(|field| field.name == *name).ok_or_else(unsupported)?;
            if field.disposition == Disposition::Transfer {
                return Err(unsupported());
            }
        }
        for field in self.codec {
            let declared = self.cells.iter().any(|cell| cell.name == field.name)
                || self.excluded.contains(&field.name);
            if !declared {
                return Err(unsupported());
            }
        }
        for (index, name) in self.key.iter().enumerate() {
            if self.key[..index].contains(name) || !self.cells.iter().any(|cell| cell.name == *name)
            {
                return Err(unsupported());
            }
        }
        if self.restrictive_projection.len() > 256
            || (!self.restrictive && !self.restrictive_projection.is_empty())
        {
            return Err(unsupported());
        }
        for (index, path) in self.restrictive_projection.iter().enumerate() {
            if path.len() > 1024
                || !path.starts_with('/')
                || self.restrictive_projection[..index].contains(path)
                || !projection_exists(self.codec, &mut path[1..].split('/'))
            {
                return Err(unsupported());
            }
        }
        Ok(())
    }
    /// Hash every recursive exclusion/selector/key/merge operand under the adopted domain.
    /// # Errors
    /// Refuses invalid compiled declarations or canonical encoding failure.
    pub fn rule_hash(&self) -> Result<[u8; 32], StorageError> {
        self.validate()?;
        let bytes = ramflux_protocol::canonical_json_bytes(self)?;
        let mut hash = framed(b"ramflux.pairing.full.rule.v1")?;
        hash.update(&bytes);
        Ok(*hash.finalize().as_bytes())
    }
    /// Build only the schema portion of a manifest row; actual cut counts are set by its
    /// bounded encoder, never accepted as the expected local catalog from a peer.
    /// # Errors
    /// Refuses invalid compiled declarations.
    pub fn manifest_family(&self) -> Result<Family, StorageError> {
        Ok(Family {
            id: self.id.into(),
            codec_version: self.codec_version,
            restrictive: self.restrictive,
            disposition: self.disposition,
            source_rows: U64(0),
            portable_records: U64(0),
            encoded_bytes: U64(0),
            rule_hash: ramflux_protocol::encode_base64url(self.rule_hash()?),
        })
    }
}
/// Commit the complete sorted static catalog, including exclude/rebuild entries.
/// # Errors
/// Refuses empty, duplicate, unsorted or invalid compiled catalogs.
pub fn full_census_hash(rules: &[FamilyRule]) -> Result<[u8; 32], StorageError> {
    if rules.is_empty() || rules.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err(schema());
    }
    let mut hash = framed(b"ramflux.pairing.full.census.v1")?;
    hash.update(&u32::try_from(rules.len()).map_err(|_| schema())?.to_be_bytes());
    for rule in rules {
        framed_value(&mut hash, rule.id.as_bytes())?;
        hash.update(&rule.rule_hash()?);
    }
    Ok(*hash.finalize().as_bytes())
}
fn framed(domain: &[u8]) -> Result<blake3::Hasher, StorageError> {
    let mut hash = blake3::Hasher::new();
    framed_value(&mut hash, domain)?;
    Ok(hash)
}
fn framed_value(hash: &mut blake3::Hasher, value: &[u8]) -> Result<(), StorageError> {
    hash.update(&u32::try_from(value.len()).map_err(|_| unsupported())?.to_be_bytes());
    hash.update(value);
    Ok(())
}
fn validate_fields(
    fields: &[FieldRule],
    depth: usize,
    remaining: &mut usize,
) -> Result<(), StorageError> {
    if fields.len() > 256 || depth > 32 {
        return Err(unsupported());
    }
    for (index, field) in fields.iter().enumerate() {
        if !identifier(field.name, false)
            || fields[..index].iter().any(|previous| previous.name == field.name)
        {
            return Err(unsupported());
        }
        validate_codec(&field.codec, depth + 1, remaining)?;
    }
    Ok(())
}
fn validate_codec(
    codec: &CodecRule,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), StorageError> {
    if depth > 32 || *remaining == 0 {
        return Err(unsupported());
    }
    *remaining -= 1;
    match codec {
        CodecRule::Boolean | CodecRule::DecimalU64 => {}
        CodecRule::EncodedBytes { decoded_bytes } => {
            if decoded_bytes.is_some_and(|bytes| bytes.0 > i64::MAX.cast_unsigned()) {
                return Err(unsupported());
            }
        }
        CodecRule::Enum { values } => {
            if values.is_empty() || values.len() > 256 {
                return Err(unsupported());
            }
            for (index, value) in values.iter().enumerate() {
                if value.is_empty()
                    || value.len() > 1024
                    || value.chars().any(char::is_control)
                    || values[..index].contains(value)
                {
                    return Err(unsupported());
                }
            }
        }
        CodecRule::Scalar { cell_type } => {
            if *cell_type == CellType::Null {
                return Err(unsupported());
            }
        }
        CodecRule::Object { fields } => validate_fields(fields, depth + 1, remaining)?,
        CodecRule::Tagged { discriminator, variants } => {
            if !identifier(discriminator, false) || variants.is_empty() || variants.len() > 256 {
                return Err(unsupported());
            }
            for (index, variant) in variants.iter().enumerate() {
                if !identifier(variant.tag, true)
                    || variants[..index].iter().any(|earlier| earlier.tag == variant.tag)
                    || variant.fields.iter().any(|field| field.name == *discriminator)
                {
                    return Err(unsupported());
                }
                validate_fields(variant.fields, depth + 1, remaining)?;
            }
        }
        CodecRule::Array { element } | CodecRule::SignedExact { body: element } => {
            validate_codec(element, depth + 1, remaining)?;
        }
    }
    Ok(())
}
fn projection_exists(fields: &[FieldRule], parts: &mut dyn Iterator<Item = &str>) -> bool {
    let Some(name) = parts.next() else { return false };
    let Some(field) = fields
        .iter()
        .find(|field| field.name == name && field.disposition == Disposition::Transfer)
    else {
        return false;
    };
    match parts.next() {
        None => true,
        Some(next) => projection_codec(&field.codec, next, parts),
    }
}
fn projection_codec<'a>(
    codec: &CodecRule,
    next: &'a str,
    parts: &mut dyn Iterator<Item = &'a str>,
) -> bool {
    match codec {
        CodecRule::Object { fields } => {
            projection_exists(fields, &mut std::iter::once(next).chain(parts))
        }
        CodecRule::Array { element } if next == "*" => {
            parts.next().is_some_and(|next| projection_codec(element, next, parts))
        }
        CodecRule::SignedExact { body } => projection_codec(body, next, parts),
        // A tagged projection must explicitly select the tag; a prefix default is forbidden.
        CodecRule::Tagged { variants, .. } => variants
            .iter()
            .find(|variant| variant.tag == next)
            .is_some_and(|variant| projection_exists(variant.fields, parts)),
        _ => false,
    }
}
