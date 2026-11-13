// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compiled-only recursive codec declarations. No peer bytes can deserialize a rule.
//! Complete SQL-family assignments and typed projection owners must precede Issue.
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{CellType, Disposition, Family, U64};
use serde::Serialize;
pub(super) mod local_actor;

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
    /// Accepted local derived SQL only. It is never a portable cell or peer-supplied DDL.
    Generated {
        cell_type: CellType,
        hidden: u32,
        expression: &'static str,
    },
    /// Explicit fail-closed worklist entry. No value, including null, is portable until
    /// the named typed owner supplies a complete declaration and bumps the codec version.
    RequiresOwner {
        owner: &'static str,
        cell_type: CellType,
    },
    Boolean,
    DecimalU64,
    EncodedBytes {
        decoded_bytes: Option<U64>,
    },
    Enum {
        values: &'static [&'static str],
    },
    Scalar {
        cell_type: CellType,
    },
    /// Exactly 192 account MAC subkey bytes, SHA256-bound to the `bundle_id` key.
    SqlMacSubkeys,
    /// Closed canonical public `DeviceRef` JSON text (at most 512 bytes), not opaque JSON.
    SqlDeviceRef,
    /// Raw SQL byte cell with an exact semantic width; never an opaque JSON codec.
    SqlBytes {
        length: U64,
        nullable: bool,
    },
    /// SQL text holding canonical unpadded base64url with an exact decoded width.
    SqlBase64 {
        decoded_bytes: U64,
        nullable: bool,
    },
    /// Raw SQL signed integer; bounds are canonical decimal strings in the rule hash.
    SqlI64 {
        min: &'static str,
        max: &'static str,
        nullable: bool,
    },
    Object {
        fields: &'static [FieldRule],
    },
    Tagged {
        discriminator: &'static str,
        variants: &'static [VariantRule],
    },
    Array {
        element: &'static Self,
    },
    SignedExact {
        body: &'static Self,
    },
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
    /// Require every declared typed owner before interpreting any nonempty family. This
    /// check precedes null handling and exclusion, so neither is an opaque-copy fallback.
    /// # Errors
    /// Refuses any intentionally unsupported/incomplete recursive codec declaration.
    pub fn require_typed_codec(&self) -> Result<(), StorageError> {
        self.validate()?;
        if self.codec.iter().any(|field| missing_owner(&field.codec)) {
            return Err(unsupported());
        }
        Ok(())
    }
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
        let current_mac = matches!(self.selector, FamilySelector::Table("account_mac_bundle"))
            && self.id == "sql/account_mac_bundle/portable"
            && self.key == ["bundle_id"];
        let imported_mac =
            matches!(self.selector, FamilySelector::Table("full_imported_mac_bundle"))
                && self.id == "sql/full_imported_mac_bundle"
                && self.key == ["source_ref", "bundle_id"];
        if self.codec.iter().any(|field| matches!(field.codec, CodecRule::SqlMacSubkeys))
            && (!(current_mac || imported_mac)
                || self.merge != MergeRule::ImportedBundle
                || self.codec.iter().any(|field| {
                    matches!(field.codec, CodecRule::SqlMacSubkeys) && field.name != "subkeys"
                }))
        {
            return Err(unsupported());
        }
        if self.codec.iter().any(|field| {
            matches!(field.codec, CodecRule::SqlDeviceRef)
                && (!imported_mac || field.name != "source_ref")
        }) {
            return Err(unsupported());
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
        self.validate_cells()?;
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
    fn validate_cells(&self) -> Result<(), StorageError> {
        if matches!(self.selector, FamilySelector::ActorPrefix(_))
            && self.codec.iter().any(|field| {
                matches!(
                    field.codec,
                    CodecRule::SqlMacSubkeys
                        | CodecRule::SqlDeviceRef
                        | CodecRule::SqlBytes { .. }
                        | CodecRule::SqlBase64 { .. }
                        | CodecRule::SqlI64 { .. }
                )
            })
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
            let physical = match field.codec {
                CodecRule::Scalar { cell_type } | CodecRule::RequiresOwner { cell_type, .. } => {
                    Some(cell_type)
                }
                CodecRule::SqlMacSubkeys | CodecRule::SqlBytes { .. } => Some(CellType::Bytes),
                CodecRule::SqlBase64 { .. } | CodecRule::SqlDeviceRef => Some(CellType::Utf8),
                CodecRule::SqlI64 { .. } => Some(CellType::I64),
                _ => None,
            };
            if let Some(cell_type) = physical {
                if cell_type != cell.cell_type {
                    return Err(unsupported());
                }
            } else if !matches!(field.codec, CodecRule::RequiresOwner { .. })
                && !matches!(cell.cell_type, CellType::Utf8 | CellType::Bytes)
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
fn missing_owner(codec: &CodecRule) -> bool {
    match codec {
        CodecRule::RequiresOwner { .. } => true,
        CodecRule::Object { fields } => fields.iter().any(|field| missing_owner(&field.codec)),
        CodecRule::Tagged { variants, .. } => variants
            .iter()
            .any(|variant| variant.fields.iter().any(|field| missing_owner(&field.codec))),
        CodecRule::Array { element } | CodecRule::SignedExact { body: element } => {
            missing_owner(element)
        }
        _ => false,
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
        if matches!(field.codec, CodecRule::Generated { .. })
            && field.disposition == Disposition::Transfer
        {
            return Err(unsupported());
        }
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
        CodecRule::SqlMacSubkeys | CodecRule::SqlDeviceRef => {
            if depth != 1 {
                return Err(unsupported());
            }
        }
        CodecRule::SqlBase64 { decoded_bytes, .. } => {
            if depth != 1 || decoded_bytes.0 != 32 {
                return Err(unsupported());
            }
        }
        CodecRule::SqlBytes { length, .. } => {
            if depth != 1 || length.0 == 0 || length.0 > i64::MAX.cast_unsigned() {
                return Err(unsupported());
            }
        }
        CodecRule::SqlI64 { min, max, .. } => {
            if depth != 1 {
                return Err(unsupported());
            }
            sql_i64_bounds(min, max)?;
        }
        CodecRule::Generated { cell_type, hidden, expression } => {
            if *cell_type == CellType::Null
                || !matches!(hidden, 2 | 3)
                || expression.is_empty()
                || expression.len() > 8192
            {
                return Err(unsupported());
            }
        }
        CodecRule::RequiresOwner { owner, cell_type } => {
            if !identifier(owner, true) || *cell_type == CellType::Null {
                return Err(unsupported());
            }
        }
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
pub(super) fn sql_i64_bounds(min: &str, max: &str) -> Result<(i64, i64), StorageError> {
    let low = min.parse::<i64>().map_err(|_| unsupported())?;
    let high = max.parse::<i64>().map_err(|_| unsupported())?;
    if low > high || low.to_string() != min || high.to_string() != max {
        return Err(unsupported());
    }
    Ok((low, high))
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

// Fresh migrated baseline. Optional/history and typed actor projections are still a
// required worklist; these declarations alone grant no record-export permission.
macro_rules! table_rule {
    ($id:literal, $table:tt, $mode:ident, $merge:ident, $restrictive:literal,
     [$($key:literal),*], [$(($name:literal,$kind:ident,$nullable:literal,$disp:ident,$field_merge:ident,$codec:expr)),* $(,)?]) => {
        FamilyRule {
            cells: table_rule!(@cells [] $(($name,$kind,$nullable,$disp)),*),
            codec_version: table_rule!(@version $table,$mode), disposition: Disposition::$mode,
            excluded: table_rule!(@excluded [] $(($name,$disp)),*),
            id: $id, key: &[$($key),*], merge: MergeRule::$merge,
            restrictive: $restrictive, selector: FamilySelector::Table($table),
            codec: &[$(FieldRule { name:$name, nullable:$nullable,
                disposition:Disposition::$disp, merge:MergeRule::$field_merge, codec:$codec }),*],
            key_grammar_version:U64(1), restrictive_projection:&[],
        }
    };
    (@version "account_erasure_generation",$mode:ident) => { U64(2) };
    (@version "object_erasure_fence",$mode:ident) => { U64(2) };
    (@version "object_erasure_lookup",$mode:ident) => { U64(2) };
    (@version "object_payload_dependency",$mode:ident) => { U64(2) };
    (@version "object_identity_replacement",$mode:ident) => { U64(2) };
    (@version "object_segment_reference_veto",$mode:ident) => { U64(2) };
    (@version "account_mac_bundle",Transfer) => { U64(2) };
    (@version "full_imported_mac_bundle",Transfer) => { U64(2) };
    (@version "runtime_inbox_recovery",$mode:ident) => { U64(2) };
    (@version "pairing_adoption",$mode:ident) => { U64(2) };
    (@version $other:literal,$mode:ident) => { U64(1) };
    (@cells [$($out:expr,)*]) => { &[$($out,)*] };
    (@cells [$($out:expr,)*] ($name:literal,$kind:ident,$nullable:literal,Transfer) $(,$rest:tt)*) => {
        table_rule!(@cells [$($out,)* CellRule {name:$name,nullable:$nullable,cell_type:CellType::$kind},] $($rest),*)
    };
    (@cells [$($out:expr,)*] ($name:literal,$kind:ident,$nullable:literal,$other:ident) $(,$rest:tt)*) => {
        table_rule!(@cells [$($out,)*] $($rest),*)
    };
    (@excluded [$($out:expr,)*]) => { &[$($out,)*] };
    (@excluded [$($out:expr,)*] ($name:literal,Transfer) $(,$rest:tt)*) => {
        table_rule!(@excluded [$($out,)*] $($rest),*)
    };
    (@excluded [$($out:expr,)*] ($name:literal,$other:ident) $(,$rest:tt)*) => {
        table_rule!(@excluded [$($out,)* $name,] $($rest),*)
    };
}

mod cleanup_local;
mod completion_local;
mod own_sync_local;
mod tables_0;
mod tables_1;
mod tables_2;
mod tables_3;
mod tail_application_local;
mod tail_local;
use tail_application_local::{APPLY as TAIL_APPLICATION, DEPENDENCY as TAIL_DEPENDENCIES};
/// Fresh migrated baseline schema declarations. No row with `RequiresOwner` can be
/// exported. Optional/history schemas and actor projections must be added explicitly.
#[must_use]
pub const fn full_transfer_catalog() -> &'static [FamilyRule] {
    TABLE_CATALOG
}
static TABLE_CATALOG: &[FamilyRule] = &[
    local_actor::GROUP_RULE,
    local_actor::SAFETY_RULE,
    tables_0::RULE_0,       // sql/a2ui_surface_cache
    tables_0::RULE_1,       // sql/account_erasure_generation
    tables_0::RULE_2,       // sql/account_key_check
    tables_0::RULE_3,       // sql/account_mac_bundle/local
    tables_0::RULE_4,       // sql/account_mac_bundle/portable
    tables_0::RULE_5,       // sql/ack_state
    tables_0::RULE_6,       // sql/audit_log
    tables_0::RULE_7,       // sql/bot_install_grant
    tables_0::RULE_8,       // sql/bot_manifest_cache
    tables_0::RULE_9,       // sql/bot_trust_pin
    tables_0::RULE_10,      // sql/contact_link_decision
    tables_0::RULE_11,      // sql/contact_message_fence_retention
    tables_0::RULE_12,      // sql/contact_message_request
    tables_0::RULE_13,      // sql/contact_message_request_fence
    tables_0::RULE_14,      // sql/contact_request_authority_floor
    tables_0::RULE_15,      // sql/contact_request_decision
    tables_0::RULE_16,      // sql/contact_request_delivery
    tables_0::RULE_17,      // sql/contact_request_fence
    tables_0::RULE_18,      // sql/contact_request_projection
    tables_0::RULE_19,      // sql/contact_request_rate
    tables_0::RULE_20,      // sql/contact_request_retirement
    tables_0::RULE_21,      // sql/contact_verification_projection
    tables_0::RULE_22,      // sql/conversation_delivery_state
    tables_0::RULE_23,      // sql/conversation_disappearing_policy
    tables_0::RULE_24,      // sql/conversation_list_state
    tables_0::RULE_25,      // sql/conversation_projection
    tables_0::RULE_26,      // sql/conversation_read_state
    tables_0::RULE_27,      // sql/conversation_tombstone
    tables_0::RULE_28,      // sql/conversation_unread_marker
    tables_0::RULE_29,      // sql/cursor_checkpoint
    tables_0::RULE_30,      // sql/device_directory
    tables_0::RULE_31,      // sql/device_identity
    tables_0::RULE_32,      // sql/device_inbox_cursor
    tables_0::RULE_33,      // sql/device_namespace_upgrade
    tables_0::RULE_34,      // sql/direct_message_projection
    tables_0::RULE_35,      // sql/event_causal_dependency
    tables_0::RULE_36,      // sql/event_tombstone
    tables_0::RULE_37,      // sql/friend_link_projection
    tables_0::RULE_38,      // sql/friend_projection
    tables_3::RULE_159,     // sql/full_imported_mac_bundle
    tables_0::RULE_39,      // sql/group_ban_projection
    tables_1::RULE_40,      // sql/group_control_event_seen
    tables_1::RULE_41,      // sql/group_invite_projection
    tables_1::RULE_42,      // sql/group_member_device_key
    tables_1::RULE_43,      // sql/group_member_projection
    tables_1::RULE_44,      // sql/group_message_tombstone_projection
    tables_1::RULE_45,      // sql/group_pending_undecrypted
    tables_1::RULE_46,      // sql/group_projection
    tables_1::RULE_47,      // sql/group_sender_identity_upgrade
    tables_1::RULE_48,      // sql/group_sender_key_counter_seen
    tables_1::RULE_49,      // sql/guardian_recovery_share_projection/local
    tables_1::RULE_50,      // sql/guardian_recovery_share_projection/portable
    tables_1::RULE_51,      // sql/home_node_binding
    tables_1::RULE_52,      // sql/identity_lifecycle_projection
    tables_1::RULE_53,      // sql/legacy_conversation_delivery_state
    tables_1::RULE_54,      // sql/legacy_conversation_read_state
    tables_1::RULE_55,      // sql/legacy_conversation_unread_marker
    tables_1::RULE_56,      // sql/legacy_group_member_device_key
    tables_1::RULE_57,      // sql/legacy_group_sender_key_counter_seen
    tables_1::RULE_58,      // sql/legacy_receipt_projection
    tables_1::RULE_59,      // sql/lineage_checkpoint
    tables_1::RULE_60,      // sql/local_event_counter
    tables_1::RULE_61,      // sql/local_event_log
    tables_1::RULE_62,      // sql/mcp_grant
    tables_1::RULE_63,      // sql/mcp_server_registry
    tables_1::RULE_64,      // sql/mcp_standing_approval
    tables_1::RULE_65,      // sql/mcp_tool_manifest
    tables_1::RULE_66,      // sql/message_copy_binding
    tables_1::RULE_67,      // sql/message_footprint
    tables_1::RULE_68,      // sql/message_footprint_actor_stage
    tables_1::RULE_69,      // sql/message_footprint_journal_stage
    tables_1::RULE_70,      // sql/message_footprint_migration
    tables_1::RULE_71,      // sql/message_footprint_outbox_stage
    tables_1::RULE_72,      // sql/message_projection
    tables_1::RULE_73,      // sql/message_tombstone_projection
    tables_1::RULE_74,      // sql/nack_state
    tables_1::RULE_75,      // sql/object_chunk/local
    tables_1::RULE_76,      // sql/object_chunk/portable
    tables_1::RULE_77,      // sql/object_erasure_fence
    tables_1::RULE_78,      // sql/object_erasure_lookup
    tables_1::RULE_79,      // sql/object_erasure_work
    tables_2::RULE_80,      // sql/object_identity_replacement
    tables_2::RULE_81,      // sql/object_index/local
    tables_2::RULE_82,      // sql/object_index/portable
    tables_2::RULE_83,      // sql/object_key_slot
    tables_2::RULE_84,      // sql/object_legacy_reference_context
    tables_2::RULE_85,      // sql/object_manifest
    tables_2::RULE_86,      // sql/object_message_reference
    tables_2::RULE_87,      // sql/object_operation
    tables_2::RULE_88,      // sql/object_payload_actor
    tables_2::RULE_89,      // sql/object_payload_dependency
    tables_2::RULE_90,      // sql/object_projection_erasure_work
    tables_2::RULE_91,      // sql/object_reference_actor
    tables_2::RULE_92,      // sql/object_reference_erasure_work
    tables_2::RULE_93,      // sql/object_retention_payload
    tables_2::RULE_94,      // sql/object_retention_reference
    tables_2::RULE_95,      // sql/object_retention_upgrade
    tables_2::RULE_96,      // sql/object_runtime_response
    tables_2::RULE_97,      // sql/object_segment_file
    tables_2::RULE_98,      // sql/object_segment_floor
    tables_2::RULE_99,      // sql/object_segment_reference_veto
    tables_2::RULE_100,     // sql/object_segment_resource
    tables_2::RULE_101,     // sql/object_share_grant_projection
    tables_2::RULE_102,     // sql/object_tombstone
    tables_2::RULE_103,     // sql/object_transfer_state
    tables_2::RULE_104,     // sql/object_transport_actor
    tables_2::RULE_105,     // sql/outbox_queue
    tables_2::RULE_106,     // sql/pairing_adoption
    tables_2::RULE_107,     // sql/pairing_floor
    completion_local::RULE, // sql/pairing_full_completion
    tail_local::RULE,       // sql/pairing_full_tail
    TAIL_APPLICATION,       // sql/pairing_full_tail_apply
    TAIL_DEPENDENCIES,      // sql/pairing_full_tail_dependency
    tables_2::RULE_108,     // sql/pairing_head
    tables_2::RULE_109,     // sql/pairing_live
    own_sync_local::RULE,   // sql/pairing_own_sync
    cleanup_local::RULE,    // sql/pairing_source_cleanup
    tables_2::RULE_110,     // sql/pairing_terminal
    tables_2::RULE_111,     // sql/pending_recovery_approval_projection
    tables_2::RULE_112,     // sql/pending_recovery_projection
    tables_2::RULE_113,     // sql/projection_checkpoint
    tables_2::RULE_114,     // sql/raw_envelope_log
    tables_2::RULE_115,     // sql/raw_inner_copy
    tables_2::RULE_116,     // sql/raw_inner_evidence
    tables_2::RULE_117,     // sql/raw_inner_owner
    tables_2::RULE_118,     // sql/receipt_identity_upgrade
    tables_2::RULE_119,     // sql/receipt_projection
    tables_3::RULE_120,     // sql/receive_erased_input
    tables_3::RULE_121,     // sql/rejected_inbox_projection
    tables_3::RULE_122,     // sql/root_group_control_event_seen
    tables_3::RULE_123,     // sql/root_group_invite_identity
    tables_3::RULE_124,     // sql/root_group_sender_key_counter_seen
    tables_3::RULE_125,     // sql/root_identity_key_upgrade
    tables_3::RULE_126,     // sql/runtime_account_identity
    tables_3::RULE_127,     // sql/runtime_ack
    tables_3::RULE_128,     // sql/runtime_actor_state
    tables_3::RULE_129,     // sql/runtime_attachment_budget
    tables_3::RULE_130,     // sql/runtime_attachment_expiry
    tables_3::RULE_131,     // sql/runtime_attachment_grant
    tables_3::RULE_132,     // sql/runtime_attachment_reference
    tables_3::RULE_133,     // sql/runtime_attachment_retirement
    tables_3::RULE_134,     // sql/runtime_home_migration_job
    tables_3::RULE_135,     // sql/runtime_home_migration_transition
    tables_3::RULE_136,     // sql/runtime_inbox_changes
    tables_3::RULE_137,     // sql/runtime_inbox_dead_letter
    tables_3::RULE_138,     // sql/runtime_inbox_policy
    tables_3::RULE_139,     // sql/runtime_inbox_recovery
    tables_3::RULE_140,     // sql/runtime_inbox_retry
    tables_3::RULE_141,     // sql/runtime_journal
    tables_3::RULE_142,     // sql/runtime_journal_bounds
    tables_3::RULE_143,     // sql/runtime_message_content
    tables_3::RULE_144,     // sql/runtime_operation
    tables_3::RULE_145,     // sql/runtime_outbox
    tables_3::RULE_146,     // sql/runtime_own_copy_state
    tables_3::RULE_147,     // sql/runtime_own_copy_usage
    tables_3::RULE_148,     // sql/runtime_privacy_maintenance
    tables_3::RULE_149,     // sql/runtime_receipt_retention
    tables_3::RULE_150,     // sql/runtime_scoped_ack
    tables_3::RULE_151,     // sql/runtime_unrouted
    tables_3::RULE_152,     // sql/schema_migration
    tables_3::RULE_153,     // sql/self_device_control_log
    tables_3::RULE_154,     // sql/session_capability_cache
    tables_3::RULE_155,     // sql/shared_group_floor_generation
    tables_3::RULE_156,     // sql/shared_group_member_projection
    tables_3::RULE_157,     // sql/shared_group_removal_floor
    tables_3::RULE_158,     // sql/sync_checkpoint
];
