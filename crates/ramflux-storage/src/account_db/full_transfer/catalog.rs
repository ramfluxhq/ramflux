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
mod contacts;
mod conversations;
mod events;
mod groups;
mod identity;
mod integrations;
mod keys;
mod message_sequence;
mod messages;
mod objects;
mod own_sync_local;
mod pairing;
mod progress;
mod receipts;
mod receive;
mod recovery;
mod routing;
mod runtime;
mod surfaces;
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
    surfaces::RULE_0,       // sql/a2ui_surface_cache
    objects::RULE_1,        // sql/account_erasure_generation
    keys::RULE_2,           // sql/account_key_check
    keys::RULE_3,           // sql/account_mac_bundle/local
    keys::RULE_4,           // sql/account_mac_bundle/portable
    receipts::RULE_5,       // sql/ack_state
    events::RULE_6,         // sql/audit_log
    integrations::RULE_7,   // sql/bot_install_grant
    integrations::RULE_8,   // sql/bot_manifest_cache
    integrations::RULE_9,   // sql/bot_trust_pin
    contacts::RULE_10,      // sql/contact_link_decision
    contacts::RULE_11,      // sql/contact_message_fence_retention
    contacts::RULE_12,      // sql/contact_message_request
    contacts::RULE_13,      // sql/contact_message_request_fence
    contacts::RULE_14,      // sql/contact_request_authority_floor
    contacts::RULE_15,      // sql/contact_request_decision
    contacts::RULE_16,      // sql/contact_request_delivery
    contacts::RULE_17,      // sql/contact_request_fence
    contacts::RULE_18,      // sql/contact_request_projection
    contacts::RULE_19,      // sql/contact_request_rate
    contacts::RULE_20,      // sql/contact_request_retirement
    contacts::RULE_21,      // sql/contact_verification_projection
    conversations::RULE_22, // sql/conversation_delivery_state
    conversations::RULE_23, // sql/conversation_disappearing_policy
    conversations::RULE_24, // sql/conversation_list_state
    conversations::RULE_25, // sql/conversation_projection
    conversations::RULE_26, // sql/conversation_read_state
    conversations::RULE_27, // sql/conversation_tombstone
    conversations::RULE_28, // sql/conversation_unread_marker
    progress::RULE_29,      // sql/cursor_checkpoint
    identity::RULE_30,      // sql/device_directory
    identity::RULE_31,      // sql/device_identity
    identity::RULE_32,      // sql/device_inbox_cursor
    identity::RULE_33,      // sql/device_namespace_upgrade
    conversations::RULE_34, // sql/direct_message_projection
    events::RULE_35,        // sql/event_causal_dependency
    events::RULE_36,        // sql/event_tombstone
    contacts::RULE_37,      // sql/friend_link_projection
    contacts::RULE_38,      // sql/friend_projection
    keys::RULE_159,         // sql/full_imported_mac_bundle
    groups::RULE_39,        // sql/group_ban_projection
    groups::RULE_40,        // sql/group_control_event_seen
    groups::RULE_41,        // sql/group_invite_projection
    groups::RULE_42,        // sql/group_member_device_key
    groups::RULE_43,        // sql/group_member_projection
    groups::RULE_44,        // sql/group_message_tombstone_projection
    groups::RULE_45,        // sql/group_pending_undecrypted
    groups::RULE_46,        // sql/group_projection
    groups::RULE_47,        // sql/group_sender_identity_upgrade
    groups::RULE_48,        // sql/group_sender_key_counter_seen
    recovery::RULE_49,      // sql/guardian_recovery_share_projection/local
    recovery::RULE_50,      // sql/guardian_recovery_share_projection/portable
    routing::RULE_51,       // sql/home_node_binding
    identity::RULE_52,      // sql/identity_lifecycle_projection
    conversations::RULE_53, // sql/legacy_conversation_delivery_state
    conversations::RULE_54, // sql/legacy_conversation_read_state
    conversations::RULE_55, // sql/legacy_conversation_unread_marker
    groups::RULE_56,        // sql/legacy_group_member_device_key
    groups::RULE_57,        // sql/legacy_group_sender_key_counter_seen
    receipts::RULE_58,      // sql/legacy_receipt_projection
    progress::RULE_59,      // sql/lineage_checkpoint
    events::RULE_60,        // sql/local_event_counter
    events::RULE_61,        // sql/local_event_log
    integrations::RULE_62,  // sql/mcp_grant
    integrations::RULE_63,  // sql/mcp_server_registry
    integrations::RULE_64,  // sql/mcp_standing_approval
    integrations::RULE_65,  // sql/mcp_tool_manifest
    messages::RULE_66,      // sql/message_copy_binding
    messages::RULE_67,      // sql/message_footprint
    messages::RULE_68,      // sql/message_footprint_actor_stage
    messages::RULE_69,      // sql/message_footprint_journal_stage
    messages::RULE_70,      // sql/message_footprint_migration
    messages::RULE_71,      // sql/message_footprint_outbox_stage
    messages::RULE_72,      // sql/message_projection
    messages::RULE_73,      // sql/message_tombstone_projection
    receipts::RULE_74,      // sql/nack_state
    objects::RULE_75,       // sql/object_chunk/local
    objects::RULE_76,       // sql/object_chunk/portable
    objects::RULE_77,       // sql/object_erasure_fence
    objects::RULE_78,       // sql/object_erasure_lookup
    objects::RULE_79,       // sql/object_erasure_work
    objects::RULE_80,       // sql/object_identity_replacement
    objects::RULE_81,       // sql/object_index/local
    objects::RULE_82,       // sql/object_index/portable
    objects::RULE_83,       // sql/object_key_slot
    objects::RULE_84,       // sql/object_legacy_reference_context
    objects::RULE_85,       // sql/object_manifest
    objects::RULE_86,       // sql/object_message_reference
    objects::RULE_87,       // sql/object_operation
    objects::RULE_88,       // sql/object_payload_actor
    objects::RULE_89,       // sql/object_payload_dependency
    objects::RULE_90,       // sql/object_projection_erasure_work
    objects::RULE_91,       // sql/object_reference_actor
    objects::RULE_92,       // sql/object_reference_erasure_work
    objects::RULE_93,       // sql/object_retention_payload
    objects::RULE_94,       // sql/object_retention_reference
    objects::RULE_95,       // sql/object_retention_upgrade
    objects::RULE_96,       // sql/object_runtime_response
    objects::RULE_97,       // sql/object_segment_file
    objects::RULE_98,       // sql/object_segment_floor
    objects::RULE_99,       // sql/object_segment_reference_veto
    objects::RULE_100,      // sql/object_segment_resource
    objects::RULE_101,      // sql/object_share_grant_projection
    objects::RULE_102,      // sql/object_tombstone
    objects::RULE_103,      // sql/object_transfer_state
    objects::RULE_104,      // sql/object_transport_actor
    runtime::RULE_105,      // sql/outbox_queue
    pairing::RULE_106,      // sql/pairing_adoption
    pairing::RULE_107,      // sql/pairing_floor
    completion_local::RULE, // sql/pairing_full_completion
    tail_local::RULE,       // sql/pairing_full_tail
    TAIL_APPLICATION,       // sql/pairing_full_tail_apply
    TAIL_DEPENDENCIES,      // sql/pairing_full_tail_dependency
    pairing::RULE_108,      // sql/pairing_head
    pairing::RULE_109,      // sql/pairing_live
    own_sync_local::RULE,   // sql/pairing_own_sync
    cleanup_local::RULE,    // sql/pairing_source_cleanup
    pairing::RULE_110,      // sql/pairing_terminal
    recovery::RULE_111,     // sql/pending_recovery_approval_projection
    recovery::RULE_112,     // sql/pending_recovery_projection
    progress::RULE_113,     // sql/projection_checkpoint
    events::RULE_114,       // sql/raw_envelope_log
    events::RULE_115,       // sql/raw_inner_copy
    events::RULE_116,       // sql/raw_inner_evidence
    events::RULE_117,       // sql/raw_inner_owner
    receipts::RULE_118,     // sql/receipt_identity_upgrade
    receipts::RULE_119,     // sql/receipt_projection
    receive::RULE_120,      // sql/receive_erased_input
    receive::RULE_121,      // sql/rejected_inbox_projection
    groups::RULE_122,       // sql/root_group_control_event_seen
    groups::RULE_123,       // sql/root_group_invite_identity
    groups::RULE_124,       // sql/root_group_sender_key_counter_seen
    identity::RULE_125,     // sql/root_identity_key_upgrade
    identity::RULE_126,     // sql/runtime_account_identity
    receipts::RULE_127,     // sql/runtime_ack
    runtime::RULE_128,      // sql/runtime_actor_state
    objects::RULE_129,      // sql/runtime_attachment_budget
    objects::RULE_130,      // sql/runtime_attachment_expiry
    objects::RULE_131,      // sql/runtime_attachment_grant
    objects::RULE_132,      // sql/runtime_attachment_reference
    objects::RULE_133,      // sql/runtime_attachment_retirement
    routing::RULE_134,      // sql/runtime_home_migration_job
    routing::RULE_135,      // sql/runtime_home_migration_transition
    receive::RULE_136,      // sql/runtime_inbox_changes
    receive::RULE_137,      // sql/runtime_inbox_dead_letter
    receive::RULE_138,      // sql/runtime_inbox_policy
    receive::RULE_139,      // sql/runtime_inbox_recovery
    receive::RULE_140,      // sql/runtime_inbox_retry
    runtime::RULE_141,      // sql/runtime_journal
    runtime::RULE_142,      // sql/runtime_journal_bounds
    messages::RULE_143,     // sql/runtime_message_content
    message_sequence::RULE,
    runtime::RULE_144,  // sql/runtime_operation
    runtime::RULE_145,  // sql/runtime_outbox
    runtime::RULE_146,  // sql/runtime_own_copy_state
    runtime::RULE_147,  // sql/runtime_own_copy_usage
    runtime::RULE_148,  // sql/runtime_privacy_maintenance
    receipts::RULE_149, // sql/runtime_receipt_retention
    receipts::RULE_150, // sql/runtime_scoped_ack
    routing::RULE_151,  // sql/runtime_unrouted
    progress::RULE_152, // sql/schema_migration
    identity::RULE_153, // sql/self_device_control_log
    routing::RULE_154,  // sql/session_capability_cache
    groups::RULE_155,   // sql/shared_group_floor_generation
    groups::RULE_156,   // sql/shared_group_member_projection
    groups::RULE_157,   // sql/shared_group_removal_floor
    progress::RULE_158, // sql/sync_checkpoint
];
