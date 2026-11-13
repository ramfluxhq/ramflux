// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant schema ownership and permanent kind/operation bindings.
use super::validation::ValidationError;
use super::{
    Call, Content, Control, Delete, Edit, FILE_DESCRIPTOR_SET, Message, Reaction, Receipt,
    SelfSync, Service, Surface, Task, Typing, content,
};
use prost::Message as _;
use prost_reflect::{DescriptorPool, MessageDescriptor};
use std::{collections::BTreeMap, sync::OnceLock};

/// Highest application layer implemented by this schema stage.
pub const COMPILED_LAYER: u32 = 3;
/// Admitted schema floor; declaration freshness cannot lower it.
pub const PROFILE_FLOOR: u32 = 3;
/// Permanently withdrawn kind numbers.
pub const RESERVED_KINDS: [u32; 3] = [13, 14, 15];
/// Approved native-field provenance and exact descriptor tags (§3.1).
pub const FIELD_MAPPINGS: &str = include_str!("schema/field_mappings.tsv");

/// One permanent kind/body/layer binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KindBinding {
    /// Permanent wire kind number.
    pub kind: u32,
    /// Unqualified generated descriptor name.
    pub body: &'static str,
    /// First supported schema layer.
    pub first_layer: u32,
}

macro_rules! kinds {
    ($(($id:literal, $name:ident, $layer:literal)),+ $(,)?) => {
        /// Exhaustive application-kind registry; Unsupported is a local projection.
        pub const KINDS: [KindBinding; 12] = [$(KindBinding { kind: $id, body: stringify!($name), first_layer: $layer }),+];

        /// Encode a generated body without introducing a second application model.
        /// # Errors
        /// Returns an error when Content has no selected constructor.
        pub fn encode_body(content: &Content) -> Result<(u32, Vec<u8>), ValidationError> {
            match content.value.as_ref().ok_or(ValidationError::MissingChoice)? {
                $(content::Value::$name(value) => Ok(($id, value.encode_to_vec())),)+
            }
        }

        /// Decode an already scanned, supported body. This grants no native authority.
        /// # Errors
        /// Returns an error for an unknown kind, unsupported field or invalid body.
        pub fn decode_body(kind: u32, bytes: &[u8], layer: u32) -> Result<Content, ValidationError> {
            let binding = kind_binding(kind).ok_or(ValidationError::Unsupported)?;
            if layer < binding.first_layer || layer > COMPILED_LAYER { return Err(ValidationError::Unsupported); }
            if super::validation::scan_message(binding.body, bytes, layer)? != super::validation::ScanOutcome::Supported {
                return Err(ValidationError::Unsupported);
            }
            let value = match kind {
                $($id => content::Value::$name($name::decode(bytes).map_err(|_| ValidationError::Malformed)?),)+
                _ => return Err(ValidationError::Unsupported),
            };
            let content = Content { value: Some(value) };
            super::validation::validate_content(&content)?;
            Ok(content)
        }
    }
}
kinds!(
    (1, Message, 1),
    (2, Service, 1),
    (3, Edit, 2),
    (4, Delete, 2),
    (5, Reaction, 2),
    (6, Receipt, 1),
    (7, Typing, 2),
    (8, Control, 1),
    (9, Surface, 1),
    (10, Task, 1),
    (11, Call, 1),
    (12, SelfSync, 1)
);

/// Find a supported permanent application constructor.
#[must_use]
pub fn kind_binding(kind: u32) -> Option<&'static KindBinding> {
    KINDS.iter().find(|entry| entry.kind == kind)
}

/// A Control.operation value and its sole legal oneof field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlBinding {
    /// Operation number.
    pub operation: u32,
    /// Payload field number.
    pub tag: u32,
    /// Exact payload descriptor name.
    pub body: &'static str,
}
/// Exact section 3.2 operation/payload map, all first introduced at layer 1.
pub const CONTROLS: [ControlBinding; 16] = [
    ControlBinding { operation: 1, tag: 16, body: "PairReset" },
    ControlBinding { operation: 2, tag: 17, body: "PairResetAck" },
    ControlBinding { operation: 3, tag: 18, body: "ContactControl" },
    ControlBinding { operation: 4, tag: 19, body: "GroupStateControl" },
    ControlBinding { operation: 5, tag: 20, body: "GroupKeyControl" },
    ControlBinding { operation: 6, tag: 21, body: "OwnContactSync" },
    ControlBinding { operation: 7, tag: 22, body: "HistoryPage" },
    ControlBinding { operation: 8, tag: 23, body: "HomeMigrationControl" },
    ControlBinding { operation: 9, tag: 24, body: "RecoveryControl" },
    ControlBinding { operation: 10, tag: 25, body: "LivePresence" },
    ControlBinding { operation: 11, tag: 26, body: "A2iControlEvent" },
    ControlBinding { operation: 12, tag: 27, body: "ObjectRevokeAccess" },
    ControlBinding { operation: 13, tag: 28, body: "OwnContactTombstone" },
    ControlBinding { operation: 14, tag: 29, body: "OwnGroupConsent" },
    ControlBinding { operation: 15, tag: 30, body: "OwnMessageCopy" },
    ControlBinding { operation: 16, tag: 31, body: "FriendControl" },
];

/// Immutable descriptor shared by scanners and operation/field consumers.
/// # Errors
/// Returns an error if the checked-in descriptor cannot be decoded.
pub fn descriptors() -> Result<&'static DescriptorPool, ValidationError> {
    static POOL: OnceLock<Result<DescriptorPool, prost_reflect::DescriptorError>> = OnceLock::new();
    POOL.get_or_init(|| DescriptorPool::decode(FILE_DESCRIPTOR_SET))
        .as_ref()
        .map_err(|_| ValidationError::Descriptor)
}

/// Resolve a schema leaf by its unqualified descriptor name.
/// # Errors
/// Returns an error for an unknown descriptor name or invalid embedded descriptor.
pub fn descriptor(name: &str) -> Result<MessageDescriptor, ValidationError> {
    descriptors()?
        .get_message_by_name(&format!("ramflux.message.v1.{name}"))
        .ok_or(ValidationError::Descriptor)
}

/// First layer for a permanent field; new additions must extend this registry.
#[must_use]
pub fn field_layer(message: &str, tag: u32) -> Option<u32> {
    type Fields = BTreeMap<&'static str, BTreeMap<u32, u32>>;
    static FIELDS: OnceLock<Fields> = OnceLock::new();
    FIELDS
        .get_or_init(|| {
            let mut fields = Fields::new();
            for row in FIELD_LAYERS.lines().filter(|row| !row.starts_with('#')) {
                let mut cells = row.split('\t');
                if let (Some(message), Some(_name), Some(tag), Some(layer)) =
                    (cells.next(), cells.next(), cells.next(), cells.next())
                    && let (Ok(tag), Ok(layer)) = (tag.parse::<u32>(), layer.parse::<u32>())
                {
                    fields.entry(message).or_default().insert(tag, layer);
                }
            }
            fields
        })
        .get(message)
        .and_then(|fields| fields.get(&tag))
        .copied()
}

/// One descriptor field exported by product adapters. Names come from the descriptor only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingField {
    /// Proto field name (`snake_case`).
    pub name: String,
    /// `ProtoJSON` field name (`camelCase`).
    pub json_name: String,
    /// Field number.
    pub tag: u32,
    /// True when JSON may omit the field.
    pub optional: bool,
    /// Closed choice name when this field is a oneof arm.
    pub oneof: Option<String>,
}

/// Descriptor-derived field vector for one generated message.
///
/// # Errors
/// Returns [`ValidationError::Descriptor`] when the type is absent.
pub fn binding_fields(message: &str) -> Result<Vec<BindingField>, ValidationError> {
    Ok(descriptor(message)?
        .fields()
        .map(|field| BindingField {
            name: field.name().to_string(),
            json_name: field.json_name().to_string(),
            tag: field.number(),
            optional: field.supports_presence() || field.containing_oneof().is_some(),
            oneof: field.containing_oneof().map(|choice| choice.name().to_string()),
        })
        .collect())
}

/// Frozen permanent field introductions; additions without metadata are unsupported.
pub const FIELD_LAYERS: &str = include_str!("schema/field_layers.tsv");
