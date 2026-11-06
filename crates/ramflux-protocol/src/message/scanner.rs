// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Descriptor traversal before prost can discard unknown peer fields.
use super::{
    registry,
    validation::{
        MAX_DEPTH, MAX_ENTITIES, MAX_MEDIA, MAX_TEXT_BYTES, ScanOutcome, ValidationError,
    },
    wire,
};
use prost_reflect::{FieldDescriptor, Kind, MessageDescriptor};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn scan(
    descriptor: &MessageDescriptor,
    bytes: &[u8],
    layer: u32,
    depth: usize,
) -> Result<ScanOutcome, ValidationError> {
    if depth > MAX_DEPTH {
        return Err(ValidationError::Limit);
    }
    if matches!(descriptor.name(), "Task" | "Surface") && bytes.len() > 30_720 {
        return Err(ValidationError::Limit);
    }
    let mut input = bytes;
    let mut previous = 0;
    let mut counts = BTreeMap::<u32, usize>::new();
    let mut choices = BTreeSet::new();
    let mut outcome = ScanOutcome::Supported;
    let (mut operation, mut payload) = (0, 0);
    let mut object_key: Option<&str> = None;
    let mut map_keys = BTreeMap::<u32, &str>::new();
    while !input.is_empty() {
        let field = wire::field(&mut input)?;
        if field.tag < previous {
            return Err(ValidationError::NonCanonical);
        }
        previous = field.tag;
        let Some(schema) = descriptor.get_field(field.tag) else {
            outcome = ScanOutcome::Unsupported;
            continue;
        };
        let count = counts.entry(field.tag).or_default();
        *count += 1;
        if *count > 1 && !schema.is_list() && !schema.is_map() {
            return Err(ValidationError::NonCanonical);
        }
        if let Some(oneof) = schema.containing_oneof()
            && !choices.insert(oneof.full_name().to_string())
        {
            return Err(ValidationError::MissingChoice);
        }
        collection_cap(descriptor.name(), schema.name(), *count)?;
        if schema.is_map() {
            let key = json_member_key(field.bytes)?;
            if map_keys.get(&field.tag).is_some_and(|previous| *previous >= key) {
                return Err(ValidationError::NonCanonical);
            }
            map_keys.insert(field.tag, key);
        }
        if descriptor.name() == "JsonObject" && schema.name() == "members" {
            let key = json_member_key(field.bytes)?;
            if object_key.is_some_and(|previous| {
                previous.encode_utf16().cmp(key.encode_utf16()) != std::cmp::Ordering::Less
            }) {
                return Err(ValidationError::NonCanonical);
            }
            object_key = Some(key);
        }
        if descriptor.name() == "FriendControl"
            && schema.name() == "action"
            && !(1..=5).contains(&field.scalar)
        {
            outcome = ScanOutcome::Unsupported;
        }
        if registry::field_layer(descriptor.name(), field.tag).is_none_or(|first| first > layer) {
            outcome = ScanOutcome::Unsupported;
        }
        if scan_field(&schema, &field, layer, depth)? == ScanOutcome::Unsupported {
            outcome = ScanOutcome::Unsupported;
        }
        if descriptor.name() == "Control" {
            if field.tag == 1 {
                operation = field.scalar;
            } else if field.tag >= 16 {
                payload = field.tag;
            }
        }
    }
    if outcome == ScanOutcome::Supported {
        for oneof in descriptor.oneofs().filter(|oneof| !oneof.is_synthetic()) {
            if !choices.contains(oneof.full_name()) {
                return Err(ValidationError::MissingChoice);
            }
        }
        if descriptor.name() == "Control"
            && !registry::CONTROLS
                .iter()
                .any(|binding| u64::from(binding.operation) == operation && binding.tag == payload)
        {
            return Err(ValidationError::Operation);
        }
    }
    Ok(outcome)
}

fn collection_cap(message: &str, field: &str, count: usize) -> Result<(), ValidationError> {
    let maximum = match (message, field) {
        ("Message", "entities") => MAX_ENTITIES,
        ("Message", "media") => MAX_MEDIA,
        _ => super::validation::MAX_INNER_BYTES / 2,
    };
    if count > maximum { Err(ValidationError::Limit) } else { Ok(()) }
}

fn scan_field(
    schema: &FieldDescriptor,
    field: &wire::Field<'_>,
    layer: u32,
    depth: usize,
) -> Result<ScanOutcome, ValidationError> {
    let expected = match schema.kind() {
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => 1,
        Kind::String | Kind::Bytes | Kind::Message(_) => 2,
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => 5,
        _ => 0,
    };
    if field.wire != expected {
        return Err(ValidationError::Malformed);
    }
    if !schema.supports_presence()
        && !schema.is_list()
        && !schema.is_map()
        && ((expected == 0 && field.scalar == 0)
            || (expected == 2 && field.bytes.is_empty())
            || (matches!(expected, 1 | 5) && field.bytes.iter().all(|byte| *byte == 0)))
    {
        return Err(ValidationError::NonCanonical);
    }
    match schema.kind() {
        Kind::Message(message) => return scan(&message, field.bytes, layer, depth + 1),
        Kind::Enum(enumeration) => {
            let signed = i64::from_le_bytes(field.scalar.to_le_bytes());
            if i32::try_from(signed).ok().and_then(|number| enumeration.get_value(number)).is_none()
            {
                return Ok(ScanOutcome::Unsupported);
            }
        }
        Kind::Bool if field.scalar > 1 => return Err(ValidationError::Malformed),
        Kind::Uint32 | Kind::Sint32 if field.scalar > u64::from(u32::MAX) => {
            return Err(ValidationError::Malformed);
        }
        Kind::Int32 if i32::try_from(i64::from_le_bytes(field.scalar.to_le_bytes())).is_err() => {
            return Err(ValidationError::Malformed);
        }
        Kind::String => validate_string(schema, field.bytes)?,
        Kind::Bytes => {
            let cap = match (schema.parent_message().name(), schema.name()) {
                ("Thumbnail", "encoded_image") => 16 * 1024,
                (name, "canonical") if name.starts_with("Native") => 8 * 1024,
                _ => super::validation::MAX_INNER_BYTES,
            };
            if field.bytes.len() > cap {
                return Err(ValidationError::Limit);
            }
        }
        _ => {}
    }
    Ok(ScanOutcome::Supported)
}

fn validate_string(schema: &FieldDescriptor, bytes: &[u8]) -> Result<(), ValidationError> {
    let identifier = schema.name().ends_with("_id")
        || schema.name().ends_with("_anchor")
        || schema.name().ends_with("_principal")
        || schema.name().ends_with("_device")
        || matches!(
            schema.name(),
            "id" | "device"
                | "account_anchor"
                | "principal"
                | "conversation"
                | "group"
                | "root"
                | "requester"
                | "assignee"
                | "author"
                | "proposer"
                | "sender"
                | "receiver"
        );
    if bytes.len() > if identifier { 256 } else { MAX_TEXT_BYTES } {
        return Err(ValidationError::Limit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ValidationError::Malformed)?;
    if identifier && text.chars().any(char::is_control) {
        return Err(ValidationError::Content);
    }
    if schema.parent_message().name() == "Reaction" && schema.name() == "token" {
        super::validation::validate_reaction_token(text)?;
    }
    if schema.parent_message().name() == "JsonValue" && schema.name() == "number" {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| ValidationError::Content)?;
        if !value.is_number() {
            return Err(ValidationError::Content);
        }
        super::super::validate_i_json_value(&value).map_err(|_| ValidationError::Content)?;
    }
    Ok(())
}

fn json_member_key(mut bytes: &[u8]) -> Result<&str, ValidationError> {
    let mut key = "";
    while !bytes.is_empty() {
        let field = wire::field(&mut bytes)?;
        if field.tag == 1 {
            key = std::str::from_utf8(field.bytes).map_err(|_| ValidationError::Malformed)?;
        }
    }
    Ok(key)
}
