// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free Unsupported diagnostics; these classifications grant no authority.
use super::{
    registry,
    validation::{self, ScannedInner, ValidationError},
    wire,
};
use prost::Message as _;
use prost_reflect::{Kind, MessageDescriptor};

#[derive(Default)]
struct Unknown {
    field: bool,
    enumeration: bool,
    entity: bool,
}

/// The first matching OV2-RX-UNSUP reason. Never exports peer bytes or a private locator.
/// This is diagnostic only: admission still requires the ordinary scanner and authority checks.
#[must_use]
pub fn reason(scanned: &ScannedInner<'_>) -> &'static str {
    if scanned.layer > registry::COMPILED_LAYER {
        return "layer_above_supported";
    }
    let Some(binding) = registry::kind_binding(scanned.kind) else {
        return "unknown_kind";
    };
    let mut unknown = Unknown::default();
    let common_bad =
        validation::scan_message("Inner", scanned.exact_inner, registry::COMPILED_LAYER).is_err()
            || super::Inner::decode(scanned.exact_inner)
                .ok()
                .and_then(|inner| inner.identity)
                .is_none();
    let _ = collect("Inner", scanned.exact_inner, registry::COMPILED_LAYER, &mut unknown);
    let body_bad = validation::scan_message(binding.body, scanned.body, scanned.layer).is_err();
    let _ = collect(binding.body, scanned.body, scanned.layer, &mut unknown);
    if unknown.field {
        "unknown_field"
    } else if unknown.enumeration {
        "unknown_enum"
    } else if unknown.entity {
        "unknown_entity"
    } else if body_bad {
        "body_undecodable"
    } else if common_bad {
        "identity_undecodable"
    } else {
        "body_undecodable"
    }
}

fn collect(
    name: &str,
    bytes: &[u8],
    layer: u32,
    unknown: &mut Unknown,
) -> Result<(), ValidationError> {
    visit(&registry::descriptor(name)?, bytes, layer, 0, unknown)
}

fn visit(
    descriptor: &MessageDescriptor,
    bytes: &[u8],
    layer: u32,
    depth: usize,
    unknown: &mut Unknown,
) -> Result<(), ValidationError> {
    if depth > validation::MAX_DEPTH || bytes.len() > validation::MAX_INNER_BYTES {
        return Err(ValidationError::Limit);
    }
    let mut input = bytes;
    while !input.is_empty() {
        let field = wire::field(&mut input)?;
        let Some(schema) = descriptor.get_field(field.tag) else {
            if descriptor.name() == "Entity" {
                unknown.entity = true;
            } else {
                unknown.field = true;
            }
            continue;
        };
        if registry::field_layer(descriptor.name(), field.tag).is_none_or(|first| first > layer) {
            unknown.field = true;
        }
        if descriptor.name() == "FriendControl"
            && schema.name() == "action"
            && !(1..=5).contains(&field.scalar)
        {
            unknown.enumeration = true;
        }
        match schema.kind() {
            Kind::Message(nested) => visit(&nested, field.bytes, layer, depth + 1, unknown)?,
            Kind::Enum(enumeration) => {
                let value = i64::from_le_bytes(field.scalar.to_le_bytes());
                if i32::try_from(value)
                    .ok()
                    .and_then(|number| enumeration.get_value(number))
                    .is_none()
                {
                    if descriptor.name() == "Entity" {
                        unknown.entity = true;
                    } else {
                        unknown.enumeration = true;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
