// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded field conversion for named native DTOs; the caller fixes the generated descriptor.
use crate::{SdkError, client::task::generated as json};
use prost_reflect::Kind;
use ramflux_protocol::message::{self as g, registry};
use serde_json::{Map, Value};

const MAX_DEPTH: usize = 32;
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(format!("generated fields: {reason}"))
}

pub(crate) fn convert(name: &str, value: &Value, generated: bool) -> Result<Value, SdkError> {
    shape(name, value, generated, 0)
}

fn shape(name: &str, value: &Value, generated: bool, depth: usize) -> Result<Value, SdkError> {
    if depth >= MAX_DEPTH {
        return Err(invalid("surface conversion nesting limit"));
    }
    if name == "JsonValue" {
        return if generated {
            Ok(serde_json::to_value(json::json_value(value)?)?)
        } else {
            json::value_json(&serde_json::from_value::<g::JsonValue>(value.clone())?)
        };
    }
    if name == "JsonObject" {
        return if generated {
            Ok(serde_json::to_value(json::json_object(
                value.as_object().ok_or_else(|| invalid("surface data must be an object"))?,
            )?)?)
        } else {
            json::object_value(&serde_json::from_value::<g::JsonObject>(value.clone())?)
        };
    }
    let descriptor =
        registry::descriptor(name).map_err(|_| invalid("surface descriptor missing"))?;
    if name != "SurfaceEvent" && descriptor.oneofs().any(|choice| !choice.is_synthetic()) {
        return choice(name, value, generated, depth, &descriptor);
    }
    if name.starts_with("SurfaceCommand") && descriptor.fields().count() == 1 {
        let field = descriptor
            .get_field_by_name("value")
            .ok_or_else(|| invalid("surface command wrapper missing"))?;
        let Kind::Message(child) = field.kind() else {
            return Err(invalid("surface command descriptor invalid"));
        };
        return if generated {
            Ok(serde_json::json!({"value":shape(child.name(), value, true, depth + 1)?}))
        } else {
            shape(
                child.name(),
                value.get("value").ok_or_else(|| invalid("surface command payload missing"))?,
                false,
                depth + 1,
            )
        };
    }
    let fields = value.as_object().ok_or_else(|| invalid("surface fields missing"))?;
    let mut result = Map::new();
    for (key, value) in fields {
        let field = descriptor
            .fields()
            .find(|field| {
                field.name() == key
                    || field.json_name() == key
                    || (field.name() == "final_" && key == "final")
            })
            .ok_or_else(|| invalid("surface field unknown"))?;
        let mut converted = value.clone();
        if !value.is_null() {
            if let Kind::Message(child) = field.kind() {
                converted = if field.is_list() {
                    Value::Array(
                        value
                            .as_array()
                            .ok_or_else(|| invalid("surface vector invalid"))?
                            .iter()
                            .map(|item| shape(child.name(), item, generated, depth + 1))
                            .collect::<Result<_, _>>()?,
                    )
                } else {
                    shape(child.name(), value, generated, depth + 1)?
                };
            } else if !generated
                && matches!(
                    field.kind(),
                    Kind::Uint64 | Kind::Int64 | Kind::Sint64 | Kind::Fixed64 | Kind::Sfixed64
                )
                && let Some(token) = value.as_str()
            {
                converted =
                    serde_json::from_str(token).map_err(|_| invalid("surface integer invalid"))?;
            }
        }
        let key = if generated { field.json_name() } else { native_key(name, &field) };
        result.insert(key.into(), converted);
    }
    if !generated {
        native_defaults(name, &descriptor, &mut result);
        if name == "SurfaceEvent" && !result.contains_key("resync") {
            result.remove("final");
        }
    }
    Ok(Value::Object(result))
}

fn native_defaults(
    name: &str,
    descriptor: &prost_reflect::MessageDescriptor,
    result: &mut Map<String, Value>,
) {
    for field in descriptor.fields() {
        let key = native_key(name, &field);
        if result.contains_key(key) {
            continue;
        }
        let default = if field.is_list() {
            Some(Value::Array(Vec::new()))
        } else if field.supports_presence() {
            None
        } else {
            match field.kind() {
                Kind::String => Some(Value::String(String::new())),
                Kind::Bool => Some(Value::Bool(false)),
                Kind::Uint64 | Kind::Int64 | Kind::Uint32 | Kind::Int32 => Some(Value::from(0)),
                _ => None,
            }
        };
        if let Some(value) = default {
            result.insert(key.into(), value);
        }
    }
    // CreateSurface.data_model defaults in the native DTO. Preserve its absence
    // in checkpoint JSON: inventing an empty message changes signed protobuf bytes.
    if descriptor.fields().any(|field| field.json_name() == "dataPatch")
        && !result.contains_key("dataPatch")
    {
        result.insert("dataPatch".into(), Value::Object(Map::new()));
    }
}

fn choice(
    name: &str,
    value: &Value,
    generated: bool,
    depth: usize,
    descriptor: &prost_reflect::MessageDescriptor,
) -> Result<Value, SdkError> {
    let tag = match name {
        "SurfaceCommand" => Some("command"),
        "SurfacePatchOp" => Some("op"),
        "TaskApprovalPayload" => Some("kind"),
        _ => None,
    };
    if generated {
        let mut fields = value.as_object().cloned().unwrap_or_default();
        let choice = if let Some(tag) = tag {
            fields
                .remove(tag)
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| invalid("surface variant tag missing"))?
        } else {
            value.as_str().ok_or_else(|| invalid("surface enum missing"))?.into()
        };
        let field = descriptor
            .fields()
            .find(|field| field.name() == choice || field.json_name() == choice)
            .ok_or_else(|| invalid("surface variant unknown"))?;
        let Kind::Message(child) = field.kind() else {
            return Err(invalid("surface variant descriptor invalid"));
        };
        let payload = shape(child.name(), &Value::Object(fields), true, depth + 1)?;
        return Ok(Value::Object(Map::from_iter([(field.json_name().into(), payload)])));
    }
    let fields = value.as_object().ok_or_else(|| invalid("surface choice missing"))?;
    if fields.len() != 1 {
        return Err(invalid("surface choice must select one variant"));
    }
    let (key, value) = fields.iter().next().ok_or_else(|| invalid("surface choice missing"))?;
    let field = descriptor
        .fields()
        .find(|field| field.name() == key || field.json_name() == key)
        .ok_or_else(|| invalid("surface choice unknown"))?;
    if let Some(tag) = tag {
        let Kind::Message(child) = field.kind() else {
            return Err(invalid("surface variant descriptor invalid"));
        };
        let mut payload = shape(child.name(), value, false, depth + 1)?
            .as_object()
            .cloned()
            .ok_or_else(|| invalid("surface variant fields missing"))?;
        payload.insert(
            tag.into(),
            Value::String(if tag == "command" { field.json_name() } else { field.name() }.into()),
        );
        return Ok(Value::Object(payload));
    }
    Ok(Value::String(field.name().into()))
}

fn native_key<'a>(name: &str, field: &'a prost_reflect::FieldDescriptor) -> &'a str {
    if field.name() == "final_" {
        "final"
    } else if matches!(name, "SurfaceResyncMetadata" | "SurfaceTaskBinding")
        || name.starts_with("SurfacePatchOp")
        || name.starts_with("Task")
        || name.starts_with("LocalMcp")
    {
        field.name()
    } else {
        field.json_name()
    }
}
