// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline, immutable upstream schemas plus the closed rf-card profile.
use super::wire::validate_identifier;
use super::{CATALOG_ID, JsonPointer, Reject};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::OnceLock};
const PROFILE: &str = include_str!("../../catalogs/rf-card-v1.json");
const COMMON: &str = include_str!("../../vendor/a2ui/specification/v1_0/json/common_types.json");
const BASE: &str = "https://a2ui.org/specification/v1_0/catalog.json";
struct Schemas {
    components: BTreeMap<String, jsonschema::Validator>,
    functions: BTreeMap<String, jsonschema::Validator>,
}
static SCHEMAS: OnceLock<Result<Schemas, Reject>> = OnceLock::new();
fn build(schema: &Value, common: &Value) -> Result<jsonschema::Validator, Reject> {
    // HTTP and filesystem resolution features are disabled. Only these embedded resources exist.
    let mut catalog: Value = serde_json::from_str(PROFILE).map_err(|_| Reject::Encoding)?;
    let map = catalog.as_object_mut().ok_or(Reject::Encoding)?;
    map.insert("$id".into(), json!(BASE));
    jsonschema::options()
        .with_base_uri("https://a2ui.org/specification/v1_0/validation.json")
        .with_resource(BASE, jsonschema::Resource::from_contents(catalog))
        .with_resource(
            "https://a2ui.org/specification/v1_0/common_types.json",
            jsonschema::Resource::from_contents(common.clone()),
        )
        .with_resource(
            "https://a2ui.org/specification/v1_0/catalogs/basic/common_types.json",
            jsonschema::Resource::from_contents(common.clone()),
        )
        .should_validate_formats(true)
        .build(schema)
        .map_err(|error| {
            #[cfg(test)]
            eprintln!("embedded A2UI schema failed to compile: {error}");
            #[cfg(not(test))]
            let _ = error;
            Reject::Encoding
        })
}
fn schemas() -> Result<&'static Schemas, Reject> {
    SCHEMAS.get_or_init(|| {
        let basic: Value = serde_json::from_str(PROFILE).map_err(|_| Reject::Encoding)?;
        let common: Value = serde_json::from_str(COMMON).map_err(|_| Reject::Encoding)?;
        let mut components = BTreeMap::new();
        for (name, schema) in basic.get("components").and_then(Value::as_object).ok_or(Reject::Encoding)? {

            let full = json!({"$defs":basic.get("$defs"),"allOf":[{"$ref":"common_types.json#/$defs/ComponentCommon"},schema],"unevaluatedProperties":false});
            components.insert(name.clone(),build(&full,&common)?);
        }
        let mut functions = BTreeMap::new();
        for (name,schema) in basic.get("functions").and_then(Value::as_object).ok_or(Reject::Encoding)? {
            let full = json!({"$defs":basic.get("$defs"),"allOf":[schema,{"type":"object","properties":{"catalogId":{"const":CATALOG_ID}}}],"unevaluatedProperties":false});
            functions.insert(name.clone(),build(&full,&common)?);
        }
        Ok(Schemas { components, functions })
    }).as_ref().map_err(Clone::clone)
}
pub(super) fn component(value: &Value) -> Result<(), Reject> {
    let name = value.get("component").and_then(Value::as_str).ok_or(Reject::Encoding)?;
    let schemas = schemas()?;
    let validator =
        schemas.components.get(name).ok_or_else(|| Reject::Validation("component".into()))?;
    validator.validate(value).map_err(|_| Reject::Validation("component schema".into()))?;
    if value.get("@catalogId").is_some_and(|v| v.as_str() != Some(CATALOG_ID)) {
        return Err(Reject::Expression);
    }
    if value.get("@checks").is_some_and(|v| v.as_array().is_none_or(|a| a.len() > 8)) {
        return Err(Reject::Limit);
    }
    if name == "TextField" && value.get("variant").and_then(Value::as_str) == Some("obscured") {
        return Err(Reject::Expression);
    }
    if name == "Button"
        && let Some(checks) = value.get("@checks")
    {
        reject_locale_checks(checks, 0)?;
    }
    expressions(value, false, 0)
}
fn reject_locale_checks(value: &Value, depth: usize) -> Result<(), Reject> {
    if depth > 16 {
        return Err(Reject::Limit);
    }
    match value {
        Value::Object(map) => {
            if let Some(name) = map.get("@call").and_then(Value::as_str) {
                if super::expression::locale_sensitive(name) {
                    return Err(Reject::LocaleDependentCheck);
                }
                if name == "formatString"
                    && let Some(program) = value.pointer("/args/value").and_then(Value::as_str)
                {
                    for expression in super::format_string::expressions(program)? {
                        reject_locale_checks(&expression, depth + 1)?;
                    }
                }
            }
            for child in map.values() {
                reject_locale_checks(child, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                reject_locale_checks(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn expressions(value: &Value, in_action: bool, depth: usize) -> Result<(), Reject> {
    if depth > 16 {
        return Err(Reject::Limit);
    }
    match value {
        Value::Object(map) => {
            if let Some(name) = map.get("@call") {
                let name = name.as_str().ok_or(Reject::Expression)?;
                if name != "@index" {
                    validate_identifier(name)?;
                }
                if name == "openUrl" && !in_action {
                    return Err(Reject::Expression);
                }
                function(value)?;
                if name == "formatString"
                    && let Some(program) = value.pointer("/args/value").and_then(Value::as_str)
                {
                    validate_program(program, depth + 1)?;
                }
                if name == "regex" {
                    super::expression::validate_regex(
                        value
                            .pointer("/args/pattern")
                            .and_then(Value::as_str)
                            .ok_or(Reject::Expression)?,
                    )?;
                }
            }
            if map.contains_key("@path")
                && (map.len() != 1 || !map.get("@path").is_some_and(Value::is_string))
            {
                return Err(Reject::Expression);
            }
            for (key, value) in map {
                if key.starts_with('@')
                    && !key.starts_with("@@")
                    && !["@path", "@call", "@catalogId", "@accessibility", "@metadata", "@checks"]
                        .contains(&key.as_str())
                {
                    return Err(Reject::Expression);
                }
                expressions(
                    value,
                    key == "functionCall" && in_action || key == "action",
                    depth + 1,
                )?;
            }
        }
        Value::Array(values) => {
            for value in values {
                expressions(value, false, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn validate_program(program: &str, depth: usize) -> Result<(), Reject> {
    if depth > 16 {
        return Err(Reject::Limit);
    }
    for expression in super::format_string::expressions(program)? {
        expressions(&expression, false, depth + 1)?;
    }
    Ok(())
}
pub(super) fn date_time_input(
    component: &Value,
    value: &Value,
    model: &Value,
    prefix: &str,
) -> Result<bool, Reject> {
    let Some(text) = value.as_str() else {
        return Ok(false);
    };
    let date = component.get("enableDate").and_then(Value::as_bool).unwrap_or(false);
    let time = component.get("enableTime").and_then(Value::as_bool).unwrap_or(false);
    let instant = if text.is_empty() {
        None
    } else if let Some(value) = temporal_value(text, date, time) {
        Some(value)
    } else {
        return Ok(false);
    };
    let (mut minimum, mut maximum) = (None, None);
    for (key, lower) in [("min", true), ("max", false)] {
        if let Some(bound) = component.get(key) {
            let bound = if let Some(text) = bound.as_str() {
                text.to_owned()
            } else {
                let path = bound.get("@path").and_then(Value::as_str).ok_or(Reject::Expression)?;
                let pointer = JsonPointer::parse(&if path.starts_with('/') {
                    path.into()
                } else {
                    format!("{prefix}/{path}")
                })?;
                pointer.get(model).and_then(Value::as_str).ok_or(Reject::Expression)?.to_owned()
            };
            let bound = temporal_value(&bound, date, time).ok_or(Reject::Expression)?;
            if lower {
                minimum = Some(bound);
            } else {
                maximum = Some(bound);
            }
            if instant.is_some_and(|instant| lower && instant < bound || !lower && instant > bound)
            {
                return Ok(false);
            }
        }
    }
    if matches!((minimum, maximum), (Some(min), Some(max)) if min > max) {
        return Err(Reject::Expression);
    }
    Ok(true)
}

fn temporal_value(text: &str, date: bool, time: bool) -> Option<i128> {
    use time::format_description::well_known::Iso8601;
    match (date, time) {
        (true, true) => time::OffsetDateTime::parse(text, &Iso8601::PARSING)
            .ok()
            .or_else(|| {
                time::PrimitiveDateTime::parse(text, &Iso8601::PARSING)
                    .ok()
                    .map(time::PrimitiveDateTime::assume_utc)
            })
            .map(time::OffsetDateTime::unix_timestamp_nanos),
        (true, false) if !text.contains('T') => time::Date::parse(text, &Iso8601::DATE)
            .ok()
            .map(|date| date.midnight().assume_utc().unix_timestamp_nanos()),
        (false, true) if !text.contains('T') => {
            let datetime = format!("1970-01-01T{text}");
            time::OffsetDateTime::parse(&datetime, &Iso8601::PARSING)
                .ok()
                .or_else(|| {
                    time::Time::parse(text, &Iso8601::TIME)
                        .ok()
                        .map(|time| time::OffsetDateTime::UNIX_EPOCH.replace_time(time))
                })
                .map(time::OffsetDateTime::unix_timestamp_nanos)
        }
        _ => None,
    }
}

const AGENT: &str =
    include_str!("../../vendor/a2ui/specification/v1_0/json/agent_to_renderer.json");
const RENDERER: &str =
    include_str!("../../vendor/a2ui/specification/v1_0/json/renderer_to_agent.json");
pub(super) fn rpc_message(value: &Value, kind: super::RpcKind) -> Result<(), Reject> {
    let mut common: Value = serde_json::from_str(COMMON).map_err(|_| Reject::Encoding)?;
    if kind == super::RpcKind::FunctionCall {
        // Agent calls are structurally validated but never resolve or execute a catalog
        // function. Unsupported names still receive the mandated function response.
        let defs =
            common.get_mut("$defs").and_then(Value::as_object_mut).ok_or(Reject::Encoding)?;
        defs.insert("FunctionCall".into(),json!({"allOf":[{"$ref":"#/$defs/FunctionCommon"},{"properties":{"args":{"type":"object"}}}],"unevaluatedProperties":false}));
    }
    let source: Value =
        serde_json::from_str(if kind == super::RpcKind::FunctionCall { AGENT } else { RENDERER })
            .map_err(|_| Reject::Encoding)?;
    // The call branch does not reference catalog component schemas; selecting it keeps all
    // schema resolution offline while preserving the upstream function-call contract.
    let schema = if kind == super::RpcKind::FunctionCall {
        source.pointer("/$defs/CallRendererFunctionMessage").ok_or(Reject::Encoding)?
    } else {
        &source
    };
    build(schema, &common)?.validate(value).map_err(|_| Reject::Encoding)?;
    let key = match kind {
        super::RpcKind::FunctionCall => "callRendererFunction",
        super::RpcKind::FunctionResponse => "rendererFunctionResponse",
        super::RpcKind::Error => "error",
    };
    let body = value.get(key).and_then(Value::as_object).ok_or(Reject::Encoding)?;
    if kind == super::RpcKind::FunctionCall {
        validate_identifier(
            body.get("callFunction")
                .and_then(|v| v.get("@call"))
                .and_then(Value::as_str)
                .ok_or(Reject::Expression)?,
        )?;
    }
    let allowed: &[&str] = match kind {
        super::RpcKind::FunctionCall => &["surfaceId", "functionCallId", "callFunction"],
        super::RpcKind::FunctionResponse => &["functionCallId", "value", "error"],
        super::RpcKind::Error => &["code", "message", "surfaceId", "path", "functionCallId"],
    };
    if body.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Reject::Encoding);
    }
    if let Some(error) = body.get("error").and_then(Value::as_object) {
        if error.keys().any(|k| !["code", "message"].contains(&k.as_str())) {
            return Err(Reject::Encoding);
        }
    }
    Ok(())
}

pub(super) fn function(value: &Value) -> Result<(), Reject> {
    let name = value.get("@call").and_then(Value::as_str).ok_or(Reject::Expression)?;
    if name == "@index" {
        let common: Value = serde_json::from_str(COMMON).map_err(|_| Reject::Encoding)?;
        return build(&json!({"$ref":"common_types.json#/$defs/IndexSystemFunction"}), &common)?
            .validate(value)
            .map_err(|_| Reject::Expression);
    }
    schemas()?
        .functions
        .get(name)
        .ok_or(Reject::Expression)?
        .validate(value)
        .map_err(|_| Reject::Expression)
}
