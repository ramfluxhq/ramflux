// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline, immutable upstream schemas plus the closed rf-card profile.
use super::wire::identifier;
use super::{CATALOG_ID, JsonPointer, Reject};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::OnceLock};
const BASIC: &str = include_str!("../../vendor/a2ui/catalogs/basic/v1/catalog.json");
const COMMON: &str = include_str!("../../vendor/a2ui/specification/v1_0/json/common_types.json");
const BASE: &str = "https://a2ui.org/specification/v1_0/catalog.json";
struct Schemas {
    components: BTreeMap<String, jsonschema::Validator>,
    functions: BTreeMap<String, jsonschema::Validator>,
}
static SCHEMAS: OnceLock<Result<Schemas, Reject>> = OnceLock::new();
fn build(schema: &Value, common: &Value) -> Result<jsonschema::Validator, Reject> {
    // HTTP and filesystem resolution features are disabled. Only these embedded resources exist.
    jsonschema::options()
        .with_base_uri(BASE)
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
        .map_err(|_| Reject::Encoding)
}
fn schemas() -> Result<&'static Schemas, Reject> {
    SCHEMAS.get_or_init(|| {
        let basic: Value = serde_json::from_str(BASIC).map_err(|_| Reject::Encoding)?;
        let common: Value = serde_json::from_str(COMMON).map_err(|_| Reject::Encoding)?;
        let mut components = BTreeMap::new();
        for (name, schema) in basic.get("components").and_then(Value::as_object).ok_or(Reject::Encoding)? {
            if matches!(name.as_str(), "Video" | "AudioPlayer" | "Image") { continue; }
            let full = json!({"$defs":basic.get("$defs"),"allOf":[{"$ref":"common_types.json#/$defs/ComponentCommon"},schema],"unevaluatedProperties":false});
            components.insert(name.clone(),build(&full,&common)?);
        }
        for (name, properties, required) in [
            ("Approval",json!({"requestRef":{"type":"string"},"taskBinding":{"type":"object","properties":{"task_id":{"type":"string"},"step_id":{"type":"string"}},"required":["task_id","step_id"],"additionalProperties":false},"explanation":{"type":"string"}}),vec!["requestRef","explanation"]),
            ("Task",json!({"title":{"type":"string"},"taskRef":{"type":"string"},"requester":{"type":"string"},"owner":{"type":"string"},"status":{"type":"string"},"progress":{"type":["integer","null"]},"steps":{"type":"array"}}),vec!["title","taskRef","requester","owner","status","steps"]),
            ("Chart",json!({"kind":{"enum":["line","bar"]},"unit":{"type":"string"},"scale":{"type":"integer"},"series":{"type":"array"}}),vec!["kind","unit","scale","series"]),
            ("Table",json!({"columns":{"type":"array"},"rows":{"type":"array"}}),vec!["columns","rows"]),
            ("Image",json!({"attachment":{"type":"object","properties":{"object_id":{"type":"string"},"manifest_digest":{"type":"string"}},"required":["object_id","manifest_digest"],"additionalProperties":false},"description":{"$ref":"common_types.json#/$defs/DynamicString"},"fit":{"enum":["contain","cover","fill","none","scaleDown"]},"variant":{"enum":["icon","avatar","smallFeature","mediumFeature","largeFeature","header"]},"weight":{"type":"number"}}),vec!["attachment","description"]),
        ] {
            let mut properties = properties.as_object().ok_or(Reject::Encoding)?.clone();
            properties.insert("component".into(),json!({"const":name}));
            let mut required = required; required.push("component");
            let full = json!({"allOf":[{"$ref":"common_types.json#/$defs/ComponentCommon"},{"type":"object","properties":properties,"required":required}],"unevaluatedProperties":false});
            components.insert(name.into(),build(&full,&common)?);
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
    expressions(value, false, 0)
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
                    identifier(name)?;
                }
                if name == "openUrl" && !in_action {
                    return Err(Reject::Expression);
                }
                function(value)?;
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
pub(super) fn date_time_input(
    component: &Value,
    value: &Value,
    model: &Value,
    prefix: &str,
) -> Result<bool, Reject> {
    let Some(text) = value.as_str() else {
        return Ok(false);
    };
    if text.is_empty() {
        return Ok(true);
    }
    let date = component.get("enableDate").and_then(Value::as_bool).unwrap_or(false);
    let time = component.get("enableTime").and_then(Value::as_bool).unwrap_or(false);
    let valid = match (date, time) {
        (true, true) => {
            time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
                .is_ok()
        }
        (true, false) => time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
            .ok()
            .is_some_and(|format| time::Date::parse(text, &format).is_ok()),
        (false, true) => time::format_description::parse_borrowed::<2>("[hour]:[minute]:[second]")
            .ok()
            .is_some_and(|format| time::Time::parse(text, &format).is_ok()),
        (false, false) => false,
    };
    if !valid {
        return Ok(false);
    }
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
            if lower && text < bound.as_str() || !lower && text > bound.as_str() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

const AGENT: &str =
    include_str!("../../vendor/a2ui/specification/v1_0/json/agent_to_renderer.json");
const RENDERER: &str =
    include_str!("../../vendor/a2ui/specification/v1_0/json/renderer_to_agent.json");
pub(super) fn rpc_message(value: &Value, kind: super::RpcKind) -> Result<(), Reject> {
    let common: Value = serde_json::from_str(COMMON).map_err(|_| Reject::Encoding)?;
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
    let allowed: &[&str] = match kind {
        super::RpcKind::FunctionCall => &["surfaceId", "functionCallId", "callFunction"],
        super::RpcKind::FunctionResponse => &["functionCallId", "result", "error"],
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
        let map = value.as_object().ok_or(Reject::Expression)?;
        let args = value.get("args").and_then(Value::as_object).ok_or(Reject::Expression)?;
        if map.len() != 2 || args.keys().any(|key| key != "offset") {
            return Err(Reject::Expression);
        }
        return Ok(());
    }
    schemas()?
        .functions
        .get(name)
        .ok_or(Reject::Expression)?
        .validate(value)
        .map_err(|_| Reject::Expression)
}
