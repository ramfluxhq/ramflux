// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Execute the bundled closed schema and its mandatory byte/semantic annotations.
use super::super::SurfaceReject;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::{collections::BTreeSet, sync::OnceLock};

type Result<T> = std::result::Result<T, SurfaceReject>;
fn reject(path: &str, rule: &str) -> SurfaceReject {
    SurfaceReject::WebCatalog { path: path.into(), rule: rule.into() }
}
fn encoded(value: &Value) -> Result<usize> {
    crate::canonical_json_bytes(value).map(|v| v.len()).map_err(|_| SurfaceReject::Encoding)
}
fn bundled() -> Result<&'static Value> {
    static SCHEMA: OnceLock<std::result::Result<Value, serde_json::Error>> = OnceLock::new();
    SCHEMA
        .get_or_init(|| serde_json::from_str(super::SCHEMA))
        .as_ref()
        .map_err(|_| SurfaceReject::Encoding)
}
pub(super) fn validate(value: &Value) -> Result<()> {
    crate::validate_i_json_value(value).map_err(|_| SurfaceReject::InvalidJson)?;
    forbidden_keys(value, "")?;
    let schema = bundled()?;
    check(value, schema, schema, "")?;
    if let Some(components) = value.get("components").and_then(Value::as_array) {
        for (i, component) in components.iter().enumerate() {
            cross_fields(component, &format!("/components/{i}"))?;
        }
    }
    Ok(())
}
fn forbidden_keys(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next = format!("{path}/{key}");
                if matches!(key.as_str(), "__proto__" | "prototype" | "constructor") {
                    return Err(reject(&next, "prototype"));
                }
                forbidden_keys(child, &next)?;
            }
        }
        Value::Array(array) => {
            for (i, child) in array.iter().enumerate() {
                forbidden_keys(child, &format!("{path}/{i}"))?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn check(value: &Value, schema: &Value, root: &Value, path: &str) -> Result<()> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let target = root
            .pointer(reference.strip_prefix('#').ok_or(SurfaceReject::Encoding)?)
            .ok_or(SurfaceReject::Encoding)?;
        return check(value, target, root, path);
    }
    if let Some(choices) = schema.get("anyOf").and_then(Value::as_array) {
        // Preserve precise errors after selecting the declared component discriminator or binding.
        if value.get("bind").is_some()
            && let Some(binding) = choices
                .iter()
                .find(|c| c.get("$ref").and_then(Value::as_str) == Some("#/$defs/Binding"))
        {
            return check(value, binding, root, path);
        }
        if let Some(kind) = value.get("type").and_then(Value::as_str) {
            if let Some(choice) = choices.iter().find(|choice| {
                choice
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.strip_prefix('#'))
                    .and_then(|r| root.pointer(r))
                    .and_then(|s| s.pointer("/properties/type/const"))
                    .and_then(Value::as_str)
                    == Some(kind)
            }) {
                return check(value, choice, root, path);
            }
            return Err(reject(&format!("{path}/type"), "discriminator"));
        }
        for choice in choices {
            if check(value, choice, root, path).is_ok() {
                return Ok(());
            }
        }
        // Literal schema is first, so type and bound failures stay exact.
        return check(value, choices.first().ok_or(SurfaceReject::Encoding)?, root, path);
    }
    if schema.get("const").is_some_and(|constant| value != constant) {
        return Err(reject(path, "const"));
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array)
        && !choices.contains(value)
    {
        return Err(reject(path, "enum"));
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        let valid = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some(),
            "null" => value.is_null(),
            _ => false,
        };
        if !valid {
            return Err(reject(path, "type"));
        }
    }
    check_string(value, schema, path)?;
    check_number(value, schema, path)?;
    if let Some(map) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(key) {
                    return Err(reject(&format!("{path}/{key}"), "required"));
                }
            }
        }
        for (key, child) in map {
            let next = format!("{path}/{key}");
            if let Some(property) = schema.get("properties").and_then(|p| p.get(key)) {
                check(child, property, root, &next)?;
            } else if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(reject(&next, "unknownField"));
            }
        }
    }
    if let Some(array) = value.as_array() {
        if schema.get("minItems").and_then(Value::as_u64).is_some_and(|n| (array.len() as u64) < n)
        {
            return Err(reject(path, "minItems"));
        }
        if schema.get("maxItems").and_then(Value::as_u64).is_some_and(|n| (array.len() as u64) > n)
        {
            return Err(reject(path, "maxItems"));
        }
        if let Some(item) = schema.get("items") {
            for (i, child) in array.iter().enumerate() {
                check(child, item, root, &format!("{path}/{i}"))?;
            }
        }
    }
    if let Some(max) = schema.get("x-encodedBytes").and_then(Value::as_u64)
        && encoded(value)? as u64 > max
    {
        return Err(reject(path, "x-encodedBytes"));
    }
    Ok(())
}
fn check_number(value: &Value, schema: &Value, path: &str) -> Result<()> {
    if let Some(number) = value.as_i64() {
        if schema.get("minimum").and_then(Value::as_i64).is_some_and(|min| number < min) {
            return Err(reject(path, "minimum"));
        }
        if schema.get("maximum").and_then(Value::as_i64).is_some_and(|max| number > max) {
            return Err(reject(path, "maximum"));
        }
    }
    Ok(())
}
fn check_string(value: &Value, schema: &Value, path: &str) -> Result<()> {
    if let Some(text) = value.as_str() {
        let length = text.chars().count();
        for (key, valid) in [
            (
                "minLength",
                schema.get("minLength").and_then(Value::as_u64).is_none_or(|n| length as u64 >= n),
            ),
            (
                "maxLength",
                schema.get("maxLength").and_then(Value::as_u64).is_none_or(|n| length as u64 <= n),
            ),
            (
                "x-utf8Bytes",
                schema
                    .get("x-utf8Bytes")
                    .and_then(Value::as_u64)
                    .is_none_or(|n| text.len() as u64 <= n),
            ),
        ] {
            if !valid {
                return Err(reject(path, key));
            }
        }
        if let Some(format) = schema.get("x-format").and_then(Value::as_str) {
            let valid = match format {
                "identifier" => identifier(text),
                "safeText" => crate::text_safety::free_text_is_safe(text),
                "objectId" => {
                    ramflux_core::ObjectId::new(text).is_ok()
                        && !text.contains("://")
                        && crate::text_safety::free_text_is_safe(text)
                }
                "digest32" => URL_SAFE_NO_PAD
                    .decode(text)
                    .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == text),
                _ => false,
            };
            if !valid {
                return Err(reject(path, format));
            }
        }
    }
    Ok(())
}
fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 24
        && text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && text.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}
fn unique(array: &Value, key: Option<&str>, path: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    if let Some(array) = array.as_array() {
        for value in array {
            let item = key.and_then(|k| value.get(k)).unwrap_or(value);
            if !seen.insert(crate::canonical_json_bytes(item).map_err(|_| SurfaceReject::Encoding)?)
            {
                return Err(reject(path, "unique"));
            }
        }
    }
    Ok(())
}
fn cross_fields(component: &Value, path: &str) -> Result<()> {
    let Some(data) = component.get("data") else {
        return Ok(());
    };
    let next = |field: &str| format!("{path}/data/{field}");
    match component.get("type").and_then(Value::as_str) {
        Some("rf.list") => unique(&data["items"], Some("key"), &next("items"))?,
        Some("rf.table") => {
            unique(&data["columns"], Some("key"), &next("columns"))?;
            unique(&data["rows"], Some("key"), &next("rows"))?;
            if let (Some(columns), Some(rows)) =
                (data["columns"].as_array(), data["rows"].as_array())
            {
                for row in rows {
                    if row["cells"].as_array().is_none_or(|cells| cells.len() != columns.len()) {
                        return Err(reject(&next("rows"), "cellCount"));
                    }
                }
            }
        }
        Some("rf.chart") => {
            unique(&data["series"], Some("key"), &next("series"))?;
        }
        Some("rf.timeline") => {
            unique(&data["events"], Some("key"), &next("events"))?;
            if let Some(events) = data["events"].as_array()
                && events.windows(2).any(|pair| pair[0]["at"].as_i64() > pair[1]["at"].as_i64())
            {
                return Err(reject(&next("events"), "timeOrder"));
            }
        }
        Some("rf.form") => unique(&data["fields"], None, &next("fields"))?,
        Some("rf.number") => {
            let min = data["min"].as_i64();
            let max = data["max"].as_i64();
            if min > max {
                return Err(reject(&next("min"), "rangeOrder"));
            }
            if let Some(value) = data["value"].as_i64()
                && (Some(value) < min || Some(value) > max)
            {
                return Err(reject(&next("value"), "range"));
            }
        }
        Some("rf.select") => {
            unique(&data["options"], Some("value"), &next("options"))?;
            if let (Some(options), Some(value)) =
                (data["options"].as_array(), data["value"].as_str())
                && !options.iter().any(|option| option["value"].as_str() == Some(value))
            {
                return Err(reject(&next("value"), "option"));
            }
        }
        Some("rf.input") if data["mode"] == "integer" => {
            if let Some(text) = data["value"].as_str()
                && text.parse::<i64>().ok().is_none_or(|n| {
                    n.unsigned_abs() > crate::MAX_SAFE_JSON_INTEGER || n.to_string() != text
                })
            {
                return Err(reject(&next("value"), "integerText"));
            }
        }
        Some("rf.map") => unique(&data["markers"], Some("key"), &next("markers"))?,
        Some("rf.progress") => {
            let total = data["total"].as_i64();
            let value = data["value"].as_i64();
            if total.is_some_and(|n| n < 1) {
                return Err(reject(&next("total"), "positive"));
            }
            if value.is_some_and(|n| n < 0 || total.is_some_and(|t| n > t)) {
                return Err(reject(&next("value"), "range"));
            }
        }
        _ => (),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateSurfaceCommand, SurfaceType};
    use serde_json::json;

    fn hash(c: &CreateSurfaceCommand) -> String {
        crate::surface_snapshot_hash(c).unwrap_or_else(|e| unreachable!("hash: {e}"))
    }
    fn samples() -> Vec<Value> {
        vec![
            json!({"id":"a","type":"rf.text","text":"plain <b>text</b>"}),
            json!({"id":"a","type":"rf.card","data":{"title":"T","body":"B"}}),
            json!({"id":"a","type":"rf.list","data":{"items":[{"key":"k","label":"L"}]}}),
            json!({"id":"a","type":"rf.table","data":{"columns":[{"key":"k","label":"L"}],"rows":[{"key":"r","cells":[1]}]}}),
            json!({"id":"a","type":"rf.chart","data":{"kind":"line","series":[{"key":"k","label":"L","points":[{"x":1,"y":2}]}]}}),
            json!({"id":"a","type":"rf.timeline","data":{"events":[{"key":"k","at":1,"label":"L","state":"done"}]}}),
            json!({"id":"a","type":"rf.form","data":{"title":"T","fields":["f"],"submit":"go"}}),
            json!({"id":"a","type":"rf.input","data":{"label":"L","value":"1","mode":"integer"}}),
            json!({"id":"a","type":"rf.number","data":{"label":"L","value":1,"min":0,"max":2}}),
            json!({"id":"a","type":"rf.select","data":{"label":"L","options":[{"value":"v","label":"L"}],"value":"v"}}),
            json!({"id":"a","type":"rf.toggle","data":{"label":"L","value":true}}),
            json!({"id":"a","type":"rf.media","data":{"kind":"image","ref":{"object_id":"object_1","manifest_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"alt":"L"}}),
            json!({"id":"a","type":"rf.map","data":{"center":{"lat_e6":0,"lon_e6":0},"zoom":1,"markers":[],"tiles":null}}),
            json!({"id":"a","type":"rf.progress","data":{"label":"L","value":1,"total":2}}),
            json!({"id":"a","type":"rf.status","data":{"label":"L","state":"pending"}}),
        ]
    }
    fn content(component: Value) -> CreateSurfaceCommand {
        CreateSurfaceCommand {
            surface_id: "surface".into(),
            surface_type: SurfaceType::MessageCard,
            catalog: super::super::CATALOG.into(),
            catalog_version: "1".into(),
            fallback_text: "Summary".into(),
            fallback_markdown: None,
            components: vec![component],
            data_model: serde_json::Map::new(),
            allowed_actions: vec![],
        }
    }
    fn negative(component: &Value, pointer: &str, value: Value, path: &str, rule: &str) {
        let mut changed = component.clone();
        *changed
            .pointer_mut(pointer)
            .unwrap_or_else(|| unreachable!("fixture pointer {pointer}")) = value;
        let c = content(changed);
        assert_eq!(super::super::validate(&c), Err(reject(path, rule)), "{pointer}");
    }

    #[test]
    fn webui_catalog_is_declarative_and_hash_compatible() {
        assert_basic_golden();
        assert!(!std::hint::black_box(super::super::ENABLED));
        for component in samples() {
            let c = content(component.clone());
            assert_eq!(super::super::validate(&c), Ok(()));
            let actual = super::super::super::snapshot::validated_hash(&c)
                .unwrap_or_else(|e| unreachable!("valid fixture: {e}"));
            assert_eq!(actual, hash(&c));
            // No projection, stripping, ordering of arrays or normalization enters the hash.
            let mut changed = c.clone();
            changed.fallback_text.push('!');
            assert_ne!(actual, hash(&changed));
            for key in
                ["scriptUrl", "html", "css", "function", "regex", "url", "onClick", "bundleDigest"]
            {
                let mut hostile = c.clone();
                hostile.components[0]
                    .as_object_mut()
                    .unwrap_or_else(|| unreachable!())
                    .insert(key.into(), json!("https://hostile.invalid/code.js"));
                assert_eq!(
                    super::super::validate(&hostile),
                    Err(reject(&format!("/components/0/{key}"), "unknownField"))
                );
            }
            negative(&component, "/type", json!("rf.Web"), "/components/0/type", "discriminator");
            negative(&component, "/id", json!("1bad"), "/components/0/id", "identifier");
            negative(&component, "/id", json!("a".repeat(25)), "/components/0/id", "identifier");
            // Check each declared field and nested closed object with its own path.
            closed_fields(
                &component,
                component_schema(&component),
                bundled().unwrap_or_else(|e| unreachable!("{e}")),
                "/components/0",
            );
        }
        let mut c = content(samples().remove(0));
        c.components[0]["scriptUrl"] = json!("https://hostile.invalid/code.js");
        assert_eq!(
            super::super::super::snapshot::validated_hash(&c),
            Err(reject("/components/0/scriptUrl", "unknownField"))
        );
        c.components[0].as_object_mut().unwrap_or_else(|| unreachable!()).remove("scriptUrl");
        c.catalog_version = "2".into();
        assert_eq!(
            super::super::super::snapshot::validated_hash(&c),
            Err(reject("/catalogVersion", "const"))
        );
        c.catalog = "basic".into();
        c.catalog_version = "1".into();
        assert_eq!(
            super::super::super::snapshot::validated_hash(&c),
            crate::surface_snapshot_hash(&c).map_err(|_| SurfaceReject::Encoding)
        );
        c.catalog = super::super::CATALOG.into();
        c.components[0]["text"] = json!("e\u{301}");
        let bytes = crate::encode_a2ui_conversation_event(
            "conv",
            1,
            &crate::A2uiConversationCommand::CreateSurface(c.clone()),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let event = crate::A2uiConversationEvent::from_wire_bytes(&bytes)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(event.command(), &crate::A2uiConversationCommand::CreateSurface(c.clone()));
        c.components[0]["text"] = json!("é");
        let crate::A2uiConversationCommand::CreateSurface(original) = event.command() else {
            unreachable!()
        };
        assert_ne!(hash(original), hash(&c));
        for key in ["__proto__", "prototype", "constructor"] {
            c.data_model = serde_json::from_value(json!({"nested":[{key:1}]}))
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                super::super::validate(&c),
                Err(reject(&format!("/dataModel/nested/0/{key}"), "prototype"))
            );
        }
        assert!(crate::A2uiConversationEvent::from_wire_bytes(br#"{"schema":"ramflux.a2ui.conversation.v2","schema":"ramflux.a2ui.conversation.v2"}"#).is_err());
    }
    fn assert_basic_golden() {
        let mut c = content(Value::Null);
        c.catalog = "basic".into();
        c.components.clear();
        let bytes = br#"{"catalog":"basic","catalogVersion":"1","fallbackText":"Summary","surfaceId":"surface","surfaceType":"message_card"}"#;
        assert_eq!(crate::canonical_json_bytes(&c).unwrap_or_else(|e| unreachable!("{e}")), bytes);
        // Independent pinned transcript, without the production domain/hash helper.
        let mut h = blake3::Hasher::new();
        h.update(b"ramflux.a2ui.surface_hash.v1");
        h.update(bytes);
        let expected = URL_SAFE_NO_PAD.encode(h.finalize().as_bytes());
        assert_eq!(super::super::super::snapshot::validated_hash(&c), Ok(expected));
    }

    fn component_schema(component: &Value) -> &'static Value {
        let name = component["type"]
            .as_str()
            .unwrap_or_else(|| unreachable!())
            .strip_prefix("rf.")
            .unwrap_or_else(|| unreachable!());
        bundled().unwrap_or_else(|e| unreachable!("{e}"))["$defs"]
            .get(name)
            .unwrap_or_else(|| unreachable!())
    }
    fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            return root
                .pointer(r.strip_prefix('#').unwrap_or_else(|| unreachable!()))
                .unwrap_or_else(|| unreachable!());
        }
        schema
    }
    fn closed_fields(value: &Value, schema: &Value, root: &Value, path: &str) {
        let schema = resolve(schema, root);
        if let Some(choices) = schema.get("anyOf").and_then(Value::as_array) {
            let choice = choices
                .iter()
                .find(|s| check(value, s, root, path).is_ok())
                .unwrap_or_else(|| unreachable!());
            closed_fields(value, choice, root, path);
            return;
        }
        if let Some(map) = value.as_object() {
            let mut hostile = value.clone();
            hostile["html"] = json!("<script>alert(1)</script>");
            assert_eq!(
                check(&hostile, schema, root, path),
                Err(reject(&format!("{path}/html"), "unknownField"))
            );
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for key in required.iter().filter_map(Value::as_str) {
                    let mut missing = value.clone();
                    missing.as_object_mut().unwrap_or_else(|| unreachable!()).remove(key);
                    assert_eq!(
                        check(&missing, schema, root, path),
                        Err(reject(&format!("{path}/{key}"), "required"))
                    );
                }
            }
            for (key, child) in map {
                closed_fields(child, &schema["properties"][key], root, &format!("{path}/{key}"));
            }
        } else if let Some(array) = value.as_array() {
            for (i, child) in array.iter().enumerate() {
                closed_fields(child, &schema["items"], root, &format!("{path}/{i}"));
            }
        }
    }

    #[test]
    fn webui_literal_cross_fields_reject_exact_errors() {
        let s = samples();
        negative(&s[8], "/data/min", json!(3), "/components/0/data/min", "rangeOrder");
        negative(&s[8], "/data/value", json!(3), "/components/0/data/value", "range");
        negative(&s[9], "/data/value", json!("missing"), "/components/0/data/value", "option");
        negative(&s[13], "/data/value", json!(-1), "/components/0/data/value", "range");
        negative(&s[13], "/data/value", json!(3), "/components/0/data/value", "range");
        negative(&s[13], "/data/total", json!(0), "/components/0/data/total", "positive");
        negative(
            &s[3],
            "/data/rows/0/cells",
            json!([1, 2]),
            "/components/0/data/rows",
            "cellCount",
        );
        for value in ["-0", "01", "+1", " 1", "1.0", "9007199254740992"] {
            negative(&s[7], "/data/value", json!(value), "/components/0/data/value", "integerText");
        }
        for (index, field) in [
            (2, "items"),
            (3, "columns"),
            (3, "rows"),
            (4, "series"),
            (5, "events"),
            (6, "fields"),
            (9, "options"),
        ] {
            let mut c = s[index].clone();
            let a = c["data"][field].as_array_mut().unwrap_or_else(|| unreachable!());
            a.push(a[0].clone());
            assert_eq!(
                super::super::validate(&content(c)),
                Err(reject(&format!("/components/0/data/{field}"), "unique"))
            );
        }
        let mut c = s[12].clone();
        c["data"]["markers"] = json!([{"key":"m","lat_e6":0,"lon_e6":0,"label":""},{"key":"m","lat_e6":0,"lon_e6":0,"label":""}]);
        assert_eq!(
            super::super::validate(&content(c)),
            Err(reject("/components/0/data/markers", "unique"))
        );
        let mut c = s[5].clone();
        c["data"]["events"] = json!([{"key":"a","at":2,"label":"","state":"done"},{"key":"b","at":1,"label":"","state":"done"}]);
        assert_eq!(
            super::super::validate(&content(c)),
            Err(reject("/components/0/data/events", "timeOrder"))
        );
    }

    #[test]
    fn webui_dispatch_enforces_top_level_profile_without_repair() {
        let mut c = content(samples().remove(0));
        c.fallback_text.clear();
        assert_eq!(super::super::super::snapshot::validated_hash(&c), Ok(hash(&c)));
        c.catalog = "basic".into();
        assert_eq!(
            super::super::super::snapshot::validated_hash(&c),
            Err(SurfaceReject::MissingFallback)
        );
        c.catalog = super::super::CATALOG.into();
        c.fallback_text = "Summary".into();
        c.components =
            (0..32).map(|i| json!({"id":format!("b{i}"),"type":"rf.text","text":"T"})).collect();
        assert_eq!(super::super::super::snapshot::validated_hash(&c), Ok(hash(&c)));
        c.components.push(json!({"id":"extra","type":"rf.text","text":"T"}));
        assert_eq!(
            super::super::super::snapshot::validated_hash(&c),
            Err(reject("/components", "maxItems"))
        );
        c.components.clear();
        c.allowed_actions =
            (0..16).map(|i| json!({"name":format!("a{i}"),"label":"L","kind":"request"})).collect();
        assert_eq!(super::super::validate(&c), Ok(()));
        c.allowed_actions.push(json!({"name":"extra","label":"L","kind":"request"}));
        assert_eq!(super::super::validate(&c), Err(reject("/allowedActions", "maxItems")));
        c.allowed_actions.clear();
        c.fallback_markdown = Some("**untrusted**".into());
        assert_eq!(
            super::super::super::snapshot::validated_hash(&c),
            Err(reject("/fallbackMarkdown", "unknownField"))
        );
    }

    #[test]
    fn webui_source_bytes_and_formats_have_exact_refusals() {
        let mut c = content(samples().remove(0));
        c.components[0]["text"] = json!("");
        let overhead = encoded(&c.components[0]).unwrap_or_else(|e| unreachable!("{e}"));
        c.components[0]["text"] = json!("a".repeat(256 - overhead));
        assert_eq!(super::super::validate(&c), Ok(()));
        c.components[0]["text"] = json!("a".repeat(257 - overhead));
        assert_eq!(super::super::validate(&c), Err(reject("/components/0", "x-encodedBytes")));
        c.components = vec![];
        c.fallback_text = "a".repeat(510);
        assert_eq!(super::super::validate(&c), Ok(()));
        c.fallback_text.push('a');
        assert_eq!(super::super::validate(&c), Err(reject("/fallbackText", "x-encodedBytes")));
        c.fallback_text = "Summary".into();
        c.data_model.insert("p".into(), json!("a".repeat(4088)));
        assert_eq!(super::super::validate(&c), Ok(()));
        c.data_model.insert("p".into(), json!("a".repeat(4089)));
        assert_eq!(super::super::validate(&c), Err(reject("/dataModel", "x-encodedBytes")));
        c.data_model.clear();
        let mut action = json!({"name":"go","label":"","kind":"request"});
        let overhead = encoded(&action).unwrap_or_else(|e| unreachable!("{e}"));
        action["label"] = json!("a".repeat(112 - overhead));
        c.allowed_actions = vec![action.clone()];
        assert_eq!(super::super::validate(&c), Ok(()));
        action["label"] = json!("a".repeat(113 - overhead));
        c.allowed_actions = vec![action];
        assert_eq!(super::super::validate(&c), Err(reject("/allowedActions/0", "x-encodedBytes")));
        let s = samples();
        negative(&s[0], "/text", json!("\u{0000}"), "/components/0/text", "safeText");
        negative(
            &s[11],
            "/data/ref/object_id",
            json!("https://hostile.invalid"),
            "/components/0/data/ref/object_id",
            "objectId",
        );
        negative(
            &s[11],
            "/data/ref/manifest_digest",
            json!("A".repeat(42) + "B"),
            "/components/0/data/ref/manifest_digest",
            "digest32",
        );
        negative(
            &s[0],
            "/text",
            json!({"bind":"/p","url":"https://hostile.invalid"}),
            "/components/0/text/url",
            "unknownField",
        );
    }

    // Mechanically exercises every schema field's numeric/count/string/byte bound,
    // including optional fields and nested records, without duplicating a bound table.
    #[test]
    fn webui_every_schema_bound_rejects_with_exact_path_and_rule() {
        let root = bundled().unwrap_or_else(|e| unreachable!("{e}"));
        bounds(root, root, "");
        for (name, schema) in root["$defs"].as_object().unwrap_or_else(|| unreachable!()) {
            bounds(schema, root, &format!("/$defs/{name}"));
        }
    }
    fn size(n: u64) -> usize {
        usize::try_from(n).unwrap_or_else(|e| unreachable!("schema bound: {e}"))
    }
    fn bounds(schema: &Value, root: &Value, path: &str) {
        if let Some(kind) = schema.get("type").and_then(Value::as_str) {
            let wrong = if kind == "null" { json!(0) } else { Value::Null };
            assert_eq!(check(&wrong, schema, root, path), Err(reject(path, "type")));
        }
        if schema.get("enum").is_some() {
            assert_eq!(check(&json!("UNKNOWN"), schema, root, path), Err(reject(path, "enum")));
        }
        if schema.get("const").is_some() {
            assert_eq!(check(&json!("UNKNOWN"), schema, root, path), Err(reject(path, "const")));
        }

        if schema.get("$ref").is_some() {
            return;
        }
        for (key, value) in [
            ("minimum", schema.get("minimum").and_then(Value::as_i64).map(|n| json!(n - 1))),
            ("maximum", schema.get("maximum").and_then(Value::as_i64).map(|n| json!(n + 1))),
            (
                "minLength",
                schema
                    .get("minLength")
                    .and_then(Value::as_u64)
                    .filter(|n| *n > 0)
                    .map(|n| json!("a".repeat(size(n - 1)))),
            ),
            (
                "maxLength",
                schema
                    .get("maxLength")
                    .and_then(Value::as_u64)
                    .map(|n| json!("a".repeat(size(n + 1)))),
            ),
            (
                "minItems",
                schema
                    .get("minItems")
                    .and_then(Value::as_u64)
                    .filter(|n| *n > 0)
                    .map(|n| json!(vec![Value::Null; size(n - 1)])),
            ),
            (
                "maxItems",
                schema
                    .get("maxItems")
                    .and_then(Value::as_u64)
                    .map(|n| json!(vec![Value::Null; size(n + 1)])),
            ),
        ] {
            if let Some(value) = value {
                assert_eq!(check(&value, schema, root, path), Err(reject(path, key)), "{path}");
            }
        }
        // Isolate encoded bounds to make the exact cap/cap+1 oracle independent
        // of earlier type/required errors; production field schemas use this check.
        if let Some(max) = schema.get("x-encodedBytes").and_then(Value::as_u64) {
            let only = json!({"type":"string","x-encodedBytes":max});
            assert_eq!(check(&json!("a".repeat(size(max - 2))), &only, root, path), Ok(()));
            assert_eq!(
                check(&json!("a".repeat(size(max - 1))), &only, root, path),
                Err(reject(path, "x-encodedBytes"))
            );
        }
        if let Some(max) = schema.get("x-utf8Bytes").and_then(Value::as_u64) {
            let only = json!({"type":"string","x-utf8Bytes":max});
            assert_eq!(
                check(&json!("é".repeat(size(max / 2 + 1))), &only, root, path),
                Err(reject(path, "x-utf8Bytes"))
            );
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (key, child) in properties {
                bounds(child, root, &format!("{path}/{key}"));
            }
        }
        if let Some(items) = schema.get("items") {
            bounds(items, root, &format!("{path}/*"));
        }
        if let Some(choices) = schema.get("anyOf").and_then(Value::as_array) {
            for child in choices {
                bounds(child, root, path);
            }
        }
    }
}
