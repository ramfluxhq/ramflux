// SPDX-License-Identifier: BSD-3-Clause
//! Case table for the host fixture publisher.
//!
//! `LOCALE_FIXTURE_HOOK` stays `en`. Add launch-locale rows in `cases.json`
//! only after the resolver accepts them. `scripts/check-card-fixtures.py`
//! rejects any other published locale.
use serde::Deserialize;
use serde_json::{Map, Value};

pub(crate) const LOCALE_FIXTURE_HOOK: &str = "en";

#[derive(Debug)]
pub(crate) struct Case {
    pub(crate) kind: String,
    pub(crate) variant: Option<String>,
    pub(crate) expect: String,
    pub(crate) components: Vec<Value>,
    pub(crate) data_model: Value,
}

#[derive(Deserialize)]
struct RawCase {
    kind: String,
    variant: Option<String>,
    expect: String,
    components: Vec<Value>,
    #[serde(default = "empty_object", rename = "dataModel")]
    data_model: Value,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

pub(crate) fn load() -> Result<Vec<Case>, String> {
    let raw: Vec<RawCase> = serde_json::from_str(include_str!("cases.json"))
        .map_err(|error| format!("cases.json: {error}"))?;
    let mut cases = Vec::with_capacity(raw.len());
    let mut stems = Vec::with_capacity(raw.len());
    for item in raw {
        let case = validate(item)?;
        let stem = stem(&case);
        if stems.iter().any(|seen| seen == &stem) {
            return Err(format!("duplicate fixture {stem}"));
        }
        stems.push(stem);
        cases.push(case);
    }
    if cases.is_empty() {
        return Err("cases.json is empty".into());
    }
    Ok(cases)
}

pub(crate) fn stem(case: &Case) -> String {
    let variant = case.variant.as_deref().unwrap_or("unset");
    format!("{}/{variant}", dir_name(&case.kind))
}

fn validate(raw: RawCase) -> Result<Case, String> {
    if raw.expect != "tree" && raw.expect != "refused" {
        return Err(format!("{}: expect is tree or refused", raw.kind));
    }
    let root =
        root_component(&raw.components).ok_or_else(|| format!("{}: missing root", raw.kind))?;
    let component = root.get("component").and_then(Value::as_str).unwrap_or("");
    if component != raw.kind {
        return Err(format!("{}: root component is {component}", raw.kind));
    }
    match_variant(&raw.kind, raw.variant.as_deref(), root.get("variant"))?;
    if !raw.data_model.is_object() {
        return Err(format!("{}: dataModel is an object", raw.kind));
    }
    Ok(Case {
        kind: raw.kind,
        variant: raw.variant,
        expect: raw.expect,
        components: raw.components,
        data_model: raw.data_model,
    })
}

fn match_variant(kind: &str, expected: Option<&str>, actual: Option<&Value>) -> Result<(), String> {
    match (expected, actual.and_then(Value::as_str)) {
        (Some(variant), Some(actual)) if variant == actual => Ok(()),
        (None, None) => Ok(()),
        _ => Err(format!("{kind}: variant does not match the root component")),
    }
}

fn root_component(components: &[Value]) -> Option<&Map<String, Value>> {
    components.iter().find_map(|component| {
        let object = component.as_object()?;
        (object.get("id").and_then(Value::as_str) == Some("root")).then_some(object)
    })
}

fn dir_name(kind: &str) -> String {
    let mut name = String::new();
    for (index, ch) in kind.chars().enumerate() {
        if ch.is_uppercase() {
            if index > 0 {
                name.push('_');
            }
            name.extend(ch.to_lowercase());
        } else {
            name.push(ch);
        }
    }
    name
}
