// SPDX-License-Identifier: BSD-3-Clause
use crate::{CardError, Component, FieldKind, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub(crate) const MAX_INPUT: usize = 16 * 1024;
pub(crate) const MAX_MODEL: usize = 4096;
pub(crate) const MAX_JSON_DEPTH: usize = 16;
pub(crate) const MAX_COMPONENTS: usize = 32;
pub(crate) const MAX_FIELDS: usize = 16;
pub(crate) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_MODEL_FIELDS: usize = 32;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardSpec {
    pub catalog: String,
    pub components: Vec<Component>,
    #[serde(deserialize_with = "unique_model")]
    pub model: BTreeMap<String, Scalar>,
    #[serde(default)]
    pub theme: Theme,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    Light,
    Dark,
}
/// Check raw byte/depth limits before deserialization allocates any values.
pub(crate) fn preflight(bytes: &[u8], max: usize) -> Result<(), CardError> {
    if bytes.len() > max {
        return Err(CardError::Limit("JSON bytes"));
    }
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *b == b'\\' {
                escaped = true;
            } else if *b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(CardError::Limit("JSON depth"));
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(CardError::Invalid("JSON depth"))?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && !matches!(s, "__proto__" | "prototype" | "constructor")
}
fn unique_model<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Scalar>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, Scalar>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique scalar model keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, Scalar>()? {
                if result.len() >= MAX_MODEL_FIELDS || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate or excessive model keys"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Visitor)
}
impl CardSpec {
    /// Parse bounded declarative card input before constructing a VM.
    /// # Errors
    /// Rejects unknown properties, invalid ownership/bindings and resource limits.
    pub fn parse(bytes: &[u8]) -> Result<Self, CardError> {
        preflight(bytes, MAX_INPUT)?;
        let spec: Self = serde_json::from_slice(bytes)?;
        spec.validate()?;
        Ok(spec)
    }
    pub(crate) fn validate(&self) -> Result<(), CardError> {
        if self.catalog != "rf-card/v1" {
            return Err(CardError::Invalid("catalog"));
        }
        if self.components.is_empty() || self.components.len() > MAX_COMPONENTS {
            return Err(CardError::Limit("components"));
        }
        if self.model.len() > MAX_MODEL_FIELDS
            || self.model.iter().any(|(k, v)| !identifier(k) || v.display().len() > MAX_MODEL)
            || serde_json::to_vec(&self.model)?.len() > MAX_MODEL
        {
            return Err(CardError::Limit("model"));
        }
        let (mut ids, mut bindings) = (BTreeSet::new(), BTreeSet::new());
        for component in &self.components {
            if !identifier(component.id()) || !ids.insert(component.id()) {
                return Err(CardError::Invalid("component identity"));
            }
            match component {
                Component::Form(form) => validate_form(form, &self.model, &mut bindings)?,
                Component::Task(task) => validate_task(task)?,
                Component::Chart(chart) => validate_chart(chart)?,
                Component::Approval(approval) => validate_approval(approval)?,
            }
        }
        crate::projection::expected(self)?.check_limits()?;
        Ok(())
    }
    pub(crate) fn render_input(&self) -> Result<String, CardError> {
        let mut components = Vec::new();
        for component in &self.components {
            let mut value = serde_json::to_value(component)?;
            if let Component::Form(form) = component {
                let fields = form
                    .normalized_fields()
                    .into_iter()
                    .map(|field| {
                        let key =
                            field.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?;
                        let scalar =
                            self.model.get(key).ok_or(CardError::Invalid("binding value"))?;
                        Ok(serde_json::json!({"field":field,"value":scalar}))
                    })
                    .collect::<Result<Vec<_>, CardError>>()?;
                value
                    .as_object_mut()
                    .ok_or(CardError::Invalid("form shape"))?
                    .insert("resolved_fields".into(), serde_json::Value::Array(fields));
            }
            components.push(value);
        }
        Ok(serde_json::to_string(&serde_json::json!({"theme":self.theme,"components":components}))?)
    }
    pub(crate) fn slots(&self) -> Vec<crate::HostSecuritySlot> {
        self.components
            .iter()
            .filter_map(|component| {
                if let Component::Approval(a) = component {
                    Some(crate::HostSecuritySlot {
                        component: a.id.clone(),
                        request_ref: a.request_ref.clone(),
                        task_binding: a.task_binding.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}
fn validate_form(
    form: &crate::Form,
    model: &BTreeMap<String, Scalar>,
    bindings: &mut BTreeSet<String>,
) -> Result<(), CardError> {
    if form.title.len() > 256
        || !identifier(&form.submit)
        || (!form.fields.is_empty() && (!form.label.is_empty() || !form.binding.is_empty()))
    {
        return Err(CardError::Invalid("form properties"));
    }
    let fields = form.normalized_fields();
    if fields.is_empty() || fields.len() > MAX_FIELDS {
        return Err(CardError::Limit("fields"));
    }
    let mut field_ids = BTreeSet::new();
    for field in fields {
        if !identifier(&field.id)
            || field.id == "submit"
            || !field_ids.insert(field.id.clone())
            || field.label.len() > 256
            || field.error.as_ref().is_some_and(|e| e.is_empty() || e.len() > 256)
        {
            return Err(CardError::Invalid("field properties"));
        }
        let key = field.binding.strip_prefix('/').ok_or(CardError::Invalid("local binding"))?;
        if !identifier(key) || !bindings.insert(key.to_owned()) {
            return Err(CardError::Invalid("binding ownership"));
        }
        let value = model.get(key).ok_or(CardError::Invalid("dangling binding"))?;
        let type_matches = matches!(
            (field.kind, value),
            (FieldKind::Input | FieldKind::Select, Scalar::Text(_))
                | (FieldKind::Number, Scalar::Number(_))
                | (FieldKind::Toggle, Scalar::Toggle(_))
        );
        if !type_matches {
            return Err(CardError::Invalid("field value type"));
        }
        if field.kind != FieldKind::Select && !field.options.is_empty() {
            return Err(CardError::Invalid("options belong to select"));
        }
        if field.kind == FieldKind::Select {
            let mut options = BTreeSet::new();
            if field.options.is_empty()
                || field.options.len() > MAX_FIELDS
                || field.options.iter().any(|v| {
                    !identifier(&v.id) || v.label.len() > 256 || !options.insert(v.id.clone())
                })
            {
                return Err(CardError::Invalid("select options"));
            }
            if let Scalar::Text(selected) = value
                && !field.options.iter().any(|v| v.id == *selected)
            {
                return Err(CardError::Invalid("selected option"));
            }
        }
        if field.kind != FieldKind::Number && (field.minimum.is_some() || field.maximum.is_some()) {
            return Err(CardError::Invalid("number bounds"));
        }
        if let Scalar::Number(number) = value
            && (!safe_integer(*number)
                || field.minimum.is_some_and(|min| !safe_integer(min) || *number < min)
                || field.maximum.is_some_and(|max| !safe_integer(max) || *number > max)
                || matches!((field.minimum,field.maximum), (Some(a),Some(b)) if a>b))
        {
            return Err(CardError::Invalid("number range"));
        }
    }

    Ok(())
}

fn validate_task(task: &crate::Task) -> Result<(), CardError> {
    if !identifier(&task.task_ref)
        || task.title.len() > 256
        || task.requester.len() > 256
        || task.owner.len() > 256
        || task.progress.is_some_and(|v| v > 100)
        || task.steps.len() > MAX_FIELDS
    {
        return Err(CardError::Invalid("task projection"));
    }
    let mut steps = BTreeSet::new();
    if task.steps.iter().any(|s| !identifier(&s.id) || s.text.len() > 256 || !steps.insert(&s.id)) {
        return Err(CardError::Invalid("task steps"));
    }

    Ok(())
}

fn validate_chart(chart: &crate::Chart) -> Result<(), CardError> {
    if chart.title.len() > 256
        || chart.unit.len() > 32
        || chart.scale == 0
        || chart.scale > 1_000_000
        || chart.series.is_empty()
        || chart.series.len() > 2
    {
        return Err(CardError::Invalid("chart profile"));
    }
    let mut series = BTreeSet::new();
    for s in &chart.series {
        if !identifier(&s.id)
            || !series.insert(&s.id)
            || s.label.len() > 256
            || s.points.is_empty()
            || s.points.len() > MAX_FIELDS
            || s.points.iter().any(|p| p.label.len() > 64 || !safe_integer(p.value))
        {
            return Err(CardError::Invalid("chart series"));
        }
    }
    let first = chart.series.first().ok_or(CardError::Invalid("chart series"))?;
    if chart
        .series
        .iter()
        .any(|s| s.points.iter().map(|p| &p.label).ne(first.points.iter().map(|p| &p.label)))
    {
        return Err(CardError::Invalid("chart labels"));
    }

    Ok(())
}

fn validate_approval(approval: &crate::Approval) -> Result<(), CardError> {
    if !identifier(&approval.request_ref)
        || approval.task_binding.as_ref().is_some_and(|s| !identifier(s))
        || approval.explanation.len() > 1024
    {
        return Err(CardError::Invalid("approval references"));
    }

    Ok(())
}

fn safe_integer(value: i64) -> bool {
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_closed_props_and_limits() {
        let input = include_str!("../fixtures/form.json");
        assert!(
            CardSpec::parse(
                input.replace("\"name\":\"Ada\"", "\"name\":\"Ada\",\"name\":\"Eve\"").as_bytes()
            )
            .is_err(),
            "duplicate model keys must not have parser-dependent semantics"
        );
        assert!(
            CardSpec::parse(input.replace("rf.form", "rf.approval").as_bytes()).is_err(),
            "security chrome must not enter the catalog"
        );
        assert!(
            CardSpec::parse(input.replace("\"title\":", "\"script\":0,\"title\":").as_bytes())
                .is_err(),
            "unknown props must fail closed"
        );
        assert!(
            CardSpec::parse(input.replace("/name", "https://example.invalid/name").as_bytes())
                .is_err(),
            "bindings must stay local"
        );
        let mut spec = CardSpec::parse(input.as_bytes()).expect("test: valid fixture");
        spec.components = vec![spec.components[0].clone(); MAX_COMPONENTS + 1];
        assert!(spec.validate().is_err(), "component limit must reject before VM allocation");
        spec = CardSpec::parse(input.as_bytes()).expect("test: fixture");
        spec.model.insert("name".into(), Scalar::Text("x".repeat(MAX_MODEL)));
        assert!(spec.validate().is_err(), "model serialization must fit 4 KiB");
        assert!(
            preflight(&[b'['; MAX_JSON_DEPTH + 1], MAX_INPUT).is_err(),
            "depth preflight must stop recursive parsing"
        );
    }
}
