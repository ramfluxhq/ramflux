// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The bounded component graph: reference resolution, template expansion, pruning and inputs.
use super::resource::{Bytes, Steps};
use super::wire::validate_identifier;
use super::{JsonPointer, MAX_DELTA_BYTES, Reject, ResolvedSlot, SurfaceSnapshot};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Template items per list, nested template scopes and expanded instances per surface.
pub(super) const MAX_TEMPLATE_ITEMS: usize = 16;
pub(super) const MAX_TEMPLATE_SCOPES: usize = 2;
pub(super) const MAX_INSTANCES: usize = 256;
const MAX_DEPTH: usize = 16;
const MAX_REFERENCE_VISITS: usize = 2048;
const MAX_EXPANDED_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(super) struct Instance<'a> {
    pub(super) component: &'a Value,
    pub(super) source: Vec<String>,
    pub(super) prefix: String,
    pub(super) scope: String,
    pub(super) parent: Option<usize>,
    pub(super) slot: ResolvedSlot,
}
pub(super) struct Graph<'a> {
    pub(super) instances: Vec<Instance<'a>>,
    pub(super) reached: BTreeSet<String>,
}
#[derive(Clone, Copy)]
struct WalkFrame<'a> {
    name: &'a str,
    source: &'a [String],
    prefix: &'a str,
    scope: &'a str,
    depth: usize,
    in_modal: bool,
    parent: Option<usize>,
    slot: ResolvedSlot,
}
struct WalkContext<'a, 'b> {
    definitions: &'b BTreeMap<&'a str, &'a Value>,
    snapshot: &'a SurfaceSnapshot,
}
struct ChildFrame {
    name: String,
    source: Vec<String>,
    prefix: String,
    scope: String,
    slot: ResolvedSlot,
}
pub(super) struct Input<'a> {
    pub(super) instance: Instance<'a>,
    pub(super) index: usize,
    pub(super) pointer: JsonPointer,
}
pub(super) fn kind(component: &Value) -> Result<&str, Reject> {
    component.get("component").and_then(Value::as_str).ok_or(Reject::Encoding)
}
pub(super) fn id(component: &Value) -> Result<&str, Reject> {
    component.get("id").and_then(Value::as_str).ok_or(Reject::Encoding)
}
pub(super) fn input(kind: &str) -> bool {
    matches!(kind, "TextField" | "CheckBox" | "Slider" | "ChoicePicker" | "DateTimeInput")
}
pub(super) fn resolve_pointer(path: &str, prefix: &str) -> Result<JsonPointer, Reject> {
    JsonPointer::parse(&if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{prefix}/{path}")
    })
}
pub(super) fn binding(value: &Value, prefix: &str) -> Result<JsonPointer, Reject> {
    let object = value.as_object().ok_or(Reject::Expression)?;
    if object.len() != 1 {
        return Err(Reject::Expression);
    }
    resolve_pointer(object.get("@path").and_then(Value::as_str).ok_or(Reject::Expression)?, prefix)
}
pub(super) fn literal(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.iter().all(|(key, _)| !key.starts_with('@') || key.starts_with("@@"))
                && map.values().all(literal)
        }
        Value::Array(values) => values.iter().all(literal),
        _ => true,
    }
}
impl<'a> Graph<'a> {
    pub(super) fn new(snapshot: &'a SurfaceSnapshot, steps: &Steps) -> Result<Self, Reject> {
        let mut definitions = BTreeMap::new();
        for component in &snapshot.components {
            let name = id(component)?;
            validate_identifier(name)?;
            validate_identifier(kind(component)?)?;
            if definitions.insert(name, component).is_some() {
                return Err(Reject::Integrity);
            }
        }
        let mut graph = Self { instances: Vec::new(), reached: BTreeSet::new() };
        let context = WalkContext { definitions: &definitions, snapshot };
        let mut references = References::default();
        for name in definitions.keys() {
            // Pruning does not excuse dangling references or cycles in supplied definitions.
            references.visit(name, &definitions, &mut BTreeSet::new())?;
        }
        graph.reached = references.visit("root", &definitions, &mut BTreeSet::new())?.reached;
        graph.walk(
            WalkFrame {
                name: "root",
                source: &[],
                prefix: "",
                scope: "Surface",
                depth: 0,
                in_modal: false,
                parent: None,
                slot: ResolvedSlot::Root,
            },
            &context,
            &mut BTreeSet::new(),
        )?;
        let mut bytes = Bytes::new(MAX_EXPANDED_BYTES);
        for instance in &graph.instances {
            expanded_value(
                instance.component,
                &snapshot.data_model,
                &instance.prefix,
                0,
                steps,
                &mut bytes,
            )?;
        }
        let mut controls = BTreeSet::new();
        for instance in &graph.instances {
            if (input(kind(instance.component)?) || kind(instance.component)? == "Button")
                && !controls.insert((id(instance.component)?, instance.source.clone()))
            {
                return Err(Reject::Validation("ambiguous control instance".into()));
            }
        }
        Ok(graph)
    }
    fn walk(
        &mut self,
        cursor: WalkFrame<'_>,
        context: &WalkContext<'a, '_>,
        stack: &mut BTreeSet<String>,
    ) -> Result<(), Reject> {
        let WalkFrame { name, source, prefix, scope, depth, in_modal, parent, slot } = cursor;
        if depth >= MAX_DEPTH
            || self.instances.len() >= MAX_INSTANCES
            || source.len() > MAX_TEMPLATE_SCOPES
        {
            return Err(Reject::Limit);
        }
        if !stack.insert(name.to_owned()) {
            return Err(Reject::Integrity);
        }
        let component = *context.definitions.get(name).ok_or(Reject::Integrity)?;
        let component_kind = kind(component)?;
        validate_composition(component_kind, depth, in_modal)?;
        let next_scope =
            if component_kind == "Card" { format!("{name}:{source:?}") } else { scope.to_owned() };
        let index = self.instances.len();
        self.instances.push(Instance {
            component,
            source: source.to_vec(),
            prefix: prefix.into(),
            scope: next_scope.clone(),
            parent,
            slot,
        });
        self.reached.insert(name.to_owned());
        let cursor = WalkFrame { scope: &next_scope, ..cursor };
        for child in self.children(component, &cursor, context)? {
            self.walk(
                WalkFrame {
                    name: &child.name,
                    source: &child.source,
                    prefix: &child.prefix,
                    scope: &child.scope,
                    depth: depth + 1,
                    in_modal: in_modal || component_kind == "Modal",
                    parent: Some(index),
                    slot: child.slot,
                },
                context,
                stack,
            )?;
        }
        stack.remove(name);
        Ok(())
    }
    /// The ordered child instances of one component; `cursor.scope` is its own form scope.
    fn children(
        &mut self,
        component: &'a Value,
        cursor: &WalkFrame<'_>,
        context: &WalkContext<'a, '_>,
    ) -> Result<Vec<ChildFrame>, Reject> {
        let WalkFrame { name, source, prefix, scope, .. } = *cursor;
        let child = |name: &str, scope: String, slot| ChildFrame {
            name: name.into(),
            source: source.to_vec(),
            prefix: prefix.into(),
            scope,
            slot,
        };
        let modal = kind(component)? == "Modal";
        let mut children = Vec::new();
        for (property, slot) in [
            ("child", ResolvedSlot::Child),
            ("trigger", ResolvedSlot::Trigger),
            ("content", ResolvedSlot::Content),
        ] {
            if let Some(value) = component.get(property) {
                let target = value.as_str().ok_or(Reject::Encoding)?;
                let child_scope = if modal && property == "content" {
                    format!("{name}.content:{source:?}")
                } else {
                    scope.to_owned()
                };
                children.push(child(target, child_scope, slot));
            }
        }
        if let Some(tabs) = component.get("tabs") {
            for (position, tab) in tabs.as_array().ok_or(Reject::Encoding)?.iter().enumerate() {
                let target = tab.get("child").and_then(Value::as_str).ok_or(Reject::Encoding)?;
                children.push(child(target, scope.to_owned(), ResolvedSlot::Tab(position)));
            }
        }
        let Some(list) = component.get("children") else {
            return Ok(children);
        };
        if let Some(array) = list.as_array() {
            for (position, value) in array.iter().enumerate() {
                let target = value.as_str().ok_or(Reject::Encoding)?;
                children.push(child(target, scope.to_owned(), ResolvedSlot::Children(position)));
            }
            return Ok(children);
        }
        let map = list.as_object().ok_or(Reject::Encoding)?;
        if map.len() != 2 {
            return Err(Reject::Encoding);
        }
        let template = map.get("componentId").and_then(Value::as_str).ok_or(Reject::Encoding)?;
        // Even an empty list must resolve its template and may not conceal a dangling reference.
        if !context.definitions.contains_key(template) {
            return Err(Reject::Integrity);
        }
        self.reached.insert(template.into());
        let pointer = resolve_pointer(
            map.get("path").and_then(Value::as_str).ok_or(Reject::Encoding)?,
            prefix,
        )?;
        let values = pointer
            .get(&context.snapshot.data_model)
            .and_then(Value::as_array)
            .ok_or(Reject::Expression)?;
        if values.len() > MAX_TEMPLATE_ITEMS || source.len() >= MAX_TEMPLATE_SCOPES {
            return Err(Reject::Limit);
        }
        for position in 0..values.len() {
            let item = format!("{}/{position}", pointer.canonical());
            let mut source = source.to_vec();
            source.push(item.clone());
            children.push(ChildFrame {
                name: template.into(),
                source,
                prefix: item,
                scope: scope.to_owned(),
                slot: ResolvedSlot::Item(position),
            });
        }
        Ok(children)
    }
    pub(super) fn inputs(&self, snapshot: &SurfaceSnapshot) -> Result<Vec<Input<'a>>, Reject> {
        let mut inputs: Vec<Input<'a>> = Vec::new();
        for (index, instance) in self.instances.iter().enumerate() {
            if input(kind(instance.component)?) {
                let pointer = binding(
                    instance.component.get("value").ok_or(Reject::Expression)?,
                    &instance.prefix,
                )?;
                if inputs.iter().any(|old| pointer.overlaps(&old.pointer)) {
                    return Err(Reject::Validation("input binding alias".into()));
                }
                inputs.push(Input { instance: instance.clone(), index, pointer });
            }
        }
        for owner in &inputs {
            for property in ["min", "max"] {
                if let Some(value) = owner.instance.component.get(property)
                    && value.is_object()
                {
                    let bound = binding(value, &owner.instance.prefix)?;
                    if inputs.iter().any(|input| input.pointer.overlaps(&bound)) {
                        return Err(Reject::Validation("input limit depends on an input".into()));
                    }
                }
            }
            validate_input(
                owner.instance.component,
                owner.pointer.get(&snapshot.data_model).ok_or(Reject::Expression)?,
                &snapshot.data_model,
                &owner.instance.prefix,
            )?;
        }
        Ok(inputs)
    }
}

pub(super) fn expanded_value(
    value: &Value,
    model: &Value,
    prefix: &str,
    depth: usize,
    steps: &Steps,
    bytes: &mut Bytes,
) -> Result<Value, Reject> {
    if depth > MAX_DEPTH {
        return Err(Reject::Limit);
    }
    match value {
        Value::Object(map) => {
            if let Some(name) = map.get("@call").and_then(Value::as_str) {
                if name == "@index" && prefix.is_empty() {
                    return Err(Reject::Expression);
                }
                if name == "formatString"
                    && matches!(
                        super::expression::evaluate_display(value, model, prefix, 0, None, steps),
                        Err(Reject::Limit)
                    )
                {
                    return Err(Reject::Limit);
                }
                if name == "formatString"
                    && let Some(source) = value.pointer("/args/value")
                    && source.get("@path").is_some()
                {
                    let pointer = binding(source, prefix)?;
                    if let Some(program) = pointer.get(model).and_then(Value::as_str) {
                        super::schema::validate_program(program, depth + 1)?;
                    }
                }
            }
            if let Some(path) = map.get("@path") {
                let pointer = resolve_pointer(path.as_str().ok_or(Reject::Expression)?, prefix)?;
                let bound = pointer.get(model).unwrap_or(&Value::Null);
                bytes.value(bound)?;
                return Ok(bound.clone());
            }
            bytes.take(2 + map.len().saturating_sub(1))?;
            let mut expanded = Map::new();
            for (key, value) in map {
                bytes.key(key)?;
                bytes.take(1)?;
                expanded.insert(
                    key.clone(),
                    expanded_value(value, model, prefix, depth + 1, steps, bytes)?,
                );
            }
            Ok(Value::Object(expanded))
        }
        Value::Array(array) => {
            bytes.take(2 + array.len().saturating_sub(1))?;
            array
                .iter()
                .map(|v| expanded_value(v, model, prefix, depth + 1, steps, bytes))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        _ => {
            bytes.value(value)?;
            Ok(value.clone())
        }
    }
}

fn validate_composition(kind: &str, depth: usize, in_modal: bool) -> Result<(), Reject> {
    if kind == "Approval" && depth != 0 || kind == "Modal" && in_modal {
        return Err(Reject::Validation("composition".into()));
    }
    Ok(())
}

#[derive(Clone, Default)]
struct ReferenceSummary {
    reached: BTreeSet<String>,
    depth: usize,
    templates: usize,
    has_modal: bool,
    approval: bool,
}
#[derive(Default)]
struct References {
    memo: BTreeMap<String, ReferenceSummary>,
    visits: usize,
}
impl References {
    fn visit(
        &mut self,
        name: &str,
        definitions: &BTreeMap<&str, &Value>,
        stack: &mut BTreeSet<String>,
    ) -> Result<ReferenceSummary, Reject> {
        self.visits += 1;
        if self.visits > MAX_REFERENCE_VISITS || stack.len() >= MAX_DEPTH {
            return Err(Reject::Limit);
        }
        if let Some(summary) = self.memo.get(name) {
            return Ok(summary.clone());
        }
        if !stack.insert(name.into()) {
            return Err(Reject::Integrity);
        }
        let component = definitions.get(name).ok_or(Reject::Integrity)?;
        let component_kind = kind(component)?;
        let mut summary = ReferenceSummary {
            reached: BTreeSet::from([name.into()]),
            has_modal: component_kind == "Modal",
            approval: component_kind == "Approval",
            ..ReferenceSummary::default()
        };
        let mut children = Vec::new();
        for property in ["child", "trigger", "content"] {
            if let Some(child) = component.get(property) {
                children.push((child.as_str().ok_or(Reject::Encoding)?, false));
            }
        }
        if let Some(tabs) = component.get("tabs") {
            for tab in tabs.as_array().ok_or(Reject::Encoding)? {
                children.push((
                    tab.get("child").and_then(Value::as_str).ok_or(Reject::Encoding)?,
                    false,
                ));
            }
        }
        if let Some(list) = component.get("children") {
            if let Some(array) = list.as_array() {
                for child in array {
                    children.push((child.as_str().ok_or(Reject::Encoding)?, false));
                }
            } else {
                children.push((
                    list.get("componentId").and_then(Value::as_str).ok_or(Reject::Encoding)?,
                    true,
                ));
            }
        }
        for (child, template) in children {
            let child = self.visit(child, definitions, stack)?;
            if child.approval || component_kind == "Modal" && child.has_modal {
                return Err(Reject::Validation("composition".into()));
            }
            summary.depth = summary.depth.max(child.depth + 1);
            summary.templates = summary.templates.max(child.templates + usize::from(template));
            summary.has_modal |= child.has_modal;
            summary.reached.extend(child.reached);
        }
        if summary.depth >= MAX_DEPTH || summary.templates > MAX_TEMPLATE_SCOPES {
            return Err(Reject::Limit);
        }
        stack.remove(name);
        self.memo.insert(name.into(), summary.clone());
        Ok(summary)
    }
}

pub(super) fn validate_input(
    component: &Value,
    value: &Value,
    model: &Value,
    prefix: &str,
) -> Result<(), Reject> {
    let good = match kind(component)? {
        "TextField" => {
            value.as_str().is_some_and(|s| s.len() <= MAX_DELTA_BYTES)
                && component.get("variant").and_then(Value::as_str) != Some("obscured")
        }
        "CheckBox" => value.is_boolean(),
        "Slider" => {
            value.as_i64().is_some()
                && value.as_f64().is_some_and(|v| {
                    v >= component.get("min").and_then(Value::as_f64).unwrap_or(0.0)
                        && component.get("max").and_then(Value::as_f64).is_some_and(|max| v <= max)
                })
        }
        "ChoicePicker" => value.as_array().is_some_and(|a| {
            let options = component.get("options").and_then(Value::as_array);
            let unique: BTreeSet<_> = a.iter().filter_map(Value::as_str).collect();
            unique.len() == a.len()
                && a.len() <= options.map_or(0, Vec::len)
                && (component.get("variant").and_then(Value::as_str) == Some("multipleSelection")
                    || a.len() <= 1)
                && a.iter().all(|v| {
                    options.is_some_and(|options| {
                        options.iter().any(|option| option.get("value") == Some(v))
                    })
                })
        }),
        "DateTimeInput" => super::schema::date_time_input(component, value, model, prefix)?,
        _ => false,
    };
    if good { Ok(()) } else { Err(Reject::Validation("input type/range".into())) }
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn slider_integer_witness_uses_fractional_literal_bounds_without_rounding() {
        let slider = json!({"component":"Slider","min":0.5,"max":2.5});
        assert!(
            validate_input(&slider, &json!(1), &json!({}), "").is_ok(),
            "an integer inside basic-catalog numeric bounds is valid"
        );
        assert!(
            validate_input(&slider, &json!(0), &json!({}), "").is_err(),
            "a fractional minimum must not silently become zero"
        );
        assert!(
            validate_input(&slider, &json!(3), &json!({}), "").is_err(),
            "an integer above a fractional maximum is rejected"
        );
        assert!(
            validate_input(&slider, &json!(1.5), &json!({}), "").is_err(),
            "the profile requires the submitted Slider value to be an integer"
        );
    }

    #[test]
    fn empty_date_input_still_validates_author_bound_types_and_order() {
        let input =
            json!({"component":"DateTimeInput","enableDate":true,"min":{"@path":"/minimum"}});
        assert!(
            validate_input(&input, &json!(""), &json!({"minimum":"2026-06-22"}), "").is_ok(),
            "an unset date may have a valid author bound"
        );
        assert!(
            validate_input(&input, &json!(""), &json!({"minimum":"invalid"}), "").is_err(),
            "unset input cannot hide an invalid author bound"
        );
        let inverted = json!({"component":"DateTimeInput","enableDate":true,"min":"2026-06-23","max":"2026-06-22"});
        assert!(
            validate_input(&inverted, &json!(""), &json!({}), "").is_err(),
            "inverted limits cannot enter a signed card"
        );
    }
}
