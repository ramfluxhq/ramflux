// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Action frames and the author-literal/raw-owned-input egress grammar.
use super::wire::{canonical, decode_canonical, identifier, validate_metadata};
use super::{
    ACTION_SCHEMA, JsonPointer, MAX_CONTEXT_ENTRIES, MAX_DELTA_BYTES, MAX_STATE_BYTES, Metadata,
    Reject, SurfaceSnapshot, SurfaceState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBinding {
    pub task_id: String,
    pub step_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Action {
    pub name: String,
    pub surface_id: String,
    pub source_component_id: String,
    pub timestamp: String,
    pub context: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMessage {
    pub version: String,
    pub action: Action,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionFrame {
    pub schema: String,
    pub conversation_id: String,
    pub surface_version: u64,
    pub surface_hash: String,
    pub source_instance: Vec<String>,
    pub args_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_binding: Option<TaskBinding>,
    pub a2ui: ActionMessage,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceAction(ActionFrame);
impl SurfaceAction {
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.0.conversation_id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.0.surface_version
    }
    #[must_use]
    pub fn surface_id(&self) -> &str {
        &self.0.a2ui.action.surface_id
    }
    #[must_use]
    pub fn surface_hash(&self) -> &str {
        &self.0.surface_hash
    }
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.0.a2ui.action.name
    }
    #[must_use]
    pub fn source_component_id(&self) -> &str {
        &self.0.a2ui.action.source_component_id
    }
    #[must_use]
    pub fn source_instance(&self) -> &[String] {
        &self.0.source_instance
    }
    #[must_use]
    pub fn values(&self) -> &Map<String, Value> {
        &self.0.a2ui.action.context
    }
    #[must_use]
    pub fn args_hash(&self) -> &str {
        &self.0.args_hash
    }
    #[must_use]
    pub fn task_binding(&self) -> Option<&TaskBinding> {
        self.0.task_binding.as_ref()
    }

    /// Admit only original canonical bytes; no last-wins Value constructor exists.
    /// # Errors
    /// Refuses extra fields, invalid version/schema, identifiers and argument commitments.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, Reject> {
        let raw: Value = decode_canonical(bytes, MAX_STATE_BYTES)?;
        super::wire::reject_null_fields(&raw, &["taskBinding"])?;
        if let Some(action) = raw.pointer("/a2ui/action") {
            super::wire::reject_null_fields(action, &["userMessage", "metadata"])?;
        }
        let frame: ActionFrame = serde_json::from_value(raw).map_err(|_| Reject::Encoding)?;
        if time::OffsetDateTime::parse(
            &frame.a2ui.action.timestamp,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        {
            return Err(Reject::Encoding);
        }
        if frame.task_binding.as_ref().is_some_and(|b| {
            [&b.task_id, &b.step_id].iter().any(|id| id.is_empty() || id.len() > 256)
        }) {
            return Err(Reject::Encoding);
        }

        if frame.schema != ACTION_SCHEMA
            || frame.a2ui.version != "1.0"
            || frame.conversation_id.is_empty()
            || !(1..=crate::MAX_SAFE_JSON_INTEGER).contains(&frame.surface_version)
            || frame.source_instance.len() > 2
            || frame.a2ui.action.context.len() > MAX_CONTEXT_ENTRIES
        {
            return Err(Reject::Encoding);
        }
        for id in [
            &frame.a2ui.action.surface_id,
            &frame.a2ui.action.source_component_id,
            &frame.a2ui.action.name,
        ] {
            identifier(id)?;
        }
        for pointer in &frame.source_instance {
            JsonPointer::parse(pointer)?;
        }
        for key in frame.a2ui.action.context.keys() {
            identifier(key)?;
        }
        validate_metadata(frame.a2ui.action.metadata.as_ref())?;
        if frame.args_hash != frame.arguments_hash()? {
            return Err(Reject::Integrity);
        }
        Ok(Self(frame))
    }
    #[must_use]
    pub const fn frame(&self) -> &ActionFrame {
        &self.0
    }
}
impl ActionFrame {
    /// Pinned hash of exactly the source instance, name, context and optional userMessage.
    /// # Errors
    /// Refuses non-I-JSON values and serialization failure.
    pub fn arguments_hash(&self) -> Result<String, Reject> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Args<'a> {
            source_instance: &'a [String],
            name: &'a str,
            context: &'a Map<String, Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            user_message: &'a Option<String>,
        }
        let a = &self.a2ui.action;
        Ok(crate::hash_base64url(
            "ramflux.a2ui.action_args.v2",
            &canonical(&Args {
                source_instance: &self.source_instance,
                name: &a.name,
                context: &a.context,
                user_message: &a.user_message,
            })?,
        ))
    }
    /// Validate locally constructed action bytes before carrier signing.
    /// # Errors
    /// Refuses invalid framing or argument hash.
    pub fn wire_bytes(&self) -> Result<Vec<u8>, Reject> {
        let bytes = canonical(self)?;
        SurfaceAction::from_wire_bytes(&bytes)?;
        Ok(bytes)
    }
}
#[derive(Clone)]
struct Instance<'a> {
    component: &'a Value,
    source: Vec<String>,
    prefix: String,
    scope: String,
}
struct Graph<'a> {
    instances: Vec<Instance<'a>>,
    reached: BTreeSet<String>,
}
struct Input<'a> {
    instance: Instance<'a>,
    pointer: JsonPointer,
}
fn kind(component: &Value) -> Result<&str, Reject> {
    component.get("component").and_then(Value::as_str).ok_or(Reject::Encoding)
}
fn id(component: &Value) -> Result<&str, Reject> {
    component.get("id").and_then(Value::as_str).ok_or(Reject::Encoding)
}
fn input(kind: &str) -> bool {
    matches!(kind, "TextField" | "CheckBox" | "Slider" | "ChoicePicker" | "DateTimeInput")
}
fn resolve_pointer(path: &str, prefix: &str) -> Result<JsonPointer, Reject> {
    JsonPointer::parse(&if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{prefix}/{path}")
    })
}
fn binding(value: &Value, prefix: &str) -> Result<JsonPointer, Reject> {
    let object = value.as_object().ok_or(Reject::Expression)?;
    if object.len() != 1 {
        return Err(Reject::Expression);
    }
    resolve_pointer(object.get("@path").and_then(Value::as_str).ok_or(Reject::Expression)?, prefix)
}
fn literal(value: &Value) -> bool {
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
    fn new(snapshot: &'a SurfaceSnapshot) -> Result<Self, Reject> {
        let mut definitions = BTreeMap::new();
        for component in &snapshot.components {
            let name = id(component)?;
            identifier(name)?;
            identifier(kind(component)?)?;
            if definitions.insert(name, component).is_some() {
                return Err(Reject::Integrity);
            }
        }
        let mut graph = Self { instances: Vec::new(), reached: BTreeSet::new() };
        graph.walk(
            "root",
            &definitions,
            snapshot,
            &[],
            "",
            "Surface",
            &mut BTreeSet::new(),
            0,
            false,
        )?;
        Ok(graph)
    }
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &mut self,
        name: &str,
        definitions: &BTreeMap<&str, &'a Value>,
        snapshot: &SurfaceSnapshot,
        source: &[String],
        prefix: &str,
        scope: &str,
        stack: &mut BTreeSet<String>,
        depth: usize,
        in_modal: bool,
    ) -> Result<(), Reject> {
        if depth >= 16 || self.instances.len() >= 256 || source.len() > 2 {
            return Err(Reject::Limit);
        }
        if !stack.insert(name.to_owned()) {
            return Err(Reject::Integrity);
        }
        let component = *definitions.get(name).ok_or(Reject::Integrity)?;
        let component_kind = kind(component)?;
        if component_kind == "Approval" && depth != 0 || component_kind == "Modal" && in_modal {
            return Err(Reject::Validation("composition".into()));
        }
        let next_scope =
            if component_kind == "Card" { format!("{name}:{source:?}") } else { scope.to_owned() };
        self.instances.push(Instance {
            component,
            source: source.to_vec(),
            prefix: prefix.into(),
            scope: next_scope.clone(),
        });
        self.reached.insert(name.to_owned());
        let mut children: Vec<(String, Vec<String>, String, String)> = Vec::new();
        for property in ["child", "trigger", "content"] {
            if let Some(value) = component.get(property) {
                let child = value.as_str().ok_or(Reject::Encoding)?;
                let child_scope = if component_kind == "Modal" && property == "content" {
                    format!("{name}.content:{source:?}")
                } else {
                    next_scope.clone()
                };
                children.push((child.into(), source.to_vec(), prefix.into(), child_scope));
            }
        }
        if let Some(tabs) = component.get("tabs") {
            for tab in tabs.as_array().ok_or(Reject::Encoding)? {
                children.push((
                    tab.get("child").and_then(Value::as_str).ok_or(Reject::Encoding)?.into(),
                    source.to_vec(),
                    prefix.into(),
                    next_scope.clone(),
                ));
            }
        }
        if let Some(list) = component.get("children") {
            if let Some(array) = list.as_array() {
                for value in array {
                    children.push((
                        value.as_str().ok_or(Reject::Encoding)?.into(),
                        source.to_vec(),
                        prefix.into(),
                        next_scope.clone(),
                    ));
                }
            } else {
                let map = list.as_object().ok_or(Reject::Encoding)?;
                if map.len() != 2 {
                    return Err(Reject::Encoding);
                }
                let template =
                    map.get("componentId").and_then(Value::as_str).ok_or(Reject::Encoding)?;
                // Even an empty list must resolve its template and may not conceal a dangling reference.
                if !definitions.contains_key(template) {
                    return Err(Reject::Integrity);
                }
                self.reached.insert(template.into());
                let pointer = resolve_pointer(
                    map.get("path").and_then(Value::as_str).ok_or(Reject::Encoding)?,
                    prefix,
                )?;
                let values = pointer
                    .get(&snapshot.data_model)
                    .and_then(Value::as_array)
                    .ok_or(Reject::Expression)?;
                if values.len() > 16 || source.len() >= 2 {
                    return Err(Reject::Limit);
                }
                for index in 0..values.len() {
                    let item = format!("{}/{index}", pointer.canonical());
                    let mut source = source.to_vec();
                    source.push(item.clone());
                    children.push((template.into(), source, item, next_scope.clone()));
                }
            }
        }
        for (child, source, prefix, scope) in children {
            self.walk(
                &child,
                definitions,
                snapshot,
                &source,
                &prefix,
                &scope,
                stack,
                depth + 1,
                in_modal || component_kind == "Modal",
            )?;
        }
        stack.remove(name);
        Ok(())
    }
    fn inputs(&self, snapshot: &SurfaceSnapshot) -> Result<Vec<Input<'a>>, Reject> {
        let mut inputs: Vec<Input<'a>> = Vec::new();
        for instance in &self.instances {
            if input(kind(instance.component)?) {
                let pointer = binding(
                    instance.component.get("value").ok_or(Reject::Expression)?,
                    &instance.prefix,
                )?;
                if inputs.iter().any(|old| pointer.overlaps(&old.pointer)) {
                    return Err(Reject::Validation("input binding alias".into()));
                }
                validate_input(
                    instance.component,
                    pointer.get(&snapshot.data_model).ok_or(Reject::Expression)?,
                    &snapshot.data_model,
                    &instance.prefix,
                )?;
                inputs.push(Input { instance: instance.clone(), pointer });
            }
        }
        Ok(inputs)
    }
}

pub(super) fn validate_components(snapshot: &mut SurfaceSnapshot) -> Result<(), Reject> {
    for component in &snapshot.components {
        validate_component_shape(component)?;
    }
    let graph = Graph::new(snapshot)?;
    let inputs = graph.inputs(snapshot)?;
    for instance in &graph.instances {
        if kind(instance.component)? == "Button" {
            validate_declaration(instance, &inputs, snapshot)?;
        }
    }
    let reached = graph.reached.clone();
    snapshot.components.retain(|component| {
        component.get("id").and_then(Value::as_str).is_some_and(|id| reached.contains(id))
    });
    Ok(())
}
fn validate_declaration(
    instance: &Instance<'_>,
    inputs: &[Input<'_>],
    snapshot: &SurfaceSnapshot,
) -> Result<(), Reject> {
    let action =
        instance.component.get("action").and_then(Value::as_object).ok_or(Reject::Encoding)?;
    if action.len() != 1 {
        return Err(Reject::Encoding);
    }
    if let Some(event) = action.get("event") {
        let event = event.as_object().ok_or(Reject::Encoding)?;
        if event.keys().any(|k| !["name", "context", "userMessage"].contains(&k.as_str())) {
            return Err(Reject::Encoding);
        }
        identifier(event.get("name").and_then(Value::as_str).ok_or(Reject::Encoding)?)?;
        if event.get("userMessage").is_some_and(|v| !v.is_string()) {
            return Err(Reject::Expression);
        }
        let empty = Map::new();
        let context = event
            .get("context")
            .map(|v| v.as_object().ok_or(Reject::Encoding))
            .transpose()?
            .unwrap_or(&empty);
        if context.len() > MAX_CONTEXT_ENTRIES {
            return Err(Reject::Limit);
        }
        let mut sent = BTreeSet::new();
        for (key, value) in context {
            identifier(key)?;
            if literal(value) {
                continue;
            }
            let pointer = binding(value, &instance.prefix)?;
            if !inputs
                .iter()
                .any(|input| input.pointer == pointer && input.instance.scope == instance.scope)
                || !sent.insert(pointer.canonical())
            {
                return Err(Reject::Validation("context input scope".into()));
            }
        }
        if let Some(checks) = instance.component.get("@checks") {
            let mut reads = Vec::new();
            collect_reads(checks, &instance.prefix, &mut reads)?;
            for pointer in reads {
                for input in inputs {
                    if pointer.overlaps(&input.pointer)
                        && (pointer != input.pointer || !sent.contains(&input.pointer.canonical()))
                    {
                        return Err(Reject::Validation("check reads unsent input".into()));
                    }
                }
            }
        }
    } else if let Some(call) = action.get("functionCall") {
        if call.get("@call").and_then(Value::as_str) != Some("openUrl") {
            return Err(Reject::Expression);
        }
        let url = call.pointer("/args/url").ok_or(Reject::Expression)?;
        let url = if let Some(s) = url.as_str() {
            s
        } else {
            let pointer = binding(url, &instance.prefix)?;
            if inputs.iter().any(|i| pointer.overlaps(&i.pointer)) {
                return Err(Reject::Expression);
            }
            pointer.get(&snapshot.data_model).and_then(Value::as_str).ok_or(Reject::Expression)?
        };
        super::link::validate_url(url)?;
    } else {
        return Err(Reject::Encoding);
    }
    Ok(())
}
fn collect_reads(value: &Value, prefix: &str, reads: &mut Vec<JsonPointer>) -> Result<(), Reject> {
    match value {
        Value::Object(map) => {
            if let Some(path) = map.get("@path") {
                reads.push(resolve_pointer(path.as_str().ok_or(Reject::Expression)?, prefix)?);
            }
            if map
                .get("@call")
                .and_then(Value::as_str)
                .is_some_and(super::expression::locale_sensitive)
            {
                return Err(Reject::LocaleDependentCheck);
            }
            if map.get("@call").and_then(Value::as_str) == Some("openUrl") {
                return Err(Reject::Expression);
            }
            for value in map.values() {
                collect_reads(value, prefix, reads)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                collect_reads(value, prefix, reads)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn validate_component_shape(component: &Value) -> Result<(), Reject> {
    super::schema::component(component)
}
fn validate_input(
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
        "Slider" => value.as_i64().is_some_and(|v| {
            v >= component.get("min").and_then(Value::as_i64).unwrap_or(0)
                && component.get("max").and_then(Value::as_i64).is_some_and(|max| v <= max)
        }),
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
impl SurfaceState {
    /// Author-side validation reconstructs only explicit raw context inputs before checking.
    /// # Errors
    /// Refuses stale actions, mismatched instances/literals/types/checks and forged arguments.
    pub fn validate_action(&self, action: &SurfaceAction) -> Result<(), Reject> {
        let frame = action.frame();
        if self.is_closed() {
            return Err(Reject::Closed);
        }
        let snapshot = self.content().ok_or(Reject::NotCreated)?;
        if self.version() != frame.surface_version
            || self.hash() != Some(frame.surface_hash.as_str())
            || self.conversation_id() != Some(frame.conversation_id.as_str())
            || snapshot.surface_id != frame.a2ui.action.surface_id
        {
            return Err(Reject::Conflict);
        }
        let graph = Graph::new(snapshot)?;
        let inputs = graph.inputs(snapshot)?;
        let source = graph
            .instances
            .iter()
            .find(|instance| {
                id(instance.component).ok() == Some(frame.a2ui.action.source_component_id.as_str())
                    && instance.source == frame.source_instance
            })
            .ok_or(Reject::Expression)?;
        if kind(source.component)? != "Button" {
            return Err(Reject::Expression);
        }
        let event = source.component.pointer("/action/event").ok_or(Reject::Expression)?;
        let declared_name = event.get("name").and_then(Value::as_str).ok_or(Reject::Encoding)?;
        let declared_message = event.get("userMessage").and_then(Value::as_str);
        let empty = Map::new();
        let context = event.get("context").and_then(Value::as_object).unwrap_or(&empty);
        let submitted = &frame.a2ui.action;
        if declared_name != submitted.name
            || declared_message != submitted.user_message.as_deref()
            || context.keys().ne(submitted.context.keys())
        {
            return Err(Reject::Integrity);
        }
        let mut overlay = snapshot.data_model.clone();
        let mut witness = Map::new();
        for (key, declared) in context {
            let value = submitted.context.get(key).ok_or(Reject::Integrity)?;
            if literal(declared) {
                if canonical(declared)? != canonical(value)? {
                    return Err(Reject::Integrity);
                }
            } else {
                let pointer = binding(declared, &source.prefix)?;
                let input = inputs
                    .iter()
                    .find(|i| i.pointer == pointer && i.instance.scope == source.scope)
                    .ok_or(Reject::Expression)?;
                validate_input(
                    input.instance.component,
                    value,
                    &snapshot.data_model,
                    &input.instance.prefix,
                )?;
                pointer.update(&mut overlay, value.clone())?;
                witness.insert(key.clone(), value.clone());
            }
        }
        if canonical(&witness)?.len() > MAX_DELTA_BYTES {
            return Err(Reject::Limit);
        }
        super::expression::checks(source.component.get("@checks"), &overlay, &source.prefix)?;
        if frame.arguments_hash()? != frame.args_hash {
            return Err(Reject::Integrity);
        }
        Ok(())
    }
}

impl std::fmt::Debug for SurfaceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurfaceAction")
            .field("surface_id", &self.surface_id())
            .field("version", &self.version())
            .field("context", &"[redacted]")
            .finish_non_exhaustive()
    }
}
