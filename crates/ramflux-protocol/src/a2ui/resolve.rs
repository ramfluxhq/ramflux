// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one public card resolver shared by author-side validation, card runtimes and terminals.
//!
//! Input is an authorized snapshot (what `surface.get` returns). Output is the resolved
//! instance tree (components reachable from `root`, references resolved, templates expanded
//! within their bounds, unreachable definitions pruned, bindings evaluated against the data
//! model plus local drafts), the inputs the card owns and the actions it allows. Admission
//! (`SurfaceState::apply`) and `SurfaceState::validate_action` run the same graph, input and
//! declaration code, so an author and a host cannot disagree about a card.
use super::graph::{Graph, Input, binding, id, kind, literal, resolve_pointer, validate_input};
use super::wire::{canonical, validate_identifier};
use super::{
    ACTION_SCHEMA, Action, ActionFrame, ActionMessage, JsonPointer, MAX_CONTEXT_ENTRIES,
    MAX_MODEL_BYTES, Reject, SurfaceSnapshot, SurfaceState,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Bound on the evaluated properties of all resolved nodes together.
const MAX_RESOLVED_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 16;

/// Local, unsent input values keyed by the canonical model pointer of an owned input.
pub type SurfaceDrafts = BTreeMap<String, Value>;

/// Where a node sits under its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "slot", content = "position")]
pub enum ResolvedSlot {
    Root,
    Child,
    Trigger,
    Content,
    /// The `tabs[position].child` of a Tabs component.
    Tab(usize),
    /// The `children[position]` entry of a static child list.
    Children(usize),
    /// Template item `position` of a `children: {componentId, path}` list.
    Item(usize),
}

/// One expanded component instance; `nodes[0]` is `root` and nodes are in pre-order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedNode {
    pub id: String,
    pub component: String,
    pub parent: Option<usize>,
    pub slot: ResolvedSlot,
    pub children: Vec<usize>,
    /// Outer-to-inner template item pointers; the action frame's `sourceInstance`.
    pub source_instance: Vec<String>,
    /// Form scope: actions may carry only inputs of the same scope.
    pub scope: String,
    /// Declared properties with `@path` replaced by its value (absent = null) and
    /// locale-independent `@call`s replaced by their result. Locale-sensitive calls
    /// (`formatNumber`, `formatCurrency`, `formatDate`, `pluralize`) stay `{"@call",…}`
    /// with resolved arguments for the host's locale formatter. `action` and `@checks`
    /// stay declarations; see [`ResolvedSurface::actions`].
    pub properties: Map<String, Value>,
}

/// An input the card owns: its model pointer is unique and overlaps no other input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedInput {
    pub node: usize,
    pub component_id: String,
    pub component: String,
    pub source_instance: Vec<String>,
    pub scope: String,
    pub pointer: String,
    /// The draft value if one was supplied, otherwise the signed model value.
    pub value: Value,
}

/// Where one action context entry comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum ResolvedContextSource {
    /// An author literal, sent exactly as declared.
    Literal { value: Value },
    /// The raw value of an owned input in the same form scope.
    Input { pointer: String },
}

/// What an allowed action does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ResolvedActionKind {
    /// A signed action event returned to the author.
    Event {
        name: String,
        user_message: Option<String>,
        context: BTreeMap<String, ResolvedContextSource>,
        /// Whether the Button's `@checks` pass on the current model and drafts.
        checks_pass: bool,
    },
    /// A host-confirmed https link request; never sent to the author.
    OpenUrl { url: String },
}

/// An action the card allows, bound to one Button instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedAction {
    pub node: usize,
    pub component_id: String,
    pub source_instance: Vec<String>,
    pub scope: String,
    #[serde(flatten)]
    pub kind: ResolvedActionKind,
}

/// The resolver output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedSurface {
    pub surface_id: String,
    pub nodes: Vec<ResolvedNode>,
    pub inputs: Vec<ResolvedInput>,
    pub actions: Vec<ResolvedAction>,
    /// Definitions not reachable from `root` (admitted state never has any).
    pub pruned: Vec<String>,
}

/// The shared core: graph, owned inputs and declared actions of one snapshot.
pub(super) struct Resolution<'a> {
    pub(super) graph: Graph<'a>,
    pub(super) inputs: Vec<Input<'a>>,
    /// `(instance index, declaration)` for every Button instance.
    pub(super) actions: Vec<(usize, ResolvedActionKind)>,
}

impl<'a> Resolution<'a> {
    pub(super) fn new(snapshot: &'a SurfaceSnapshot) -> Result<Self, Reject> {
        for component in &snapshot.components {
            super::schema::component(component)?;
        }
        let graph = Graph::new(snapshot)?;
        let inputs = graph.inputs(snapshot)?;
        let mut actions = Vec::new();
        for (index, instance) in graph.instances.iter().enumerate() {
            if kind(instance.component)? == "Button" {
                let declared = declaration(instance, &inputs, snapshot)?;
                actions.push((index, declared));
            }
        }
        Ok(Self { graph, inputs, actions })
    }

    /// The declared action of the Button instance `(component_id, source_instance)`.
    pub(super) fn action(
        &self,
        component_id: &str,
        source_instance: &[String],
    ) -> Result<(&super::graph::Instance<'a>, &ResolvedActionKind), Reject> {
        let (index, instance) = self
            .graph
            .instances
            .iter()
            .enumerate()
            .find(|(_, instance)| {
                id(instance.component).ok() == Some(component_id)
                    && instance.source == source_instance
            })
            .ok_or(Reject::Expression)?;
        let (_, declared) =
            self.actions.iter().find(|(at, _)| *at == index).ok_or(Reject::Expression)?;
        Ok((instance, declared))
    }

    /// The owned input bound to `pointer` within form `scope`.
    pub(super) fn input(&self, pointer: &str, scope: &str) -> Option<&Input<'a>> {
        self.inputs
            .iter()
            .find(|input| input.pointer.canonical() == pointer && input.instance.scope == scope)
    }
}

fn declaration(
    instance: &super::graph::Instance<'_>,
    inputs: &[Input<'_>],
    snapshot: &SurfaceSnapshot,
) -> Result<ResolvedActionKind, Reject> {
    let action =
        instance.component.get("action").and_then(Value::as_object).ok_or(Reject::Encoding)?;
    if action.len() != 1 {
        return Err(Reject::Encoding);
    }
    if let Some(event) = action.get("event") {
        return event_declaration(instance, event, inputs, snapshot);
    }
    let call = action.get("functionCall").ok_or(Reject::Encoding)?;
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
    Ok(ResolvedActionKind::OpenUrl { url: url.to_owned() })
}

fn event_declaration(
    instance: &super::graph::Instance<'_>,
    event: &Value,
    inputs: &[Input<'_>],
    snapshot: &SurfaceSnapshot,
) -> Result<ResolvedActionKind, Reject> {
    let event = event.as_object().ok_or(Reject::Encoding)?;
    if event.keys().any(|k| !["name", "context", "userMessage"].contains(&k.as_str())) {
        return Err(Reject::Encoding);
    }
    let name = event.get("name").and_then(Value::as_str).ok_or(Reject::Encoding)?;
    validate_identifier(name)?;
    if event.get("userMessage").is_some_and(|v| !v.is_string()) {
        return Err(Reject::Expression);
    }
    let empty = Map::new();
    let declared = event
        .get("context")
        .map(|v| v.as_object().ok_or(Reject::Encoding))
        .transpose()?
        .unwrap_or(&empty);
    if declared.len() > MAX_CONTEXT_ENTRIES {
        return Err(Reject::Limit);
    }
    let mut context = BTreeMap::new();
    let mut sent = BTreeSet::new();
    for (key, value) in declared {
        validate_identifier(key)?;
        if literal(value) {
            context.insert(key.clone(), ResolvedContextSource::Literal { value: value.clone() });
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
        context.insert(key.clone(), ResolvedContextSource::Input { pointer: pointer.canonical() });
    }
    if let Some(checks) = instance.component.get("@checks") {
        let mut reads = Vec::new();
        let owned: Vec<_> = inputs.iter().map(|input| input.pointer.clone()).collect();
        let check_context =
            CheckContext { prefix: &instance.prefix, model: &snapshot.data_model, owned: &owned };
        collect_reads(checks, &check_context, &mut reads, 0)?;
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
    Ok(ResolvedActionKind::Event {
        name: name.to_owned(),
        user_message: event.get("userMessage").and_then(Value::as_str).map(str::to_owned),
        context,
        // Filled by the resolver against the model and drafts it resolves.
        checks_pass: false,
    })
}

struct CheckContext<'a> {
    prefix: &'a str,
    model: &'a Value,
    owned: &'a [JsonPointer],
}
fn collect_reads(
    value: &Value,
    context: &CheckContext<'_>,
    reads: &mut Vec<JsonPointer>,
    depth: usize,
) -> Result<(), Reject> {
    if depth > MAX_DEPTH {
        return Err(Reject::Limit);
    }
    match value {
        Value::Object(map) => {
            if let Some(path) = map.get("@path") {
                reads.push(resolve_pointer(
                    path.as_str().ok_or(Reject::Expression)?,
                    context.prefix,
                )?);
            }
            if let Some(name) = map.get("@call").and_then(Value::as_str) {
                if super::expression::locale_sensitive(name) {
                    return Err(Reject::LocaleDependentCheck);
                }
                if name == "openUrl" || name == "@index" && context.prefix.is_empty() {
                    return Err(Reject::Expression);
                }
                if name == "formatString" {
                    return collect_program_reads(value, context, reads, depth);
                }
            }
            for value in map.values() {
                collect_reads(value, context, reads, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                collect_reads(value, context, reads, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn collect_program_reads(
    value: &Value,
    context: &CheckContext<'_>,
    reads: &mut Vec<JsonPointer>,
    depth: usize,
) -> Result<(), Reject> {
    let source = value.pointer("/args/value").ok_or(Reject::Expression)?;
    let mut source_reads = Vec::new();
    collect_reads(source, context, &mut source_reads, depth + 1)?;
    if source_reads.iter().any(|read| context.owned.iter().any(|owner| read.overlaps(owner))) {
        // A draft cannot supply a new check program that reads arbitrary hidden inputs.
        return Err(Reject::Validation("input-controlled check program".into()));
    }
    let program = super::expression::evaluate(source, context.model, context.prefix, depth + 1)?;
    for expression in
        super::format_string::expressions(program.as_str().ok_or(Reject::Expression)?)?
    {
        collect_reads(&expression, context, reads, depth + 1)?;
    }
    reads.extend(source_reads);
    Ok(())
}

impl SurfaceSnapshot {
    /// Resolve this snapshot with no local drafts.
    /// # Errors
    /// See [`SurfaceSnapshot::resolve_with_drafts`].
    pub fn resolve(&self) -> Result<ResolvedSurface, Reject> {
        self.resolve_with_drafts(&SurfaceDrafts::new())
    }

    /// Resolve this snapshot; `drafts` overlay owned inputs for display, checks and actions.
    /// # Errors
    /// The same typed refusals as admission (`Integrity` for dangling, duplicate or cyclic
    /// references; `Limit` for more than 16 template items, 2 nested template scopes, 256
    /// instances, depth 16 or 64 KiB expanded; `Validation`/`Expression`/`Encoding` for
    /// shapes, bindings and declarations), plus `Validation` for a draft that targets no
    /// owned input or fails its input type/range, `Expression` for a display function that
    /// cannot be evaluated, and `Limit` for over 64 KiB of resolved properties.
    pub fn resolve_with_drafts(&self, drafts: &SurfaceDrafts) -> Result<ResolvedSurface, Reject> {
        validate_identifier(&self.surface_id)?;
        let resolution = Resolution::new(self)?;
        let model = overlay(self, &resolution.inputs, drafts)?;
        let mut nodes = Vec::with_capacity(resolution.graph.instances.len());
        let mut resolved_bytes = 0usize;
        for instance in &resolution.graph.instances {
            let properties = properties(instance.component, &model, &instance.prefix)?;
            resolved_bytes =
                resolved_bytes.checked_add(canonical(&properties)?.len()).ok_or(Reject::Limit)?;
            if resolved_bytes > MAX_RESOLVED_BYTES {
                return Err(Reject::Limit);
            }
            nodes.push(ResolvedNode {
                id: id(instance.component)?.to_owned(),
                component: kind(instance.component)?.to_owned(),
                parent: instance.parent,
                slot: instance.slot,
                children: Vec::new(),
                source_instance: instance.source.clone(),
                scope: instance.scope.clone(),
                properties,
            });
        }
        for index in 0..nodes.len() {
            if let Some(parent) = nodes.get(index).and_then(|node| node.parent)
                && let Some(parent) = nodes.get_mut(parent)
            {
                parent.children.push(index);
            }
        }
        let inputs = resolution
            .inputs
            .iter()
            .map(|input| owned_input(input, &model))
            .collect::<Result<Vec<_>, _>>()?;
        let actions = allowed_actions(&resolution, &model)?;
        let pruned = self
            .components
            .iter()
            .filter_map(|component| component.get("id").and_then(Value::as_str))
            .filter(|name| !resolution.graph.reached.contains(*name))
            .map(str::to_owned)
            .collect();
        Ok(ResolvedSurface { surface_id: self.surface_id.clone(), nodes, inputs, actions, pruned })
    }
}

fn overlay(
    snapshot: &SurfaceSnapshot,
    inputs: &[Input<'_>],
    drafts: &SurfaceDrafts,
) -> Result<Value, Reject> {
    let mut model = snapshot.data_model.clone();
    for (path, value) in drafts {
        let pointer = JsonPointer::parse(path)?;
        let input = inputs
            .iter()
            .find(|input| input.pointer == pointer)
            .ok_or_else(|| Reject::Validation("draft targets no owned input".into()))?;
        validate_input(
            input.instance.component,
            value,
            &snapshot.data_model,
            &input.instance.prefix,
        )?;
        pointer.update(&mut model, value.clone())?;
    }
    if canonical(&model)?.len() > MAX_MODEL_BYTES {
        return Err(Reject::Limit);
    }
    Ok(model)
}

fn properties(
    component: &Value,
    model: &Value,
    prefix: &str,
) -> Result<Map<String, Value>, Reject> {
    let mut out = Map::new();
    for (key, value) in component.as_object().ok_or(Reject::Encoding)? {
        match key.as_str() {
            "id" | "component" => {}
            "action" | "@checks" => {
                out.insert(key.clone(), value.clone());
            }
            _ => {
                out.insert(key.clone(), display(value, model, prefix, 0)?);
            }
        }
    }
    Ok(out)
}

fn display(value: &Value, model: &Value, prefix: &str, depth: usize) -> Result<Value, Reject> {
    if depth > MAX_DEPTH {
        return Err(Reject::Limit);
    }
    match value {
        Value::Object(map) => {
            if let Some(path) = map.get("@path") {
                let pointer = resolve_pointer(path.as_str().ok_or(Reject::Expression)?, prefix)?;
                return Ok(pointer.get(model).cloned().unwrap_or(Value::Null));
            }
            if let Some(name) = map.get("@call").and_then(Value::as_str) {
                if !super::expression::locale_sensitive(name) {
                    return super::expression::evaluate(value, model, prefix, depth);
                }
                // Locale formatting belongs to the host; hand it resolved arguments.
                let mut call = map.clone();
                if let Some(args) = map.get("args") {
                    call.insert("args".into(), display(args, model, prefix, depth + 1)?);
                }
                return Ok(Value::Object(call));
            }
            let mut out = Map::new();
            for (key, value) in map {
                out.insert(key.clone(), display(value, model, prefix, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(values) => values
            .iter()
            .map(|value| display(value, model, prefix, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Ok(value.clone()),
    }
}

fn owned_input(input: &Input<'_>, model: &Value) -> Result<ResolvedInput, Reject> {
    Ok(ResolvedInput {
        node: input.index,
        component_id: id(input.instance.component)?.to_owned(),
        component: kind(input.instance.component)?.to_owned(),
        source_instance: input.instance.source.clone(),
        scope: input.instance.scope.clone(),
        pointer: input.pointer.canonical(),
        value: input.pointer.get(model).cloned().ok_or(Reject::Expression)?,
    })
}

fn allowed_actions(
    resolution: &Resolution<'_>,
    model: &Value,
) -> Result<Vec<ResolvedAction>, Reject> {
    let mut actions = Vec::with_capacity(resolution.actions.len());
    for (index, declared) in &resolution.actions {
        let instance = resolution.graph.instances.get(*index).ok_or(Reject::Integrity)?;
        let mut kind_out = declared.clone();
        if let ResolvedActionKind::Event { checks_pass, .. } = &mut kind_out {
            *checks_pass = super::expression::checks(
                instance.component.get("@checks"),
                model,
                &instance.prefix,
            )
            .is_ok();
        }
        actions.push(ResolvedAction {
            node: *index,
            component_id: id(instance.component)?.to_owned(),
            source_instance: instance.source.clone(),
            scope: instance.scope.clone(),
            kind: kind_out,
        });
    }
    Ok(actions)
}

impl ResolvedSurface {
    /// The allowed action of the Button instance `(component_id, source_instance)`.
    #[must_use]
    pub fn action(
        &self,
        component_id: &str,
        source_instance: &[String],
    ) -> Option<&ResolvedAction> {
        self.actions.iter().find(|action| {
            action.component_id == component_id && action.source_instance == source_instance
        })
    }

    /// Build the action frame for one allowed event from author literals and the current
    /// (draft or signed) values of owned inputs, bound to the shown version and hash of
    /// `state`. Sign its `wire_bytes()`; `SurfaceState::validate_action` accepts exactly
    /// what this builds when the drafts pass their checks.
    /// # Errors
    /// `Expression` for an `openUrl` action or a missing input, `Conflict` when `state`
    /// does not hold this surface, and argument-hash serialization failures.
    pub fn action_frame(
        &self,
        state: &SurfaceState,
        action: &ResolvedAction,
        timestamp: &str,
    ) -> Result<ActionFrame, Reject> {
        let ResolvedActionKind::Event { name, user_message, context, .. } = &action.kind else {
            return Err(Reject::Expression);
        };
        if state.content().map(|snapshot| snapshot.surface_id.as_str())
            != Some(self.surface_id.as_str())
        {
            return Err(Reject::Conflict);
        }
        let mut values = Map::new();
        for (key, source) in context {
            let value = match source {
                ResolvedContextSource::Literal { value } => value.clone(),
                ResolvedContextSource::Input { pointer } => self
                    .inputs
                    .iter()
                    .find(|input| &input.pointer == pointer)
                    .map(|input| input.value.clone())
                    .ok_or(Reject::Expression)?,
            };
            values.insert(key.clone(), value);
        }
        let mut frame = ActionFrame {
            schema: ACTION_SCHEMA.into(),
            conversation_id: state.conversation_id().ok_or(Reject::NotCreated)?.to_owned(),
            surface_version: state.version(),
            surface_hash: state.hash().ok_or(Reject::NotCreated)?.to_owned(),
            source_instance: action.source_instance.clone(),
            args_hash: String::new(),
            task_binding: None,
            a2ui: ActionMessage {
                version: "1.0".into(),
                action: Action {
                    name: name.clone(),
                    surface_id: self.surface_id.clone(),
                    source_component_id: action.component_id.clone(),
                    timestamp: timestamp.to_owned(),
                    context: values,
                    user_message: user_message.clone(),
                    metadata: None,
                },
            },
        };
        frame.args_hash = frame.arguments_hash()?;
        Ok(frame)
    }
}
