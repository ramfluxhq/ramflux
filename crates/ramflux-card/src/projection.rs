// SPDX-License-Identifier: BSD-3-Clause
//! Resolver-to-native projection. The signed library cannot change these semantics.
use crate::{CardError, CardSpec, EventToken, HostSlot, Node, NodeKind, Tree, slots::SlotRequest};
use ramflux_protocol::a2ui::{ResolvedSlot, ResolvedSurface};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Default)]
pub(crate) struct LocalState {
    pub tabs: BTreeMap<String, usize>,
    pub modals: BTreeSet<String>,
    pub consumed: BTreeSet<String>,
    pub link: Option<(String, String)>,
}
impl LocalState {
    pub(crate) fn cancel_link(&mut self) {
        if let Some((key, _)) = self.link.take() {
            self.consumed.remove(&key);
        }
    }
}
pub(crate) fn expected(spec: &CardSpec) -> Result<Tree, CardError> {
    project(spec, 1, 1, 0, &LocalState::default())
}
pub(crate) fn project(
    spec: &CardSpec,
    session: u64,
    version: u64,
    edit_seq: u64,
    local: &LocalState,
) -> Result<Tree, CardError> {
    let resolved = spec.resolved()?;
    let keys = keys(&resolved)?;
    let mounted = mounted(&resolved, &keys, local)?;
    let mut nodes = Vec::new();
    let mut host_slots = Vec::new();
    for (index, source) in resolved.nodes.iter().enumerate() {
        let key = keys.get(index).ok_or(CardError::Invalid("instance key"))?.clone();
        let mut attrs = source.properties.clone();
        for field in [
            "id",
            "component",
            "children",
            "child",
            "action",
            "@checks",
            "@catalogId",
            "@metadata",
            "trigger",
            "content",
        ] {
            attrs.remove(field);
        }
        if let Some(tabs) = attrs.get_mut("tabs").and_then(Value::as_array_mut) {
            for tab in tabs {
                tab.as_object_mut().ok_or(CardError::Invalid("tab"))?.remove("child");
            }
        }
        let accessibility = attrs.remove("@accessibility").unwrap_or_else(|| json!({"live":"off"}));
        attrs.insert("accessibility".into(), accessibility);
        let is_mounted = *mounted.get(index).ok_or(CardError::Invalid("mounted instance"))?;
        let action = resolved.actions.iter().find(|action| action.node == index);
        let disabled = !is_mounted
            || local.consumed.contains(&key)
            || action.is_some_and(|action| {
                matches!(
                    action.kind,
                    ramflux_protocol::a2ui::ResolvedActionKind::Event { checks_pass: false, .. }
                )
            });
        attrs.insert("disabled".into(), json!(disabled));
        attrs.insert("errors".into(), json!(source.errors));
        if let Some(input) = resolved.inputs.iter().find(|input| input.node == index) {
            attrs.insert("input_pointer".into(), json!(input.pointer));
        }
        if action.is_some() {
            attrs.insert("action_ref".into(), json!(key));
        }
        let kind: NodeKind = serde_json::from_value(json!(source.component))?;
        let token = EventToken {
            session,
            signed_version: spec.signed_version,
            edit_seq,
            tree_version: version,
            key: key.clone(),
        };
        if is_mounted {
            slot(source, &keys, &key, &token, local, &mut host_slots)?;
        }
        nodes.push(Node {
            key,
            component_id: source.id.clone(),
            source_instance: source.source_instance.clone(),
            scope: source.scope.clone(),
            parent_key: source
                .parent
                .map(|parent| keys.get(parent).cloned().ok_or(CardError::Invalid("parent")))
                .transpose()?,
            slot: source.slot,
            children: source
                .children
                .iter()
                .map(|child| keys.get(*child).cloned().ok_or(CardError::Invalid("child")))
                .collect::<Result<_, _>>()?,
            kind,
            attrs,
        });
    }
    let tree = Tree {
        schema: "ramflux.card.tree.v1".into(),
        session,
        signed_version: spec.signed_version,
        signed_hash: spec.signed_hash.clone(),
        edit_seq,
        tree_version: version,
        root_key: keys.first().cloned().ok_or(CardError::Invalid("root"))?,
        nodes,
        host_slots,
    };
    tree.check_limits()?;
    Ok(tree)
}
pub(crate) fn keys(resolved: &ResolvedSurface) -> Result<Vec<String>, CardError> {
    let mut routes: Vec<Vec<ResolvedSlot>> = Vec::new();
    let mut keys = Vec::new();
    for node in &resolved.nodes {
        let mut route = node
            .parent
            .map(|parent| routes.get(parent).cloned().ok_or(CardError::Invalid("route")))
            .transpose()?
            .unwrap_or_default();
        route.push(node.slot);
        // Use the protocol canonicalizer even if dependency feature unification
        // enables insertion-ordered serde maps in a downstream SDK build.
        keys.push(
            ramflux_protocol::canonical_json_string(&json!([node.id, node.source_instance, route]))
                .map_err(|_| CardError::Invalid("canonical instance key"))?,
        );
        routes.push(route);
    }
    Ok(keys)
}
fn mounted(
    resolved: &ResolvedSurface,
    keys: &[String],
    local: &LocalState,
) -> Result<Vec<bool>, CardError> {
    let mut mounted = Vec::new();
    for node in &resolved.nodes {
        let visible = match node.parent {
            None => true,
            Some(parent) => {
                let ancestor = resolved.nodes.get(parent).ok_or(CardError::Invalid("parent"))?;
                let key = keys.get(parent).ok_or(CardError::Invalid("parent key"))?;
                *mounted.get(parent).ok_or(CardError::Invalid("preorder"))?
                    && match node.slot {
                        ResolvedSlot::Tab(index) => {
                            local.tabs.get(key).copied().unwrap_or(0) == index
                        }
                        ResolvedSlot::Trigger => false,
                        ResolvedSlot::Content if ancestor.component == "Modal" => {
                            local.modals.contains(key)
                        }
                        _ => true,
                    }
            }
        };
        mounted.push(visible);
    }
    Ok(mounted)
}
fn slot(
    source: &ramflux_protocol::a2ui::ResolvedNode,
    keys: &[String],
    key: &str,
    token: &EventToken,
    local: &LocalState,
    slots: &mut Vec<HostSlot>,
) -> Result<(), CardError> {
    let p = &source.properties;
    let text = |field: &str| {
        p.get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(CardError::Invalid("slot property"))
    };
    let request_id = serde_json::to_string(token)?;
    let request = match source.component.as_str() {
        "Approval" => Some((
            "approval",
            SlotRequest::Approval {
                request_id,
                request_ref: text("requestRef")?,
                task_binding: p
                    .get("taskBinding")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()?,
            },
        )),
        "Image" => Some((
            "image",
            SlotRequest::Image {
                request_id,
                attachment: p.get("attachment").cloned().ok_or(CardError::Invalid("attachment"))?,
                description: text("description")?,
                fit: p.get("fit").and_then(Value::as_str).unwrap_or("fill").into(),
                variant: p.get("variant").and_then(Value::as_str).unwrap_or("mediumFeature").into(),
            },
        )),
        "Modal" => {
            let trigger = source
                .children
                .first()
                .and_then(|index| keys.get(*index))
                .cloned()
                .ok_or(CardError::Invalid("modal trigger"))?;
            let content = source
                .children
                .get(1)
                .and_then(|index| keys.get(*index))
                .cloned()
                .ok_or(CardError::Invalid("modal content"))?;
            Some(("modal", SlotRequest::Modal { trigger_key: trigger, content_key: content }))
        }
        "Button" => {
            local.link.as_ref().filter(|(link_key, _)| link_key == key).map(|(_, url)| {
                ("link_open", SlotRequest::LinkOpen { request_id, url: url.clone() })
            })
        }
        _ => None,
    };
    if let Some((kind, request)) = request {
        slots.push(HostSlot {
            id: ramflux_protocol::canonical_json_string(&json!([kind, key]))
                .map_err(|_| CardError::Invalid("canonical slot id"))?,
            key: key.into(),
            token: token.clone(),
            request,
        });
    }
    Ok(())
}
