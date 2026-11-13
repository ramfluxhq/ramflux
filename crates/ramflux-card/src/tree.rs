// SPDX-License-Identifier: BSD-3-Clause
use crate::{CardError, CardSpec, ChartKind, Choice, HostSecuritySlot, Series, spec::preflight};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_TREE: usize = 64 * 1024;
const MAX_EXPANDED_NODES: usize = 256;
const MAX_NODE_DEPTH: usize = 16;
/// Only native form controls. Approval, HTML and navigation are absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Column,
    Form,
    TextField,
    Submit,
    Number,
    Select,
    Toggle,
    Text,
    Task,
    Progress,
    Chart,
    Table,
    ApprovalInfo,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub key: String,
    pub kind: NodeKind,
    pub text: String,
    pub value: String,
    pub action: Option<String>,
    pub children: Vec<Node>,
    #[serde(default, skip_serializing_if = "Attrs::is_empty")]
    pub attrs: Box<Attrs>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Style {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub border: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plot {
    pub kind: ChartKind,
    pub unit: String,
    pub scale: u32,
    pub series: Vec<Series>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Attrs {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<Choice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plot: Option<Plot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<Style>,
}
impl Attrs {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub root: Node,
}
/// Upsert uses a shallow node; children are attached by their own keyed operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Mutation {
    Remove { key: String },
    Upsert { parent: Option<String>, index: usize, node: Node },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationBatch {
    pub previous_version: u64,
    pub version: u64,
    pub mutations: Vec<Mutation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_slots: Vec<HostSecuritySlot>,
}

impl Tree {
    pub(crate) fn parse(bytes: &[u8], spec: &CardSpec) -> Result<Self, CardError> {
        preflight(bytes, MAX_TREE)?;
        let tree: Self = serde_json::from_slice(bytes)?;
        tree.check_limits()?;
        palette(&tree.root, &spec.presentation()?)?;
        if tree.without_style() != crate::projection::expected(spec)? {
            return Err(CardError::Invalid("component semantics"));
        }
        Ok(tree)
    }
    pub(crate) fn check_limits(&self) -> Result<(), CardError> {
        let mut keys = BTreeSet::new();
        let mut expanded = 0;
        validate_node(&self.root, 1, &mut keys, &mut expanded)
    }
    pub(crate) fn without_style(&self) -> Self {
        fn strip(node: &mut Node) {
            node.attrs.style = None;
            for child in &mut node.children {
                strip(child);
            }
        }
        let mut tree = self.clone();
        strip(&mut tree.root);
        tree
    }
    pub(crate) fn diff(
        &self,
        old: Option<&Self>,
        previous_version: u64,
        version: u64,
    ) -> MutationBatch {
        let before = old.map_or_else(Vec::new, |tree| flatten(&tree.root));
        let after = flatten(&self.root);
        let before_map: BTreeMap<_, _> = before.iter().map(|m| (&m.node.key, m)).collect();
        let after_keys: BTreeSet<_> = after.iter().map(|m| &m.node.key).collect();
        let mut mutations = Vec::new();
        for entry in before.iter().rev() {
            if !after_keys.contains(&entry.node.key) {
                mutations.push(Mutation::Remove { key: entry.node.key.clone() });
            }
        }
        let mut reparented = BTreeSet::new();
        for entry in after {
            let old = before_map.get(&entry.node.key);
            let must_rebuild = old
                .is_some_and(|old| old.parent != entry.parent || old.node.kind != entry.node.kind)
                || entry.parent.as_ref().is_some_and(|parent| reparented.contains(parent));
            if must_rebuild {
                reparented.insert(entry.node.key.clone());
            }
            if must_rebuild || old.is_none_or(|old| **old != entry) {
                mutations.push(Mutation::Upsert {
                    parent: entry.parent,
                    index: entry.index,
                    node: entry.node,
                });
            }
        }
        MutationBatch { previous_version, version, mutations, host_slots: Vec::new() }
    }
}
fn validate_node(
    node: &Node,
    depth: usize,
    keys: &mut BTreeSet<String>,
    expanded: &mut usize,
) -> Result<(), CardError> {
    *expanded = expanded.saturating_add(
        1 + node.attrs.options.len()
            + node.attrs.rows.iter().map(|r| 1 + r.len()).sum::<usize>()
            + node
                .attrs
                .plot
                .as_ref()
                .map_or(0, |p| p.series.iter().map(|s| s.points.len()).sum::<usize>()),
    );
    if depth > MAX_NODE_DEPTH || *expanded > MAX_EXPANDED_NODES {
        return Err(CardError::Limit("expanded nodes or depth"));
    }
    if node.key.len() > 160
        || node.text.len() > 1024
        || node.value.len() > 4096
        || !keys.insert(node.key.clone())
    {
        return Err(CardError::Invalid("tree key or text"));
    }
    if let Some(style) = &node.attrs.style {
        for color in [&style.color, &style.background, &style.border].into_iter().flatten() {
            if !(color.len() == 7 || color.len() == 9)
                || !color.starts_with('#')
                || !color.bytes().skip(1).all(|v| v.is_ascii_hexdigit())
            {
                return Err(CardError::Invalid("semantic color"));
            }
        }
        if style.gap.is_some_and(|v| v > 64) || style.padding.is_some_and(|v| v > 64) {
            return Err(CardError::Invalid("semantic geometry"));
        }
    }
    for child in &node.children {
        validate_node(child, depth + 1, keys, expanded)?;
    }
    Ok(())
}
#[derive(PartialEq, Eq)]
struct FlatNode {
    parent: Option<String>,
    index: usize,
    node: Node,
}
fn flatten(root: &Node) -> Vec<FlatNode> {
    fn visit(node: &Node, parent: Option<String>, index: usize, out: &mut Vec<FlatNode>) {
        let mut shallow = node.clone();
        shallow.children.clear();
        out.push(FlatNode { parent, index, node: shallow });
        for (index, child) in node.children.iter().enumerate() {
            visit(child, Some(node.key.clone()), index, out);
        }
    }
    let mut out = Vec::new();
    visit(root, None, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_trees_and_bounds_expansion() {
        let spec =
            CardSpec::parse(include_bytes!("../fixtures/form.json")).expect("test: valid card");
        let fixture = include_str!("../fixtures/form.tree.json");
        assert!(
            Tree::parse(fixture.replace("text_field", "approval").as_bytes(), &spec).is_err(),
            "unknown/security controls must be rejected"
        );
        assert!(
            Tree::parse(fixture.replace("profile:submit", "profile:field").as_bytes(), &spec)
                .is_err(),
            "duplicate keys must be rejected"
        );
        assert!(
            Tree::parse(fixture.replace("Ada", "Eve").as_bytes(), &spec).is_err(),
            "renderer cannot change bound field values"
        );
        let mut tree: Tree = serde_json::from_str(fixture).expect("test: typed fixture");
        let child = tree.root.children.first().expect("test: first form").clone();
        tree.root.children = (0..MAX_EXPANDED_NODES)
            .map(|index| {
                let mut n = child.clone();
                n.key = format!("form-{index}");
                n.children.clear();
                n
            })
            .collect();
        assert!(
            matches!(tree.check_limits(), Err(CardError::Limit("expanded nodes or depth"))),
            "257 nodes must fail the expansion bound"
        );
        tree.root.children.pop();
        tree.check_limits().expect("test: exactly 256 nodes accepted");
        let mut bytes = fixture.as_bytes().to_vec();
        bytes.resize(MAX_TREE, b' ');
        Tree::parse(&bytes, &spec).expect("test: exactly 64 KiB accepted");
        bytes.push(b' ');
        assert!(matches!(Tree::parse(&bytes, &spec), Err(CardError::Limit("JSON bytes"))));
    }
    #[test]
    fn keyed_diff_orders_removals_and_skips_unchanged_nodes() {
        let tree: Tree = serde_json::from_str(include_str!("../fixtures/form.tree.json"))
            .expect("test: tree fixture");
        let mut changed = tree.clone();
        changed.root.children.clear();
        let batch = changed.diff(Some(&tree), 1, 2);
        let keys: Vec<_> = batch
            .mutations
            .iter()
            .filter_map(|m| match m {
                Mutation::Remove { key } => Some(key.as_str()),
                Mutation::Upsert { .. } => None,
            })
            .collect();
        assert_eq!(
            keys,
            ["profile:submit", "profile:field", "profile"],
            "children must be removed before their parent"
        );
        assert!(
            tree.diff(Some(&tree), 1, 2).mutations.is_empty(),
            "unchanged keyed tree needs only a version advance"
        );
    }
}

#[cfg(test)]
mod depth_and_move_tests {
    use super::*;
    #[test]
    fn eight_node_levels_hit_the_explicit_json_nesting_budget() {
        const LEVELS: usize = 8;
        let mut node = Node {
            key: "leaf".into(),
            kind: NodeKind::Column,
            text: String::new(),
            value: String::new(),
            action: None,
            children: Vec::new(),
            attrs: Box::default(),
        };
        for level in 1..LEVELS {
            node = Node {
                key: format!("node-{level}"),
                kind: NodeKind::Column,
                text: String::new(),
                value: String::new(),
                action: None,
                children: vec![node],
                attrs: Box::default(),
            };
        }
        let bytes = serde_json::to_vec(&Tree { root: node }).expect("test: bounded deep tree");
        let spec =
            CardSpec::parse(include_bytes!("../fixtures/form.json")).expect("test: card fixture");
        assert!(
            matches!(Tree::parse(&bytes, &spec), Err(CardError::Limit("JSON depth"))),
            "JSON object/children nesting is distinct from the semantic node-depth cap"
        );
    }
    #[test]
    fn reparent_after_ancestor_removal_reemits_the_retained_subtree() {
        let original: Tree = serde_json::from_str(include_str!("../fixtures/form.tree.json"))
            .expect("test: tree fixture");
        let mut old = original.clone();
        let mut wrapper = original.root.clone();
        wrapper.key = "wrapper".into();
        old.root.children = vec![wrapper];
        let batch = original.diff(Some(&old), 1, 2);
        assert!(
            matches!(batch.mutations.first(),Some(Mutation::Remove {key}) if key=="wrapper"),
            "old ancestor must be removed first"
        );
        let upserts: Vec<_> = batch
            .mutations
            .iter()
            .filter_map(|m| {
                if let Mutation::Upsert { node, .. } = m { Some(node.key.as_str()) } else { None }
            })
            .collect();
        assert_eq!(
            upserts,
            ["profile", "profile:field", "profile:submit"],
            "reparenting must recreate unchanged descendants destroyed with their ancestor"
        );
    }
}

fn palette(node: &Node, presentation: &crate::Presentation) -> Result<(), CardError> {
    if let Some(style) = &node.attrs.style {
        for value in [&style.color, &style.background, &style.border].into_iter().flatten() {
            if !presentation.owns_color(value) {
                return Err(CardError::Invalid("color outside host tokens"));
            }
        }
        for value in [style.gap, style.padding].into_iter().flatten() {
            if !presentation.tokens.values().any(|token| token.as_u64() == Some(u64::from(value))) {
                return Err(CardError::Invalid("geometry outside host tokens"));
            }
        }
    }
    for child in &node.children {
        palette(child, presentation)?;
    }
    Ok(())
}
