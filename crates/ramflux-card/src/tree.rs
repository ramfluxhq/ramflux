// SPDX-License-Identifier: BSD-3-Clause
use crate::{CardError, CardSpec, spec::preflight};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_TREE: usize = 64 * 1024;
const MAX_EXPANDED_NODES: usize = 256;
/// Only native form controls. Approval, HTML and navigation are absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Column,
    Form,
    TextField,
    Submit,
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
}

impl Tree {
    pub(crate) fn parse(bytes: &[u8], spec: &CardSpec) -> Result<Self, CardError> {
        preflight(bytes, MAX_TREE)?;
        let tree: Self = serde_json::from_slice(bytes)?;
        let mut keys = BTreeSet::new();
        validate_node(&tree.root, 1, &mut keys)?;
        let root = &tree.root;
        if root.key != "root"
            || root.kind != NodeKind::Column
            || !root.text.is_empty()
            || !root.value.is_empty()
            || root.action.is_some()
            || root.children.len() != spec.components.len()
        {
            return Err(CardError::Invalid("root structure"));
        }
        for (node, form) in root.children.iter().zip(&spec.components) {
            let value = spec
                .model
                .get(form.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?)
                .ok_or(CardError::Invalid("binding"))?;
            let [field, submit] = node.children.as_slice() else {
                return Err(CardError::Invalid("form controls"));
            };
            if node.key != form.id
                || node.kind != NodeKind::Form
                || node.text != form.title
                || !node.value.is_empty()
                || node.action.is_some()
                || field.key != format!("{}:field", form.id)
                || field.kind != NodeKind::TextField
                || field.text != form.label
                || field.value != *value
                || field.action.is_some()
                || !field.children.is_empty()
                || submit.key != format!("{}:submit", form.id)
                || submit.kind != NodeKind::Submit
                || submit.text != form.submit
                || !submit.value.is_empty()
                || submit.action.as_ref() != Some(&form.submit)
                || !submit.children.is_empty()
            {
                return Err(CardError::Invalid("form semantics"));
            }
        }
        Ok(tree)
    }
    pub(crate) fn diff(
        &self,
        old: Option<&Self>,
        previous_version: u64,
        version: u64,
    ) -> MutationBatch {
        let before = old.map_or_else(Vec::new, |tree| flatten(&tree.root));
        let after = flatten(&self.root);
        let before_map: BTreeMap<_, _> = before.iter().map(|m| (&m.2.key, m)).collect();
        let after_keys: BTreeSet<_> = after.iter().map(|m| &m.2.key).collect();
        let mut mutations = Vec::new();
        for (_, _, node) in before.iter().rev() {
            if !after_keys.contains(&node.key) {
                mutations.push(Mutation::Remove { key: node.key.clone() });
            }
        }
        for entry in after {
            if before_map.get(&entry.2.key).is_none_or(|old| **old != entry) {
                mutations.push(Mutation::Upsert { parent: entry.0, index: entry.1, node: entry.2 });
            }
        }
        MutationBatch { previous_version, version, mutations }
    }
}
fn validate_node(node: &Node, depth: usize, keys: &mut BTreeSet<String>) -> Result<(), CardError> {
    if depth > crate::spec::MAX_DEPTH || keys.len() >= MAX_EXPANDED_NODES {
        return Err(CardError::Limit("expanded nodes or depth"));
    }
    if node.key.len() > 80
        || node.text.len() > 256
        || node.value.len() > 4096
        || !keys.insert(node.key.clone())
    {
        return Err(CardError::Invalid("tree key or text"));
    }
    for child in &node.children {
        validate_node(child, depth + 1, keys)?;
    }
    Ok(())
}
fn flatten(root: &Node) -> Vec<(Option<String>, usize, Node)> {
    fn visit(
        node: &Node,
        parent: Option<String>,
        index: usize,
        out: &mut Vec<(Option<String>, usize, Node)>,
    ) {
        let mut shallow = node.clone();
        shallow.children.clear();
        out.push((parent, index, shallow));
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
            Tree::parse(&serde_json::to_vec(&tree).expect("test: bounded expanded tree"), &spec)
                .is_err(),
            "expanded-node limit must reject before publication"
        );
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
