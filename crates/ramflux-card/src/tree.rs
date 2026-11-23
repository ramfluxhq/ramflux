// SPDX-License-Identifier: BSD-3-Clause
//! Flat keyed ABI-5 trees and atomic, shallow mutation batches.
use crate::{CardError, CardSpec, HostSlot, NodeKind, spec::preflight};
use ramflux_protocol::a2ui::ResolvedSlot;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
pub(crate) const MAX_TREE: usize = 256 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub key: String,
    pub component_id: String,
    pub source_instance: Vec<String>,
    pub scope: String,
    pub parent_key: Option<String>,
    pub slot: ResolvedSlot,
    pub children: Vec<String>,
    pub kind: NodeKind,
    pub attrs: Map<String, Value>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub schema: String,
    pub session: u64,
    pub signed_version: u64,
    pub signed_hash: String,
    pub edit_seq: u64,
    pub tree_version: u64,
    pub root_key: String,
    pub nodes: Vec<Node>,
    pub host_slots: Vec<HostSlot>,
    /// String-catalog tag after fallback.
    #[serde(default = "english_tag")]
    pub locale: String,
    /// CLDR locale used for numbers, dates and plurals.
    #[serde(default = "english_tag")]
    pub format_locale: String,
    /// `rtl` for Arabic, otherwise `ltr`.
    #[serde(default = "ltr_direction")]
    pub direction: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Remove { key: String },
    Upsert { parent: Option<String>, index: usize, node: Node },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationBatch {
    pub schema: String,
    pub session: u64,
    pub previous_version: u64,
    pub version: u64,
    pub signed_version: u64,
    pub signed_hash: String,
    pub edit_seq: u64,
    pub mutations: Vec<Mutation>,
    pub host_slots: Vec<HostSlot>,
    /// String-catalog tag after fallback. Present even when no node changed.
    #[serde(default = "english_tag")]
    pub locale: String,
    /// CLDR locale used for numbers, dates and plurals.
    #[serde(default = "english_tag")]
    pub format_locale: String,
    /// `rtl` for Arabic, otherwise `ltr`.
    #[serde(default = "ltr_direction")]
    pub direction: String,
}
fn english_tag() -> String {
    "en".to_owned()
}
fn ltr_direction() -> String {
    "ltr".to_owned()
}
impl Tree {
    pub(crate) fn parse(bytes: &[u8], spec: &CardSpec) -> Result<Self, CardError> {
        preflight(bytes, MAX_TREE)?;
        let value: Value = serde_json::from_slice(bytes)?;
        let expected =
            spec.render_tree.clone().map_or_else(|| crate::projection::expected(spec), Ok)?;
        // Compare raw JSON as well as typed semantics: serde flattening must never
        // discard an unknown field in a host slot or node before this check.
        if value != serde_json::to_value(&expected)? {
            return Err(CardError::Invalid("component semantics"));
        }
        expected.check_limits()?;
        Ok(expected)
    }
    pub(crate) fn check_limits(&self) -> Result<(), CardError> {
        if self.nodes.len() > 256 || serde_json::to_vec(self)?.len() > MAX_TREE {
            return Err(CardError::Limit("tree"));
        }
        let mut keys = BTreeSet::new();
        let mut bytes = 0usize;
        for node in &self.nodes {
            if !keys.insert(&node.key) {
                return Err(CardError::Invalid("duplicate tree key"));
            }
            bytes = bytes.saturating_add(serde_json::to_vec(&node.attrs)?.len());
        }
        if bytes > 64 * 1024 {
            return Err(CardError::Limit("resolved properties"));
        }
        Ok(())
    }
    pub(crate) fn diff(
        &self,
        old: Option<&Self>,
        previous_version: u64,
        version: u64,
    ) -> Result<MutationBatch, CardError> {
        let before: BTreeMap<_, _> =
            old.into_iter().flat_map(|t| &t.nodes).map(|node| (&node.key, node)).collect();
        let keys: BTreeSet<_> = self.nodes.iter().map(|node| &node.key).collect();
        let mut mutations = Vec::new();
        if let Some(old) = old {
            for node in old.nodes.iter().rev() {
                if !keys.contains(&node.key) {
                    mutations.push(Mutation::Remove { key: node.key.clone() });
                }
            }
        }
        // Emit all surviving children when an edge list changes. This also rebuilds an
        // unchanged descendant after its ancestor was removed/reinserted by the host.
        let mut rebuilt = BTreeSet::new();
        for node in &self.nodes {
            let index = self.index(node)?;
            let previous = before.get(&node.key);
            let parent_rebuilt = node.parent_key.as_ref().is_some_and(|key| rebuilt.contains(key));
            let moved = match (old, previous) {
                (Some(old), Some(previous)) => {
                    old.index(previous)? != index || previous.parent_key != node.parent_key
                }
                _ => true,
            };
            if parent_rebuilt || moved || previous.is_none_or(|previous| *previous != node) {
                let mut shallow = node.clone();
                shallow.children.clear();
                mutations.push(Mutation::Upsert {
                    parent: node.parent_key.clone(),
                    index,
                    node: shallow,
                });
                rebuilt.insert(node.key.clone());
            }
        }
        let batch = MutationBatch {
            schema: "ramflux.card.mutations.v1".into(),
            session: self.session,
            previous_version,
            version,
            signed_version: self.signed_version,
            signed_hash: self.signed_hash.clone(),
            edit_seq: self.edit_seq,
            mutations,
            host_slots: self.host_slots.clone(),
            locale: self.locale.clone(),
            format_locale: self.format_locale.clone(),
            direction: self.direction.clone(),
        };
        if batch.mutations.len() > 512 || serde_json::to_vec(&batch)?.len() > MAX_TREE {
            return Err(CardError::Limit("mutation batch"));
        }
        Ok(batch)
    }
    fn index(&self, node: &Node) -> Result<usize, CardError> {
        match &node.parent_key {
            None => Ok(0),
            Some(parent) => self
                .nodes
                .iter()
                .find(|node| &node.key == parent)
                .and_then(|parent| parent.children.iter().position(|key| key == &node.key))
                .ok_or(CardError::Invalid("tree edge")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::fixture;
    #[test]
    fn rejects_invalid_trees_and_bounds_expansion() {
        let spec = fixture();
        let mut tree = crate::projection::expected(&spec).expect("test: projection");
        tree.nodes[0].attrs.insert("html".into(), Value::String("script".into()));
        assert!(
            Tree::parse(&serde_json::to_vec(&tree).expect("test: tree"), &spec).is_err(),
            "VM semantics cannot add attributes"
        );
        tree.nodes = vec![tree.nodes[0].clone(); 257];
        assert!(tree.check_limits().is_err(), "expanded nodes are bounded");
    }
    #[test]
    fn keyed_diff_orders_removals_and_skips_unchanged_nodes() {
        let tree = crate::projection::expected(&fixture()).expect("test: tree");
        assert!(
            tree.diff(Some(&tree), 1, 2).expect("test: diff").mutations.is_empty(),
            "unchanged nodes need no upsert"
        );
        let mut empty = tree.clone();
        empty.nodes.clear();
        let batch = empty.diff(Some(&tree), 1, 2).expect("test: removal batch");
        assert_eq!(
            batch.mutations.first(),
            Some(&Mutation::Remove { key: tree.nodes.last().expect("test: leaf").key.clone() }),
            "remove descendants before parents"
        );
    }
    #[test]
    fn eight_node_levels_hit_the_explicit_json_nesting_budget() {
        let spec = fixture();
        let tree = crate::projection::expected(&spec).expect("test: tree");
        let bytes = serde_json::to_vec(&tree).expect("test: flat tree");
        assert_eq!(
            Tree::parse(&bytes, &spec).expect("test: ABI5 flat edges"),
            tree,
            "flat keyed edges do not recursively embed nodes"
        );
        assert!(
            preflight(&[b'['; 33], MAX_TREE).is_err(),
            "JSON transport recursion remains bounded"
        );
    }
    #[test]
    fn reparent_after_ancestor_removal_reemits_the_retained_subtree() {
        let tree = crate::projection::expected(&fixture()).expect("test: tree");
        let mut after = tree.clone();
        let old = after.nodes[1].clone();
        let child = after.nodes[2].key.clone();
        after.nodes[0].children = old.children.clone();
        for node in &mut after.nodes {
            if node.parent_key.as_ref() == Some(&old.key) {
                node.parent_key = Some(after.root_key.clone());
            }
        }
        after.nodes.remove(1);
        let batch = after.diff(Some(&tree), 1, 2).expect("test: reparent");
        assert!(
            batch
                .mutations
                .iter()
                .any(|m| matches!(m,Mutation::Upsert{node,..} if node.key==child)),
            "reparented retained children must be reattached"
        );
    }
}
