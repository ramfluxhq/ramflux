// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Permanent node-key history and native prekeys, indexed individually in redb.
use super::{
    BTreeMap, NodeCoreError, Read, ReadableDatabase, ReadableTable, RouterRedbStore,
    TableDefinition,
};
use ramflux_crypto::custody::{VerifiedNodeRecord, verify_node_identity_record};
use ramflux_protocol::custody::{Envelope, NodeIdentityRecord};
const HISTORY: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_node_history_v1");
const HEADS: TableDefinition<&str, &str> = TableDefinition::new("custody_node_heads_v1");
const BINDINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_node_key_bindings_v1");
const PREKEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_prekeys_v3");
fn error(e: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(e.to_string())
}
impl RouterRedbStore {
    /// Persist an authenticated node head and permanent history/key-id indexes atomically.
    /// # Errors
    /// Rejects rollback, rebindings, missing historical predecessors and database failures.
    pub fn observe_custody_node(
        &self,
        node: &VerifiedNodeRecord,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(error)?;
        {
            let mut heads = tx.open_table(HEADS).map_err(error)?;
            let mut history = tx.open_table(HISTORY).map_err(error)?;
            let mut keys = tx.open_table(BINDINGS).map_err(error)?;
            let body = &node.envelope().body;
            let old_hash =
                heads.get(body.node_id.as_str()).map_err(error)?.map(|v| v.value().to_string());
            let entries: Vec<_> = body
                .receipt_keys
                .iter()
                .map(|k| (&k.key_id, &k.public_key, "home_relay".to_owned()))
                .chain(
                    body.proxy_keys
                        .iter()
                        .map(|k| (&k.key_id, &k.public_key, format!("node_proxy:{}", k.proxy_id))),
                )
                .collect();
            let mut known = BTreeMap::new();
            let mut publics = BTreeMap::new();
            for (id, public, _) in &entries {
                let id_key = format!("{}/id/{id}", body.node_id);
                if let Some(v) = keys.get(id_key.as_str()).map_err(error)? {
                    let pair: (String, String) =
                        serde_json::from_slice(v.value()).map_err(error)?;
                    known.insert((*id).clone(), pair);
                }
                let pub_key = format!("{}/pub/{public}", body.node_id);
                if let Some(v) = keys.get(pub_key.as_str()).map_err(error)? {
                    let value: String = serde_json::from_slice(v.value()).map_err(error)?;
                    publics.insert((*public).clone(), value);
                }
            }
            if let Some(old_hash) = old_hash {
                let bytes = history
                    .get(old_hash.as_str())
                    .map_err(error)?
                    .ok_or_else(|| error("node predecessor missing"))?
                    .value()
                    .to_vec();
                let old: Envelope<NodeIdentityRecord> =
                    ramflux_protocol::custody::decode(&bytes, 512 * 1024).map_err(error)?;
                let old = verify_node_identity_record(
                    &old,
                    &body.node_id,
                    &body.node_signing_public_key,
                    now,
                )
                .map_err(error)?;
                old.verify_successor(
                    node,
                    |id| known.get(id).cloned(),
                    |public| publics.get(public).cloned(),
                )
                .map_err(error)?;
            }
            for (id, public, role) in entries {
                let id_key = format!("{}/id/{id}", body.node_id);
                let pub_key = format!("{}/pub/{public}", body.node_id);
                let bytes = serde_json::to_vec(&(public, role)).map_err(error)?;
                keys.insert(id_key.as_str(), bytes.as_slice()).map_err(error)?;
                let bytes = serde_json::to_vec(id).map_err(error)?;
                keys.insert(pub_key.as_str(), bytes.as_slice()).map_err(error)?;
            }
            let bytes = ramflux_protocol::canonical_json_bytes(node.envelope()).map_err(error)?;
            history.insert(node.hash(), bytes.as_slice()).map_err(error)?;
            heads.insert(body.node_id.as_str(), node.hash()).map_err(error)?;
        }
        tx.commit().map_err(error)
    }
    /// # Errors
    /// Rejects database failures or malformed retained records.
    pub fn custody_node_history(
        &self,
        hash: &str,
    ) -> Result<Option<Envelope<NodeIdentityRecord>>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let Ok(table) = tx.open_table(HISTORY) else { return Ok(None) };
        table
            .get(hash)
            .map_err(error)?
            .map(|bytes| {
                ramflux_protocol::custody::decode(bytes.value(), 512 * 1024).map_err(error)
            })
            .transpose()
    }
    pub(crate) fn custody_prekey(
        &self,
        target: &str,
    ) -> Result<Option<serde_json::Value>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let Ok(table) = tx.open_table(PREKEYS) else { return Ok(None) };
        table
            .get(target)
            .map_err(error)?
            .map(|bytes| serde_json::from_slice(bytes.value()).map_err(error))
            .transpose()
    }
    pub(crate) fn record_custody_prekey(
        &self,
        target: &str,
        bundle: &serde_json::Value,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(error)?;
        {
            let mut table = tx.open_table(PREKEYS).map_err(error)?;
            let bytes = ramflux_protocol::canonical_json_bytes(bundle).map_err(error)?;
            table.insert(target, bytes.as_slice()).map_err(error)?;
        }
        tx.commit().map_err(error)
    }
}
