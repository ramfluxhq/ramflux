// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::{
    FEDERATION_BAD_NODE_ADVISORY_KEY, FEDERATION_DISCOVERY_PIN_KEY,
    FEDERATION_HANDSHAKE_REPLAY_KEY, FEDERATION_INVITATION_STATE_KEY,
    FEDERATION_LIFECYCLE_TOMBSTONE_KEY, FEDERATION_NEGOTIATED_CAPABILITIES_KEY,
    FEDERATION_NODE_SIGNING_SEED_KEY, FEDERATION_OUTBOUND_SPOOL_TABLE, FEDERATION_ROUTE_STATE_KEY,
    FEDERATION_STATE_TABLE, FederationTrustState, NodeCoreError, load_snapshot,
    open_redb_with_table, save_snapshot,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct FederationRedbStore {
    db: redb::Database,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationOutboundSpoolEntry {
    pub peer_node_id: String,
    pub seq: u64,
    pub forward: crate::FederatedEnvelopeForwardRequest,
    pub enqueued_at: u64,
    pub attempt_count: u64,
    pub expires_at: u64,
}

impl FederationRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let db = open_redb_with_table(path, FEDERATION_STATE_TABLE)?;
        let write_txn =
            db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let _table = write_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(Self { db })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_state(&self, state: &FederationTrustState) -> Result<(), NodeCoreError> {
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_ROUTE_STATE_KEY,
            &state.routes_by_node,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_BAD_NODE_ADVISORY_KEY,
            &state.advisories_by_id,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_LIFECYCLE_TOMBSTONE_KEY,
            &state.lifecycle_tombstones_by_target,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_INVITATION_STATE_KEY,
            &state.invitations_by_id,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_NEGOTIATED_CAPABILITIES_KEY,
            &state.negotiated_capabilities_by_node,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_HANDSHAKE_REPLAY_KEY,
            &state.seen_handshakes,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_DISCOVERY_PIN_KEY,
            &state.discovery_pins_by_node,
        )?;
        save_snapshot(
            &self.db,
            FEDERATION_STATE_TABLE,
            FEDERATION_NODE_SIGNING_SEED_KEY,
            &state.node_signing_seed,
        )
    }

    /// # Errors
    /// Returns an error when the persisted federation state cannot be read.
    pub fn load_state(&self) -> Result<Option<FederationTrustState>, NodeCoreError> {
        let routes_by_node: Option<_> =
            load_snapshot(&self.db, FEDERATION_STATE_TABLE, FEDERATION_ROUTE_STATE_KEY)?;
        let node_signing_seed: Option<Option<[u8; 32]>> =
            load_snapshot(&self.db, FEDERATION_STATE_TABLE, FEDERATION_NODE_SIGNING_SEED_KEY)?;
        if routes_by_node.is_none() && node_signing_seed.is_none() {
            return Ok(None);
        }
        Ok(Some(FederationTrustState {
            routes_by_node: routes_by_node.unwrap_or_default(),
            advisories_by_id: load_snapshot(
                &self.db,
                FEDERATION_STATE_TABLE,
                FEDERATION_BAD_NODE_ADVISORY_KEY,
            )?
            .unwrap_or_default(),
            lifecycle_tombstones_by_target: load_snapshot(
                &self.db,
                FEDERATION_STATE_TABLE,
                FEDERATION_LIFECYCLE_TOMBSTONE_KEY,
            )?
            .unwrap_or_default(),
            invitations_by_id: load_snapshot(
                &self.db,
                FEDERATION_STATE_TABLE,
                FEDERATION_INVITATION_STATE_KEY,
            )?
            .unwrap_or_default(),
            negotiated_capabilities_by_node: load_snapshot(
                &self.db,
                FEDERATION_STATE_TABLE,
                FEDERATION_NEGOTIATED_CAPABILITIES_KEY,
            )?
            .unwrap_or_default(),
            seen_handshakes: load_snapshot(
                &self.db,
                FEDERATION_STATE_TABLE,
                FEDERATION_HANDSHAKE_REPLAY_KEY,
            )?
            .unwrap_or_default(),
            discovery_pins_by_node: load_snapshot(
                &self.db,
                FEDERATION_STATE_TABLE,
                FEDERATION_DISCOVERY_PIN_KEY,
            )?
            .unwrap_or_default(),
            node_signing_seed: node_signing_seed.unwrap_or_default(),
        }))
    }

    /// # Errors
    /// Returns an error when the outbound spool entry cannot be persisted.
    pub fn spool_outbound_forward(
        &self,
        peer_node_id: &str,
        forward: &crate::FederatedEnvelopeForwardRequest,
        enqueued_at: u64,
        ttl_seconds: u64,
    ) -> Result<FederationOutboundSpoolEntry, NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let entry = {
            let table = write_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let seq = next_spool_seq_in_table(&table, peer_node_id)?;
            FederationOutboundSpoolEntry {
                peer_node_id: peer_node_id.to_owned(),
                seq,
                forward: forward.clone(),
                enqueued_at,
                attempt_count: 0,
                expires_at: enqueued_at.saturating_add(ttl_seconds),
            }
        };
        let bytes = serialize_spool_entry(&entry)?;
        let key = outbound_spool_key(peer_node_id, entry.seq);
        {
            let mut table = write_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when pending outbound spool entries cannot be read.
    pub fn list_pending_for_peer(
        &self,
        peer_node_id: &str,
        limit: usize,
    ) -> Result<Vec<FederationOutboundSpoolEntry>, NodeCoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let prefix = outbound_spool_key_prefix(peer_node_id);
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let mut entries = Vec::new();
        for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
            let (key, value) = entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            entries.push(deserialize_spool_entry(value.value())?);
            if entries.len() == limit {
                break;
            }
        }
        entries.sort_by_key(|entry| entry.seq);
        Ok(entries)
    }

    /// # Errors
    /// Returns an error when pending outbound spool entries cannot be read.
    pub fn list_pending_outbound(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationOutboundSpoolEntry>, NodeCoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let mut entries = Vec::new();
        for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
            let (_key, value) = entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            entries.push(deserialize_spool_entry(value.value())?);
            if entries.len() == limit {
                break;
            }
        }
        entries.sort_by(|left, right| {
            left.peer_node_id.cmp(&right.peer_node_id).then_with(|| left.seq.cmp(&right.seq))
        });
        Ok(entries)
    }

    /// # Errors
    /// Returns an error when the outbound spool entry cannot be deleted.
    pub fn mark_outbound_delivered(
        &self,
        peer_node_id: &str,
        seq: u64,
    ) -> Result<(), NodeCoreError> {
        let key = outbound_spool_key(peer_node_id, seq);
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _removed = table
                .remove(key.as_str())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))
    }

    /// # Errors
    /// Returns an error when the outbound spool attempt counter cannot be updated.
    pub fn record_outbound_attempt(
        &self,
        peer_node_id: &str,
        seq: u64,
    ) -> Result<(), NodeCoreError> {
        let key = outbound_spool_key(peer_node_id, seq);
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let mut entry = {
                let Some(current) = table
                    .get(key.as_str())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?
                else {
                    return Ok(());
                };
                deserialize_spool_entry(current.value())?
            };
            entry.attempt_count = entry.attempt_count.saturating_add(1);
            let bytes = serialize_spool_entry(&entry)?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))
    }

    /// # Errors
    /// Returns an error when expired outbound spool entries cannot be removed.
    pub fn expire_outbound_spool(&self, now: u64) -> Result<usize, NodeCoreError> {
        let expired_keys = {
            let read_txn =
                self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let table = read_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let mut expired = Vec::new();
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                let (key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let spool_entry = deserialize_spool_entry(value.value())?;
                if spool_entry.expires_at <= now {
                    expired.push(key.value().to_owned());
                }
            }
            expired
        };
        if expired_keys.is_empty() {
            return Ok(0);
        }
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(FEDERATION_OUTBOUND_SPOOL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for key in &expired_keys {
                table
                    .remove(key.as_str())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(expired_keys.len())
    }
}

fn next_spool_seq_in_table(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    peer_node_id: &str,
) -> Result<u64, NodeCoreError> {
    let prefix = outbound_spool_key_prefix(peer_node_id);
    let mut max_seq = 0_u64;
    for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
        let (key, _value) = entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let key = key.value();
        if let Some(seq) = key.strip_prefix(&prefix).and_then(|suffix| suffix.parse().ok()) {
            max_seq = max_seq.max(seq);
        }
    }
    Ok(max_seq.saturating_add(1))
}

fn outbound_spool_key(peer_node_id: &str, seq: u64) -> String {
    format!("{}{:020}", outbound_spool_key_prefix(peer_node_id), seq)
}

fn outbound_spool_key_prefix(peer_node_id: &str) -> String {
    format!("{:08}:{}:", peer_node_id.len(), peer_node_id)
}

fn serialize_spool_entry(entry: &FederationOutboundSpoolEntry) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(entry)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn deserialize_spool_entry(bytes: &[u8]) -> Result<FederationOutboundSpoolEntry, NodeCoreError> {
    serde_json::from_slice(bytes)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}
