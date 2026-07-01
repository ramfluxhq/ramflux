// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::NodeCoreError;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const ROUTER_SNAPSHOT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_snapshot_v1");
pub(crate) const ROUTER_INBOX_ENTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_inbox_entry_v1");
pub(crate) const ROUTER_CURSOR_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_cursor_state_v1");
pub(crate) const ROUTER_REPLAY_TUPLE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_replay_tuple_v1");
pub(crate) const ROUTER_SESSION_ENTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_session_entry_v1");
pub(crate) const ROUTER_LIFECYCLE_RECORD_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_lifecycle_record_v1");
pub(crate) const ROUTER_LIFECYCLE_TOMBSTONE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_lifecycle_tombstone_v1");
pub(crate) const ROUTER_DEACTIVATED_TARGET_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_deactivated_target_v1");
pub(crate) const ROUTER_DELETED_TARGET_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_deleted_target_v1");
pub(crate) const ROUTER_ABUSE_REPORT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_abuse_report_v1");
pub(crate) const ROUTER_SESSION_CHECKPOINT_KEY: &str = "session_checkpoint";
pub(crate) const ROUTER_INBOX_SLICE_KEY: &str = "opaque_device_inbox";
pub(crate) const ROUTER_IDENTITY_REGISTRY_KEY: &str = "identity_registry";
pub(crate) const ROUTER_LIFECYCLE_STATE_KEY: &str = "lifecycle_state";
pub(crate) const ROUTER_LIFECYCLE_TOMBSTONE_KEY: &str = "lifecycle_tombstone";
pub(crate) const ROUTER_DEACTIVATED_TARGETS_KEY: &str = "deactivated_delivery_targets";
pub(crate) const ROUTER_DELETED_TARGETS_KEY: &str = "deleted_delivery_targets";
pub(crate) const ROUTER_ABUSE_REPORT_KEY: &str = "abuse_report_state";
pub(crate) const ROUTER_REPLAY_GUARD_STATE_KEY: &str = "replay_guard_state";
pub(crate) const RETENTION_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("retention_state_v1");
pub(crate) const RETENTION_STATE_KEY: &str = "retention_state";
pub(crate) const NOTIFY_QUEUE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_queue_v1");
pub(crate) const NOTIFY_QUEUE_KEY: &str = "notify_queue";
pub(crate) const NOTIFY_QUEUE_ENTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_queue_entry_v1");
pub(crate) const NOTIFY_PROVIDER_ATTEMPT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_provider_attempt_v1");
pub(crate) const NOTIFY_ROUTE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_route_v1");
pub(crate) const NOTIFY_CREDENTIAL_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_credential_v1");
pub(crate) const RELAY_CACHE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("object_relay_cache_v1");
pub(crate) const RELAY_CACHE_KEY: &str = "object_relay_cache";
pub(crate) const RELAY_CHUNK_ENTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("object_relay_chunk_entry_v1");
pub(crate) const RELAY_TOMBSTONE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("object_relay_tombstone_v1");
pub(crate) const FEDERATION_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("federation_state_v1");
pub(crate) const FEDERATION_OUTBOUND_SPOOL_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("federation_outbound_spool_v1");
pub(crate) const FEDERATION_INBOUND_FORWARD_SEEN_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("federation_inbound_forward_seen_v1");
pub(crate) const FEDERATION_ROUTE_STATE_KEY: &str = "route_state";
pub(crate) const FEDERATION_BAD_NODE_ADVISORY_KEY: &str = "bad_node_advisory";
pub(crate) const FEDERATION_LIFECYCLE_TOMBSTONE_KEY: &str = "lifecycle_tombstone";
pub(crate) const FEDERATION_INVITATION_STATE_KEY: &str = "invitation_state";
pub(crate) const FEDERATION_NEGOTIATED_CAPABILITIES_KEY: &str = "negotiated_capabilities";
pub(crate) const FEDERATION_HANDSHAKE_REPLAY_KEY: &str = "handshake_replay_state";
pub(crate) const FEDERATION_DISCOVERY_PIN_KEY: &str = "discovery_pin_state";
pub(crate) const FEDERATION_NODE_SIGNING_SEED_KEY: &str = "node_signing_seed";
pub(crate) const SIGNALING_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("signaling_state_v1");
pub(crate) const SIGNALING_STATE_KEY: &str = "signaling_state";
pub(crate) const GATEWAY_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("gateway_state_v1");
pub(crate) const GATEWAY_CHALLENGE_STATE_KEY: &str = "challenge_state";
pub(crate) const GATEWAY_SESSION_CHECKPOINT_KEY: &str = "session_checkpoint";
pub(crate) const GATEWAY_DELIVERY_FRAME_QUEUE_KEY: &str = "delivery_frame_queue";
pub(crate) const GATEWAY_PRE_AUTH_POLICY_KEY: &str = "pre_auth_policy";
pub(crate) const GATEWAY_PRE_AUTH_METRICS_KEY: &str = "pre_auth_metrics";
pub(crate) const GATEWAY_PRE_AUTH_RATE_STATE_KEY: &str = "pre_auth_rate_state";
pub(crate) const GATEWAY_REPLAY_GUARD_STATE_KEY: &str = "replay_guard_state";
pub(crate) const GATEWAY_RESUME_TOKEN_INDEX_KEY: &str = "resume_token_index";

pub(crate) fn open_redb_with_table(
    path: impl AsRef<Path>,
    table: TableDefinition<&str, &[u8]>,
) -> Result<redb::Database, NodeCoreError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| NodeCoreError::StoreDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let db =
        redb::Database::create(path).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    {
        let _table = write_txn
            .open_table(table)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(db)
}

pub(crate) fn save_snapshot<T: Serialize>(
    db: &redb::Database,
    table: TableDefinition<&str, &[u8]>,
    key: &str,
    value: &T,
) -> Result<(), NodeCoreError> {
    let snapshot = serialize_snapshot_value(value)?;
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    {
        let mut table = write_txn
            .open_table(table)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        table
            .insert(key, snapshot.as_slice())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

pub(crate) fn save_snapshot_batch(
    db: &redb::Database,
    table: TableDefinition<&str, &[u8]>,
    entries: &[(&str, Vec<u8>)],
) -> Result<(), NodeCoreError> {
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    {
        let mut table = write_txn
            .open_table(table)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        for (key, snapshot) in entries {
            table
                .insert(*key, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
    }
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

pub(crate) fn serialize_snapshot_value<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(value)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

pub(crate) fn load_snapshot<T: serde::de::DeserializeOwned>(
    db: &redb::Database,
    table: TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<Option<T>, NodeCoreError> {
    let read_txn = db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let table =
        read_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let Some(snapshot) =
        table.get(key).map_err(|source| NodeCoreError::Redb(source.to_string()))?
    else {
        return Ok(None);
    };
    let value = serde_json::from_slice(snapshot.value())
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    Ok(Some(value))
}
