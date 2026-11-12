// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental root-owned replay evidence with expiry-safe replacement.
use super::{GatewayRedbStore, GatewayState};
use crate::{GATEWAY_STATE_TABLE, NodeCoreError, serialize_snapshot_value};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

const REPLAY: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_replay_entries_v2");
const EXPIRY: TableDefinition<(i64, &str), u8> = TableDefinition::new("gateway_replay_expiry_v2");
const ROOTS: TableDefinition<&str, u8> = TableDefinition::new("gateway_replay_roots_v2");

#[derive(Serialize, Deserialize)]
struct ReplayEntry {
    owner: String,
    expiry: i64,
}

impl GatewayRedbStore {
    /// Validate and durably record a gateway authentication before session establishment.
    /// # Errors
    /// Rejects invalid auth, replay/capacity exhaustion and failed durable writes.
    #[cfg(test)]
    pub(crate) fn authenticate(
        &self,
        state: &mut GatewayState,
        open: &crate::GatewayOpenFrame,
        auth: &crate::GatewayAuthFrame,
        now: i64,
        registered: &crate::DeviceAuthKeyResponse,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let source = crate::validate_gateway_auth_with_replay(
            open,
            auth,
            now,
            state.replay_guard_state_mut(),
            registered,
        )?;
        self.save_auth_replay(&source, &auth.signed_request, now)?;
        Ok(source)
    }

    /// Durably record one already-validated auth before acknowledging it.
    /// # Errors
    /// Returns storage or serialization errors; callers must refuse authentication.
    pub fn save_auth_replay(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        self.write_guard()?.save_auth_replay(source, request, now)
    }

    pub(super) fn save_auth_replay_unlocked(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        let key = request
            .replay_tuple_key(source)
            .map_err(|e| NodeCoreError::ReplayGuard(e.to_string()))?;
        let bytes = serialize_snapshot_value(&ReplayEntry {
            owner: source.root_commitment().to_owned(),
            expiry: request.expires_at,
        })?;
        let write = self.db.begin_write().map_err(redb_error)?;
        {
            let mut entries = write.open_table(REPLAY).map_err(redb_error)?;
            let mut expiry = write.open_table(EXPIRY).map_err(redb_error)?;
            let previous = entries
                .get(key.as_str())
                .map_err(redb_error)?
                .map(|raw| serde_json::from_slice::<ReplayEntry>(raw.value()))
                .transpose()
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
            if let Some(previous) = previous {
                if previous.owner != source.root_commitment()
                    || previous.expiry > request.expires_at
                {
                    return Err(NodeCoreError::ReplayGuard("stale replay commit".into()));
                }
                expiry.remove((previous.expiry, key.as_str())).map_err(redb_error)?;
            }
            let mut roots = write.open_table(ROOTS).map_err(redb_error)?;
            if roots.get(source.root_commitment()).map_err(redb_error)?.is_none()
                && roots.len().map_err(redb_error)?
                    >= crate::replay_guard::GATEWAY_REPLAY_ROOTS as u64
            {
                return Err(NodeCoreError::GatewayReplayCapacity);
            }
            roots.insert(source.root_commitment(), 0).map_err(redb_error)?;
            let stale = expiry
                .iter()
                .map_err(redb_error)?
                .take(64)
                .map(|row| {
                    row.map(|(key, _)| {
                        let (at, key) = key.value();
                        (at, key.to_owned())
                    })
                    .map_err(redb_error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (at, key) in stale {
                if at >= now {
                    break;
                }
                let current_expiry = entries
                    .get(key.as_str())
                    .map_err(redb_error)?
                    .map(|raw| serde_json::from_slice::<ReplayEntry>(raw.value()))
                    .transpose()
                    .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?
                    .map(|entry| entry.expiry);
                if current_expiry == Some(at) {
                    entries.remove(key.as_str()).map_err(redb_error)?;
                }
                expiry.remove((at, key.as_str())).map_err(redb_error)?;
            }
            entries.insert(key.as_str(), bytes.as_slice()).map_err(redb_error)?;
            expiry.insert((request.expires_at, key.as_str()), 0).map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.durable_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn load_replay_journal(
        &self,
        state: &mut GatewayState,
    ) -> Result<(), NodeCoreError> {
        let read_roots = self.db.begin_read().map_err(redb_error)?;
        let roots = read_roots.open_table(ROOTS).map_err(redb_error)?;
        for row in roots.iter().map_err(redb_error)? {
            let (root, _) = row.map_err(redb_error)?;
            state.replay_guard_state.restore_gateway_root(root.value().to_owned());
        }
        let read = self.db.begin_read().map_err(redb_error)?;
        let table = read.open_table(REPLAY).map_err(redb_error)?;
        for row in table.iter().map_err(redb_error)? {
            let (key, value) = row.map_err(redb_error)?;
            let entry: ReplayEntry = serde_json::from_slice(value.value())
                .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
            state.replay_guard_state.restore_owned_request(
                key.value().to_owned(),
                entry.owner,
                entry.expiry,
            );
        }
        Ok(())
    }
}

fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

pub(super) fn initialize_tables(write: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    write.open_table(REPLAY).map_err(redb_error)?;
    write.open_table(EXPIRY).map_err(redb_error)?;
    write.open_table(ROOTS).map_err(redb_error)?;
    Ok(())
}

#[cfg(test)]
#[path = "gateway_replay_journal_tests.rs"]
mod tests;
