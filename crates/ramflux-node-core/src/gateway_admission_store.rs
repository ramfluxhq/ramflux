// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental gateway replay journal. Legacy snapshots remain replay evidence.
use super::{GatewayRedbStore, GatewayState};
use crate::{GATEWAY_STATE_TABLE, NodeCoreError, serialize_snapshot_value};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const REPLAY: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_replay_entries_v1");
const EXPIRY: TableDefinition<(i64, &str), u8> = TableDefinition::new("gateway_replay_expiry_v1");
const JOURNAL: &str = "replay_journal_v1";

#[derive(Serialize, Deserialize)]
struct ReplayEntry {
    owner: String,
    expiry: i64,
}

impl GatewayRedbStore {
    /// Validate and durably record a gateway authentication before session establishment.
    /// # Errors
    /// Rejects invalid auth, replay/capacity exhaustion and failed durable writes.
    pub fn authenticate(
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
        let key = request
            .replay_tuple_key(source)
            .map_err(|e| NodeCoreError::ReplayGuard(e.to_string()))?;
        let bytes = serialize_snapshot_value(&ReplayEntry {
            owner: source.storage_key().to_owned(),
            expiry: request.expires_at,
        })?;
        let write = self.db.begin_write().map_err(redb_error)?;
        {
            let mut entries = write.open_table(REPLAY).map_err(redb_error)?;
            let mut expiry = write.open_table(EXPIRY).map_err(redb_error)?;
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
                entries.remove(key.as_str()).map_err(redb_error)?;
                expiry.remove((at, key.as_str())).map_err(redb_error)?;
            }
            entries.insert(key.as_str(), bytes.as_slice()).map_err(redb_error)?;
            expiry.insert((request.expires_at, key.as_str()), 0).map_err(redb_error)?;
            let mut table = write.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
            table.insert(JOURNAL, &[1_u8][..]).map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.durable_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Persist only this authenticated session and its newly issued resume token.
    /// # Errors
    /// Returns errors on missing session/token or failed durable commit.
    pub fn save_authenticated_session(
        &self,
        state: &GatewayState,
        session: &str,
        token_hash: &str,
    ) -> Result<(), NodeCoreError> {
        let session_key = format!("auth_session/{session}");
        let token_key = format!("auth_resume/{token_hash}");
        let value = state
            .sessions_by_id
            .get(session)
            .ok_or_else(|| NodeCoreError::ItestHttp("missing auth session".into()))?;
        let token = state
            .resume_token_index_by_hash
            .get(token_hash)
            .ok_or_else(|| NodeCoreError::ItestHttp("missing auth resume token".into()))?;
        self.save_gateway_entries(&[
            (session_key.as_str(), serialize_snapshot_value(value)?),
            (token_key.as_str(), serialize_snapshot_value(token)?),
        ])
    }

    pub(super) fn load_session_overlay(
        &self,
        state: &mut GatewayState,
    ) -> Result<(), NodeCoreError> {
        let read = self.db.begin_read().map_err(redb_error)?;
        let table = read.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
        for row in table.range("auth_resume/".."auth_session0").map_err(redb_error)? {
            let (key, value) = row.map_err(redb_error)?;
            if let Some(id) = key.value().strip_prefix("auth_session/") {
                let session = serde_json::from_slice(value.value())
                    .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
                state.sessions_by_id.insert(id.to_owned(), session);
            } else if let Some(hash) = key.value().strip_prefix("auth_resume/") {
                let token = serde_json::from_slice(value.value())
                    .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
                state.resume_token_index_by_hash.insert(hash.to_owned(), token);
            }
        }
        Ok(())
    }

    pub(super) fn save_full_gateway_entries(
        &self,
        entries: &[(&str, Vec<u8>)],
    ) -> Result<(), NodeCoreError> {
        let write = self.db.begin_write().map_err(redb_error)?;
        {
            let mut table = write.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
            let overlay = table
                .range("auth_resume/".."auth_session0")
                .map_err(redb_error)?
                .map(|row| row.map(|(key, _)| key.value().to_owned()).map_err(redb_error))
                .collect::<Result<Vec<_>, _>>()?;
            for key in overlay {
                table.remove(key.as_str()).map_err(redb_error)?;
            }
            for (key, bytes) in entries {
                table.insert(*key, bytes.as_slice()).map_err(redb_error)?;
            }
        }
        #[cfg(any(test, feature = "durability-test-hooks"))]
        if self.fail_pre_auth_commit.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return Err(NodeCoreError::Redb("injected pre-auth commit failure".into()));
        }
        write.commit().map_err(redb_error)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.durable_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn replay_journal_active(&self) -> Result<bool, NodeCoreError> {
        let read = self.db.begin_read().map_err(redb_error)?;
        let table = read.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
        Ok(table.get(JOURNAL).map_err(redb_error)?.is_some())
    }

    pub(super) fn load_replay_journal(
        &self,
        state: &mut GatewayState,
    ) -> Result<(), NodeCoreError> {
        if !self.replay_journal_active()? {
            return Ok(());
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
