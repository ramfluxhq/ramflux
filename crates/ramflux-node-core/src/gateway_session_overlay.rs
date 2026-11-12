// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current-format session/token rows and bounded expiry cleanup, independent of admission.
use super::{GatewayRedbStore, GatewayState};
use crate::{
    GatewayFrame, GatewayResumeTokenMetadata, GatewaySession, NodeCoreError,
    serialize_snapshot_value,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::BTreeMap;

const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_sessions_v2");
const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_resume_tokens_v2");
const FRAMES: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_frames_v2");
const SESSION_EXPIRY: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("gateway_session_expiry_v2");
const TOKEN_EXPIRY: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("gateway_resume_expiry_v2");

/// One bounded session and optional resume-token publication.
#[derive(Clone)]
pub struct GatewaySessionCheckpoint {
    session: GatewaySession,
    token: Option<GatewayResumeTokenMetadata>,
}

impl GatewayState {
    /// Copy one session and token under the state lock, after acquiring the store writer gate.
    /// # Errors
    /// Rejects missing session/token bindings.
    pub fn session_checkpoint(
        &self,
        session: &str,
        token_hash: Option<&str>,
    ) -> Result<GatewaySessionCheckpoint, NodeCoreError> {
        let session = self
            .sessions_by_id
            .get(session)
            .ok_or_else(|| NodeCoreError::ItestHttp("missing auth session".into()))?
            .clone();
        let token = token_hash
            .map(|hash| {
                self.resume_token_index_by_hash
                    .get(hash)
                    .cloned()
                    .ok_or_else(|| NodeCoreError::ItestHttp("missing auth resume token".into()))
            })
            .transpose()?;
        Ok(GatewaySessionCheckpoint { session, token })
    }
}

impl GatewayRedbStore {
    /// Persist one selected session/token pair. Gateway callers use a writer guard before capture.
    /// # Errors
    /// Returns binding, serialization or storage errors.
    pub fn save_authenticated_session(
        &self,
        state: &GatewayState,
        session: &str,
        token_hash: &str,
    ) -> Result<(), NodeCoreError> {
        let writer = self.write_guard()?;
        let checkpoint = state.session_checkpoint(session, Some(token_hash))?;
        writer.save_session_checkpoint(&checkpoint)
    }

    pub(super) fn save_session_checkpoint_unlocked(
        &self,
        checkpoint: &GatewaySessionCheckpoint,
    ) -> Result<(), NodeCoreError> {
        let session_bytes = serialize_snapshot_value(&checkpoint.session)?;
        let token_bytes = checkpoint.token.as_ref().map(serialize_snapshot_value).transpose()?;
        let write = self.db.begin_write().map_err(redb_error)?;
        {
            let mut sessions = write.open_table(SESSIONS).map_err(redb_error)?;
            let mut index = write.open_table(SESSION_EXPIRY).map_err(redb_error)?;
            if let Some(old) =
                sessions.get(checkpoint.session.session_id.as_str()).map_err(redb_error)?
            {
                let old: GatewaySession = decode(old.value())?;
                index
                    .remove((old.last_heartbeat_at, old.session_id.as_str()))
                    .map_err(redb_error)?;
            }
            sessions
                .insert(checkpoint.session.session_id.as_str(), session_bytes.as_slice())
                .map_err(redb_error)?;
            index
                .insert(
                    (checkpoint.session.last_heartbeat_at, checkpoint.session.session_id.as_str()),
                    0,
                )
                .map_err(redb_error)?;
            if let (Some(token), Some(bytes)) = (&checkpoint.token, &token_bytes) {
                write
                    .open_table(TOKENS)
                    .map_err(redb_error)?
                    .insert(token.resume_token_hash.as_str(), bytes.as_slice())
                    .map_err(redb_error)?;
                write
                    .open_table(TOKEN_EXPIRY)
                    .map_err(redb_error)?
                    .insert((token.issued_at, token.resume_token_hash.as_str()), 0)
                    .map_err(redb_error)?;
            }
        }
        write.commit().map_err(redb_error)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.record_incremental_commit();
        Ok(())
    }

    pub(super) fn save_full_gateway_entries(
        &self,
        entries: &[(&str, Vec<u8>)],
        state: &GatewayState,
    ) -> Result<(), NodeCoreError> {
        let sessions = state
            .sessions_by_id
            .iter()
            .map(|(key, value)| Ok((key.as_str(), serialize_snapshot_value(value)?)))
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let tokens = state
            .resume_token_index_by_hash
            .iter()
            .map(|(key, value)| Ok((key.as_str(), serialize_snapshot_value(value)?)))
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let frames = state
            .frames_by_session
            .iter()
            .map(|(key, value)| Ok((key.as_str(), serialize_snapshot_value(value)?)))
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let write = self.db.begin_write().map_err(redb_error)?;
        {
            let mut table = write.open_table(crate::GATEWAY_STATE_TABLE).map_err(redb_error)?;
            for (key, bytes) in entries {
                table.insert(*key, bytes.as_slice()).map_err(redb_error)?;
            }
        }
        replace_rows(&write, SESSIONS, &sessions)?;
        replace_rows(&write, TOKENS, &tokens)?;
        replace_rows(&write, FRAMES, &frames)?;
        {
            let mut session_index = write.open_table(SESSION_EXPIRY).map_err(redb_error)?;
            session_index.retain(|_, _| false).map_err(redb_error)?;
            for session in state.sessions_by_id.values() {
                session_index
                    .insert((session.last_heartbeat_at, session.session_id.as_str()), 0)
                    .map_err(redb_error)?;
            }
            let mut token_index = write.open_table(TOKEN_EXPIRY).map_err(redb_error)?;
            token_index.retain(|_, _| false).map_err(redb_error)?;
            for token in state.resume_token_index_by_hash.values() {
                token_index
                    .insert((token.issued_at, token.resume_token_hash.as_str()), 0)
                    .map_err(redb_error)?;
            }
        }
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.before_admission_commit()?;
        write.commit().map_err(redb_error)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.record_incremental_commit();
        Ok(())
    }

    pub(super) fn load_sessions(&self) -> Result<BTreeMap<String, GatewaySession>, NodeCoreError> {
        self.load_session_rows(SESSIONS)
    }
    pub(super) fn load_tokens(
        &self,
    ) -> Result<BTreeMap<String, GatewayResumeTokenMetadata>, NodeCoreError> {
        self.load_session_rows(TOKENS)
    }
    pub(super) fn load_frames(&self) -> Result<BTreeMap<String, Vec<GatewayFrame>>, NodeCoreError> {
        self.load_session_rows(FRAMES)
    }
    fn load_session_rows<T: serde::de::DeserializeOwned>(
        &self,
        definition: TableDefinition<&str, &[u8]>,
    ) -> Result<BTreeMap<String, T>, NodeCoreError> {
        let read = self.db.begin_read().map_err(redb_error)?;
        let table = read.open_table(definition).map_err(redb_error)?;
        table
            .iter()
            .map_err(redb_error)?
            .map(|row| {
                let (key, value) = row.map_err(redb_error)?;
                Ok((key.value().to_owned(), decode(value.value())?))
            })
            .collect()
    }

    pub(super) fn prune_session_rows_unlocked(
        &self,
        now: u64,
        window: u64,
    ) -> Result<(), NodeCoreError> {
        let write = self.db.begin_write().map_err(redb_error)?;
        for (definition, index_definition, session_rows) in
            [(SESSIONS, SESSION_EXPIRY, true), (TOKENS, TOKEN_EXPIRY, false)]
        {
            let mut rows = write.open_table(definition).map_err(redb_error)?;
            let mut index = write.open_table(index_definition).map_err(redb_error)?;
            let expired = index
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
            for (at, key) in expired {
                if now.saturating_sub(at) <= window {
                    break;
                }
                rows.remove(key.as_str()).map_err(redb_error)?;
                index.remove((at, key.as_str())).map_err(redb_error)?;
                if session_rows {
                    write
                        .open_table(FRAMES)
                        .map_err(redb_error)?
                        .remove(key.as_str())
                        .map_err(redb_error)?;
                }
            }
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }
}

pub(super) fn initialize_tables(write: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    for table in [SESSIONS, TOKENS, FRAMES] {
        write.open_table(table).map_err(redb_error)?;
    }
    write.open_table(SESSION_EXPIRY).map_err(redb_error)?;
    write.open_table(TOKEN_EXPIRY).map_err(redb_error)?;
    Ok(())
}
fn replace_rows(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
    entries: &[(&str, Vec<u8>)],
) -> Result<(), NodeCoreError> {
    let mut table = write.open_table(definition).map_err(redb_error)?;
    table.retain(|_, _| false).map_err(redb_error)?;
    for (key, value) in entries {
        table.insert(*key, value.as_slice()).map_err(redb_error)?;
    }
    Ok(())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, NodeCoreError> {
    serde_json::from_slice(bytes).map_err(|error| NodeCoreError::ItestJson(error.to_string()))
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
