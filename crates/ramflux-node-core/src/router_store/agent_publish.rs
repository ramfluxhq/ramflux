// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consumed agent-publication authorizations, written in the same redb transaction as the
//! custody directory record they admitted.

pub(crate) mod agent_host;

use crate::{NodeCoreError, RouterRedbStore, custody_authority::CustodyAccountState};
use agent_host::AgentHostBinding;
use ramflux_protocol::custody::{AgentPublishReceipt, CustodyRefusal};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

/// Request identifier to the consumed authorization and its saved receipt.
const AGENT_PUBLISHES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("agent_publish_receipts_v1");
/// Decision hash to the request identifier that consumed it.
const AGENT_DECISIONS: TableDefinition<&str, &str> =
    TableDefinition::new("agent_publish_decisions_v1");

/// Inputs of one admitted publication: the directory record and the authorization it consumed.
#[derive(Clone, Copy)]
pub(crate) struct AgentPublicationWrite<'a> {
    pub request_id: &'a str,
    pub row: &'a StoredAgentPublish,
    pub anchor: &'a str,
    pub state: &'a CustodyAccountState,
    pub expected: Option<&'a CustodyAccountState>,
    pub source: std::net::IpAddr,
    pub now: u64,
    pub host: &'a AgentHostBinding,
}

/// One consumed authorization. `receipt` is the exact receipt returned to the publisher.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredAgentPublish {
    pub request_hash: String,
    pub record_hash: String,
    pub decision_hash: String,
    pub receipt: AgentPublishReceipt,
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn conflict() -> NodeCoreError {
    NodeCoreError::AgentPublishRefused(CustodyRefusal::IdempotencyConflict)
}

impl RouterRedbStore {
    /// Saved authorization for one request identifier, if it was admitted before.
    pub(crate) fn agent_publish_by_request(
        &self,
        request_id: &str,
    ) -> Result<Option<StoredAgentPublish>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(AGENT_PUBLISHES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(error(e)),
        };
        let Some(value) = table.get(request_id).map_err(error)? else {
            return Ok(None);
        };
        serde_json::from_slice(value.value()).map(Some).map_err(error)
    }

    /// Request identifier that consumed this decision hash, if any.
    pub(crate) fn agent_decision_consumer(
        &self,
        decision_hash: &str,
    ) -> Result<Option<String>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(AGENT_DECISIONS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(error(e)),
        };
        Ok(table.get(decision_hash).map_err(error)?.map(|value| value.value().to_owned()))
    }

    /// Insert the consumed authorization inside `tx`. The caller writes the directory record
    /// in the same transaction, so both rows commit or neither does.
    pub(crate) fn record_agent_publish_in_tx(
        tx: &redb::WriteTransaction,
        request_id: &str,
        row: &StoredAgentPublish,
    ) -> Result<(), NodeCoreError> {
        {
            let mut publishes = tx.open_table(AGENT_PUBLISHES).map_err(error)?;
            if publishes.get(request_id).map_err(error)?.is_some() {
                return Err(conflict());
            }
            let mut decisions = tx.open_table(AGENT_DECISIONS).map_err(error)?;
            if decisions.get(row.decision_hash.as_str()).map_err(error)?.is_some() {
                return Err(conflict());
            }
            let bytes = serde_json::to_vec(row).map_err(error)?;
            publishes.insert(request_id, bytes.as_slice()).map_err(error)?;
            decisions.insert(row.decision_hash.as_str(), request_id).map_err(error)?;
        }
        Ok(())
    }

    /// Commit one directory record and its consumed authorization in one transaction.
    pub(crate) fn record_agent_publication(
        &self,
        write: &AgentPublicationWrite<'_>,
    ) -> Result<(), NodeCoreError> {
        let AgentPublicationWrite { request_id, row, anchor, state, expected, source, now, host } =
            *write;
        self.prune_custody_history(now)?;
        let prepared = self.prepare_notify_owner(state, now)?;
        let tx = self.begin_write().map_err(error)?;
        Self::insert_agent_host_in_tx(&tx, anchor, host)?;
        Self::record_agent_publish_in_tx(&tx, request_id, row)?;
        self.record_custody_account_in_tx(
            &tx,
            super::CustodyAccountWrite {
                anchor,
                state,
                expected,
                is_new: expected.is_none(),
                source,
                now,
            },
        )?;
        let committed = RouterRedbStore::commit_notify_owner(&tx, &prepared)?;
        tx.commit().map_err(error)?;
        self.publish_notify_owner(&prepared, &committed)?;
        self.observe_custody_publication_commit();
        Ok(())
    }
}
