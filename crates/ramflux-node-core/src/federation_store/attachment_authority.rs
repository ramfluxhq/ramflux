// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable attachment-authority pin history (P25 N6a, M8 and L2). The history is never
//! deleted: withdrawal, restart and peer removal keep every row, so a generation floor
//! cannot be lowered by re-introducing an older signed record.
use super::FederationRedbStore;
use crate::NodeCoreError;
use crate::federation_attachment::{
    AuthorityAdoption, AuthorityPin, FederationAttachmentAuthority, Withdrawn,
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

const HISTORY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("attachment_authority_history_v1");
const COUNTER: TableDefinition<&str, u64> = TableDefinition::new("attachment_authority_nodes_v1");
const COUNTER_KEY: &str = "nodes";
/// History rows are bounded; slots are never refunded.
pub const MAX_AUTHORITY_NODES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHistory {
    pub max_generation: u64,
    pub key_at_max: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

fn redb_err(e: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(e.to_string())
}

impl FederationRedbStore {
    /// Opening verifies that the row count equals the durable counter; a mismatch fails
    /// closed and is never repaired.
    pub(super) fn initialize_attachment_authority(&self) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(redb_err)?;
        let (rows, counter) = {
            let history = tx.open_table(HISTORY).map_err(redb_err)?;
            let counter = tx.open_table(COUNTER).map_err(redb_err)?;
            let stored = counter.get(COUNTER_KEY).map_err(redb_err)?.map(|v| v.value());
            (history.len().map_err(redb_err)?, stored)
        };
        match counter {
            None if rows == 0 => {
                tx.open_table(COUNTER)
                    .map_err(redb_err)?
                    .insert(COUNTER_KEY, 0)
                    .map_err(redb_err)?;
            }
            Some(n) if n == rows => {}
            _ => {
                return Err(redb_err("attachment authority history counter mismatch"));
            }
        }
        tx.commit().map_err(redb_err)
    }

    /// Read one node's history row.
    /// # Errors
    /// Storage failures.
    pub fn attachment_authority_history(
        &self,
        node_id: &str,
    ) -> Result<Option<AuthorityHistory>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_err)?;
        let table = tx.open_table(HISTORY).map_err(redb_err)?;
        table
            .get(node_id)
            .map_err(redb_err)?
            .map(|v| serde_json::from_slice(v.value()).map_err(redb_err))
            .transpose()
    }

    /// Number of history rows (equals the durable counter).
    /// # Errors
    /// Storage failures.
    pub fn attachment_authority_nodes(&self) -> Result<u64, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_err)?;
        let counter = tx.open_table(COUNTER).map_err(redb_err)?;
        Ok(counter.get(COUNTER_KEY).map_err(redb_err)?.map_or(0, |v| v.value()))
    }

    /// Decide availability for one freshly verified record in a single write transaction.
    /// # Errors
    /// `AttachmentAuthorityHistoryCapacity` for a 4097th node (nothing is written).
    pub fn adopt_attachment_authority(
        &self,
        node_id: &str,
        authority: Option<&FederationAttachmentAuthority>,
        negotiated: bool,
        now: u64,
    ) -> Result<AuthorityAdoption, NodeCoreError> {
        self.adopt_attachment_authority_capped(
            node_id,
            authority,
            negotiated,
            now,
            MAX_AUTHORITY_NODES,
        )
    }

    pub(crate) fn adopt_attachment_authority_capped(
        &self,
        node_id: &str,
        authority: Option<&FederationAttachmentAuthority>,
        negotiated: bool,
        now: u64,
        max_nodes: u64,
    ) -> Result<AuthorityAdoption, NodeCoreError> {
        let Some(authority) = authority.filter(|_| negotiated) else {
            return Ok(AuthorityAdoption::Unavailable(Withdrawn::Absent));
        };
        let key = authority
            .validate()
            .map_err(|_| redb_err("attachment authority pin is not canonical"))?;
        let pin = AuthorityPin { generation: authority.generation, key };
        let tx = self.db.begin_write().map_err(redb_err)?;
        let existing: Option<AuthorityHistory> = tx
            .open_table(HISTORY)
            .map_err(redb_err)?
            .get(node_id)
            .map_err(redb_err)?
            .map(|v| serde_json::from_slice(v.value()).map_err(redb_err))
            .transpose()?;
        let row = match existing {
            None => {
                let nodes = tx
                    .open_table(COUNTER)
                    .map_err(redb_err)?
                    .get(COUNTER_KEY)
                    .map_err(redb_err)?
                    .map_or(0, |v| v.value());
                if nodes >= max_nodes {
                    return Err(NodeCoreError::AttachmentAuthorityHistoryCapacity);
                }
                tx.open_table(COUNTER)
                    .map_err(redb_err)?
                    .insert(COUNTER_KEY, nodes + 1)
                    .map_err(redb_err)?;
                AuthorityHistory {
                    max_generation: pin.generation,
                    key_at_max: authority.signing_public_key.clone(),
                    first_seen: now,
                    last_seen: now,
                }
            }
            Some(row) if pin.generation > row.max_generation => AuthorityHistory {
                max_generation: pin.generation,
                key_at_max: authority.signing_public_key.clone(),
                last_seen: now,
                ..row
            },
            Some(row) if pin.generation == row.max_generation => {
                if row.key_at_max != authority.signing_public_key {
                    return Ok(AuthorityAdoption::Unavailable(Withdrawn::Substitution));
                }
                AuthorityHistory { last_seen: now, ..row }
            }
            Some(_) => return Ok(AuthorityAdoption::Unavailable(Withdrawn::Rollback)),
        };
        tx.open_table(HISTORY)
            .map_err(redb_err)?
            .insert(node_id, serde_json::to_vec(&row).map_err(redb_err)?.as_slice())
            .map_err(redb_err)?;
        tx.commit().map_err(redb_err)?;
        Ok(AuthorityAdoption::Available(pin))
    }
}

#[cfg(test)]
mod tests;
