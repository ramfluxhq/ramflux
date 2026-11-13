// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore Reaction registers using the same immutable signed order as live receive.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use ramflux_protocol::message as g;
use rusqlite::{OptionalExtension, params};

#[derive(serde::Deserialize)]
struct Register {
    identity: g::EventIdentity,
    reaction: g::Reaction,
}

fn order(bytes: &[u8]) -> Result<g::identity::EventOrder, StorageError> {
    let register: Register = serde_json::from_slice(bytes)?;
    g::identity::verify(&register.identity).map_err(|_| StorageError::AuthorizationRejected)?;
    if register.reaction.operation_id != register.identity.id {
        return Err(StorageError::AuthorizationRejected);
    }
    g::identity::order_key(&register.identity).map_err(|_| StorageError::AuthorizationRejected)
}

impl BackupDatabase {
    pub(super) fn merge_reaction_registers(&self) -> Result<(), StorageError> {
        self.require_reaction_receipts_agree()?;
        let mut statement = self.db.prepare(
            "SELECT state_kind,state_json FROM incoming.runtime_actor_state r
             WHERE state_kind LIKE 'routed/reaction/%'
             AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e
               WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state'
               AND e.row_id=r.rowid)",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (key, incoming) = row?;
            let incoming_order = order(&incoming)?;
            let local: Option<Vec<u8>> = self
                .db
                .query_row(
                    "SELECT state_json FROM main.runtime_actor_state WHERE state_kind=?1",
                    [&key],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(local) = local {
                if order(&local)? >= incoming_order {
                    continue;
                }
                self.db.execute(
                    "UPDATE main.runtime_actor_state SET state_json=?2 WHERE state_kind=?1",
                    params![key, incoming],
                )?;
            }
            // Missing keys are inserted together with their operation receipts and bindings
            // by the generic merge. Collisions already hold the signed winner above.
        }
        Ok(())
    }
    fn require_reaction_receipts_agree(&self) -> Result<(), StorageError> {
        let mut statement = self.db.prepare(
            "SELECT l.state_json,r.state_json FROM incoming.runtime_actor_state r
             JOIN main.runtime_actor_state l USING(state_kind)
             WHERE r.state_kind LIKE 'routed/reaction-operation/%'
             AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e
               WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state'
               AND e.row_id=r.rowid)",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (local, incoming) = row?;
            let local: g::Reaction = serde_json::from_slice(&local)?;
            let incoming: g::Reaction = serde_json::from_slice(&incoming)?;
            if local != incoming {
                return Err(StorageError::AuthorizationRejected);
            }
        }
        Ok(())
    }
}
