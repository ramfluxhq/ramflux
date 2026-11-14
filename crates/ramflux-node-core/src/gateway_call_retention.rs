// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed call replay horizons and bounded indexed expiry/collection.

use super::{
    CALL_INTENT, GatewayRedbStore, IntentRow, IntentState, NodeCoreError, ReadableDatabase,
    ReadableTable, TableDefinition, authority, call_ref_key, digest_key, event_key, load_row,
    media_allowed_for, owner_matches, redb_error, rejected, wake_key,
};
use crate::send_authority::{AuthorityOrigin, AuthorityScope, SendAuthorityError};

pub(super) const DUE: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("gateway_call_authority_due_v1");
const CLEANUP_LIMIT: usize = 128;

pub(super) fn fix_horizon(row: &mut IntentRow) -> Result<(), NodeCoreError> {
    if !matches!(row.state, IntentState::Open | IntentState::Answered)
        && row.collect_after.is_none()
    {
        let terminal = *row.terminal_at.get_or_insert(crate::now_unix_seconds());
        row.collect_after = Some(
            row.expires_at
                .max(row.max_request_expires_at)
                .max(terminal)
                .checked_add(120)
                .ok_or(SendAuthorityError::Invalid)?,
        );
    }
    Ok(())
}

fn due(row: &IntentRow) -> Option<u64> {
    if row.state == IntentState::Open { Some(row.expires_at) } else { row.collect_after }
}

pub(super) fn index(
    tx: &redb::WriteTransaction,
    old: Option<&IntentRow>,
    row: &IntentRow,
) -> Result<(), NodeCoreError> {
    let mut table = tx.open_table(DUE).map_err(redb_error)?;
    if let Some(at) = old.and_then(due) {
        table.remove((at, row.start_digest.as_str())).map_err(redb_error)?;
    }
    if let Some(at) = due(row) {
        table.insert((at, row.start_digest.as_str()), 0).map_err(redb_error)?;
    }
    Ok(())
}

impl GatewayRedbStore {
    /// # Errors
    /// Missing, expired or foreign control contexts cannot extend a live call's retention.
    pub fn admit_call_context_request(
        &self,
        context: &ramflux_protocol::CallSubmitContext,
        participant: &str,
        epoch: u64,
        request_expires_at: u64,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        context.validate().map_err(|_| rejected())?;
        self.recover_call_scope(&context.start_digest)?;
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let row = load_row(&table, &digest_key(&context.start_digest))?.ok_or_else(rejected)?;
        if row.call_ref != context.call_ref
            || !owner_matches(&row, participant, epoch)
            || !media_allowed_for(row.state, now, row.expires_at)
        {
            return Err(rejected());
        }
        if request_expires_at <= row.max_request_expires_at {
            return Ok(());
        }
        let mut next = row.clone();
        next.max_request_expires_at = request_expires_at;
        drop(table);
        drop(tx);
        self.sync_call_row(Some(&row), &next, None)
    }

    /// Expire ringing calls, then retire closed authority only at its immutable denial horizon.
    /// # Errors
    /// Failed fencing or component retirement stays charged for exact retry/survey recovery.
    pub fn prune_call_authority(&self, now: u64) -> Result<usize, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(DUE).map_err(redb_error)?;
        let candidates = table
            .range(..=(now, "\u{10ffff}"))
            .map_err(redb_error)?
            .take(CLEANUP_LIMIT)
            .map(|entry| {
                entry.map(|(key, _)| (key.value().0, key.value().1.to_owned())).map_err(redb_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(table);
        drop(tx);
        let mut collected = 0;
        for (at, digest) in candidates {
            let tx = self.db.begin_read().map_err(redb_error)?;
            let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
            let Some(row) = load_row(&table, &digest_key(&digest))? else {
                return Err(SendAuthorityError::Invalid.into());
            };
            drop(table);
            drop(tx);
            if due(&row) != Some(at) {
                return Err(SendAuthorityError::Conflict.into());
            }
            if row.state == IntentState::Open {
                let mut next = row.clone();
                next.state = IntentState::Expired;
                next.terminal_at = Some(row.expires_at);
                fix_horizon(&mut next)?;
                self.sync_call_row(Some(&row), &next, None)?;
                continue;
            }
            if row.collect_after.is_none_or(|horizon| now < horizon) {
                continue;
            }
            let scope = AuthorityScope::Call { start_digest: digest.clone() };
            let pending = AuthorityOrigin::pending(&self.db, &scope)?;
            let root = authority::recipient_root(&row)?;
            let slot = authority::call_slot(&root, &digest)?;
            let mut keys = vec![
                digest_key(&digest),
                event_key(
                    &row.source_identity,
                    row.source_epoch,
                    &row.source_event_id,
                    &row.target_delivery_id,
                ),
                call_ref_key(&row.call_ref),
            ];
            if let Some(wake) = &row.wake_id {
                keys.push(wake_key(wake));
            }
            keys.extend(row.silenced_envelopes.iter().cloned());
            let tx = self.db.begin_write().map_err(redb_error)?;
            {
                let mut table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
                let current =
                    load_row(&table, &digest_key(&digest))?.ok_or(SendAuthorityError::Conflict)?;
                if authority::row_hash(&current)? != authority::row_hash(&row)? {
                    return Err(SendAuthorityError::Conflict.into());
                }
                for key in &keys {
                    table.remove(key.as_str()).map_err(redb_error)?;
                }
                tx.open_table(DUE)
                    .map_err(redb_error)?
                    .remove((at, digest.as_str()))
                    .map_err(redb_error)?;
                if let Some(pending) = &pending {
                    AuthorityOrigin::retire(&tx, &scope, &pending.mutation)?;
                }
                crate::send_authority::retire_origin_call_rows(&tx, &root, &slot, &keys)?;
            }
            tx.commit().map_err(redb_error)?;
            if let (Some(client), Some(pending)) = (self.call_authority.get(), pending) {
                client.retire_component(&pending.reservation)?;
            }
            collected += 1;
        }
        Ok(collected)
    }
}
