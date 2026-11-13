// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Tuple-owned retirement cannot race a delayed publication back into an open mirror.

use super::{
    AuthorityCallState, AuthorityPhase, AuthorityRecord, LocalAuthorityResource, Mirror,
    NodeCoreError, RECEIPT_SCOPES, ROWS, ReadableDatabase, ReadableTable, SendAuthorityError,
    SendAuthorityStore, TableDefinition, budget, encode, issuance, read_scope, reservation, rpc,
    same_operation, storage,
};

pub(super) const SHARED_DUE: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("notification_shared_authority_due_v1");
pub(super) const SHARED_TIMES: TableDefinition<&str, u64> =
    TableDefinition::new("notification_shared_authority_times_v1");
pub(super) const LOCAL_DUE: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("notification_local_root_due_v1");
pub(super) const LOCAL_TIMES: TableDefinition<&str, u64> =
    TableDefinition::new("notification_local_root_times_v1");
const SHARED_HORIZON: u64 = 604_800 + 120;

pub(super) fn shared_closed(record: &AuthorityRecord) -> bool {
    match record {
        AuthorityRecord::Owner { revoked: true, .. } => true,
        AuthorityRecord::LocalRows {
            resource: LocalAuthorityResource::TargetRoutes, rows, ..
        } => rows.iter().any(|row| row.key == "routes" && row.value.is_none()),
        _ => false,
    }
}

pub(super) fn shared_deadline(
    record: &AuthorityRecord,
    previous: Option<u64>,
) -> Result<Option<u64>, SendAuthorityError> {
    if shared_closed(record) {
        Ok(Some(
            previous.unwrap_or(
                crate::now_unix_seconds()
                    .checked_add(SHARED_HORIZON)
                    .ok_or(SendAuthorityError::Invalid)?,
            ),
        ))
    } else {
        Ok(None)
    }
}

pub(super) fn index_shared(
    tx: &redb::WriteTransaction,
    key: &str,
    at: Option<u64>,
) -> Result<(), SendAuthorityError> {
    let mut times = tx.open_table(SHARED_TIMES).map_err(storage)?;
    let previous = times.remove(key).map_err(storage)?.map(|v| v.value());
    if let Some(at) = previous {
        tx.open_table(SHARED_DUE).map_err(storage)?.remove((at, key)).map_err(storage)?;
    }
    if let Some(at) = at {
        times.insert(key, at).map_err(storage)?;
        tx.open_table(SHARED_DUE).map_err(storage)?.insert((at, key), 0).map_err(storage)?;
    }
    Ok(())
}

impl SendAuthorityStore {
    pub(crate) fn ensure_local_root(
        &self,
        root: &str,
    ) -> Result<reservation::ReservationReply, SendAuthorityError> {
        let identity = self.local_identity.lock().map_err(storage)?.clone();
        if reservation::require_origin(&self.db, &identity).is_err() {
            reservation::initialize(&self.db, 4096, std::slice::from_ref(&identity))?;
        }
        let receipt = reservation::local_receipt(
            &self.db,
            &identity,
            root,
            &self.boot,
            crate::now_unix_seconds(),
        )?;
        let horizon = reservation::orphan_horizon(
            &self.db,
            receipt.reservation_id.as_deref().ok_or(SendAuthorityError::Invalid)?,
        )?;
        let tx = self.db.begin_write().map_err(storage)?;
        let existing = tx
            .open_table(LOCAL_TIMES)
            .map_err(storage)?
            .get(root)
            .map_err(storage)?
            .map(|v| v.value());
        if existing.is_none() {
            tx.open_table(LOCAL_TIMES).map_err(storage)?.insert(root, horizon).map_err(storage)?;
            tx.open_table(LOCAL_DUE)
                .map_err(storage)?
                .insert((horizon, root), 0)
                .map_err(storage)?;
            budget::charge(&tx, root, None, true, "local_due", (root.len() * 2 + 32, 2))?;
        }
        tx.commit().map_err(storage)?;
        Ok(receipt)
    }

    pub(crate) fn prune_local_roots(
        &self,
        now: u64,
        mut empty: impl FnMut(&str) -> Result<bool, NodeCoreError>,
        mut cleanup: impl FnMut(&redb::WriteTransaction, &AuthorityRecord) -> Result<(), NodeCoreError>,
    ) -> Result<usize, NodeCoreError> {
        let identity = self.local_identity.lock().map_err(storage)?.clone();
        let tx = self.db.begin_read().map_err(storage)?;
        let keys = tx
            .open_table(LOCAL_DUE)
            .map_err(storage)?
            .range(..=(now, "\u{10ffff}"))
            .map_err(storage)?
            .take(128)
            .map(|entry| {
                entry.map(|(key, _)| (key.value().0, key.value().1.to_owned())).map_err(storage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(tx);
        let mut count = 0;
        for (at, root) in keys {
            let receipt = reservation::local_existing(&self.db, &identity, &root)?
                .ok_or(SendAuthorityError::Invalid)?;
            let id = receipt.reservation_id.as_deref().ok_or(SendAuthorityError::Invalid)?;
            let retired = if empty(&root)? {
                self.retire_component_scopes(id, now, &mut cleanup)?
            } else {
                None
            };
            let tx = self.db.begin_write().map_err(storage)?;
            tx.open_table(LOCAL_DUE)
                .map_err(storage)?
                .remove((at, root.as_str()))
                .map_err(storage)?;
            if let Some(horizon) = retired {
                reservation::notify_retired(
                    &tx,
                    id,
                    receipt.reservation_generation.ok_or(SendAuthorityError::Invalid)?,
                    horizon,
                )?;
                let next = now.checked_add(60).ok_or(SendAuthorityError::Invalid)?;
                tx.open_table(LOCAL_TIMES)
                    .map_err(storage)?
                    .insert(root.as_str(), next)
                    .map_err(storage)?;
                tx.open_table(LOCAL_DUE)
                    .map_err(storage)?
                    .insert((next, root.as_str()), 0)
                    .map_err(storage)?;
            } else {
                let next = now.checked_add(60).ok_or(SendAuthorityError::Invalid)?;
                tx.open_table(LOCAL_TIMES)
                    .map_err(storage)?
                    .insert(root.as_str(), next)
                    .map_err(storage)?;
                tx.open_table(LOCAL_DUE)
                    .map_err(storage)?
                    .insert((next, root.as_str()), 0)
                    .map_err(storage)?;
            }
            tx.commit().map_err(storage)?;
            if retired.is_some() {
                reservation::apply(
                    &self.db,
                    &identity,
                    &reservation::ReservationRequest {
                        version: 1,
                        request_id: rpc::random_id()?,
                        operation_id: receipt.operation_id,
                        recipient_root: root.clone(),
                        slot_id: None,
                        reservation_id: receipt.reservation_id,
                        reservation_generation: receipt.reservation_generation,
                        origin_incarnation: receipt.origin_incarnation,
                        action: reservation::ReservationAction::Retire,
                    },
                    now,
                )?;
                let tx = self.db.begin_write().map_err(storage)?;
                let next = tx
                    .open_table(LOCAL_TIMES)
                    .map_err(storage)?
                    .remove(root.as_str())
                    .map_err(storage)?
                    .map(|v| v.value());
                if let Some(next) = next {
                    tx.open_table(LOCAL_DUE)
                        .map_err(storage)?
                        .remove((next, root.as_str()))
                        .map_err(storage)?;
                }
                budget::uncharge(&tx, &root, None, true, "local_due")?;
                tx.commit().map_err(storage)?;
                count += 1;
            }
        }
        reservation::prune(&self.db, now)?;
        Ok(count)
    }

    pub(super) fn retire_component_scopes(
        &self,
        id: &str,
        now: u64,
        mut cleanup: impl FnMut(&redb::WriteTransaction, &AuthorityRecord) -> Result<(), NodeCoreError>,
    ) -> Result<Option<u64>, SendAuthorityError> {
        let Some(records) = self.retirable_scopes(id, now)? else { return Ok(None) };
        let keys = records.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(Some(reservation::orphan_horizon(&self.db, id)?));
        }
        self.close_retiring_scopes(&records)?;
        let tx = self.db.begin_write().map_err(storage)?;
        let mut retired_wakes = Vec::new();
        {
            let mut table = tx.open_table(ROWS).map_err(storage)?;
            for (key, row) in &records {
                let current = read_scope(&table, key)?.ok_or(SendAuthorityError::Conflict)?;
                if !same_operation(&current.mutation, &row.mutation) {
                    return Err(SendAuthorityError::Conflict);
                }
                cleanup(&tx, &row.desired).map_err(storage)?;
                table.remove(key.as_str()).map_err(storage)?;
                tx.open_table(RECEIPT_SCOPES)
                    .map_err(storage)?
                    .remove((id, key.as_str()))
                    .map_err(storage)?;
                if let AuthorityRecord::Call { recipient_root, start_digest, .. } = &row.desired {
                    retired_wakes.extend(
                        crate::notify::retire_call_wakes(&tx, recipient_root, start_digest, now)
                            .map_err(storage)?,
                    );
                    let body = serde_json::json!({"recipient_root":recipient_root,"start_digest":start_digest});
                    let slot = ramflux_crypto::blake3_256_base64url(
                        "ramflux.notification.call_slot.v1\0",
                        &ramflux_protocol::canonical_json_bytes(&body).map_err(storage)?,
                    );
                    budget::uncharge(
                        &tx,
                        recipient_root,
                        Some(&slot),
                        true,
                        &format!("scope:{key}"),
                    )?;
                } else {
                    let root = reservation::root(&self.db, id)?;
                    budget::uncharge(&tx, &root, None, true, &format!("scope:{key}"))?;
                    if let Some(at) = row.shared_retire_after {
                        tx.open_table(SHARED_DUE)
                            .map_err(storage)?
                            .remove((at, key.as_str()))
                            .map_err(storage)?;
                        tx.open_table(SHARED_TIMES)
                            .map_err(storage)?
                            .remove(key.as_str())
                            .map_err(storage)?;
                    }
                }
            }
        }
        tx.commit().map_err(storage)?;
        let mut gate = self.gate.lock().map_err(storage)?;
        for wake in retired_wakes {
            gate.wakes.remove(&wake);
        }
        for key in keys {
            if gate.get(&key).is_some_and(|mirror| mirror.retiring) {
                gate.remove(&key);
            }
        }
        Ok(Some(now))
    }
    fn close_retiring_scopes(
        &self,
        records: &[(String, super::DurableScope)],
    ) -> Result<(), SendAuthorityError> {
        let sizes = records
            .iter()
            .map(|(key, row)| Ok((key.clone(), encode(row)?.len())))
            .collect::<Result<std::collections::BTreeMap<_, _>, SendAuthorityError>>()?;
        {
            let mut gate = self.gate.lock().map_err(storage)?;
            for (key, row) in records {
                gate.loading.remove(key);
                if !gate.contains_key(key) {
                    let bytes = *sizes.get(key).ok_or(SendAuthorityError::Invalid)?;
                    issuance::cache_room(&mut gate, key, bytes)?;
                    gate.insert(
                        key.clone(),
                        Mirror {
                            scope: row.clone(),
                            open: false,
                            retiring: true,
                            encoded_bytes: bytes,
                        },
                    );
                }
                if let Some(mirror) = gate.get_mut(key) {
                    if !same_operation(&mirror.scope.mutation, &row.mutation) {
                        return Err(SendAuthorityError::Conflict);
                    }
                    mirror.open = false;
                    mirror.retiring = true;
                }
            }
        }
        Ok(())
    }

    fn retirable_scopes(
        &self,
        id: &str,
        now: u64,
    ) -> Result<Option<Vec<(String, super::DurableScope)>>, SendAuthorityError> {
        let tx = self.db.begin_read().map_err(storage)?;
        let index = tx.open_table(RECEIPT_SCOPES).map_err(storage)?;
        let keys = index
            .range((id, "")..=(id, "\u{10ffff}"))
            .map_err(storage)?
            .take(129)
            .map(|entry| entry.map(|(key, _)| key.value().1.to_owned()).map_err(storage))
            .collect::<Result<Vec<_>, _>>()?;
        if keys.len() > 128 {
            return Err(SendAuthorityError::Capacity);
        }
        let table = tx.open_table(ROWS).map_err(storage)?;
        let mut records = Vec::new();
        for key in &keys {
            let row = read_scope(&table, key)?.ok_or(SendAuthorityError::Invalid)?;
            if shared_closed(&row.desired) && row.mutation.phase == AuthorityPhase::Stable {
                if matches!(row.desired, AuthorityRecord::LocalRows { .. })
                    && row.shared_retire_after.is_none_or(|at| at > now)
                {
                    return Ok(None);
                }
                records.push((key.clone(), row));
                continue;
            }
            let AuthorityRecord::Call {
                state,
                terminal_at: Some(terminal),
                signed_start,
                pending_cancel,
                ..
            } = &row.desired
            else {
                return Ok(None);
            };
            let intent = signed_start
                .as_ref()
                .or(pending_cancel.as_ref())
                .ok_or(SendAuthorityError::Invalid)?;
            if matches!(state, AuthorityCallState::Ringing | AuthorityCallState::Answered)
                || now < intent.body.expires_at.max(*terminal).saturating_add(120)
            {
                return Ok(None);
            }
            if row.mutation.phase != AuthorityPhase::Stable {
                return Ok(None);
            }
            records.push((key.clone(), row));
        }
        drop(table);
        drop(index);
        drop(tx);
        Ok(Some(records))
    }
}
