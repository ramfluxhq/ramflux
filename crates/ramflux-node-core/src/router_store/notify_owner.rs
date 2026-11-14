// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Router owner publications share a transaction with their remote notification fences.

use super::{
    NodeCoreError, Read, ReadableDatabase, ReadableTable, ReadableTableMetadata, RouterRedbStore,
    TableDefinition,
};
use crate::{
    custody_authority::CustodyAccountState,
    send_authority::{
        AuthorityClient, AuthorityMutation, AuthorityOrigin, AuthorityPhase, AuthorityReadPurpose,
        AuthorityReadRefusal, AuthorityReadReply, AuthorityReadRequest, AuthorityReadResult,
        AuthorityRecord, AuthorityRpc, AuthorityScope, AuthorityUpdate, PreparedAuthority,
        SendAuthorityError,
    },
};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_accounts_v3");
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

impl RouterRedbStore {
    /// # Errors
    /// Refuses duplicate configuration or unavailable OS randomness.
    pub fn configure_owner_send_authority(
        &self,
        rpc: Arc<dyn AuthorityRpc>,
    ) -> Result<(), NodeCoreError> {
        self.notify_authority
            .set(Arc::new(AuthorityClient::new(rpc)?))
            .map_err(|_| SendAuthorityError::Conflict.into())
    }

    pub(crate) fn prepare_notify_owner(
        &self,
        state: &CustodyAccountState,
        now: u64,
    ) -> Result<Vec<PreparedAuthority>, NodeCoreError> {
        self.prune_notify_owner(now)?;
        let anchor = &state.publication.record.body.account_anchor;
        let tx = self.db.begin_read().map_err(error)?;
        let previous = account(&tx, anchor)?;
        let mut targets = BTreeSet::new();
        for state in previous.iter().chain(std::iter::once(state)) {
            for device in &state.publication.record.body.devices {
                targets.insert(
                    ramflux_protocol::qualified_device_id(anchor, &device.device_id)
                        .map_err(error)?,
                );
            }
        }
        if targets.len() > 128 {
            return Err(SendAuthorityError::Capacity.into());
        }
        let mut enrolled = Vec::new();
        for target in targets {
            if AuthorityOrigin::pending(
                &self.db,
                &AuthorityScope::Owner { target_delivery_id: target.clone() },
            )?
            .is_some()
            {
                enrolled.push(target);
            }
        }
        let payload = ramflux_protocol::canonical_json_bytes(state).map_err(error)?;
        let mut records = enrolled
            .into_iter()
            .map(|target| {
                owner_record(&tx, state, &target, now)
                    .map(|record| (target, record, anchor.clone(), payload.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The parent's commit also changes these derived records. Close every dependent
        // mirror before that commit, with its exact unchanged child state as recovery data.
        for scope in AuthorityOrigin::dependent_owner_scopes(&self.db, anchor)? {
            let AuthorityScope::Owner { target_delivery_id } = scope else {
                return Err(SendAuthorityError::Invalid.into());
            };
            let child = ramflux_protocol::parse_qualified_device_id(&target_delivery_id)
                .map_err(error)?
                .map(|(root, _)| root)
                .ok_or(SendAuthorityError::Invalid)?;
            let child_state = account(&tx, &child)?.ok_or(SendAuthorityError::Invalid)?;
            let record =
                owner_record_with_parent(&tx, &child_state, &target_delivery_id, now, Some(state))?;
            records.push((
                target_delivery_id,
                record,
                child,
                ramflux_protocol::canonical_json_bytes(&child_state).map_err(error)?,
            ));
        }
        drop(tx);
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let client = self.notify_authority.get().ok_or(SendAuthorityError::Closed)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut prepared = Vec::new();
        for (target, record, root, payload) in records {
            prepared.push(client.prepare(
                &self.db,
                AuthorityUpdate {
                    scope: &AuthorityScope::Owner { target_delivery_id: target },
                    record: &record,
                    recipient_root: &root,
                    slot_id: None,
                    desired_payload: &payload,
                    deadline,
                },
            )?);
        }
        Ok(prepared)
    }

    /// Collect denied owner components only after their fixed replay horizon.
    /// # Errors
    /// Uncertain writes or a missing retirement ACK retain the reservation for survey retry.
    pub fn prune_notify_owner(&self, now: u64) -> Result<usize, NodeCoreError> {
        let Some(client) = self.notify_authority.get() else { return Ok(0) };
        let mut count = 0;
        for (scope, row) in AuthorityOrigin::closed_shared_due(&self.db, now)? {
            let tx = self.db.begin_write().map_err(error)?;
            AuthorityOrigin::retire(&tx, &scope, &row.mutation)?;
            tx.commit().map_err(error)?;
            if !AuthorityOrigin::reservation_nonempty(&self.db, &row.mutation.reservation_id)? {
                client.retire_component(&row.reservation)?;
            }
            count += 1;
        }
        Ok(count)
    }

    pub(crate) fn commit_notify_owner(
        tx: &redb::WriteTransaction,
        prepared: &[PreparedAuthority],
    ) -> Result<Vec<AuthorityMutation>, NodeCoreError> {
        prepared
            .iter()
            .map(|row| {
                if row.mutation.phase == AuthorityPhase::Committed {
                    Ok(row.mutation.clone())
                } else {
                    AuthorityOrigin::commit_in_transaction(tx, &row.scope, &row.mutation)
                        .map_err(Into::into)
                }
            })
            .collect()
    }

    pub(crate) fn publish_notify_owner(
        &self,
        prepared: &[PreparedAuthority],
        committed: &[AuthorityMutation],
    ) -> Result<(), NodeCoreError> {
        let Some(client) = self.notify_authority.get() else { return Ok(()) };
        if prepared.len() != committed.len() {
            return Err(SendAuthorityError::Conflict.into());
        }
        for (row, mutation) in prepared.iter().zip(committed) {
            client.finish(&self.db, row, mutation)?;
        }
        Ok(())
    }

    fn enroll_notify_owner(
        &self,
        client: &AuthorityClient,
        request: &AuthorityReadRequest,
        anchor: &str,
        target_delivery_id: &str,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let state = account(&tx, anchor)?.ok_or(SendAuthorityError::Closed)?;
        let record = owner_record(&tx, &state, target_delivery_id, crate::now_unix_seconds())?;
        let payload = ramflux_protocol::canonical_json_bytes(&state).map_err(error)?;
        drop(tx);
        client.update(
            &self.db,
            AuthorityUpdate {
                scope: &request.scope,
                record: &record,
                recipient_root: anchor,
                slot_id: None,
                desired_payload: &payload,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            |tx, bytes| {
                let expected: CustodyAccountState =
                    ramflux_protocol::parse_i_json(bytes).map_err(error)?;
                let current = tx
                    .open_table(ACCOUNTS)
                    .map_err(error)?
                    .get(anchor)
                    .map_err(error)?
                    .map(|value| value.value().to_vec())
                    .ok_or(SendAuthorityError::Closed)?;
                let current: CustodyAccountState =
                    ramflux_protocol::parse_i_json(&current).map_err(error)?;
                if current != expected {
                    return Err(SendAuthorityError::Conflict.into());
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Read original owner evidence and its operation binding from one authoritative snapshot.
    /// # Errors
    /// Missing, closing and pre-restart coordination never grant current ownership.
    pub fn notify_owner_read(
        &self,
        request: &AuthorityReadRequest,
    ) -> Result<AuthorityReadReply, NodeCoreError> {
        request.validate()?;
        let AuthorityScope::Owner { target_delivery_id } = &request.scope else {
            return Err(SendAuthorityError::Invalid.into());
        };
        let (anchor, _) = ramflux_protocol::parse_qualified_device_id(target_delivery_id)
            .map_err(error)?
            .ok_or(SendAuthorityError::Invalid)?;
        if request.purpose == AuthorityReadPurpose::Current
            && let Some(client) = self.notify_authority.get()
        {
            let pending = AuthorityOrigin::pending(&self.db, &request.scope)?;
            if pending.is_none() {
                self.enroll_notify_owner(client, request, &anchor, target_delivery_id)?;
            }
            if !client.scope_ready(&request.scope)
                || pending.as_ref().is_some_and(|p| {
                    p.mutation.notify_boot != request.notify_boot
                        || p.mutation.phase != AuthorityPhase::Stable
                })
            {
                client.ensure_current(&self.db, &request.scope, |tx, bytes| {
                    let state: CustodyAccountState =
                        ramflux_protocol::parse_i_json(bytes).map_err(error)?;
                    let table = tx.open_table(ACCOUNTS).map_err(error)?;
                    // An unchanged owner resync cannot replay publication budgets or migration side effects.
                    let current =
                        table.get(anchor.as_str()).map_err(error)?.map(|v| v.value().to_vec());
                    let current = current
                        .as_deref()
                        .map(ramflux_protocol::parse_i_json::<CustodyAccountState>)
                        .transpose()
                        .map_err(error)?;
                    if current.as_ref() != Some(&state) {
                        return Err(SendAuthorityError::Conflict.into());
                    }
                    Ok(())
                })?;
            }
        }
        let tx = self.db.begin_read().map_err(error)?;
        let current = account(&tx, &anchor)?
            .as_ref()
            .map(|state| owner_record(&tx, state, target_delivery_id, crate::now_unix_seconds()))
            .transpose()?;
        let ready =
            self.notify_authority.get().is_some_and(|client| client.scope_ready(&request.scope));
        let result = if request.purpose == AuthorityReadPurpose::Current && !ready {
            AuthorityReadResult::Refused { reason: AuthorityReadRefusal::ResyncRequired }
        } else {
            AuthorityOrigin::read(
                &tx,
                &request.scope,
                &request.notify_boot,
                request.purpose,
                request.operation_id.as_deref(),
                current.as_ref(),
            )?
        };
        let actual_boot = AuthorityOrigin::binding(&tx, &request.scope)?
            .map(|row| row.notify_boot)
            .or_else(|| self.notify_authority.get().and_then(|client| client.known_boot()))
            .ok_or(SendAuthorityError::Closed)?;
        Ok(AuthorityReadReply {
            version: 1,
            request_id: request.request_id.clone(),
            notify_boot: actual_boot,
            scope: request.scope.clone(),
            result,
        })
    }
}

fn account(
    tx: &redb::ReadTransaction,
    anchor: &str,
) -> Result<Option<CustodyAccountState>, NodeCoreError> {
    let table = match tx.open_table(ACCOUNTS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(error(e)),
    };
    let Some(bytes) = table.get(anchor).map_err(error)? else { return Ok(None) };
    if bytes.value().len() > 16 * 1024 * 1024 {
        return Err(SendAuthorityError::Capacity.into());
    }
    ramflux_protocol::parse_i_json(bytes.value()).map(Some).map_err(error)
}

fn owner_record(
    tx: &redb::ReadTransaction,
    state: &CustodyAccountState,
    target: &str,
    now: u64,
) -> Result<AuthorityRecord, NodeCoreError> {
    owner_record_with_parent(tx, state, target, now, None)
}

fn owner_record_with_parent(
    tx: &redb::ReadTransaction,
    state: &CustodyAccountState,
    target: &str,
    now: u64,
    parent: Option<&CustodyAccountState>,
) -> Result<AuthorityRecord, NodeCoreError> {
    let denied = || AuthorityRecord::Owner {
        version: 1,
        target_delivery_id: target.into(),
        owner: None,
        branch_public_key: None,
        custody_authority: None,
        revoked: true,
    };
    let Some((anchor, device_id)) =
        ramflux_protocol::parse_qualified_device_id(target).map_err(error)?
    else {
        return Ok(denied());
    };
    let publication = &state.publication;
    if anchor != publication.record.body.account_anchor {
        return Err(SendAuthorityError::Invalid.into());
    }
    let convert = |value: &crate::CustodyPublication| ramflux_protocol::custody::Publication {
        record: value.record.clone(),
        compacted_ids: value.compacted_ids.clone(),
    };
    let master = &publication.record.body.master_certificate.body;
    let custodian = if master.custody_kind == ramflux_protocol::custody::CustodyKind::ExternalHuman
    {
        let actual = match parent {
            Some(parent)
                if parent.publication.record.body.account_anchor
                    == master.primary_device_ref.account_anchor =>
            {
                Some(parent.clone())
            }
            _ => account(tx, &master.primary_device_ref.account_anchor)?,
        };
        let Some(actual) = actual else { return Ok(denied()) };
        let verified =
            ramflux_crypto::custody::verify_record(&actual.publication.record, now, None, None)
                .map_err(error)?;
        if actual.pins.require_current(&verified).is_err() {
            return Ok(denied());
        }
        Some(convert(&actual.publication))
    } else {
        None
    };
    let evidence = ramflux_protocol::custody::CustodyAuthority {
        publication: convert(publication),
        custodian_publication: custodian,
    };
    let Ok(verified) = ramflux_crypto::custody::verify_publication(&evidence, now) else {
        return Ok(denied());
    };
    if state.pins.require_current(&verified).is_err() {
        return Ok(denied());
    }
    let Some(device) =
        publication.record.body.devices.iter().find(|row| row.device_id == device_id)
    else {
        return Ok(denied());
    };
    let owner = ramflux_protocol::custody::DeviceRef {
        account_anchor: anchor,
        device_id,
        device_epoch: device.device_epoch,
    };
    let Ok(branch) = verified.authorize(&owner, "register", now) else { return Ok(denied()) };
    Ok(AuthorityRecord::Owner {
        version: 1,
        target_delivery_id: target.into(),
        owner: Some(owner),
        branch_public_key: Some(branch.branch_signing_public_key.clone()),
        custody_authority: Some(Box::new(evidence)),
        revoked: false,
    })
}
