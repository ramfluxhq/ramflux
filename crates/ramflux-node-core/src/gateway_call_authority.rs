// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway's durable call authority adapter. A stored call alone is not a send permit.

use super::{
    CALL_INTENT, GatewayRedbStore, IntentRow, IntentState, NodeCoreError, ReadableDatabase,
    ReadableTable, WakeOwnerLookup, call_ref_key, digest_key, event_key, find_row, load_row,
    owner_matches, redb_error, rejected, retention, save_row, wake_key,
};
use crate::send_authority::{
    AuthorityCallState, AuthorityClient, AuthorityOrigin, AuthorityPhase, AuthorityReadPurpose,
    AuthorityReadRefusal, AuthorityReadReply, AuthorityReadRequest, AuthorityReadResult,
    AuthorityRecord, AuthorityRpc, AuthorityScope, AuthorityUpdate, SendAuthorityError,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StagedCall {
    expected_hash: Option<String>,
    row: IntentRow,
    silence: Option<String>,
}

impl GatewayRedbStore {
    /// A stream may negotiate correlated calls only with its durable coordinator configured.
    #[must_use]
    pub fn call_resolution_configured(&self) -> bool {
        self.call_authority.get().is_some()
    }
    /// # Errors
    /// A wake alias, call reference and signed context must all name the same stored Start.
    pub fn validate_call_owner_context(
        &self,
        lookup: &WakeOwnerLookup<'_>,
        context: &ramflux_protocol::CallSubmitContext,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let row = find_row(&table, lookup.wake_id, lookup.call_ref)?.ok_or_else(rejected)?;
        if row.start_digest != context.start_digest
            || row.call_ref != context.call_ref
            || !owner_matches(&row, lookup.owner_device, lookup.owner_epoch)
        {
            return Err(rejected());
        }
        Ok(())
    }

    /// # Errors
    /// Returns a typed refusal if the origin was configured twice or randomness fails.
    pub fn configure_call_send_authority(
        &self,
        rpc: Arc<dyn AuthorityRpc>,
    ) -> Result<(), NodeCoreError> {
        let client = Arc::new(AuthorityClient::new(rpc)?);
        self.call_authority.set(client).map_err(|_| SendAuthorityError::Conflict)?;
        Ok(())
    }

    /// Metadata and original Start/terminal evidence are read from the same disk snapshot.
    /// # Errors
    /// Unknown scopes, old boots and unsynchronized origin restarts never yield current authority.
    pub fn call_authority_read(
        &self,
        request: &AuthorityReadRequest,
    ) -> Result<AuthorityReadReply, NodeCoreError> {
        request.validate()?;
        if request.version != 1 {
            return Err(SendAuthorityError::Invalid.into());
        }
        let AuthorityScope::Call { start_digest } = &request.scope else {
            return Err(SendAuthorityError::Invalid.into());
        };
        if request.purpose == AuthorityReadPurpose::Current
            && let Some(client) = self.call_authority.get()
        {
            let pending = AuthorityOrigin::pending(&self.db, &request.scope)?;
            if !client.scope_ready(&request.scope)
                || pending.as_ref().is_some_and(|p| {
                    p.mutation.notify_boot != request.notify_boot
                        || p.mutation.phase != AuthorityPhase::Stable
                })
            {
                client.ensure_current(&self.db, &request.scope, |tx, bytes| {
                    let staged: StagedCall =
                        ramflux_protocol::parse_i_json(bytes).map_err(redb_error)?;
                    persist_staged(tx, &staged)
                })?;
            }
        }
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
        let row = load_row(&table, &digest_key(start_digest))?;
        let current = row.as_ref().map(authority_record).transpose()?;
        let ready =
            self.call_authority.get().is_some_and(|client| client.scope_ready(&request.scope));
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
            .or_else(|| self.call_authority.get().and_then(|client| client.known_boot()))
            .ok_or(SendAuthorityError::Closed)?;
        Ok(AuthorityReadReply {
            version: 1,
            request_id: request.request_id.clone(),
            notify_boot: actual_boot,
            scope: request.scope.clone(),
            result,
        })
    }

    pub(super) fn recover_call_scope(&self, digest: &str) -> Result<(), NodeCoreError> {
        let Some(client) = self.call_authority.get() else { return Ok(()) };
        let scope = AuthorityScope::Call { start_digest: digest.into() };
        let Some(pending) = AuthorityOrigin::pending(&self.db, &scope)? else { return Ok(()) };
        if pending.mutation.phase != AuthorityPhase::Stable
            || !client.scope_ready(&scope)
            || client.known_boot().is_some_and(|boot| boot != pending.mutation.notify_boot)
        {
            drop(pending);
            client.ensure_current(&self.db, &scope, |tx, bytes| {
                let staged: StagedCall =
                    ramflux_protocol::parse_i_json(bytes).map_err(redb_error)?;
                persist_staged(tx, &staged)
            })?;
        }
        Ok(())
    }

    pub(super) fn sync_call_row(
        &self,
        expected: Option<&IntentRow>,
        row: &IntentRow,
        silence: Option<String>,
    ) -> Result<(), NodeCoreError> {
        let staged = StagedCall {
            expected_hash: expected.map(row_hash).transpose()?,
            row: row.clone(),
            silence,
        };
        if let Some(client) = self.call_authority.get() {
            let scope = AuthorityScope::Call { start_digest: row.start_digest.clone() };
            let record = authority_record(row)?;
            let root = recipient_root(row)?;
            let slot = call_slot(&root, &row.start_digest)?;
            let payload = serde_json::to_vec(&staged)
                .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
            client.update(
                &self.db,
                AuthorityUpdate {
                    scope: &scope,
                    record: &record,
                    recipient_root: &root,
                    slot_id: Some(&slot),
                    desired_payload: &payload,
                    deadline: Instant::now() + Duration::from_secs(10),
                },
                |tx, bytes| {
                    if bytes.len() > 65536 {
                        return Err(SendAuthorityError::Capacity.into());
                    }
                    let staged: StagedCall = ramflux_protocol::parse_i_json(bytes)
                        .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
                    persist_staged(tx, &staged)
                },
            )
        } else {
            let tx = self.db.begin_write().map_err(redb_error)?;
            persist_staged(&tx, &staged)?;
            tx.commit().map_err(redb_error)
        }
    }
}

fn persist_staged(tx: &redb::WriteTransaction, staged: &StagedCall) -> Result<(), NodeCoreError> {
    let row = &staged.row;
    let root = recipient_root(row)?;
    let slot = call_slot(&root, &row.start_digest)?;
    let encoded = ramflux_protocol::canonical_json_bytes(row).map_err(redb_error)?;
    let mut charges = vec![
        (digest_key(&row.start_digest), encoded.len()),
        (
            event_key(
                &row.source_identity,
                row.source_epoch,
                &row.source_event_id,
                &row.target_delivery_id,
            ),
            row.start_digest.len(),
        ),
    ];
    if let Some(wake) = row.wake_id.as_deref() {
        charges.push((wake_key(wake), row.start_digest.len()));
    }
    if !row.call_ref.is_empty() {
        charges.push((call_ref_key(&row.call_ref), row.start_digest.len()));
    }
    charges.extend(row.silenced_envelopes.iter().map(|key| (key.clone(), 1)));
    if let Some(silence) = &staged.silence {
        charges.push((silence.clone(), 1));
    }
    crate::send_authority::charge_origin_rows(tx, &root, &slot, &charges)?;
    let mut table = tx.open_table(CALL_INTENT).map_err(redb_error)?;
    let key = digest_key(&row.start_digest);
    let existing = load_row(&table, &key)?;
    let old_hash = existing.as_ref().map(row_hash).transpose()?;
    retention::index(tx, existing.as_ref(), row)?;
    if old_hash != Some(row_hash(row)?) {
        if old_hash != staged.expected_hash {
            return Err(SendAuthorityError::Conflict.into());
        }
        save_row(&mut table, &key, row)?;
    }
    let event = event_key(
        &row.source_identity,
        row.source_epoch,
        &row.source_event_id,
        &row.target_delivery_id,
    );
    table.insert(event.as_str(), row.start_digest.as_bytes()).map_err(redb_error)?;
    if let Some(wake) = row.wake_id.as_deref() {
        table.insert(wake_key(wake).as_str(), row.start_digest.as_bytes()).map_err(redb_error)?;
    }
    if !row.call_ref.is_empty() {
        table
            .insert(call_ref_key(&row.call_ref).as_str(), row.start_digest.as_bytes())
            .map_err(redb_error)?;
    }
    for silence in &row.silenced_envelopes {
        table.insert(silence.as_str(), b"1".as_slice()).map_err(redb_error)?;
    }
    if let Some(silence) = staged.silence.as_deref() {
        table.insert(silence, b"1".as_slice()).map_err(redb_error)?;
    }
    Ok(())
}

pub(super) fn row_hash(row: &IntentRow) -> Result<String, NodeCoreError> {
    let bytes = ramflux_protocol::canonical_json_bytes(row)
        .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url("ramflux.notification.call_origin_row.v1\0", &bytes))
}

pub(super) fn recipient_root(row: &IntentRow) -> Result<String, NodeCoreError> {
    ramflux_protocol::parse_qualified_device_id(&row.target_device)
        .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?
        .map(|(root, _)| root)
        .ok_or_else(rejected)
}

pub(super) fn call_slot(root: &str, digest: &str) -> Result<String, NodeCoreError> {
    let bytes = ramflux_protocol::canonical_json_bytes(
        &serde_json::json!({"recipient_root":root,"start_digest":digest}),
    )
    .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url("ramflux.notification.call_slot.v1\0", &bytes))
}

fn authority_record(row: &IntentRow) -> Result<AuthorityRecord, NodeCoreError> {
    let state = match row.state {
        IntentState::Open => AuthorityCallState::Ringing,
        IntentState::Answered => AuthorityCallState::Answered,
        IntentState::Rejected => AuthorityCallState::Rejected,
        IntentState::Ended => AuthorityCallState::Ended,
        IntentState::Cancelled => AuthorityCallState::Cancelled,
        IntentState::Expired => AuthorityCallState::Expired,
    };
    let invite_hash = if row.signed_start.is_some() {
        let bytes = ramflux_protocol::canonical_json_bytes(&ramflux_protocol::encode_base64url(
            &row.encrypted_invite,
        ))
        .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
        Some(ramflux_crypto::blake3_256_base64url("ramflux.notification.call_invite.v1\0", &bytes))
    } else {
        None
    };
    Ok(AuthorityRecord::Call {
        version: 1,
        start_digest: row.start_digest.clone(),
        recipient_root: recipient_root(row)?,
        signed_start: row.signed_start.clone().map(Box::new),
        pending_cancel: row.pending_cancel.clone().map(Box::new),
        state,
        invite_hash,
        terminal_at: row.terminal_at,
    })
}
