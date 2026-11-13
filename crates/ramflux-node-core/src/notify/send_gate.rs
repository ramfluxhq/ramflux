// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local encrypted row publication and final provider authority assembly.

use super::{
    NOTIFY_CREDENTIAL_TABLE, NOTIFY_PROVIDER_ATTEMPT_TABLE, NOTIFY_QUEUE_ENTRY_TABLE,
    NOTIFY_ROUTE_TABLE, NOTIFY_WAKE_DUE, NOTIFY_WAKE_LEDGER, NodeCoreError, NotifyQueueState,
    NotifyRedbStore, PreparedProviderPush, ProviderPushAttempt, PushProviderKind, Read,
    ReadableDatabase, WakeLedgerRow, ledger_row, notify_provider_attempt_key, routes,
    serialize_notify_provider_attempt_binary, serialize_notify_value,
};
use crate::send_authority::{
    AuthorityCallState, AuthorityPhase, AuthorityPin, AuthorityReadPurpose, AuthorityReadReply,
    AuthorityReadRequest, AuthorityReadResult, AuthorityRecord, AuthorityScope,
    LocalAuthorityResource, LocalAuthorityRow, SendAuthorityError, WakeIssuance, reservation,
};
use redb::{ReadableTable, TableDefinition};
use std::time::Instant;

const OWNERS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_route_authority_v1");
const MARKS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_route_high_water_v1");
const FENCES: TableDefinition<&str, (u64, u64)> = TableDefinition::new("notify_route_fence_v2");
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

pub(super) type RemoteAuthorityReader = dyn Fn(&AuthorityReadRequest, Instant) -> Result<AuthorityReadReply, NodeCoreError>
    + Send
    + Sync;

pub(super) struct WakeMapping {
    pub root: String,
    pub generation: u64,
}
pub(super) const DIAGNOSTICS: TableDefinition<(&str, &str), u8> =
    TableDefinition::new("notify_wake_diagnostic_index_v1");
pub(super) const CALL_WAKES: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("notify_call_wake_index_v1");
pub(super) const ROOT_WAKES: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("notify_shared_wake_index_v1");

impl NotifyRedbStore {
    /// Original admission deadline covering OAuth, readiness, lookup and issuance.
    /// # Errors
    /// Missing, pre-boot or expired wake memory refuses provider preparation.
    pub fn provider_push_deadline(
        &self,
        prepared: &PreparedProviderPush,
    ) -> Result<Instant, NodeCoreError> {
        let row = self
            .load_wake_ledger_row(&prepared.payload.wake_id)?
            .ok_or(SendAuthorityError::Closed)?;
        self.send_authority
            .wake_deadline(&prepared.payload.wake_id, &row.digest)
            .map_err(Into::into)
    }
    pub(super) fn charge_wake_work(
        tx: &redb::WriteTransaction,
        key: &str,
        row: &WakeLedgerRow,
        pushes: &[PreparedProviderPush],
    ) -> Result<(), NodeCoreError> {
        let Some(root) = &row.recipient_root else { return Ok(()) };
        if row.work_bytes == 0 {
            return Ok(());
        }
        let slot = row.start_digest.as_deref().map(|digest| call_slot(root, digest)).transpose()?;
        let mut bytes = usize::try_from(row.work_bytes).map_err(error)?;
        for push in pushes {
            let size = serde_json::to_vec(push).map_err(error)?.len();
            bytes = bytes
                .checked_add(size.checked_mul(2).ok_or(SendAuthorityError::Capacity)?)
                .ok_or(SendAuthorityError::Capacity)?;
        }
        crate::send_authority::charge_resource(
            tx,
            root,
            slot.as_deref(),
            true,
            &format!("work:{key}"),
            (bytes, 2 + u64::try_from(pushes.len()).map_err(error)?),
        )?;
        Ok(())
    }

    pub(super) fn charge_prepared_work(
        &self,
        key: &str,
        pushes: &[PreparedProviderPush],
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(error)?;
        let row = {
            let table = tx.open_table(NOTIFY_WAKE_LEDGER).map_err(error)?;
            ledger_row(&table, key)?
        };
        if let Some(row) = row {
            Self::charge_wake_work(&tx, key, &row, pushes)?;
        }
        tx.commit().map_err(error)
    }

    pub(super) fn charge_provider_diagnostic(
        &self,
        attempt: &ProviderPushAttempt,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(error)?;
        let row = {
            let table = tx.open_table(NOTIFY_WAKE_LEDGER).map_err(error)?;
            ledger_row(&table, &attempt.queue_id)?
        };
        if let Some(WakeLedgerRow { recipient_root: Some(root), .. }) = row {
            let key = notify_provider_attempt_key(&attempt.queue_id, 0, attempt)?;
            let bytes = serialize_notify_provider_attempt_binary(attempt)?;
            crate::send_authority::charge_resource(
                &tx,
                &root,
                None,
                true,
                &format!("attempt:{key}"),
                (2 * bytes.len() + 2 * key.len() + attempt.queue_id.len(), 3),
            )?;
            tx.open_table(DIAGNOSTICS)
                .map_err(error)?
                .insert((attempt.queue_id.as_str(), key.as_str()), 1)
                .map_err(error)?;
        }
        tx.commit().map_err(error)
    }

    /// Configure the exact authenticated origin reader; a missing reader never grants authority.
    pub fn set_send_authority_reader<F>(&mut self, read: F)
    where
        F: Fn(&AuthorityReadRequest, Instant) -> Result<AuthorityReadReply, NodeCoreError>
            + Send
            + Sync
            + 'static,
    {
        self.send_authority_reader = Some(Box::new(read));
    }

    pub(super) fn charge_wake_row(
        tx: &redb::WriteTransaction,
        key: &str,
        row: &WakeLedgerRow,
    ) -> Result<(), NodeCoreError> {
        let Some(root) = &row.recipient_root else {
            return Ok(());
        };
        let slot = row.start_digest.as_deref().map(|digest| call_slot(root, digest)).transpose()?;
        let bytes = serde_json::to_vec(row).map_err(error)?;
        crate::send_authority::charge_resource(
            tx,
            root,
            slot.as_deref(),
            true,
            &format!("wake:{key}"),
            (
                2 * bytes.len()
                    + 3 * key.len()
                    + row.start_digest.as_ref().map_or(0, String::len)
                    + 128,
                4,
            ),
        )?;
        if let Some(digest) = &row.start_digest {
            tx.open_table(CALL_WAKES)
                .map_err(error)?
                .insert((digest.as_str(), key), row.retain_until)
                .map_err(error)?;
        } else {
            tx.open_table(ROOT_WAKES)
                .map_err(error)?
                .insert((root.as_str(), key), row.retain_until)
                .map_err(error)?;
        }
        Ok(())
    }

    pub(super) fn wake_root(&self, target: &str) -> Result<String, NodeCoreError> {
        let root = ramflux_protocol::parse_qualified_device_id(target)
            .map_err(error)?
            .map_or_else(crate::send_authority::reservation::system_root, |(root, _)| root);
        self.send_authority.ensure_local_root(&root)?;
        Ok(root)
    }

    /// Remove expired journal copies before any coordinator retirement ACK releases capacity.
    /// # Errors
    /// A failed WAL barrier or local cleanup retains the component reservation.
    pub fn prune_notification_authority(&self, now: u64) -> Result<usize, NodeCoreError> {
        let now = self.send_authority.retention_clock(now)?;
        let _writer = self.local_writer.try_lock().map_err(|_| SendAuthorityError::Busy)?;
        self.prune_wake_ledger(now)?;
        self.send_authority.prune_local_roots(
            now,
            |root| {
                let tx = self.db.begin_read().map_err(error)?;
                if super::wake_admission::nonempty(&tx, root)? {
                    return Ok(false);
                }
                let table = tx.open_table(ROOT_WAKES).map_err(error)?;
                Ok(table
                    .range((root, "")..=(root, "\u{10ffff}"))
                    .map_err(error)?
                    .next()
                    .transpose()
                    .map_err(error)?
                    .is_none())
            },
            |tx, record| {
                let AuthorityRecord::LocalRows {
                    resource: LocalAuthorityResource::TargetRoutes,
                    scope_key,
                    ..
                } = record
                else {
                    return Err(SendAuthorityError::Invalid.into());
                };
                for definition in [NOTIFY_ROUTE_TABLE, OWNERS, MARKS] {
                    tx.open_table(definition)
                        .map_err(error)?
                        .remove(scope_key.as_str())
                        .map_err(error)?;
                }
                tx.open_table(FENCES).map_err(error)?.remove(scope_key.as_str()).map_err(error)?;
                Ok(())
            },
        )
    }

    pub(super) fn prune_wake_copies(&self, now: u64) -> Result<(), NodeCoreError> {
        if let Some(shards) = &self.wal_shards {
            for shard in shards {
                shard.store.prune_expired(now)?;
            }
        }
        Ok(())
    }

    /// Authenticate at the service boundary before calling this exact coordinator operation.
    /// # Errors
    /// Required WAL cleanup completes before a component can acknowledge retirement.
    pub fn authority_reservation_reply(
        &self,
        origin: &str,
        request: &reservation::ReservationRequest,
        now: u64,
    ) -> Result<reservation::ReservationReply, NodeCoreError> {
        if request.action == reservation::ReservationAction::Retire {
            self.prune_wake_ledger(now)?;
        }
        self.send_authority.reservation_reply(origin, request, now).map_err(Into::into)
    }

    pub(super) fn verified_call_mapping(
        &self,
        signed: &ramflux_protocol::SignedWakeV2,
    ) -> Result<Option<WakeMapping>, NodeCoreError> {
        let Some(digest) = signed.body.call_intent_digest.as_deref() else { return Ok(None) };
        let scope = AuthorityScope::Call { start_digest: digest.into() };
        let query = AuthorityReadRequest {
            version: 1,
            request_id: ramflux_protocol::encode_base64url(
                ramflux_crypto::random_32().map_err(error)?,
            ),
            notify_boot: self.send_authority.boot().into(),
            scope: scope.clone(),
            purpose: AuthorityReadPurpose::Current,
            operation_id: None,
        };
        let reply = self.send_authority_reader.as_ref().ok_or(SendAuthorityError::Closed)?(
            &query,
            self.send_authority.wake_deadline(
                &signed.body.wake_id,
                &ramflux_protocol::wake_request_digest(signed).map_err(error)?,
            )?,
        )?;
        if reply.version != 1
            || reply.request_id != query.request_id
            || reply.notify_boot != query.notify_boot
            || reply.scope != scope
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        let AuthorityReadResult::Record {
            phase: AuthorityPhase::Stable,
            generation,
            record_hash,
            record,
            ..
        } = reply.result
        else {
            return Err(SendAuthorityError::Closed.into());
        };
        record.verify_evidence(crate::now_unix_seconds())?;
        if record.record_hash()? != record_hash {
            return Err(SendAuthorityError::Invalid.into());
        }
        let AuthorityRecord::Call {
            recipient_root,
            signed_start: Some(start),
            state: AuthorityCallState::Ringing,
            ..
        } = record.as_ref()
        else {
            return Err(SendAuthorityError::Closed.into());
        };
        if start.body.target_delivery_id != signed.body.target_delivery_id
            || start.body.target_epoch != signed.body.target_owner_epoch
            || start.body.expires_at != signed.body.expires_at
            || ramflux_protocol::call_intent_digest(start).map_err(error)? != digest
        {
            return Err(SendAuthorityError::Conflict.into());
        }
        if self.send_authority.pin(&scope)?
            != (AuthorityPin { scope: scope.clone(), generation, record_hash })
        {
            return Err(SendAuthorityError::Closed.into());
        }
        Ok(Some(WakeMapping { root: recipient_root.clone(), generation }))
    }

    pub(super) fn resume_route_mutation(&self, target: &str) -> Result<(), NodeCoreError> {
        self.resume_local_mutation(&AuthorityScope::TargetRoutes {
            target_delivery_id: target.into(),
        })
    }

    pub(super) fn resume_local_mutation(
        &self,
        scope: &AuthorityScope,
    ) -> Result<(), NodeCoreError> {
        self.send_authority.resume_local(scope, |tx, record| {
            let AuthorityRecord::LocalRows { resource, scope_key, rows, .. } = record else {
                return Err(SendAuthorityError::Invalid.into());
            };
            for row in rows {
                let bytes = row
                    .value
                    .as_deref()
                    .map(ramflux_protocol::decode_base64url)
                    .transpose()
                    .map_err(error)?;
                if *resource == LocalAuthorityResource::TargetRoutes && row.key == "fence" {
                    let mut table = tx.open_table(FENCES).map_err(error)?;
                    if let Some(bytes) = bytes {
                        let fence: (u64, u64) =
                            ramflux_protocol::parse_i_json(&bytes).map_err(error)?;
                        table.insert(scope_key.as_str(), fence).map_err(error)?;
                    } else {
                        table.remove(scope_key.as_str()).map_err(error)?;
                    }
                } else {
                    let definition = match resource {
                        LocalAuthorityResource::TargetRoutes => match row.key.as_str() {
                            "routes" => NOTIFY_ROUTE_TABLE,
                            "owner" => OWNERS,
                            "marks" => MARKS,
                            _ => return Err(SendAuthorityError::Invalid.into()),
                        },
                        LocalAuthorityResource::Credential if row.key == *scope_key => {
                            NOTIFY_CREDENTIAL_TABLE
                        }
                        LocalAuthorityResource::Credential => {
                            return Err(SendAuthorityError::Invalid.into());
                        }
                    };
                    let mut table = tx.open_table(definition).map_err(error)?;
                    if let Some(bytes) = bytes {
                        table.insert(scope_key.as_str(), bytes.as_slice()).map_err(error)?;
                    } else {
                        table.remove(scope_key.as_str()).map_err(error)?;
                    }
                }
            }
            Ok(())
        })
    }

    pub(super) fn commit_route_transaction(
        &self,
        tx: redb::WriteTransaction,
        target: &str,
    ) -> Result<(), NodeCoreError> {
        let mut rows = Vec::new();
        for (name, definition) in
            [("routes", NOTIFY_ROUTE_TABLE), ("owner", OWNERS), ("marks", MARKS)]
        {
            let table = tx.open_table(definition).map_err(error)?;
            let value = table
                .get(target)
                .map_err(error)?
                .map(|v| ramflux_protocol::encode_base64url(v.value()));
            rows.push(LocalAuthorityRow { key: name.into(), value });
        }
        let fence =
            tx.open_table(FENCES).map_err(error)?.get(target).map_err(error)?.map(|v| v.value());
        rows.push(LocalAuthorityRow {
            key: "fence".into(),
            value: fence
                .map(|v| {
                    ramflux_protocol::canonical_json_bytes(&v)
                        .map(ramflux_protocol::encode_base64url)
                })
                .transpose()
                .map_err(error)?,
        });
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        tx.abort().map_err(error)?;
        let record = AuthorityRecord::LocalRows {
            version: 1,
            resource: LocalAuthorityResource::TargetRoutes,
            scope_key: target.into(),
            rows: rows.clone(),
        };
        self.send_authority.local_change(
            &AuthorityScope::TargetRoutes { target_delivery_id: target.into() },
            &record,
            |tx| {
                for row in rows {
                    let bytes = row
                        .value
                        .map(|v| ramflux_protocol::decode_base64url(&v))
                        .transpose()
                        .map_err(error)?;
                    if row.key == "fence" {
                        let mut table = tx.open_table(FENCES).map_err(error)?;
                        if let Some(bytes) = bytes {
                            let value: (u64, u64) =
                                ramflux_protocol::parse_i_json(&bytes).map_err(error)?;
                            table.insert(target, value).map_err(error)?;
                        } else {
                            table.remove(target).map_err(error)?;
                        }
                    } else {
                        let definition = match row.key.as_str() {
                            "routes" => NOTIFY_ROUTE_TABLE,
                            "owner" => OWNERS,
                            "marks" => MARKS,
                            _ => return Err(SendAuthorityError::Invalid.into()),
                        };
                        let mut table = tx.open_table(definition).map_err(error)?;
                        if let Some(bytes) = bytes {
                            table.insert(target, bytes.as_slice()).map_err(error)?;
                        } else {
                            table.remove(target).map_err(error)?;
                        }
                    }
                }
                Ok(())
            },
        )
    }

    pub(super) fn commit_credential_transaction(
        &self,
        tx: redb::WriteTransaction,
        id: &str,
    ) -> Result<(), NodeCoreError> {
        let value = tx
            .open_table(NOTIFY_CREDENTIAL_TABLE)
            .map_err(error)?
            .get(id)
            .map_err(error)?
            .map(|v| ramflux_protocol::encode_base64url(v.value()));
        tx.abort().map_err(error)?;
        let record = AuthorityRecord::LocalRows {
            version: 1,
            resource: LocalAuthorityResource::Credential,
            scope_key: id.into(),
            rows: vec![LocalAuthorityRow { key: id.into(), value: value.clone() }],
        };
        self.send_authority.local_change(
            &AuthorityScope::Credential { credential_id: id.into() },
            &record,
            |tx| {
                let mut table = tx.open_table(NOTIFY_CREDENTIAL_TABLE).map_err(error)?;
                if let Some(value) = value {
                    let bytes = ramflux_protocol::decode_base64url(&value).map_err(error)?;
                    table.insert(id, bytes.as_slice()).map_err(error)?;
                } else {
                    table.remove(id).map_err(error)?;
                }
                Ok(())
            },
        )
    }

    pub(super) fn replace_authority_snapshot(
        &self,
        state: &NotifyQueueState,
    ) -> Result<(), NodeCoreError> {
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        let tx = self.db.begin_read().map_err(error)?;
        let mut targets = std::collections::BTreeSet::new();
        for row in tx.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?.iter().map_err(error)? {
            let (key, _) = row.map_err(error)?;
            targets.insert(key.value().to_owned());
        }
        targets.extend(state.routes_by_device.keys().cloned());
        let mut credentials = std::collections::BTreeSet::new();
        for row in tx.open_table(NOTIFY_CREDENTIAL_TABLE).map_err(error)?.iter().map_err(error)? {
            let (key, _) = row.map_err(error)?;
            credentials.insert(key.value().to_owned());
        }
        credentials.extend(state.credentials_by_id.keys().cloned());
        drop(tx);
        for target in targets {
            self.resume_route_mutation(&target)?;
            let desired = state.routes_by_device.get(&target).cloned().unwrap_or_default();
            if self.load_notify_routes(&target)? == desired {
                continue;
            }
            let tx = self.db.begin_write().map_err(error)?;
            {
                let mut table = tx.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
                if desired.is_empty() {
                    table.remove(target.as_str()).map_err(error)?;
                } else {
                    let bytes = routes::seal(&self.route_key, &target, &desired)?;
                    table.insert(target.as_str(), bytes.as_slice()).map_err(error)?;
                }
            }
            self.commit_route_transaction(tx, &target)?;
        }
        for id in credentials {
            self.resume_local_mutation(&AuthorityScope::Credential { credential_id: id.clone() })?;
            let desired = state.credentials_by_id.get(&id);
            if self.load_notify_credential(&id)?.as_ref() == desired {
                continue;
            }
            let tx = self.db.begin_write().map_err(error)?;
            {
                let mut table = tx.open_table(NOTIFY_CREDENTIAL_TABLE).map_err(error)?;
                if let Some(value) = desired {
                    let bytes = serialize_notify_value(value)?;
                    table.insert(id.as_str(), bytes.as_slice()).map_err(error)?;
                } else {
                    table.remove(id.as_str()).map_err(error)?;
                }
            }
            self.commit_credential_transaction(tx, &id)?;
        }
        Ok(())
    }

    pub(super) fn prune_expired_routes(&self, now: u64) -> Result<usize, NodeCoreError> {
        const PAGE: usize = 128;
        let _writer = self.local_writer.try_lock().map_err(|_| SendAuthorityError::Busy)?;
        let after = self.route_expiry_cursor.lock().map_err(error)?.clone();
        let tx = self.db.begin_read().map_err(error)?;
        let table = tx.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
        let range = match after.as_deref() {
            Some(after) => {
                table.range::<&str>((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            }
            None => table.range::<&str>(..),
        }
        .map_err(error)?;
        let keys = range
            .take(PAGE)
            .map(|entry| {
                let (key, _) = entry.map_err(error)?;
                if key.value().len() > 512 {
                    return Err(SendAuthorityError::Invalid.into());
                }
                Ok(key.value().to_owned())
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        drop(table);
        drop(tx);
        let mut removed = 0;
        for target in &keys {
            self.resume_route_mutation(target)?;
            let mut values = self.load_notify_routes(target)?;
            let before = values.len();
            values.retain(|route| route.expires_at > now);
            if values.len() == before {
                continue;
            }
            removed += before - values.len();
            let tx = self.db.begin_write().map_err(error)?;
            {
                let mut table = tx.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
                if values.is_empty() {
                    table.remove(target.as_str()).map_err(error)?;
                    tx.open_table(OWNERS).map_err(error)?.remove(target.as_str()).map_err(error)?;
                } else {
                    let bytes = routes::seal(&self.route_key, target, &values)?;
                    table.insert(target.as_str(), bytes.as_slice()).map_err(error)?;
                }
            }
            self.commit_route_transaction(tx, target)?;
        }
        *self.route_expiry_cursor.lock().map_err(error)? =
            if keys.len() == PAGE { keys.last().cloned() } else { None };
        Ok(removed)
    }

    fn local_provider_pins(
        &self,
        prepared: &PreparedProviderPush,
    ) -> Result<Vec<AuthorityPin>, NodeCoreError> {
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        let target = prepared.route.device_delivery_id.as_str();
        let credential = prepared.credential.credential_id();
        let route_scope = AuthorityScope::TargetRoutes { target_delivery_id: target.into() };
        if self.send_authority.pin(&route_scope).is_err() {
            self.resume_local_mutation(&route_scope)?;
            let tx = self.db.begin_write().map_err(error)?;
            self.commit_route_transaction(tx, target)?;
        }
        let credential_scope = AuthorityScope::Credential { credential_id: credential.into() };
        if self.send_authority.pin(&credential_scope).is_err() {
            self.resume_local_mutation(&credential_scope)?;
            let tx = self.db.begin_write().map_err(error)?;
            self.commit_credential_transaction(tx, credential)?;
        }
        // These exact snapshots were used to construct the complete provider request.
        let routes = self.load_notify_routes(target)?;
        if !routes.iter().any(|row| row == &prepared.route)
            || self.load_notify_credential(credential)?.as_ref() != Some(&prepared.credential)
        {
            return Err(SendAuthorityError::Closed.into());
        }
        Ok(vec![
            self.send_authority.pin(&route_scope)?,
            self.send_authority.pin(&credential_scope)?,
        ])
    }

    fn remote_provider_pin(
        &self,
        scope: AuthorityScope,
        prepared: &PreparedProviderPush,
        deadline: Instant,
    ) -> Result<(AuthorityPin, u64), NodeCoreError> {
        let request = AuthorityReadRequest {
            version: 1,
            request_id: ramflux_protocol::encode_base64url(
                ramflux_crypto::random_32().map_err(error)?,
            ),
            notify_boot: self.send_authority.boot().into(),
            scope: scope.clone(),
            purpose: AuthorityReadPurpose::Current,
            operation_id: None,
        };
        let reply = self.send_authority_reader.as_ref().ok_or(SendAuthorityError::Closed)?(
            &request, deadline,
        )?;
        if reply.version != 1
            || reply.request_id != request.request_id
            || reply.notify_boot != request.notify_boot
            || reply.scope != scope
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        let AuthorityReadResult::Record {
            phase: AuthorityPhase::Stable,
            generation,
            record_hash,
            record,
            ..
        } = reply.result
        else {
            return Err(SendAuthorityError::Closed.into());
        };
        if record.record_hash()? != record_hash {
            return Err(SendAuthorityError::Invalid.into());
        }
        record.verify_evidence(crate::now_unix_seconds())?;
        match record.as_ref() {
            AuthorityRecord::Owner {
                target_delivery_id,
                owner: Some(owner),
                revoked: false,
                ..
            } if target_delivery_id == &prepared.route.device_delivery_id
                && owner.device_epoch == prepared.owner_epoch => {}
            AuthorityRecord::Call {
                signed_start: Some(start),
                state: AuthorityCallState::Ringing,
                ..
            } if start.body.target_delivery_id == prepared.route.device_delivery_id => {}
            _ => return Err(SendAuthorityError::Closed.into()),
        }
        let valid_until = match record.as_ref() {
            AuthorityRecord::Owner {
                owner: Some(owner),
                custody_authority: Some(evidence),
                ..
            } => {
                let cert = evidence
                    .publication
                    .record
                    .body
                    .devices
                    .iter()
                    .find(|device| device.device_id == owner.device_id)
                    .and_then(|device| device.branch_certificate.as_ref())
                    .ok_or(SendAuthorityError::Closed)?;
                let mut until = cert.body.expires_at;
                if let Some(custodian) = &evidence.custodian_publication {
                    let primary = &evidence
                        .publication
                        .record
                        .body
                        .master_certificate
                        .body
                        .primary_device_ref;
                    let cert = custodian
                        .record
                        .body
                        .devices
                        .iter()
                        .find(|device| device.device_id == primary.device_id)
                        .and_then(|device| device.branch_certificate.as_ref())
                        .ok_or(SendAuthorityError::Closed)?;
                    until = until.min(cert.body.expires_at);
                }
                until
            }
            AuthorityRecord::Call { signed_start: Some(start), .. } => start.body.expires_at,
            _ => return Err(SendAuthorityError::Closed.into()),
        };
        let pin = AuthorityPin { scope, generation, record_hash };
        if self.send_authority.pin(&pin.scope)? != pin {
            return Err(SendAuthorityError::Closed.into());
        }
        Ok((pin, valid_until))
    }

    /// Lookup and decode finish before the gate. The closure enqueues the owned full body once.
    /// # Errors
    /// Refuses missing coordination, stale snapshots, old-boot calls and terminal wake state.
    pub fn issue_provider_push<T>(
        &self,
        prepared: &PreparedProviderPush,
        issue: impl FnOnce() -> Result<T, NodeCoreError>,
    ) -> Result<T, NodeCoreError> {
        let row = self
            .load_wake_ledger_row(&prepared.payload.wake_id)?
            .ok_or(SendAuthorityError::Closed)?;
        let mut pins = self.local_provider_pins(prepared)?;
        let deadline = self.send_authority.wake_deadline(&prepared.payload.wake_id, &row.digest)?;
        let (owner, mut valid_until) = self.remote_provider_pin(
            AuthorityScope::Owner { target_delivery_id: prepared.route.device_delivery_id.clone() },
            prepared,
            deadline,
        )?;
        pins.push(owner);
        if let Some(start) = &row.start_digest {
            if row.authority_boot != self.send_authority.boot() {
                return Err(SendAuthorityError::Closed.into());
            }
            let (pin, until) = self.remote_provider_pin(
                AuthorityScope::Call { start_digest: start.clone() },
                prepared,
                deadline,
            )?;
            if row.call_generation != Some(pin.generation) {
                return Err(SendAuthorityError::Closed.into());
            }
            pins.push(pin);
            valid_until = valid_until.min(until);
        }
        self.send_authority.with_send_permit(
            WakeIssuance {
                wake_id: &prepared.payload.wake_id,
                digest: &row.digest,
                start: row.start_digest.as_deref(),
                target: &prepared.route.device_delivery_id,
                credential: prepared.credential.credential_id(),
                pins: &pins,
                valid_until: prepared.route.expires_at.min(valid_until),
                voip: prepared.route.provider == PushProviderKind::ApnsVoip,
            },
            issue,
        )
    }
}

fn call_slot(root: &str, digest: &str) -> Result<String, NodeCoreError> {
    let body = serde_json::json!({"recipient_root":root,"start_digest":digest});
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.notification.call_slot.v1\0",
        &ramflux_protocol::canonical_json_bytes(&body).map_err(error)?,
    ))
}

pub(super) fn retire_wake_rows(
    tx: &redb::WriteTransaction,
    key: &str,
    row: &WakeLedgerRow,
) -> Result<(), NodeCoreError> {
    if let Some(root) = &row.recipient_root {
        let slot = row.start_digest.as_deref().map(|digest| call_slot(root, digest)).transpose()?;
        if let Some(digest) = &row.start_digest {
            tx.open_table(CALL_WAKES)
                .map_err(error)?
                .remove((digest.as_str(), key))
                .map_err(error)?;
        } else {
            tx.open_table(ROOT_WAKES)
                .map_err(error)?
                .remove((root.as_str(), key))
                .map_err(error)?;
        }
        for kind in ["wake", "work"] {
            crate::send_authority::uncharge_resource(
                tx,
                root,
                slot.as_deref(),
                true,
                &format!("{kind}:{key}"),
            )?;
        }
    }
    tx.open_table(NOTIFY_QUEUE_ENTRY_TABLE).map_err(error)?.remove(key).map_err(error)?;
    let mut attempts = tx.open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE).map_err(error)?;
    let mut diagnostics = tx.open_table(DIAGNOSTICS).map_err(error)?;
    let keys = diagnostics
        .range((key, "")..=(key, "\u{10ffff}"))
        .map_err(error)?
        .take(129)
        .map(|entry| entry.map(|(entry, _)| entry.value().1.to_owned()).map_err(error))
        .collect::<Result<Vec<_>, _>>()?;
    if keys.len() > 128 {
        return Err(SendAuthorityError::Capacity.into());
    }
    for attempt_key in keys {
        if let Some(root) = &row.recipient_root {
            crate::send_authority::uncharge_resource(
                tx,
                root,
                None,
                true,
                &format!("attempt:{attempt_key}"),
            )?;
        }
        attempts.remove(attempt_key.as_str()).map_err(error)?;
        diagnostics.remove((key, attempt_key.as_str())).map_err(error)?;
    }
    Ok(())
}

pub(crate) fn retire_call_wakes(
    tx: &redb::WriteTransaction,
    root: &str,
    digest: &str,
    now: u64,
) -> Result<Vec<String>, NodeCoreError> {
    let mut retired = super::wake_admission::retire_call(tx, digest, now)?;
    let mut index = tx.open_table(CALL_WAKES).map_err(error)?;
    let rows = index
        .range((digest, "")..=(digest, "\u{10ffff}"))
        .map_err(error)?
        .take(129)
        .map(|entry| entry.map(|(key, at)| (key.value().1.to_owned(), at.value())).map_err(error))
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 128 || rows.iter().any(|(_, until)| *until > now) {
        return Err(SendAuthorityError::Closed.into());
    }
    let slot = call_slot(root, digest)?;
    let mut ledger = tx.open_table(NOTIFY_WAKE_LEDGER).map_err(error)?;
    let mut due = tx.open_table(NOTIFY_WAKE_DUE).map_err(error)?;
    for (key, until) in &rows {
        ledger.remove(key.as_str()).map_err(error)?;
        due.remove((*until, key.as_str())).map_err(error)?;
        index.remove((digest, key.as_str())).map_err(error)?;
        tx.open_table(NOTIFY_QUEUE_ENTRY_TABLE)
            .map_err(error)?
            .remove(key.as_str())
            .map_err(error)?;
        crate::send_authority::uncharge_resource(
            tx,
            root,
            Some(&slot),
            true,
            &format!("wake:{key}"),
        )?;
    }
    retired.extend(rows.into_iter().map(|(key, _)| key));
    Ok(retired)
}
