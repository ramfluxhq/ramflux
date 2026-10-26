// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh-head leases serialize honest creator devices before ownership handover.
use super::transfer_wire::{
    TransferBody, TransferControl, TransferDevice, TransferHead, TransferProbe,
};
use crate::prelude::*;
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::{GroupStateActor, GroupTransferAcceptance};
use serde::{Deserialize, Serialize};
pub(crate) const SEND_PREFIX: &str = "group-transfer/send/";
const PENDING: &str = "group-transfer/pending/";
const LEASE: &str = "group-transfer/lease/";
const TRANSFER_SKEW_SECONDS: i64 = 300;
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TransferDelivery {
    pub control: TransferControl,
    pub expires_at: i64,
    pub next_at: i64,
    pub delivered: BTreeSet<(String, String)>,
    #[serde(default)]
    pub acknowledged: BTreeSet<(String, String)>,
}
#[derive(Deserialize, Serialize)]
struct Pending {
    probe: TransferProbe,
    replies: BTreeMap<String, TransferHead>,
    expires_at: i64,
}
#[derive(Deserialize, Serialize)]
struct Lease {
    #[serde(default)]
    issuer: Option<TransferDevice>,
    proposal: String,
    head: String,
    expires_at: i64,
}
fn key(prefix: &str, group: &str) -> String {
    format!("{prefix}{}", ramflux_protocol::encode_base64url(group))
}
fn device_key(device: &ramflux_crypto::RootQualifiedDeviceRef) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.group.transfer.device.v1",
        &ramflux_protocol::canonical_json_bytes(&(device.root_commitment(), device.device_id()))?,
    ))
}
pub(crate) fn requires_sync() -> SdkError {
    requires_sync_reason("head_check_pending")
}
pub(crate) fn requires_sync_reason(reason: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: "transfer_requires_sync".into(),
        message: "Ownership transfer requires synchronization".into(),
        body: Box::new(serde_json::json!({"reason_code":reason})),
    }
}
impl RamfluxClient {
    pub(super) fn check_group_transfer_lease(
        &self,
        group: &str,
        nonce: Option<&str>,
    ) -> Result<(), SdkError> {
        self.release_group_transfer_lease_at(group, now_unix_timestamp())?;
        let lease: Option<Lease> = self.account_db()?.load_actor_state(&key(LEASE, group))?;
        if lease.is_some_and(|lease| nonce != Some(lease.proposal.as_str())) {
            return Err(requires_sync_reason("transfer_outcome_pending"));
        }
        Ok(())
    }
    fn transfer_target_selected(
        &self,
        group: &str,
        target: &TransferDevice,
    ) -> Result<bool, SdkError> {
        let Some(state) = self.account_db()?.shared_group_state(group)? else { return Ok(false) };
        if state.view().effective_role(&target.root, &target.device).is_none() {
            return Ok(false);
        }
        // Missing cached authority is not proof that an implicit sibling was deselected.
        if self.observed_device_set(&target.root)?.is_none() {
            return Ok(true);
        }
        Ok(self
            .shared_group_selected_devices(&state)?
            .get(&target.root)
            .is_some_and(|devices| devices.contains(&target.device)))
    }
    fn release_group_transfer_lease_at(&self, group: &str, now: i64) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            if let Some(lease) = db.load_actor_state::<Lease>(&key(LEASE, group))? {
                let released = if lease.expires_at.saturating_add(TRANSFER_SKEW_SECONDS) < now {
                    true
                } else if let Some(issuer) = &lease.issuer {
                    !self.transfer_target_selected(group, issuer)?
                } else {
                    false
                };
                if released {
                    self.finish_group_transfer_outcome(group, &lease.proposal)?;
                    db.remove_actor_state(&key(LEASE, group))?;
                }
            }
            Ok(())
        })
    }
    fn release_cancel_targets(&self, row: &mut TransferDelivery) -> Result<bool, SdkError> {
        let state = self.account_db()?.shared_group_state(row.control.group())?;
        let selected =
            state.as_ref().map(|state| self.shared_group_selected_devices(state)).transpose()?;
        let mut known = BTreeMap::new();
        for target in row.control.targets() {
            let represented = state.as_ref().is_some_and(|state| {
                state.view().effective_role(&target.root, &target.device).is_some()
            });
            let has_authority = if let Some(value) = known.get(&target.root) {
                *value
            } else {
                let value = self.observed_device_set(&target.root)?.is_some();
                known.insert(target.root.clone(), value);
                value
            };
            let active = represented
                && (!has_authority
                    || selected
                        .as_ref()
                        .and_then(|selected| selected.get(&target.root))
                        .is_some_and(|devices| devices.contains(&target.device)));
            if !active {
                let key = (target.root.clone(), target.device.clone());
                row.acknowledged.insert(key.clone());
                row.delivered.insert(key);
            }
        }
        Ok(row
            .control
            .targets()
            .iter()
            .all(|d| row.acknowledged.contains(&(d.root.clone(), d.device.clone()))))
    }
    fn cancellation_delivery_pending(&self, group: &str) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let mut pending = false;
        for id in db.actor_state_key_page(SEND_PREFIX, 512)? {
            let Some(mut row) = db.load_actor_state::<TransferDelivery>(&id)? else { continue };
            if row.control.group() == group
                && matches!(&row.control.body, TransferBody::Head{reply} if reply.cancelled)
            {
                if self.release_cancel_targets(&mut row)? {
                    db.remove_actor_state(&id)?;
                } else {
                    db.persist_actor_state(&id, &row)?;
                    pending = true;
                }
            }
        }
        Ok(pending)
    }
    /// Advance abandoned proposals without needing another user transfer request.
    pub(crate) fn advance_group_transfer_deadlines(&self, now: i64) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for id in db.actor_state_key_page(PENDING, 128)? {
            if let Some(pending) = db.load_actor_state::<Pending>(&id)?
                && pending.probe.expires_at.saturating_add(TRANSFER_SKEW_SECONDS) < now
            {
                if let Some(state) = db.shared_group_state(&pending.probe.base.group_id)?
                    && state.snapshot().transfers.iter().any(|transfer| {
                        transfer.acceptance.nonce == pending.probe.id
                            && transfer.previous_hash == pending.probe.base.state_hash
                    })
                {
                    self.finish_group_transfer_head_change(&state)?;
                } else {
                    self.cancel_group_transfer(&pending.probe)?;
                }
            }
        }
        for id in db.actor_state_key_page(LEASE, 4096)? {
            let bytes = ramflux_protocol::decode_base64url(
                id.strip_prefix(LEASE).ok_or_else(|| super::invalid("transfer lease key"))?,
            )
            .map_err(|_| super::invalid("transfer lease key encoding"))?;
            let group =
                String::from_utf8(bytes).map_err(|_| super::invalid("transfer lease group"))?;
            self.release_group_transfer_lease_at(&group, now)?;
        }
        // Visit each delivery once; do not re-scan the complete queue for each group.
        for id in db.actor_state_key_page(SEND_PREFIX, 512)? {
            let Some(mut row) = db.load_actor_state::<TransferDelivery>(&id)? else { continue };
            if matches!(&row.control.body, TransferBody::Head{reply} if reply.cancelled) {
                if self.release_cancel_targets(&mut row)? {
                    db.remove_actor_state(&id)?;
                } else {
                    db.persist_actor_state(&id, &row)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn stage_group_transfer_control(
        &self,
        control: TransferControl,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let now = now_unix_timestamp();
        db.retain_expiring_actor_states(SEND_PREFIX, now, 512)?;
        let head = match &control.body {
            TransferBody::Probe { probe } => &probe.base.state_hash,
            TransferBody::Head { reply } => &reply.head.state_hash,
        };
        let kind = matches!(control.body, TransferBody::Probe { .. });
        let outcome = match &control.body {
            TransferBody::Probe { .. } => (false, false, false, None),
            TransferBody::Head { reply } => (
                reply.cancelled,
                reply.cancel_ack,
                reply.requires_sync,
                Some(reply.requested_hash.as_str()),
            ),
        };
        let id = ramflux_protocol::hash_base64url(
            "ramflux.group.transfer.delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                kind,
                control.proposal(),
                &control.actor().identity,
                head,
                control.targets(),
                outcome,
            ))?,
        );
        let id = format!("{SEND_PREFIX}{id}");
        if db.actor_state_exists(&id)? {
            return Ok(());
        }
        let rows = db.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
        if rows.len() >= 512
            || rows.iter().filter(|row| row.control.group() == control.group()).count() >= 8
        {
            return Err(ramflux_protocol::ProtocolError::GroupStateLimit(
                ramflux_protocol::GroupStateLimit::Requests,
            )
            .into());
        }
        let packet = super::GroupControlPacket::new(super::GroupControlBody::Transfer {
            control: Box::new(control.clone()),
        });
        if serde_json::to_vec(&packet)?.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES
        {
            return Err(ramflux_protocol::ProtocolError::GroupStateLimit(
                ramflux_protocol::GroupStateLimit::Bytes,
            )
            .into());
        }
        db.persist_actor_state(
            &id,
            &TransferDelivery {
                expires_at: if matches!(&control.body,TransferBody::Head{reply} if reply.cancelled)
                {
                    ramflux_protocol::MAX_SAFE_JSON_INTEGER.cast_signed()
                } else {
                    control.expires_at().saturating_add(300)
                },
                control,
                next_at: now,
                delivered: BTreeSet::new(),
                acknowledged: BTreeSet::new(),
            },
        )?;
        Ok(())
    }
    pub(crate) async fn group_transfer_authorization(
        &self,
        gateway: &GatewaySessionConfig,
        state: &VerifiedGroupState,
        creator: &GroupStateActor,
        target: &str,
    ) -> Result<GroupTransferAcceptance, SdkError> {
        let actor = self.owned_group_actor(target)?;
        if actor.identity.root_commitment != state.creator().identity.root_commitment
            || !state.view().members.iter().any(|member| member.identity == creator.identity)
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        let manifest = match self
            .shared_group_manifest(gateway, &state.view().group_id, &actor.identity.root_commitment)
            .await
        {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(%error,"ownership head-check directory unavailable");
                return Err(requires_sync_reason("directory_unavailable"));
            }
        };
        self.persist_identity_directory(&manifest)?;
        let required = self.group_transfer_participants(state, creator, &actor, &manifest)?;
        let id = key(PENDING, &state.view().group_id);
        let now = now_unix_timestamp();
        if let Some(pending) = self.account_db()?.load_actor_state::<Pending>(&id)?
            && pending.probe.expires_at >= now
            && pending.probe.base.state_hash == state.snapshot().state_hash
            && pending.probe.creator == *creator
            && pending.probe.required == required
        {
            self.check_group_transfer_lease(&state.view().group_id, Some(&pending.probe.id))?;
            return self.completed_group_transfer(&pending, state);
        }
        if let Some(old) = self.account_db()?.load_actor_state::<Pending>(&id)? {
            self.cancel_group_transfer(&old.probe)?;
            return Err(requires_sync_reason("previous_transfer_cancelled"));
        }
        if self.cancellation_delivery_pending(&state.view().group_id)? {
            return Err(requires_sync_reason("cancellation_delivery_pending"));
        }
        self.check_group_transfer_lease(&state.view().group_id, None)?;
        self.account_db()?.retain_expiring_actor_states(PENDING, now, 128)?;
        if !self.account_db()?.actor_state_exists(&id)?
            && self.account_db()?.actor_state_usage(PENDING)?.0 >= 128
        {
            return Err(requires_sync());
        }
        let probe = TransferProbe {
            id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            actor,
            creator: creator.clone(),
            base: state.snapshot().clone(),
            required,
            issued_at: now,
            expires_at: now.saturating_add(60),
        };
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.reserve_group_transfer(&probe, state)?;
            let control = TransferControl::sign(
                self,
                TransferBody::Probe { probe: Box::new(probe.clone()) },
            )?;
            self.stage_group_transfer_control(control)?;
            self.account_db()?.persist_actor_state(
                &id,
                &Pending {
                    probe: probe.clone(),
                    replies: BTreeMap::new(),
                    // The issue deadline is probe.expires_at; cancellation/commit owns retention.
                    expires_at: ramflux_protocol::MAX_SAFE_JSON_INTEGER.cast_signed(),
                },
            )?;
            Ok(())
        })?;
        if probe.required.is_empty() {
            return Ok(ramflux_crypto::accept_group_transfer(
                self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                creator,
                state,
                &probe.id,
                now,
            )?);
        }
        Err(requires_sync())
    }
    fn completed_group_transfer(
        &self,
        pending: &Pending,
        state: &VerifiedGroupState,
    ) -> Result<GroupTransferAcceptance, SdkError> {
        for participant in &pending.probe.required {
            let identity = self.device_identity_for_root(&participant.root, &participant.device)?;
            let Some(reply) = pending.replies.get(&device_key(&identity)?) else {
                return Err(requires_sync());
            };
            self.require_cached_root_authority(&identity)?;
            if self.trusted_device(&identity)?["signing_public_key"]
                != reply.actor.identity.signing_public_key
                || reply.requires_sync
                || reply.expires_at < now_unix_timestamp().saturating_sub(300)
                || reply.head.state_hash != state.snapshot().state_hash
            {
                return Err(requires_sync());
            }
        }
        if pending.probe.creator.identity == pending.probe.actor.identity {
            return Ok(ramflux_crypto::accept_group_transfer(
                self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                &pending.probe.creator,
                state,
                &pending.probe.id,
                now_unix_timestamp(),
            )?);
        }
        let acceptance = pending
            .replies
            .values()
            .find_map(|reply| reply.acceptance.as_deref())
            .ok_or_else(requires_sync)?;
        ramflux_crypto::verify_group_transfer_acceptance(acceptance)?;
        if acceptance.creator != pending.probe.creator
            || acceptance.base_hash != state.snapshot().state_hash
            || acceptance.nonce != pending.probe.id
        {
            return Err(requires_sync());
        }
        Ok(acceptance.clone())
    }
    fn reserve_group_transfer(
        &self,
        probe: &TransferProbe,
        state: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        self.check_group_transfer_lease(&state.view().group_id, Some(&probe.id))?;
        self.reserve_group_transfer_outcome(probe)?;
        self.account_db()?.persist_actor_state(
            &key(LEASE, &state.view().group_id),
            &Lease {
                proposal: probe.id.clone(),
                issuer: Some(TransferDevice {
                    root: probe.actor.identity.root_commitment.clone(),
                    device: probe.actor.identity.device_id.clone(),
                }),
                head: state.snapshot().state_hash.clone(),
                expires_at: probe.expires_at,
            },
        )?;
        Ok(())
    }
    pub(crate) fn apply_group_transfer_control(
        &self,
        control: &TransferControl,
        target: &str,
    ) -> Result<(), SdkError> {
        control.verify(now_unix_timestamp())?;
        let genesis = match &control.body {
            TransferBody::Probe { probe } => &probe.base.genesis,
            TransferBody::Head { reply } => &reply.head.genesis,
        };
        if self
            .account_db()?
            .shared_group_state(control.group())?
            .is_some_and(|current| current.genesis() != genesis)
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        match &control.body {
            TransferBody::Probe { probe } => self.answer_group_transfer(probe, target),
            TransferBody::Head { reply } => self.receive_group_transfer_head(reply, target),
        }
    }
    fn answer_group_transfer(&self, probe: &TransferProbe, target: &str) -> Result<(), SdkError> {
        let base = ramflux_crypto::verify_group_state_snapshot(probe.base.clone())?;
        if self.group_snapshot_requires_consent(&base)? {
            return Err(super::invalid("group consent is pending"));
        }
        let current = self.account_db()?.shared_group_state(&base.view().group_id)?;
        if current.as_ref().is_none_or(|old| base.view().epoch > old.view().epoch) {
            self.accept_shared_group_state(&base, target)?;
        }
        let current = self
            .account_db()?
            .shared_group_state(&base.view().group_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let actor = self.owned_group_actor(target)?;
        let participant = TransferDevice {
            root: actor.identity.root_commitment.clone(),
            device: actor.identity.device_id.clone(),
        };
        if !probe.required.contains(&participant) {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        let fresh = current.snapshot().state_hash == base.snapshot().state_hash
            && current.creator().root_public_key == base.creator().root_public_key;
        let mut fresh = fresh;
        if fresh && actor.identity.root_commitment == base.creator().identity.root_commitment {
            match self.reserve_group_transfer(probe, &current) {
                Ok(()) => {}
                Err(error)
                    if crate::bus::io::local_bus_error_code(&error) == "transfer_requires_sync" =>
                {
                    fresh = false;
                }
                Err(error) => return Err(error),
            }
        }
        let acceptance = if fresh && actor.identity == probe.creator.identity {
            Some(Box::new(ramflux_crypto::accept_group_transfer(
                self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                &actor,
                &current,
                &probe.id,
                probe.issued_at,
            )?))
        } else {
            None
        };
        let reply = TransferHead {
            proposal: probe.id.clone(),
            actor,
            requested_hash: base.snapshot().state_hash.clone(),
            head: current.snapshot().clone(),
            acceptance,
            requires_sync: !fresh,
            target: TransferDevice {
                root: probe.actor.identity.root_commitment.clone(),
                device: probe.actor.identity.device_id.clone(),
            },
            issued_at: now_unix_timestamp(),
            expires_at: now_unix_timestamp().saturating_add(60),
            additional_targets: Vec::new(),
            cancelled: false,
            cancel_ack: false,
        };
        self.stage_group_transfer_control(TransferControl::sign(
            self,
            TransferBody::Head { reply: Box::new(reply) },
        )?)
    }
    fn receive_group_transfer_head(
        &self,
        reply: &TransferHead,
        target: &str,
    ) -> Result<(), SdkError> {
        if reply.cancelled {
            return self.observe_group_transfer_cancel(reply, target);
        }
        if reply.cancel_ack {
            return self.observe_group_transfer_cancel_ack(reply);
        }
        let id = key(PENDING, &reply.head.group_id);
        let Some(mut pending) = self.account_db()?.load_actor_state::<Pending>(&id)? else {
            return self.observe_stale_transfer_refusal(reply);
        };
        if pending.probe.id != reply.proposal
            || pending.probe.base.state_hash != reply.requested_hash
        {
            return Ok(());
        }
        let actor = &reply.actor.identity;
        if reply.acceptance.is_some() && *actor != pending.probe.creator.identity {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        if !pending.probe.required.contains(&TransferDevice {
            root: actor.root_commitment.clone(),
            device: actor.device_id.clone(),
        }) {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        let head = ramflux_crypto::verify_group_state_snapshot(reply.head.clone())?;
        let base = ramflux_crypto::verify_group_state_snapshot(pending.probe.base.clone())?;
        if head.genesis() != base.genesis() {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        if reply.requires_sync || head.snapshot().state_hash != base.snapshot().state_hash {
            self.cancel_group_transfer(&pending.probe)?;
            if matches!(
                head.relation_to(&base),
                Ok(ramflux_crypto::GroupStateRelation::Extension
                    | ramflux_crypto::GroupStateRelation::IncomingPreferred
                    | ramflux_crypto::GroupStateRelation::RemovalConflict)
            ) {
                self.accept_shared_group_state(&head, target)?;
            }
            return Ok(());
        }
        let identity = self.device_identity_for_root(&actor.root_commitment, &actor.device_id)?;
        pending.replies.insert(device_key(&identity)?, reply.clone());
        self.account_db()?.persist_actor_state(&id, &pending)?;
        Ok(())
    }
    pub(super) fn finish_group_transfer_head_change(
        &self,
        state: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        let group = &state.view().group_id;
        if let Some(lease) = self.account_db()?.load_actor_state::<Lease>(&key(LEASE, group))? {
            let committed = state.snapshot().transfers.iter().any(|transfer| {
                transfer.acceptance.nonce == lease.proposal && transfer.previous_hash == lease.head
            });
            if committed {
                self.finish_group_transfer_outcome(group, &lease.proposal)?;
                self.account_db()?.remove_actor_state(&key(LEASE, group))?;
                self.account_db()?.remove_actor_state(&key(PENDING, group))?;
            } else if let Some(pending) =
                self.account_db()?.load_actor_state::<Pending>(&key(PENDING, group))?
                && pending.probe.base.state_hash != state.snapshot().state_hash
            {
                self.cancel_group_transfer(&pending.probe)?;
            }
        }
        Ok(())
    }
    pub(crate) fn stage_stale_transfer_refusal(
        &self,
        incoming: &VerifiedGroupState,
        target: &str,
    ) -> Result<(), SdkError> {
        let current = self
            .account_db()?
            .shared_group_state(&incoming.view().group_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let Some(transfer) =
            incoming.snapshot().transfers.iter().enumerate().find_map(|(index, transfer)| {
                (current.snapshot().transfers.get(index) != Some(transfer)).then_some(transfer)
            })
        else {
            return Ok(());
        };
        let source = &incoming.snapshot().issuer.identity;
        let old_root = &current.creator().identity.root_commitment;
        let own = self.owned_device_identity()?;
        let additional_targets = self
            .shared_group_selected_devices(&current)?
            .remove(old_root)
            .unwrap_or_default()
            .into_iter()
            .filter(|d| {
                !(old_root == &source.root_commitment && d == &source.device_id
                    || old_root == own.root_commitment() && d == own.device_id())
            })
            .map(|device| TransferDevice { root: old_root.clone(), device })
            .collect();
        let reply = TransferHead {
            proposal: transfer.acceptance.nonce.clone(),
            actor: self.owned_group_actor(target)?,
            requested_hash: transfer.previous_hash.clone(),
            head: current.snapshot().clone(),
            acceptance: None,
            requires_sync: true,
            target: TransferDevice {
                root: source.root_commitment.clone(),
                device: source.device_id.clone(),
            },
            issued_at: now_unix_timestamp(),
            expires_at: now_unix_timestamp().saturating_add(60),
            additional_targets,
            cancelled: false,
            cancel_ack: false,
        };
        self.stage_group_transfer_control(TransferControl::sign(
            self,
            TransferBody::Head { reply: Box::new(reply) },
        )?)
    }
}

impl RamfluxClient {
    fn group_transfer_participants(
        &self,
        state: &VerifiedGroupState,
        creator: &GroupStateActor,
        actor: &GroupStateActor,
        manifest: &crate::prekey::SdkDeviceManifestResponse,
    ) -> Result<Vec<TransferDevice>, SdkError> {
        let selected = self.shared_group_selected_devices(state)?;
        let mut required: BTreeSet<TransferDevice> = manifest
            .devices
            .iter()
            .filter(|d| {
                d.device_id != actor.identity.device_id
                    && selected
                        .get(&manifest.principal_commitment)
                        .is_some_and(|names| names.contains(&d.device_id))
            })
            .map(|d| TransferDevice {
                root: manifest.principal_commitment.clone(),
                device: d.device_id.clone(),
            })
            .collect();
        if creator.identity != actor.identity {
            required.insert(TransferDevice {
                root: creator.identity.root_commitment.clone(),
                device: creator.identity.device_id.clone(),
            });
        }
        Ok(required.into_iter().collect())
    }
}

impl RamfluxClient {
    fn cancel_group_transfer(&self, probe: &TransferProbe) -> Result<(), SdkError> {
        let actor = self.owned_device_identity()?;
        if actor.root_commitment() != probe.actor.identity.root_commitment
            || actor.device_id() != probe.actor.identity.device_id
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            if let Some((target, remaining)) = probe.required.split_first() {
                let now = now_unix_timestamp();
                let reply = TransferHead {
                    proposal: probe.id.clone(),
                    actor: probe.actor.clone(),
                    requested_hash: probe.base.state_hash.clone(),
                    head: probe.base.clone(),
                    acceptance: None,
                    requires_sync: true,
                    target: target.clone(),
                    additional_targets: remaining.to_vec(),
                    cancelled: true,
                    cancel_ack: false,
                    issued_at: now,
                    expires_at: now.saturating_add(7 * 86400),
                };
                self.stage_group_transfer_control(TransferControl::sign(
                    self,
                    TransferBody::Head { reply: Box::new(reply) },
                )?)?;
            }
            self.remember_group_transfer_outcome(
                &probe.base.group_id,
                &probe.id,
                TransferDevice {
                    root: probe.actor.identity.root_commitment.clone(),
                    device: probe.actor.identity.device_id.clone(),
                },
            )?;
            self.account_db()?.remove_actor_state(&key(PENDING, &probe.base.group_id))?;
            self.account_db()?.remove_actor_state(&key(LEASE, &probe.base.group_id))?;
            Ok(())
        })
    }
    fn observe_group_transfer_cancel(
        &self,
        reply: &TransferHead,
        target: &str,
    ) -> Result<(), SdkError> {
        let group = &reply.head.group_id;
        if let Some(lease) = self.account_db()?.load_actor_state::<Lease>(&key(LEASE, group))?
            && lease.proposal == reply.proposal
            && lease.head == reply.requested_hash
        {
            let source = TransferDevice {
                root: reply.actor.identity.root_commitment.clone(),
                device: reply.actor.identity.device_id.clone(),
            };
            if lease.issuer.as_ref() != Some(&source)
                || !reply.requires_sync
                || reply.acceptance.is_some()
            {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            self.remember_group_transfer_outcome(group, &reply.proposal, source)?;
            self.account_db()?.remove_actor_state(&key(LEASE, group))?;
        }
        self.remember_group_transfer_outcome(
            group,
            &reply.proposal,
            TransferDevice {
                root: reply.actor.identity.root_commitment.clone(),
                device: reply.actor.identity.device_id.clone(),
            },
        )?;
        let ack = TransferHead {
            proposal: reply.proposal.clone(),
            actor: self.owned_group_actor(target)?,
            requested_hash: reply.requested_hash.clone(),
            head: reply.head.clone(),
            acceptance: None,
            requires_sync: false,
            target: TransferDevice {
                root: reply.actor.identity.root_commitment.clone(),
                device: reply.actor.identity.device_id.clone(),
            },
            additional_targets: Vec::new(),
            cancelled: false,
            cancel_ack: true,
            issued_at: now_unix_timestamp(),
            expires_at: now_unix_timestamp().saturating_add(60),
        };
        self.stage_group_transfer_control(TransferControl::sign(
            self,
            TransferBody::Head { reply: Box::new(ack) },
        )?)
    }
    fn observe_group_transfer_cancel_ack(&self, reply: &TransferHead) -> Result<(), SdkError> {
        let actor = &reply.actor.identity;
        for id in self.account_db()?.actor_state_key_page(SEND_PREFIX, 512)? {
            let Some(mut row) = self.account_db()?.load_actor_state::<TransferDelivery>(&id)?
            else {
                continue;
            };
            if let TransferBody::Head { reply: cancel } = &row.control.body
                && cancel.cancelled
                && cancel.proposal == reply.proposal
                && cancel.requested_hash == reply.requested_hash
                && cancel.head.genesis == reply.head.genesis
                && row
                    .control
                    .targets()
                    .iter()
                    .any(|d| d.root == actor.root_commitment && d.device == actor.device_id)
            {
                row.acknowledged.insert((actor.root_commitment.clone(), actor.device_id.clone()));
                row.delivered.insert((actor.root_commitment.clone(), actor.device_id.clone()));
                if self.release_cancel_targets(&mut row)? {
                    self.account_db()?.remove_actor_state(&id)?;
                } else {
                    self.account_db()?.persist_actor_state(&id, &row)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn refresh_group_transfer_cancellation(
        &self,
        row: &mut TransferDelivery,
    ) -> Result<(), SdkError> {
        if let TransferBody::Head { reply } = &mut row.control.body
            && reply.cancelled
            && reply.expires_at < now_unix_timestamp().saturating_add(60)
        {
            let own = self.owned_device_identity()?;
            let local = self.trusted_device(&own)?;
            let target =
                local["target_delivery_id"].as_str().ok_or(StorageError::AuthorizationRejected)?;
            reply.actor = self.owned_group_actor(target)?;
            reply.issued_at = now_unix_timestamp();
            reply.expires_at = reply.issued_at.saturating_add(7 * 86400);
            row.control = TransferControl::sign(self, row.control.body.clone())?;
        }
        Ok(())
    }
    fn observe_stale_transfer_refusal(&self, reply: &TransferHead) -> Result<(), SdkError> {
        if !reply.requires_sync {
            return Ok(());
        }
        let Some(state) = self.account_db()?.shared_group_state(&reply.head.group_id)? else {
            return Ok(());
        };
        if !state.snapshot().transfers.iter().any(|transfer| {
            transfer.acceptance.nonce == reply.proposal
                && transfer.previous_hash == reply.requested_hash
        }) || state.genesis() != &reply.head.genesis
        {
            return Ok(());
        }
        let id = format!(
            "group-transfer/refused/{}/{}",
            ramflux_protocol::encode_base64url(&reply.head.group_id),
            reply.proposal
        );
        self.account_db()?.append_group_journal(
            &id,
            "group.state.conflict",
            &serde_json::json!({
                "group_id":reply.head.group_id,"reason":"transfer_refused_stale",
                "base_hash":reply.requested_hash,"head_hash":reply.head.state_hash,
            }),
            now_unix_timestamp(),
            &id,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::{GroupStateChange, SharedGroupRole};
    #[test]
    fn r7_sibling_reservation_waits_for_signed_outcome_not_the_issue_deadline()
    -> Result<(), SdkError> {
        let path = super::super::tests::temp_root("transfer-outcome")?;
        let phone = super::super::tests::person(&path.join("phone"), "owner", "phone", 11, 12)?;
        let laptop = super::super::tests::person(&path.join("laptop"), "owner", "laptop", 11, 32)?;
        let next = super::super::tests::person(&path.join("next"), "next", "next", 21, 22)?;
        install_transfer_directories(&phone, &laptop, &next)?;
        phone.shared_group_create("group", "thread", None, "target-phone")?;
        let base = phone.shared_group_change(
            "group",
            "target-phone",
            GroupStateChange::Add {
                member: next.owned_group_actor("target-next")?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        laptop.accept_shared_group_state(&base, "target-laptop")?;
        let now = now_unix_timestamp();
        let probe = TransferProbe {
            id: ramflux_protocol::encode_base64url([75; 32]),
            actor: phone.owned_group_actor("target-phone")?,
            creator: next.owned_group_actor("target-next")?,
            base: base.snapshot().clone(),
            required: vec![TransferDevice {
                root: laptop.owned_device_identity()?.root_commitment().into(),
                device: "laptop".into(),
            }],
            issued_at: now - 100,
            expires_at: now - 40,
        };
        laptop.reserve_group_transfer(&probe, &base)?;
        assert_eq!(
            crate::bus::io::local_bus_error_body(
                &laptop
                    .check_group_transfer_lease("group", None)
                    .err()
                    .ok_or(StorageError::AuthorizationRejected)?
            )
            .reason_code
            .as_deref(),
            Some("transfer_outcome_pending")
        );
        // An unrelated creator edit is not proof that this handover finished.
        let edited = phone.shared_group_change(
            "group",
            "target-phone",
            GroupStateChange::SetName { name: "concurrent".into() },
        )?;
        laptop.accept_shared_group_state(&edited, "target-laptop")?;
        assert!(laptop.check_group_transfer_lease("group", None).is_err());
        // A different creator sibling cannot impersonate the proposing device's cancellation.
        let forged = TransferHead {
            proposal: probe.id.clone(),
            actor: laptop.owned_group_actor("target-laptop")?,
            requested_hash: base.snapshot().state_hash.clone(),
            head: base.snapshot().clone(),
            acceptance: None,
            requires_sync: true,
            target: probe.required[0].clone(),
            additional_targets: Vec::new(),
            cancelled: true,
            cancel_ack: false,
            issued_at: now,
            expires_at: now + 7 * 86400,
        };
        let forged =
            TransferControl::sign(&laptop, TransferBody::Head { reply: Box::new(forged) })?;
        assert!(laptop.apply_group_transfer_control(&forged, "target-laptop").is_err());
        phone.cancel_group_transfer(&probe)?;
        let rows = phone.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
        let cancel = rows
            .iter()
            .find(|r| matches!(&r.control.body,TransferBody::Head{reply} if reply.cancelled))
            .ok_or(StorageError::AuthorizationRejected)?;
        assert!(cancel.expires_at > now.saturating_add(7 * 86400));
        let mut renewed = cancel.clone();
        if let TransferBody::Head { reply } = &mut renewed.control.body {
            reply.issued_at = now - 8 * 86400;
            reply.expires_at = now - 86400;
        }
        phone.refresh_group_transfer_cancellation(&mut renewed)?;
        renewed.control.verify(now_unix_timestamp())?;
        laptop.apply_group_transfer_control(&cancel.control, "target-laptop")?;
        assert!(
            !phone.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?.is_empty(),
            "cancellation is retained until observation is acknowledged"
        );
        let replies = laptop.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
        let ack = replies
            .iter()
            .find(|r| matches!(&r.control.body,TransferBody::Head{reply} if reply.cancel_ack))
            .ok_or(StorageError::AuthorizationRejected)?;
        phone.apply_group_transfer_control(&ack.control, "target-phone")?;
        assert!(phone.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?.is_empty());
        laptop.check_group_transfer_lease("group", None)?;
        laptop.shared_group_change(
            "group",
            "target-laptop",
            GroupStateChange::SetName { name: "unlocked".into() },
        )?;
        assert_commit_releases_reservation(&phone, &laptop, &next, probe)?;
        drop((phone, laptop, next));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
    pub(super) fn install_transfer_directories(
        phone: &RamfluxClient,
        laptop: &RamfluxClient,
        next: &RamfluxClient,
    ) -> Result<(), SdkError> {
        use crate::client::identity_authority::test_support::{public_manifest, sign_manifest};
        let mut owner = public_manifest(phone)?;
        owner.devices.extend(public_manifest(laptop)?.devices);
        sign_manifest(
            phone.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut owner,
            2,
        )?;
        let target = public_manifest(next)?;
        for client in [phone, laptop, next] {
            client.persist_identity_directory(&owner)?;
            client.persist_identity_directory(&target)?;
        }
        Ok(())
    }
    fn assert_commit_releases_reservation(
        phone: &RamfluxClient,
        laptop: &RamfluxClient,
        next: &RamfluxClient,
        probe: TransferProbe,
    ) -> Result<(), SdkError> {
        let unlocked = laptop
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::AuthorizationRejected)?;
        phone.accept_shared_group_state(&unlocked, "target-phone")?;
        let mut committed_probe = probe;
        committed_probe.id = ramflux_protocol::encode_base64url([76; 32]);
        committed_probe.base = unlocked.snapshot().clone();
        committed_probe.issued_at = now_unix_timestamp();
        committed_probe.expires_at = committed_probe.issued_at + 60;
        laptop.reserve_group_transfer(&committed_probe, &unlocked)?;
        phone.cancel_group_transfer(&committed_probe)?;
        let rows = phone.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
        let cancel = rows
            .iter()
            .find(|row| row.control.proposal() == committed_probe.id)
            .ok_or(StorageError::AuthorizationRejected)?;
        laptop.apply_group_transfer_control(&cancel.control, "target-laptop")?;
        laptop.answer_group_transfer(&committed_probe, "target-laptop")?;
        laptop.check_group_transfer_lease("group", None)?;
        committed_probe.id = ramflux_protocol::encode_base64url([77; 32]);
        laptop.reserve_group_transfer(&committed_probe, &unlocked)?;
        let acceptance = ramflux_crypto::accept_group_transfer(
            next.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &committed_probe.creator,
            &unlocked,
            &committed_probe.id,
            now_unix_timestamp(),
        )?;
        let transferred = phone.shared_group_change(
            "group",
            "target-phone",
            GroupStateChange::TransferOwnership {
                creator: committed_probe.creator,
                acceptance: Box::new(acceptance),
            },
        )?;
        laptop.accept_shared_group_state(&transferred, "target-laptop")?;
        laptop.check_group_transfer_lease("group", None)?;
        Ok(())
    }
    #[test]
    fn r7_transfer_controls_tolerate_five_minutes_of_skew_and_bind_acceptance_to_issuer_time()
    -> Result<(), SdkError> {
        let path = super::super::tests::temp_root("transfer-clock")?;
        let owner = super::super::tests::person(&path.join("owner"), "owner", "owner", 11, 12)?;
        let next = super::super::tests::person(&path.join("next"), "next", "next", 21, 22)?;
        owner.shared_group_create("group", "thread", None, "target-owner")?;
        let base = owner.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::Add {
                member: next.owned_group_actor("target-next")?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        next.accept_shared_group_state(&base, "target-next")?;
        let now = now_unix_timestamp();
        for offset in [-300, 300] {
            let probe = TransferProbe {
                id: ramflux_protocol::encode_base64url([if offset < 0 { 75 } else { 76 }; 32]),
                actor: owner.owned_group_actor("target-owner")?,
                creator: next.owned_group_actor("target-next")?,
                base: base.snapshot().clone(),
                required: vec![TransferDevice {
                    root: next.owned_device_identity()?.root_commitment().into(),
                    device: "next".into(),
                }],
                issued_at: now + offset,
                expires_at: now + offset + 60,
            };
            let wire = TransferControl::sign(
                &owner,
                TransferBody::Probe { probe: Box::new(probe.clone()) },
            )?;
            wire.verify(now)?;
            next.answer_group_transfer(&probe, "target-next")?;
            let rows = next.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
            let acceptance = rows
                .iter()
                .find_map(|row| match &row.control.body {
                    TransferBody::Head { reply } => {
                        reply.acceptance.as_deref().filter(|a| a.issued_at == probe.issued_at)
                    }
                    TransferBody::Probe { .. } => None,
                })
                .ok_or(StorageError::AuthorizationRejected)?;
            let count = rows.len();
            let mut repeated =
                rows.last().ok_or(StorageError::AuthorizationRejected)?.control.clone();
            if let TransferBody::Head { reply } = &mut repeated.body {
                reply.issued_at += 1;
                reply.expires_at += 1;
            }
            repeated = TransferControl::sign(&next, repeated.body)?;
            next.stage_group_transfer_control(repeated)?;
            assert_eq!(
                next.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?.len(),
                count,
                "repeated probes must not consume additional reply slots"
            );
            assert_eq!(acceptance.issued_at, probe.issued_at);
            assert!(wire.verify(now - 301 - offset.abs()).is_err());
        }
        drop((owner, next));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "transfer_deadline_tests.rs"]
mod deadline_tests;
