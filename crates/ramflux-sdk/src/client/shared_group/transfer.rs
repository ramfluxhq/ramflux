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
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TransferDelivery {
    pub control: TransferControl,
    pub expires_at: i64,
    pub next_at: i64,
    pub delivered: BTreeSet<(String, String)>,
}
#[derive(Deserialize, Serialize)]
struct Pending {
    probe: TransferProbe,
    replies: BTreeMap<String, TransferHead>,
    expires_at: i64,
}
#[derive(Deserialize, Serialize)]
struct Lease {
    proposal: String,
    head: String,
    expires_at: i64,
}
fn key(prefix: &str, group: &str) -> String {
    format!("{prefix}{}", ramflux_protocol::encode_base64url(group))
}
fn device_key(root: &str, device: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.group.transfer.device.v1",
        &ramflux_protocol::canonical_json_bytes(&(root, device))?,
    ))
}
pub(crate) fn requires_sync() -> SdkError {
    ramflux_protocol::ProtocolError::GroupTransferRequiresSync.into()
}
impl RamfluxClient {
    pub(super) fn check_group_transfer_lease(
        &self,
        group: &str,
        nonce: Option<&str>,
    ) -> Result<(), SdkError> {
        let lease: Option<Lease> =
            self.account_db()?.load_actor_state(&key("group-transfer/lease/", group))?;
        if lease.is_some_and(|lease| {
            lease.expires_at > now_unix_timestamp() && nonce != Some(lease.proposal.as_str())
        }) {
            return Err(requires_sync());
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
        let id = ramflux_protocol::hash_base64url(
            "ramflux.group.transfer.delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                kind,
                control.proposal(),
                &control.actor().identity,
                head,
                control.targets(),
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
                expires_at: control.expires_at(),
                control,
                next_at: now,
                delivered: BTreeSet::new(),
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
                return Err(requires_sync());
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
        if self
            .account_db()?
            .load_actor_state::<Pending>(&id)?
            .is_some_and(|old| old.probe.base.state_hash != state.snapshot().state_hash)
        {
            self.account_db()?.remove_actor_state(&id)?;
            self.account_db()?
                .remove_actor_state(&key("group-transfer/lease/", &state.view().group_id))?;
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
            self.reserve_group_transfer(&probe.id, state, probe.expires_at)?;
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
                    expires_at: probe.expires_at,
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
            let Some(reply) =
                pending.replies.get(&device_key(&participant.root, &participant.device)?)
            else {
                return Err(requires_sync());
            };
            let identity = self.device_identity_for_root(&participant.root, &participant.device)?;
            self.require_cached_root_authority(&identity)?;
            if self.trusted_device(&identity)?["signing_public_key"]
                != reply.actor.identity.signing_public_key
                || reply.requires_sync
                || reply.expires_at < now_unix_timestamp()
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
        proposal: &str,
        state: &VerifiedGroupState,
        expires_at: i64,
    ) -> Result<(), SdkError> {
        self.check_group_transfer_lease(&state.view().group_id, Some(proposal))?;
        self.account_db()?.persist_actor_state(
            &key("group-transfer/lease/", &state.view().group_id),
            &Lease {
                proposal: proposal.into(),
                head: state.snapshot().state_hash.clone(),
                expires_at,
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
            match self.reserve_group_transfer(&probe.id, &current, probe.expires_at) {
                Ok(()) => {}
                Err(SdkError::Protocol(
                    ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
                )) => fresh = false,
                Err(error) => return Err(error),
            }
        }
        let acceptance = if fresh && actor.identity == probe.creator.identity {
            Some(Box::new(ramflux_crypto::accept_group_transfer(
                self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                &actor,
                &current,
                &probe.id,
                now_unix_timestamp(),
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
            expires_at: probe.expires_at,
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
        let id = key(PENDING, &reply.head.group_id);
        let Some(mut pending) = self.account_db()?.load_actor_state::<Pending>(&id)? else {
            return Ok(());
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
            self.account_db()?.remove_actor_state(&id)?;
            self.account_db()?
                .remove_actor_state(&key("group-transfer/lease/", &head.view().group_id))?;
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
        pending
            .replies
            .insert(device_key(&actor.root_commitment, &actor.device_id)?, reply.clone());
        self.account_db()?.persist_actor_state(&id, &pending)?;
        Ok(())
    }
    pub(super) fn finish_group_transfer_head_change(
        &self,
        state: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        let group = &state.view().group_id;
        if self
            .account_db()?
            .load_actor_state::<Lease>(&key("group-transfer/lease/", group))?
            .is_some_and(|lease| lease.head != state.snapshot().state_hash)
        {
            self.account_db()?.remove_actor_state(&key("group-transfer/lease/", group))?;
            self.account_db()?.remove_actor_state(&key(PENDING, group))?;
            for record_key in self.account_db()?.actor_state_key_page(SEND_PREFIX, 512)? {
                if self
                    .account_db()?
                    .load_actor_state::<TransferDelivery>(&record_key)?
                    .is_some_and(|row| {
                        row.control.group() == group
                            && matches!(row.control.body, TransferBody::Probe { .. })
                    })
                {
                    self.account_db()?.remove_actor_state(&record_key)?;
                }
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
