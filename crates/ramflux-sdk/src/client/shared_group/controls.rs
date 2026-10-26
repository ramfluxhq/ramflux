// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Small authenticated controls share pair delivery without impersonating group snapshots.
use crate::prelude::*;
use ramflux_protocol::group_state::{GroupChangeRequest, GroupChangeResult, GroupStateActor};
use serde::{Deserialize, Serialize};
pub(crate) const CONTROL_SCHEMA: &str = "ramflux.sdk.group_control.v2";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupControlPacket {
    pub schema: String,
    pub body: GroupControlBody,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum GroupControlBody {
    Request { request: GroupChangeRequest, federation: Option<LocalBusFederationRoute> },
    Result { result: GroupChangeResult },
    DeviceSet { group_id: String, actor: GroupStateActor, device_set_epoch: u64 },
    Transfer { control: Box<super::TransferControl> },
}
impl GroupControlPacket {
    pub(crate) fn new(body: GroupControlBody) -> Self {
        Self { schema: CONTROL_SCHEMA.into(), body }
    }
    pub(crate) fn group(&self) -> &str {
        match &self.body {
            GroupControlBody::Request { request, .. } => &request.group_id,
            GroupControlBody::Result { result } => &result.group_id,
            GroupControlBody::DeviceSet { group_id, .. } => group_id,
            GroupControlBody::Transfer { control } => control.group(),
        }
    }
    pub(crate) fn actor(&self) -> &GroupStateActor {
        match &self.body {
            GroupControlBody::Request { request, .. } => &request.actor,
            GroupControlBody::Result { result } => &result.creator,
            GroupControlBody::DeviceSet { actor, .. } => actor,
            GroupControlBody::Transfer { control } => control.actor(),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BeaconRecord {
    pub packet: GroupControlPacket,
    pub expires_at: i64,
    pub next_at: i64,
    pub delivered: BTreeSet<(String, String)>,
}
impl RamfluxClient {
    pub(crate) fn stage_group_device_beacon(
        &self,
        group: &str,
        target: &str,
        epoch: u64,
    ) -> Result<(), SdkError> {
        let id = format!("group-beacon/{}", ramflux_protocol::encode_base64url(group));
        let now = now_unix_timestamp();
        let old: Option<BeaconRecord> = self.account_db()?.load_actor_state(&id)?;
        if old.is_some_and(|old| matches!(old.packet.body,GroupControlBody::DeviceSet {device_set_epoch,..} if device_set_epoch==epoch)) { return Ok(()); }
        self.account_db()?.persist_actor_state(
            &id,
            &BeaconRecord {
                packet: GroupControlPacket::new(GroupControlBody::DeviceSet {
                    group_id: group.into(),
                    actor: self.owned_group_actor(target)?,
                    device_set_epoch: epoch,
                }),
                expires_at: now.saturating_add(7 * 86400),
                next_at: now,
                delivered: BTreeSet::new(),
            },
        )?;
        Ok(())
    }
    fn admit_group_control(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        entry: &GatewayInboxEntry,
        packet: &GroupControlPacket,
    ) -> Result<(), SdkError> {
        ramflux_crypto::verify_group_state_actor(packet.actor())?;
        if let GroupControlBody::Transfer { control } = &packet.body {
            control.verify(now_unix_timestamp())?;
            match &control.body {
                super::TransferBody::Probe { probe } => {
                    ramflux_crypto::verify_group_state_actor(&probe.creator)?;
                    if probe.actor.identity.root_commitment
                        != state.creator().identity.root_commitment
                        || probe.base.genesis != *state.genesis()
                        || probe.required.len()
                            > ramflux_protocol::group_state::MAX_GROUP_DEVICES_PER_ROOT + 1
                        || probe.required.iter().any(|device| {
                            device.root != probe.actor.identity.root_commitment
                                && (device.root != probe.creator.identity.root_commitment
                                    || device.device != probe.creator.identity.device_id)
                        })
                    {
                        return Err(StorageError::GroupPermissionDenied.into());
                    }
                }
                super::TransferBody::Head { reply } => {
                    if reply.head.genesis != *state.genesis() {
                        return Err(StorageError::GroupPermissionDenied.into());
                    }
                    let own = self.owned_device_identity()?;
                    if !control
                        .targets()
                        .iter()
                        .any(|d| d.root == own.root_commitment() && d.device == own.device_id())
                    {
                        return Err(StorageError::GroupPermissionDenied.into());
                    }
                }
            }
        }
        let actor = &packet.actor().identity;
        // The certified local roster is sufficient for admission; outsiders must
        // not trigger directory IO or consume persistent request/result capacity.
        if state.view().effective_role(&actor.root_commitment, &actor.device_id).is_none()
            || (matches!(packet.body, GroupControlBody::Result { .. })
                && actor.root_commitment != state.creator().identity.root_commitment)
            || (matches!(packet.body, GroupControlBody::Request { .. })
                && self.owned_device_identity()?.root_commitment()
                    != state.creator().identity.root_commitment)
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        let source = self.authenticated_device_identity(entry)?;
        if source.root_commitment() != actor.root_commitment
            || source.device_id() != actor.device_id
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        Ok(())
    }
    pub(crate) async fn prepare_group_control(
        &self,
        engine: &GatewaySessionEngine,
        entry: &GatewayInboxEntry,
        routing: &crate::client::routed::Routing,
        packet: &GroupControlPacket,
    ) -> Result<(), SdkError> {
        if packet.schema != CONTROL_SCHEMA || routing.group_id.as_deref() != Some(packet.group()) {
            return Err(super::invalid("group control routing mismatch"));
        }
        let state = self.group_control_base(packet)?;
        if routing.conversation_id != state.view().conversation_id {
            return Err(super::invalid("group control conversation mismatch"));
        }
        self.admit_group_control(&state, entry, packet)?;
        self.verify_group_actor_source(&engine.config, packet.actor(), entry).await?;
        match &packet.body {
            GroupControlBody::Transfer { .. } => {}
            GroupControlBody::Request { request, federation } => {
                ramflux_crypto::verify_group_change_request(request, now_unix_timestamp())?;
                let own = self.owned_device_identity()?;
                if own.root_commitment() != state.creator().identity.root_commitment
                    || request.genesis_hash != state.genesis_hash()?
                {
                    return Err(StorageError::GroupPermissionDenied.into());
                }
                // Candidate additions can only use an active key from the current directory.
                if let ramflux_protocol::GroupStateChange::Add { member, .. } = &request.change
                    && ramflux_crypto::validate_group_change_request(
                        &state,
                        request,
                        now_unix_timestamp(),
                    )
                    .is_ok()
                {
                    let manifest = if let Some(federation) = federation {
                        let url = federation.recipient_prekey_url.clone().ok_or_else(|| {
                            super::invalid("federated addition requires prekey directory")
                        })?;
                        let root = member.root_commitment.clone();
                        tokio::task::spawn_blocking(move || {
                            crate::client::contact::fetch_verified_device_manifest_from_url(
                                &url, &root,
                            )
                        })
                        .await
                        .map_err(|error| {
                            SdkError::InboundPending(format!("federation manifest worker: {error}"))
                        })??
                    } else {
                        self.shared_group_manifest(
                            &engine.config,
                            packet.group(),
                            &member.root_commitment,
                        )
                        .await?
                    };
                    if manifest.principal_id != member.principal_id
                        || !manifest.devices.iter().any(|device| {
                            device.device_id == member.device_id
                                && device.branch_public_key == member.signing_public_key
                                && device.target_delivery_id == member.target_delivery_id
                        })
                    {
                        return Err(StorageError::GroupPermissionDenied.into());
                    }
                    self.persist_identity_directory(&manifest)?;
                }
            }
            GroupControlBody::Result { result } => {
                if result.creator.identity.root_commitment
                    != state.creator().identity.root_commitment
                {
                    return Err(StorageError::GroupPermissionDenied.into());
                }
            }
            GroupControlBody::DeviceSet { actor, device_set_epoch, .. } => {
                if state
                    .view()
                    .effective_role(&actor.identity.root_commitment, &actor.identity.device_id)
                    .is_none()
                    || self
                        .observed_device_set(&actor.identity.root_commitment)?
                        .is_none_or(|set| set.device_set_epoch < *device_set_epoch)
                {
                    return Err(StorageError::GroupPermissionDenied.into());
                }
                self.ensure_shared_group_device(
                    &state,
                    &self.authenticated_device_identity(entry)?,
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn apply_group_control(
        &self,
        packet: &GroupControlPacket,
    ) -> Result<bool, SdkError> {
        match &packet.body {
            GroupControlBody::Request { request, federation } => {
                self.insert_group_request(request, true)?;
                if let Some(mut record) = self.group_change_record(request, true)?
                    && record.federation.is_none()
                {
                    record.federation.clone_from(federation);
                    self.persist_group_request(&record)?;
                }
            }
            GroupControlBody::Result { result } => self.apply_group_request_result(result)?,
            GroupControlBody::DeviceSet { .. } => {}
            GroupControlBody::Transfer { control } => {
                let own = self.owned_device_identity()?;
                let local = self.trusted_device(&own)?;
                let target = local["target_delivery_id"]
                    .as_str()
                    .ok_or(StorageError::GroupPermissionDenied)?;
                self.apply_group_transfer_control(control, target)?;
            }
        }
        Ok(false)
    }
}

impl RamfluxClient {
    fn group_control_base(
        &self,
        packet: &GroupControlPacket,
    ) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
        if let Some(state) = self.account_db()?.shared_group_state(packet.group())? {
            Ok(state)
        } else if let GroupControlBody::Transfer { control } = &packet.body {
            if let super::TransferBody::Probe { probe } = &control.body {
                let base = ramflux_crypto::verify_group_state_snapshot(probe.base.clone())?;
                if self.group_snapshot_requires_consent(&base)? {
                    return Err(super::invalid("group consent is pending"));
                }
                Ok(base)
            } else {
                Err(StorageError::GroupPermissionDenied.into())
            }
        } else {
            Err(StorageError::GroupPermissionDenied.into())
        }
    }
}
