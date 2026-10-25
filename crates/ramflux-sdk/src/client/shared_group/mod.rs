// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full authenticated group state, local actor certificates and root-qualified projections.
use crate::prelude::*;
use ramflux_crypto::{
    VerifiedGroupState, advance_group_state, certify_group_state_actor, create_group_state,
};
use ramflux_protocol::group_state::{GroupMemberIdentity, GroupStateActor, GroupStateChange};
use serde_json::{Value, json};

mod bootstrap;
mod controls;
mod creator_conflicts;
mod devices;
mod federation;
mod invitations;
mod message_ids;
mod requests;
mod routes;
pub(crate) use bootstrap::{PreparedSharedGroup, is_packet as is_shared_group_packet};
#[cfg(test)]
use bootstrap::{decode_packet, packet_bytes};
pub(crate) use controls::{BeaconRecord, GroupControlBody, GroupControlPacket};
pub(crate) use requests::request_key as request_record_key;
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(reason.into())
}
impl RamfluxClient {
    pub(crate) fn local_is_group_member(&self, group: &str) -> Result<bool, SdkError> {
        if let Some(state) = self.account_db()?.shared_group_state(group)? {
            let local = self.owned_device_identity()?;
            return Ok(state
                .view()
                .effective_role(local.root_commitment(), local.device_id())
                .is_some());
        }
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(self.group_state(group)?.members.contains(&branch.device_id))
    }

    pub(super) fn shared_group_local_target(&self, group: &str) -> Result<String, SdkError> {
        let local: GroupMemberIdentity = serde_json::from_value(
            self.account_db()?
                .client_record("group-local", group)?
                .ok_or(StorageError::GroupPermissionDenied)?,
        )?;
        Ok(local.target_delivery_id)
    }

    pub(crate) fn owned_group_actor(&self, target: &str) -> Result<GroupStateActor, SdkError> {
        Ok(certify_group_state_actor(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            target,
        )?)
    }
    pub(crate) fn shared_group_create(
        &self,
        group: &str,
        conversation: &str,
        name: Option<String>,
        target: &str,
    ) -> Result<VerifiedGroupState, SdkError> {
        if self.account_db()?.group_snapshot_epoch(group)?.is_some() {
            return Err(invalid("group already exists"));
        }
        let actor = self.owned_group_actor(target)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let verified = create_group_state(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            branch,
            &actor,
            ramflux_crypto::GroupStateCreateInput {
                group_id: group,
                conversation_id: conversation,
                max_members: 200,
                new_member_history: "no_history",
                name,
                now: now_unix_timestamp(),
            },
        )?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.account_db()?.commit_shared_group_state(&verified, &actor)?;
            crate::bus::enqueue_shared_group(self, &verified, None)
        })?;
        Ok(verified)
    }
    pub(crate) fn shared_group_change(
        &self,
        group: &str,
        target: &str,
        change: GroupStateChange,
    ) -> Result<VerifiedGroupState, SdkError> {
        let previous = self
            .account_db()?
            .shared_group_state(group)?
            .ok_or_else(|| invalid("group requires an authenticated state snapshot"))?;
        let actor = self.owned_group_actor(target)?;
        let state = advance_group_state(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &actor,
            &previous,
            change.clone(),
        )?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.account_db()?.commit_shared_group_state(&state, &actor)?;
            self.record_group_write(&state, change)?;
            crate::bus::enqueue_shared_group(self, &state, Some(&previous))
        })?;
        Ok(state)
    }
    pub(crate) fn accept_shared_group_state(
        &self,
        verified: &VerifiedGroupState,
        local_target: &str,
    ) -> Result<bool, SdkError> {
        self.account_db()?.write_transaction(|| {
            let actor = self.owned_group_actor(local_target)?;
            let previous = self.account_db()?.shared_group_state(&verified.view().group_id)?;
            if verified.member_storage_key(&actor.identity)?.is_none() && previous.is_none() {
                return Err(invalid("first group snapshot does not grant local membership"));
            }
            let Some(reconciled) = self.reconcile_group_state(verified, local_target)? else {
                return Ok(false);
            };
            let changed = self.account_db()?.commit_shared_group_state(&reconciled, &actor)?;
            for record in self.group_change_records()?.into_iter().filter(|record| {
                !record.incoming && record.request.group_id == reconciled.view().group_id
            }) {
                if let (GroupStateChange::Add { member, .. }, Some(federation)) =
                    (&record.request.change, record.federation)
                    && reconciled.view().members.iter().any(|current| current.identity == *member)
                {
                    self.persist_shared_group_federation_route(
                        &reconciled.view().group_id,
                        &member.root_commitment,
                        &federation,
                    )?;
                }
            }
            if reconciled.snapshot().state_hash != verified.snapshot().state_hash {
                crate::bus::enqueue_shared_group(self, &reconciled, previous.as_ref())?;
            }
            Ok(changed)
        })
    }
    pub(crate) async fn verify_shared_group_source(
        &self,
        gateway: &GatewaySessionConfig,
        state: &VerifiedGroupState,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        self.verify_group_actor_source(gateway, &state.snapshot().issuer, entry).await?;
        self.ensure_shared_group_device(state, &self.authenticated_device_identity(entry)?)
    }
    pub(crate) async fn verify_group_actor_source(
        &self,
        gateway: &GatewaySessionConfig,
        issuer: &GroupStateActor,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(entry)?;
        if issuer.identity.root_commitment != source.root_commitment()
            || issuer.identity.device_id != source.device_id()
            || issuer.identity.principal_id != entry.envelope.source_principal_id
            || issuer.identity.device_id != entry.envelope.source_device_id
        {
            return Err(invalid("group state issuer differs from authenticated transport"));
        }
        let manifest = crate::client::contact::fetch_verified_device_manifest(
            gateway,
            &issuer.identity.root_commitment,
        )
        .await?;
        if manifest.principal_id != issuer.identity.principal_id
            || manifest.root_public_key != issuer.root_public_key
            || !manifest.devices.iter().any(|device| {
                device.device_id == issuer.identity.device_id
                    && device.branch_public_key == issuer.identity.signing_public_key
                    && device.target_delivery_id == issuer.identity.target_delivery_id
            })
        {
            return Err(invalid("group state issuer is absent from its verified manifest"));
        }
        self.persist_identity_directory(&manifest)?;
        Ok(())
    }
    /// A public display view retains literal names; authority and pins use verified root-qualified ids.
    pub(crate) fn shared_group_display(&self, group: &str) -> Result<Option<GroupState>, SdkError> {
        let Some(verified) = self.account_db()?.shared_group_state(group)? else {
            return Ok(None);
        };
        let state = verified.view();
        let mut members = BTreeSet::new();
        let mut roles = BTreeMap::new();
        for (root, names) in self.shared_group_selected_devices(&verified)? {
            for device in names {
                if let Some(role) = state.effective_role(&root, &device) {
                    members.insert(device.clone());
                    roles.insert(device, role.as_str().into());
                }
            }
        }
        Ok(Some(GroupState {
            group_id: state.group_id.clone(),
            group_epoch: state.epoch,
            max_members: state.max_members,
            new_member_history: state.new_member_history.clone(),
            members,
            roles,
        }))
    }
    pub(crate) fn shared_group_metadata(&self, group: &str) -> Result<Option<Value>, SdkError> {
        let Some(verified) = self.account_db()?.shared_group_state(group)? else {
            return Ok(None);
        };
        let state = verified.view();
        let display = self.shared_group_display(group)?.ok_or_else(|| invalid("group absent"))?;
        let mut value = serde_json::to_value(display)?;
        value["member_roster"] = json!(state.members);
        value["excluded_devices"] = json!(state.excluded);
        value["name"] = json!(state.name);
        value["name_epoch"] = json!(state.name_epoch);
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests;
