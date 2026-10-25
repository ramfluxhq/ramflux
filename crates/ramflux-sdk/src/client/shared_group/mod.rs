// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full authenticated group state, local actor certificates and root-qualified projections.
use crate::prelude::*;
use ramflux_crypto::{
    VerifiedGroupState, advance_group_state, certify_group_state_actor, sign_group_state_operation,
    sign_group_state_snapshot,
};
use ramflux_protocol::group_state::{GroupMemberIdentity, GroupStateActor, GroupStateChange};
use serde_json::{Value, json};

mod bootstrap;
pub(crate) use bootstrap::{PACKET_SCHEMA, PreparedSharedGroup, decode_packet, packet_bytes};
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(reason.into())
}
impl RamfluxClient {
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
        let operation = sign_group_state_operation(
            branch,
            &actor,
            group,
            1,
            None,
            GroupStateChange::Create {
                conversation_id: conversation.into(),
                max_members: 1000,
                new_member_history: "no_history".into(),
                name,
            },
        )?;
        let verified = sign_group_state_snapshot(branch, &actor, vec![operation])?;
        self.account_db()?.commit_shared_group_state(&verified, &actor)?;
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
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &actor,
            &previous,
            change,
        )?;
        self.account_db()?.commit_shared_group_state(&state, &actor)?;
        Ok(state)
    }
    pub(crate) fn accept_shared_group_state(
        &self,
        verified: &VerifiedGroupState,
        local_target: &str,
    ) -> Result<bool, SdkError> {
        let actor = self.owned_group_actor(local_target)?;
        let previous = self.account_db()?.shared_group_state(&verified.view().group_id)?;
        if verified.member_storage_key(&actor.identity)?.is_none() && previous.is_none() {
            return Err(invalid("first group snapshot does not grant local membership"));
        }
        Ok(self.account_db()?.commit_shared_group_state(verified, &actor)?)
    }
    pub(crate) async fn verify_shared_group_source(
        &self,
        gateway: &GatewaySessionConfig,
        state: &VerifiedGroupState,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let issuer = &state.snapshot().issuer;
        if issuer.identity.principal_id != entry.envelope.source_principal_id
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
        for member in &state.members {
            members.insert(member.identity.device_id.clone());
            roles.insert(member.identity.device_id.clone(), member.role.as_str().into());
        }
        if let Some(local) = self.account_db()?.client_record("group-local", group)? {
            let local: GroupMemberIdentity = serde_json::from_value(local)?;
            if let Some(role) = state.effective_role(&local.root_commitment, &local.device_id) {
                members.insert(local.device_id.clone());
                roles.insert(local.device_id, role.as_str().into());
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
