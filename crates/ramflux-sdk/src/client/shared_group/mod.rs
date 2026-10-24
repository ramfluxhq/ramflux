// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full authenticated group state, local actor certificates and root-qualified projections.
use crate::prelude::*;
use ramflux_crypto::{
    VerifiedGroupState, advance_group_state, certify_group_state_actor, sign_group_state_operation,
    sign_group_state_snapshot, verify_group_state_snapshot,
};
use ramflux_protocol::group_state::{
    GroupMemberIdentity, GroupStateActor, GroupStateChange, GroupStateSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const PACKET_SCHEMA: &str = "ramflux.sdk.group_state.v1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedGroupPacket {
    pub(crate) schema: String,
    pub(crate) snapshot_base64: String,
}
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(reason.into())
}
pub(crate) fn packet_bytes(state: &VerifiedGroupState) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&SharedGroupPacket {
        schema: PACKET_SCHEMA.into(),
        snapshot_base64: ramflux_protocol::encode_base64url(
            ramflux_protocol::canonical_json_bytes(state.snapshot())?,
        ),
    })?)
}
pub(crate) fn decode_packet(bytes: &[u8]) -> Result<Option<VerifiedGroupState>, SdkError> {
    let Ok(header) = serde_json::from_slice::<Value>(bytes) else {
        return Ok(None);
    };
    if header["schema"] != PACKET_SCHEMA {
        return Ok(None);
    }
    if bytes.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES * 2 {
        return Err(invalid("group state packet exceeds its byte budget"));
    }
    let packet: SharedGroupPacket = ramflux_protocol::parse_i_json(bytes)?;
    let bytes = ramflux_protocol::decode_base64url(&packet.snapshot_base64)
        .map_err(|_| invalid("invalid group state encoding"))?;
    Ok(Some(verify_group_state_snapshot(GroupStateSnapshot::from_wire_bytes(&bytes)?)?))
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
    /// Translate a known identity only after its root/key agrees with the signed group's pin.
    pub(crate) fn shared_group_storage_member(
        &self,
        group: &str,
        identity: &GroupMemberIdentity,
    ) -> Result<String, SdkError> {
        let state = self
            .account_db()?
            .shared_group_state(group)?
            .ok_or_else(|| invalid("shared group absent"))?;
        state.member_storage_key(identity)?.ok_or_else(|| invalid("device is not a group member"))
    }
    pub(crate) fn group_member_storage_id(
        &self,
        group: &str,
        device: &str,
    ) -> Result<String, SdkError> {
        let Some(state) = self.account_db()?.shared_group_state(group)? else {
            return Ok(device.into());
        };
        if self.device_branch.as_ref().is_some_and(|branch| branch.device_id == device) {
            return self
                .shared_group_storage_member(group, &self.owned_group_actor("local")?.identity);
        }
        let matches = state
            .view()
            .members
            .iter()
            .filter(|member| member.identity.device_id == device)
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(invalid("ambiguous device name requires a root-qualified identity"));
        }
        if let Some(member) = matches.first() {
            return self.shared_group_storage_member(group, &member.identity);
        }
        let record = self
            .account_db()?
            .client_record("device", device)?
            .ok_or_else(|| invalid("group sender identity is unavailable"))?;
        let required = |field: &str| {
            record[field]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("group sender identity is incomplete"))
        };
        self.shared_group_storage_member(
            group,
            &GroupMemberIdentity {
                principal_id: required("principal_id")?,
                root_commitment: required("principal_commitment")?,
                device_id: device.into(),
                signing_public_key: required("signing_public_key")?,
                target_delivery_id: required("target_delivery_id")?,
            },
        )
    }
}

#[cfg(test)]
mod tests;
