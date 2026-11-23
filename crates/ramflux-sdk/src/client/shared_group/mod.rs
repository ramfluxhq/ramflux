// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full authenticated group state, local actor certificates and root-qualified projections.
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use ramflux_crypto::{
    VerifiedGroupState, advance_native_group_state_with_order, certify_native_group_state_actor,
    create_native_group_state,
};
use ramflux_protocol::group_state::{GroupMemberIdentity, GroupStateActor, GroupStateChange};
use serde_json::{Value, json};

mod bootstrap;
mod controls;
mod generated;
mod generated_send;
mod receive_directory;
mod snapshot_generated;
pub(crate) use receive_directory::{GroupDirectoryEvidence, GroupDirectoryRequest};
mod creator_conflicts;
mod devices;
// Pure bounded selection for layer planning; this is not an authorization capability.
pub(crate) use devices::select as select_layer_devices;
mod federation;
mod invitations;
pub(crate) mod maintenance;
mod message_ids;
mod own_consent;
mod requests;
mod routes;
mod service_row;
mod transfer;
mod transfer_outcome;
mod transfer_wire;
#[cfg(test)]
pub(crate) use bootstrap::decode_packet as decode_shared_group_packet;
pub(crate) use bootstrap::{PreparedSharedGroup, is_packet as is_shared_group_packet};
pub(crate) use controls::{BeaconRecord, GroupControlBody, GroupControlPacket};
pub(crate) use requests::request_key as request_record_key;
pub(crate) use transfer::{SEND_PREFIX as TRANSFER_SEND_PREFIX, TransferDelivery};
pub(crate) use transfer_wire::{TransferBody, TransferControl};
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(reason.into())
}
impl RamfluxClient {
    pub(crate) fn local_is_group_member(&self, group: &str) -> Result<bool, SdkError> {
        if self.group_invitation_declined(group)? {
            return Ok(false);
        }
        if let Some(state) = self.account_db()?.shared_group_state(group)? {
            let local = self.owned_device_identity()?;
            return Ok(state
                .view()
                .effective_role(local.root_commitment(), local.device_id())
                .is_some());
        }
        self.born_v3_account.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(false)
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
        let account = self.born_v3_account.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(certify_native_group_state_actor(
            account.verified(),
            branch,
            target,
            crate::custody::network_now()?,
        )?)
    }

    pub(crate) fn shared_group_create(
        &self,
        group: &str,
        conversation: &str,
        name: Option<String>,
        target: &str,
    ) -> Result<VerifiedGroupState, SdkError> {
        self.shared_group_create_with_primary(group, conversation, name, target, None)
    }
    pub(crate) fn shared_group_create_with_primary(
        &self,
        group: &str,
        conversation: &str,
        name: Option<String>,
        target: &str,
        primary: Option<&ramflux_crypto::custody::SelfSigningKey>,
    ) -> Result<VerifiedGroupState, SdkError> {
        if self.account_db()?.group_snapshot_epoch(group)?.is_some() {
            return Err(invalid("group already exists"));
        }
        let actor = self.owned_group_actor(target)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let input = ramflux_crypto::GroupStateCreateInput {
            group_id: group,
            conversation_id: conversation,
            max_members: 200,
            new_member_history: "no_history",
            name,
            now: now_unix_timestamp(),
        };
        let verified = create_native_group_state(
            primary.ok_or(SdkError::CustodyVaultUnavailable)?,
            branch,
            &actor,
            input,
        )?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.account_db()?.commit_shared_group_state(&verified, &actor)?;
            self.observe_native_task_roster(&verified)?;
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
        self.shared_group_change_with_primary(group, target, change, None)
    }
    pub(crate) fn shared_group_change_with_primary(
        &self,
        group: &str,
        target: &str,
        change: GroupStateChange,
        primary: Option<&ramflux_crypto::custody::SelfSigningKey>,
    ) -> Result<VerifiedGroupState, SdkError> {
        let previous = self
            .account_db()?
            .shared_group_state(group)?
            .ok_or_else(|| invalid("group requires an authenticated state snapshot"))?;
        let nonce = match &change {
            GroupStateChange::TransferOwnership { acceptance, .. } => {
                Some(acceptance.nonce.as_str())
            }
            _ => None,
        };
        self.check_group_transfer_lease(group, nonce)?;
        let actor = self.owned_group_actor(target)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let primary = primary.ok_or(SdkError::CustodyVaultUnavailable)?;
        let state =
            self.account_db()?.write_transaction(|| -> Result<VerifiedGroupState, SdkError> {
                let order = self.service_order_for_change(&previous, &change, &actor)?;
                let state = advance_native_group_state_with_order(
                    primary,
                    branch,
                    &actor,
                    &previous,
                    change.clone(),
                    order,
                )?;
                self.account_db()?.commit_shared_group_state(&state, &actor)?;
                self.observe_native_task_roster(&state)?;
                self.record_group_write(&state, change)?;
                self.finish_group_transfer_head_change(&state)?;
                self.project_accepted_group_service(Some(&previous), &state)?;
                crate::bus::enqueue_shared_group(self, &state, Some(&previous))?;
                Ok(state)
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
            match self.reconcile_group_state(verified, local_target, None)? {
                creator_conflicts::Reconciled::Adopt(reconciled) => self
                    .commit_reconciled_group_state(
                        &reconciled,
                        verified,
                        previous.as_ref(),
                        &actor,
                    ),
                // Skipped states change nothing; a deferred creator repair is held by its marker
                // and committed once `redrive_creator_repairs` runs with the account primary.
                creator_conflicts::Reconciled::Skip | creator_conflicts::Reconciled::Deferred => {
                    Ok(false)
                }
            }
        })
    }
    /// Commit a reconciled state; republish it only when it differs from the received one.
    pub(super) fn commit_reconciled_group_state(
        &self,
        reconciled: &VerifiedGroupState,
        received: &VerifiedGroupState,
        previous: Option<&VerifiedGroupState>,
        actor: &GroupStateActor,
    ) -> Result<bool, SdkError> {
        let changed = self.account_db()?.commit_shared_group_state(reconciled, actor)?;
        self.observe_native_task_roster(reconciled)?;
        self.finish_group_transfer_head_change(reconciled)?;
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
        if changed {
            self.project_accepted_group_service(previous, reconciled)?;
        }
        if reconciled.snapshot().state_hash != received.snapshot().state_hash {
            crate::bus::enqueue_shared_group(self, reconciled, previous)?;
        }
        Ok(changed)
    }
    pub(crate) async fn verify_shared_group_source(
        &self,
        gateway: &GatewaySessionConfig,
        state: &VerifiedGroupState,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        self.verify_group_actor_source(gateway, &state.snapshot().issuer, entry).await?;
        self.ensure_shared_group_device(
            state,
            &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
        )
    }
    pub(crate) async fn verify_group_actor_source(
        &self,
        gateway: &GatewaySessionConfig,
        issuer: &GroupStateActor,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let root = self.group_actor_manifest_request(issuer, entry)?;
        let origin = self.sender_manifest_origin(&entry.envelope, &root)?;
        let manifest =
            crate::client::foreign_manifest::fetch_sender_manifest(gateway, origin, &root).await?;
        self.accept_group_actor_manifest(issuer, entry, &manifest)
    }

    pub(crate) fn group_actor_manifest_request(
        &self,
        issuer: &GroupStateActor,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        self.confirm_group_actor_transport(issuer, entry)?;
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if !self.account_db()?.charge_contact_request(
            &format!("group-control:{}", source.root_commitment()),
            32,
            60,
            now_unix_timestamp(),
        )? {
            return Err(SdkError::InboundPending("group control source rate exceeded".into()));
        }
        Ok(issuer.identity.root_commitment.clone())
    }

    fn confirm_group_actor_transport(
        &self,
        issuer: &GroupStateActor,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if issuer.identity.root_commitment != source.root_commitment()
            || issuer.identity.device_id != source.device_id()
            || issuer.identity.principal_id != entry.envelope.source_principal_id
            || issuer.identity.device_id != entry.envelope.source_device_id
        {
            return Err(invalid("group state issuer differs from authenticated transport"));
        }
        Ok(())
    }

    pub(crate) fn accept_group_actor_manifest(
        &self,
        issuer: &GroupStateActor,
        entry: &GatewayInboxEntry,
        manifest: &crate::SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        self.confirm_group_actor_transport(issuer, entry)?;
        super::contact::verify_device_manifest(manifest, &issuer.identity.root_commitment)?;
        if manifest.principal_id != issuer.identity.principal_id
            || !group_actor_matches_manifest(manifest, issuer)
            || !manifest.devices.iter().any(|device| {
                device.device_id == issuer.identity.device_id
                    && device.branch_public_key == issuer.identity.signing_public_key
                    && device.target_delivery_id == issuer.identity.target_delivery_id
            })
        {
            return Err(invalid("group state issuer is absent from its verified manifest"));
        }
        self.persist_identity_directory(manifest)?;
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
        let selected = match self.shared_group_selected_devices(&verified) {
            Ok(selected) => selected,
            Err(
                SdkError::InboundPending(_)
                | SdkError::SenderManifestRequired { .. }
                | SdkError::FreshHeadRequired { .. },
            ) => {
                // Display only the verified historical roster when current authority is absent.
                // Live routes and sends still use the strict roster selector directly.
                devices::select(state, &BTreeMap::new())
            }
            Err(error) => return Err(error),
        };
        for (root, names) in selected {
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
        value["conversation_id"] = json!(state.conversation_id);
        value["member_roster"] = json!(state.members);
        value["excluded_devices"] = json!(state.excluded);
        value["name"] = json!(state.name);
        value["name_epoch"] = json!(state.name_epoch);
        Ok(Some(value))
    }
}

fn group_actor_matches_manifest(
    manifest: &crate::prekey::SdkDeviceManifestResponse,
    issuer: &GroupStateActor,
) -> bool {
    match (&manifest.custody, &issuer.native_authority) {
        (Some(custody), Some(authority)) => {
            let current = &custody.publication.record.body.master_certificate;
            authority.master_certificate == *current
                && issuer.root_public_key == current.body.self_signing_public_key
                && manifest.root_public_key == current.body.master_public_key
        }
        (None, None) => manifest.root_public_key == issuer.root_public_key,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod native_tests;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use requests::RequestRecord;
