// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-root full snapshots with independent transport issuer authentication.
mod requests;
mod snapshot;
mod transfer;
mod transition;
use crate::{CryptoError, DeviceBranch, IdentityRoot};
use ed25519_dalek::Signer;
use ramflux_protocol::{
    canonical_json_bytes, encode_base64url,
    group_state::{
        GROUP_CHANGE_REQUEST_DOMAIN, GROUP_CHANGE_RESULT_DOMAIN, GROUP_REQUEST_TTL_SECONDS,
        GROUP_STATE_ACTOR_DOMAIN, GROUP_STATE_SNAPSHOT_DOMAIN, GroupCreatorTransfer,
        GroupDeviceExclusion, GroupMemberIdentity, GroupStateActor, GroupStateChange,
        GroupStateGenesis, GroupStateLimit, GroupStateSnapshot, MAX_GROUP_CREATOR_TRANSFERS,
        MAX_GROUP_DEVICES, MAX_GROUP_DEVICES_PER_ROOT, MAX_GROUP_NAME_BYTES, MAX_GROUP_STATE_BYTES,
        MAX_GROUP_STATE_EXCLUSIONS, MAX_GROUP_STATE_MEMBERS, SharedGroupMember, SharedGroupRole,
        SharedGroupState,
    },
};
pub use requests::*;
use serde_json::{Value, json};
pub use snapshot::{
    GroupStateCreateInput, advance_group_state, advance_native_group_state, create_group_state,
    create_native_group_state,
};
pub use transfer::{accept_group_transfer, verify_group_transfer_acceptance};
#[derive(Clone)]
pub struct VerifiedGroupState {
    snapshot: GroupStateSnapshot,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupStateRelation {
    Same,
    Extension,
    Ancestor,
    IncomingPreferred,
    ExistingPreferred,
    Unrelated,
    RemovalConflict,
}
impl VerifiedGroupState {
    #[must_use]
    pub const fn view(&self) -> &SharedGroupState {
        &self.snapshot.state
    }
    #[must_use]
    pub const fn snapshot(&self) -> &GroupStateSnapshot {
        &self.snapshot
    }
    #[must_use]
    pub const fn genesis(&self) -> &GroupStateGenesis {
        &self.snapshot.genesis
    }
    #[must_use]
    pub const fn creator(&self) -> &GroupStateActor {
        &self.snapshot.creator
    }
    /// # Errors
    /// Returns canonical encoding errors.
    pub fn genesis_hash(&self) -> Result<String, CryptoError> {
        snapshot::genesis_hash(self.genesis())
    }
    /// # Errors
    /// Rejects invalid identities or a principal conflicting with the creator-signed roster.
    pub fn member_storage_key(
        &self,
        identity: &GroupMemberIdentity,
    ) -> Result<Option<String>, CryptoError> {
        identity_valid(identity)?;
        if self.view().members.iter().any(|member| {
            member.identity.root_commitment == identity.root_commitment
                && member.identity.principal_id != identity.principal_id
        }) {
            return Err(invalid("identity conflicts with group membership"));
        }
        if self.view().effective_role(&identity.root_commitment, &identity.device_id).is_none() {
            return Ok(None);
        }
        Ok(Some(format!(
            "root~{}",
            encode_base64url(canonical_json_bytes(&(
                &identity.root_commitment,
                &identity.device_id
            ))?)
        )))
    }
    #[must_use]
    pub fn extends(&self, previous: &Self) -> bool {
        self.relation_to(previous).is_ok_and(|relation| {
            matches!(relation, GroupStateRelation::Same | GroupStateRelation::Extension)
        })
    }
    #[must_use]
    pub fn contains_head(&self, epoch: u64, hash: &str) -> bool {
        self.view().epoch == epoch && self.view().head_hash == hash
    }
    /// Compare only creator-certified full snapshots; no cross-root operation fork choice exists.
    /// # Errors
    /// Returns canonical encoding errors.
    pub fn relation_to(&self, previous: &Self) -> Result<GroupStateRelation, CryptoError> {
        let relation = self.authority_relation_to(previous)?;
        if matches!(relation, GroupStateRelation::Extension | GroupStateRelation::IncomingPreferred)
            && !transfer::preserves_removals(previous.view(), self.view())
        {
            return if self.snapshot.transfers == previous.snapshot.transfers {
                Ok(GroupStateRelation::RemovalConflict)
            } else {
                Err(ramflux_protocol::ProtocolError::GroupTransferRequiresSync.into())
            };
        }
        Ok(relation)
    }
    fn authority_relation_to(&self, previous: &Self) -> Result<GroupStateRelation, CryptoError> {
        use GroupStateRelation::{
            Ancestor, ExistingPreferred, Extension, IncomingPreferred, Same, Unrelated,
        };
        if self.genesis() != previous.genesis() {
            return Ok(Unrelated);
        }
        // Fresh handovers win their base and same-epoch sibling races. A
        // predecessor with newer accepted state requires a fresh handover.
        if self.snapshot.transfers != previous.snapshot.transfers {
            return Ok(if self.snapshot.transfers.starts_with(&previous.snapshot.transfers) {
                let handover = &self.snapshot.transfers[previous.snapshot.transfers.len()];
                let matches_base = previous.view().epoch + 1 == handover.epoch
                    && previous.snapshot.state_hash == handover.previous_hash;
                let sibling = previous.view().epoch == handover.epoch
                    && previous.snapshot.previous_hash.as_deref()
                        == Some(handover.previous_hash.as_str());
                if previous.view().epoch >= handover.acceptance.base_epoch
                    && !matches_base
                    && !sibling
                {
                    return Err(ramflux_protocol::ProtocolError::GroupTransferRequiresSync.into());
                }
                Extension
            } else if previous.snapshot.transfers.starts_with(&self.snapshot.transfers) {
                let transfer = &previous.snapshot.transfers[self.snapshot.transfers.len()];
                if self.view().epoch < transfer.epoch { Ancestor } else { Unrelated }
            } else {
                Unrelated
            });
        }
        // The handover snapshot is still signed by the former creator. Once
        // its transfer is known, that key cannot replace the accepted handover
        // content (or a successor head), even by reusing the same certificate.
        if self
            .snapshot
            .transfers
            .last()
            .is_some_and(|transfer| transfer.epoch == self.view().epoch)
            && self.snapshot.state_hash != previous.snapshot.state_hash
        {
            return Ok(Unrelated);
        }
        if self.view().epoch < previous.view().epoch {
            return Ok(Ancestor);
        }
        if self.view().epoch > previous.view().epoch {
            // A former creator cannot erase a transfer already accepted by this member.
            return Ok(if self.snapshot.transfers.starts_with(&previous.snapshot.transfers) {
                Extension
            } else {
                Unrelated
            });
        }
        if self.snapshot.state_hash == previous.snapshot.state_hash {
            return Ok(Same);
        }
        if snapshot::signer_key(self.snapshot())? != snapshot::signer_key(previous.snapshot())? {
            return Ok(Unrelated);
        }
        Ok(
            if ramflux_protocol::decode_base64url(&self.snapshot.state_hash)?
                < ramflux_protocol::decode_base64url(&previous.snapshot.state_hash)?
            {
                IncomingPreferred
            } else {
                ExistingPreferred
            },
        )
    }
}
pub(super) fn invalid(reason: &'static str) -> CryptoError {
    ramflux_protocol::ProtocolError::InvalidGroupState(reason).into()
}
pub(super) fn identity_valid(identity: &GroupMemberIdentity) -> Result<(), CryptoError> {
    for id in [&identity.principal_id, &identity.device_id, &identity.target_delivery_id] {
        if id.trim().is_empty()
            || id.len() > 256
            || !ramflux_protocol::text_safety::single_line_is_safe(id)
        {
            return Err(invalid("invalid member identity"));
        }
    }
    ramflux_protocol::validate_device_name(&identity.device_id)?;
    let root = ramflux_protocol::decode_base64url(&identity.root_commitment)?;
    if root.len() != 32 || encode_base64url(&root) != identity.root_commitment {
        return Err(invalid("invalid member root"));
    }
    let key = crate::verifying_key_from_base64url(&identity.signing_public_key)?;
    if key.is_weak() || encode_base64url(key.to_bytes()) != identity.signing_public_key {
        return Err(invalid("invalid member key"));
    }
    Ok(())
}
fn actor_body(actor: &GroupStateActor) -> Value {
    let mut body = json!({"domain":GROUP_STATE_ACTOR_DOMAIN,"identity":actor.identity,"root_public_key":actor.root_public_key});
    if let Some(authority) = &actor.native_authority {
        body["native_authority"] = json!(authority);
    }
    body
}
/// # Errors
/// Rejects an invalid actor or mismatched root and branch.
pub fn certify_group_state_actor(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    target: &str,
) -> Result<GroupStateActor, CryptoError> {
    if root.principal_id != branch.principal_id {
        return Err(invalid("actor principal mismatch"));
    }
    let public = root.signing_key.verifying_key();
    let mut actor = GroupStateActor {
        identity: GroupMemberIdentity {
            principal_id: branch.principal_id.clone(),
            root_commitment: crate::identity_root_commitment(&public),
            device_id: branch.device_id.clone(),
            signing_public_key: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
            target_delivery_id: target.into(),
        },
        root_public_key: encode_base64url(public.to_bytes()),
        root_signature: String::new(),
        native_authority: None,
    };
    identity_valid(&actor.identity)?;
    actor.root_signature = encode_base64url(
        root.signing_key.sign(&canonical_json_bytes(&actor_body(&actor))?).to_bytes(),
    );
    Ok(actor)
}
/// Build a born-v3 group actor from the current certified branch capability.
///
/// # Errors
/// Rejects a branch absent from the verified native authority, missing group capability,
/// expired authority, or a target that is not the branch's anchor-qualified delivery id.
pub fn certify_native_group_state_actor(
    record: &crate::custody::VerifiedRecord,
    branch: &DeviceBranch,
    target: &str,
    now: u64,
) -> Result<GroupStateActor, CryptoError> {
    let body = &record.envelope().body;
    let reference = ramflux_protocol::custody::DeviceRef {
        account_anchor: body.account_anchor.clone(),
        device_id: branch.device_id.clone(),
        device_epoch: branch.device_epoch,
    };
    let device = body
        .devices
        .iter()
        .find(|device| {
            device.device_id == branch.device_id && device.device_epoch == branch.device_epoch
        })
        .ok_or_else(|| invalid("native group branch unavailable"))?;
    let branch_certificate = device
        .branch_certificate
        .clone()
        .ok_or_else(|| invalid("native group branch certificate unavailable"))?;
    let mut actor = GroupStateActor {
        identity: GroupMemberIdentity {
            principal_id: body.principal_id.clone(),
            root_commitment: body.account_anchor.clone(),
            device_id: branch.device_id.clone(),
            signing_public_key: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
            target_delivery_id: target.into(),
        },
        root_public_key: body.master_certificate.body.self_signing_public_key.clone(),
        root_signature: String::new(),
        native_authority: Some(Box::new(ramflux_protocol::group_state::GroupNativeAuthority {
            master_certificate: body.master_certificate.clone(),
            branch_certificate,
        })),
    };
    identity_valid(&actor.identity)?;
    verify_group_state_actor_at(&actor, Some(now))?;
    record.authorize(&reference, "group", now)?;
    // Keep construction visibly distinct from the legacy root-signature path.
    actor.root_signature.clear();
    Ok(actor)
}
/// # Errors
/// Rejects malformed identities or certificates not signed by the claimed root.
pub fn verify_group_state_actor(actor: &GroupStateActor) -> Result<(), CryptoError> {
    verify_group_state_actor_at(actor, None)
}
pub(super) fn verify_group_state_actor_at(
    actor: &GroupStateActor,
    issued_at: Option<u64>,
) -> Result<(), CryptoError> {
    identity_valid(&actor.identity)?;
    if actor.native_authority.is_some() {
        return crate::custody::verify_group_native_authority(actor, issued_at);
    }
    let public = crate::verifying_key_from_base64url(&actor.root_public_key)?;
    if public.is_weak()
        || encode_base64url(public.to_bytes()) != actor.root_public_key
        || crate::identity_root_commitment(&public) != actor.identity.root_commitment
    {
        return Err(invalid("actor root mismatch"));
    }
    crate::verify_canonical_signature(
        &canonical_json_bytes(&actor_body(actor))?,
        &actor.root_signature,
        &actor.root_public_key,
    )
}
fn branch_matches(branch: &DeviceBranch, actor: &GroupStateActor) -> Result<(), CryptoError> {
    verify_group_state_actor(actor)?;
    if branch.device_id != actor.identity.device_id
        || branch.principal_id != actor.identity.principal_id
        || encode_base64url(branch.signing_key.verifying_key().to_bytes())
            != actor.identity.signing_public_key
    {
        return Err(invalid("actor branch mismatch"));
    }
    Ok(())
}
fn root_matches(root: &IdentityRoot, actor: &GroupStateActor) -> Result<(), CryptoError> {
    if actor.native_authority.is_some()
        || root.principal_id != actor.identity.principal_id
        || encode_base64url(root.signing_key.verifying_key().to_bytes()) != actor.root_public_key
    {
        return Err(invalid("creator root mismatch"));
    }
    Ok(())
}
fn check_issuer(view: &SharedGroupState, issuer: &GroupStateActor) -> Result<(), CryptoError> {
    if view.effective_role(&issuer.identity.root_commitment, &issuer.identity.device_id).is_none()
        || view.members.iter().any(|m| {
            m.identity.root_commitment == issuer.identity.root_commitment
                && m.identity.principal_id != issuer.identity.principal_id
        })
    {
        return Err(invalid("snapshot issuer is not an authorized member"));
    }
    Ok(())
}
fn transport_body(snapshot: &GroupStateSnapshot) -> Result<Value, CryptoError> {
    let mut value = serde_json::to_value(snapshot).map_err(|_| invalid("group JSON encoding"))?;
    value.as_object_mut().ok_or_else(|| invalid("snapshot object"))?.remove("signature");
    Ok(value)
}
/// Re-sign transport provenance without altering the creator's full snapshot.
/// # Errors
/// Rejects an invalid or unauthorized issuer.
pub fn resign_group_state_snapshot(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    state: &VerifiedGroupState,
) -> Result<VerifiedGroupState, CryptoError> {
    branch_matches(branch, actor)?;
    check_issuer(state.view(), actor)?;
    let mut snapshot = state.snapshot.clone();
    snapshot.issuer = actor.clone();
    snapshot.signature = crate::sign_with_device_branch(branch, &transport_body(&snapshot)?)?;
    verify_group_state_snapshot(snapshot)
}
/// # Errors
/// Rejects invalid creator signatures, roster structure, transport issuers, hashes or budgets.
pub fn verify_group_state_snapshot(
    snapshot: GroupStateSnapshot,
) -> Result<VerifiedGroupState, CryptoError> {
    snapshot::verify(&snapshot)?;
    verify_group_state_actor(&snapshot.issuer)?;
    check_issuer(&snapshot.state, &snapshot.issuer)?;
    crate::verify_device_branch_signature(
        &snapshot.issuer.identity.signing_public_key,
        &transport_body(&snapshot)?,
        &snapshot.signature,
    )?;
    Ok(VerifiedGroupState { snapshot })
}
#[cfg(test)]
mod tests;
