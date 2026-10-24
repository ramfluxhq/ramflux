// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authenticated group writers, signed history and monotonic snapshot proofs.
mod checkpoint;
mod transition;
use crate::{CryptoError, DeviceBranch, IdentityRoot};
pub use checkpoint::{advance_group_state, compact_group_state};
use ed25519_dalek::Signer;
use ramflux_protocol::{
    canonical_json_bytes, encode_base64url,
    group_state::{
        GROUP_STATE_ACTOR_DOMAIN, GROUP_STATE_OPERATION_DOMAIN, GROUP_STATE_SNAPSHOT_DOMAIN,
        GroupDeviceExclusion, GroupMemberIdentity, GroupStateActor, GroupStateChange,
        GroupStateOperation, GroupStateSnapshot, MAX_GROUP_NAME_BYTES, MAX_GROUP_STATE_BYTES,
        MAX_GROUP_STATE_EXCLUSIONS, MAX_GROUP_STATE_MEMBERS, MAX_GROUP_STATE_STEPS,
        SharedGroupMember, SharedGroupRole, SharedGroupState,
    },
};
use serde_json::{Value, json};
#[derive(Clone)]
pub struct VerifiedGroupState {
    snapshot: GroupStateSnapshot,
    view: SharedGroupState,
    heads: std::collections::BTreeMap<u64, String>,
}
impl VerifiedGroupState {
    #[must_use]
    pub const fn view(&self) -> &SharedGroupState {
        &self.view
    }
    #[must_use]
    pub const fn snapshot(&self) -> &GroupStateSnapshot {
        &self.snapshot
    }
    #[must_use]
    pub fn contains_head(&self, epoch: u64, hash: &str) -> bool {
        self.heads.get(&epoch).is_some_and(|known| known == hash)
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
    if identity.device_id.starts_with("root~") || identity.device_id.starts_with("legacy~") {
        return Err(invalid("reserved device name"));
    }
    let root = ramflux_protocol::decode_base64url(&identity.root_commitment)?;
    if root.len() != 32 || encode_base64url(&root) != identity.root_commitment {
        return Err(invalid("invalid member root"));
    }
    let key = crate::verifying_key_from_base64url(&identity.signing_public_key)?;
    if key.is_weak() || encode_base64url(key.to_bytes()) != identity.signing_public_key {
        return Err(invalid("invalid member signing key"));
    }
    Ok(())
}
fn actor_body(actor: &GroupStateActor) -> Value {
    json!({"domain":GROUP_STATE_ACTOR_DOMAIN,"identity":actor.identity,"root_public_key":actor.root_public_key})
}
fn operation_body(operation: &GroupStateOperation) -> Value {
    json!({"domain":GROUP_STATE_OPERATION_DOMAIN,"schema":operation.schema,"group_id":operation.group_id,"epoch":operation.epoch,"previous_hash":operation.previous_hash,"actor":operation.actor,"change":operation.change})
}
fn snapshot_body(snapshot: &GroupStateSnapshot) -> Value {
    json!({"domain":GROUP_STATE_SNAPSHOT_DOMAIN,"schema":snapshot.schema,"group_id":snapshot.group_id,"epoch":snapshot.epoch,"state_hash":snapshot.state_hash,"checkpoint":snapshot.checkpoint,"operations":snapshot.operations,"issuer":snapshot.issuer})
}
/// Root-sign an exact local branch key for group state. Roles are never part of this certificate.
/// # Errors
/// Rejects root/branch identity mismatch, invalid identifiers, keys or canonical data.
pub fn certify_group_state_actor(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    target: &str,
) -> Result<GroupStateActor, CryptoError> {
    if root.principal_id != branch.principal_id {
        return Err(invalid("actor root principal mismatch"));
    }
    let public = root.signing_key.verifying_key();
    let mut actor = GroupStateActor {
        identity: GroupMemberIdentity {
            principal_id: branch.principal_id.clone(),
            root_commitment: crate::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &public.to_bytes(),
            ),
            device_id: branch.device_id.clone(),
            signing_public_key: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
            target_delivery_id: target.into(),
        },
        root_public_key: encode_base64url(public.to_bytes()),
        root_signature: String::new(),
    };
    identity_valid(&actor.identity)?;
    actor.root_signature = encode_base64url(
        root.signing_key.sign(&canonical_json_bytes(&actor_body(&actor))?).to_bytes(),
    );
    Ok(actor)
}
/// # Errors
/// Rejects malformed identities or a certificate not signed by the claimed root.
pub fn verify_group_state_actor(actor: &GroupStateActor) -> Result<(), CryptoError> {
    identity_valid(&actor.identity)?;
    let public = crate::verifying_key_from_base64url(&actor.root_public_key)?;
    if public.is_weak()
        || encode_base64url(public.to_bytes()) != actor.root_public_key
        || crate::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &public.to_bytes(),
        ) != actor.identity.root_commitment
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
/// # Errors
/// Rejects an invalid actor or canonical serialization. History authority is checked by snapshot verification.
pub fn sign_group_state_operation(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    group: &str,
    epoch: u64,
    previous_hash: Option<String>,
    change: GroupStateChange,
) -> Result<GroupStateOperation, CryptoError> {
    branch_matches(branch, actor)?;
    let mut operation = GroupStateOperation {
        schema: GROUP_STATE_OPERATION_DOMAIN.into(),
        group_id: group.into(),
        epoch,
        previous_hash,
        actor: actor.clone(),
        change,
        signature: String::new(),
    };
    operation.signature = crate::sign_with_device_branch(branch, &operation_body(&operation))?;
    Ok(operation)
}
/// # Errors
/// Rejects noncanonical operation data.
pub fn group_state_head_hash(operation: &GroupStateOperation) -> Result<String, CryptoError> {
    Ok(crate::blake3_256_base64url(
        "ramflux.group_state.head.v1",
        &canonical_json_bytes(operation)?,
    ))
}
fn check_issuer(
    view: &SharedGroupState,
    operations: &[GroupStateOperation],
    issuer: &GroupStateActor,
) -> Result<(), CryptoError> {
    let identity = &issuer.identity;
    let role = view.effective_role(&identity.root_commitment, &identity.device_id);
    if view.members.iter().any(|member| {
        member.identity.root_commitment == identity.root_commitment
            && member.identity.device_id == identity.device_id
            && member.identity.signing_public_key != identity.signing_public_key
    }) {
        return Err(invalid("issuer key differs from the group pin"));
    }
    let completed_writer = operations.last().is_some_and(|last| {
        last.actor.identity.root_commitment == identity.root_commitment
            && last.actor.identity.device_id == identity.device_id
    });
    if role.is_none() && !completed_writer {
        return Err(invalid("snapshot issuer is not an authorized member"));
    }
    if view.members.iter().any(|m| {
        m.identity.root_commitment == identity.root_commitment
            && m.identity.principal_id != identity.principal_id
    }) {
        return Err(invalid("issuer principal mismatch"));
    }
    Ok(())
}
/// # Errors
/// Rejects invalid history, an unauthorized snapshot issuer or byte-budget overflow.
pub fn sign_group_state_snapshot(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    operations: Vec<GroupStateOperation>,
) -> Result<VerifiedGroupState, CryptoError> {
    branch_matches(branch, actor)?;
    sign_snapshot_parts(branch, actor, operations, None)
}
fn sign_snapshot_parts(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    operations: Vec<GroupStateOperation>,
    checkpoint: Option<ramflux_protocol::group_state::GroupStateCheckpoint>,
) -> Result<VerifiedGroupState, CryptoError> {
    branch_matches(branch, actor)?;
    let (view, heads) = transition::derive(&operations, checkpoint.as_ref())?;
    check_issuer(&view, &operations, actor)?;
    let mut snapshot = GroupStateSnapshot {
        schema: GROUP_STATE_SNAPSHOT_DOMAIN.into(),
        group_id: view.group_id.clone(),
        epoch: view.epoch,
        state_hash: crate::blake3_256_base64url(
            "ramflux.group_state.content.v1",
            &canonical_json_bytes(&view)?,
        ),
        checkpoint,
        operations,
        issuer: actor.clone(),
        signature: String::new(),
    };
    snapshot.signature = crate::sign_with_device_branch(branch, &snapshot_body(&snapshot))?;
    if canonical_json_bytes(&snapshot)?.len() > MAX_GROUP_STATE_BYTES {
        return Err(invalid("snapshot byte budget exceeded"));
    }
    Ok(VerifiedGroupState { snapshot, view, heads })
}
/// Verify the entire root-authorized role history before a snapshot can mutate local state.
/// # Errors
/// Rejects invalid signatures, roles, epochs, hashes, identities, names or budgets.
pub fn verify_group_state_snapshot(
    snapshot: GroupStateSnapshot,
) -> Result<VerifiedGroupState, CryptoError> {
    if snapshot.schema != GROUP_STATE_SNAPSHOT_DOMAIN
        || canonical_json_bytes(&snapshot)?.len() > MAX_GROUP_STATE_BYTES
    {
        return Err(invalid("invalid snapshot header or budget"));
    }
    verify_group_state_actor(&snapshot.issuer)?;
    let (view, heads) = transition::derive(&snapshot.operations, snapshot.checkpoint.as_ref())?;
    if snapshot.group_id != view.group_id
        || snapshot.epoch != view.epoch
        || snapshot.state_hash
            != crate::blake3_256_base64url(
                "ramflux.group_state.content.v1",
                &canonical_json_bytes(&view)?,
            )
    {
        return Err(invalid("snapshot state hash mismatch"));
    }
    check_issuer(&view, &snapshot.operations, &snapshot.issuer)?;
    crate::verify_device_branch_signature(
        &snapshot.issuer.identity.signing_public_key,
        &snapshot_body(&snapshot),
        &snapshot.signature,
    )?;
    Ok(VerifiedGroupState { snapshot, view, heads })
}

#[cfg(test)]
mod tests;
