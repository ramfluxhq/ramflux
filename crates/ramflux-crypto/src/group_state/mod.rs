// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authenticated group writers, signed history and monotonic snapshot proofs.
mod checkpoint;
mod lineage;
pub use lineage::GroupStateRelation;
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
    ramflux_protocol::validate_device_name(&identity.device_id)?;
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
fn root_matches(root: &IdentityRoot, actor: &GroupStateActor) -> Result<(), CryptoError> {
    if root.principal_id != actor.identity.principal_id
        || encode_base64url(root.signing_key.verifying_key().to_bytes()) != actor.root_public_key
    {
        return Err(invalid("group writer root mismatch"));
    }
    Ok(())
}
pub(super) fn root_operation_body(operation: &GroupStateOperation) -> Value {
    json!({"domain":"ramflux.group_state.root_operation.v1","operation":operation_body(operation)})
}
/// Header and exact transition authenticated by both the account root and its local branch.
pub struct GroupStateOperationInput<'a> {
    pub group_id: &'a str,
    pub epoch: u64,
    pub previous_hash: Option<String>,
    pub change: GroupStateChange,
}
/// # Errors
/// Rejects an invalid actor or canonical serialization. History authority is checked by snapshot verification.
pub fn sign_group_state_operation(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    input: GroupStateOperationInput<'_>,
) -> Result<GroupStateOperation, CryptoError> {
    let GroupStateOperationInput { group_id, epoch, previous_hash, change } = input;
    branch_matches(branch, actor)?;
    root_matches(root, actor)?;
    let mut operation = GroupStateOperation {
        schema: GROUP_STATE_OPERATION_DOMAIN.into(),
        group_id: group_id.into(),
        epoch,
        previous_hash,
        actor: actor.clone(),
        change,
        root_signature: String::new(),
        signature: String::new(),
    };
    operation.root_signature = encode_base64url(
        root.signing_key.sign(&canonical_json_bytes(&root_operation_body(&operation))?).to_bytes(),
    );
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
fn check_issuer(view: &SharedGroupState, issuer: &GroupStateActor) -> Result<(), CryptoError> {
    let identity = &issuer.identity;
    let role = view.effective_role(&identity.root_commitment, &identity.device_id);
    // Transport admission verifies the issuer's current root-signed device set. Group history
    // retains the original declaration and must not pin a retired branch key forever.
    if role.is_none() {
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
    let (view, mut heads) = transition::derive(&operations, checkpoint.as_ref())?;
    lineage::merge(&mut heads, checkpoint.as_ref())?;
    check_issuer(&view, actor)?;
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
/// Re-sign an already verified snapshot for delivery without rewriting its history or checkpoint.
/// # Errors
/// Rejects an actor outside the verified membership or a mismatched private branch.
pub fn resign_group_state_snapshot(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    state: &VerifiedGroupState,
) -> Result<VerifiedGroupState, CryptoError> {
    branch_matches(branch, actor)?;
    check_issuer(state.view(), actor)?;
    let mut snapshot = state.snapshot().clone();
    snapshot.issuer = actor.clone();
    snapshot.signature = crate::sign_with_device_branch(branch, &snapshot_body(&snapshot))?;
    verify_group_state_snapshot(snapshot)
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
    let (view, mut heads) = transition::derive(&snapshot.operations, snapshot.checkpoint.as_ref())?;
    lineage::merge(&mut heads, snapshot.checkpoint.as_ref())?;
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
    check_issuer(&view, &snapshot.issuer)?;
    crate::verify_device_branch_signature(
        &snapshot.issuer.identity.signing_public_key,
        &snapshot_body(&snapshot),
        &snapshot.signature,
    )?;
    Ok(VerifiedGroupState { snapshot, view, heads })
}

#[cfg(test)]
mod tests;
