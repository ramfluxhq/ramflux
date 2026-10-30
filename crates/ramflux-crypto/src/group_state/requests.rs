// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Requests authenticate intent; only the creator can turn intent into group state.
use super::{
    CryptoError, DeviceBranch, GROUP_CHANGE_REQUEST_DOMAIN, GROUP_CHANGE_RESULT_DOMAIN,
    GROUP_REQUEST_TTL_SECONDS, GroupStateActor, GroupStateChange, IdentityRoot, SharedGroupRole,
    SharedGroupState, Signer, Value, VerifiedGroupState, branch_matches, canonical_json_bytes,
    encode_base64url, invalid, root_matches, snapshot, transition, verify_group_state_actor,
    verify_group_state_actor_at,
};
use ramflux_protocol::group_state::{GroupChangeRequest, GroupChangeResult, GroupChangeStatus};
fn request_body(request: &GroupChangeRequest) -> Result<Value, CryptoError> {
    let mut value = serde_json::to_value(request).map_err(|_| invalid("group JSON encoding"))?;
    value.as_object_mut().ok_or_else(|| invalid("request object"))?.remove("signature");
    Ok(value)
}
fn result_body(result: &GroupChangeResult) -> Result<Value, CryptoError> {
    let mut value = serde_json::to_value(result).map_err(|_| invalid("group JSON encoding"))?;
    value.as_object_mut().ok_or_else(|| invalid("result object"))?.remove("signature");
    Ok(value)
}
pub struct GroupChangeRequestInput {
    pub request_id: String,
    pub change: GroupStateChange,
    pub now: i64,
}
/// # Errors
/// Rejects an invalid signer, request id, lifetime or role against the current view.
pub fn sign_group_change_request(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    state: &VerifiedGroupState,
    input: GroupChangeRequestInput,
) -> Result<GroupChangeRequest, CryptoError> {
    branch_matches(branch, actor)?;
    let mut request = GroupChangeRequest {
        schema: GROUP_CHANGE_REQUEST_DOMAIN.into(),
        group_id: state.view().group_id.clone(),
        genesis_hash: state.genesis_hash()?,
        base_epoch: state.view().epoch,
        creator_root: state.creator().identity.root_commitment.clone(),
        request_id: input.request_id,
        actor: actor.clone(),
        change: input.change,
        issued_at: input.now,
        expires_at: input.now.saturating_add(GROUP_REQUEST_TTL_SECONDS),
        signature: String::new(),
    };
    request.signature = crate::sign_with_device_branch(branch, &request_body(&request)?)?;
    verify_group_change_request(&request, input.now)?;
    validate_group_change_request(state, &request, input.now)?;
    Ok(request)
}
/// # Errors
/// Rejects malformed, forged, oversized, future-dated or expired requests.
pub fn verify_group_change_request(
    request: &GroupChangeRequest,
    now: i64,
) -> Result<(), CryptoError> {
    if request.schema != GROUP_CHANGE_REQUEST_DOMAIN
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || !ramflux_protocol::text_safety::single_line_is_safe(&request.request_id)
        || request.issued_at < 0
        || request.issued_at > now.saturating_add(300)
        || request.expires_at <= now
        || request.expires_at <= request.issued_at
        || request.expires_at.saturating_sub(request.issued_at) > GROUP_REQUEST_TTL_SECONDS
        || canonical_json_bytes(request)?.len() > 8192
    {
        return Err(invalid("invalid or expired group change request"));
    }
    let issued_at = u64::try_from(request.issued_at).map_err(|_| invalid("group request clock"))?;
    verify_group_state_actor_at(&request.actor, Some(issued_at))?;
    crate::verify_device_branch_signature(
        &request.actor.identity.signing_public_key,
        &request_body(request)?,
        &request.signature,
    )
}
/// # Errors
/// Revalidates stale requests against current membership. Former admins never authorize state.
pub fn validate_group_change_request(
    state: &VerifiedGroupState,
    request: &GroupChangeRequest,
    now: i64,
) -> Result<(), CryptoError> {
    verify_group_change_request(request, now)?;
    if request.group_id != state.view().group_id
        || request.genesis_hash != state.genesis_hash()?
        || request.base_epoch > state.view().epoch
        || request.creator_root != state.creator().identity.root_commitment
    {
        return Err(invalid("request group or creator changed"));
    }
    if matches!(request.change, GroupStateChange::TransferOwnership { .. }) {
        return Err(invalid("ownership transfer uses the creator command"));
    }
    let mut trial = state.view().clone();
    if change_already_applied(&trial, &request.change) {
        // Even an idempotent request must come from a currently authorized requester.
        if !matches!(
            trial.effective_role(
                &request.actor.identity.root_commitment,
                &request.actor.identity.device_id
            ),
            Some(SharedGroupRole::Owner | SharedGroupRole::Admin)
        ) {
            return Err(invalid("requester no longer authorized"));
        }
        return Ok(());
    }
    transition::apply(
        &mut trial,
        &request.actor,
        &request.change,
        state.view().epoch.saturating_add(1),
        now,
    )
}
#[must_use]
pub fn change_already_applied(state: &SharedGroupState, change: &GroupStateChange) -> bool {
    match change {
        GroupStateChange::Remove { root_commitment, device_id } => {
            state.effective_role(root_commitment, device_id).is_none()
        }
        GroupStateChange::Add { member, role } => {
            state.members.iter().any(|current| current.identity == *member && current.role == *role)
        }
        GroupStateChange::SetRole { root_commitment, device_id, role } => {
            state.effective_role(root_commitment, device_id) == Some(*role)
        }
        GroupStateChange::SetName { name } => state.name.as_ref() == Some(name),
        GroupStateChange::TransferOwnership { creator, .. } => state.members.iter().any(|m| {
            m.identity.root_commitment == creator.identity.root_commitment
                && m.role == SharedGroupRole::Owner
        }),
    }
}
/// # Errors
/// Only the creator root may apply a request, after current-state role verification.
pub fn apply_group_change_request(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    state: &VerifiedGroupState,
    request: &GroupChangeRequest,
    now: i64,
) -> Result<VerifiedGroupState, CryptoError> {
    validate_group_change_request(state, request, now)?;
    if change_already_applied(state.view(), &request.change) {
        return Ok(state.clone());
    }
    snapshot::advance_as(
        root,
        branch,
        actor,
        state,
        snapshot::Apply { requester: &request.actor, change: request.change.clone(), now },
    )
}
/// Apply an authorized request under the current born-v3 owner authority.
///
/// # Errors
/// Rejects an invalid requester, creator authority, stale state, or state transition.
pub fn apply_native_group_change_request(
    primary: &crate::custody::SelfSigningKey,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    state: &VerifiedGroupState,
    request: &GroupChangeRequest,
    now: i64,
) -> Result<VerifiedGroupState, CryptoError> {
    validate_group_change_request(state, request, now)?;
    if change_already_applied(state.view(), &request.change) {
        return Ok(state.clone());
    }
    snapshot::advance_as_with_native_signer(
        primary,
        branch,
        actor,
        state,
        snapshot::Apply { requester: &request.actor, change: request.change.clone(), now },
    )
}
/// # Errors
/// Rejects an invalid creator signer or request serialization.
pub fn sign_group_change_result(
    root: &IdentityRoot,
    actor: &GroupStateActor,
    request: &GroupChangeRequest,
    state: &VerifiedGroupState,
    status: GroupChangeStatus,
    now: i64,
) -> Result<GroupChangeResult, CryptoError> {
    root_matches(root, actor)?;
    if actor.identity.root_commitment != state.creator().identity.root_commitment {
        return Err(invalid("result signer is not creator"));
    }
    let mut result = unsigned_group_change_result(actor, request, state, status, now)?;
    result.signature = encode_base64url(
        root.signing_key.sign(&canonical_json_bytes(&result_body(&result)?)?).to_bytes(),
    );
    Ok(result)
}
fn unsigned_group_change_result(
    actor: &GroupStateActor,
    request: &GroupChangeRequest,
    state: &VerifiedGroupState,
    status: GroupChangeStatus,
    now: i64,
) -> Result<GroupChangeResult, CryptoError> {
    Ok(GroupChangeResult {
        schema: GROUP_CHANGE_RESULT_DOMAIN.into(),
        group_id: request.group_id.clone(),
        request_id: request.request_id.clone(),
        request_hash: group_change_request_hash(request)?,
        requester: request.actor.identity.clone(),
        creator: actor.clone(),
        status,
        epoch: state.view().epoch,
        state_hash: state.snapshot().state_hash.clone(),
        issued_at: now,
        expires_at: request.expires_at,
        signature: String::new(),
    })
}
/// Sign a terminal request result with the current born-v3 owner authority.
///
/// # Errors
/// Rejects a mismatched native signer, non-owner actor, or invalid serialization.
pub fn sign_native_group_change_result(
    primary: &crate::custody::SelfSigningKey,
    actor: &GroupStateActor,
    request: &GroupChangeRequest,
    state: &VerifiedGroupState,
    status: GroupChangeStatus,
    now: i64,
) -> Result<GroupChangeResult, CryptoError> {
    if actor.native_authority.is_none() || primary.public_key() != actor.root_public_key {
        return Err(invalid("native result signer authority mismatch"));
    }
    if actor.identity.root_commitment != state.creator().identity.root_commitment {
        return Err(invalid("result signer is not creator"));
    }
    let mut result = unsigned_group_change_result(actor, request, state, status, now)?;
    result.signature =
        primary.sign_group_state_bytes(&canonical_json_bytes(&result_body(&result)?)?);
    Ok(result)
}
/// # Errors
/// Rejects mismatched, expired or forged results.
pub fn verify_group_change_result(
    result: &GroupChangeResult,
    request: &GroupChangeRequest,
    state: &VerifiedGroupState,
    now: i64,
) -> Result<(), CryptoError> {
    if result.schema != GROUP_CHANGE_RESULT_DOMAIN
        || result.group_id != request.group_id
        || result.request_id != request.request_id
        || result.request_hash != group_change_request_hash(request)?
        || result.requester != request.actor.identity
        || result.creator.identity.root_commitment != state.creator().identity.root_commitment
        || result.expires_at <= now
        || result.expires_at != request.expires_at
        || result.issued_at > now.saturating_add(300)
    {
        return Err(invalid("invalid group change result"));
    }
    verify_group_state_actor(&result.creator)?;
    crate::verify_canonical_signature(
        &canonical_json_bytes(&result_body(result)?)?,
        &result.signature,
        &state.creator().root_public_key,
    )
}
/// # Errors
/// Returns canonical encoding errors.
pub fn group_change_request_hash(request: &GroupChangeRequest) -> Result<String, CryptoError> {
    Ok(crate::blake3_256_base64url(GROUP_CHANGE_REQUEST_DOMAIN, &canonical_json_bytes(request)?))
}
