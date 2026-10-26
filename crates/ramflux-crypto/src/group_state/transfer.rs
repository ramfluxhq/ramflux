// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transferee authorization and receiver removal continuity for creator handovers.
use super::{
    CryptoError, DeviceBranch, GroupCreatorTransfer, GroupStateActor, Value, VerifiedGroupState,
    branch_matches, encode_base64url, invalid, json, verify_group_state_actor,
};
use ramflux_protocol::{GroupTransferAcceptance, SharedGroupState};
const ACCEPTANCE_DOMAIN: &str = "ramflux.group_state.transfer_acceptance.v1";
fn signing(acceptance: &GroupTransferAcceptance) -> Result<Value, CryptoError> {
    let mut body = serde_json::to_value(acceptance).map_err(|_| invalid("transfer encoding"))?;
    body.as_object_mut().ok_or_else(|| invalid("transfer object"))?.remove("signature");
    Ok(json!({"domain":ACCEPTANCE_DOMAIN,"body":body}))
}
/// Countersign the exact current group head, using the transferee's root-certified branch.
/// # Errors
/// Rejects a nonmember transferee, mismatched branch, invalid nonce or clock.
pub fn accept_group_transfer(
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    previous: &VerifiedGroupState,
    nonce: &str,
    now: i64,
) -> Result<GroupTransferAcceptance, CryptoError> {
    branch_matches(branch, actor)?;
    if !previous.view().members.iter().any(|member| member.identity == actor.identity) {
        return Err(invalid("transferee must be an explicit member"));
    }
    let mut acceptance = GroupTransferAcceptance {
        group_id: previous.view().group_id.clone(),
        genesis_hash: previous.genesis_hash()?,
        base_epoch: previous.view().epoch,
        base_hash: previous.snapshot().state_hash.clone(),
        from_public_key: previous.creator().root_public_key.clone(),
        creator: actor.clone(),
        nonce: nonce.into(),
        issued_at: now,
        expires_at: now.saturating_add(60),
        signature: String::new(),
    };
    acceptance.signature = crate::sign_with_device_branch(branch, &signing(&acceptance)?)?;
    verify_group_transfer_acceptance(&acceptance)?;
    Ok(acceptance)
}
/// # Errors
/// Rejects malformed scopes, invalid root/branch signatures or a lease exceeding 60 seconds.
pub fn verify_group_transfer_acceptance(
    acceptance: &GroupTransferAcceptance,
) -> Result<(), CryptoError> {
    verify_group_state_actor(&acceptance.creator)?;
    for hash in [&acceptance.genesis_hash, &acceptance.base_hash, &acceptance.nonce] {
        let bytes = ramflux_protocol::decode_base64url(hash)?;
        if bytes.len() != 32 || encode_base64url(&bytes) != *hash {
            return Err(invalid("transfer hash"));
        }
    }
    crate::verifying_key_from_base64url(&acceptance.from_public_key)?;
    if acceptance.group_id.is_empty()
        || acceptance.group_id.len() > 256
        || acceptance.base_epoch == 0
        || acceptance.base_epoch >= ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || acceptance.issued_at < 0
        || acceptance.expires_at <= acceptance.issued_at
        || acceptance.expires_at > acceptance.issued_at.saturating_add(60)
    {
        return Err(invalid("transfer acceptance scope or lifetime"));
    }
    crate::verify_device_branch_signature(
        &acceptance.creator.identity.signing_public_key,
        &signing(acceptance)?,
        &acceptance.signature,
    )
}
pub(super) fn validate_issue(
    previous: &VerifiedGroupState,
    creator: &GroupStateActor,
    acceptance: &GroupTransferAcceptance,
    now: i64,
) -> Result<(), CryptoError> {
    verify_group_transfer_acceptance(acceptance)?;
    if acceptance.creator != *creator
        || acceptance.group_id != previous.view().group_id
        || acceptance.genesis_hash != previous.genesis_hash()?
        || acceptance.base_epoch != previous.view().epoch
        || acceptance.base_hash != previous.snapshot().state_hash
        || acceptance.from_public_key != previous.creator().root_public_key
        || now < acceptance.issued_at
        || now > acceptance.expires_at
    {
        return Err(ramflux_protocol::ProtocolError::GroupTransferRequiresSync.into());
    }
    Ok(())
}
pub(super) fn verify_certificate(transfer: &GroupCreatorTransfer) -> Result<(), CryptoError> {
    let acceptance = &transfer.acceptance;
    verify_group_transfer_acceptance(acceptance)?;
    if acceptance.creator != transfer.creator
        || acceptance.group_id != transfer.group_id
        || acceptance.genesis_hash != transfer.genesis_hash
        || acceptance.base_epoch + 1 != transfer.epoch
        || acceptance.base_hash != transfer.previous_hash
        || acceptance.from_public_key != transfer.from_public_key
        || transfer.issued_at < acceptance.issued_at
        || transfer.issued_at > acceptance.expires_at
    {
        return Err(invalid("handover differs from transferee acceptance"));
    }
    Ok(())
}
pub(super) fn preserves_removals(previous: &SharedGroupState, incoming: &SharedGroupState) -> bool {
    previous.excluded.iter().all(|removed| {
        let prior_root_present =
            previous.members.iter().any(|m| m.identity.root_commitment == removed.root_commitment);
        let candidates: Vec<_> = incoming
            .members
            .iter()
            .filter(|m| m.identity.root_commitment == removed.root_commitment)
            .collect();
        if !prior_root_present {
            return candidates.iter().all(|member| member.joined_epoch > removed.removed_epoch);
        }
        if incoming.effective_role(&removed.root_commitment, &removed.device_id).is_none() {
            return true;
        }
        candidates.iter().any(|member| {
            member.identity.device_id == removed.device_id
                && member.joined_epoch > removed.removed_epoch
        }) || candidates.iter().all(|member| member.joined_epoch > removed.removed_epoch)
    })
}
