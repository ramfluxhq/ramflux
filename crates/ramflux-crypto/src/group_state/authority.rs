// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-root delegation for bounded administrative checkpoints.
use super::{
    CryptoError, GroupStateActor, IdentityRoot, SharedGroupRole, SharedGroupState,
    VerifiedGroupState, group_state_head_hash, invalid,
};
use ramflux_protocol::{
    canonical_json_bytes,
    group_state::{
        GroupCheckpointAuthority, GroupDeviceExclusion, GroupStateCheckpoint, SharedGroupMember,
    },
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const DOMAIN: &str = "ramflux.group_state.checkpoint_authority.v1";

pub(super) fn protected(
    state: &SharedGroupState,
) -> (Vec<SharedGroupMember>, Vec<GroupDeviceExclusion>) {
    let roots: BTreeSet<_> = state
        .members
        .iter()
        .filter(|member| matches!(member.role, SharedGroupRole::Owner | SharedGroupRole::Admin))
        .map(|member| member.identity.root_commitment.as_str())
        .collect();
    (
        state
            .members
            .iter()
            .filter(|member| roots.contains(member.identity.root_commitment.as_str()))
            .cloned()
            .collect(),
        state
            .excluded
            .iter()
            .filter(|entry| roots.contains(entry.root_commitment.as_str()))
            .cloned()
            .collect(),
    )
}

fn body(authority: &GroupCheckpointAuthority) -> Value {
    json!({"domain":DOMAIN,"genesis_hash":authority.genesis_hash,"epoch":authority.epoch,
        "head_hash":authority.head_hash,"members":authority.members,"excluded":authority.excluded})
}

pub(super) fn for_checkpoint(
    root: &IdentityRoot,
    actor: &GroupStateActor,
    previous: &VerifiedGroupState,
) -> Result<GroupCheckpointAuthority, CryptoError> {
    let (members, excluded) = protected(previous.view());
    if let Some(authority) =
        previous.snapshot().checkpoint.as_ref().and_then(|checkpoint| checkpoint.authority.as_ref())
        && authority.members == members
        && authority.excluded == excluded
    {
        return Ok(authority.clone());
    }
    if actor.identity.root_commitment == previous.genesis().actor.identity.root_commitment {
        let mut authority = GroupCheckpointAuthority {
            genesis_hash: group_state_head_hash(previous.genesis())?,
            epoch: previous.view().epoch,
            head_hash: previous.view().head_hash.clone(),
            members,
            excluded,
            signature: String::new(),
        };
        authority.signature = crate::sign_canonical_bytes_with_seed(
            &canonical_json_bytes(&body(&authority))?,
            root.signing_key.to_bytes(),
        );
        return Ok(authority);
    }
    let authority = previous
        .snapshot()
        .checkpoint
        .as_ref()
        .and_then(|checkpoint| checkpoint.authority.as_ref())
        .ok_or_else(|| invalid("admin checkpoint requires creator-root delegation"))?;
    if authority.members != members || authority.excluded != excluded {
        return Err(invalid("admin checkpoint cannot alter delegated privileges"));
    }
    Ok(authority.clone())
}

pub(super) fn verify(checkpoint: &GroupStateCheckpoint) -> Result<(), CryptoError> {
    let creator = &checkpoint.genesis.actor;
    let is_creator = checkpoint.owner.identity.root_commitment == creator.identity.root_commitment
        && checkpoint.owner.identity.principal_id == creator.identity.principal_id;
    let Some(authority) = checkpoint.authority.as_ref() else {
        return if is_creator { Ok(()) } else { Err(invalid("missing checkpoint delegation")) };
    };
    if authority.genesis_hash != group_state_head_hash(&checkpoint.genesis)?
        || authority.epoch == 0
        || authority.epoch > checkpoint.state.epoch
        || ramflux_protocol::decode_base64url(&authority.head_hash)?.len() != 32
        || (authority.epoch == checkpoint.state.epoch
            && authority.head_hash != checkpoint.state.head_hash)
        || protected(&checkpoint.state) != (authority.members.clone(), authority.excluded.clone())
    {
        return Err(invalid("checkpoint delegation does not match privileged membership"));
    }
    crate::verify_canonical_signature(
        &canonical_json_bytes(&body(authority))?,
        &authority.signature,
        &creator.root_public_key,
    )?;
    if !is_creator
        && checkpoint.state.effective_role(
            &checkpoint.owner.identity.root_commitment,
            &checkpoint.owner.identity.device_id,
        ) != Some(SharedGroupRole::Admin)
    {
        return Err(invalid("checkpoint signer is not a delegated admin"));
    }
    Ok(())
}
