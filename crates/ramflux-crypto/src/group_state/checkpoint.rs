// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-root checkpoints bound replay work without giving members snapshot authority.
use super::{
    CryptoError, DeviceBranch, GroupStateActor, GroupStateChange, VerifiedGroupState,
    branch_matches, group_state_head_hash, identity_valid, invalid, root_matches,
    sign_snapshot_parts, verify_group_state_actor,
};
use ramflux_protocol::group_state::{
    GROUP_STATE_CHECKPOINT_DOMAIN, GroupStateCheckpoint, MAX_GROUP_STATE_EXCLUSIONS,
    MAX_GROUP_STATE_MEMBERS, SharedGroupRole, SharedGroupState,
};
use ramflux_protocol::{canonical_json_bytes, encode_base64url};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) fn body(checkpoint: &GroupStateCheckpoint) -> Value {
    let mut value = json!({"domain":GROUP_STATE_CHECKPOINT_DOMAIN,"schema":checkpoint.schema,
        "genesis":checkpoint.genesis,"state":checkpoint.state,"owner":checkpoint.owner});
    if !checkpoint.lineage.is_empty() {
        value["lineage"] = json!(checkpoint.lineage);
    }
    value
}
pub(super) fn verify_checkpoint(
    checkpoint: &GroupStateCheckpoint,
) -> Result<SharedGroupState, CryptoError> {
    let (genesis, _) = super::transition::derive(std::slice::from_ref(&checkpoint.genesis), None)?;
    let creator = &checkpoint.genesis.actor.identity;
    verify_group_state_actor(&checkpoint.owner)?;
    if checkpoint.schema != GROUP_STATE_CHECKPOINT_DOMAIN
        || checkpoint.owner.identity.root_commitment != creator.root_commitment
        || checkpoint.owner.identity.principal_id != creator.principal_id
    {
        return Err(invalid("checkpoint requires the creator root"));
    }
    crate::verify_canonical_signature(
        &canonical_json_bytes(&body(checkpoint))?,
        &checkpoint.signature,
        &checkpoint.owner.root_public_key,
    )?;
    super::lineage::validate(checkpoint)?;
    let state = &checkpoint.state;
    if state.group_id != genesis.group_id
        || state.conversation_id != genesis.conversation_id
        || state.epoch < genesis.epoch
        || state.epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || state.max_members != genesis.max_members
        || state.new_member_history != genesis.new_member_history
        || state.members.is_empty()
        || state.members.len() > MAX_GROUP_STATE_MEMBERS
        || state.members.len()
            > usize::try_from(state.max_members).map_err(|_| invalid("member bound"))?
        || state.excluded.len() > MAX_GROUP_STATE_EXCLUSIONS
        || state.name_epoch > state.epoch
        || state.name.is_some() != (state.name_epoch > 0)
        || ramflux_protocol::decode_base64url(&state.head_hash)?.len() != 32
    {
        return Err(invalid("invalid checkpoint state"));
    }
    if let Some(name) = &state.name {
        super::transition::name_valid(name)?;
    }
    let mut members = BTreeSet::new();
    let mut owners = 0;
    for member in &state.members {
        identity_valid(&member.identity)?;
        if member.joined_epoch == 0
            || member.joined_epoch > state.epoch
            || !members.insert((&member.identity.root_commitment, &member.identity.device_id))
        {
            return Err(invalid("invalid checkpoint member"));
        }
        if member.role == SharedGroupRole::Owner {
            owners += 1;
            if member.identity != *creator || member.joined_epoch != 1 {
                return Err(invalid("checkpoint cannot replace the creator"));
            }
        }
        if state.members.iter().any(|other| {
            other.identity.root_commitment == member.identity.root_commitment
                && other.identity.principal_id != member.identity.principal_id
        }) {
            return Err(invalid("checkpoint principal mismatch"));
        }
    }
    let mut exclusions = BTreeSet::new();
    for excluded in &state.excluded {
        let root = ramflux_protocol::decode_base64url(&excluded.root_commitment)?;
        if root.len() != 32
            || encode_base64url(root) != excluded.root_commitment
            || excluded.device_id.trim().is_empty()
            || excluded.device_id.len() > 256
            || !ramflux_protocol::text_safety::single_line_is_safe(&excluded.device_id)
            || excluded.removed_epoch == 0
            || excluded.removed_epoch > state.epoch
            || !exclusions.insert((&excluded.root_commitment, &excluded.device_id))
            || members.contains(&(&excluded.root_commitment, &excluded.device_id))
        {
            return Err(invalid("invalid checkpoint exclusion"));
        }
    }
    if owners != 1
        || state.effective_role(
            &checkpoint.owner.identity.root_commitment,
            &checkpoint.owner.identity.device_id,
        ) != Some(SharedGroupRole::Owner)
        || (state.epoch == 1 && state != &genesis)
    {
        return Err(invalid("invalid checkpoint creator authority"));
    }
    Ok(state.clone())
}

impl VerifiedGroupState {
    /// Root-qualified storage identifier, admitted only by this verified group's membership.
    /// This is a storage codec, not an authentication credential.
    /// # Errors
    /// Rejects malformed identities and principal aliases. Device-key authentication is separate.
    pub fn member_storage_key(
        &self,
        identity: &ramflux_protocol::group_state::GroupMemberIdentity,
    ) -> Result<Option<String>, CryptoError> {
        identity_valid(identity)?;
        if self.view.members.iter().any(|member| {
            member.identity.root_commitment == identity.root_commitment
                && member.identity.principal_id != identity.principal_id
        }) {
            return Err(invalid("identity conflicts with verified group membership"));
        }
        if self.view.effective_role(&identity.root_commitment, &identity.device_id).is_none() {
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
    /// Compare authenticated ancestry without treating checkpoint recency as proof of extension.
    #[must_use]
    pub fn extends(&self, previous: &Self) -> bool {
        self.relation_to(previous).is_ok_and(|relation| {
            matches!(
                relation,
                super::GroupStateRelation::Same | super::GroupStateRelation::Extension
            )
        })
    }
    pub(super) fn genesis(&self) -> &ramflux_protocol::group_state::GroupStateOperation {
        self.snapshot
            .checkpoint
            .as_ref()
            .map_or_else(|| &self.snapshot.operations[0], |checkpoint| &checkpoint.genesis)
    }
    pub(super) fn genesis_hash(&self) -> Option<String> {
        group_state_head_hash(self.genesis()).ok()
    }
}

/// Compact already verified history using the immutable creator root's certified branch.
/// # Errors
/// Rejects non-owner roots, removed devices, invalid certificates or snapshot byte overflow.
pub fn compact_group_state(
    root: &crate::IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    previous: &VerifiedGroupState,
) -> Result<VerifiedGroupState, CryptoError> {
    branch_matches(branch, actor)?;
    root_matches(root, actor)?;
    if actor.identity.root_commitment != previous.genesis().actor.identity.root_commitment
        || previous.view.effective_role(&actor.identity.root_commitment, &actor.identity.device_id)
            != Some(SharedGroupRole::Owner)
    {
        return Err(invalid("only the creator root can compact group state"));
    }
    let mut checkpoint = GroupStateCheckpoint {
        schema: GROUP_STATE_CHECKPOINT_DOMAIN.into(),
        genesis: previous.genesis().clone(),
        state: previous.view.clone(),
        owner: actor.clone(),
        lineage: super::lineage::retained(previous),
        signature: String::new(),
    };
    checkpoint.signature = crate::sign_canonical_bytes_with_seed(
        &canonical_json_bytes(&body(&checkpoint))?,
        root.signing_key.to_bytes(),
    );
    verify_checkpoint(&checkpoint)?;
    sign_snapshot_parts(branch, actor, Vec::new(), Some(checkpoint))
}

/// Append one authorized operation, compacting creator-owned history before replay reaches its cap.
/// # Errors
/// Rejects unauthorized transitions, invalid writers, epoch overflow and exhausted snapshot budgets.
pub fn advance_group_state(
    root: &crate::IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    previous: &VerifiedGroupState,
    change: GroupStateChange,
) -> Result<VerifiedGroupState, CryptoError> {
    let compact = previous.snapshot.operations.len() >= 32
        && previous.genesis().actor.identity.root_commitment == actor.identity.root_commitment
        && previous.view.effective_role(&actor.identity.root_commitment, &actor.identity.device_id)
            == Some(SharedGroupRole::Owner);
    let base = if compact {
        compact_group_state(root, branch, actor, previous)?
    } else {
        previous.clone()
    };
    let operation = super::sign_group_state_operation(
        root,
        branch,
        actor,
        crate::group_state::GroupStateOperationInput {
            group_id: &base.view.group_id,
            epoch: base.view.epoch.checked_add(1).ok_or_else(|| invalid("group epoch overflow"))?,
            previous_hash: Some(base.view.head_hash.clone()),
            change,
        },
    )?;
    let mut operations = base.snapshot.operations;
    operations.push(operation);
    sign_snapshot_parts(branch, actor, operations, base.snapshot.checkpoint)
}
