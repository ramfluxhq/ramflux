// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authoritative role transitions derived from verified operations, never declared snapshot roles.
use super::{
    CryptoError, GROUP_STATE_OPERATION_DOMAIN, GroupDeviceExclusion, GroupMemberIdentity,
    GroupStateActor, GroupStateChange, GroupStateOperation, MAX_GROUP_NAME_BYTES,
    MAX_GROUP_STATE_EXCLUSIONS, MAX_GROUP_STATE_MEMBERS, MAX_GROUP_STATE_STEPS, SharedGroupMember,
    SharedGroupRole, SharedGroupState, group_state_head_hash, identity_valid, invalid,
    verify_group_state_actor,
};
use ramflux_protocol::group_permissions::{
    can_change_group_member_role, can_invite_group_member, can_remove_group_member,
    is_group_admin_role,
};
pub(super) fn name_valid(name: &str) -> Result<(), CryptoError> {
    if name.trim().is_empty()
        || name.len() > MAX_GROUP_NAME_BYTES
        || !ramflux_protocol::text_safety::single_line_is_safe(name)
    {
        return Err(invalid("invalid group name"));
    }
    Ok(())
}
fn actor_role(
    state: &SharedGroupState,
    actor: &GroupStateActor,
) -> Result<SharedGroupRole, CryptoError> {
    if state.members.iter().any(|m| {
        m.identity.root_commitment == actor.identity.root_commitment
            && m.identity.principal_id != actor.identity.principal_id
    }) {
        return Err(invalid("actor principal mismatch"));
    }
    if state.members.iter().any(|member| {
        member.identity.root_commitment == actor.identity.root_commitment
            && member.identity.device_id == actor.identity.device_id
            && member.identity.signing_public_key != actor.identity.signing_public_key
    }) {
        return Err(invalid("actor key differs from the group pin"));
    }
    state
        .effective_role(&actor.identity.root_commitment, &actor.identity.device_id)
        .ok_or_else(|| invalid("actor is not a member"))
}
fn initial(operation: &GroupStateOperation) -> Result<SharedGroupState, CryptoError> {
    let GroupStateChange::Create { conversation_id, max_members, new_member_history, name } =
        &operation.change
    else {
        return Err(invalid("group history must begin with creation"));
    };
    if operation.epoch != 1
        || operation.previous_hash.is_some()
        || *max_members == 0
        || usize::try_from(*max_members).map_err(|_| invalid("member limit"))?
            > MAX_GROUP_STATE_MEMBERS
        || conversation_id.trim().is_empty()
        || conversation_id.len() > 256
        || !ramflux_protocol::text_safety::single_line_is_safe(conversation_id)
        || !matches!(new_member_history.as_str(), "no_history" | "none" | "all_history")
    {
        return Err(invalid("invalid group creation"));
    }
    if let Some(name) = name {
        name_valid(name)?;
    }
    Ok(SharedGroupState {
        group_id: operation.group_id.clone(),
        conversation_id: conversation_id.clone(),
        epoch: 1,
        max_members: *max_members,
        new_member_history: new_member_history.clone(),
        name: name.clone(),
        name_epoch: u64::from(name.is_some()),
        members: vec![SharedGroupMember {
            identity: operation.actor.identity.clone(),
            role: SharedGroupRole::Owner,
            joined_epoch: 1,
        }],
        excluded: Vec::new(),
        head_hash: String::new(),
    })
}
fn add(
    state: &mut SharedGroupState,
    actor: SharedGroupRole,
    identity: &GroupMemberIdentity,
    role: SharedGroupRole,
    epoch: u64,
) -> Result<(), CryptoError> {
    identity_valid(identity)?;
    if !can_invite_group_member(actor.as_str(), role.as_str()) {
        return Err(invalid("member add not authorized"));
    }
    if state.members.len()
        >= usize::try_from(state.max_members).map_err(|_| invalid("member limit"))?
    {
        return Err(invalid("group member limit exceeded"));
    }
    if state.members.iter().any(|m| {
        m.identity.root_commitment == identity.root_commitment
            && (m.identity.device_id == identity.device_id
                || m.identity.principal_id != identity.principal_id)
    }) {
        return Err(invalid("duplicate or conflicting member"));
    }
    state.excluded.retain(|e| {
        e.root_commitment != identity.root_commitment || e.device_id != identity.device_id
    });
    state.members.push(SharedGroupMember { identity: identity.clone(), role, joined_epoch: epoch });
    Ok(())
}
fn remove(
    state: &mut SharedGroupState,
    actor: SharedGroupRole,
    root: &str,
    device: &str,
    epoch: u64,
) -> Result<(), CryptoError> {
    let target = state
        .effective_role(root, device)
        .ok_or_else(|| invalid("removed device is not a member"))?;
    if !can_remove_group_member(actor.as_str(), target.as_str()) {
        return Err(invalid("member removal not authorized"));
    }
    if root.is_empty()
        || device.trim().is_empty()
        || device.len() > 256
        || !ramflux_protocol::text_safety::single_line_is_safe(device)
        || state.excluded.len() >= MAX_GROUP_STATE_EXCLUSIONS
    {
        return Err(invalid("invalid removed identity or exclusion budget"));
    }
    state.members.retain(|m| m.identity.root_commitment != root || m.identity.device_id != device);
    state.excluded.push(GroupDeviceExclusion {
        root_commitment: root.into(),
        device_id: device.into(),
        removed_epoch: epoch,
    });
    Ok(())
}
fn role(
    state: &mut SharedGroupState,
    actor: SharedGroupRole,
    root: &str,
    device: &str,
    new_role: SharedGroupRole,
) -> Result<(), CryptoError> {
    let target = state
        .members
        .iter_mut()
        .find(|m| m.identity.root_commitment == root && m.identity.device_id == device)
        .ok_or_else(|| invalid("role target is not an explicit member"))?;
    if !can_change_group_member_role(actor.as_str(), target.role.as_str(), new_role.as_str()) {
        return Err(invalid("role change not authorized"));
    }
    target.role = new_role;
    Ok(())
}
fn apply(state: &mut SharedGroupState, operation: &GroupStateOperation) -> Result<(), CryptoError> {
    let actor = actor_role(state, &operation.actor)?;
    match &operation.change {
        GroupStateChange::Create { .. } => return Err(invalid("group cannot be recreated")),
        GroupStateChange::Add { member, role: joined_role } => {
            add(state, actor, member, *joined_role, operation.epoch)?;
        }
        GroupStateChange::Remove { root_commitment, device_id } => {
            remove(state, actor, root_commitment, device_id, operation.epoch)?;
        }
        GroupStateChange::SetRole { root_commitment, device_id, role: new_role } => {
            role(state, actor, root_commitment, device_id, *new_role)?;
        }
        GroupStateChange::SetName { name } => {
            if !is_group_admin_role(actor.as_str()) {
                return Err(invalid("group rename not authorized"));
            }
            name_valid(name)?;
            state.name = Some(name.clone());
            state.name_epoch = operation.epoch;
        }
    }
    state.epoch = operation.epoch;
    Ok(())
}
pub(super) fn derive(
    operations: &[GroupStateOperation],
    checkpoint: Option<&ramflux_protocol::group_state::GroupStateCheckpoint>,
) -> Result<(SharedGroupState, std::collections::BTreeMap<u64, String>), CryptoError> {
    if (operations.is_empty() && checkpoint.is_none()) || operations.len() > MAX_GROUP_STATE_STEPS {
        return Err(invalid("group history step budget exceeded"));
    }
    let mut state = checkpoint.map(super::checkpoint::verify_checkpoint).transpose()?;
    let mut heads = std::collections::BTreeMap::new();
    if let Some(current) = state.as_ref() {
        heads.insert(current.epoch, current.head_hash.clone());
    }
    for operation in operations {
        if operation.schema != GROUP_STATE_OPERATION_DOMAIN
            || operation.group_id.trim().is_empty()
            || operation.group_id.len() > 256
            || !ramflux_protocol::text_safety::single_line_is_safe(&operation.group_id)
            || operation.epoch != state.as_ref().map_or(1, |s| s.epoch.saturating_add(1))
            || operation.epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        {
            return Err(invalid("invalid group operation header or epoch"));
        }
        verify_group_state_actor(&operation.actor)?;
        crate::verify_canonical_signature(
            &ramflux_protocol::canonical_json_bytes(&super::root_operation_body(operation))?,
            &operation.root_signature,
            &operation.actor.root_public_key,
        )?;
        crate::verify_device_branch_signature(
            &operation.actor.identity.signing_public_key,
            &super::operation_body(operation),
            &operation.signature,
        )?;
        if let Some(current) = &mut state {
            let current: &mut SharedGroupState = current;
            if current.group_id != operation.group_id
                || operation.previous_hash.as_deref() != Some(&current.head_hash)
            {
                return Err(invalid("group operation chain mismatch"));
            }
            apply(current, operation)?;
        } else {
            state = Some(initial(operation)?);
        }
        let current = state.as_mut().ok_or_else(|| invalid("missing group state"))?;
        current.members.sort_by(|a, b| {
            (&a.identity.root_commitment, &a.identity.device_id)
                .cmp(&(&b.identity.root_commitment, &b.identity.device_id))
        });
        current.excluded.sort_by(|a, b| {
            (&a.root_commitment, &a.device_id).cmp(&(&b.root_commitment, &b.device_id))
        });
        current.head_hash = group_state_head_hash(operation)?;
        heads.insert(current.epoch, current.head_hash.clone());
    }
    Ok((state.ok_or_else(|| invalid("empty history"))?, heads))
}
