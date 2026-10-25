// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Apply requester role rules before the creator certifies a replacement roster.
use super::{
    CryptoError, GroupDeviceExclusion, GroupMemberIdentity, GroupStateActor, GroupStateChange,
    GroupStateGenesis, MAX_GROUP_DEVICES, MAX_GROUP_DEVICES_PER_ROOT, MAX_GROUP_NAME_BYTES,
    MAX_GROUP_STATE_EXCLUSIONS, MAX_GROUP_STATE_MEMBERS, SharedGroupMember, SharedGroupRole,
    SharedGroupState, identity_valid, invalid,
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
        member.role == SharedGroupRole::Owner
            && member.identity.root_commitment == actor.identity.root_commitment
    }) {
        return Ok(SharedGroupRole::Owner);
    }
    // Exact operations also carry the account root's signature. A root-authorized branch
    // rotation preserves this root/device membership; stale certificates alone cannot write.
    state
        .effective_role(&actor.identity.root_commitment, &actor.identity.device_id)
        .ok_or_else(|| invalid("actor is not a member"))
}
pub(super) fn initial(
    genesis: &GroupStateGenesis,
    name: Option<String>,
) -> Result<SharedGroupState, CryptoError> {
    let max_members = genesis.max_members;
    if max_members == 0
        || usize::try_from(max_members).map_err(|_| invalid("member limit"))?
            > MAX_GROUP_STATE_MEMBERS
        || genesis.conversation_id.trim().is_empty()
        || genesis.conversation_id.len() > 256
        || !ramflux_protocol::text_safety::single_line_is_safe(&genesis.conversation_id)
        || !matches!(genesis.new_member_history.as_str(), "no_history" | "none" | "all_history")
    {
        return Err(invalid("invalid group creation"));
    }
    if let Some(name) = &name {
        name_valid(name)?;
    }
    let name_epoch = u64::from(name.is_some());
    Ok(SharedGroupState {
        group_id: genesis.group_id.clone(),
        conversation_id: genesis.conversation_id.clone(),
        epoch: 1,
        max_members,
        new_member_history: genesis.new_member_history.clone(),
        name,
        name_epoch,
        members: vec![SharedGroupMember {
            identity: genesis.actor.identity.clone(),
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
    let roots = state
        .members
        .iter()
        .map(|member| &member.identity.root_commitment)
        .collect::<std::collections::BTreeSet<_>>();
    if !roots.contains(&identity.root_commitment)
        && roots.len() >= usize::try_from(state.max_members).map_err(|_| invalid("member limit"))?
    {
        return Err(ramflux_protocol::ProtocolError::GroupStateLimit(
            ramflux_protocol::GroupStateLimit::Members,
        )
        .into());
    }
    if state.members.len() >= MAX_GROUP_DEVICES
        || state
            .members
            .iter()
            .filter(|member| member.identity.root_commitment == identity.root_commitment)
            .count()
            >= MAX_GROUP_DEVICES_PER_ROOT
    {
        return Err(ramflux_protocol::ProtocolError::GroupStateLimit(
            ramflux_protocol::GroupStateLimit::Devices,
        )
        .into());
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
    now: i64,
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
        expires_at: now.saturating_add(ramflux_protocol::group_state::GROUP_REQUEST_TTL_SECONDS),
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
pub(super) fn apply(
    state: &mut SharedGroupState,
    actor: &GroupStateActor,
    change: &GroupStateChange,
    epoch: u64,
    now: i64,
) -> Result<(), CryptoError> {
    let actor = actor_role(state, actor)?;
    match change {
        GroupStateChange::Add { member, role: joined_role } => {
            add(state, actor, member, *joined_role, epoch)?;
        }
        GroupStateChange::Remove { root_commitment, device_id } => {
            remove(state, actor, root_commitment, device_id, epoch, now)?;
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
            state.name_epoch = epoch;
        }
        GroupStateChange::TransferOwnership { .. } => {
            return Err(invalid("transfer requires the creator root"));
        }
    }
    state.epoch = epoch;
    Ok(())
}
