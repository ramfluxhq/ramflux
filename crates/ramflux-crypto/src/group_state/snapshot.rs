// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full snapshots jump across arbitrary lag while preserving creator-root transfer authority.
use super::{
    CryptoError, DeviceBranch, GROUP_STATE_SNAPSHOT_DOMAIN, GroupCreatorTransfer, GroupStateActor,
    GroupStateChange, GroupStateGenesis, GroupStateLimit, GroupStateSnapshot, IdentityRoot,
    MAX_GROUP_CREATOR_TRANSFERS, MAX_GROUP_DEVICES, MAX_GROUP_DEVICES_PER_ROOT,
    MAX_GROUP_STATE_BYTES, MAX_GROUP_STATE_EXCLUSIONS, SharedGroupRole, Signer, Value,
    VerifiedGroupState, branch_matches, canonical_json_bytes, encode_base64url, identity_valid,
    invalid, json, root_matches, transition, transport_body, verify_group_state_actor,
    verify_group_state_snapshot,
};
use std::collections::{BTreeMap, BTreeSet};
const GENESIS_DOMAIN: &str = "ramflux.group_state.genesis.v2";
const TRANSFER_DOMAIN: &str = "ramflux.group_state.creator_transfer.v1";
fn without_signature<T: serde::Serialize>(value: &T, domain: &str) -> Result<Value, CryptoError> {
    let mut value = serde_json::to_value(value).map_err(|_| invalid("group JSON encoding"))?;
    let object = value.as_object_mut().ok_or_else(|| invalid("group object"))?;
    object.remove("signature");
    object.insert("domain".into(), json!(domain));
    Ok(value)
}
pub(super) fn genesis_hash(genesis: &GroupStateGenesis) -> Result<String, CryptoError> {
    Ok(crate::blake3_256_base64url(GENESIS_DOMAIN, &canonical_json_bytes(genesis)?))
}
fn core_body(snapshot: &GroupStateSnapshot) -> Value {
    let mut state = snapshot.state.clone();
    state.head_hash.clear();
    json!({"domain": GROUP_STATE_SNAPSHOT_DOMAIN,"genesis":snapshot.genesis,"creator":snapshot.creator,
        "transfers":snapshot.transfers,"group_id":snapshot.group_id,"epoch":snapshot.epoch,
        "previous_hash":snapshot.previous_hash,"state":state,"issued_at":snapshot.issued_at})
}
fn root_body(snapshot: &GroupStateSnapshot) -> Value {
    json!({"domain":"ramflux.group_state.creator_signature.v2","content":core_body(snapshot),"state_hash":snapshot.state_hash})
}
pub(super) fn signer_key(snapshot: &GroupStateSnapshot) -> Result<&str, CryptoError> {
    let mut expected = snapshot.genesis.actor.root_public_key.as_str();
    let mut epoch = 1;
    let genesis = genesis_hash(&snapshot.genesis)?;
    for transfer in &snapshot.transfers {
        if transfer.group_id != snapshot.group_id
            || transfer.genesis_hash != genesis
            || transfer.from_public_key != expected
            || transfer.epoch <= epoch
            || transfer.epoch > snapshot.epoch
        {
            return Err(invalid("invalid creator transfer chain"));
        }
        verify_group_state_actor(&transfer.creator)?;
        crate::verify_canonical_signature(
            &canonical_json_bytes(&without_signature(transfer, TRANSFER_DOMAIN)?)?,
            &transfer.signature,
            expected,
        )?;
        epoch = transfer.epoch;
        expected = &transfer.creator.root_public_key;
    }
    if expected != snapshot.creator.root_public_key {
        return Err(invalid("uncertified creator"));
    }
    Ok(snapshot
        .transfers
        .last()
        .filter(|transfer| transfer.epoch == snapshot.epoch)
        .map_or(expected, |transfer| transfer.from_public_key.as_str()))
}
pub(super) fn verify(snapshot: &GroupStateSnapshot) -> Result<(), CryptoError> {
    if canonical_json_bytes(snapshot)?.len() > MAX_GROUP_STATE_BYTES {
        return Err(ramflux_protocol::ProtocolError::GroupStateLimit(GroupStateLimit::Bytes).into());
    }
    if snapshot.schema != GROUP_STATE_SNAPSHOT_DOMAIN
        || snapshot.group_id != snapshot.genesis.group_id
        || snapshot.group_id != snapshot.state.group_id
        || snapshot.group_id.trim().is_empty()
        || snapshot.group_id.len() > 256
        || !ramflux_protocol::text_safety::single_line_is_safe(&snapshot.group_id)
        || snapshot.epoch == 0
        || snapshot.epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || snapshot.epoch != snapshot.state.epoch
        || (snapshot.epoch == 1) != snapshot.previous_hash.is_none()
        || snapshot.issued_at < 0
        || snapshot.transfers.len() > MAX_GROUP_CREATOR_TRANSFERS
    {
        return Err(invalid("invalid creator snapshot header"));
    }
    if let Some(previous) = &snapshot.previous_hash {
        hash_valid(previous)?;
    }
    verify_group_state_actor(&snapshot.genesis.actor)?;
    verify_group_state_actor(&snapshot.creator)?;
    crate::verify_canonical_signature(
        &canonical_json_bytes(&without_signature(&snapshot.genesis, GENESIS_DOMAIN)?)?,
        &snapshot.genesis.signature,
        &snapshot.genesis.actor.root_public_key,
    )?;
    transition::initial(&snapshot.genesis, None)?;
    verify_roster(snapshot)?;
    let hash = crate::blake3_256_base64url(
        "ramflux.group_state.content.v2",
        &canonical_json_bytes(&core_body(snapshot))?,
    );
    if snapshot.state_hash != hash || snapshot.state.head_hash != hash {
        return Err(invalid("snapshot content hash mismatch"));
    }
    crate::verify_canonical_signature(
        &canonical_json_bytes(&root_body(snapshot))?,
        &snapshot.root_signature,
        signer_key(snapshot)?,
    )
}
fn hash_valid(hash: &str) -> Result<(), CryptoError> {
    let bytes = ramflux_protocol::decode_base64url(hash)?;
    if bytes.len() != 32 || encode_base64url(bytes) != hash {
        return Err(invalid("invalid snapshot hash"));
    }
    Ok(())
}
fn verify_roster(snapshot: &GroupStateSnapshot) -> Result<(), CryptoError> {
    let state = &snapshot.state;
    if state.max_members != snapshot.genesis.max_members
        || state.new_member_history != snapshot.genesis.new_member_history
        || state.conversation_id != snapshot.genesis.conversation_id
        || state.name_epoch > state.epoch
        || state.members.is_empty()
        || state.excluded.len() > MAX_GROUP_STATE_EXCLUSIONS
        || state.members.len() > MAX_GROUP_DEVICES
    {
        return Err(invalid("invalid full roster"));
    }
    if let Some(name) = &state.name {
        transition::name_valid(name)?;
    }
    let mut devices = BTreeSet::new();
    let mut roots = BTreeMap::new();
    let mut owners = 0;
    for member in &state.members {
        identity_valid(&member.identity)?;
        if member.joined_epoch == 0
            || member.joined_epoch > state.epoch
            || !devices.insert((&member.identity.root_commitment, &member.identity.device_id))
        {
            return Err(invalid("duplicate group member"));
        }
        let (principal, count) = roots
            .entry(&member.identity.root_commitment)
            .or_insert((&member.identity.principal_id, 0));
        *count += 1;
        if *principal != &member.identity.principal_id || *count > MAX_GROUP_DEVICES_PER_ROOT {
            return Err(invalid("conflicting root or member device cap"));
        }
        if member.role == SharedGroupRole::Owner {
            owners += 1;
            if member.identity.root_commitment != snapshot.creator.identity.root_commitment {
                return Err(invalid("owner differs from creator"));
            }
        }
    }
    if owners != 1
        || roots.len() > usize::try_from(state.max_members).map_err(|_| invalid("member cap"))?
    {
        return Err(invalid("invalid owner or member cap"));
    }
    let mut excluded = BTreeSet::new();
    for entry in &state.excluded {
        hash_valid(&entry.root_commitment)?;
        ramflux_protocol::validate_device_name(&entry.device_id)?;
        if entry.removed_epoch == 0
            || entry.removed_epoch > state.epoch
            || entry.expires_at < 0
            || devices.contains(&(&entry.root_commitment, &entry.device_id))
            || !excluded.insert((&entry.root_commitment, &entry.device_id))
        {
            return Err(invalid("invalid exclusion"));
        }
    }
    Ok(())
}
pub struct GroupStateCreateInput<'a> {
    pub group_id: &'a str,
    pub conversation_id: &'a str,
    pub max_members: u32,
    pub new_member_history: &'a str,
    pub name: Option<String>,
    pub now: i64,
}
/// # Errors
/// Rejects invalid identities, creation parameters or snapshot budgets.
pub fn create_group_state(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    input: GroupStateCreateInput<'_>,
) -> Result<VerifiedGroupState, CryptoError> {
    branch_matches(branch, actor)?;
    root_matches(root, actor)?;
    let mut genesis = GroupStateGenesis {
        group_id: input.group_id.into(),
        conversation_id: input.conversation_id.into(),
        actor: actor.clone(),
        max_members: input.max_members,
        new_member_history: input.new_member_history.into(),
        signature: String::new(),
    };
    genesis.signature = encode_base64url(
        root.signing_key
            .sign(&canonical_json_bytes(&without_signature(&genesis, GENESIS_DOMAIN)?)?)
            .to_bytes(),
    );
    let state = transition::initial(&genesis, input.name)?;
    let snapshot = GroupStateSnapshot {
        schema: GROUP_STATE_SNAPSHOT_DOMAIN.into(),
        group_id: state.group_id.clone(),
        epoch: 1,
        state_hash: String::new(),
        previous_hash: None,
        genesis,
        creator: actor.clone(),
        transfers: Vec::new(),
        state,
        issued_at: input.now,
        root_signature: String::new(),
        issuer: actor.clone(),
        signature: String::new(),
    };
    sign(root, branch, actor, snapshot)
}
fn sign(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    mut snapshot: GroupStateSnapshot,
) -> Result<VerifiedGroupState, CryptoError> {
    snapshot.state.members.sort_by(|a, b| {
        (&a.identity.root_commitment, &a.identity.device_id)
            .cmp(&(&b.identity.root_commitment, &b.identity.device_id))
    });
    snapshot.state.excluded.sort_by(|a, b| {
        (&a.root_commitment, &a.device_id).cmp(&(&b.root_commitment, &b.device_id))
    });
    snapshot.state_hash = crate::blake3_256_base64url(
        "ramflux.group_state.content.v2",
        &canonical_json_bytes(&core_body(&snapshot))?,
    );
    snapshot.state.head_hash.clone_from(&snapshot.state_hash);
    snapshot.epoch = snapshot.state.epoch;
    snapshot.root_signature = encode_base64url(
        root.signing_key.sign(&canonical_json_bytes(&root_body(&snapshot))?).to_bytes(),
    );
    snapshot.issuer = actor.clone();
    snapshot.signature = crate::sign_with_device_branch(branch, &transport_body(&snapshot)?)?;
    verify_group_state_snapshot(snapshot)
}
/// # Errors
/// Only the current creator root may certify a replacement state. Role requests use `apply_group_change_request`.
pub fn advance_group_state(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    previous: &VerifiedGroupState,
    change: GroupStateChange,
) -> Result<VerifiedGroupState, CryptoError> {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid("group clock"))?
            .as_secs(),
    )
    .map_err(|_| invalid("group clock"))?;
    advance_as(root, branch, actor, previous, Apply { requester: actor, change, now })
}
pub(super) struct Apply<'a> {
    pub requester: &'a GroupStateActor,
    pub change: GroupStateChange,
    pub now: i64,
}
pub(super) fn advance_as(
    root: &IdentityRoot,
    branch: &DeviceBranch,
    actor: &GroupStateActor,
    previous: &VerifiedGroupState,
    input: Apply<'_>,
) -> Result<VerifiedGroupState, CryptoError> {
    let Apply { requester, change, now } = input;
    branch_matches(branch, actor)?;
    root_matches(root, actor)?;
    if actor.identity.root_commitment != previous.creator().identity.root_commitment {
        return Err(invalid("only the creator root can sign group state"));
    }
    let mut snapshot = previous.snapshot.clone();
    let epoch = snapshot
        .epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
        .ok_or_else(|| invalid("group epoch overflow"))?;
    snapshot.previous_hash = Some(snapshot.state_hash.clone());
    snapshot.epoch = epoch;
    snapshot.issued_at = now;
    // Group-only device exclusions share the seven-day boundary window. Permanent
    // exclusion of a device from an active member root uses signed account revocation.
    snapshot.state.excluded.retain(|entry| entry.expires_at > now);
    if let GroupStateChange::TransferOwnership { creator } = &change {
        if requester.identity.root_commitment != previous.creator().identity.root_commitment
            || snapshot.transfers.len() >= MAX_GROUP_CREATOR_TRANSFERS
        {
            return Err(invalid("ownership transfer not authorized or transfer cap exceeded"));
        }
        verify_group_state_actor(creator)?;
        let selected = snapshot
            .state
            .members
            .iter()
            .position(|m| m.identity == creator.identity)
            .ok_or_else(|| invalid("new creator must be a verified explicit member"))?;
        for member in &mut snapshot.state.members {
            if member.role == SharedGroupRole::Owner {
                member.role = SharedGroupRole::Admin;
            }
        }
        snapshot.state.members[selected].role = SharedGroupRole::Owner;
        let mut transfer = GroupCreatorTransfer {
            group_id: snapshot.group_id.clone(),
            genesis_hash: genesis_hash(&snapshot.genesis)?,
            from_public_key: actor.root_public_key.clone(),
            creator: creator.clone(),
            epoch,
            previous_hash: previous.snapshot.state_hash.clone(),
            signature: String::new(),
        };
        transfer.signature = encode_base64url(
            root.signing_key
                .sign(&canonical_json_bytes(&without_signature(&transfer, TRANSFER_DOMAIN)?)?)
                .to_bytes(),
        );
        snapshot.creator = creator.clone();
        snapshot.transfers.push(transfer);
        snapshot.state.epoch = epoch;
    } else {
        transition::apply(&mut snapshot.state, requester, &change, epoch, now)?;
    }
    sign(root, branch, actor, snapshot)
}
