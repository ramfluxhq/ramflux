// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single-writer authority, arbitrary lag, transfer and stale requester regressions.
use super::*;
use ramflux_protocol::GroupChangeStatus;
struct Person {
    root: IdentityRoot,
    branch: DeviceBranch,
    actor: GroupStateActor,
}
fn person(
    principal: &str,
    device: &str,
    root_seed: u8,
    branch_seed: u8,
) -> Result<Person, CryptoError> {
    let root = crate::create_identity_root(principal, [root_seed; 32]);
    let branch = crate::create_device_branch(principal, device, 1, [branch_seed; 32]);
    let actor = certify_group_state_actor(&root, &branch, &format!("target-{device}"))?;
    Ok(Person { root, branch, actor })
}
fn create(owner: &Person) -> Result<VerifiedGroupState, CryptoError> {
    create_group_state(
        &owner.root,
        &owner.branch,
        &owner.actor,
        GroupStateCreateInput {
            group_id: "group",
            conversation_id: "thread",
            max_members: 200,
            new_member_history: "no_history",
            name: Some("Checklist".into()),
            now: 1000,
        },
    )
}
fn step(
    state: &VerifiedGroupState,
    owner: &Person,
    change: GroupStateChange,
) -> Result<VerifiedGroupState, CryptoError> {
    advance_group_state(&owner.root, &owner.branch, &owner.actor, state, change)
}
fn add(
    state: &VerifiedGroupState,
    owner: &Person,
    peer: &Person,
    role: SharedGroupRole,
) -> Result<VerifiedGroupState, CryptoError> {
    step(state, owner, GroupStateChange::Add { member: peer.actor.identity.clone(), role })
}
#[test]
fn full_snapshot_bootstraps_peer_and_implicit_owner_sibling() -> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let peer = person("peer", "phone", 21, 22)?;
    let sibling = person("owner", "laptop", 11, 32)?;
    let second = add(&create(&owner)?, &owner, &peer, SharedGroupRole::Member)?;
    assert_eq!(
        second.view().effective_role(&sibling.actor.identity.root_commitment, "laptop"),
        Some(SharedGroupRole::Owner)
    );
    let third = add(&second, &owner, &sibling, SharedGroupRole::Member)?;
    assert_eq!(verify_group_state_snapshot(third.snapshot().clone())?.view(), third.view());
    assert_eq!(third.view().epoch, 3);
    assert_eq!(third.view().members.len(), 3);
    assert_ne!(
        third.member_storage_key(&owner.actor.identity)?,
        third.member_storage_key(&peer.actor.identity)?
    );
    Ok(())
}
#[test]
fn more_than_sixty_four_epochs_fast_forward_in_one_snapshot() -> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let first = create(&owner)?;
    let mut state = first.clone();
    for epoch in 2..=132 {
        state = step(&state, &owner, GroupStateChange::SetName { name: format!("Name {epoch}") })?;
    }
    assert_eq!(state.relation_to(&first)?, GroupStateRelation::Extension);
    assert_eq!(state.view().epoch, 132);
    assert!(canonical_json_bytes(state.snapshot())?.len() < 5000, "no operation history growth");
    Ok(())
}
#[test]
fn admins_request_but_never_sign_state_and_demoted_requests_cannot_undo_removal()
-> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let admin = person("admin", "phone", 21, 22)?;
    let victim = person("victim", "phone", 31, 32)?;
    let base = add(
        &add(&create(&owner)?, &owner, &admin, SharedGroupRole::Admin)?,
        &owner,
        &victim,
        SharedGroupRole::Member,
    )?;
    let change = GroupStateChange::Remove {
        root_commitment: victim.actor.identity.root_commitment.clone(),
        device_id: "phone".into(),
    };
    let request = sign_group_change_request(
        &admin.branch,
        &admin.actor,
        &base,
        GroupChangeRequestInput {
            request_id: "remove-offline".into(),
            change: change.clone(),
            now: 1000,
        },
    )?;
    assert!(step(&base, &admin, GroupStateChange::SetName { name: "forged".into() }).is_err());
    let demoted = step(
        &base,
        &owner,
        GroupStateChange::SetRole {
            root_commitment: admin.actor.identity.root_commitment.clone(),
            device_id: "phone".into(),
            role: SharedGroupRole::Member,
        },
    )?;
    assert!(
        apply_group_change_request(
            &owner.root,
            &owner.branch,
            &owner.actor,
            &demoted,
            &request,
            1001
        )
        .is_err()
    );
    let refused = sign_group_change_result(
        &owner.root,
        &owner.actor,
        &request,
        &demoted,
        GroupChangeStatus::PermissionDenied,
        1001,
    )?;
    verify_group_change_result(&refused, &request, &demoted, 1001)?;
    assert_eq!(refused.status, GroupChangeStatus::PermissionDenied);
    // An honest offline admin's intent is valid when the creator returns, even at a newer base.
    let renamed = step(&base, &owner, GroupStateChange::SetName { name: "newer".into() })?;
    let applied = apply_group_change_request(
        &owner.root,
        &owner.branch,
        &owner.actor,
        &renamed,
        &request,
        1001,
    )?;
    assert!(
        applied.view().effective_role(&victim.actor.identity.root_commitment, "phone").is_none()
    );
    let duplicate = apply_group_change_request(
        &owner.root,
        &owner.branch,
        &owner.actor,
        &applied,
        &request,
        1002,
    )?;
    assert_eq!(duplicate.snapshot().state_hash, applied.snapshot().state_hash);
    assert!(verify_group_change_request(&request, request.expires_at).is_err());
    Ok(())
}
#[test]
fn creator_devices_choose_the_same_snapshot_and_other_roots_cannot_forge_it()
-> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let sibling = person("owner", "laptop", 11, 32)?;
    let other = person("other", "phone", 21, 22)?;
    let base = create(&owner)?;
    let a = step(&base, &owner, GroupStateChange::SetName { name: "a".into() })?;
    let b = step(&base, &sibling, GroupStateChange::SetName { name: "b".into() })?;
    let (winner, loser) = if a.relation_to(&b)? == GroupStateRelation::IncomingPreferred {
        (&a, &b)
    } else {
        (&b, &a)
    };
    assert_eq!(winner.relation_to(loser)?, GroupStateRelation::IncomingPreferred);
    assert_eq!(loser.relation_to(winner)?, GroupStateRelation::ExistingPreferred);
    let mut forged = a.snapshot().clone();
    forged.state.name = Some("attacker".into());
    assert!(verify_group_state_snapshot(forged).is_err());
    assert!(resign_group_state_snapshot(&other.branch, &other.actor, &a).is_err());
    let mut copied = a.snapshot().clone();
    copied.creator = other.actor;
    assert!(verify_group_state_snapshot(copied).is_err());
    Ok(())
}
#[test]
fn ownership_transfer_certifies_new_root_and_old_root_loses_writes() -> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let next = person("next", "phone", 21, 22)?;
    let base = add(&create(&owner)?, &owner, &next, SharedGroupRole::Member)?;
    let transferred =
        step(&base, &owner, GroupStateChange::TransferOwnership { creator: next.actor.clone() })?;
    let state = step(&transferred, &next, GroupStateChange::SetName { name: "new owner".into() })?;
    assert_eq!(state.relation_to(&base)?, GroupStateRelation::Extension);
    assert!(
        step(&transferred, &owner, GroupStateChange::SetName { name: "former owner".into() })
            .is_err()
    );
    let former = step(&base, &owner, GroupStateChange::SetName { name: "stale fork".into() })?;
    let former = step(&former, &owner, GroupStateChange::SetName { name: "old root".into() })?;
    assert_eq!(former.relation_to(&transferred)?, GroupStateRelation::Unrelated);
    let mut forged = state.snapshot().clone();
    forged.transfers[0].creator = owner.actor.clone();
    assert!(verify_group_state_snapshot(forged).is_err());
    Ok(())
}
#[test]
fn member_roots_and_explicit_devices_have_distinct_typed_caps() -> Result<(), CryptoError> {
    let owner = person("owner", "d0", 11, 12)?;
    let mut state = create(&owner)?;
    for index in 1..16 {
        let sibling = person("owner", &format!("d{index}"), 11, 20 + index)?;
        state = add(&state, &owner, &sibling, SharedGroupRole::Member)?;
    }
    let excess = person("owner", "overflow", 11, 90)?;
    assert!(matches!(
        add(&state, &owner, &excess, SharedGroupRole::Member),
        Err(CryptoError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
            GroupStateLimit::Devices
        )))
    ));
    let peer = person("peer", "phone", 21, 22)?;
    assert!(
        add(&state, &owner, &peer, SharedGroupRole::Member).is_ok(),
        "one root cannot wedge another"
    );
    assert!(
        step(&state, &owner, GroupStateChange::SetName { name: "bad\u{202e}text".into() }).is_err()
    );
    Ok(())
}
#[test]
fn removal_excludes_siblings_and_transport_certificates_never_sign_creator_state()
-> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let sibling = person("owner", "laptop", 11, 32)?;
    let peer = person("peer", "phone", 21, 22)?;
    let base = add(
        &add(&create(&owner)?, &owner, &sibling, SharedGroupRole::Member)?,
        &owner,
        &peer,
        SharedGroupRole::Admin,
    )?;
    let removed = step(
        &base,
        &owner,
        GroupStateChange::Remove {
            root_commitment: owner.actor.identity.root_commitment.clone(),
            device_id: "laptop".into(),
        },
    )?;
    assert!(
        removed.view().effective_role(&owner.actor.identity.root_commitment, "laptop").is_none()
    );
    assert!(resign_group_state_snapshot(&sibling.branch, &sibling.actor, &removed).is_err());
    let forwarded = resign_group_state_snapshot(&peer.branch, &peer.actor, &removed)?;
    assert_eq!(forwarded.snapshot().root_signature, removed.snapshot().root_signature);
    let mut forged = forwarded.snapshot().clone();
    forged.epoch += 1;
    forged.state.epoch += 1;
    forged.signature = crate::sign_with_device_branch(&peer.branch, &transport_body(&forged)?)?;
    assert!(verify_group_state_snapshot(forged).is_err());
    Ok(())
}

#[test]
fn group_only_exclusions_expire_after_the_boundary_window() -> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let sibling = person("owner", "laptop", 11, 32)?;
    let base = add(&create(&owner)?, &owner, &sibling, SharedGroupRole::Member)?;
    let removed = snapshot::advance_as(
        &owner.root,
        &owner.branch,
        &owner.actor,
        &base,
        snapshot::Apply {
            requester: &owner.actor,
            change: GroupStateChange::Remove {
                root_commitment: owner.actor.identity.root_commitment.clone(),
                device_id: "laptop".into(),
            },
            now: 1000,
        },
    )?;
    assert!(
        removed.view().effective_role(&owner.actor.identity.root_commitment, "laptop").is_none()
    );
    let pruned = snapshot::advance_as(
        &owner.root,
        &owner.branch,
        &owner.actor,
        &removed,
        snapshot::Apply {
            requester: &owner.actor,
            change: GroupStateChange::SetName { name: "After boundary".into() },
            now: 1000 + GROUP_REQUEST_TTL_SECONDS,
        },
    )?;
    assert_eq!(pruned.view().excluded.len(), 0);
    assert!(
        pruned.view().effective_role(&owner.actor.identity.root_commitment, "laptop").is_some(),
        "permanent removal requires signed account revocation"
    );
    Ok(())
}

#[test]
fn ownership_transfer_budget_has_a_typed_capacity_refusal() -> Result<(), CryptoError> {
    let owner = person("owner", "phone", 11, 12)?;
    let mut current = create(&owner)?;
    for _ in 0..MAX_GROUP_CREATOR_TRANSFERS {
        current = step(
            &current,
            &owner,
            GroupStateChange::TransferOwnership { creator: owner.actor.clone() },
        )?;
    }
    assert!(matches!(
        step(
            &current,
            &owner,
            GroupStateChange::TransferOwnership { creator: owner.actor.clone() }
        ),
        Err(CryptoError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
            GroupStateLimit::Transfers
        )))
    ));
    Ok(())
}
