// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signed-state authority, sibling convergence and bounded recovery regressions.
use super::*;
struct Person {
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
    Ok(Person { branch, actor })
}
fn create(owner: &Person) -> Result<VerifiedGroupState, CryptoError> {
    let operation = sign_group_state_operation(
        &owner.branch,
        &owner.actor,
        "group",
        1,
        None,
        GroupStateChange::Create {
            max_members: 1000,
            new_member_history: "no_history".into(),
            name: Some("Checklist".into()),
        },
    )?;
    sign_group_state_snapshot(&owner.branch, &owner.actor, vec![operation])
}
fn step(
    state: &VerifiedGroupState,
    author: &Person,
    change: GroupStateChange,
) -> Result<VerifiedGroupState, CryptoError> {
    let mut operations = state.snapshot().operations.clone();
    operations.push(sign_group_state_operation(
        &author.branch,
        &author.actor,
        "group",
        state.view().epoch + 1,
        Some(state.view().head_hash.clone()),
        change,
    )?);
    sign_group_state_snapshot(&author.branch, &author.actor, operations)
}
#[test]
fn complete_state_bootstraps_existing_peer_and_owner_sibling_at_epoch_three()
-> Result<(), CryptoError> {
    let owner = person("owner", "owner-phone", 11, 12)?;
    let peer = person("agent", "agent-phone", 21, 22)?;
    let sibling = person("owner", "owner-laptop", 11, 42)?;
    let initial = create(&owner)?;
    let joined = step(
        &initial,
        &owner,
        GroupStateChange::Add {
            member: peer.actor.identity.clone(),
            role: SharedGroupRole::Member,
        },
    )?;
    // An owned device follows its root before an explicit branch entry is added.
    assert_eq!(
        joined.view().effective_role(
            &sibling.actor.identity.root_commitment,
            &sibling.actor.identity.device_id
        ),
        Some(SharedGroupRole::Owner)
    );
    let current = step(
        &joined,
        &owner,
        GroupStateChange::Add {
            member: sibling.actor.identity.clone(),
            role: SharedGroupRole::Member,
        },
    )?;
    let peer_copy = verify_group_state_snapshot(current.snapshot().clone())?;
    let sibling_copy = verify_group_state_snapshot(current.snapshot().clone())?;
    assert_eq!(current.view().epoch, 3);
    assert_eq!(current.view().members.len(), 3);
    assert_eq!(peer_copy.view(), current.view());
    assert_eq!(sibling_copy.view(), current.view());
    assert!(current.contains_head(1, &initial.view().head_hash));
    assert!(current.contains_head(2, &joined.view().head_hash));
    Ok(())
}
#[test]
fn a_root_certificate_never_self_declares_an_admin_role() -> Result<(), CryptoError> {
    let owner = person("owner", "owner", 11, 12)?;
    let peer = person("peer", "peer", 21, 22)?;
    let stranger = person("stranger", "stranger", 31, 32)?;
    let first = create(&owner)?;
    assert!(step(&first, &stranger, GroupStateChange::SetName { name: "forged".into() }).is_err());
    let joined = step(
        &first,
        &owner,
        GroupStateChange::Add {
            member: peer.actor.identity.clone(),
            role: SharedGroupRole::Member,
        },
    )?;
    assert!(step(&joined, &peer, GroupStateChange::SetName { name: "forged".into() }).is_err());
    assert!(
        step(
            &joined,
            &peer,
            GroupStateChange::SetRole {
                root_commitment: peer.actor.identity.root_commitment.clone(),
                device_id: peer.actor.identity.device_id.clone(),
                role: SharedGroupRole::Owner
            }
        )
        .is_err()
    );
    let promoted = step(
        &joined,
        &owner,
        GroupStateChange::SetRole {
            root_commitment: peer.actor.identity.root_commitment.clone(),
            device_id: peer.actor.identity.device_id.clone(),
            role: SharedGroupRole::Admin,
        },
    )?;
    let renamed = step(&promoted, &peer, GroupStateChange::SetName { name: "Équipe".into() })?;
    assert_eq!(renamed.view().name.as_deref(), Some("Équipe"));
    assert_eq!(renamed.view().name_epoch, 4);
    Ok(())
}
#[test]
fn copied_device_names_stay_separate_and_root_substitution_fails() -> Result<(), CryptoError> {
    let owner = person("owner", "owner", 11, 12)?;
    let bob = person("bob", "phone", 21, 22)?;
    let mallory = person("mallory", "phone", 31, 32)?;
    let first = step(
        &create(&owner)?,
        &owner,
        GroupStateChange::Add { member: bob.actor.identity.clone(), role: SharedGroupRole::Admin },
    )?;
    let second = step(
        &first,
        &owner,
        GroupStateChange::Add {
            member: mallory.actor.identity.clone(),
            role: SharedGroupRole::Member,
        },
    )?;
    assert_eq!(second.view().members.len(), 3);
    assert_eq!(
        second.view().effective_role(&bob.actor.identity.root_commitment, "phone"),
        Some(SharedGroupRole::Admin)
    );
    assert_eq!(
        second.view().effective_role(&mallory.actor.identity.root_commitment, "phone"),
        Some(SharedGroupRole::Member)
    );
    let mut forged = mallory.actor.clone();
    forged.identity.root_commitment.clone_from(&bob.actor.identity.root_commitment);
    assert!(verify_group_state_actor(&forged).is_err());
    let mut corrupt = second.snapshot().clone();
    corrupt.operations[1]
        .actor
        .identity
        .signing_public_key
        .clone_from(&mallory.actor.identity.signing_public_key);
    assert!(verify_group_state_snapshot(corrupt).is_err());
    Ok(())
}
#[test]
fn removals_exclude_an_owned_device_and_remove_the_last_peer_root_grant() -> Result<(), CryptoError>
{
    let owner = person("owner", "owner", 11, 12)?;
    let sibling = person("owner", "laptop", 11, 42)?;
    let peer = person("peer", "phone", 21, 22)?;
    let joined = step(
        &create(&owner)?,
        &owner,
        GroupStateChange::Add {
            member: peer.actor.identity.clone(),
            role: SharedGroupRole::Member,
        },
    )?;
    let with_sibling = step(
        &joined,
        &owner,
        GroupStateChange::Add {
            member: sibling.actor.identity.clone(),
            role: SharedGroupRole::Member,
        },
    )?;
    let without_sibling = step(
        &with_sibling,
        &owner,
        GroupStateChange::Remove {
            root_commitment: sibling.actor.identity.root_commitment.clone(),
            device_id: sibling.actor.identity.device_id.clone(),
        },
    )?;
    assert_eq!(
        without_sibling.view().effective_role(&sibling.actor.identity.root_commitment, "laptop"),
        None
    );
    let removed = step(
        &without_sibling,
        &owner,
        GroupStateChange::Remove {
            root_commitment: peer.actor.identity.root_commitment.clone(),
            device_id: peer.actor.identity.device_id.clone(),
        },
    )?;
    assert_eq!(
        removed.view().effective_role(&peer.actor.identity.root_commitment, "another-sibling"),
        None
    );
    assert!(
        sign_group_state_snapshot(&peer.branch, &peer.actor, removed.snapshot().operations.clone())
            .is_err()
    );
    Ok(())
}
#[test]
fn forks_tampered_snapshots_and_unsafe_names_do_not_advance_a_known_head() -> Result<(), CryptoError>
{
    let owner = person("owner", "owner", 11, 12)?;
    let first = create(&owner)?;
    let a = step(&first, &owner, GroupStateChange::SetName { name: "A".into() })?;
    let b = step(&first, &owner, GroupStateChange::SetName { name: "B".into() })?;
    assert!(!b.contains_head(a.view().epoch, &a.view().head_hash));
    let mut corrupt = a.snapshot().clone();
    corrupt.state_hash.clone_from(&b.snapshot().state_hash);
    assert!(verify_group_state_snapshot(corrupt).is_err());
    for name in ["", " ", "fake\nname", "fake\u{202e}name"] {
        assert!(step(&first, &owner, GroupStateChange::SetName { name: name.into() }).is_err());
    }
    let too_long = "x".repeat(MAX_GROUP_NAME_BYTES + 1);
    assert!(step(&first, &owner, GroupStateChange::SetName { name: too_long }).is_err());
    let bytes = vec![b' '; MAX_GROUP_STATE_BYTES + 1];
    assert!(GroupStateSnapshot::from_wire_bytes(&bytes).is_err());
    assert!(GroupStateSnapshot::from_wire_bytes(br#"{"schema":"a","schema":"b"}"#).is_err());
    Ok(())
}
