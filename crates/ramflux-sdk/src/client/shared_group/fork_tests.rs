// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Both fork directions retain the local removal and rename after automatic repair.
use super::*;

#[test]
fn shared_group_remove_and_rename_forks_converge_without_dropping_either_write()
-> Result<(), SdkError> {
    for removal_wins in [false, true] {
        let root = temp_root("fork-repair")?;
        let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
        let admin = person(&root.join("admin"), "admin", "admin", 21, 22)?;
        let victim = person(&root.join("victim"), "victim", "victim", 31, 32)?;
        owner.shared_group_create("group", "thread", Some("base".into()), "target-owner")?;
        owner.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::Add {
                member: admin.owned_group_actor("target-admin")?.identity,
                role: ramflux_protocol::SharedGroupRole::Admin,
            },
        )?;
        let base = owner.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::Add {
                member: victim.owned_group_actor("target-victim")?.identity,
                role: ramflux_protocol::SharedGroupRole::Admin,
            },
        )?;
        admin.accept_shared_group_state(&base, "target-admin")?;
        victim.accept_shared_group_state(&base, "target-victim")?;
        let removed = owner.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::Remove {
                root_commitment: victim.owned_device_identity()?.root_commitment().into(),
                device_id: "victim".into(),
            },
        )?;
        let actor = admin.owned_group_actor("target-admin")?;
        let name = choose_fork_name(&admin, &base, &removed, removal_wins)?;
        let renamed = admin.shared_group_change(
            "group",
            "target-admin",
            GroupStateChange::SetName { name: name.clone() },
        )?;
        let delegated = ramflux_crypto::compact_group_state(
            admin.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            admin.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &actor,
            &renamed,
        )?;
        admin.accept_shared_group_state(&delegated, "target-admin")?;
        for _ in 0..3 {
            let owner_state = owner
                .account_db()?
                .shared_group_state("group")?
                .ok_or(StorageError::GroupPermissionDenied)?;
            let prepared = admin
                .prepare_shared_group_payload(owner_state.clone(), &packet_bytes(&owner_state)?)?;
            admin.apply_prepared_shared_group(&prepared, "target-admin")?;
            let admin_state = admin
                .account_db()?
                .shared_group_state("group")?
                .ok_or(StorageError::GroupPermissionDenied)?;
            let prepared = owner
                .prepare_shared_group_payload(admin_state.clone(), &packet_bytes(&admin_state)?)?;
            owner.apply_prepared_shared_group(&prepared, "target-owner")?;
        }
        let final_owner = owner
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let final_admin = admin
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        assert_eq!(final_owner.view(), final_admin.view());
        assert_eq!(final_owner.view().name.as_ref(), Some(&name));
        assert_eq!(
            final_owner
                .view()
                .effective_role(victim.owned_device_identity()?.root_commitment(), "victim"),
            None
        );
        assert!(final_owner.view().epoch > removed.view().epoch);
        assert!(final_owner.view().epoch > renamed.view().epoch);
        let terminal: Value =
            serde_json::from_slice(&owner.shared_group_packet(&final_owner, false)?)?;
        assert!(
            terminal.get("distribution_base64").is_none(),
            "removed devices never receive the winning head's seed"
        );
        drop((owner, admin, victim));
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn shared_group_unrelated_proof_is_consumed_as_a_typed_conflict_without_changing_state()
-> Result<(), SdkError> {
    let root = temp_root("unrelated")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let other = person(&root.join("other"), "owner", "owner", 11, 12)?;
    let before = owner.shared_group_create(
        "group",
        "thread",
        Some("first genesis".into()),
        "target-owner",
    )?;
    let unrelated = other.shared_group_create(
        "group",
        "thread",
        Some("other genesis".into()),
        "target-owner",
    )?;
    let prepared =
        owner.prepare_shared_group_payload(unrelated.clone(), &packet_bytes(&unrelated)?)?;
    assert!(!owner.apply_prepared_shared_group(&prepared, "target-owner")?);
    assert_eq!(
        owner
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view(),
        before.view()
    );
    let event = owner
        .account_db()?
        .latest_journal_event("group.state.conflict")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(event.body["reason"], "unrelated_history");
    assert_eq!(owner.account_db()?.due_inbox_retries(now_unix_timestamp())?, Vec::<Vec<u8>>::new());
    drop((owner, other));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_group_stale_delegation_cannot_restore_a_demoted_admin() -> Result<(), SdkError> {
    let root = temp_root("stale-admin")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let admin = person(&root.join("admin"), "admin", "admin", 21, 22)?;
    let observer = person(&root.join("observer"), "observer", "observer", 31, 32)?;
    owner.shared_group_create("group", "thread", None, "target-owner")?;
    owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: observer.owned_group_actor("target-observer")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let member = admin.owned_group_actor("target-admin")?.identity;
    let joined = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: member.clone(),
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    admin.accept_shared_group_state(&joined, "target-admin")?;
    let demoted = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::SetRole {
            root_commitment: member.root_commitment.clone(),
            device_id: member.device_id.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let stale = admin.shared_group_change(
        "group",
        "target-admin",
        GroupStateChange::SetName { name: "stale privileged head".into() },
    )?;
    let delegated = ramflux_crypto::compact_group_state(
        admin.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        admin.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &admin.owned_group_actor("target-admin")?,
        &stale,
    )?;
    observer.accept_shared_group_state(&demoted, "target-observer")?;
    assert!(!observer.accept_shared_group_state(&delegated, "target-observer")?);
    assert_eq!(
        observer
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view(),
        demoted.view()
    );
    assert_eq!(
        observer
            .account_db()?
            .latest_journal_event("group.state.conflict")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .body["reason"],
        "stale_delegation"
    );
    drop((owner, admin, observer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn choose_fork_name(
    admin: &RamfluxClient,
    base: &ramflux_crypto::VerifiedGroupState,
    removed: &ramflux_crypto::VerifiedGroupState,
    removal_wins: bool,
) -> Result<String, SdkError> {
    let actor = admin.owned_group_actor("target-admin")?;
    let mut selected = None;
    for index in 0..128 {
        let name = format!("concurrent-name-{index}");
        let candidate = ramflux_crypto::advance_group_state(
            admin.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            admin.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &actor,
            base,
            GroupStateChange::SetName { name: name.clone() },
        )?;
        let preferred = candidate.relation_to(removed)?
            == ramflux_crypto::GroupStateRelation::ExistingPreferred;
        if preferred == removal_wins {
            selected = Some(name);
            break;
        }
    }
    selected.ok_or_else(|| invalid("failed to construct requested fork order"))
}
