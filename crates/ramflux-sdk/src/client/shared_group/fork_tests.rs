// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-device convergence and durable foreign-request revalidation.
use super::*;
use ramflux_protocol::{GroupChangeStatus, SharedGroupRole};
#[test]
fn creator_device_conflicts_replay_losing_removal_or_name() -> Result<(), SdkError> {
    let root = temp_root("creator-forks")?;
    let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
    let sibling = person(&root.join("sibling"), "owner", "laptop", 11, 32)?;
    let victim = person(&root.join("victim"), "victim", "phone", 21, 22)?;
    owner.shared_group_create("group", "thread", Some("base".into()), "target-phone")?;
    let base = owner.shared_group_change(
        "group",
        "target-phone",
        GroupStateChange::Add {
            member: victim.owned_group_actor("target-phone")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    sibling.accept_shared_group_state(&base, "target-laptop")?;
    owner.shared_group_change(
        "group",
        "target-phone",
        GroupStateChange::Remove {
            root_commitment: victim.owned_device_identity()?.root_commitment().into(),
            device_id: "phone".into(),
        },
    )?;
    sibling.shared_group_change(
        "group",
        "target-laptop",
        GroupStateChange::SetName { name: "concurrent name".into() },
    )?;
    for _ in 0..3 {
        let a = owner
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        sibling.accept_shared_group_state(&a, "target-laptop")?;
        let b = sibling
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        owner.accept_shared_group_state(&b, "target-phone")?;
    }
    let a = owner
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let b = sibling
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(a.view(), b.view());
    assert_eq!(a.view().name.as_deref(), Some("concurrent name"));
    assert!(
        a.view()
            .effective_role(victim.owned_device_identity()?.root_commitment(), "phone")
            .is_none()
    );
    drop((owner, sibling, victim));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn offline_admin_removal_waits_for_owner_and_duplicate_has_one_result() -> Result<(), SdkError> {
    let root = temp_root("admin-offline")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let admin = person(&root.join("admin"), "admin", "admin", 21, 22)?;
    let victim = person(&root.join("victim"), "victim", "victim", 31, 32)?;
    owner.shared_group_create("group", "thread", None, "target-owner")?;
    owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: admin.owned_group_actor("target-admin")?.identity,
            role: SharedGroupRole::Admin,
        },
    )?;
    let base = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: victim.owned_group_actor("target-victim")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    admin.accept_shared_group_state(&base, "target-admin")?;
    let request = admin.stage_group_change_request(
        "group",
        "target-admin",
        GroupStateChange::Remove {
            root_commitment: victim.owned_device_identity()?.root_commitment().into(),
            device_id: "victim".into(),
        },
        Some("offline-remove"),
    )?;
    assert_eq!(
        admin.group_change_statuses(Some("group"))?["requests"][0]["status"],
        "waiting_for_owner"
    );
    assert_eq!(
        admin.group_state("group")?.group_epoch,
        base.view().epoch,
        "request has no state authority"
    );
    owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::SetName { name: "new base".into() },
    )?;
    owner.persist_identity_directory(
        &crate::client::identity_authority::test_support::public_manifest(&admin)?,
    )?;
    owner.insert_group_request(&request, true)?;
    let result = owner.process_group_request(&request, "target-owner")?;
    assert_eq!(result.status, GroupChangeStatus::Applied);
    assert_eq!(owner.process_group_request(&request, "target-owner")?, result);
    assert!(!owner.group_state("group")?.members.contains("victim"));
    admin.apply_group_request_result(&result)?;
    assert_eq!(admin.group_change_statuses(Some("group"))?["requests"][0]["status"], "applied");
    drop((owner, admin, victim));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn demoted_admin_pending_removal_gets_signed_refusal() -> Result<(), SdkError> {
    let root = temp_root("demoted-request")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let admin = person(&root.join("admin"), "admin", "admin", 21, 22)?;
    let victim = person(&root.join("victim"), "victim", "victim", 31, 32)?;
    owner.shared_group_create("group", "thread", None, "target-owner")?;
    let member = admin.owned_group_actor("target-admin")?.identity;
    owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add { member: member.clone(), role: SharedGroupRole::Admin },
    )?;
    let base = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: victim.owned_group_actor("target-victim")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    admin.accept_shared_group_state(&base, "target-admin")?;
    let request = admin.stage_group_change_request(
        "group",
        "target-admin",
        GroupStateChange::Remove {
            root_commitment: victim.owned_device_identity()?.root_commitment().into(),
            device_id: "victim".into(),
        },
        Some("stale-remove"),
    )?;
    let current = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::SetRole {
            root_commitment: member.root_commitment,
            device_id: "admin".into(),
            role: SharedGroupRole::Member,
        },
    )?;
    owner.persist_identity_directory(
        &crate::client::identity_authority::test_support::public_manifest(&admin)?,
    )?;
    owner.insert_group_request(&request, true)?;
    let result = owner.process_group_request(&request, "target-owner")?;
    assert_eq!(result.status, GroupChangeStatus::PermissionDenied);
    assert_eq!(
        owner
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .snapshot()
            .state_hash,
        current.snapshot().state_hash
    );
    admin.apply_group_request_result(&result)?;
    assert_eq!(admin.group_change_statuses(None)?["requests"][0]["status"], "permission_denied");
    assert!(
        admin
            .shared_group_change(
                "group",
                "target-admin",
                GroupStateChange::SetName { name: "forged".into() }
            )
            .is_err()
    );
    drop((owner, admin, victim));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn a_lagging_member_commits_latest_full_state_without_history_resolution() -> Result<(), SdkError> {
    let root = temp_root("long-lag")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let peer = person(&root.join("peer"), "peer", "peer", 21, 22)?;
    owner.shared_group_create("group", "thread", None, "target-owner")?;
    let initial = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: peer.owned_group_actor("target-peer")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    peer.accept_shared_group_state(&initial, "target-peer")?;
    let mut state = initial;
    for epoch in 0..70 {
        state = owner.shared_group_change(
            "group",
            "target-owner",
            GroupStateChange::SetName { name: format!("Name {epoch}") },
        )?;
    }
    assert!(peer.accept_shared_group_state(&state, "target-peer")?);
    assert_eq!(
        peer.account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view(),
        state.view()
    );
    drop((owner, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pending_requests_are_bounded_per_root_and_capacity_has_a_signed_result() -> Result<(), SdkError>
{
    let root = temp_root("request-cap")?;
    let owner = person(&root.join("owner"), "owner", "owner", 11, 12)?;
    let admin = person(&root.join("admin"), "admin", "admin", 21, 22)?;
    owner.shared_group_create("group", "thread", None, "target-owner")?;
    let base = owner.shared_group_change(
        "group",
        "target-owner",
        GroupStateChange::Add {
            member: admin.owned_group_actor("target-admin")?.identity,
            role: SharedGroupRole::Admin,
        },
    )?;
    admin.accept_shared_group_state(&base, "target-admin")?;
    let change = GroupStateChange::SetName { name: "Pending".into() };
    for index in 0..8 {
        let id = format!("request-{index}");
        let request =
            admin.stage_group_change_request("group", "target-admin", change.clone(), Some(&id))?;
        assert_eq!(
            admin.stage_group_change_request("group", "target-admin", change.clone(), Some(&id))?,
            request
        );
        owner.persist_identity_directory(
            &crate::client::identity_authority::test_support::public_manifest(&admin)?,
        )?;
        owner.insert_group_request(&request, true)?;
    }
    assert!(matches!(
        admin.stage_group_change_request("group", "target-admin", change.clone(), Some("ninth")),
        Err(SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
            ramflux_protocol::GroupStateLimit::Requests
        )))
    ));
    let ninth = ramflux_crypto::sign_group_change_request(
        admin.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &admin.owned_group_actor("target-admin")?,
        &base,
        ramflux_crypto::GroupChangeRequestInput {
            request_id: "ninth".into(),
            change,
            now: now_unix_timestamp(),
        },
    )?;
    owner.insert_group_request(&ninth, true)?;
    let refusal = owner.process_group_request(&ninth, "target-owner")?;
    assert_eq!(refusal.status, GroupChangeStatus::Capacity);
    ramflux_crypto::verify_group_change_result(&refusal, &ninth, &base, now_unix_timestamp())?;
    assert_eq!(owner.group_state("group")?.group_epoch, base.view().epoch);
    drop((owner, admin));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
