// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-device convergence and durable foreign-request revalidation.
use super::*;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::{Fixture as Native, bus as native_bus};
use crate::prekey::SdkDeviceManifestResponse;
use ramflux_crypto::advance_native_group_state;
use ramflux_protocol::{GroupChangeStatus, SharedGroupRole};

/// Runs one native fixture future to completion on a fresh current-thread runtime.
fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
) -> Result<T, SdkError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
        .map_err(|error| SdkError::LocalBus(error.to_string()))
}

/// One native account whose only device is `device`, held as a public-bus fixture.
fn native_person(id: &str, device: &str) -> Result<LocalBusAccountState, SdkError> {
    block_on(async move {
        let fixture = Native::with_device(id, device).await?;
        Ok(fixture.into_bus())
    })
}

/// A laptop sibling of `phone`. It carries the account primary, as the phone holds it.
fn native_sibling(
    phone: &mut LocalBusAccountState,
    id: &str,
    device: &str,
) -> Result<LocalBusAccountState, SdkError> {
    block_on(Box::pin(native_bus::sibling(phone, id, device)))
}

/// Device storage key that the raw group entry points expect as their target.
fn skey(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.owned_device_identity()?.storage_key().into())
}

/// Manifest that the account's own native fixture published.
fn manifest_of(account: &LocalBusAccountState) -> Result<SdkDeviceManifestResponse, SdkError> {
    account
        .client
        .native_bus_fixture
        .as_ref()
        .map(|material| material.manifest.clone())
        .ok_or(SdkError::CustodySetupInvalid)
}

/// Primary-signed revocation of `device` on `account`. Returns the manifest that receivers adopt.
fn primary_revoked_manifest(
    account: &LocalBusAccountState,
    device: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let material =
        account.client.native_bus_fixture.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    let mut manifest = material.manifest.clone();
    let vault = material.vault.clone();
    let mut native = manifest.custody.clone().ok_or(SdkError::CustodySetupInvalid)?;
    let now = crate::custody::network_now()?.max(native.publication.record.body.issued_at);
    let current = account
        .client
        .current_custody_authority(&manifest.principal_commitment, now)?
        .ok_or(SdkError::CustodySetupInvalid)?;
    let primary = vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    native.publication.record = primary.revoke_device(&current, device, now)?;
    native.devices.retain(|entry| entry.device_ref.device_id != device);
    manifest.devices.retain(|entry| entry.device_id != device);
    manifest.custody = Some(native);
    Ok(manifest)
}

#[test]
fn creator_device_conflicts_replay_losing_removal_or_name() -> Result<(), SdkError> {
    let mut owner = native_person("owner", "phone")?;
    let sibling = native_sibling(&mut owner, "owner-laptop", "laptop")?;
    let victim = native_person("victim", "phone")?;
    owner.client.fixture_group_create("group", "thread", Some("base".into()), "phone")?;
    let base = owner.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Add {
            member: victim.client.fixture_group_actor("phone")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    sibling.client.fixture_accept_group_state(&base, "laptop")?;
    owner.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Remove {
            root_commitment: victim.client.owned_device_identity()?.root_commitment().into(),
            device_id: "phone".into(),
        },
    )?;
    sibling.client.fixture_group_change(
        "group",
        "laptop",
        GroupStateChange::SetName { name: "concurrent name".into() },
    )?;
    for _ in 0..3 {
        let a = owner
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        sibling.client.fixture_accept_group_state(&a, "laptop")?;
        let b = sibling
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        owner.client.fixture_accept_group_state(&b, "phone")?;
    }
    let a = owner
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let b = sibling
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(a.view(), b.view());
    assert_eq!(a.view().name.as_deref(), Some("concurrent name"));
    assert!(
        a.view()
            .effective_role(victim.client.owned_device_identity()?.root_commitment(), "phone")
            .is_none()
    );
    let owner_ids = service_ids(&owner.client, "thread")?;
    let sibling_ids = service_ids(&sibling.client, "thread")?;
    assert_eq!(owner_ids, sibling_ids, "creator devices share the signed service history");
    assert_eq!(
        owner_ids.len(),
        a.snapshot().service_events.len(),
        "the timeline is the signed log, not the union of both branches"
    );
    Ok(())
}

#[test]
fn divergent_service_histories_follow_the_signed_order() -> Result<(), SdkError> {
    let mut phone = native_person("fork-owner", "phone")?;
    let laptop = native_sibling(&mut phone, "fork-owner-laptop", "laptop")?;
    let member = native_person("fork-member", "phone")?;
    let late = native_person("fork-late", "phone")?;
    phone.client.fixture_group_create("fork-group", "fork-thread", Some("base".into()), "phone")?;
    phone.client.fixture_group_change(
        "fork-group",
        "phone",
        GroupStateChange::Add {
            member: member.client.fixture_group_actor("phone")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    let parent = phone.client.fixture_group_change(
        "fork-group",
        "phone",
        GroupStateChange::Add {
            member: late.client.fixture_group_actor("phone")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    assert!(laptop.client.fixture_accept_group_state(&parent, "laptop")?);
    assert!(member.client.fixture_accept_group_state(&parent, "phone")?);
    assert!(late.client.fixture_accept_group_state(&parent, "phone")?);
    let alpha = phone.client.fixture_group_change(
        "fork-group",
        "phone",
        GroupStateChange::SetName { name: "alpha".into() },
    )?;
    let beta = laptop.client.fixture_group_change(
        "fork-group",
        "laptop",
        GroupStateChange::SetName { name: "beta".into() },
    )?;
    let (winner, loser) = preferred_branch(&alpha, &beta)?;
    let winner_name = branch_name(winner)?;
    let loser_name = branch_name(loser)?;
    assert!(member.client.fixture_accept_group_state(loser, "phone")?);
    let saw_loser = service_ids(&member.client, "fork-thread")?;
    assert_eq!(
        service_names(&member.client, "fork-thread")?,
        vec![loser_name.to_owned()],
        "the losing branch is visible before the preferred log arrives"
    );
    assert!(late.client.fixture_accept_group_state(winner, "phone")?);
    assert!(member.client.fixture_accept_group_state(winner, "phone")?);
    let adopted = service_ids(&member.client, "fork-thread")?;
    let late_ids = service_ids(&late.client, "fork-thread")?;
    assert_eq!(adopted, late_ids, "late admission matches a device that saw the losing branch");
    assert_eq!(
        adopted.len(),
        winner.snapshot().service_events.len(),
        "rows that are not in the signed log are replaced"
    );
    assert!(
        saw_loser.iter().any(|id| !adopted.contains(id)),
        "the losing event id does not remain after the preferred log is adopted"
    );
    assert!(!member.client.fixture_accept_group_state(winner, "phone")?);
    assert_eq!(
        service_ids(&member.client, "fork-thread")?,
        adopted,
        "projecting the convergent state again does not resurrect the losing row"
    );
    assert_eq!(
        service_names(&member.client, "fork-thread")?,
        vec![winner_name.to_owned()],
        "the adopted timeline carries the preferred name only"
    );
    Ok(())
}

fn preferred_branch<'a>(
    alpha: &'a ramflux_crypto::VerifiedGroupState,
    beta: &'a ramflux_crypto::VerifiedGroupState,
) -> Result<
    (&'a ramflux_crypto::VerifiedGroupState, &'a ramflux_crypto::VerifiedGroupState),
    SdkError,
> {
    use ramflux_crypto::GroupStateRelation::{ExistingPreferred, IncomingPreferred};
    match alpha.relation_to(beta)? {
        IncomingPreferred => Ok((alpha, beta)),
        ExistingPreferred => Ok((beta, alpha)),
        other => Err(SdkError::LocalBus(format!("test: fork relation {other:?}"))),
    }
}

fn service_ids(client: &RamfluxClient, thread: &str) -> Result<Vec<String>, SdkError> {
    Ok(service_rows(client, thread)?.into_iter().map(|row| row.id).collect())
}

fn branch_name(state: &ramflux_crypto::VerifiedGroupState) -> Result<&str, SdkError> {
    state
        .snapshot()
        .service_events
        .iter()
        .rev()
        .find_map(|event| match &event.change {
            ramflux_protocol::group_state::GroupServiceChange::SetName { name } => {
                Some(name.as_str())
            }
            _ => None,
        })
        .ok_or_else(|| SdkError::LocalBus("test: branch has no name event".into()))
}

fn service_names(client: &RamfluxClient, thread: &str) -> Result<Vec<String>, SdkError> {
    let mut names = Vec::new();
    for row in service_rows(client, thread)? {
        if row.state == "tombstone" {
            return Err(SdkError::LocalBus("test: replaced service row left a tombstone".into()));
        }
        let Some(ramflux_protocol::message::content::Value::Service(service)) =
            row.content.as_ref().and_then(|content| content.value.as_ref())
        else {
            continue;
        };
        if let Some(text) = &service.text {
            names.push(text.clone());
        }
    }
    Ok(names)
}

fn service_rows(
    client: &RamfluxClient,
    thread: &str,
) -> Result<Vec<crate::client::typed_read_model::MessageView>, SdkError> {
    let page = client.generated_message_view_page(thread, None, 100)?;
    let mut rows: Vec<_> = page.messages.into_iter().filter(|row| row.kind == "service").collect();
    rows.sort_by_key(|row| (row.hlc_ms, row.hlc_logical, row.device_sequence.0));
    Ok(rows)
}
#[test]
fn offline_admin_removal_waits_for_owner_and_duplicate_has_one_result() -> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    let admin = native_person("admin", "admin")?;
    let victim = native_person("victim", "victim")?;
    owner.client.fixture_group_create("group", "thread", None, "owner")?;
    owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add {
            member: admin.client.fixture_group_actor("admin")?.identity,
            role: SharedGroupRole::Admin,
        },
    )?;
    let base = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add {
            member: victim.client.fixture_group_actor("victim")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    admin.client.fixture_accept_group_state(&base, "admin")?;
    let request = admin.client.stage_group_change_request(
        "group",
        &skey(&admin.client)?,
        GroupStateChange::Remove {
            root_commitment: victim.client.owned_device_identity()?.root_commitment().into(),
            device_id: "victim".into(),
        },
        Some("offline-remove"),
    )?;
    assert_eq!(
        admin.client.group_change_statuses(Some("group"))?["requests"][0]["status"],
        "waiting_for_owner"
    );
    assert_eq!(
        admin.client.group_state("group")?.group_epoch,
        base.view().epoch,
        "request has no state authority"
    );
    owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::SetName { name: "new base".into() },
    )?;
    owner.client.persist_fetched_identity_directory(&manifest_of(&admin)?)?;
    owner.client.insert_group_request(&request, true)?;
    let primary = owner.client.fixture_primary()?;
    let result = owner.client.process_group_request_with_primary(
        &request,
        &skey(&owner.client)?,
        primary.as_ref(),
    )?;
    assert_eq!(result.status, GroupChangeStatus::Applied);
    assert_eq!(
        owner.client.process_group_request_with_primary(
            &request,
            &skey(&owner.client)?,
            primary.as_ref(),
        )?,
        result
    );
    assert!(!owner.client.group_state("group")?.members.contains("victim"));
    admin.client.apply_group_request_result(&result)?;
    assert_eq!(
        admin.client.group_change_statuses(Some("group"))?["requests"][0]["status"],
        "applied"
    );
    Ok(())
}
#[test]
fn demoted_admin_pending_removal_gets_signed_refusal() -> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    let admin = native_person("admin", "admin")?;
    let victim = native_person("victim", "victim")?;
    owner.client.fixture_group_create("group", "thread", None, "owner")?;
    let member = admin.client.fixture_group_actor("admin")?.identity;
    owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add { member: member.clone(), role: SharedGroupRole::Admin },
    )?;
    let base = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add {
            member: victim.client.fixture_group_actor("victim")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    admin.client.fixture_accept_group_state(&base, "admin")?;
    let request = admin.client.stage_group_change_request(
        "group",
        &skey(&admin.client)?,
        GroupStateChange::Remove {
            root_commitment: victim.client.owned_device_identity()?.root_commitment().into(),
            device_id: "victim".into(),
        },
        Some("stale-remove"),
    )?;
    let current = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::SetRole {
            root_commitment: member.root_commitment,
            device_id: "admin".into(),
            role: SharedGroupRole::Member,
        },
    )?;
    owner.client.persist_fetched_identity_directory(&manifest_of(&admin)?)?;
    owner.client.insert_group_request(&request, true)?;
    let primary = owner.client.fixture_primary()?;
    let result = owner.client.process_group_request_with_primary(
        &request,
        &skey(&owner.client)?,
        primary.as_ref(),
    )?;
    assert_eq!(result.status, GroupChangeStatus::PermissionDenied);
    assert_eq!(
        owner
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .snapshot()
            .state_hash,
        current.snapshot().state_hash
    );
    admin.client.apply_group_request_result(&result)?;
    assert_eq!(
        admin.client.group_change_statuses(None)?["requests"][0]["status"],
        "permission_denied"
    );
    assert!(
        admin
            .client
            .fixture_group_change(
                "group",
                "admin",
                GroupStateChange::SetName { name: "forged".into() }
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn a_lagging_member_commits_latest_full_state_without_history_resolution() -> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    let peer = native_person("peer", "peer")?;
    owner.client.fixture_group_create("group", "thread", None, "owner")?;
    let initial = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add {
            member: peer.client.fixture_group_actor("peer")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    peer.client.fixture_accept_group_state(&initial, "peer")?;
    let mut state = initial;
    for epoch in 0..70 {
        state = owner.client.fixture_group_change(
            "group",
            "owner",
            GroupStateChange::SetName { name: format!("Name {epoch}") },
        )?;
    }
    assert!(peer.client.fixture_accept_group_state(&state, "peer")?);
    assert_eq!(
        peer.client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view(),
        state.view()
    );
    Ok(())
}

#[test]
fn pending_requests_are_bounded_per_root_and_capacity_has_a_signed_result() -> Result<(), SdkError>
{
    let owner = native_person("owner", "owner")?;
    let admin = native_person("admin", "admin")?;
    owner.client.fixture_group_create("group", "thread", None, "owner")?;
    let base = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add {
            member: admin.client.fixture_group_actor("admin")?.identity,
            role: SharedGroupRole::Admin,
        },
    )?;
    admin.client.fixture_accept_group_state(&base, "admin")?;
    let change = GroupStateChange::SetName { name: "Pending".into() };
    let admin_target = skey(&admin.client)?;
    for index in 0..8 {
        let id = format!("request-{index}");
        let request = admin.client.stage_group_change_request(
            "group",
            &admin_target,
            change.clone(),
            Some(&id),
        )?;
        assert_eq!(
            admin.client.stage_group_change_request(
                "group",
                &admin_target,
                change.clone(),
                Some(&id)
            )?,
            request
        );
        owner.client.persist_fetched_identity_directory(&manifest_of(&admin)?)?;
        owner.client.insert_group_request(&request, true)?;
    }
    assert!(matches!(
        admin.client.stage_group_change_request(
            "group",
            &admin_target,
            change.clone(),
            Some("ninth")
        ),
        Err(SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
            ramflux_protocol::GroupStateLimit::Requests
        )))
    ));
    let ninth = ramflux_crypto::sign_group_change_request(
        admin.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &admin.client.owned_group_actor(&admin_target)?,
        &base,
        ramflux_crypto::GroupChangeRequestInput {
            request_id: "ninth".into(),
            change,
            now: now_unix_timestamp(),
        },
    )?;
    owner.client.insert_group_request(&ninth, true)?;
    let primary = owner.client.fixture_primary()?;
    let refusal = owner.client.process_group_request_with_primary(
        &ninth,
        &skey(&owner.client)?,
        primary.as_ref(),
    )?;
    assert_eq!(refusal.status, GroupChangeStatus::Capacity);
    ramflux_crypto::verify_group_change_result(&refusal, &ninth, &base, now_unix_timestamp())?;
    assert_eq!(owner.client.group_state("group")?.group_epoch, base.view().epoch);
    Ok(())
}

#[test]
fn creator_conflict_rechecks_device_revocation_before_replaying_a_foreign_request()
-> Result<(), SdkError> {
    let mut owner = native_person("owner", "phone")?;
    let sibling = native_sibling(&mut owner, "owner-laptop", "laptop")?;
    let admin = native_person("admin", "admin")?;
    owner.client.fixture_group_create("group", "thread", None, "phone")?;
    let base = owner.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Add {
            member: admin.client.fixture_group_actor("admin")?.identity,
            role: SharedGroupRole::Admin,
        },
    )?;
    admin.client.fixture_accept_group_state(&base, "admin")?;
    sibling.client.fixture_accept_group_state(&base, "laptop")?;
    let admin_target = skey(&admin.client)?;
    let first = admin.client.stage_group_change_request(
        "group",
        &admin_target,
        GroupStateChange::SetName { name: "Foreign first".into() },
        Some("repair-first"),
    )?;
    let second = admin.client.stage_group_change_request(
        "group",
        &admin_target,
        GroupStateChange::SetName { name: "Foreign second".into() },
        Some("repair-second"),
    )?;
    let manifest = manifest_of(&admin)?;
    for (client, request) in [(&owner.client, &first), (&sibling.client, &second)] {
        client.persist_fetched_identity_directory(&manifest)?;
        client.insert_group_request(request, true)?;
        let primary = client.fixture_primary()?;
        assert_eq!(
            client
                .process_group_request_with_primary(request, &skey(client)?, primary.as_ref())?
                .status,
            GroupChangeStatus::Applied
        );
    }
    let left = owner
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let right = sibling
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let (loser, winning, request, target) =
        if right.relation_to(&left)? == ramflux_crypto::GroupStateRelation::IncomingPreferred {
            (&owner.client, right, &first, "phone")
        } else {
            (&sibling.client, left, &second, "laptop")
        };
    let revoked = primary_revoked_manifest(&admin, "admin")?;
    loser.persist_fetched_identity_directory(&revoked)?;
    loser.fixture_accept_group_state(&winning, target)?;
    assert_eq!(
        loser
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view()
            .name,
        winning.view().name
    );
    let refused = loser
        .group_change_record(request, true)?
        .and_then(|record| record.result)
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(refused.status, GroupChangeStatus::PermissionDenied);
    Ok(())
}

#[test]
fn r7_owner_forks_repair_durable_removals_without_pending_intent() -> Result<(), SdkError> {
    for expired in [false, true] {
        let mut phone = native_person("owner", "phone")?;
        let laptop = native_sibling(&mut phone, "owner-laptop", "laptop")?;
        let peer = native_person("peer", "peer")?;
        phone.client.fixture_group_create("group", "thread", None, "phone")?;
        let base = phone.client.fixture_group_change(
            "group",
            "phone",
            GroupStateChange::Add {
                member: peer.client.fixture_group_actor("peer")?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        laptop.client.fixture_accept_group_state(&base, "laptop")?;
        phone.client.fixture_group_change(
            "group",
            "phone",
            GroupStateChange::Remove {
                root_commitment: peer.client.owned_device_identity()?.root_commitment().into(),
                device_id: "peer".into(),
            },
        )?;
        let pending =
            format!("group-state/creator-pending/{}", ramflux_protocol::encode_base64url("group"));
        if expired {
            let mut entries: Vec<serde_json::Value> = phone
                .client
                .account_db()?
                .load_actor_state(&pending)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            for entry in &mut entries {
                entry["expires_at"] = json!(0);
            }
            phone.client.account_db()?.persist_actor_state(&pending, &entries)?;
        } else {
            phone.client.account_db()?.remove_actor_state(&pending)?;
        }
        for name in ["laptop first", "laptop latest"] {
            laptop.client.fixture_group_change(
                "group",
                "laptop",
                GroupStateChange::SetName { name: name.into() },
            )?;
        }
        let incoming = laptop
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        assert!(phone.client.fixture_accept_group_state(&incoming, "phone")?);
        let repaired = phone
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        assert!(laptop.client.fixture_accept_group_state(&repaired, "laptop")?);
        assert_eq!(
            laptop
                .client
                .account_db()?
                .shared_group_state("group")?
                .ok_or(StorageError::GroupPermissionDenied)?
                .snapshot()
                .state_hash,
            repaired.snapshot().state_hash
        );
        assert_eq!(repaired.view().name.as_deref(), Some("laptop latest"));
        assert!(
            repaired
                .view()
                .effective_role(peer.client.owned_device_identity()?.root_commitment(), "peer")
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn r7_pruned_wire_exclusions_still_repair_from_indexed_receiver_floors() -> Result<(), SdkError> {
    let mut phone = native_person("owner", "phone")?;
    let laptop = native_sibling(&mut phone, "owner-laptop", "laptop")?;
    let peer = native_person("peer", "peer")?;
    let initial = phone.client.fixture_group_create("group", "thread", None, "phone")?;
    let joined = phone.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Add {
            member: peer.client.fixture_group_actor("peer")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    laptop.client.fixture_accept_group_state(&joined, "laptop")?;
    phone.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::Remove {
            root_commitment: peer.client.owned_device_identity()?.root_commitment().into(),
            device_id: "peer".into(),
        },
    )?;
    // Model a later full snapshot after departed-root exclusions are pruned.
    let primary = phone.client.fixture_primary()?.ok_or(SdkError::CustodySetupInvalid)?;
    let branch = phone.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let actor = phone.client.owned_group_actor(&skey(&phone.client)?)?;
    let mut pruned = initial;
    for name in ["one", "two", "three"] {
        pruned = advance_native_group_state(
            &primary,
            branch,
            &actor,
            &pruned,
            GroupStateChange::SetName { name: name.into() },
        )?;
    }
    phone.client.fixture_accept_group_state(&pruned, "phone")?;
    assert_eq!(
        phone
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::AuthorizationRejected)?
            .view()
            .excluded,
        []
    );
    phone.client.account_db()?.remove_actor_state(&format!(
        "group-state/creator-pending/{}",
        ramflux_protocol::encode_base64url("group")
    ))?;
    for name in ["laptop one", "laptop two", "laptop three"] {
        laptop.client.fixture_group_change(
            "group",
            "laptop",
            GroupStateChange::SetName { name: name.into() },
        )?;
    }
    let incoming = laptop
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::AuthorizationRejected)?;
    assert_eq!(incoming.relation_to(&pruned)?, ramflux_crypto::GroupStateRelation::Extension);
    phone.client.fixture_accept_group_state(&incoming, "phone")?;
    let repaired = phone
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::AuthorizationRejected)?;
    laptop.client.fixture_accept_group_state(&repaired, "laptop")?;
    assert_eq!(
        laptop
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::AuthorizationRejected)?
            .snapshot()
            .state_hash,
        repaired.snapshot().state_hash
    );
    assert!(
        repaired
            .view()
            .effective_role(peer.client.owned_device_identity()?.root_commitment(), "peer")
            .is_none()
    );
    Ok(())
}
