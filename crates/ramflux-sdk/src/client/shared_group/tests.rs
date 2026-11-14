// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-state convergence, first-message keys, names and removal through SDK group APIs.
use super::*;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::{Fixture as Native, bus as native_bus};
use crate::prekey::SdkDeviceManifestResponse;
pub(super) fn temp_root(label: &str) -> Result<ramflux_test_support::TestPath, SdkError> {
    Ok(ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(
        format!(
            "ramflux-group-{label}-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ),
    ))
}
/// Runs one native fixture future to completion on a fresh current-thread runtime.
fn native_block_on<T>(
    future: impl std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
) -> Result<T, SdkError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
        .map_err(|error| SdkError::LocalBus(error.to_string()))
}

/// One native account whose only device is `device`, held as a public-bus fixture.
pub(super) fn native_person(id: &str, device: &str) -> Result<LocalBusAccountState, SdkError> {
    native_block_on(async move {
        let fixture = Native::with_device(id, device).await?;
        Ok(fixture.into_bus())
    })
}

/// A laptop sibling of `phone`. It carries the account primary, as the phone holds it.
pub(super) fn native_sibling(
    phone: &mut LocalBusAccountState,
    id: &str,
    device: &str,
) -> Result<LocalBusAccountState, SdkError> {
    native_block_on(Box::pin(native_bus::sibling(phone, id, device)))
}

/// Manifest that the account's own native fixture published.
pub(super) fn manifest_of(
    account: &LocalBusAccountState,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    account
        .client
        .native_bus_fixture
        .as_ref()
        .map(|material| material.manifest.clone())
        .ok_or(SdkError::CustodySetupInvalid)
}

/// Device storage key that the raw group entry points expect as their target.
pub(super) fn native_target(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.owned_device_identity()?.storage_key().into())
}

/// Publishes each listed account's native manifest into every listed account's directory.
pub(super) fn install_native_directories(
    accounts: &[&LocalBusAccountState],
) -> Result<(), SdkError> {
    for holder in accounts {
        for source in accounts {
            holder.client.persist_fetched_identity_directory(&manifest_of(source)?)?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn three_devices_converge_and_each_first_group_message_reaches_the_other_members()
-> crate::client::native_test_support::TestResult {
    crate::client::native_test_support::watchdog::within(native_activation::three_devices()).await?
}
#[test]
fn readonly_group_metadata_does_not_need_private_root_material() -> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    owner.client.fixture_group_create("group", "thread", Some("Checklist".into()), "owner")?;
    let before = owner.client.shared_group_metadata("group")?;
    let mut reader = RamfluxClient::new();
    reader.active_account_db = Some(owner.client.account_db()?.open_reader()?);
    assert_eq!(reader.shared_group_metadata("group")?, before);
    drop((reader, owner));
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn one_bootstrap_packet_supplies_the_first_key_and_replays_do_not_reset_the_receiver()
-> crate::client::native_test_support::TestResult {
    crate::client::native_test_support::watchdog::within(native_activation::bootstrap_continuity())
        .await?
}

#[tokio::test(flavor = "current_thread")]
async fn shared_group_implicit_sibling_can_send_and_own_history_keeps_signed_names()
-> crate::client::native_test_support::TestResult {
    crate::client::native_test_support::watchdog::within(
        native_activation::implicit_sibling_history(),
    )
    .await?
}

#[path = "head_scope_tests.rs"]
mod head_scope_tests;

#[path = "fork_tests.rs"]
mod fork_tests;

#[test]
fn r5_contact_forwarding_cannot_adopt_a_stranger_group_or_override_decline() -> Result<(), SdkError>
{
    let stranger = native_person("stranger", "phone")?;
    let contact = native_person("contact", "phone")?;
    let user = native_person("user", "phone")?;
    stranger.client.fixture_group_create("g", "t", None, "phone")?;
    stranger.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::Add {
            member: contact.client.fixture_group_actor("phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let state = stranger.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::Add {
            member: user.client.fixture_group_actor("phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let contact_root = contact.client.owned_device_identity()?.root_commitment().to_owned();
    user.client.establish_friend_link("friend", "user", &contact_root)?;
    let forwarded = ramflux_crypto::resign_group_state_snapshot(
        contact.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &contact.client.fixture_group_actor("phone")?,
        &state,
    )?;
    assert!(user.client.group_snapshot_requires_consent(&forwarded)?);
    let packet = contact.client.shared_group_packet(&forwarded, false)?;
    user.client.hold_group_invitation(&forwarded, &packet)?;
    let user_target = native_target(&user.client)?;
    user.client.decide_group_invitation("g", false, &user_target)?;
    assert!(user.client.group_snapshot_requires_consent(&forwarded).is_err());
    let prepared = user.client.prepare_shared_group_payload(forwarded, &packet)?;
    assert!(user.client.apply_prepared_shared_group(&prepared, &user_target).is_err());
    assert!(user.client.account_db()?.shared_group_state("g")?.is_none());
    assert!(user.client.account_db()?.client_record("conversation", "t")?.is_none());
    drop((stranger, contact, user));
    Ok(())
}
#[test]
fn r5_removed_requester_flood_is_not_stored_and_other_groups_keep_capacity() -> Result<(), SdkError>
{
    use ramflux_crypto::{GroupChangeRequestInput, sign_group_change_request};
    let owner = native_person("owner", "phone")?;
    let removed = native_person("removed", "phone")?;
    let admin = native_person("admin", "phone")?;
    let victim = native_person("victim", "phone")?;
    for person in [&owner, &removed, &admin, &victim] {
        owner.client.persist_fetched_identity_directory(&manifest_of(person)?)?;
    }
    owner.client.fixture_group_create("g", "t", None, "phone")?;
    owner.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::Add {
            member: removed.client.fixture_group_actor("phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    owner.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::Add {
            member: admin.client.fixture_group_actor("phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    let before = owner.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::Add {
            member: victim.client.fixture_group_actor("phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    owner.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::Remove {
            root_commitment: removed.client.owned_device_identity()?.root_commitment().into(),
            device_id: "phone".into(),
        },
    )?;
    for index in 0..80 {
        let request = sign_group_change_request(
            removed.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &removed.client.fixture_group_actor("phone")?,
            &before,
            GroupChangeRequestInput {
                request_id: format!("flood-{index}"),
                change: GroupStateChange::SetName { name: "spam".into() },
                now: now_unix_timestamp(),
            },
        )?;
        assert!(owner.client.insert_group_request(&request, true).is_err());
    }
    assert!(owner.client.group_change_records()?.is_empty());
    let removal = sign_group_change_request(
        admin.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &admin.client.fixture_group_actor("phone")?,
        &before,
        GroupChangeRequestInput {
            request_id: "admin-removal".into(),
            change: GroupStateChange::Remove {
                root_commitment: victim.client.owned_device_identity()?.root_commitment().into(),
                device_id: "phone".into(),
            },
            now: now_unix_timestamp(),
        },
    )?;
    owner.client.insert_group_request(&removal, true)?;
    let owner_target = native_target(&owner.client)?;
    let owner_primary = owner.client.fixture_primary()?;
    assert_eq!(
        owner
            .client
            .process_group_request_with_primary(&removal, &owner_target, owner_primary.as_ref())?
            .status,
        ramflux_protocol::GroupChangeStatus::Applied
    );

    owner.client.fixture_group_create("other", "other-thread", None, "phone")?;
    let other = owner
        .client
        .account_db()?
        .shared_group_state("other")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let request = sign_group_change_request(
        owner.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &owner.client.fixture_group_actor("phone")?,
        &other,
        GroupChangeRequestInput {
            request_id: "legitimate-removal".into(),
            change: GroupStateChange::SetName { name: "legitimate".into() },
            now: now_unix_timestamp(),
        },
    )?;
    owner.client.insert_group_request(&request, true)?;
    assert_eq!(owner.client.group_change_records()?.len(), 2);
    drop((owner, removed, admin, victim));
    Ok(())
}
#[test]
fn r5_processed_results_still_count_toward_the_source_partition() -> Result<(), SdkError> {
    let owner = native_person("owner", "phone")?;
    owner.client.fixture_group_create("g", "t", None, "phone")?;
    let state = owner
        .client
        .account_db()?
        .shared_group_state("g")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    for index in 0..65 {
        let request = ramflux_crypto::sign_group_change_request(
            owner.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &owner.client.fixture_group_actor("phone")?,
            &state,
            ramflux_crypto::GroupChangeRequestInput {
                request_id: format!("processed-{index}"),
                change: GroupStateChange::SetName { name: "name".into() },
                now: now_unix_timestamp(),
            },
        )?;
        let result = owner.client.insert_group_request(&request, true);
        if index == 64 {
            assert!(result.is_err());
        } else {
            result?;
            let mut row = owner
                .client
                .group_change_record(&request, true)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            row.local_status = "result_ready".into();
            owner.client.persist_group_request(&row)?;
        }
    }
    assert_eq!(owner.client.group_change_records()?.len(), 64);
    drop(owner);
    Ok(())
}
#[test]
fn r5_group_aliases_follow_message_deletion_and_pending_expiry() -> Result<(), SdkError> {
    let owner = native_person("owner", "phone")?;
    owner.client.fixture_group_create("g", "t", None, "phone")?;
    let (canonical, _) = owner.client.qualify_outgoing_group_message("g", "logical")?;
    owner.client.send_direct_message("t", &canonical, "phone", b"body")?;
    owner.client.account_db()?.delete_direct_message("t", &canonical, "local", "delete")?;
    assert_eq!(owner.client.outgoing_group_logical_id(&canonical)?, None);
    let (pending, _) = owner.client.qualify_outgoing_group_message("g", "pending")?;
    let alias_key = format!("group-message/alias/{pending}");
    let mut row: serde_json::Value = owner
        .client
        .account_db()?
        .load_actor_state(&alias_key)?
        .ok_or(SdkError::IdentityRootMissing)?;
    row["expires_at"] = serde_json::json!(0);
    owner.client.account_db()?.persist_actor_state(&alias_key, &row)?;
    owner.client.qualify_outgoing_group_message("g", "next")?;
    assert_eq!(owner.client.outgoing_group_logical_id(&pending)?, None);
    drop(owner);
    Ok(())
}
#[test]
fn r5_successor_transfer_chain_replaces_an_offline_members_higher_epoch_projection()
-> Result<(), SdkError> {
    let mut owner = native_person("owner", "phone")?;
    let laptop = native_sibling(&mut owner, "owner-laptop", "laptop")?;
    let bob = native_person("bob", "phone")?;
    let observer = native_person("observer", "phone")?;
    owner.client.fixture_group_create("g", "t", None, "phone")?;
    for member in [&bob, &observer] {
        owner.client.fixture_group_change(
            "g",
            "phone",
            GroupStateChange::Add {
                member: member.client.fixture_group_actor("phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
    }
    let base = owner
        .client
        .account_db()?
        .shared_group_state("g")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let mut fork = base.clone();
    let laptop_primary =
        laptop.client.fixture_primary()?.ok_or(SdkError::CustodyVaultUnavailable)?;
    for index in 0..5 {
        fork = ramflux_crypto::advance_native_group_state(
            &laptop_primary,
            laptop.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &laptop.client.fixture_group_actor("laptop")?,
            &fork,
            GroupStateChange::SetName { name: format!("fork-{index}") },
        )?;
    }
    observer.client.fixture_accept_group_state(&fork, "phone")?;
    owner.client.fixture_accept_group_state(&fork, "phone")?;
    bob.client.fixture_accept_group_state(&fork, "phone")?;
    let creator = bob.client.fixture_group_actor("phone")?;
    let acceptance = ramflux_crypto::accept_group_transfer(
        bob.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &creator,
        &fork,
        &ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        now_unix_timestamp(),
    )?;
    let transfer = owner.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::TransferOwnership { creator, acceptance: Box::new(acceptance) },
    )?;
    bob.client.fixture_accept_group_state(&transfer, "phone")?;
    let successor = bob.client.fixture_group_change(
        "g",
        "phone",
        GroupStateChange::SetName { name: "successor".into() },
    )?;
    assert!(successor.view().epoch > fork.view().epoch);
    assert!(observer.client.fixture_accept_group_state(&successor, "phone")?);
    assert_eq!(
        observer
            .client
            .account_db()?
            .shared_group_state("g")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .creator(),
        successor.creator()
    );
    assert!(!observer.client.fixture_accept_group_state(&fork, "phone")?);
    drop((owner, laptop, bob, observer));
    Ok(())
}
#[test]
fn r5_legacy_nonmember_results_are_pruned_on_new_admission() -> Result<(), SdkError> {
    let owner = native_person("owner", "phone")?;
    let outsider = native_person("outsider", "phone")?;
    let base = owner.client.fixture_group_create("g", "t", None, "phone")?;
    // Reconstruct a row admitted by the former receive path, using a genuine
    // root-certified outsider and a creator-signed refusal.
    let mut request = ramflux_protocol::GroupChangeRequest {
        schema: ramflux_protocol::group_state::GROUP_CHANGE_REQUEST_DOMAIN.into(),
        group_id: "g".into(),
        genesis_hash: base.genesis_hash()?,
        base_epoch: 1,
        creator_root: owner.client.owned_device_identity()?.root_commitment().into(),
        request_id: "old-outsider".into(),
        actor: outsider.client.fixture_group_actor("phone")?,
        change: GroupStateChange::SetName { name: "spam".into() },
        issued_at: now_unix_timestamp(),
        expires_at: now_unix_timestamp() + 86400,
        signature: String::new(),
    };
    let mut body = serde_json::to_value(&request)?;
    body.as_object_mut().ok_or(SdkError::IdentityRootMissing)?.remove("signature");
    request.signature = ramflux_crypto::sign_with_device_branch(
        outsider.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &body,
    )?;
    ramflux_crypto::verify_group_change_request(&request, now_unix_timestamp())?;
    // Retention reads stored rows; wire verification remains mandatory on new admission.
    let owner_primary = owner.client.fixture_primary()?.ok_or(SdkError::CustodyVaultUnavailable)?;
    let result = ramflux_crypto::sign_native_group_change_result(
        &owner_primary,
        &owner.client.fixture_group_actor("phone")?,
        &request,
        &base,
        ramflux_protocol::GroupChangeStatus::PermissionDenied,
        now_unix_timestamp(),
    )?;
    owner.client.persist_group_request(&super::requests::RequestRecord {
        request,
        incoming: true,
        result: Some(result),
        local_status: "result_ready".into(),
        expires_at: now_unix_timestamp() + 86400,
        next_at: 0,
        delivered: BTreeSet::new(),
        federation: None,
    })?;
    owner.client.fixture_group_create("other", "other-thread", None, "phone")?;
    let owner_target = native_target(&owner.client)?;
    let request = owner.client.stage_group_change_request(
        "other",
        &owner_target,
        GroupStateChange::SetName { name: "legitimate".into() },
        None,
    )?;
    let rows = owner.client.group_change_records()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request, request);
    drop((owner, outsider));
    Ok(())
}
#[test]
fn r5_signed_capacity_results_are_bounded_and_cannot_spend_another_groups_pool()
-> Result<(), SdkError> {
    let owner = native_person("owner", "owner")?;
    let admin = native_person("admin", "admin")?;
    owner.client.fixture_group_create("group", "thread", None, "owner")?;
    let base = owner.client.fixture_group_change(
        "group",
        "owner",
        GroupStateChange::Add {
            member: admin.client.fixture_group_actor("admin")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    let owner_target = native_target(&owner.client)?;
    for index in 0..65 {
        let request = ramflux_crypto::sign_group_change_request(
            admin.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &admin.client.fixture_group_actor("admin")?,
            &base,
            ramflux_crypto::GroupChangeRequestInput {
                request_id: format!("flood-{index}"),
                change: GroupStateChange::SetName { name: "unchanged".into() },
                now: now_unix_timestamp(),
            },
        )?;
        let result = owner.client.insert_group_request(&request, true);
        if index == 64 {
            assert!(result.is_err());
            continue;
        }
        result?;
        if index >= 8 {
            let response = owner.client.process_group_request(&request, &owner_target)?;
            assert_eq!(response.status, ramflux_protocol::GroupChangeStatus::Capacity);
            ramflux_crypto::verify_group_change_result(
                &response,
                &request,
                &base,
                now_unix_timestamp(),
            )?;
        }
    }
    assert_eq!(owner.client.group_change_records()?.len(), 64);
    owner.client.fixture_group_create("other", "other-thread", None, "owner")?;
    let other = owner.client.fixture_group_change(
        "other",
        "owner",
        GroupStateChange::Add {
            member: admin.client.fixture_group_actor("admin")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    let request = ramflux_crypto::sign_group_change_request(
        admin.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &admin.client.fixture_group_actor("admin")?,
        &other,
        ramflux_crypto::GroupChangeRequestInput {
            request_id: "other-request".into(),
            change: GroupStateChange::SetName { name: "legitimate".into() },
            now: now_unix_timestamp(),
        },
    )?;
    owner.client.insert_group_request(&request, true)?;
    assert_eq!(owner.client.group_change_records()?.len(), 65);
    assert!(
        owner.client.group_change_record(&request, true)?.is_some_and(|row| row.result.is_none())
    );
    assert_eq!(owner.client.group_state("group")?.group_epoch, base.view().epoch);
    drop((owner, admin));
    Ok(())
}
#[path = "native_activation_tests.rs"]
mod native_activation;
