// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::identity_authority::VerifiedLayerRoster;
use crate::client::native_test_support::{Fixture, TestResult};
use crate::custody::{DeclarationValidity, load_account, sign_layer_declaration};
use crate::prekey::SdkDeviceManifestResponse;
use crate::time::FixedClock;
use crate::{GatewayDirectMessage, RamfluxClient, SdkError};
use ramflux_protocol::custody::{
    CustodyManifest, CustodyManifestDevice, DeviceRef, LayerDeclaration,
    MAX_LAYER_DECLARATION_VALIDITY_SECONDS, MESSAGE_LAYER_FLOOR, SignedLayerDeclaration,
};
use ramflux_protocol::group_state::{GroupStateChange, SharedGroupRole};
use ramflux_protocol::message::KindId;
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR};
use ramflux_protocol::schema_profile::{ACTIVE_STORAGE_GENERATION, MESSAGE_SCHEMA_V1_GENERATION};
use std::cell::Cell;
use std::collections::BTreeSet;

fn representation<'a>(
    plan: &'a SelectionPlan,
    contains: &str,
) -> Result<&'a Representation, Box<dyn std::error::Error>> {
    plan.representations
        .iter()
        .find(|row| row.targets.iter().any(|target| target.device_id == contains))
        .ok_or_else(|| "missing representation".into())
}

fn assert_typed(encoding: Encoding, kind: KindId, layer: u32) {
    assert_eq!(encoding, Encoding::Typed { kind, layer });
}

fn assert_peer_upgrade(error: &SdkError) -> TestResult {
    match error {
        SdkError::LocalBusRefused { code, message, .. }
            if code == "PeerUpgradeRequired"
                && message == "admitted clients must support the profile floor" =>
        {
            Ok(())
        }
        other => Err(format!("expected PeerUpgradeRequired, got {other}").into()),
    }
}

fn wall_now() -> TestResult<u64> {
    Ok(crate::custody::network_now()?)
}

fn primary_key(fixture: &Fixture) -> TestResult<ramflux_crypto::custody::SelfSigningKey> {
    let native = fixture.manifest.custody.as_ref().ok_or("native")?;
    Ok(fixture.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?)
}

fn native_of(manifest: &SdkDeviceManifestResponse) -> TestResult<CustodyManifest> {
    Ok((**manifest.custody.as_ref().ok_or("native")?).clone())
}

fn persist_declared(fixture: &Fixture, manifest: &SdkDeviceManifestResponse) -> TestResult {
    fixture.client.persist_fetched_identity_directory(manifest)?;
    Ok(())
}

fn dm_message(sender: &Fixture, peer: &Fixture, message_id: &str) -> GatewayDirectMessage {
    GatewayDirectMessage {
        conversation_id: "dm".into(),
        message_id: message_id.into(),
        envelope_id: message_id.into(),
        source_principal_id: sender.manifest.principal_id.clone(),
        sender_id: sender.config.device_id.clone(),
        recipient_device_id: Some(peer.config.device_id.clone()),
        recipient_principal_commitment: Some(peer.manifest.principal_commitment.clone()),
        target_delivery_id: peer.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 0,
    }
}

fn publish_primary(
    fixture: &Fixture,
    issued: u64,
    expires: u64,
) -> TestResult<SdkDeviceManifestResponse> {
    let id = fixture.client.account_db()?.local_account_id.clone();
    let account = load_account(&fixture.root.0, &id, issued)?;
    let (_, branch) =
        account.credentials(fixture.vault.as_ref(), &fixture.config.device_id, issued)?;
    let publication = account.candidate_message_layer_publication(
        &fixture.root.0,
        &branch,
        &primary_key(fixture)?,
        MESSAGE_LAYER_FLOOR,
        DeclarationValidity { issued_at: issued, expires_at: expires },
    )?;
    let mut native = native_of(&fixture.manifest)?;
    native.publication = publication.clone();
    native.devices[0].message_layer = publication.record.body.devices[0].message_layer.clone();
    Ok(SdkDeviceManifestResponse::from_native(native)?)
}

fn enroll_sibling(
    fixture: &Fixture,
    native: &mut CustodyManifest,
    device_id: &str,
    issued: u64,
) -> TestResult<ramflux_crypto::DeviceBranch> {
    let primary = primary_key(fixture)?;
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, issued, None, None)?;
    let branch = ramflux_crypto::create_device_branch(
        &fixture.manifest.principal_id,
        device_id,
        1,
        ramflux_crypto::random_32()?,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::random_32()?);
    let mut certificate = native.publication.record.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or("branch")?
        .body
        .clone();
    certificate.device_id = device_id.into();
    certificate.device_epoch = 1;
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
    certificate.agreement_identity_public_key =
        ramflux_protocol::encode_base64url(&agreement.public);
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    native.publication.record =
        primary.enroll_device(&current, primary.certify_branch(certificate)?, issued)?;
    native.devices.push(CustodyManifestDevice {
        device_ref: DeviceRef {
            account_anchor: fixture.manifest.principal_commitment.clone(),
            device_id: device_id.into(),
            device_epoch: 1,
        },
        target_delivery_id: format!("{device_id}-delivery"),
        prekey_bundle: native.devices[0].prekey_bundle.clone(),
        message_layer: None,
    });
    Ok(branch)
}

fn sign_layers(
    fixture: &Fixture,
    native: &mut CustodyManifest,
    layers: &[(&str, &ramflux_crypto::DeviceBranch, u64, u64)],
    issued: u64,
) -> TestResult {
    let primary = primary_key(fixture)?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
    body.device_set_epoch =
        ramflux_protocol::custody::encode_epoch(range, revision.checked_add(1).ok_or("revision")?)?;
    body.issued_at = issued;
    for (device_id, branch, layer_issued, layer_expires) in layers {
        let device =
            body.devices.iter_mut().find(|row| row.device_id == *device_id).ok_or("device")?;
        let signed = sign_layer_declaration(
            branch,
            DeviceRef {
                account_anchor: body.account_anchor.clone(),
                device_id: (*device_id).into(),
                device_epoch: device.device_epoch,
            },
            MESSAGE_LAYER_FLOOR,
            1,
            *layer_issued,
            *layer_expires,
        )?;
        device.message_layer = Some(signed.clone());
        let projected = native
            .devices
            .iter_mut()
            .find(|row| row.device_ref.device_id == *device_id)
            .ok_or("proj")?;
        projected.message_layer = Some(signed);
    }
    native.publication.record = primary.sign_record(body)?;
    Ok(())
}

fn sign_layer_raw(
    branch: &ramflux_crypto::DeviceBranch,
    device: DeviceRef,
    issued_at: u64,
    expires_at: u64,
) -> TestResult<SignedLayerDeclaration> {
    let declaration = LayerDeclaration {
        device,
        max_layer: MESSAGE_LAYER_FLOOR,
        declaration_sequence: 1,
        issued_at,
        expires_at,
    };
    let bytes = ramflux_protocol::custody::signing_bytes(
        ramflux_protocol::domain::CUSTODY_MESSAGE_LAYER_DECLARATION,
        &declaration,
    )?;
    Ok(SignedLayerDeclaration {
        branch_signature: ramflux_crypto::sign_canonical_bytes_with_device_branch(&bytes, branch),
        declaration,
    })
}

fn project_layers(native: &mut CustodyManifest) {
    for device in &mut native.devices {
        device.message_layer = native
            .publication
            .record
            .body
            .devices
            .iter()
            .find(|row| row.device_id == device.device_ref.device_id)
            .and_then(|row| row.message_layer.clone());
    }
}

fn own_roster(
    fixture: &Fixture,
    extras: &[(&str, u64, u64)],
    issued: u64,
) -> TestResult<SdkDeviceManifestResponse> {
    let mut native = native_of(&fixture.manifest)?;
    let id = fixture.client.account_db()?.local_account_id.clone();
    let account = load_account(&fixture.root.0, &id, issued)?;
    let (_, primary_branch) =
        account.credentials(fixture.vault.as_ref(), &fixture.config.device_id, issued)?;
    let primary_id = fixture.config.device_id.clone();
    let mut branches = Vec::new();
    for (name, layer_issued, layer_expires) in extras {
        if *name == primary_id {
            continue;
        }
        let branch = enroll_sibling(fixture, &mut native, name, issued)?;
        branches.push((name.to_string(), branch, *layer_issued, *layer_expires));
    }
    let mut layers = Vec::new();
    let primary_window = extras
        .iter()
        .find(|(name, _, _)| *name == primary_id)
        .map_or((issued, issued + 3_600), |row| (row.1, row.2));
    layers.push((primary_id.as_str(), &primary_branch.signing, primary_window.0, primary_window.1));
    for (name, branch, layer_issued, layer_expires) in &branches {
        layers.push((name.as_str(), branch, *layer_issued, *layer_expires));
    }
    sign_layers(fixture, &mut native, &layers, issued)?;
    Ok(SdkDeviceManifestResponse::from_native(native)?)
}

fn shared_group(
    owner: &Fixture,
    owner_manifest: &SdkDeviceManifestResponse,
    members: &[(&Fixture, &SdkDeviceManifestResponse)],
    group_id: &str,
) -> TestResult {
    persist_declared(owner, owner_manifest)?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        group_id,
        "thread",
        Some("group".into()),
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    for (member, manifest) in members {
        persist_declared(owner, manifest)?;
        let actor = member.client.owned_group_actor(&member.config.target_delivery_id)?;
        owner.client.shared_group_change_with_primary(
            group_id,
            &owner.config.target_delivery_id,
            GroupStateChange::Add { member: actor.identity, role: SharedGroupRole::Member },
            Some(&primary),
        )?;
    }
    Ok(())
}

fn plan_of(request: &SelectionRequest) -> TestResult<SelectionPlan> {
    Ok(select(request)?)
}

#[tokio::test]
async fn group_fresh_cohort_minimum() -> TestResult {
    let alice = Fixture::with_device("p05-group-alice", "alice").await?;
    let bob = Fixture::with_device("p05-group-bob", "bob").await?;
    let carol = Fixture::with_device("p05-group-carol", "carol").await?;
    let issued = wall_now()? + 1;
    let alice_m = publish_primary(&alice, issued, issued + 3_600)?;
    let bob_m = publish_primary(&bob, issued, issued + 3_600)?;
    let carol_m = publish_primary(&carol, issued, issued + 10)?;
    persist_declared(&alice, &alice_m)?;
    shared_group(&alice, &alice_m, &[(&bob, &bob_m), (&carol, &carol_m)], "g1")?;
    let _clock = FixedClock::set(i64::try_from(issued + 20)?);
    let request =
        alice.client.group_selection_request("g1", "alice", "event-1", KindId::KindMessage)?;
    assert_eq!(request.source_compiled_support, COMPILED_LAYER);
    let plan = plan_of(&request)?;
    assert_eq!(plan.logical_event_id, "event-1");
    assert_eq!(plan.fresh_cohort_layer, Some(PROFILE_FLOOR));
    assert_eq!(plan.representations.len(), 2);
    let fresh = representation(&plan, "bob")?;
    let floor = representation(&plan, "carol")?;
    assert_eq!(fresh.variant_counter, 1);
    assert_eq!(floor.variant_counter, 2);
    assert_eq!(fresh.selected_layer, PROFILE_FLOOR);
    assert_eq!(floor.selected_layer, PROFILE_FLOOR);
    assert!(!fresh.targets.iter().any(|target| target.device_id == "carol"));
    assert!(!fresh.targets.iter().any(|target| target.device_id == "alice"));
    assert_eq!(floor.targets.len(), 1);
    assert_typed(fresh.encoding, KindId::KindMessage, PROFILE_FLOOR);
    assert_typed(floor.encoding, KindId::KindMessage, PROFILE_FLOOR);
    Ok(())
}

#[tokio::test]
async fn own_and_dm_fresh_minimum() -> TestResult {
    let own = Fixture::new("p05-own-dm").await?;
    let peer = Fixture::new("p05-own-dm-peer").await?;
    let issued = wall_now()? + 1;
    let own_m = own_roster(
        &own,
        &[("watch", issued, issued + 3_600), ("laptop", issued, issued + 10)],
        issued,
    )?;
    let peer_fresh = publish_primary(&peer, issued, issued + 3_600)?;
    persist_declared(&own, &peer_fresh)?;
    persist_declared(&peer, &peer_fresh)?;
    let _clock = FixedClock::set(i64::try_from(issued + 20)?);
    let own_plan = plan_of(&RamfluxClient::own_copy_selection_request(
        "own-1",
        &own.config.device_id,
        &own_m,
        KindId::KindMessage,
    )?)?;
    let dm_plan = plan_of(
        &own.client.dm_selection_request(&dm_message(&own, &peer, "dm-1"), KindId::KindMessage)?,
    )?;
    assert_eq!(own_plan.scope, FanoutScope::OwnCopy);
    assert_eq!(dm_plan.scope, FanoutScope::Dm);
    assert_eq!(own_plan.logical_event_id, "own-1");
    assert_eq!(dm_plan.logical_event_id, "dm-1");
    assert_eq!(own_plan.fresh_cohort_layer, Some(PROFILE_FLOOR));
    assert_eq!(dm_plan.fresh_cohort_layer, Some(PROFILE_FLOOR));
    let own_fresh = representation(&own_plan, "watch")?;
    let own_floor = representation(&own_plan, "laptop")?;
    assert_eq!(own_fresh.variant_counter, 1);
    assert_eq!(own_floor.variant_counter, 2);
    assert!(!own_fresh.targets.iter().any(|target| target.device_id == "laptop"));
    assert_eq!(dm_plan.representations.len(), 1);
    assert_eq!(representation(&dm_plan, &peer.config.device_id)?.variant_counter, 1);
    FixedClock::advance_to(i64::try_from(issued + 3_600)?);
    let at_expiry = plan_of(
        &own.client
            .dm_selection_request(&dm_message(&own, &peer, "dm-bound"), KindId::KindMessage)?,
    )?;
    assert_eq!(at_expiry.representations.len(), 1);
    assert_eq!(at_expiry.fresh_cohort_layer, Some(PROFILE_FLOOR));
    Ok(())
}

#[tokio::test]
async fn membership_change_rebuilds_unsubmitted_representation() -> TestResult {
    let owner = Fixture::with_device("p05-recheck-owner", "owner").await?;
    let alice = Fixture::with_device("p05-recheck-alice", "alice").await?;
    let bob = Fixture::with_device("p05-recheck-bob", "bob").await?;
    let issued = wall_now()? + 1;
    let owner_m = publish_primary(&owner, issued, issued + 3_600)?;
    let alice_m = publish_primary(&alice, issued, issued + 3_600)?;
    let bob_m = publish_primary(&bob, issued, issued + 3_600)?;
    persist_declared(&owner, &owner_m)?;
    shared_group(&owner, &owner_m, &[(&alice, &alice_m), (&bob, &bob_m)], "g-recheck")?;
    let _clock = FixedClock::set(i64::try_from(issued)?);
    let first = owner.client.group_selection_request(
        "g-recheck",
        "owner",
        "event-1",
        KindId::KindMessage,
    )?;
    let plan = select(&first)?;
    let unchanged = recheck(&plan, &first)?;
    assert_eq!(unchanged.variant_counter_high_water, 1);
    assert_eq!(plan.representations[0].variant_counter, 1);
    assert_eq!(unchanged.representations[0].variant_counter, 1);
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(owner.vault.as_ref())?;
    let bob_id = bob.client.owned_device_identity()?;
    let reads = Cell::new(0);
    let rebuilt = select_with_current_membership(|| {
        reads.set(reads.get() + 1);
        if reads.get() == 2 {
            owner.client.shared_group_change_with_primary(
                "g-recheck",
                &owner.config.target_delivery_id,
                GroupStateChange::Remove {
                    root_commitment: bob_id.root_commitment().into(),
                    device_id: bob_id.device_id().into(),
                },
                Some(&primary),
            )?;
        }
        owner.client.group_selection_request("g-recheck", "owner", "event-1", KindId::KindMessage)
    })?;
    assert_eq!(reads.get(), 2);
    assert_eq!(rebuilt.logical_event_id, "event-1");
    assert_eq!(rebuilt.variant_counter_high_water, 2);
    assert!(
        !rebuilt
            .representations
            .iter()
            .any(|row| { row.targets.iter().any(|target| target.device_id == "bob") })
    );
    assert!(rebuilt.representations.iter().all(|row| {
        !plan.representations.iter().any(|old| old.variant_counter == row.variant_counter)
    }));
    Ok(())
}

#[tokio::test]
async fn downgrade_does_not_execute_structural_control() -> TestResult {
    let owner = Fixture::with_device("p05-down-owner", "owner").await?;
    let alice = Fixture::with_device("p05-down-alice", "alice").await?;
    let issued = wall_now()? + 1;
    let owner_m = publish_primary(&owner, issued, issued + 3_600)?;
    let alice_m = publish_primary(&alice, issued, issued + 3_600)?;
    persist_declared(&owner, &owner_m)?;
    shared_group(&owner, &owner_m, &[(&alice, &alice_m)], "g-down")?;
    let _clock = FixedClock::set(i64::try_from(issued)?);
    for kind in [KindId::KindDelete, KindId::KindEdit, KindId::KindReaction, KindId::KindControl] {
        assert_typed(encoding_for(kind, PROFILE_FLOOR)?, kind, PROFILE_FLOOR);
        assert_eq!(encoding_for(kind, PROFILE_FLOOR - 1)?, Encoding::PeerUpgradeRequired);
        let request = owner.client.group_selection_request("g-down", "owner", "event-1", kind)?;
        let plan = plan_of(&request)?;
        for row in &plan.representations {
            assert_typed(row.encoding, kind, PROFILE_FLOOR);
        }
    }
    let mut refused =
        owner.client.group_selection_request("g-down", "owner", "event-1", KindId::KindDelete)?;
    refused.source_compiled_support = PROFILE_FLOOR - 1;
    match select(&refused) {
        Err(error) => assert_peer_upgrade(&error)?,
        Ok(_) => return Err("layer-1-only client must fail admission".into()),
    }
    Ok(())
}

#[tokio::test]
async fn offline_over_24h_still_receives_floor_in_dm_group_and_own_copy() -> TestResult {
    let owner = Fixture::with_device("p05-off-owner", "owner").await?;
    let fresh = Fixture::with_device("p05-off-fresh", "fresh").await?;
    let stale = Fixture::with_device("p05-off-stale", "stale").await?;
    let issued = wall_now()? + 1;
    let stale_exp = issued + MAX_LAYER_DECLARATION_VALIDITY_SECONDS;
    let fresh_issued = issued + 120;
    let fresh_exp = fresh_issued + MAX_LAYER_DECLARATION_VALIDITY_SECONDS;
    let owner_m = publish_primary(&owner, fresh_issued, fresh_exp)?;
    let fresh_m = publish_primary(&fresh, fresh_issued, fresh_exp)?;
    let stale_m = publish_primary(&stale, issued, stale_exp)?;
    persist_declared(&owner, &owner_m)?;
    persist_declared(&owner, &fresh_m)?;
    persist_declared(&owner, &stale_m)?;
    persist_declared(&fresh, &fresh_m)?;
    persist_declared(&stale, &stale_m)?;
    shared_group(&owner, &owner_m, &[(&fresh, &fresh_m), (&stale, &stale_m)], "g-off")?;
    let own_m = own_roster(
        &owner,
        &[("watch", fresh_issued, fresh_exp), ("stale", issued, stale_exp)],
        fresh_issued,
    )?;
    let _clock = FixedClock::set(i64::try_from(stale_exp + 5)?);
    let group = plan_of(&owner.client.group_selection_request(
        "g-off",
        "owner",
        "event-1",
        KindId::KindDelete,
    )?)?;
    let dm = plan_of(
        &owner
            .client
            .dm_selection_request(&dm_message(&owner, &stale, "dm-off"), KindId::KindDelete)?,
    )?;
    let own = plan_of(&RamfluxClient::own_copy_selection_request(
        "own-off",
        &owner.config.device_id,
        &own_m,
        KindId::KindDelete,
    )?)?;
    for (plan, stale_id, fresh_id) in [
        (&group, "stale", Some("fresh")),
        (&dm, stale.config.device_id.as_str(), None),
        (&own, "stale", Some("watch")),
    ] {
        let floor = representation(plan, stale_id)?;
        assert_eq!(floor.selected_layer, PROFILE_FLOOR);
        assert_typed(floor.encoding, KindId::KindDelete, PROFILE_FLOOR);
        if let Some(fresh_id) = fresh_id {
            let fresh_row = representation(plan, fresh_id)?;
            assert_eq!(fresh_row.variant_counter, 1);
            assert_eq!(floor.variant_counter, 2);
            assert!(!fresh_row.targets.iter().any(|target| target.device_id == stale_id));
            assert_eq!(plan.representations.len(), 2);
        } else {
            assert_eq!(plan.fresh_cohort_layer, None);
            assert_eq!(plan.representations.len(), 1);
            assert_eq!(floor.variant_counter, 1);
        }
    }
    Ok(())
}

#[test]
fn schema_gate_off_skips_candidate_plan() -> TestResult {
    assert!(!schema_v1_selected());
    assert_eq!(ACTIVE_STORAGE_GENERATION, 0);
    assert_eq!(MESSAGE_SCHEMA_V1_GENERATION, 1);
    let built = Cell::new(false);
    let plan = RamfluxClient::candidate_target_plan(|| {
        built.set(true);
        Err(SdkError::CustodySetupInvalid)
    })?;
    assert!(plan.is_none());
    assert!(!built.get(), "gate-off adapters must not construct a selection request");
    Ok(())
}

#[test]
fn variant_counter_overflow_is_exact() -> TestResult {
    let mut representations = Vec::new();
    let mut counter = u64::MAX;
    let error = push_representation(
        &mut representations,
        &mut counter,
        KindId::KindMessage,
        PROFILE_FLOOR,
        BTreeSet::new(),
    )
    .err()
    .ok_or("overflow")?;
    match error {
        SdkError::LocalBusRefused { code, message, .. }
            if code == "ValidationFailed" && message == "variant counter overflow" =>
        {
            Ok(())
        }
        other => Err(format!("expected overflow, got {other}").into()),
    }
}

fn classify_own(
    manifest: &SdkDeviceManifestResponse,
    source: &str,
    now: u64,
) -> TestResult<SelectionPlan> {
    let _clock = FixedClock::set(i64::try_from(now)?);
    plan_of(&RamfluxClient::own_copy_selection_request(
        "class-1",
        source,
        manifest,
        KindId::KindMessage,
    )?)
}

fn assert_target_stale(plan: &SelectionPlan, device_id: &str) -> TestResult {
    assert_eq!(plan.fresh_cohort_layer, None);
    let floor = representation(plan, device_id)?;
    assert_eq!(floor.selected_layer, PROFILE_FLOOR);
    assert_eq!(floor.variant_counter, 1);
    Ok(())
}

fn classify_unverified_stale(
    manifest: &SdkDeviceManifestResponse,
    source: &str,
    now: u64,
    device_id: &str,
) -> TestResult {
    assert!(VerifiedLayerRoster::verify(manifest, now).is_err(), "P04 must refuse this directory");
    assert_target_stale(&classify_own(manifest, source, now)?, device_id)
}

#[tokio::test]
async fn forged_declaration_is_classified_stale() -> TestResult {
    let own = Fixture::new("p05-forged").await?;
    let issued = wall_now()? + 1;
    let mut native = native_of(&own_roster(&own, &[("laptop", issued, issued + 3_600)], issued)?)?;
    let device = native
        .publication
        .record
        .body
        .devices
        .iter_mut()
        .find(|row| row.device_id == "laptop")
        .ok_or("laptop")?;
    let signed = device.message_layer.as_mut().ok_or("layer")?;
    signed.branch_signature = ramflux_protocol::encode_base64url([7_u8; 64]);
    project_layers(&mut native);
    let manifest = SdkDeviceManifestResponse::from_native(native)?;
    classify_unverified_stale(&manifest, &own.config.device_id, issued + 1, "laptop")
}

#[tokio::test]
async fn foreign_device_declaration_is_classified_stale() -> TestResult {
    let own = Fixture::new("p05-foreign").await?;
    let issued = wall_now()? + 1;
    let mut native = native_of(&own.manifest)?;
    let laptop = enroll_sibling(&own, &mut native, "laptop", issued)?;
    let primary_ref = DeviceRef {
        account_anchor: own.manifest.principal_commitment.clone(),
        device_id: own.config.device_id.clone(),
        device_epoch: 1,
    };
    let foreign = sign_layer_declaration(
        &laptop,
        primary_ref,
        MESSAGE_LAYER_FLOOR,
        1,
        issued,
        issued + 3_600,
    )?;
    let device = native
        .publication
        .record
        .body
        .devices
        .iter_mut()
        .find(|row| row.device_id == "laptop")
        .ok_or("laptop")?;
    device.message_layer = Some(foreign);
    project_layers(&mut native);
    let manifest = SdkDeviceManifestResponse::from_native(native)?;
    classify_unverified_stale(&manifest, &own.config.device_id, issued + 1, "laptop")
}

#[tokio::test]
async fn wrong_epoch_declaration_is_classified_stale() -> TestResult {
    let own = Fixture::new("p05-epoch").await?;
    let issued = wall_now()? + 1;
    let mut native = native_of(&own.manifest)?;
    let laptop = enroll_sibling(&own, &mut native, "laptop", issued)?;
    let wrong = sign_layer_declaration(
        &laptop,
        DeviceRef {
            account_anchor: own.manifest.principal_commitment.clone(),
            device_id: "laptop".into(),
            device_epoch: 99,
        },
        MESSAGE_LAYER_FLOOR,
        1,
        issued,
        issued + 3_600,
    )?;
    let device = native
        .publication
        .record
        .body
        .devices
        .iter_mut()
        .find(|row| row.device_id == "laptop")
        .ok_or("laptop")?;
    device.message_layer = Some(wrong);
    project_layers(&mut native);
    let manifest = SdkDeviceManifestResponse::from_native(native)?;
    classify_unverified_stale(&manifest, &own.config.device_id, issued + 1, "laptop")
}

#[tokio::test]
async fn legacy_unsigned_layer_field_is_classified_stale() -> TestResult {
    let own = Fixture::new("p05-legacy").await?;
    let issued = wall_now()? + 1;
    let mut manifest = own_roster(&own, &[("laptop", issued, issued + 3_600)], issued)?;
    manifest.custody = None;
    classify_unverified_stale(&manifest, &own.config.device_id, issued + 1, "laptop")
}

#[tokio::test]
async fn attacker_branch_key_swapped_in_is_classified_stale() -> TestResult {
    let own = Fixture::new("p05-attacker-branch").await?;
    let issued = wall_now()? + 1;
    let mut native = native_of(&own_roster(&own, &[("laptop", issued, issued + 3_600)], issued)?)?;
    let attacker = ramflux_crypto::create_device_branch(
        &own.manifest.principal_id,
        "attacker",
        1,
        ramflux_crypto::random_32()?,
    );
    let device = native
        .publication
        .record
        .body
        .devices
        .iter_mut()
        .find(|row| row.device_id == "laptop")
        .ok_or("laptop")?;
    let certificate = device.branch_certificate.as_mut().ok_or("cert")?;
    certificate.body.branch_signing_public_key =
        ramflux_protocol::encode_base64url(attacker.signing_key.verifying_key().as_bytes());
    let epoch = device.device_epoch;
    device.message_layer = Some(sign_layer_raw(
        &attacker,
        DeviceRef {
            account_anchor: own.manifest.principal_commitment.clone(),
            device_id: "laptop".into(),
            device_epoch: epoch,
        },
        issued,
        issued + 3_600,
    )?);
    project_layers(&mut native);
    let manifest = SdkDeviceManifestResponse::from_native(native)?;
    classify_unverified_stale(&manifest, &own.config.device_id, issued + 1, "laptop")
}

#[tokio::test]
async fn thirty_day_declaration_observed_on_day_10_is_classified_stale() -> TestResult {
    let own = Fixture::new("p05-thirty-day").await?;
    let issued = wall_now()? + 1;
    let mut native = native_of(&own.manifest)?;
    let laptop = enroll_sibling(&own, &mut native, "laptop", issued)?;
    let thirty_days = 30 * MAX_LAYER_DECLARATION_VALIDITY_SECONDS;
    let day_10 = issued + 10 * MAX_LAYER_DECLARATION_VALIDITY_SECONDS;
    let device = native
        .publication
        .record
        .body
        .devices
        .iter_mut()
        .find(|row| row.device_id == "laptop")
        .ok_or("laptop")?;
    device.message_layer = Some(sign_layer_raw(
        &laptop,
        DeviceRef {
            account_anchor: own.manifest.principal_commitment.clone(),
            device_id: "laptop".into(),
            device_epoch: device.device_epoch,
        },
        issued,
        issued + thirty_days,
    )?);
    project_layers(&mut native);
    let manifest = SdkDeviceManifestResponse::from_native(native)?;
    classify_unverified_stale(&manifest, &own.config.device_id, day_10, "laptop")
}

#[test]
fn control_route_selects_control_kind() {
    assert_eq!(kind_id_for_route(&crate::client::routed::Kind::Control), KindId::KindControl);
    assert_eq!(kind_id_for_route(&crate::client::routed::Kind::GroupControl), KindId::KindControl);
    assert_eq!(kind_id_for_route(&crate::client::routed::Kind::Direct), KindId::KindMessage);
}
