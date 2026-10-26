// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public kind comes from verified root profiles, never card labels or cached boolean flags.
use super::*;

#[test]
fn signed_authority_change_marks_manual_verification_stale_without_changing_active_device_hash()
-> TestResult {
    let owner = Actor::new("owner", "phone", 231, 232, 1)?;
    let late = Actor::new("owner", "unready", 231, 233, 1)?;
    let peer = Actor::new("peer", "peer", 234, 235, 1)?;
    let signed = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    observe(&peer.client, &signed)?;
    let own = peer.manifest()?;
    observe(&peer.client, &own)?;
    peer.client.establish_friend_link(
        "contact",
        &own.principal_commitment,
        &signed.principal_commitment,
    )?;
    let db = peer.client.account_db()?;
    let before = db.client_record("identity", "owner")?.ok_or("row")?;
    let hash = before["device_set_hash"].as_str().ok_or("hash")?;
    db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
        contact_identity_commitment: &signed.principal_commitment,
        safety_number_hash: "verified-safety",
        device_set_hash: hash,
        lineage_head: "lineage",
        verified_at: crate::time::now_unix_timestamp(),
        verified_by_device_id: "peer",
    })?;
    db.persist_actor_state(
        &format!("identity/safety_verified_set/{}", signed.principal_commitment),
        &set_fingerprint(signed.signed_device_set.as_ref().ok_or("set")?)?,
    )?;
    assert_eq!(
        crate::bus::read_model::row(&peer.client, "identity", "owner")?["safety_state"],
        "verified"
    );
    assert_eq!(
        peer.client.contact_safety_number(&signed.principal_commitment)?.verification_state,
        "verified"
    );
    let stamp_key = format!("identity/safety_verified_set/{}", signed.principal_commitment);
    let stamp = db.load_actor_state::<String>(&stamp_key)?.ok_or("stamp")?;
    db.remove_actor_state(&stamp_key)?;
    assert_eq!(
        peer.client.contact_safety_number(&signed.principal_commitment)?.verification_state,
        "verified"
    );
    assert_eq!(
        db.load_actor_state::<String>(&stamp_key)?,
        Some(stamp.clone()),
        "a missing legacy stamp is baselined on first matching read"
    );
    let next = with_revoked_device(&owner, &signed, &late)?;
    observe(&peer.client, &next)?;
    let row = crate::bus::read_model::row(&peer.client, "identity", "owner")?;
    assert_eq!(
        row["device_set_hash"], before["device_set_hash"],
        "a tombstone changes authority but not active safety material"
    );
    assert!(peer.client.verified_principal_kind("owner")?.is_none());
    assert_eq!(db.load_actor_state::<String>(&stamp_key)?, Some(stamp));
    assert_eq!(row["verified"], false, "a stale complete-set stamp also reaches contact flags");
    assert_eq!(row["kind_verified"], true, "the public profile remains authenticated");
    assert_eq!(
        row["safety_state"], "verification_stale",
        "manual verification covers the complete signed set"
    );
    assert_eq!(
        peer.client.contact_safety_number(&signed.principal_commitment)?.verification_state,
        "verification_stale"
    );
    assert_eq!(
        peer.client
            .contact_verification_status(&signed.principal_commitment)?
            .ok_or("stored")?
            .verification_state,
        "verified",
        "stored verification is audit history, not current authority"
    );
    peer.client.mark_contact_safety_verified(&signed.principal_commitment, "peer")?;
    assert_eq!(
        peer.client.contact_safety_number(&signed.principal_commitment)?.verification_state,
        "verified"
    );
    assert_eq!(
        crate::bus::read_model::row(&peer.client, "identity", "owner")?["safety_state"],
        "verified"
    );
    Ok(())
}
fn with_revoked_device(
    owner: &Actor,
    signed: &SdkDeviceManifestResponse,
    late: &Actor,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let mut next = signed.clone();
    let old = next.signed_device_set.take().ok_or_else(|| invalid("fixture set"))?;
    let mut devices = old.devices;
    let mut retired =
        late.manifest()?.signed_device_set.ok_or_else(|| invalid("fixture retired set"))?.devices;
    for device in &mut retired {
        device.status = ramflux_protocol::DeviceSetStatus::Revoked;
        device.revoked_at = Some(crate::time::now_unix_timestamp());
    }
    devices.extend(retired);
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    next.signed_device_set = Some(ramflux_crypto::sign_device_set_with_profile(
        owner.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: old.principal_kind,
            device_set_epoch: 2,
            devices,
        },
        old.profile.map(|p| *p),
    )?);
    Ok(next)
}
fn with_profile(
    owner: &Actor,
    mut manifest: SdkDeviceManifestResponse,
    name: &str,
    profile_epoch: u64,
    set_epoch: u64,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let root = owner.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let old = manifest.signed_device_set.take().ok_or_else(|| invalid("fixture set"))?;
    let profile =
        ramflux_crypto::sign_identity_profile(root, old.principal_kind, name, profile_epoch)?;
    manifest.signed_device_set = Some(ramflux_crypto::sign_device_set_with_profile(
        root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: old.principal_kind,
            device_set_epoch: set_epoch,
            devices: old.devices,
        },
        Some(profile),
    )?);
    Ok(manifest)
}
#[test]
fn lookup_exposes_verified_kind_and_normalized_public_name_without_manual_contact_verification()
-> TestResult {
    let owner = Actor::new("agent", "agent-device", 131, 132, 1)?;
    mode(&owner, PrincipalKind::HeadlessAi, LocalBusClientMode::HeadlessAi)?;
    let peer = Actor::new("bob", "bob", 141, 142, 1)?;
    let signed = with_profile(&owner, owner.manifest()?, "Cafe\u{301} Agent", 1, 1)?;
    observe(&peer.client, &signed)?;
    let row = crate::bus::read_model::row(&peer.client, "identity", "agent")?;
    assert_eq!(row["kind"], "headless_ai");
    assert_eq!(row["kind_verified"], true);
    assert_eq!(row["kind_asserted"], "headless_ai");
    assert_eq!(row["display_name"], "Café Agent");
    assert_eq!(row["safety_state"], "unverified");
    let contact = peer.client.contact_entry("agent")?;
    assert_eq!(contact["kind_asserted"], "headless_ai");
    assert_eq!(contact["display_name"], "Café Agent");
    assert_eq!(contact["kind_verified"], true);
    assert_eq!(contact["verified"], false);
    assert!(crate::client::task::actor_kind_verified(&peer.client, "agent", "agent-device"));
    assert!(!crate::client::task::actor_role_kind_verified(
        &peer.client,
        "agent",
        "agent-device",
        ramflux_protocol::ActorType::Human
    ));
    assert!(crate::client::task::actor_role_kind_verified(
        &peer.client,
        "agent",
        "agent-device",
        ramflux_protocol::ActorType::Bot
    ));
    assert!(!crate::client::task::actor_kind_verified(&peer.client, "agent", "bob"));
    assert!(!crate::client::task::actor_kind_verified(&peer.client, "unknown", "agent-device"));
    Ok(())
}
#[test]
fn unsigned_legacy_and_spoofed_cached_kind_never_become_verified() -> TestResult {
    let owner = Actor::new("alice", "alice", 151, 152, 1)?;
    let peer = Actor::new("bob", "bob", 161, 162, 1)?;
    let legacy = owner.manifest()?;
    observe(&peer.client, &legacy)?;
    let db = peer.client.account_db()?;
    let mut row = db.client_record("identity", "alice")?.ok_or("row")?;
    row["kind_verified"] = serde_json::json!(true);
    row["kind"] = serde_json::json!("bot");
    db.persist_client_record("identity", "alice", &row)?;
    assert_eq!(
        crate::bus::read_model::row(&peer.client, "identity", "alice")?["kind_verified"],
        false
    );
    assert!(!crate::client::task::actor_kind_verified(&peer.client, "alice", "alice"));
    let mut unsigned = with_profile(&owner, legacy.clone(), "Alice", 1, 2)?;
    unsigned
        .signed_device_set
        .as_mut()
        .ok_or("set")?
        .profile
        .as_mut()
        .ok_or("profile")?
        .signature
        .clear();
    assert!(observe(&peer.client, &unsigned).is_err());
    let mut forged = with_profile(&owner, legacy, "Alice", 1, 2)?;
    forged.signed_device_set.as_mut().ok_or("set")?.profile.as_mut().ok_or("profile")?.kind =
        PrincipalKind::Bot;
    assert!(observe(&peer.client, &forged).is_err());
    assert!(peer.client.verified_identity_profile("alice")?.is_none());
    Ok(())
}
#[test]
fn profile_epoch_floor_survives_restart_and_rejects_new_device_sets_with_old_profiles() -> TestResult
{
    let owner = Actor::new("alice", "alice", 171, 172, 1)?;
    let mut peer = Actor::new("bob", "bob", 181, 182, 1)?;
    let legacy = owner.manifest()?;
    let current = with_profile(&owner, legacy.clone(), "Current", 2, 2)?;
    observe(&peer.client, &current)?;
    peer.reopen()?;
    for bad in [
        with_profile(&owner, legacy.clone(), "Old", 1, 3)?,
        with_profile(&owner, legacy.clone(), "Equivocation", 2, 3)?,
    ] {
        assert!(observe(&peer.client, &bad).is_err());
    }
    let mut omitted = legacy;
    sign_set(&owner, &mut omitted, 4)?;
    assert!(observe(&peer.client, &omitted).is_err());
    assert_eq!(
        peer.client.verified_identity_profile("alice")?.ok_or("profile")?.display_name,
        "Current"
    );
    Ok(())
}
#[test]
fn public_profile_is_published_by_the_device_set_signer_and_survives_device_set_changes()
-> TestResult {
    let owner = Actor::new("alice", "alice-phone", 191, 192, 1)?;
    let second = Actor::new("alice", "alice-laptop", 191, 193, 1)?;
    let peer = Actor::new("bob", "bob", 201, 202, 1)?;
    owner.client.set_identity_display_name("Public Alice")?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    let first = enroll(&mut node, &owner, None)?;
    let added = enroll(&mut node, &second, Some(&first))?;
    observe(&peer.client, &added)?;
    assert_eq!(
        peer.client.verified_identity_profile("alice")?.ok_or("profile")?.display_name,
        "Public Alice"
    );
    assert_eq!(
        added.signed_device_set.as_ref().ok_or("set")?.profile,
        first.signed_device_set.as_ref().ok_or("set")?.profile
    );
    owner.client.set_identity_display_name("New Public Alice")?;
    let updated = enroll(&mut node, &owner, Some(&added))?;
    observe(&peer.client, &updated)?;
    assert_eq!(
        peer.client.verified_identity_profile("alice")?.ok_or("profile")?.display_name,
        "New Public Alice"
    );
    let mut cold = RamfluxClient::new();
    cold.open_account_index(&owner.path)?;
    cold.unlock_account(&owner.id, b"test-secret")?;
    assert!(cold.identity_root.is_none(), "read-model profile verification needs no root secret");
    assert_eq!(
        cold.verified_identity_profile("alice")?.ok_or("cold profile")?.display_name,
        "New Public Alice"
    );
    Ok(())
}

#[test]
fn a_valid_long_principal_remains_publishable_with_a_bounded_safe_default_name() -> TestResult {
    let principal = "a".repeat(200);
    let owner = Actor::new(&principal, "phone", 211, 212, 1)?;
    let set = owner.client.prepare_owned_authority(None)?;
    let profile = set.profile.as_ref().ok_or("profile")?;
    assert_eq!(profile.display_name, "Account");
    ramflux_crypto::verify_signed_device_set(
        &owner.client.identity_root.as_ref().ok_or("root")?.signing_key.verifying_key(),
        &set,
    )?;
    Ok(())
}

#[test]
fn profile_manifest_requires_root_authentication_and_unique_authorized_devices() -> TestResult {
    let phone = Actor::new("alice", "phone", 221, 222, 1)?;
    let laptop = Actor::new("alice", "laptop", 221, 223, 1)?;
    let foreign = Actor::new("mallory", "phone", 231, 232, 1)?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    let first = enroll(&mut node, &phone, None)?;
    let full = enroll(&mut node, &laptop, Some(&first))?;
    verify_manifest(&full, &full.principal_commitment)?;
    let mut duplicate = full.clone();
    duplicate.devices.push(duplicate.devices[0].clone());
    assert!(verify_manifest(&duplicate, &full.principal_commitment).is_err());
    let mut unsigned_empty = full.clone();
    unsigned_empty.devices.clear();
    unsigned_empty.signed_device_set.as_mut().ok_or("set")?.signature.clear();
    assert!(verify_manifest(&unsigned_empty, &full.principal_commitment).is_err());
    let mut unbound = full.clone();
    unbound.devices[0] = foreign.manifest()?.devices.remove(0);
    unbound.devices[0].principal_id.clone_from(&full.principal_id);
    unbound.devices[0].principal_commitment.clone_from(&full.principal_commitment);
    unbound.devices[0].branch_proof.principal_id.clone_from(&full.principal_id);
    assert!(verify_manifest(&unbound, &full.principal_commitment).is_err());
    Ok(())
}

#[path = "profile_read_tests.rs"]
mod read_tests;

#[path = "profile_restore_tests.rs"]
mod restore_tests;

#[path = "verification_migration_tests.rs"]
mod verification_migration;
