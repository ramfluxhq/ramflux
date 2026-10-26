// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public kind comes from verified root profiles, never card labels or cached boolean flags.
use super::*;
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
