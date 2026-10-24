// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group membership selects roots from signed controls and invite provenance, never directory names.
use super::*;
fn legacy_join(
    author: &Actor,
    event: &ramflux_protocol::GroupEvent,
) -> Result<ramflux_protocol::GroupEvent, SdkError> {
    let mut event = event.clone();
    event.schema = "ramflux.client_event.v1".into();
    event.version = 1;
    event.ext.ext.remove(ramflux_protocol::GROUP_DEVICE_ROOTS_EXTENSION);
    event.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        author.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &event,
    )?;
    Ok(event)
}
#[test]
fn copied_name_cannot_pin_first_claimer_and_signed_member_root_chooses_bob() -> TestResult {
    let alice = Actor::new("alice", "alice", 21, 22, 1)?;
    let bob = Actor::new("bob", "shared", 31, 32, 1)?;
    let mallory = Actor::new("mallory", "shared", 41, 42, 1)?;
    let observer = Actor::new("carol", "carol", 51, 52, 1)?;
    let a = alice.manifest()?;
    let b = bob.manifest()?;
    let m = mallory.manifest()?;
    observe(&alice.client, &m)?;
    assert_eq!(alice.client.device_reference("shared")?, "shared");
    assert!(alice.client.require_cached_root_authority("shared").is_err());

    alice.client.create_group("g", "alice")?;
    assert!(matches!(
        alice.client.add_group_member("g", "shared", "member"),
        Err(SdkError::InboundPending(_))
    ));
    assert!(!alice.client.group_state("g")?.members.contains("shared"));
    observe(&alice.client, &b)?;
    alice.client.add_group_member_with_root("g", "shared", "member", &b.principal_commitment)?;
    let event = alice.client.create_signed_group_member_join_event(
        "g",
        "alice",
        "shared",
        "member",
        &a.principal_commitment,
    )?;
    let roots = ramflux_protocol::GroupDeviceRoots::from_event(&event)?.ok_or("signed roots")?;
    assert_eq!(roots.member_principal_commitment.as_deref(), Some(b.principal_commitment.as_str()));
    for manifest in [&a, &m] {
        observe(&observer.client, manifest)?;
    }
    observer.client.create_group(
        "g",
        &ramflux_protocol::qualified_device_id(&a.principal_commitment, "alice")?,
    )?;
    assert!(matches!(
        observer.client.apply_group_control_event(&legacy_join(&alice, &event)?),
        Err(SdkError::InboundPending(_))
    ));
    assert!(matches!(
        observer.client.apply_group_control_event(&event),
        Err(SdkError::InboundPending(_))
    ));
    assert_eq!(observer.client.group_state("g")?.group_epoch, 1);
    observe(&observer.client, &b)?;
    observer.client.apply_group_control_event(&event)?;
    assert_eq!(
        observer.client.group_device_reference("g", "shared")?,
        ramflux_protocol::qualified_device_id(&b.principal_commitment, "shared")?
    );
    observer.client.require_group_sender_pin("g", "bob", "shared")?;
    assert!(observer.client.require_group_sender_pin("g", "mallory", "shared").is_err());
    let before = observer.client.group_state("g")?;
    let mut forged = event.clone();
    forged.ext.ext.get_mut(ramflux_protocol::GROUP_DEVICE_ROOTS_EXTENSION).ok_or("roots")?["member_principal_commitment"] =
        serde_json::json!(m.principal_commitment);
    assert!(observer.client.apply_group_control_event(&forged).is_err());
    assert_eq!(observer.client.group_state("g")?, before);
    Ok(())
}
#[test]
fn legacy_join_uses_its_groups_invite_root_and_ambiguous_invites_wait_for_v2() -> TestResult {
    let alice = Actor::new("alice", "alice", 61, 62, 1)?;
    let bob = Actor::new("bob", "shared", 71, 72, 1)?;
    let mallory = Actor::new("mallory", "shared", 81, 82, 1)?;
    let observer = Actor::new("carol", "carol", 91, 92, 1)?;
    let a = alice.manifest()?;
    let b = bob.manifest()?;
    let m = mallory.manifest()?;
    for manifest in [&b, &m] {
        observe(&alice.client, manifest)?;
    }
    for manifest in [&a, &b, &m] {
        observe(&observer.client, manifest)?;
    }
    alice.client.create_group("g", "alice")?;
    observer.client.create_group(
        "g",
        &ramflux_protocol::qualified_device_id(&a.principal_commitment, "alice")?,
    )?;
    let b_ref = ramflux_protocol::qualified_device_id(&b.principal_commitment, "shared")?;
    let m_ref = ramflux_protocol::qualified_device_id(&m.principal_commitment, "shared")?;
    let (invite, _) = alice.client.create_signed_group_member_invite(
        "g",
        "alice",
        &b_ref,
        &b.devices[0].branch_public_key,
        "member",
        now_unix_timestamp() + 600,
        "test",
    )?;
    observer.client.apply_group_control_event(&invite)?;
    alice.client.add_group_member_with_root("g", "shared", "member", &b.principal_commitment)?;
    let joined = alice.client.create_signed_group_member_join_event(
        "g",
        "alice",
        "shared",
        "member",
        &a.principal_commitment,
    )?;
    observer.client.apply_group_control_event(&legacy_join(&alice, &joined)?)?;
    observer.client.require_group_sender_pin("g", "bob", "shared")?;
    // A second group demonstrates that conflicting invite roots never select the last directory row.
    alice.client.create_group("h", "alice")?;
    observer.client.create_group(
        "h",
        &ramflux_protocol::qualified_device_id(&a.principal_commitment, "alice")?,
    )?;
    for (reference, manifest) in [(&b_ref, &b), (&m_ref, &m)] {
        let (invite, _) = alice.client.create_signed_group_member_invite(
            "h",
            "alice",
            reference,
            &manifest.devices[0].branch_public_key,
            "member",
            now_unix_timestamp() + 600,
            "test",
        )?;
        observer.client.apply_group_control_event(&invite)?;
    }
    alice.client.add_group_member_with_root("h", "shared", "member", &b.principal_commitment)?;
    let joined = alice.client.create_signed_group_member_join_event(
        "h",
        "alice",
        "shared",
        "member",
        &a.principal_commitment,
    )?;
    assert!(matches!(
        observer.client.apply_group_control_event(&legacy_join(&alice, &joined)?),
        Err(SdkError::InboundPending(_))
    ));
    assert_eq!(observer.client.group_state("h")?.group_epoch, 1);
    observer.client.apply_group_control_event(&joined)?;
    observer.client.require_group_sender_pin("h", "bob", "shared")?;
    Ok(())
}
