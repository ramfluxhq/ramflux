// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Profiles cannot be substituted, omitted, equivocated or rolled back under a newer device set.
use crate::*;
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn input(epoch: u64) -> DeviceSetSigningInput {
    DeviceSetSigningInput {
        principal_kind: PrincipalKind::Human,
        device_set_epoch: epoch,
        devices: vec![SignedDeviceSetEntry {
            device_id: "phone".into(),
            device_epoch: 1,
            signing_key_commitment: ramflux_protocol::encode_base64url([3; 32]),
            agreement_key_commitment: ramflux_protocol::encode_base64url([4; 32]),
            status: DeviceSetStatus::Active,
            revoked_at: None,
        }],
    }
}
#[test]
fn public_profile_normalizes_names_and_rejects_controls_oversize_and_unsupported_kind() -> TestResult
{
    let root = create_identity_root("alice", [1; 32]);
    let profile = sign_identity_profile(&root, PrincipalKind::Human, "  Cafe\u{301}  ", 1)?;
    assert_eq!(profile.display_name, "Café");
    verify_identity_profile(&root.signing_key.verifying_key(), &profile)?;
    for name in ["", "  ", "a\nb", "a\u{202e}b", "a\u{200b}b", "name\n"] {
        assert!(sign_identity_profile(&root, PrincipalKind::Human, name, 1).is_err());
    }
    assert!(sign_identity_profile(&root, PrincipalKind::Human, &"x".repeat(129), 1).is_err());
    assert!(sign_identity_profile(&root, PrincipalKind::Workflow, "Workflow", 1).is_err());
    assert!(sign_identity_profile(&root, PrincipalKind::Bot, "Bot", 0).is_err());
    Ok(())
}
#[test]
fn forged_unsigned_wrong_root_and_noncanonical_profiles_never_verify() -> TestResult {
    let root = create_identity_root("alice", [1; 32]);
    let public = root.signing_key.verifying_key();
    let signed = sign_identity_profile(&root, PrincipalKind::Human, "Café", 1)?;
    for field in ["signature", "name", "kind", "epoch", "principal", "domain", "noncanonical"] {
        let mut bad = signed.clone();
        match field {
            "signature" => bad.signature.clear(),
            "name" => bad.display_name = "Other".into(),
            "kind" => bad.kind = PrincipalKind::Bot,
            "epoch" => bad.epoch = 2,
            "principal" => bad.principal_id = "bob".into(),
            "domain" => bad.domain = "other".into(),
            _ => bad.display_name = "Cafe\u{301}".into(),
        }
        assert!(verify_identity_profile(&public, &bad).is_err(), "{field}");
    }
    assert!(
        verify_identity_profile(
            &create_identity_root("mallory", [2; 32]).signing_key.verifying_key(),
            &signed
        )
        .is_err()
    );
    let other = create_identity_root("alice", [2; 32]);
    let other_profile = sign_identity_profile(&other, PrincipalKind::Human, "Café", 1)?;
    assert!(sign_device_set_with_profile(&root, input(1), Some(other_profile)).is_err());
    Ok(())
}
#[test]
fn newer_device_set_cannot_replay_erase_or_equivocate_a_verified_profile() -> TestResult {
    let root = create_identity_root("alice", [1; 32]);
    let public = root.signing_key.verifying_key();
    let legacy = sign_device_set(&root, input(1))?;
    let profile = sign_identity_profile(&root, PrincipalKind::Human, "Alice", 2)?;
    let published = sign_device_set_with_profile(&root, input(2), Some(profile.clone()))?;
    verify_signed_device_set(&public, &published)?;
    validate_device_set_transition(&legacy, &published)?;
    let same = sign_device_set_with_profile(&root, input(3), Some(profile))?;
    validate_device_set_transition(&published, &same)?;
    for next in [
        sign_device_set(&root, input(4))?,
        sign_device_set_with_profile(
            &root,
            input(4),
            Some(sign_identity_profile(&root, PrincipalKind::Human, "Old", 1)?),
        )?,
        sign_device_set_with_profile(
            &root,
            input(4),
            Some(sign_identity_profile(&root, PrincipalKind::Human, "Other", 2)?),
        )?,
    ] {
        verify_signed_device_set(&public, &next)?;
        assert!(validate_device_set_transition(&published, &next).is_err());
    }
    let newer = sign_device_set_with_profile(
        &root,
        input(4),
        Some(sign_identity_profile(&root, PrincipalKind::Human, "New", 3)?),
    )?;
    validate_device_set_transition(&same, &newer)?;
    let mut substituted = newer.clone();
    substituted.profile = published.profile;
    assert!(verify_signed_device_set(&public, &substituted).is_err());
    Ok(())
}

#[test]
fn validly_signed_profile_with_a_different_set_kind_is_rejected() -> TestResult {
    let root = create_identity_root("alice", [1; 32]);
    let public = root.signing_key.verifying_key();
    let profile = sign_identity_profile(&root, PrincipalKind::Bot, "Alice", 1)?;
    verify_identity_profile(&public, &profile)?;
    let mut bot_input = input(1);
    bot_input.principal_kind = PrincipalKind::Bot;
    let mut record = sign_device_set_with_profile(&root, bot_input, Some(profile))?;
    record.principal_kind = PrincipalKind::Human;
    let bytes = ramflux_protocol::signed_device_set_signing_bytes(&record)?;
    record.signature = sign_canonical_bytes_with_seed(&bytes, root.signing_key.to_bytes());
    verify_canonical_signature(
        &bytes,
        &record.signature,
        &ramflux_protocol::encode_base64url(public.to_bytes()),
    )?;
    assert!(matches!(
        verify_signed_device_set(&public, &record),
        Err(CryptoError::IdentityAuthority("profile and device-set owner or kind mismatch"))
    ));
    Ok(())
}
