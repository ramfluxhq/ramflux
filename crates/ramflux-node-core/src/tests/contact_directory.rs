// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Principal directory admission must not choose between conflicting active roots.
use super::*;
fn register(
    registry: &mut IdentityRegistry,
    device: &str,
    nonce: u64,
) -> Result<IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let request = registration_request("alice", device, nonce, None, "test-source")?;
    registry.register_identity(&request)?;
    let branch =
        ramflux_crypto::create_device_branch("alice", device, 1, seed_from_nonce(0x41, nonce));
    let key = ramflux_crypto::X25519KeyPair::from_seed([71; 32]);
    let prekey = ramflux_crypto::X25519KeyPair::from_seed([72; 32]);
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: device.into(),
        bundle: ramflux_crypto::create_prekey_bundle(&branch, &key, "prekey", &prekey, None, None)?,
    })?;
    Ok(request)
}
#[test]
fn principal_lookup_returns_only_one_active_root_and_never_a_revoked_or_ambiguous_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = IdentityRegistry::default();
    assert!(registry.principal_manifest("alice").is_none());
    let first = register(&mut registry, "alice-one", 1)?;
    let found = registry.principal_manifest("alice").ok_or("missing active identity")?;
    assert_eq!(found.principal_commitment, first.principal_commitment);
    assert_eq!(found.devices[0].device_id, "alice-one");
    // Exercise a legacy snapshot with conflicting registrations, without admitting
    // a conflicting root through the current registration boundary.
    let mut other = IdentityRegistry::default();
    let second = register(&mut other, "alice-two", 2)?;
    let mut saved = serde_json::to_value(&registry)?;
    let old = serde_json::to_value(other)?;
    for field in ["devices", "root_public_keys_by_commitment", "prekey_bundles"] {
        if let Some(map) = old[field].as_object() {
            saved[field].as_object_mut().ok_or("registry map missing")?.extend(map.clone());
        }
    }
    registry = serde_json::from_value(saved)?;
    assert!(
        registry.principal_manifest("alice").is_none(),
        "conflicting active roots must not be selected by map order"
    );
    for (request, nonce) in [(second, 2), (first, 1)] {
        let revoked_at = request.now + 1;
        let body = serde_json::json!({"device_id":request.proof.device_id,"principal_commitment":request.principal_commitment,"revoked_at":revoked_at});
        let root = ramflux_crypto::create_identity_root("alice", seed_from_nonce(0x31, nonce));
        registry.revoke_device(&DeviceRevokeRequest {
            device_id: request.proof.device_id,
            principal_commitment: request.principal_commitment,
            root_public_key: request.root_public_key,
            revoked_at,
            signature: ramflux_crypto::sign_canonical_bytes_with_seed(
                &ramflux_protocol::canonical_json_bytes(&body)?,
                root.signing_key.to_bytes(),
            ),
        })?;
        if nonce == 2 {
            assert_eq!(
                registry
                    .principal_manifest("alice")
                    .ok_or("remaining identity missing")?
                    .devices
                    .len(),
                1
            );
        }
    }
    assert!(registry.principal_manifest("alice").is_none());
    Ok(())
}

#[test]
fn a_second_root_cannot_take_a_registered_name_even_after_every_device_is_revoked()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = IdentityRegistry::default();
    let first = register(&mut registry, "alice-one", 1)?;
    let takeover = registration_request("alice", "mallory", 2, None, "other-source")?;
    assert!(matches!(registry.register_identity(&takeover), Err(NodeCoreError::PrincipalIdTaken)));
    assert_eq!(
        registry.principal_manifest("alice").ok_or("original lookup lost")?.principal_commitment,
        first.principal_commitment
    );
    let revoked_at = first.now + 1;
    let body = serde_json::json!({"device_id":first.proof.device_id,"principal_commitment":first.principal_commitment,"revoked_at":revoked_at});
    registry.revoke_device(&DeviceRevokeRequest {
        device_id: first.proof.device_id,
        principal_commitment: first.principal_commitment,
        root_public_key: first.root_public_key,
        revoked_at,
        signature: ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::canonical_json_bytes(&body)?,
            seed_from_nonce(0x31, 1),
        ),
    })?;
    assert!(registry.principal_manifest("alice").is_none());
    let mut restored: IdentityRegistry = serde_json::from_slice(&serde_json::to_vec(&registry)?)?;
    assert!(matches!(restored.register_identity(&takeover), Err(NodeCoreError::PrincipalIdTaken)));
    // Legacy snapshots lack the reservation table; metadata purge must migrate
    // the original binding before removing active directory records.
    let mut legacy = serde_json::to_value(&restored)?;
    legacy.as_object_mut().ok_or("legacy registry")?.remove("principal_root_bindings");
    let mut restored: IdentityRegistry = serde_json::from_value(legacy)?;
    restored.remove_principal_metadata("alice");
    let mut restored: IdentityRegistry = serde_json::from_slice(&serde_json::to_vec(&restored)?)?;
    assert!(matches!(restored.register_identity(&takeover), Err(NodeCoreError::PrincipalIdTaken)));
    Ok(())
}

#[test]
fn principal_lookup_authenticates_before_lookup_and_shares_quotas_across_an_accounts_devices()
-> Result<(), Box<dyn std::error::Error>> {
    use ramflux_protocol::IdentityDirectoryReason as Reason;
    let router = RouterCore::new();
    let registration = registration_request("alice", "alice-one", 1, None, "test-source")?;
    let reply = router.mvp1_register_identity(&registration)?;
    let mut query = crate::PrincipalLookupRequest {
        principal_id: "alice".into(),
        session_id: "forged".into(),
        requester_device_id: "alice-one".into(),
        target_delivery_id: reply.target_delivery_id,
        gateway_id: registration.gateway_id.clone(),
        source: "127.0.0.1".parse()?,
    };
    let denied = router.mvp1_authenticated_principal_lookup(&query, 100);
    assert_eq!(denied.reason_code, Some(Reason::AuthenticationRequired));
    query.principal_id = "missing".into();
    assert_eq!(router.mvp1_authenticated_principal_lookup(&query, 100), denied);
    let current = router.session(&query.target_delivery_id).ok_or("session")?;
    query.session_id = current.session_id;
    // Register a second device with the same root using a fresh root-signed proof.
    let mut second = registration_request("alice", "alice-two", 2, None, "test-source")?;
    let root = ramflux_crypto::create_identity_root("alice", seed_from_nonce(0x31, 1));
    let branch =
        ramflux_crypto::create_device_branch("alice", "alice-two", 1, seed_from_nonce(0x41, 2));
    second.root_public_key = registration.root_public_key.clone();
    second.principal_commitment = registration.principal_commitment.clone();
    second.proof = ramflux_crypto::authorize_device_branch(
        &root,
        &branch,
        IDENTITY_BIND_AUDIENCE,
        vec![IDENTITY_BIND_CAPABILITY.to_owned()],
        second.now - 1,
        second.now + 60,
    )?;
    second.target_delivery_id = "target_alice-two".into();
    second.session_id = "session_alice-two".into();
    let second_reply = router.mvp1_register_identity(&second)?;
    let branch =
        ramflux_crypto::create_device_branch("alice", "alice-one", 1, seed_from_nonce(0x41, 1));
    let identity = ramflux_crypto::X25519KeyPair::from_seed([71; 32]);
    let prekey = ramflux_crypto::X25519KeyPair::from_seed([72; 32]);
    router.mvp1_publish_prekey(PrekeyPublishRequest {
        device_id: "alice-one".into(),
        bundle: ramflux_crypto::create_prekey_bundle(
            &branch, &identity, "prekey", &prekey, None, None,
        )?,
    })?;
    query.principal_id = "alice".into();
    let known = router.mvp1_authenticated_principal_lookup(&query, 100);
    assert!(known.manifest.is_some());
    assert_eq!(known.reason_code, None);
    query.principal_id = "missing".into();
    let unknown = router.mvp1_authenticated_principal_lookup(&query, 100);
    assert!(unknown.manifest.is_none());
    assert_eq!(unknown.reason_code, None);
    assert_eq!(
        serde_json::to_value(known)?.as_object().ok_or("known shape")?.keys().collect::<Vec<_>>(),
        serde_json::to_value(unknown)?
            .as_object()
            .ok_or("unknown shape")?
            .keys()
            .collect::<Vec<_>>()
    );
    for _ in 0..58 {
        assert_eq!(router.mvp1_authenticated_principal_lookup(&query, 100).reason_code, None);
    }
    query.target_delivery_id = second_reply.target_delivery_id;
    query.requester_device_id = "alice-two".into();
    query.session_id =
        router.session(&query.target_delivery_id).ok_or("second session")?.session_id;
    assert_eq!(
        router.mvp1_authenticated_principal_lookup(&query, 100).reason_code,
        Some(Reason::RateLimited)
    );
    assert_eq!(router.mvp1_authenticated_principal_lookup(&query, 160).reason_code, None);
    Ok(())
}

#[test]
fn a_foreign_root_cannot_take_a_device_or_delivery_alias_and_revoke_its_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = IdentityRegistry::default();
    let alice = register(&mut registry, "alice-one", 1)?;
    let mallory = registration_request("mallory", "mallory-one", 2, None, "attacker")?;
    registry.register_identity(&mallory)?;
    let takeover = registration_request("mallory-two", "alice-one", 3, None, "attacker")?;
    assert!(matches!(registry.register_identity(&takeover), Err(NodeCoreError::DeviceIdTaken)));
    let mut alias = mallory.clone();
    alias.target_delivery_id = alice.target_delivery_id.clone();
    assert!(matches!(registry.register_identity(&alias), Err(NodeCoreError::DeviceIdTaken)));
    let body = serde_json::json!({"device_id":"alice-one","principal_commitment":mallory.principal_commitment,"revoked_at":mallory.now});
    let revoke = DeviceRevokeRequest {
        device_id: "alice-one".into(),
        principal_commitment: mallory.principal_commitment.clone(),
        root_public_key: mallory.root_public_key.clone(),
        revoked_at: mallory.now,
        signature: ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::canonical_json_bytes(&body)?,
            seed_from_nonce(0x31, 2),
        ),
    };
    assert!(registry.revoke_device(&revoke).is_err());
    assert_eq!(
        registry.principal_manifest("alice").ok_or("alice missing")?.principal_commitment,
        alice.principal_commitment
    );
    let mut again = alice.clone();
    let root = ramflux_crypto::create_identity_root("alice", seed_from_nonce(0x31, 1));
    let device =
        ramflux_crypto::create_device_branch("alice", "alice-one", 2, seed_from_nonce(0x41, 9));
    again.branch_public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    again.proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        IDENTITY_BIND_AUDIENCE,
        vec![IDENTITY_BIND_CAPABILITY.into()],
        alice.now,
        alice.now + 3600,
    )?;
    registry.register_identity(&again)?;
    let mut legacy = serde_json::to_value(&registry)?;
    legacy.as_object_mut().ok_or("registry")?.remove("device_root_bindings");
    legacy.as_object_mut().ok_or("registry")?.remove("delivery_root_bindings");
    let mut restored: IdentityRegistry = serde_json::from_value(legacy)?;
    restored.remove_principal_metadata("alice");
    assert!(matches!(restored.register_identity(&takeover), Err(NodeCoreError::DeviceIdTaken)));
    Ok(())
}

#[test]
fn every_taken_name_probe_is_charged_before_the_name_check_and_pow_precedes_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = IdentityRegistry::default();
    register(&mut registry, "alice-one", 1)?;
    registry.set_registration_policy(RegistrationPolicy {
        per_source_ip_registration_limit: 2,
        ..RegistrationPolicy::default()
    });
    let probe = registration_request("alice", "other", 2, None, "attacker")?;
    let mut taken = 0;
    for _ in 0..15 {
        if matches!(registry.register_identity(&probe), Err(NodeCoreError::PrincipalIdTaken)) {
            taken += 1;
        }
    }
    assert_eq!(taken, 2);
    assert!(
        registry
            .register_identity(&registration_request("fresh", "fresh", 3, None, "attacker")?)
            .is_err()
    );
    registry.set_registration_policy(RegistrationPolicy {
        challenge_policy: RegistrationChallengePolicy::Pow,
        pow_difficulty_bits: 1,
        ..RegistrationPolicy::default()
    });
    assert!(!matches!(registry.register_identity(&probe), Err(NodeCoreError::PrincipalIdTaken)));
    assert!(RegistrationPolicy::default().per_source_ip_registration_limit < u32::MAX);
    Ok(())
}

#[test]
fn failed_registration_source_tables_are_bounded_and_ipv6_sources_share_a_prefix_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = IdentityRegistry::default();
    let mut request = registration_request("probe", "probe", 1, None, "source")?;
    request.root_public_key = String::new();
    for i in 0..4100 {
        request.source_ip_hash = Some(format!("source-{i}"));
        assert!(registry.register_identity(&request).is_err());
    }
    let state = serde_json::to_value(&registry)?;
    assert!(state["registration_times_by_source_ip"].as_object().ok_or("sources")?.len() <= 4096);
    assert_eq!(
        crate::source_ip_hash("2001:db8:1:2::1"),
        crate::source_ip_hash("2001:db8:1:2::ffff")
    );
    assert_ne!(crate::source_ip_hash("2001:db8:1:2::1"), crate::source_ip_hash("2001:db8:1:3::1"));
    Ok(())
}

#[test]
fn legacy_devices_are_owned_by_their_signed_root_even_when_a_principal_name_is_ambiguous()
-> Result<(), Box<dyn std::error::Error>> {
    let mut first = IdentityRegistry::default();
    let alice = register(&mut first, "alice-one", 1)?;
    let mut second = IdentityRegistry::default();
    register(&mut second, "alice-two", 2)?;
    let mut snapshot = serde_json::to_value(&first)?;
    let other = serde_json::to_value(&second)?;
    for field in ["devices", "root_public_keys_by_commitment", "prekey_bundles"] {
        snapshot[field]
            .as_object_mut()
            .ok_or("snapshot")?
            .extend(other[field].as_object().ok_or("other")?.clone());
    }
    let mut registry: IdentityRegistry = serde_json::from_value(snapshot)?;
    let root = ramflux_crypto::create_identity_root("alice", seed_from_nonce(0x31, 1));
    let device = ramflux_crypto::create_device_branch("alice", "alice-two", 2, [98; 32]);
    let mut claim = alice.clone();
    claim.target_delivery_id = "new-alias".into();
    claim.branch_public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    claim.proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        IDENTITY_BIND_AUDIENCE,
        vec![IDENTITY_BIND_CAPABILITY.into()],
        claim.now,
        claim.now + 3600,
    )?;
    assert!(matches!(registry.register_identity(&claim), Err(NodeCoreError::DeviceIdTaken)));
    registry.remove_principal_metadata("alice");
    assert!(matches!(registry.register_identity(&claim), Err(NodeCoreError::DeviceIdTaken)));
    Ok(())
}
