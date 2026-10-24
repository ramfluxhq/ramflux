// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Principal directory admission must not choose between conflicting active roots.
use super::*;
fn registration_request(
    principal: &str,
    device: &str,
    nonce: u64,
    pow: Option<RegistrationPowProof>,
    source: &str,
) -> Result<IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let mut request =
        super::registration_request(&RouterCore::new(), principal, device, nonce, pow, source)?;
    let root = ramflux_crypto::create_identity_root(principal, seed_from_nonce(0x31, nonce));
    let branch =
        ramflux_crypto::create_device_branch(principal, device, 1, seed_from_nonce(0x41, nonce));
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(seed_from_nonce(0x51, nonce));
    request.root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    request.principal_commitment =
        ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
    request.proof = ramflux_crypto::authorize_device_branch_v2(
        &root,
        &branch,
        ramflux_crypto::BranchAuthorization {
            audience: IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
            issued_at: request.now - 1,
            expires_at: request.now + 3600,
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            agreement_identity_public_key: agreement.public,
        },
    )?;
    let mut entries = request.device_set.take().ok_or("missing set")?.devices;
    request.device_set = Some(ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: std::mem::take(&mut entries),
        },
    )?);
    Ok(request)
}

fn register(
    registry: &mut IdentityRegistry,
    device: &str,
    nonce: u64,
) -> Result<IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let request = registration_request("alice", device, nonce, None, "test-source")?;
    registry.register_identity(&request)?;
    let branch =
        ramflux_crypto::create_device_branch("alice", device, 1, seed_from_nonce(0x41, nonce));
    let key = ramflux_crypto::X25519KeyPair::from_seed(seed_from_nonce(0x51, nonce));
    let prekey = ramflux_crypto::X25519KeyPair::from_seed([72; 32]);
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: device.into(),
        bundle: ramflux_crypto::create_prekey_bundle(&branch, &key, "prekey", &prekey, None, None)?,
    })?;
    Ok(request)
}
fn revoke_root_device(
    registry: &mut IdentityRegistry,
    request: &IdentityRegisterRequest,
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root(
        &request.proof.principal_id,
        seed_from_nonce(0x31, nonce),
    );
    let mut next =
        registry.signed_device_set(&request.principal_commitment).ok_or("signed set")?.clone();
    next.device_set_epoch += 1;
    let device =
        next.devices.iter_mut().find(|d| d.device_id == request.proof.device_id).ok_or("device")?;
    device.status = ramflux_protocol::DeviceSetStatus::Revoked;
    device.revoked_at = Some(request.now + 1);
    let record = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: next.principal_kind,
            device_set_epoch: next.device_set_epoch,
            devices: next.devices,
        },
    )?;
    registry.publish_signed_device_set(&crate::DeviceSetPublishRequest {
        root_public_key: request.root_public_key.clone(),
        record,
    })?;
    Ok(())
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
    for field in
        ["devices", "root_public_keys_by_commitment", "prekey_bundles", "signed_device_sets"]
    {
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
        revoke_root_device(&mut registry, &request, nonce)?;
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
    revoke_root_device(&mut registry, &first, 1)?;
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
    second = same_root_registration(second, 1, 2)?;
    let root = ramflux_crypto::create_identity_root("alice", seed_from_nonce(0x31, 1));
    let mut entries = registration.device_set.as_ref().ok_or("first set")?.devices.clone();
    entries.extend(second.device_set.as_ref().ok_or("second set")?.devices.clone());
    second.device_set = Some(ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 2,
            devices: entries,
        },
    )?);
    second.target_delivery_id = "target_alice-two".into();
    second.session_id = "session_alice-two".into();
    let second_reply = router.mvp1_register_identity(&second)?;
    let branch =
        ramflux_crypto::create_device_branch("alice", "alice-one", 1, seed_from_nonce(0x41, 1));
    let identity = ramflux_crypto::X25519KeyPair::from_seed(seed_from_nonce(0x51, 1));
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
    registry.register_identity(&takeover)?;
    assert_eq!(
        registry.device_manifest(&alice.principal_commitment).ok_or("alice root missing")?.devices
            [0]
        .branch_public_key,
        alice.branch_public_key
    );
    assert_eq!(
        registry
            .device_manifest(&takeover.principal_commitment)
            .ok_or("second root missing")?
            .principal_id,
        "mallory-two"
    );
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
    let mut again = same_root_registration(
        registration_request("alice", "alice-one", 9, None, "owner")?,
        1,
        9,
    )?;
    again.device_set = Some(ramflux_crypto::sign_device_set(
        &ramflux_crypto::create_identity_root("alice", seed_from_nonce(0x31, 1)),
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 2,
            devices: again.device_set.as_ref().ok_or("rotation set")?.devices.clone(),
        },
    )?);
    // Same-epoch key replacement is rejected; the existing owner's key stays intact.
    assert!(registry.register_identity(&again).is_err());
    let mut legacy = serde_json::to_value(&registry)?;
    legacy.as_object_mut().ok_or("registry")?.remove("device_root_bindings");
    legacy.as_object_mut().ok_or("registry")?.remove("delivery_root_bindings");
    let mut restored: IdentityRegistry = serde_json::from_value(legacy)?;
    restored.remove_principal_metadata("alice");
    assert!(restored.register_identity(&takeover).is_err());
    assert_eq!(
        restored
            .device_manifest(&mallory.principal_commitment)
            .ok_or("mallory preserved")?
            .principal_id,
        "mallory"
    );
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
    for field in
        ["devices", "root_public_keys_by_commitment", "prekey_bundles", "signed_device_sets"]
    {
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
    assert!(registry.register_identity(&claim).is_err());
    registry.remove_principal_metadata("alice");
    assert!(registry.register_identity(&claim).is_err());
    Ok(())
}

#[test]
fn reopening_legacy_registration_policies_restores_finite_admission_and_keeps_operator_limits()
-> Result<(), Box<dyn std::error::Error>> {
    for (limit, window, expected_limit, expected_window) in
        [(u32::MAX, 60, 120, 60), (0, 60, 120, 60), (3, 0, 3, 60), (3, 90, 3, 90)]
    {
        let path = temp_store_path(&format!("registration-upgrade-{limit}-{window}"))?;
        let router = RouterCore::new();
        router.upsert_session(session("upgrade-session", SessionLifecycle::Live, 1, 1))?;
        router.mvp6_set_registration_policy(RegistrationPolicy {
            per_source_ip_registration_limit: limit,
            registration_window_seconds: window,
            ..RegistrationPolicy::default()
        });
        let store = RouterRedbStore::open(&path)?;
        store.save_router(&router)?;
        drop(store);
        let store = RouterRedbStore::open(&path)?;
        let restored = store.load_router()?.ok_or("missing router")?;
        let mut request = registration_request("upgrade", "device", 1, None, "same-source")?;
        request.root_public_key.clear();
        for _ in 0..expected_limit {
            let error = restored.mvp1_register_identity(&request).err().ok_or("invalid root")?;
            assert!(
                !error.to_string().contains("registration source rate exceeded"),
                "limit cut off too early: {error}"
            );
        }
        assert!(
            restored
                .mvp1_register_identity(&request)
                .err()
                .ok_or("budget exhausted")?
                .to_string()
                .contains("registration source rate exceeded"),
            "legacy snapshot must not retain unlimited admission"
        );
        assert_eq!(
            restored.mvp6_registration_policy().per_source_ip_registration_limit,
            expected_limit
        );
        assert_eq!(
            restored.mvp6_registration_policy().registration_window_seconds,
            expected_window
        );
        drop(restored);
        drop(store);
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn registration_policy_setters_and_snapshot_loads_share_finite_normalization()
-> Result<(), Box<dyn std::error::Error>> {
    for (limit, window) in [(0, 0), (u32::MAX, 0), (7, 13), (1, u64::MAX)] {
        let policy = RegistrationPolicy {
            per_source_ip_registration_limit: limit,
            registration_window_seconds: window,
            challenge_policy: RegistrationChallengePolicy::Pow,
            pow_difficulty_bits: 9,
        };
        let mut registry = IdentityRegistry::new();
        registry.set_registration_policy(policy.clone());
        let mut snapshot = serde_json::to_value(IdentityRegistry::new())?;
        snapshot["registration_policy"] = serde_json::to_value(policy)?;
        let loaded: IdentityRegistry = serde_json::from_value(snapshot)?;
        assert_eq!(registry.registration_policy(), loaded.registration_policy());
        let expected_limit = if matches!(limit, 0 | u32::MAX) { 120 } else { limit };
        let expected_window = if window == 0 { 60 } else { window };
        assert_eq!(registry.registration_policy().per_source_ip_registration_limit, expected_limit);
        assert_eq!(registry.registration_policy().registration_window_seconds, expected_window);
        assert_eq!(registry.registration_policy().pow_difficulty_bits, 9);
        assert_eq!(
            registry.registration_policy().challenge_policy,
            RegistrationChallengePolicy::Pow
        );
        let restarted: IdentityRegistry = serde_json::from_slice(&serde_json::to_vec(&registry)?)?;
        assert_eq!(registry.registration_policy(), restarted.registration_policy());
    }
    Ok(())
}
