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
    let second = register(&mut registry, "alice-two", 2)?;
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
