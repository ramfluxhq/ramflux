// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Seed one real identity admission so binary shutdown must checkpoint a nonempty journal.

pub(super) fn seed(database: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let store = ramflux_node_core::RouterRedbStore::open(database)?;
    let router = store.load_router()?.unwrap_or_default();
    let principal = "shutdown-identity";
    let root = ramflux_crypto::create_identity_root(principal, [0x61; 32]);
    let device = ramflux_crypto::create_device_branch(principal, "phone", 1, [0x62; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([0x63; 32]);
    let now = i64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    )?;
    let proof = ramflux_crypto::authorize_device_branch_v2(
        &root,
        &device,
        ramflux_crypto::BranchAuthorization {
            audience: ramflux_node_core::IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.into()],
            issued_at: now - 1,
            expires_at: now + 3600,
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            agreement_identity_public_key: agreement.public,
        },
    )?;
    let branch_public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    let (signing_key_commitment, agreement_key_commitment) =
        ramflux_crypto::device_key_commitments(
            &branch_public_key,
            &ramflux_protocol::encode_base64url(agreement.public),
        )?;
    let device_set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: "phone".into(),
                device_epoch: 1,
                signing_key_commitment,
                agreement_key_commitment,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    let root_bytes = root.signing_key.verifying_key().to_bytes();
    router.register_identity_durable(
        &ramflux_node_core::IdentityRegisterRequest {
            device_set: Some(device_set),
            principal_commitment: ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &root_bytes,
            ),
            root_public_key: ramflux_protocol::encode_base64url(root_bytes),
            branch_public_key,
            proof,
            target_delivery_id: "shutdown-identity-target".into(),
            gateway_id: "ramflux-gateway".into(),
            session_id: "shutdown-identity-session".into(),
            push_alias_hash: None,
            now,
            registration_pow: None,
            source_ip_hash: Some(ramflux_node_core::source_ip_hash("127.0.0.1")),
        },
        &store,
    )?;
    assert_eq!(
        store.pending_identity_admission_count()?,
        1,
        "shutdown must start with a nonempty identity journal"
    );
    Ok(())
}
