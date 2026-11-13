// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

fn signed_candidate(envelope_id: &str, nonce: u64) -> Result<Envelope, Box<dyn std::error::Error>> {
    let mut envelope = envelope(envelope_id, "target_alice", DeliveryClass::OpaqueEvent);
    envelope.created_at = i64::try_from(crate::now_unix_seconds())?;
    envelope.delivery_mode = Some("durable".into());
    envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x22_u8; 32]));
    Ok(signed_registered_envelope(envelope, "alice", "phone", nonce)?)
}

fn registered_router(nonce: u64) -> Result<RouterCore, Box<dyn std::error::Error>> {
    let router = RouterCore::new();
    router.mvp1_register_identity(&registration_request(
        &router,
        "alice",
        "phone",
        nonce,
        None,
        "ip_candidate_bind",
    )?)?;
    Ok(router)
}

fn authority_mismatch(
    result: Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(NodeCoreError::SourceAuthorityRefused {
            reason_code: crate::EnvelopeAuthorityReason::AuthorityMismatch,
        }) => {
            assert_eq!(
                NodeCoreError::SourceAuthorityRefused {
                    reason_code: crate::EnvelopeAuthorityReason::AuthorityMismatch,
                }
                .to_string(),
                "source authority refused: AuthorityMismatch"
            );
            Ok(())
        }
        other => Err(format!("exact AuthorityMismatch, got {other:?}").into()),
    }
}

#[test]
fn tampered_delivery_mode_fails_node_entry_signature() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let nonce = 901;
    let router = registered_router(nonce)?;
    let signed = signed_candidate("bind-mode", nonce)?;
    let source = router.authenticated_envelope_source_from(
        &signed,
        None,
        crate::RouterEnvelopeOrigin::Gateway,
    )?;
    let authority = router
        .mvp1_device_auth_key_checked(source.storage_key())?
        .ok_or("registered source authority missing")?;
    let mut flipped = signed;
    flipped.delivery_mode = Some("ephemeral".into());
    authority_mismatch(authority.verify_envelope_source(&flipped))?;
    // The durable entry rejects ephemeral mode before reaching the signature verifier.
    assert!(matches!(
        router.authenticated_envelope_source_from(
            &flipped,
            None,
            crate::RouterEnvelopeOrigin::Gateway,
        ),
        Err(NodeCoreError::DeliveryModeRefused)
    ));
    Ok(())
}

#[test]
fn tampered_collapse_tag_fails_node_entry_signature() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let nonce = 902;
    let router = registered_router(nonce)?;
    let signed = signed_candidate("bind-tag", nonce)?;
    router.authenticated_envelope_source_from(
        &signed,
        None,
        crate::RouterEnvelopeOrigin::Gateway,
    )?;
    let mut flipped = signed;
    flipped.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    authority_mismatch(router.authenticated_envelope_source_from(
        &flipped,
        None,
        crate::RouterEnvelopeOrigin::Gateway,
    ))
}

#[test]
fn sender_signature_requires_ciphertext_hash_on_every_node_verifier()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = 911;
    let router = registered_router(nonce)?;
    let mut signed = signed_candidate("v2-hash-binding", nonce)?;
    signed.schema = "ramflux.envelope.v2".into();
    signed.domain = "ramflux.envelope.v2".into();
    signed.version = 2;
    signed.encrypted_payload = ramflux_protocol::encode_base64url(b"ciphertext");
    signed.payload_hash = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::ENVELOPE,
        signed.encrypted_payload.as_bytes(),
    );
    signed.report_commitment = Some(ramflux_protocol::encode_base64url([3; 32]));
    signed.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&signed)?,
        seed_from_nonce(0x41, nonce),
    );
    let authority = router
        .mvp1_device_auth_key_checked(&ramflux_protocol::qualified_device_id(
            signed.ext.ext["source_root_commitment"].as_str().ok_or("root missing")?,
            "phone",
        )?)?
        .ok_or("registered authority missing")?;
    authority.verify_envelope_source(&signed)?;
    router
        .ephemeral_view()
        .authenticate_ephemeral_source(&signed)
        .map_err(|error| format!("positive ephemeral source: {error:?}"))?;
    signed.ext.ext.insert("source_device_authority".into(), serde_json::to_value(&authority)?);
    crate::DeviceAuthKeyResponse::forwarded_envelope_source(&signed)?;
    let digest = crate::router_store::sender_retry::content_digest(&signed)?;
    let mut swapped = signed;
    swapped.encrypted_payload = ramflux_protocol::encode_base64url(b"different ciphertext");
    assert!(
        router.ephemeral_view().authenticate_ephemeral_source(&swapped).is_err(),
        "ephemeral node accepted swapped ciphertext"
    );
    assert!(matches!(
        authority.verify_envelope_source(&swapped),
        Err(NodeCoreError::SourceAuthorityRefused {
            reason_code: crate::EnvelopeAuthorityReason::PayloadHashMismatch
        })
    ));
    assert!(matches!(
        crate::DeviceAuthKeyResponse::forwarded_envelope_source(&swapped),
        Err(NodeCoreError::SourceAuthorityRefused {
            reason_code: crate::EnvelopeAuthorityReason::PayloadHashMismatch
        })
    ));
    assert!(
        crate::router_store::sender_retry::content_digest(&swapped).is_err(),
        "reject before comparing retry digest {digest}"
    );
    Ok(())
}
