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
    router.authenticated_envelope_source_from(
        &signed,
        None,
        crate::RouterEnvelopeOrigin::Gateway,
    )?;
    let mut flipped = signed;
    flipped.delivery_mode = Some("ephemeral".into());
    authority_mismatch(router.authenticated_envelope_source_from(
        &flipped,
        None,
        crate::RouterEnvelopeOrigin::Gateway,
    ))
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
