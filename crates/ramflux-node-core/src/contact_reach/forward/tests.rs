// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Carrier coverage only; receiving-home policy and source adoption are separate real components.
use super::*;
use ramflux_protocol::{
    contact_reach::{Route, Traffic},
    custody::{DeviceRef, Envelope as Signed},
};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn digest(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn forward() -> TestResult<ReachForward> {
    let envelope = crate::test_support::federation_fixtures::envelope(
        "sealed",
        "target",
        DeliveryClass::Message,
    );
    let route = Route {
        version: 1,
        source: DeviceRef { account_anchor: digest(1), device_id: "phone".into(), device_epoch: 1 },
        recipient_root: digest(2),
        conversation_id: ramflux_protocol::message::dm_scope::derive(&digest(1), &digest(2))?,
        traffic: Traffic::Dm,
        envelope_hash: ramflux_protocol::custody::framed_hash(
            wire::ENVELOPE_HASH_DOMAIN,
            &envelope,
        )?,
        authority_head_hash: digest(3),
        issued_at: 1_760_000_000,
        expires_at: 1_760_003_600,
    };
    Ok(ReachForward {
        signing_key_id: String::new(),
        signature_alg: SignatureAlg::Ed25519,
        signature: String::new(),
        source_node_id: "source.example".into(),
        target_node_id: "target.example".into(),
        delivery_class: ReachDeliveryClass::Message,
        required_capability: ReachCapability::V1,
        submission: Submission {
            route: Signed { body: route, signature: ramflux_protocol::encode_base64url([4; 64]) },
            envelope,
            cost: None,
        },
        migration_evidence: None,
    })
}
#[test]
fn cr_forward_signature_covers_enclosed_route_and_sealed_bytes() -> TestResult {
    let mut forward = forward()?;
    forward.sign("source.example", [7; 32])?;
    let public = ramflux_crypto::public_key_base64url_from_seed([7; 32]);
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&forward)?,
        &forward.signature,
        &public,
    )?;
    let mut changed = forward.clone();
    changed.submission.envelope.encrypted_payload.push('x');
    assert!(
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&changed)?,
            &changed.signature,
            &public
        )
        .is_err(),
        "node signature must cover exact sealed envelope bytes"
    );
    let mut changed = forward.clone();
    changed.submission.route.body.authority_head_hash = digest(9);
    assert!(
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&changed)?,
            &changed.signature,
            &public
        )
        .is_err(),
        "node signature must cover nested branch route metadata"
    );
    Ok(())
}
#[test]
fn cr_forward_closed_codec_refuses_old_carrier_and_missing_null() -> TestResult {
    let mut forward = forward()?;
    forward.sign("source.example", [7; 32])?;
    let bytes = ramflux_protocol::canonical_json_bytes(&forward)?;
    assert_eq!(ReachForward::decode(&bytes)?, forward, "the exact new carrier must round trip");
    let mut value = serde_json::to_value(&forward)?;
    value.as_object_mut().ok_or("object")?.remove("migration_evidence");
    assert!(
        ReachForward::decode(&serde_json::to_vec(&value)?).is_err(),
        "nullable migration evidence cannot be omitted"
    );
    let mut value = serde_json::to_value(&forward)?;
    value
        .as_object_mut()
        .ok_or("object")?
        .insert("admin_token".into(), serde_json::json!("legacy"));
    assert!(
        ReachForward::decode(&serde_json::to_vec(&value)?).is_err(),
        "the new peer carrier has no admin token alternative"
    );
    value.as_object_mut().ok_or("object")?.remove("admin_token");
    let submission =
        value.as_object_mut().ok_or("object")?.remove("submission").ok_or("submission")?;
    value
        .as_object_mut()
        .ok_or("object")?
        .insert("envelope".into(), submission.get("envelope").ok_or("envelope")?.clone());
    assert!(
        ReachForward::decode(&serde_json::to_vec(&value)?).is_err(),
        "bare-envelope forwarding must not substitute for a Submission"
    );
    Ok(())
}
