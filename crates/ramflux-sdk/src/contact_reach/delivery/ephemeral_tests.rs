// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native pair sealing tests the volatile sender-authentication boundary only.
//! Receiving permissions and authenticated home transport have separate controls.
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_crypto::{contact_reach as crypto, custody::VerifiedRecord};
use ramflux_protocol::{contact_reach as wire, custody};

#[tokio::test(flavor = "current_thread")]
async fn cr_native_ephemeral_requires_the_checked_sender_transcript() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), Box::pin(checked_transcript())).await?
}

async fn checked_transcript() -> TestResult {
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (source, target) = Box::pin(crate::client::routed::native_typing_pair_fixture()).await?;
    let (envelope, _) = crate::client::routed::native_typing_delivery_fixture(&source, &target)?;
    let now = u64::try_from(envelope.created_at)?;
    let root = source.client.own_account_anchor()?;
    let authority = source
        .client
        .current_custody_authority(&root, now)?
        .ok_or("current native sender authority")?;
    let frame = wrap(&source, envelope, &authority)?;
    let now_ms = now.checked_mul(1000).ok_or("typing clock overflow")?;
    crypto::verify_ephemeral(&frame, &authority, now_ms)?;
    let branch = source.client.device_branch.as_ref().ok_or("source branch")?;
    let mut generic = frame.frame.envelope.clone();
    generic.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&generic, branch.signing_key.to_bytes())?;
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&generic)?,
        &generic.signed.signature,
        &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes()),
    )?;
    assert!(
        crypto::verify_ephemeral(&wrap(&source, generic, &authority)?, &authority, now_ms).is_err(),
        "a valid generic object signature must not replace the native v2 sender transcript"
    );
    let mut wrong_target = frame.clone();
    wrong_target.frame.envelope.target_delivery_id = source.config.target_delivery_id.clone();
    wrong_target.frame.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&wrong_target.frame.envelope)?,
        branch.signing_key.to_bytes(),
    );
    ramflux_protocol::verify_envelope_sender_signature(
        &wrong_target.frame.envelope,
        &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes()),
    )?;
    wrong_target.route.body.envelope_hash =
        custody::framed_hash(wire::EPHEMERAL_HASH_DOMAIN, &wrong_target.frame)?;
    wrong_target.route = crypto::sign_route(wrong_target.route.body, branch)?;
    assert!(
        crypto::verify_ephemeral(&wrong_target, &authority, now_ms).is_err(),
        "a fresh W cannot move the enclosed frame to another recipient root"
    );
    assert!(
        crypto::verify_ephemeral(&frame, &authority, frame.frame.expires_at_ms).is_err(),
        "a fresh verification call cannot extend the original signed Typing deadline"
    );
    Ok(())
}

fn wrap(
    source: &Fixture,
    envelope: ramflux_protocol::Envelope,
    authority: &VerifiedRecord,
) -> TestResult<wire::ReachEphemeral> {
    let created = u64::try_from(envelope.created_at)?;
    let expires = created.checked_add(u64::from(envelope.ttl)).ok_or("expiry overflow")?;
    let recipient = ramflux_protocol::parse_qualified_device_id(&envelope.target_delivery_id)?
        .ok_or("native recipient")?
        .0;
    let root = source.client.own_account_anchor()?;
    let branch = source.client.device_branch.as_ref().ok_or("branch")?;
    let frame = wire::EphemeralFrame {
        frame_type: wire::EphemeralFrameKind::Ephemeral,
        envelope,
        expires_at_ms: expires.checked_mul(1000).ok_or("deadline overflow")?,
    };
    let route = crypto::sign_route(
        wire::Route {
            version: 1,
            source: custody::DeviceRef {
                account_anchor: root.clone(),
                device_id: branch.device_id.clone(),
                device_epoch: branch.device_epoch,
            },
            recipient_root: recipient.clone(),
            conversation_id: ramflux_protocol::message::dm_scope::derive(&root, &recipient)?,
            traffic: wire::Traffic::Typing,
            group: None,
            envelope_hash: custody::framed_hash(wire::EPHEMERAL_HASH_DOMAIN, &frame)?,
            authority_head_hash: custody::object_hash(authority.envelope())?,
            issued_at: created,
            expires_at: expires,
        },
        branch,
    )?;
    Ok(wire::ReachEphemeral { route, frame })
}
