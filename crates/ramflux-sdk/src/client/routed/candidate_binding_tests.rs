// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_crypto::CryptoError;

fn sealed_pair() -> Result<(Fixture, Fixture, GatewayInboxEntry), SdkError> {
    let a = Fixture::new("alice", 121)?;
    let b = Fixture::new("bob", 122)?;
    let entry = seal(&a, &b, message("candidate-bind", "c"), b"bind-body")?;
    Ok((a, b, entry))
}

fn rewrite_sidecar(
    envelope: &ramflux_protocol::Envelope,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut sidecar: serde_json::Value =
        serde_json::from_slice(compact.sidecar).map_err(|error| invalid(&error.to_string()))?;
    edit(&mut sidecar);
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    let mut out = envelope.clone();
    out.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    out.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        out.encrypted_payload.as_bytes(),
    );
    Ok(out)
}

fn resign(sender: &Fixture, envelope: &mut ramflux_protocol::Envelope) -> Result<(), SdkError> {
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        envelope,
    )?;
    Ok(())
}

fn receiver_pair_snapshot(receiver: &Fixture, sender: &Fixture) -> Result<Vec<u8>, SdkError> {
    let local = receiver.client.local_device_identity(&receiver.id)?;
    let remote =
        receiver.client.device_identity(&fixture_peer_reference(&receiver.client, &sender.id)?)?;
    receiver.client.persisted_pair_snapshot(&local, &remote)
}

fn verify_failed(result: Result<Opened, SdkError>) -> Result<(), SdkError> {
    match result {
        Err(SdkError::Crypto(CryptoError::VerifyFailed)) => {
            assert_eq!(
                SdkError::Crypto(CryptoError::VerifyFailed).to_string(),
                "crypto error: ed25519 verification failed"
            );
            Ok(())
        }
        Err(error) => Err(invalid(&format!("exact verify failure, got {error}"))),
        Ok(_) => Err(invalid("exact verify failure, got Ok")),
    }
}

fn aead_failed(result: Result<Opened, SdkError>) -> Result<(), SdkError> {
    match result {
        Err(SdkError::Crypto(CryptoError::AeadFailed)) => {
            assert_eq!(
                SdkError::Crypto(CryptoError::AeadFailed).to_string(),
                "crypto error: aead operation failed"
            );
            Ok(())
        }
        Err(error) => Err(invalid(&format!("exact aead failure, got {error}"))),
        Ok(_) => Err(invalid("exact aead failure, got Ok")),
    }
}

#[test]
fn candidate_seal_writes_named_fields_and_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (_a, b, entry) = sealed_pair()?;
    assert_eq!(entry.envelope.delivery_mode.as_deref(), Some("durable"));
    assert_eq!(
        ramflux_protocol::decode_base64url(
            entry.envelope.collapse_tag.as_deref().ok_or_else(|| invalid("collapse_tag"))?
        )
        .map_err(|_| invalid("collapse_tag"))?
        .len(),
        32
    );
    let opened = b.client.open_routed(&entry, "bob")?;
    assert_eq!(opened.body.as_slice(), b"bind-body");
    Ok(())
}

#[test]
fn tampered_delivery_mode_fails_open_routed_signature() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (_a, b, entry) = sealed_pair()?;
    b.client.authenticated_envelope_sender(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry,
    )?;
    let mut tampered = entry.clone();
    tampered.envelope.delivery_mode = Some("ephemeral".into());
    verify_failed(b.client.open_routed(&tampered, "bob"))
}

#[test]
fn tampered_collapse_tag_fails_open_routed_signature() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (_a, b, entry) = sealed_pair()?;
    b.client.authenticated_envelope_sender(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry,
    )?;
    let mut tampered = entry.clone();
    tampered.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    verify_failed(b.client.open_routed(&tampered, "bob"))
}

#[test]
fn resigned_outer_delivery_mode_mismatch_fails_aead_and_keeps_pair() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b, entry) = sealed_pair()?;
    let before = receiver_pair_snapshot(&b, &a)?;
    let mut changed = entry.clone();
    changed.envelope.delivery_mode = Some("ephemeral".into());
    resign(&a, &mut changed.envelope)?;
    aead_failed(b.client.open_routed(&changed, "bob"))?;
    assert_eq!(before, receiver_pair_snapshot(&b, &a)?);
    Ok(())
}

#[test]
fn resigned_outer_collapse_tag_mismatch_fails_aead_and_keeps_pair() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b, entry) = sealed_pair()?;
    let before = receiver_pair_snapshot(&b, &a)?;
    let mut changed = entry.clone();
    changed.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    resign(&a, &mut changed.envelope)?;
    aead_failed(b.client.open_routed(&changed, "bob"))?;
    assert_eq!(before, receiver_pair_snapshot(&b, &a)?);
    Ok(())
}

#[test]
fn sdk_decode_refuses_absent_compact_ciphertext_field() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (_a, _b, entry) = sealed_pair()?;
    let missing = rewrite_sidecar(&entry.envelope, |sidecar| {
        if let Some(object) = sidecar["ciphertext"].as_object_mut() {
            object.remove("ciphertext");
        }
    })?;
    match decode(&missing) {
        Err(SdkError::InboundRejected(message))
            if message == "compact candidate sidecar ciphertext field is required" =>
        {
            Ok(())
        }
        other => Err(invalid(&format!("exact missing ciphertext error, got {other:?}"))),
    }
}

#[test]
fn gate_off_v2_aad_bytes_are_unchanged() -> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let bundle = [0x11_u8; 32];
    let aad = associated_data("aad-v2-golden", "alice", "bob", &bundle)?;
    let expected = ramflux_protocol::canonical_json_bytes(&(
        "ramflux.sdk.envelope.aad.v2",
        "aad-v2-golden",
        dm_device_id_hash("alice"),
        dm_device_id_hash("bob"),
        bundle,
        2_u32,
    ))?;
    assert_eq!(aad, expected);
    let text = String::from_utf8(aad).map_err(|_| invalid("aad utf8"))?;
    assert!(text.starts_with(r#"["ramflux.sdk.envelope.aad.v2","aad-v2-golden""#));
    assert!(!text.contains("aad.v3"));
    Ok(())
}
