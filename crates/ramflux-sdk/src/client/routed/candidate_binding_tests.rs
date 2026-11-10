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

fn inbound_open(result: Result<Opened, SdkError>, expected: &str) -> Result<(), SdkError> {
    match result {
        Err(SdkError::InboundRejected(message)) if message == expected => Ok(()),
        Err(error) => Err(invalid(&format!("exact {expected}, got {error}"))),
        Ok(_) => Err(invalid(&format!("exact {expected}, got Ok"))),
    }
}

fn inbound_decode(
    result: Result<SdkDmEncryptedEnvelope, SdkError>,
    expected: &str,
) -> Result<(), SdkError> {
    match result {
        Err(SdkError::InboundRejected(message)) if message == expected => Ok(()),
        Err(error) => Err(invalid(&format!("exact {expected}, got {error}"))),
        Ok(_) => Err(invalid(&format!("exact {expected}, got Ok"))),
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
    inbound_decode(decode(&missing), "compact candidate sidecar ciphertext field is required")
}

#[test]
fn sdk_decode_refuses_absent_compact_ciphertext_object() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (_a, _b, entry) = sealed_pair()?;
    let missing = rewrite_sidecar(&entry.envelope, |sidecar| {
        if let Some(object) = sidecar.as_object_mut() {
            object.remove("ciphertext");
        }
    })?;
    inbound_decode(decode(&missing), "compact candidate sidecar ciphertext field is required")
}

const GATE_OFF_V2_AAD_GOLDEN: &[u8] = br#"["ramflux.sdk.envelope.aad.v2","aad-v2-golden",[95,204,188,78,87,206,108,231,22,135,120,138,131,53,234,166,144,158,255,72,86,227,216,174,1,195,102,74,15,153,26,204],[208,39,172,93,44,11,143,110,159,26,136,102,41,124,125,100,133,204,131,100,133,50,252,128,27,30,187,199,67,3,193,238],[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17],2]"#;

#[test]
fn gate_off_v2_aad_bytes_are_unchanged() -> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let bundle = [0x11_u8; 32];
    let aad = associated_data("aad-v2-golden", "alice", "bob", &bundle)?;
    assert_eq!(aad, GATE_OFF_V2_AAD_GOLDEN);
    let text = String::from_utf8(aad).map_err(|_| invalid("aad utf8"))?;
    assert!(text.starts_with(r#"["ramflux.sdk.envelope.aad.v2","aad-v2-golden""#));
    assert!(!text.contains("aad.v3"));
    Ok(())
}

const NAMED_FIELDS_GATE_OFF: &str =
    "named delivery_mode and collapse_tag are refused while schema v1 is off";

#[test]
fn gate_off_named_delivery_mode_is_refused_by_open_routed() -> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = Some("ephemeral".into());
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), NAMED_FIELDS_GATE_OFF)
}

#[test]
fn gate_off_named_collapse_tag_is_refused_by_open_routed() -> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), NAMED_FIELDS_GATE_OFF)
}

#[test]
fn gate_off_named_field_conflicting_with_ext_bridge_is_refused_by_open_routed()
-> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = Some("durable".into());
    changed.envelope.ext.ext.insert(
        ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION.to_owned(),
        serde_json::json!("ephemeral"),
    );
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), NAMED_FIELDS_GATE_OFF)
}

#[test]
fn open_routed_refuses_missing_delivery_mode() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = None;
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), "delivery_mode is required")
}

#[test]
fn open_routed_refuses_unknown_delivery_mode() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = Some("bogus".into());
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), "new profile rejects unknown delivery_mode")
}

#[test]
fn open_routed_refuses_31_byte_collapse_tag() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 31]));
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), "collapse_tag must be 32 bytes")
}

#[test]
fn established_pair_resigned_mode_mismatch_fails_aead_and_original_still_opens()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b, first) = sealed_pair()?;
    let opened = b.client.open_routed(&first, "bob")?;
    assert_eq!(opened.body.as_slice(), b"bind-body");
    b.client.persist_pair(
        &b.client.local_device_identity("bob")?,
        &b.client.device_identity(&fixture_peer_reference(&b.client, "alice")?)?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    let second = seal(&a, &b, message("candidate-bind-2", "c"), b"second-body")?;
    let before = receiver_pair_snapshot(&b, &a)?;
    assert!(!before.is_empty());
    let mut changed = second.clone();
    changed.envelope.delivery_mode = Some("ephemeral".into());
    resign(&a, &mut changed.envelope)?;
    aead_failed(b.client.open_routed(&changed, "bob"))?;
    assert_eq!(before, receiver_pair_snapshot(&b, &a)?);
    assert_eq!(b.client.open_routed(&second, "bob")?.body.as_slice(), b"second-body");
    Ok(())
}
