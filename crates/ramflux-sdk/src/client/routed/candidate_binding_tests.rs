// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_crypto::CryptoError;
use ramflux_protocol::message as g;

fn sealed_pair() -> Result<(Fixture, Fixture, GatewayInboxEntry), SdkError> {
    let a = Fixture::new("alice", 121)?;
    let b = Fixture::new("bob", 122)?;
    let source = a.client.owned_device_identity()?;
    let mut stream = crate::client::generated_content::GeneratedEventStream::new(
        "c",
        g::QualifiedDevice {
            account_anchor: source.root_commitment().into(),
            device_id: source.device_id().into(),
            device_epoch: a
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .device_epoch,
        },
    );
    let exact = RamfluxClient::encode_generated_message(
        &mut stream,
        b"candidate-bind".to_vec(),
        g::Message { text: "bind-body".into(), ..Default::default() },
    )?;
    let entry = seal(&a, &b, message("candidate-bind", "c"), &exact)?;
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
        Err(SdkError::Protocol(ramflux_protocol::ProtocolError::SignatureVerificationFailed)) => {
            assert_eq!(
                SdkError::Protocol(ramflux_protocol::ProtocolError::SignatureVerificationFailed)
                    .to_string(),
                "protocol error: ed25519 verification failed"
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
    let (_, content) = RamfluxClient::decode_generated_inner(&opened.body)?;
    assert!(
        matches!(content.value, Some(g::content::Value::Message(message)) if message.text == "bind-body")
    );
    Ok(())
}

#[test]
fn tampered_delivery_mode_fails_open_routed_signature() -> Result<(), SdkError> {
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
    let (a, b, entry) = sealed_pair()?;
    let before = receiver_pair_snapshot(&b, &a)?;
    let forged = ramflux_protocol::encode_base64url([0x00_u8; 32]);
    let mut changed = entry.clone();
    changed.envelope = rewrite_sidecar(&changed.envelope, |sidecar| {
        sidecar["collapse_tag"] = serde_json::Value::String(forged.clone());
    })?;
    changed.envelope.collapse_tag = Some(forged);
    resign(&a, &mut changed.envelope)?;
    aead_failed(b.client.open_routed(&changed, "bob"))?;
    assert_eq!(before, receiver_pair_snapshot(&b, &a)?);
    Ok(())
}

#[test]
fn sdk_decode_refuses_absent_compact_ciphertext_field() -> Result<(), SdkError> {
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
fn active_aad_refuses_retired_v2_transcript() -> Result<(), SdkError> {
    let bundle = [0x11_u8; 32];
    let aad = associated_data("aad-v2-golden", "alice", "bob", &bundle)?;
    assert_ne!(aad, GATE_OFF_V2_AAD_GOLDEN);
    let text = String::from_utf8(aad).map_err(|_| invalid("aad utf8"))?;
    assert!(text.contains("aad.v3"));
    assert!(!text.contains("aad.v2"));
    Ok(())
}

#[test]
fn active_named_delivery_mode_tampering_is_refused_by_open_routed() -> Result<(), SdkError> {
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = Some("ephemeral".into());
    resign(&a, &mut changed.envelope)?;
    assert!(b.client.open_routed(&changed, "bob").is_err());
    Ok(())
}

#[test]
fn active_named_collapse_tag_tampering_is_refused_by_open_routed() -> Result<(), SdkError> {
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    resign(&a, &mut changed.envelope)?;
    assert!(b.client.open_routed(&changed, "bob").is_err());
    Ok(())
}

#[test]
fn active_named_field_conflicting_with_retired_bridge_is_refused_by_open_routed()
-> Result<(), SdkError> {
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = Some("durable".into());
    changed.envelope.ext.ext.insert(
        ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION.to_owned(),
        serde_json::json!("ephemeral"),
    );
    resign(&a, &mut changed.envelope)?;
    assert!(b.client.open_routed(&changed, "bob").is_err());
    Ok(())
}

#[test]
fn open_routed_refuses_missing_delivery_mode() -> Result<(), SdkError> {
    let (_a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = None;
    assert!(
        matches!(
            b.client.open_routed(&changed, "bob"),
            Err(SdkError::Protocol(ramflux_protocol::ProtocolError::SenderTranscriptProfile))
        ),
        "missing mode must be refused before any pair state change"
    );
    Ok(())
}

#[test]
fn open_routed_refuses_unknown_delivery_mode() -> Result<(), SdkError> {
    let (a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.delivery_mode = Some("bogus".into());
    resign(&a, &mut changed.envelope)?;
    inbound_open(b.client.open_routed(&changed, "bob"), "new profile rejects unknown delivery_mode")
}

#[test]
fn open_routed_refuses_31_byte_collapse_tag() -> Result<(), SdkError> {
    let (_a, b, entry) = sealed_pair()?;
    let mut changed = entry;
    changed.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 31]));
    assert!(
        matches!(
            b.client.open_routed(&changed, "bob"),
            Err(SdkError::Protocol(ramflux_protocol::ProtocolError::SenderTranscriptProfile))
        ),
        "invalid tag length must be refused before any pair state change"
    );
    Ok(())
}

#[test]
fn established_pair_resigned_mode_mismatch_fails_aead_and_original_still_opens()
-> Result<(), SdkError> {
    let (a, b, first) = sealed_pair()?;
    let opened = b.client.open_routed(&first, "bob")?;
    let (_, content) = RamfluxClient::decode_generated_inner(&opened.body)?;
    assert!(
        matches!(content.value, Some(g::content::Value::Message(message)) if message.text == "bind-body")
    );
    b.client.persist_pair(
        &b.client.local_device_identity("bob")?,
        &b.client.device_identity(&fixture_peer_reference(&b.client, "alice")?)?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    let (first_identity, _) = RamfluxClient::decode_generated_inner(&opened.body)?;
    let mut stream = crate::client::generated_content::GeneratedEventStream::new(
        "c",
        first_identity.author.ok_or_else(|| invalid("first author"))?,
    );
    let _ = stream.next(b"first")?;
    let exact = RamfluxClient::encode_generated_message(
        &mut stream,
        b"second".to_vec(),
        g::Message { text: "second-body".into(), ..Default::default() },
    )?;
    let mut outbound = message("candidate-bind-2", "c");
    outbound.message_id =
        ramflux_protocol::encode_base64url(RamfluxClient::decode_generated_inner(&exact)?.0.id);
    let second = seal(&a, &b, outbound, &exact)?;
    let before = receiver_pair_snapshot(&b, &a)?;
    assert_ne!(before.len(), 0);
    let mut changed = second.clone();
    changed.envelope.delivery_mode = Some("ephemeral".into());
    resign(&a, &mut changed.envelope)?;
    aead_failed(b.client.open_routed(&changed, "bob"))?;
    assert_eq!(before, receiver_pair_snapshot(&b, &a)?);
    assert_eq!(
        b.client.open_routed(&second, "bob")?.body.as_slice(),
        exact,
        "refused mode tampering must preserve the exact successor"
    );
    Ok(())
}
