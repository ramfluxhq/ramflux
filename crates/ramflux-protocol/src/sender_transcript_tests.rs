// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde_json::json;
fn fixture() -> Result<Value, ProtocolError> {
    Ok(serde_json::from_str(include_str!("sender_transcript_vectors.json"))?)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}
#[test]
fn sender_transcript_golden_vectors() -> Result<(), ProtocolError> {
    let fixture = fixture()?;
    let envelope = &fixture["envelope"];
    let original = sender_signed_transcript(envelope, SenderTranscriptMode::WithCiphertext)?;
    assert!(original.ciphertext_bound);
    assert_eq!(Some(hex(&original.bytes).as_str()), fixture["transcript_hex"].as_str());
    let evidence: Value = serde_json::from_slice(&sender_origin_evidence(envelope)?)?;
    let retained = sender_signed_transcript(&evidence, SenderTranscriptMode::Evidence)?;
    assert!(!retained.ciphertext_bound);
    assert_eq!(original.bytes, retained.bytes);
    for field in [
        "schema",
        "version",
        "domain",
        "signing_key_id",
        "signature_alg",
        "envelope_id",
        "source_principal_id",
        "source_device_id",
        "target_delivery_id",
        "routing_set_id",
        "delivery_class",
        "priority",
        "ttl",
        "created_at",
        "payload_hash",
        "delivery_mode",
        "collapse_tag",
        "report_commitment",
        "ext",
    ] {
        let mut changed = evidence.clone();
        changed[field] = if field == "ext" {
            json!({"source_root_commitment":"other"})
        } else {
            json!("changed")
        };
        assert!(
            match sender_signed_transcript(&changed, SenderTranscriptMode::Evidence) {
                Err(_) => true,
                Ok(bytes) => bytes.bytes != original.bytes,
            },
            "unsigned field {field}"
        );
    }
    let mut flipped = evidence.clone();
    flipped["ext"]["message_metadata_commitment"] = json!(encode_base64url([78; 32]));
    assert_ne!(
        sender_signed_transcript(&flipped, SenderTranscriptMode::Evidence)?.bytes,
        original.bytes
    );
    let mut appended = envelope.clone();
    appended["signature"] = json!("other signature");
    appended["node_report_receipt"] = json!({"node":"n"});
    appended["ext"]["source_device_authority"] = json!({"proof":"native"});
    appended["ext"]["home_node_migration_forward_count"] = json!(1);
    for key in ["franking_tag", "node_id", "accepted_at"] {
        appended["ext"]["franking"][key] = json!("node addition");
    }
    assert_eq!(
        sender_signed_transcript(&appended, SenderTranscriptMode::WithCiphertext)?.bytes,
        original.bytes
    );
    Ok(())
}
#[test]
fn evidence_rejects_encrypted_payload_key_present_empty_or_nonempty() -> Result<(), ProtocolError> {
    let fixture = fixture()?;
    let mut evidence: Value =
        serde_json::from_slice(&sender_origin_evidence(&fixture["envelope"])?)?;
    for text in ["", "Ym94"] {
        evidence["encrypted_payload"] = json!(text);
        assert!(matches!(
            sender_signed_transcript(&evidence, SenderTranscriptMode::Evidence),
            Err(ProtocolError::EvidenceContainsCiphertext)
        ));
    }
    Ok(())
}
#[test]
fn sender_signature_requires_ciphertext_hash_before_transcript() -> Result<(), ProtocolError> {
    let mut envelope = fixture()?["envelope"].clone();
    envelope["encrypted_payload"] = json!("b3RoZXI");
    assert!(matches!(
        sender_signed_transcript(&envelope, SenderTranscriptMode::WithCiphertext),
        Err(ProtocolError::PayloadHashMismatch)
    ));
    envelope["encrypted_payload"] = json!("Ym95"); // Valid base64 text for different bytes.
    assert!(matches!(
        sender_signed_transcript(&envelope, SenderTranscriptMode::WithCiphertext),
        Err(ProtocolError::PayloadHashMismatch)
    ));
    Ok(())
}

#[test]
fn sender_evidence_verifies_without_claiming_ciphertext_binding() -> Result<(), ProtocolError> {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[17; 32]);
    let public = encode_base64url(key.verifying_key().to_bytes());
    let mut envelope = fixture()?["envelope"].clone();
    let transcript = sender_signed_transcript(&envelope, SenderTranscriptMode::WithCiphertext)?;
    envelope["signature"] = json!(encode_base64url(key.sign(&transcript.bytes).to_bytes()));
    assert!(
        verify_sender_signature(&envelope, SenderTranscriptMode::WithCiphertext, &public)?
            .ciphertext_bound
    );
    let evidence: Value = serde_json::from_slice(&sender_origin_evidence(&envelope)?)?;
    assert!(
        !verify_sender_signature(&evidence, SenderTranscriptMode::Evidence, &public)?
            .ciphertext_bound
    );
    envelope["encrypted_payload"] = json!("b3RoZXI");
    assert!(matches!(
        verify_sender_signature(&envelope, SenderTranscriptMode::WithCiphertext, &public),
        Err(ProtocolError::PayloadHashMismatch)
    ));
    // An authentic signature over an unrelated hash claim is still only evidence about that claim.
    let mut unrelated = evidence;
    unrelated["payload_hash"] = json!(encode_base64url([77; 32]));
    let transcript = sender_signed_transcript(&unrelated, SenderTranscriptMode::Evidence)?;
    unrelated["signature"] = json!(encode_base64url(key.sign(&transcript.bytes).to_bytes()));
    assert!(
        !verify_sender_signature(&unrelated, SenderTranscriptMode::Evidence, &public)?
            .ciphertext_bound
    );
    Ok(())
}

#[test]
fn payload_hash_rejects_noncanonical_trailing_bits() -> Result<(), ProtocolError> {
    let mut envelope = fixture()?["envelope"].clone();
    envelope["encrypted_payload"] = json!("AA");
    envelope["payload_hash"] = json!(crate::hash_base64url(domain::ENVELOPE, b"AA"));
    sender_signed_transcript(&envelope, SenderTranscriptMode::WithCiphertext)?;
    assert_ne!(
        crate::hash_base64url(domain::ENVELOPE, b"AA"),
        crate::hash_base64url(domain::ENVELOPE, b"AB")
    );
    envelope["encrypted_payload"] = json!("AB");
    envelope["payload_hash"] = json!(crate::hash_base64url(domain::ENVELOPE, b"AB"));
    assert!(matches!(
        sender_signed_transcript(&envelope, SenderTranscriptMode::WithCiphertext),
        Err(ProtocolError::PayloadHashMismatch)
    ));
    Ok(())
}

#[test]
fn live_and_candidate_transcripts_agree() -> Result<(), Box<dyn std::error::Error>> {
    let value = fixture()?["envelope"].clone();
    let live: crate::Envelope = serde_json::from_value(value.clone())?;
    let candidate: crate::message::outer::CandidateOuterEnvelope = serde_json::from_value(value)?;
    assert_eq!(
        crate::envelope_sender_signed_bytes(&live)?,
        crate::candidate_outer_sender_signed_bytes(&candidate)?
    );
    Ok(())
}

#[test]
fn v1_signature_not_accepted_as_v2_and_vice_versa() -> Result<(), ProtocolError> {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[37; 32]);
    let public = encode_base64url(key.verifying_key().to_bytes());
    let mut value = fixture()?["envelope"].clone();
    let legacy_bytes = crate::signed_bytes(&value)?;
    value["signature"] = json!(encode_base64url(key.sign(&legacy_bytes).to_bytes()));
    assert!(
        verify_sender_signature(&value, SenderTranscriptMode::WithCiphertext, &public).is_err()
    );
    let new_bytes = sender_signed_transcript(&value, SenderTranscriptMode::WithCiphertext)?.bytes;
    value["signature"] = json!(encode_base64url(key.sign(&new_bytes).to_bytes()));
    assert!(
        crate::verify_canonical_signature(
            &legacy_bytes,
            value["signature"].as_str().ok_or(ProtocolError::SenderTranscriptProfile)?,
            &public
        )
        .is_err()
    );
    value["schema"] = json!("ramflux.envelope.v1");
    value["domain"] = json!("ramflux.envelope.v1");
    value["version"] = json!(1);
    assert!(matches!(
        verify_sender_signature(&value, SenderTranscriptMode::WithCiphertext, &public),
        Err(ProtocolError::SenderTranscriptProfile)
    ));
    Ok(())
}

#[test]
fn transport_verifiers_use_checked_sender_transcript() {
    let verifiers = [
        ("SDK ephemeral", include_str!("../../ramflux-sdk/src/ephemeral/lifetime.rs")),
        ("SDK durable", include_str!("../../ramflux-sdk/src/client/routed/auth.rs")),
        ("SDK own copy", include_str!("../../ramflux-sdk/src/client/own_device_copy.rs")),
        ("node source and forwarder", include_str!("../../ramflux-node-core/src/device_source.rs")),
        ("custody", include_str!("../../ramflux-node-core/src/custody_delivery.rs")),
        ("gateway", include_str!("../../../apps/ramflux-gateway/src/submit_source.rs")),
    ];
    for (name, source) in verifiers {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            production.contains("verify_envelope_sender_signature("),
            "missing checked verifier: {name}"
        );
        assert!(
            !production.contains("verify_canonical_signature("),
            "manual envelope verification bypass: {name}"
        );
    }
    assert!(
        include_str!("../../ramflux-node-core/src/router/c1_view.rs")
            .contains("authority.verify_envelope_source(envelope)")
    );
    assert!(
        include_str!("../../ramflux-node-core/src/router_store/sender_retry.rs")
            .contains("envelope_sender_signed_bytes(envelope)")
    );
}

#[test]
fn sender_verification_preserves_strict_ed25519_checks() -> Result<(), ProtocolError> {
    let mut identity_key = [0; 32];
    identity_key[0] = 1;
    let mut signature = [0; 64];
    signature[0] = 1;
    let mut envelope = fixture()?["envelope"].clone();
    envelope["signature"] = json!(encode_base64url(signature));
    assert!(matches!(
        verify_sender_signature(
            &envelope,
            SenderTranscriptMode::WithCiphertext,
            &encode_base64url(identity_key)
        ),
        Err(ProtocolError::SignatureVerificationFailed)
    ));
    Ok(())
}
