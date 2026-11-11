// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
#[test]
fn generic_v2_senders_use_checked_transcript() -> Result<(), Box<dyn std::error::Error>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let mut envelope = fixture["envelope"].clone();
    envelope["signature"] = serde_json::json!(sign_protocol_object(&envelope)?);
    ramflux_protocol::verify_sender_signature(
        &envelope,
        ramflux_protocol::SenderTranscriptMode::WithCiphertext,
        &fixture_public_key_base64url(),
    )?;
    envelope["signature"] = serde_json::json!(sign_protocol_object_with_seed(&envelope, [17; 32])?);
    let evidence: serde_json::Value =
        serde_json::from_slice(&ramflux_protocol::sender_origin_evidence(&envelope)?)?;
    ramflux_protocol::verify_sender_signature(
        &evidence,
        ramflux_protocol::SenderTranscriptMode::Evidence,
        &public_key_base64url_from_seed([17; 32]),
    )?;
    envelope["encrypted_payload"] = serde_json::json!("b3RoZXI");
    assert!(matches!(
        sign_protocol_object(&envelope),
        Err(CryptoError::Protocol(ramflux_protocol::ProtocolError::PayloadHashMismatch))
    ));
    assert!(matches!(
        sign_protocol_object_with_seed(&envelope, [17; 32]),
        Err(CryptoError::Protocol(ramflux_protocol::ProtocolError::PayloadHashMismatch))
    ));
    Ok(())
}
