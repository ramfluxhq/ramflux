// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate outer-envelope transport serializer (S10a P06, dormant).
//!
//! Live gateway JSON frames stay on [`crate::MAX_GATEWAY_FRAME_BYTES`] and the
//! existing length-prefixed codecs. This module encodes the v1 candidate outer
//! type only.

use ramflux_protocol::message::outer::{
    CandidateOuterEnvelope, MAX_COMPLETE_FRAME_BYTES, decode_candidate_outer_ijson,
};

use crate::TransportError;

/// Length-prefix and admit a candidate outer envelope.
///
/// # Errors
/// Returns [`TransportError::FrameTooLarge`] when the canonical body exceeds the
/// shared 1 MiB gateway cap, or a protocol error when encoding fails.
pub fn encode_candidate_outer_frame(
    outer: &CandidateOuterEnvelope,
) -> Result<Vec<u8>, TransportError> {
    let body = ramflux_protocol::canonical_json_bytes(outer)?;
    if body.len() > crate::MAX_GATEWAY_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge { len: body.len() });
    }
    let len =
        u32::try_from(body.len()).map_err(|_| TransportError::FrameTooLarge { len: body.len() })?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Split a candidate outer frame and decode through I-JSON plus the named-mode profile.
///
/// # Errors
/// Frame-length, I-JSON, or profile refusals.
pub fn decode_candidate_outer_frame(
    frame: &[u8],
) -> Result<CandidateOuterEnvelope, TransportError> {
    if frame.len() < 4 {
        return Err(TransportError::FrameTooShort { len: frame.len() });
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > crate::MAX_GATEWAY_FRAME_BYTES || 4 + len != frame.len() {
        return Err(TransportError::FrameTooLarge { len });
    }
    decode_candidate_outer_ijson(&frame[4..]).map_err(|error| {
        TransportError::Protocol(ramflux_protocol::ProtocolError::TransportProtocol(
            error.to_string(),
        ))
    })
}

const _: () = assert!(crate::MAX_GATEWAY_FRAME_BYTES == MAX_COMPLETE_FRAME_BYTES);

#[cfg(test)]
mod tests {
    use super::{decode_candidate_outer_frame, encode_candidate_outer_frame};
    use ramflux_protocol::message::outer::{
        CANDIDATE_ENVELOPE_SCHEMA, CandidateDeliveryClass, CandidateOuterEnvelope,
        NamedDeliveryMode,
    };
    use ramflux_protocol::{DeliveryClass, Envelope, Ext};
    use ramflux_protocol::{Priority, SignatureAlg, SignedFields, canonical_json_bytes, domain};

    fn candidate() -> CandidateOuterEnvelope {
        CandidateOuterEnvelope {
            schema: CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
            version: 2,
            domain: domain::ENVELOPE.to_owned(),
            envelope_id: "envelope".to_owned(),
            source_principal_id: "principal".to_owned(),
            source_device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            delivery_class: CandidateDeliveryClass::Message,
            priority: Priority::Normal,
            ttl_seconds: 300,
            created_at: 1_762_128_000,
            encrypted_payload: "payload".to_owned(),
            payload_hash: "hash".to_owned(),
            collapse_tag: ramflux_protocol::encode_base64url([0x22_u8; 32]),
            delivery_mode: NamedDeliveryMode::Durable,
            node_report_receipt: None,
            signed: SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
        }
    }

    #[test]
    fn candidate_frame_round_trips_under_shared_cap() -> Result<(), Box<dyn std::error::Error>> {
        let frame = encode_candidate_outer_frame(&candidate())?;
        let decoded = decode_candidate_outer_frame(&frame)?;
        assert_eq!(decoded.delivery_mode, NamedDeliveryMode::Durable);
        assert_eq!(decoded.delivery_class, CandidateDeliveryClass::Message);
        Ok(())
    }

    #[test]
    fn live_envelope_json_bytes_do_not_use_candidate_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let envelope = Envelope {
            schema: domain::ENVELOPE.to_owned(),
            version: 1,
            domain: domain::ENVELOPE.to_owned(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            envelope_id: "envelope".to_owned(),
            source_principal_id: "principal".to_owned(),
            source_device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Normal,
            ttl: 300,
            created_at: 1_000,
            encrypted_payload: "payload".to_owned(),
            payload_hash: "hash".to_owned(),
            delivery_mode: None,
            collapse_tag: None,
        };
        let live = canonical_json_bytes(&envelope)?;
        assert!(
            !live
                .windows(CANDIDATE_ENVELOPE_SCHEMA.len())
                .any(|w| w == CANDIDATE_ENVELOPE_SCHEMA.as_bytes())
        );
        assert_eq!(live, canonical_json_bytes(&serde_json::from_slice::<Envelope>(&live)?)?);
        Ok(())
    }

    #[test]
    fn short_candidate_frame_is_truncated_not_too_large() -> Result<(), Box<dyn std::error::Error>>
    {
        match decode_candidate_outer_frame(&[0, 1, 2]) {
            Err(error) => {
                assert_eq!(error.to_string(), "frame too short: 3 bytes");
                Ok(())
            }
            Ok(_) => Err("short frame must be refused".into()),
        }
    }
}
