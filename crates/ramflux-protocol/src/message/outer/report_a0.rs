// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical P06 A0 for report commitments (Decision 5 exclusions by omission).

use serde::{Deserialize, Serialize};

use super::{CandidateDeliveryClass, NamedDeliveryMode};
use crate::{ProtocolError, SignatureAlg, canonical_json_bytes};

/// Sender outer fields bound into C. Excludes ciphertext, `payload_hash`,
/// sender signature, `report_commitment`, and appended node metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateReportA0 {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub source_device_id: String,
    pub target_delivery_id: String,
    pub delivery_class: CandidateDeliveryClass,
    pub priority: crate::Priority,
    pub ttl_seconds: u32,
    pub created_at: i64,
    pub collapse_tag: String,
    pub delivery_mode: NamedDeliveryMode,
    pub signing_key_id: String,
    pub signature_alg: SignatureAlg,
    pub source_authority: String,
}

/// Canonical P06 outer-codec bytes for A0.
///
/// # Errors
/// Returns canonical JSON failures.
pub fn encode_candidate_report_a0(fields: &CandidateReportA0) -> Result<Vec<u8>, ProtocolError> {
    canonical_json_bytes(fields)
}

/// Rebuild A0 from a received live envelope (candidate profile).
///
/// # Errors
/// Returns [`ProtocolError::InvalidDomain`] when named candidate fields are absent.
pub fn candidate_report_a0_from_envelope(
    envelope: &crate::Envelope,
) -> Result<CandidateReportA0, ProtocolError> {
    let delivery_mode = match envelope.delivery_mode.as_deref() {
        Some("durable") => NamedDeliveryMode::Durable,
        Some("ephemeral") => NamedDeliveryMode::Ephemeral,
        _ => {
            return Err(ProtocolError::InvalidDomain {
                expected: "durable|ephemeral",
                actual: envelope.delivery_mode.clone().unwrap_or_default(),
            });
        }
    };
    let collapse_tag = envelope.collapse_tag.clone().ok_or_else(|| {
        ProtocolError::InvalidDomain { expected: "collapse_tag", actual: String::new() }
    })?;
    let source_authority = envelope
        .ext
        .ext
        .get("source_root_commitment")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProtocolError::InvalidDomain {
            expected: "source_authority",
            actual: String::new(),
        })?
        .to_owned();
    Ok(CandidateReportA0 {
        schema: envelope.schema.clone(),
        version: envelope.version,
        domain: envelope.domain.clone(),
        envelope_id: envelope.envelope_id.clone(),
        source_principal_id: envelope.source_principal_id.clone(),
        source_device_id: envelope.source_device_id.clone(),
        target_delivery_id: envelope.target_delivery_id.clone(),
        delivery_class: candidate_delivery_class(&envelope.delivery_class)?,
        priority: envelope.priority.clone(),
        ttl_seconds: envelope.ttl,
        created_at: envelope.created_at,
        collapse_tag,
        delivery_mode,
        signing_key_id: envelope.signed.signing_key_id.clone(),
        signature_alg: envelope.signed.signature_alg.clone(),
        source_authority,
    })
}

fn candidate_delivery_class(
    class: &crate::DeliveryClass,
) -> Result<CandidateDeliveryClass, ProtocolError> {
    match class {
        crate::DeliveryClass::Message | crate::DeliveryClass::OpaqueEvent => {
            Ok(CandidateDeliveryClass::Message)
        }
        crate::DeliveryClass::CallWake | crate::DeliveryClass::NotificationWake => {
            Ok(CandidateDeliveryClass::CallWake)
        }
        _ => {
            Err(ProtocolError::InvalidDomain { expected: "message", actual: format!("{class:?}") })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::outer::{CandidateDeliveryClass, NamedDeliveryMode};
    use crate::{Priority, ProtocolError, SignatureAlg};

    const PINNED_A0_HEX: &str = "7b22636f6c6c617073655f746167223a2249694969496949694969496949694969496949694969496949694969496949694969496949694969496949222c22637265617465645f6174223a313736323132383030302c2264656c69766572795f636c617373223a226d657373616765222c2264656c69766572795f6d6f6465223a2264757261626c65222c22646f6d61696e223a2272616d666c75782e656e76656c6f70652e7631222c22656e76656c6f70655f6964223a22656e76656c6f7065222c227072696f72697479223a226e6f726d616c222c22736368656d61223a2272616d666c75782e656e76656c6f70652e7631222c227369676e61747572655f616c67223a2265643235353139222c227369676e696e675f6b65795f6964223a2266697874757265222c22736f757263655f617574686f72697479223a22222c22736f757263655f6465766963655f6964223a22646576696365222c22736f757263655f7072696e636970616c5f6964223a227072696e636970616c222c227461726765745f64656c69766572795f6964223a22746172676574222c2274746c5f7365636f6e6473223a3330302c2276657273696f6e223a317d";

    fn vector_a0() -> CandidateReportA0 {
        CandidateReportA0 {
            schema: crate::domain::ENVELOPE.to_owned(),
            version: 1,
            domain: crate::domain::ENVELOPE.to_owned(),
            envelope_id: "envelope".to_owned(),
            source_principal_id: "principal".to_owned(),
            source_device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            delivery_class: CandidateDeliveryClass::Message,
            priority: Priority::Normal,
            ttl_seconds: 300,
            created_at: 1_762_128_000,
            collapse_tag: crate::encode_base64url([0x22_u8; 32]),
            delivery_mode: NamedDeliveryMode::Durable,
            signing_key_id: "fixture".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            source_authority: String::new(),
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    #[test]
    fn pinned_candidate_report_a0_bytes() -> Result<(), ProtocolError> {
        let encoded = encode_candidate_report_a0(&vector_a0())?;
        assert_eq!(hex_encode(&encoded), PINNED_A0_HEX);
        Ok(())
    }

    fn envelope(class: crate::DeliveryClass, authority: Option<&str>) -> crate::Envelope {
        let mut envelope = crate::Envelope {
            schema: crate::domain::ENVELOPE.to_owned(),
            version: 1,
            domain: crate::domain::ENVELOPE.to_owned(),
            ext: crate::Ext::default(),
            signed: crate::SignedFields {
                signing_key_id: "device:alice".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: String::new(),
            },
            envelope_id: "envelope".to_owned(),
            source_principal_id: "alice".to_owned(),
            source_device_id: "alice".to_owned(),
            target_delivery_id: "bob".to_owned(),
            routing_set_id: None,
            delivery_class: class,
            priority: Priority::Normal,
            ttl: 300,
            created_at: 1,
            encrypted_payload: String::new(),
            payload_hash: String::new(),
            delivery_mode: Some("durable".to_owned()),
            collapse_tag: Some(crate::encode_base64url([0x22_u8; 32])),
            report_commitment: Some(crate::encode_base64url([0x33_u8; 32])),
        };
        if let Some(authority) = authority {
            envelope.ext.ext.insert(
                "source_root_commitment".into(),
                serde_json::Value::String(authority.to_owned()),
            );
        }
        envelope
    }

    #[test]
    fn from_envelope_uses_device_signing_key_id_and_message_class() -> Result<(), ProtocolError> {
        let a0 = candidate_report_a0_from_envelope(&envelope(
            crate::DeliveryClass::OpaqueEvent,
            Some("anchor"),
        ))?;
        assert_eq!(a0.signing_key_id, "device:alice");
        assert_eq!(a0.delivery_class, CandidateDeliveryClass::Message);
        assert_eq!(a0.source_authority, "anchor");
        Ok(())
    }

    #[test]
    fn from_envelope_maps_notification_wake_to_call_wake() -> Result<(), ProtocolError> {
        let a0 = candidate_report_a0_from_envelope(&envelope(
            crate::DeliveryClass::NotificationWake,
            Some("anchor"),
        ))?;
        assert_eq!(a0.delivery_class, CandidateDeliveryClass::CallWake);
        Ok(())
    }

    #[test]
    fn from_envelope_refuses_missing_source_authority() {
        let missing =
            candidate_report_a0_from_envelope(&envelope(crate::DeliveryClass::OpaqueEvent, None));
        assert!(matches!(
            missing,
            Err(ProtocolError::InvalidDomain { expected: "source_authority", .. })
        ));
        let mut empty = envelope(crate::DeliveryClass::OpaqueEvent, Some(""));
        empty
            .ext
            .ext
            .insert("source_root_commitment".into(), serde_json::Value::String(String::new()));
        assert!(matches!(
            candidate_report_a0_from_envelope(&empty),
            Err(ProtocolError::InvalidDomain { expected: "source_authority", .. })
        ));
    }
}
