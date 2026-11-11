// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate node report receipts (S10a P08). Unwired on live ingress until P24.

use ramflux_protocol::message::outer::CandidateOuterEnvelope;
use serde::{Deserialize, Serialize};

use crate::{NodeCoreError, NodeServiceSigningKey};

/// Independently signed acceptance evidence. Not part of the sender AEAD.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeReportReceipt {
    pub node_id: String,
    pub envelope_id: String,
    pub source_ref: String,
    pub target_delivery_id: String,
    pub report_commitment: String,
    pub payload_hash: String,
    pub accepted_at: u64,
    pub signature: String,
}

/// Per-message group opening plus native author proof required for group reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupReportEvidence<'a> {
    pub inner: &'a [u8],
    pub opening: &'a [u8; 32],
    pub a0: &'a [u8],
    pub group_message_opening: &'a [u8],
    pub native_author_proof: &'a [u8],
}

fn source_ref(envelope: &CandidateOuterEnvelope) -> Result<String, NodeCoreError> {
    ramflux_protocol::qualified_device_id(&envelope.source_principal_id, &envelope.source_device_id)
        .map_err(|error| NodeCoreError::InvalidConfiguration(error.to_string()))
}

fn commitment_bytes(encoded: &str) -> Result<[u8; 32], NodeCoreError> {
    let raw = ramflux_protocol::decode_base64url(encoded)
        .map_err(|error| NodeCoreError::InvalidConfiguration(error.to_string()))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
        NodeCoreError::InvalidConfiguration("report_commitment must be 32 bytes".into())
    })
}

fn receipt_input<'a>(
    receipt: &'a NodeReportReceipt,
    source_ref: &'a str,
    commitment: &'a [u8; 32],
) -> ramflux_crypto::NodeReportReceiptInput<'a> {
    ramflux_crypto::NodeReportReceiptInput {
        node_id: receipt.node_id.as_str(),
        envelope_id: receipt.envelope_id.as_str(),
        authenticated_source_ref: source_ref.as_bytes(),
        target_delivery_id: receipt.target_delivery_id.as_str(),
        report_commitment: commitment,
        payload_hash: receipt.payload_hash.as_str(),
        accepted_at: receipt.accepted_at,
    }
}

/// Append a v2 receipt using outer C and `payload_hash`. Does not decrypt Inner.
///
/// # Errors
/// Missing/invalid C, identity encoding, signing, or JSON.
pub fn append_node_report_receipt(
    envelope: &mut CandidateOuterEnvelope,
    node_id: &str,
    signer: &NodeServiceSigningKey,
    accepted_at: u64,
) -> Result<NodeReportReceipt, NodeCoreError> {
    let source = source_ref(envelope)?;
    let report_commitment = commitment_bytes(&envelope.report_commitment)?;
    let mut receipt = NodeReportReceipt {
        node_id: node_id.to_owned(),
        envelope_id: envelope.envelope_id.clone(),
        source_ref: source,
        target_delivery_id: envelope.target_delivery_id.clone(),
        report_commitment: envelope.report_commitment.clone(),
        payload_hash: envelope.payload_hash.clone(),
        accepted_at,
        signature: String::new(),
    };
    let input = receipt_input(&receipt, &receipt.source_ref, &report_commitment);
    receipt.signature = signer
        .sign_node_report_receipt(input)
        .map_err(|error| NodeCoreError::InvalidConfiguration(error.to_string()))?;
    envelope.node_report_receipt = Some(
        serde_json::to_value(&receipt)
            .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
    );
    Ok(receipt)
}

/// Verify a receipt against the envelope using the trusted node record key.
///
/// # Errors
/// Binding mismatch or a signature that does not match `trusted_node_public_key`.
pub fn verify_bound_node_report_receipt(
    envelope: &CandidateOuterEnvelope,
    receipt: &NodeReportReceipt,
    trusted_node_public_key: &str,
) -> Result<(), NodeCoreError> {
    let source = source_ref(envelope)?;
    if receipt.envelope_id != envelope.envelope_id
        || receipt.source_ref != source
        || receipt.target_delivery_id != envelope.target_delivery_id
        || receipt.report_commitment != envelope.report_commitment
        || receipt.payload_hash != envelope.payload_hash
    {
        return Err(NodeCoreError::InvalidConfiguration(
            ramflux_crypto::CryptoError::NodeReportReceiptMismatch.to_string(),
        ));
    }
    let commitment = commitment_bytes(&receipt.report_commitment)?;
    ramflux_crypto::verify_node_report_receipt(
        &receipt_input(receipt, &receipt.source_ref, &commitment),
        &receipt.signature,
        trusted_node_public_key,
    )
    .map_err(|error| NodeCoreError::InvalidConfiguration(error.to_string()))
}

/// Group reports need the verified Inner opening **and** native author proof.
///
/// # Errors
/// Missing group opening/author, C mismatch, or untrusted node receipt.
pub fn verify_group_report_evidence(
    envelope: &CandidateOuterEnvelope,
    receipt: &NodeReportReceipt,
    evidence: GroupReportEvidence<'_>,
    trusted_node_public_key: &str,
) -> Result<(), NodeCoreError> {
    if evidence.group_message_opening.is_empty() {
        return Err(NodeCoreError::InvalidConfiguration(
            ramflux_crypto::CryptoError::GroupReportOpeningMissing.to_string(),
        ));
    }
    if evidence.native_author_proof.is_empty() {
        return Err(NodeCoreError::InvalidConfiguration(
            ramflux_crypto::CryptoError::GroupReportAuthorMissing.to_string(),
        ));
    }
    let expected = ramflux_crypto::report_commitment(evidence.opening, evidence.inner, evidence.a0)
        .map_err(|error| NodeCoreError::InvalidConfiguration(error.to_string()))?;
    let got = commitment_bytes(&envelope.report_commitment)?;
    if expected != got {
        return Err(NodeCoreError::InvalidConfiguration(
            ramflux_crypto::CryptoError::ReportCommitmentMismatch.to_string(),
        ));
    }
    verify_bound_node_report_receipt(envelope, receipt, trusted_node_public_key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use ramflux_protocol::message::client_class::{
        ClientDeliveryClass, ProviderPush, client_class_from_delivery,
        client_class_from_notification, provider_push,
    };
    use ramflux_protocol::message::outer::{
        CANDIDATE_ENVELOPE_SCHEMA, CandidateDeliveryClass, CandidateOuterEnvelope,
        NamedDeliveryMode,
    };
    use ramflux_protocol::{
        DeliveryClass, NotificationDeliveryClass, Priority, SignatureAlg, SignedFields,
    };

    fn outer() -> CandidateOuterEnvelope {
        let commitment = ramflux_protocol::encode_base64url([0xC1; 32]);
        CandidateOuterEnvelope {
            ext: ramflux_protocol::Ext::default(),
            routing_set_id: None,
            schema: CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
            version: 2,
            domain: "ramflux.envelope.v2".to_owned(),
            envelope_id: "env-p08".into(),
            source_principal_id: "alice".into(),
            source_device_id: "device-a".into(),
            target_delivery_id: "bob".into(),
            delivery_class: CandidateDeliveryClass::Message,
            priority: Priority::Normal,
            ttl_seconds: 300,
            created_at: 1,
            encrypted_payload: "ciphertext".into(),
            payload_hash: "payload-hash".into(),
            collapse_tag: ramflux_protocol::encode_base64url([0x11; 32]),
            delivery_mode: NamedDeliveryMode::Durable,
            node_report_receipt: None,
            signed: SignedFields {
                signing_key_id: "device:alice".into(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "sig".into(),
            },
            report_commitment: commitment,
        }
    }

    #[test]
    fn report_receipt_accepts_only_bound_opening_and_trusted_node() {
        let trusted = NodeServiceSigningKey::from_seed([0x81; 32]);
        let reporter = NodeServiceSigningKey::from_seed([0x82; 32]);
        let mut envelope = outer();
        let receipt =
            append_node_report_receipt(&mut envelope, "node-p08", &trusted, 1_760_000_001)
                .expect("append");
        assert!(envelope.node_report_receipt.is_some());
        verify_bound_node_report_receipt(&envelope, &receipt, trusted.public_key_base64url())
            .expect("trusted");
        assert!(
            verify_bound_node_report_receipt(&envelope, &receipt, reporter.public_key_base64url())
                .is_err(),
            "reporter-supplied key must not verify"
        );
        let mut drifted = envelope.clone();
        drifted.payload_hash = "other-hash".into();
        assert!(
            verify_bound_node_report_receipt(&drifted, &receipt, trusted.public_key_base64url())
                .is_err()
        );
    }

    #[test]
    fn group_report_requires_message_opening_and_native_author() {
        let trusted = NodeServiceSigningKey::from_seed([0x83; 32]);
        let inner = b"group-inner";
        let opening = [0x44; 32];
        let a0 = b"a0-bytes";
        let commitment = ramflux_crypto::report_commitment(&opening, inner, a0).expect("C");
        let mut envelope = outer();
        envelope.report_commitment = ramflux_protocol::encode_base64url(commitment);
        envelope.delivery_class = CandidateDeliveryClass::Message;
        let receipt =
            append_node_report_receipt(&mut envelope, "node-p08", &trusted, 9).expect("append");
        let missing_opening = verify_group_report_evidence(
            &envelope,
            &receipt,
            GroupReportEvidence {
                inner,
                opening: &opening,
                a0,
                group_message_opening: &[],
                native_author_proof: b"author",
            },
            trusted.public_key_base64url(),
        );
        assert!(missing_opening.expect_err("opening").to_string().contains("per-message opening"));
        let missing_author = verify_group_report_evidence(
            &envelope,
            &receipt,
            GroupReportEvidence {
                inner,
                opening: &opening,
                a0,
                group_message_opening: b"open",
                native_author_proof: &[],
            },
            trusted.public_key_base64url(),
        );
        assert!(missing_author.expect_err("author").to_string().contains("native author"));
        verify_group_report_evidence(
            &envelope,
            &receipt,
            GroupReportEvidence {
                inner,
                opening: &opening,
                a0,
                group_message_opening: b"open",
                native_author_proof: b"author-proof",
            },
            trusted.public_key_base64url(),
        )
        .expect("complete group report");
    }

    #[test]
    fn all_classes_producers_consumers_and_push_mapping() {
        assert_eq!(
            client_class_from_delivery(&DeliveryClass::OpaqueEvent).ok(),
            Some(ClientDeliveryClass::Message)
        );
        assert_eq!(
            client_class_from_delivery(&DeliveryClass::SelfDeviceControl).ok(),
            Some(ClientDeliveryClass::Message)
        );
        assert_eq!(
            client_class_from_delivery(&DeliveryClass::NotificationWake).ok(),
            Some(ClientDeliveryClass::CallWake)
        );
        assert!(client_class_from_delivery(&DeliveryClass::ObjectManifest).is_err());
        assert!(client_class_from_delivery(&DeliveryClass::ObjectChunk).is_err());
        assert!(client_class_from_delivery(&DeliveryClass::FederationControl).is_err());
        assert_eq!(provider_push(ClientDeliveryClass::Message, false), ProviderPush::MessageWake);
        assert_eq!(provider_push(ClientDeliveryClass::CallWake, false), ProviderPush::CallWakeVoip);
        assert_eq!(provider_push(ClientDeliveryClass::Message, true), ProviderPush::None);
        assert_eq!(
            client_class_from_notification(&NotificationDeliveryClass::UserContentNotification),
            ClientDeliveryClass::Message
        );
        assert_eq!(
            client_class_from_notification(&NotificationDeliveryClass::CallWakeNotification),
            ClientDeliveryClass::CallWake
        );
    }

    #[test]
    fn conference_invite_maps_to_call_wake() {
        let class =
            client_class_from_notification(&NotificationDeliveryClass::ConferenceWakeNotification);
        assert_eq!(class, ClientDeliveryClass::CallWake);
        assert_ne!(class, ClientDeliveryClass::Message);
        assert_eq!(provider_push(class, false), ProviderPush::CallWakeVoip);
    }
}
