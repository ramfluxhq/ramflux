// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission sidecars preserve every byte covered by the sender's reach route.
use super::{Result, refuse};
use ramflux_protocol::{Envelope, NodeReportReceipt, contact_reach::Reason};

pub(super) fn issue(
    envelope: &Envelope,
    node_id: &str,
    key: &ed25519_dalek::SigningKey,
    accepted_at: u64,
) -> Result<Option<NodeReportReceipt>> {
    let Some(commitment) = ramflux_protocol::message::outer::live_report_commitment_bytes(envelope)
        .map_err(|_| refuse(Reason::ReachRouteInvalid))?
    else {
        return Ok(None);
    };
    let mut receipt = NodeReportReceipt {
        node_id: node_id.into(),
        envelope_id: envelope.envelope_id.clone(),
        source_ref: ramflux_protocol::qualified_device_id(
            &envelope.source_principal_id,
            &envelope.source_device_id,
        )?,
        target_delivery_id: envelope.target_delivery_id.clone(),
        report_commitment: envelope
            .report_commitment
            .clone()
            .ok_or_else(|| refuse(Reason::ReachRouteInvalid))?,
        payload_hash: envelope.payload_hash.clone(),
        accepted_at,
        signature: String::new(),
    };
    receipt.signature = ramflux_crypto::sign_node_report_receipt(
        &ramflux_crypto::NodeReportReceiptInput {
            node_id: &receipt.node_id,
            envelope_id: &receipt.envelope_id,
            authenticated_source_ref: receipt.source_ref.as_bytes(),
            target_delivery_id: &receipt.target_delivery_id,
            report_commitment: &commitment,
            payload_hash: &receipt.payload_hash,
            accepted_at,
        },
        key,
    )?;
    ramflux_crypto::contact_reach::verify_bound_node_report_receipt(
        envelope,
        &receipt,
        &ramflux_protocol::encode_base64url(key.verifying_key().to_bytes()),
    )?;
    Ok(Some(receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_report_receipt_sidecar_keeps_original_envelope_hash()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut envelope = crate::test_support::federation_fixtures::envelope(
            "sealed",
            "target",
            ramflux_protocol::DeliveryClass::Message,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        assert!(
            issue(&envelope, "home.example", &key, 1000)?.is_none(),
            "no report commitment means an explicit null sidecar"
        );
        envelope.report_commitment = Some(ramflux_protocol::encode_base64url([8; 32]));
        let bytes = ramflux_protocol::canonical_json_bytes(&envelope)?;
        let hash = ramflux_protocol::custody::framed_hash(
            ramflux_protocol::contact_reach::ENVELOPE_HASH_DOMAIN,
            &envelope,
        )?;
        let receipt = issue(&envelope, "home.example", &key, 1000)?.ok_or("receipt")?;
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(&envelope)?,
            bytes,
            "home acceptance must never append metadata inside the frozen sender envelope"
        );
        assert_eq!(
            ramflux_protocol::custody::framed_hash(
                ramflux_protocol::contact_reach::ENVELOPE_HASH_DOMAIN,
                &envelope
            )?,
            hash,
            "the original W hash remains valid after receipt issuance"
        );
        ramflux_crypto::contact_reach::verify_bound_node_report_receipt(
            &envelope,
            &receipt,
            &ramflux_crypto::public_key_base64url_from_seed([7; 32]),
        )?;
        let mut changed = envelope;
        changed.payload_hash.push('x');
        assert!(
            ramflux_crypto::contact_reach::verify_bound_node_report_receipt(
                &changed,
                &receipt,
                &ramflux_crypto::public_key_base64url_from_seed([7; 32]),
            )
            .is_err(),
            "the sidecar cannot be transplanted to different sender bytes"
        );
        Ok(())
    }
}
