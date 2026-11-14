// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify home acceptance evidence beside the original sender envelope.
use super::{CryptoError, reject};
use ramflux_protocol::{Envelope, NodeReportReceipt};

pub(super) fn input<'a>(
    receipt: &'a NodeReportReceipt,
    commitment: &'a [u8; 32],
) -> crate::NodeReportReceiptInput<'a> {
    crate::NodeReportReceiptInput {
        node_id: &receipt.node_id,
        envelope_id: &receipt.envelope_id,
        authenticated_source_ref: receipt.source_ref.as_bytes(),
        target_delivery_id: &receipt.target_delivery_id,
        report_commitment: commitment,
        payload_hash: &receipt.payload_hash,
        accepted_at: receipt.accepted_at,
    }
}

/// Authenticate the receipt against the unchanged envelope and an independently trusted home key.
/// # Errors
/// Refuses oversized evidence, changed bindings, missing commitment and invalid home signatures.
pub fn verify_bound_node_report_receipt(
    envelope: &Envelope,
    receipt: &NodeReportReceipt,
    home_key: &str,
) -> Result<(), CryptoError> {
    let source = ramflux_protocol::qualified_device_id(
        &envelope.source_principal_id,
        &envelope.source_device_id,
    )?;
    if ramflux_protocol::canonical_json_bytes(receipt)?.len() > 2048
        || receipt.envelope_id != envelope.envelope_id
        || receipt.source_ref != source
        || receipt.target_delivery_id != envelope.target_delivery_id
        || Some(receipt.report_commitment.as_str()) != envelope.report_commitment.as_deref()
        || receipt.payload_hash != envelope.payload_hash
        || receipt.accepted_at > ramflux_protocol::MAX_SAFE_JSON_INTEGER
    {
        return Err(reject("reach report receipt binding"));
    }
    let commitment = ramflux_protocol::message::outer::require_live_report_commitment(envelope)
        .map_err(|_| reject("reach report commitment"))?;
    crate::verify_node_report_receipt(&input(receipt, &commitment), &receipt.signature, home_key)
}
