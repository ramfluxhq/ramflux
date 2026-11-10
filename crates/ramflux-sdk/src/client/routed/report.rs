// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Direct routed report commitment, collapse tag, and receiver C check (S10a P07b1).

use super::{RamfluxClient, invalid};
use crate::prelude::*;
use ramflux_protocol::message::outer::{
    CandidateDeliveryClass, CandidateReportA0, NamedDeliveryMode,
    candidate_report_a0_from_envelope, encode_candidate_report_a0,
};
use zeroize::Zeroizing;

pub(super) struct DirectReport {
    pub collapse_tag: [u8; 32],
    pub report_commitment: [u8; 32],
    pub framed: ramflux_crypto::ReportFrame,
}

/// Fresh kf generated inside the Direct producer.
pub(super) fn fresh_report_opening() -> Result<Zeroizing<[u8; 32]>, SdkError> {
    Ok(Zeroizing::new(ramflux_crypto::random_32()?))
}

pub(super) fn assemble_direct_report(
    client: &RamfluxClient,
    message: &GatewayDirectMessage,
    session: &ramflux_crypto::DmSession,
    inner: &[u8],
    local_device_id: &str,
) -> Result<DirectReport, SdkError> {
    let opening = fresh_report_opening()?;
    let kcollapse = ramflux_crypto::collapse_key(
        session.root_key.expose(),
        &session.bootstrap_transcript_hash,
    )?;
    let collapse_tag = ramflux_crypto::collapse_tag(
        &kcollapse,
        message.conversation_id.as_bytes(),
        message.target_delivery_id.as_bytes(),
    )?;
    let source_principal_id = client
        .device_branch
        .as_ref()
        .map_or_else(|| message.source_principal_id.clone(), |branch| branch.principal_id.clone());
    let a0 = CandidateReportA0 {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        envelope_id: message.envelope_id.clone(),
        source_principal_id,
        source_device_id: local_device_id.to_owned(),
        target_delivery_id: message.target_delivery_id.clone(),
        delivery_class: CandidateDeliveryClass::Message,
        priority: ramflux_protocol::Priority::Normal,
        ttl_seconds: message.ttl,
        created_at: message.created_at,
        collapse_tag: ramflux_protocol::encode_base64url(collapse_tag),
        delivery_mode: NamedDeliveryMode::Durable,
        signing_key_id: "fixture".to_owned(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        source_authority: client.own_account_anchor()?,
    };
    let a0_bytes = encode_candidate_report_a0(&a0)?;
    let report_commitment = ramflux_crypto::report_commitment(&opening, inner, &a0_bytes)?;
    Ok(DirectReport {
        collapse_tag,
        report_commitment,
        framed: ramflux_crypto::frame_report_plaintext(inner, &opening)?,
    })
}

pub(super) fn opened_inner_plaintext(
    envelope: &ramflux_protocol::Envelope,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let Some(commitment) = envelope.report_commitment.as_deref() else {
        return Ok(Zeroizing::new(plaintext.to_vec()));
    };
    let parsed = ramflux_crypto::parse_report_plaintext(plaintext)?;
    let expected = decode_fixed_32(commitment, "report_commitment")?;
    let a0 = candidate_report_a0_from_envelope(envelope)?;
    let a0_bytes = encode_candidate_report_a0(&a0)?;
    ramflux_crypto::verify_report_opening(parsed.opening(), parsed.inner(), &a0_bytes, &expected)?;
    Ok(Zeroizing::new(parsed.inner().to_vec()))
}

fn decode_fixed_32(value: &str, field: &'static str) -> Result<[u8; 32], SdkError> {
    let raw = ramflux_protocol::decode_base64url(value)
        .map_err(|_| invalid(&format!("{field} must be 32 bytes")))?;
    raw.as_slice().try_into().map_err(|_| invalid(&format!("{field} must be 32 bytes")))
}
