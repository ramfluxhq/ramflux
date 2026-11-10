// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Direct routed report commitment, collapse tag, and receiver C check (S10a P07b1).

use super::{RamfluxClient, invalid};
use crate::gateway::helpers::sdk_device_signed_fields;
use crate::prelude::*;
use ramflux_protocol::message::outer::{
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

thread_local! {
    static COMMITTED_REPORT_A0: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static OMIT_DIRECT_REPORT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[must_use]
pub(super) fn omit_direct_report() -> bool {
    #[cfg(test)]
    {
        OMIT_DIRECT_REPORT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    false
}

#[cfg(test)]
pub(super) fn set_omit_direct_report(omit: bool) {
    OMIT_DIRECT_REPORT.with(|cell| cell.set(omit));
}

pub(crate) fn take_committed_report_a0() -> Option<Vec<u8>> {
    COMMITTED_REPORT_A0.with(|cell| cell.borrow_mut().take())
}

#[cfg(test)]
pub(super) fn set_committed_report_a0(bytes: Vec<u8>) {
    COMMITTED_REPORT_A0.with(|cell| *cell.borrow_mut() = Some(bytes));
}

pub(crate) fn refuse_a0_mismatch(
    envelope: &ramflux_protocol::Envelope,
    committed: &[u8],
) -> Result<(), SdkError> {
    let live = encode_candidate_report_a0(
        &candidate_report_a0_from_envelope(envelope)
            .map_err(|error| invalid(&error.to_string()))?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    if live.as_slice() != committed {
        return Err(invalid("report a0 drifted from sealed envelope"));
    }
    Ok(())
}

pub(super) fn assemble_direct_report(
    client: &RamfluxClient,
    message: &GatewayDirectMessage,
    session: &ramflux_crypto::DmSession,
    inner: &[u8],
    local_device_id: &str,
    recipient: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<DirectReport, SdkError> {
    let kcollapse =
        session.collapse_key().ok_or(ramflux_crypto::CryptoError::MissingCollapseKey)?;
    let collapse_tag = ramflux_crypto::collapse_tag(
        kcollapse,
        message.conversation_id.as_bytes(),
        recipient.storage_key().as_bytes(),
    )?;
    let opening = fresh_report_opening()?;
    let a0 = candidate_report_a0_from_envelope(&report_a0_envelope(
        client,
        message,
        local_device_id,
        &ramflux_protocol::encode_base64url(collapse_tag),
    )?)?;
    let a0_bytes = encode_candidate_report_a0(&a0)?;
    let report_commitment = ramflux_crypto::report_commitment(&opening, inner, &a0_bytes)?;
    COMMITTED_REPORT_A0.with(|cell| *cell.borrow_mut() = Some(a0_bytes));
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

pub(super) fn refuse_direct_candidate_opening(
    envelope: &ramflux_protocol::Envelope,
    session: &ramflux_crypto::DmSession,
    kind: &super::Kind,
) -> Result<(), SdkError> {
    if *kind != super::Kind::Direct || !crate::client::target_selection::schema_v1_selected() {
        return Ok(());
    }
    if envelope.report_commitment.is_none() {
        return Err(SdkError::Crypto(ramflux_crypto::CryptoError::ReportCommitmentMissing));
    }
    if session.collapse_key().is_none() {
        return Err(SdkError::Crypto(ramflux_crypto::CryptoError::MissingCollapseKey));
    }
    Ok(())
}

pub(super) fn refuse_payload_outer_mismatch(
    outer: &ramflux_protocol::Envelope,
    nested: &SdkDmEncryptedEnvelope,
) -> Result<(), SdkError> {
    let tag_mismatch = nested
        .collapse_tag
        .as_deref()
        .is_some_and(|tag| Some(tag) != outer.collapse_tag.as_deref());
    let commitment_mismatch = nested
        .report_commitment
        .as_deref()
        .is_some_and(|commitment| Some(commitment) != outer.report_commitment.as_deref());
    if tag_mismatch || commitment_mismatch {
        return Err(invalid("payload report fields must match outer"));
    }
    Ok(())
}

fn report_a0_envelope(
    client: &RamfluxClient,
    message: &GatewayDirectMessage,
    local_device_id: &str,
    collapse_tag: &str,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let source_principal_id = client
        .device_branch
        .as_ref()
        .map_or_else(|| message.source_principal_id.clone(), |branch| branch.principal_id.clone());
    let mut envelope = ramflux_protocol::Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_device_signed_fields(local_device_id, ""),
        envelope_id: message.envelope_id.clone(),
        source_principal_id,
        source_device_id: local_device_id.to_owned(),
        target_delivery_id: message.target_delivery_id.clone(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: message.ttl,
        created_at: message.created_at,
        encrypted_payload: String::new(),
        payload_hash: String::new(),
        delivery_mode: Some("durable".to_owned()),
        collapse_tag: Some(collapse_tag.to_owned()),
        report_commitment: None,
    };
    envelope.ext.ext.insert(
        "source_root_commitment".into(),
        serde_json::Value::String(client.own_account_anchor()?),
    );
    Ok(envelope)
}

fn decode_fixed_32(value: &str, field: &'static str) -> Result<[u8; 32], SdkError> {
    let raw = ramflux_protocol::decode_base64url(value)
        .map_err(|_| invalid(&format!("{field} must be 32 bytes")))?;
    raw.as_slice().try_into().map_err(|_| invalid(&format!("{field} must be 32 bytes")))
}
