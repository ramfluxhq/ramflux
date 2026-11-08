// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::expect_used)]

use super::{
    COLLAPSE_KEY_INFO, REPORT_OPENING_DOMAIN, ReportA0, ReportDeliveryClass, ReportDeliveryMode,
    ReportPriority, assemble_report_opening, collapse_key, collapse_tag, cover_collapse_tag,
    encode_report_a0, frame_report_plaintext, parse_report_plaintext, report_commitment,
    verify_report_opening,
};
use crate::CryptoError;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const VECTOR_CREATED_AT: u64 = 1_762_128_000;
const VECTOR_TTL_SECONDS: u64 = 300;
const VECTOR_INNER: &[u8] = b"s10a-p07-inner:A\xF0\x9F\x98\x80\xC3\xA9";

fn vector_opening() -> [u8; 32] {
    [0x33; 32]
}

fn vector_collapse() -> [u8; 32] {
    [0x22; 32]
}

fn vector_envelope_id() -> Vec<u8> {
    ramflux_protocol::encode_base64url([0x11; 32]).into_bytes()
}

fn vector_a0_fields(collapse: &[u8; 32]) -> ReportA0<'_> {
    ReportA0 {
        envelope_id: b"",
        source_principal_id: b"vector-source",
        source_device_id: b"vector-device",
        target_delivery_id: b"vector-target",
        delivery_class: ReportDeliveryClass::Message,
        priority: ReportPriority::Normal,
        ttl_seconds: VECTOR_TTL_SECONDS,
        created_at: VECTOR_CREATED_AT,
        collapse_tag: collapse,
        delivery_mode: ReportDeliveryMode::Durable,
    }
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("fixture fits u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn independent_a0(fields: &ReportA0<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, fields.envelope_id);
    lp(&mut out, fields.source_principal_id);
    lp(&mut out, fields.source_device_id);
    lp(&mut out, fields.target_delivery_id);
    lp(&mut out, fields.delivery_class.as_bytes());
    lp(&mut out, fields.priority.as_bytes());
    out.extend_from_slice(&fields.ttl_seconds.to_be_bytes());
    out.extend_from_slice(&fields.created_at.to_be_bytes());
    lp(&mut out, fields.collapse_tag);
    lp(&mut out, fields.delivery_mode.as_bytes());
    out
}

fn independent_commitment(opening: &[u8; 32], inner: &[u8], a0: &[u8]) -> [u8; 32] {
    let mut context = Vec::new();
    lp(&mut context, REPORT_OPENING_DOMAIN.as_bytes());
    lp(&mut context, inner);
    lp(&mut context, a0);
    let mut hasher = blake3::Hasher::new_keyed(opening);
    hasher.update(&context);
    hasher.finalize().into()
}

fn independent_collapse_key(sk: &[u8], pair_binding: &[u8]) -> [u8; 32] {
    let mut extract = <Hmac<Sha256> as KeyInit>::new_from_slice(pair_binding).expect("salt");
    extract.update(sk);
    let prk = extract.finalize().into_bytes();
    let mut expand = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).expect("prk");
    expand.update(&[]);
    expand.update(COLLAPSE_KEY_INFO.as_bytes());
    expand.update(&[1_u8]);
    let block = expand.finalize().into_bytes();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&block);
    key
}

fn independent_collapse_tag(
    kcollapse: &[u8; 32],
    conversation_id: &[u8],
    recipient_device_ref: &[u8],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(kcollapse).expect("hmac");
    let mut tagged = Vec::new();
    lp(&mut tagged, conversation_id);
    lp(&mut tagged, recipient_device_ref);
    mac.update(&tagged);
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0_u8; 32];
    tag.copy_from_slice(&bytes);
    tag
}

fn vector_fields<'a>(envelope_id: &'a [u8], collapse: &'a [u8; 32]) -> ReportA0<'a> {
    let mut fields = vector_a0_fields(collapse);
    fields.envelope_id = envelope_id;
    fields
}

#[test]
fn frame_wire_bytes_are_u32_length_inner_and_opening() -> Result<(), CryptoError> {
    let inner = b"A";
    let opening = vector_opening();
    let frame = frame_report_plaintext(inner, &opening)?;
    let mut expected = Vec::new();
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(inner);
    expected.extend_from_slice(&opening);
    assert_eq!(frame.as_bytes(), expected);
    Ok(())
}

#[test]
fn frame_round_trip_preserves_inner_and_opening() -> Result<(), CryptoError> {
    let inner = VECTOR_INNER;
    let opening = vector_opening();
    let frame = frame_report_plaintext(inner, &opening)?;
    let parsed = parse_report_plaintext(frame.as_bytes())?;
    assert_eq!(parsed.inner(), inner);
    assert_eq!(parsed.opening(), &opening);
    Ok(())
}

#[test]
fn parse_refuses_short_frame() {
    let err = parse_report_plaintext(&[0, 0, 0, 1, 0x33]).expect_err("short");
    assert!(matches!(err, CryptoError::ReportFrameTooShort));
}

#[test]
fn parse_refuses_inner_length_mismatch() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&8_u32.to_be_bytes());
    frame.extend_from_slice(b"short");
    frame.extend_from_slice(&[0x33; 32]);
    let err = parse_report_plaintext(&frame).expect_err("mismatch");
    assert!(matches!(err, CryptoError::ReportInnerLengthMismatch));
}

#[test]
fn parse_refuses_zero_padding_tail() -> Result<(), CryptoError> {
    let mut frame = frame_report_plaintext(b"I", &vector_opening())?.as_bytes().to_vec();
    frame.push(0);
    let err = parse_report_plaintext(&frame).expect_err("padding");
    assert!(matches!(err, CryptoError::ReportPaddingOrHeaderRefused));
    Ok(())
}

#[test]
fn parse_refuses_header_encryption_trailer() -> Result<(), CryptoError> {
    let mut frame = frame_report_plaintext(b"I", &vector_opening())?.as_bytes().to_vec();
    frame.extend_from_slice(&[0x01, 0x00]);
    let err = parse_report_plaintext(&frame).expect_err("he");
    assert!(matches!(err, CryptoError::ReportPaddingOrHeaderRefused));
    Ok(())
}

#[test]
fn a0_wire_bytes_match_independent_encoder() -> Result<(), CryptoError> {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let fields = vector_fields(&envelope_id, &collapse);
    assert_eq!(encode_report_a0(&fields)?, independent_a0(&fields));
    Ok(())
}

#[test]
fn vector_commitment_matches_independent_keyed_blake3() -> Result<(), CryptoError> {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let fields = vector_fields(&envelope_id, &collapse);
    let a0 = independent_a0(&fields);
    let opening = vector_opening();
    let expected = independent_commitment(&opening, VECTOR_INNER, &a0);
    assert_eq!(report_commitment(&opening, VECTOR_INNER, &a0)?, expected);
    verify_report_opening(&opening, VECTOR_INNER, &a0, &expected)?;
    Ok(())
}

#[test]
fn verify_refuses_wrong_opening() {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let a0 = independent_a0(&vector_fields(&envelope_id, &collapse));
    let expected = independent_commitment(&vector_opening(), VECTOR_INNER, &a0);
    let err =
        verify_report_opening(&[0x44; 32], VECTOR_INNER, &a0, &expected).expect_err("wrong kf");
    assert!(matches!(err, CryptoError::ReportCommitmentMismatch));
}

#[test]
fn verify_refuses_wrong_inner() {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let a0 = independent_a0(&vector_fields(&envelope_id, &collapse));
    let expected = independent_commitment(&vector_opening(), VECTOR_INNER, &a0);
    let err = verify_report_opening(&vector_opening(), b"other-inner", &a0, &expected)
        .expect_err("wrong I");
    assert!(matches!(err, CryptoError::ReportCommitmentMismatch));
}

#[test]
fn verify_refuses_wrong_a0_delivery_class() {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let mut fields = vector_fields(&envelope_id, &collapse);
    let a0 = independent_a0(&fields);
    let expected = independent_commitment(&vector_opening(), VECTOR_INNER, &a0);
    fields.delivery_class = ReportDeliveryClass::CallWake;
    let tampered = independent_a0(&fields);
    let err = verify_report_opening(&vector_opening(), VECTOR_INNER, &tampered, &expected)
        .expect_err("wrong A0");
    assert!(matches!(err, CryptoError::ReportCommitmentMismatch));
}

#[test]
fn collapse_key_and_tag_match_independent_hkdf_hmac() -> Result<(), CryptoError> {
    let sk = [0x11_u8; 32];
    let pair_binding = b"pair-binding";
    let expected_key = independent_collapse_key(&sk, pair_binding);
    assert_eq!(collapse_key(&sk, pair_binding)?, expected_key);
    let expected_tag = independent_collapse_tag(&expected_key, b"vector", b"device-ref");
    assert_eq!(collapse_tag(&expected_key, b"vector", b"device-ref")?, expected_tag);
    Ok(())
}

#[test]
fn collapse_tag_differs_by_conversation() -> Result<(), CryptoError> {
    let key = collapse_key(&[0x11; 32], b"pair")?;
    let left = collapse_tag(&key, b"conv-a", b"device")?;
    let right = collapse_tag(&key, b"conv-b", b"device")?;
    assert_ne!(left, right);
    Ok(())
}

#[test]
fn cover_collapse_tag_is_thirty_two_nonzero_bytes() -> Result<(), CryptoError> {
    let tag = cover_collapse_tag()?;
    assert_eq!(tag.len(), 32);
    assert_ne!(tag, [0_u8; 32]);
    Ok(())
}

#[test]
fn assemble_binds_frame_a0_and_commitment() -> Result<(), CryptoError> {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let fields = vector_fields(&envelope_id, &collapse);
    let assembled = assemble_report_opening(VECTOR_INNER, &fields, vector_opening())?;
    assert_eq!(assembled.collapse_tag, collapse);
    let parsed = parse_report_plaintext(assembled.framed_plaintext())?;
    verify_report_opening(
        parsed.opening(),
        parsed.inner(),
        &assembled.a0,
        &assembled.report_commitment,
    )?;
    Ok(())
}

#[test]
fn assembled_report_debug_redacts_secret_plaintext_and_opening() -> Result<(), CryptoError> {
    let collapse = vector_collapse();
    let envelope_id = vector_envelope_id();
    let fields = vector_fields(&envelope_id, &collapse);
    let assembled = assemble_report_opening(VECTOR_INNER, &fields, vector_opening())?;
    let debug = format!("{assembled:?}");
    assert_eq!(
        debug,
        "AssembledReportOpening { collapse_tag: \"[REDACTED]\", report_commitment: \"[REDACTED]\", opening: \"[REDACTED]\", framed_plaintext: \"[REDACTED]\", a0: \"[REDACTED]\" }"
    );
    let parsed = parse_report_plaintext(assembled.framed_plaintext())?;
    assert_eq!(
        format!("{parsed:?}"),
        "ParsedReportPlaintext { inner: \"[REDACTED]\", opening: \"[REDACTED]\" }"
    );
    Ok(())
}
