// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S10a report-opening framer: length + exact Inner + opening, no padding or HE.
//!
//! Candidate only until S10a activation (P24/P25). Live franking stays in
//! [`crate::franking`]. LP here is u32 big-endian, not the u16 franking helper.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CryptoError, blake3_keyed_derive, hkdf_sha256, random_32};

/// Decision 5 transcript domain. Retired `ramflux.franking_opening.v1` is not reused.
pub const REPORT_OPENING_DOMAIN: &str = "ramflux.message.report_opening.v1";
/// HKDF info for the per-session collapse key (Decision 4).
pub const COLLAPSE_KEY_INFO: &str = "ramflux.message.collapse_key.v1";

const OPENING_LEN: usize = 32;
const LEN_PREFIX: usize = 4;

/// Canonical sender outer fields for A0 (Decision 5 exclusions applied by omission).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportA0<'a> {
    pub envelope_id: &'a [u8],
    pub source_principal_id: &'a [u8],
    pub source_device_id: &'a [u8],
    pub target_delivery_id: &'a [u8],
    pub delivery_class: ReportDeliveryClass,
    pub priority: ReportPriority,
    pub ttl_seconds: u64,
    pub created_at: u64,
    pub collapse_tag: &'a [u8; 32],
    pub delivery_mode: ReportDeliveryMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportDeliveryClass {
    Message,
    CallWake,
}

impl ReportDeliveryClass {
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Message => b"message",
            Self::CallWake => b"call_wake",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportPriority {
    Normal,
    Low,
    High,
}

impl ReportPriority {
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Normal => b"normal",
            Self::Low => b"low",
            Self::High => b"high",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportDeliveryMode {
    Durable,
    Ephemeral,
}

impl ReportDeliveryMode {
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Durable => b"durable",
            Self::Ephemeral => b"ephemeral",
        }
    }
}

/// Uniform tag, commitment, opening and S10a body plaintext (no Padme tail).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledReportOpening {
    pub collapse_tag: [u8; 32],
    pub report_commitment: [u8; 32],
    pub opening: [u8; 32],
    pub framed_plaintext: Vec<u8>,
    pub a0: Vec<u8>,
}

fn write_u32_lp(out: &mut Vec<u8>, bytes: &[u8], overflow: CryptoError) -> Result<(), CryptoError> {
    let len = u32::try_from(bytes.len()).map_err(|_| overflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Encodes A0 as LP(variable fields) and raw u64 big-endian integers.
///
/// # Errors
/// Returns [`CryptoError::ReportA0TooLarge`] when a field exceeds `u32` length.
pub fn encode_report_a0(fields: &ReportA0<'_>) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::new();
    write_u32_lp(&mut out, fields.envelope_id, CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut out, fields.source_principal_id, CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut out, fields.source_device_id, CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut out, fields.target_delivery_id, CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut out, fields.delivery_class.as_bytes(), CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut out, fields.priority.as_bytes(), CryptoError::ReportA0TooLarge)?;
    out.extend_from_slice(&fields.ttl_seconds.to_be_bytes());
    out.extend_from_slice(&fields.created_at.to_be_bytes());
    write_u32_lp(&mut out, fields.collapse_tag, CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut out, fields.delivery_mode.as_bytes(), CryptoError::ReportA0TooLarge)?;
    Ok(out)
}

/// Frames `u32_be(inner_length) || exact_inner || kf[32]` with no padding or HE.
///
/// # Errors
/// Returns [`CryptoError::ReportInnerTooLarge`] when Inner exceeds `u32` length.
pub fn frame_report_plaintext(inner: &[u8], opening: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let inner_len = u32::try_from(inner.len()).map_err(|_| CryptoError::ReportInnerTooLarge)?;
    let mut out = Vec::with_capacity(LEN_PREFIX + inner.len() + OPENING_LEN);
    out.extend_from_slice(&inner_len.to_be_bytes());
    out.extend_from_slice(inner);
    out.extend_from_slice(opening);
    Ok(out)
}

/// Parses an S10a report plaintext and refuses any trailing padding or HE bytes.
///
/// # Errors
/// Returns a distinct report-opening error for short frames, inner-length
/// mismatch, or trailing padding/header bytes.
pub fn parse_report_plaintext(frame: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
    if frame.len() < LEN_PREFIX + OPENING_LEN {
        return Err(CryptoError::ReportFrameTooShort);
    }
    let mut len_bytes = [0_u8; LEN_PREFIX];
    len_bytes.copy_from_slice(&frame[..LEN_PREFIX]);
    let inner_len = u32::from_be_bytes(len_bytes);
    let inner_len =
        usize::try_from(inner_len).map_err(|_| CryptoError::ReportInnerLengthMismatch)?;
    let expected = LEN_PREFIX
        .checked_add(inner_len)
        .and_then(|n| n.checked_add(OPENING_LEN))
        .ok_or(CryptoError::ReportInnerLengthMismatch)?;
    if frame.len() < expected {
        return Err(CryptoError::ReportInnerLengthMismatch);
    }
    if frame.len() > expected {
        return Err(CryptoError::ReportPaddingOrHeaderRefused);
    }
    let inner = frame[LEN_PREFIX..LEN_PREFIX + inner_len].to_vec();
    let mut opening = [0_u8; OPENING_LEN];
    opening.copy_from_slice(&frame[LEN_PREFIX + inner_len..]);
    Ok((inner, opening))
}

/// `C = BLAKE3_keyed(kf, LP(domain) || LP(I) || LP(A0))`.
///
/// # Errors
/// Returns a length error when domain, Inner or A0 exceeds `u32`.
pub fn report_commitment(
    opening: &[u8; 32],
    inner: &[u8],
    a0: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut context = Vec::new();
    write_u32_lp(&mut context, REPORT_OPENING_DOMAIN.as_bytes(), CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut context, inner, CryptoError::ReportInnerTooLarge)?;
    write_u32_lp(&mut context, a0, CryptoError::ReportA0TooLarge)?;
    Ok(blake3_keyed_derive(opening, &context))
}

/// Recomputes C and refuses a mismatch before display.
///
/// # Errors
/// Returns [`CryptoError::ReportCommitmentMismatch`] when C does not match, or
/// a length error while encoding the transcript.
pub fn verify_report_opening(
    opening: &[u8; 32],
    inner: &[u8],
    a0: &[u8],
    expected: &[u8; 32],
) -> Result<(), CryptoError> {
    let actual = report_commitment(opening, inner, a0)?;
    if actual == *expected { Ok(()) } else { Err(CryptoError::ReportCommitmentMismatch) }
}

/// Derives `Kcollapse = HKDF-SHA256(SK, salt=pair_binding, info=collapse_key.v1, 32)`.
///
/// # Errors
/// Returns HKDF/HMAC failures from the shared extractor.
pub fn collapse_key(sk: &[u8], pair_binding: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut key = [0_u8; 32];
    hkdf_sha256(pair_binding, sk, COLLAPSE_KEY_INFO.as_bytes(), &mut key)?;
    Ok(key)
}

/// `tag = HMAC-SHA256(Kcollapse, LP(conversation_id) || LP(recipient_device_ref))`.
///
/// # Errors
/// Returns HMAC init failure or a `u32` length overflow on the tagged fields.
pub fn collapse_tag(
    kcollapse: &[u8; 32],
    conversation_id: &[u8],
    recipient_device_ref: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(kcollapse)
        .map_err(|_err| CryptoError::HmacFailed)?;
    let mut tagged = Vec::new();
    write_u32_lp(&mut tagged, conversation_id, CryptoError::ReportA0TooLarge)?;
    write_u32_lp(&mut tagged, recipient_device_ref, CryptoError::ReportA0TooLarge)?;
    mac.update(&tagged);
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0_u8; 32];
    tag.copy_from_slice(&bytes);
    Ok(tag)
}

/// 32 CSPRNG bytes when a conversation tag is meaningless. Missing tags are never allowed.
///
/// # Errors
/// Returns [`CryptoError::RandomUnavailable`] when the OS CSPRNG fails.
pub fn cover_collapse_tag() -> Result<[u8; 32], CryptoError> {
    random_32()
}

/// Frames Inner, encodes A0 and computes C. Does not encrypt.
///
/// # Errors
/// Returns report-opening length or HKDF errors from the helpers above.
pub fn assemble_report_opening(
    inner: &[u8],
    fields: &ReportA0<'_>,
    opening: [u8; 32],
) -> Result<AssembledReportOpening, CryptoError> {
    let opening = Zeroizing::new(opening);
    let a0 = encode_report_a0(fields)?;
    let framed_plaintext = frame_report_plaintext(inner, &opening)?;
    let report_commitment = report_commitment(&opening, inner, &a0)?;
    Ok(AssembledReportOpening {
        collapse_tag: *fields.collapse_tag,
        report_commitment,
        opening: *opening,
        framed_plaintext,
        a0,
    })
}

#[cfg(test)]
mod tests;
