// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender authentication preserves identity claims while excluding appended public node metadata.
use crate::{Envelope, ProtocolError};
/// Canonical sender-signed envelope bytes, retaining the root claim and all sender metadata.
/// # Errors
/// Returns canonical JSON errors.
pub fn envelope_sender_signed_bytes(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    Ok(crate::sender_signed_transcript(envelope, crate::SenderTranscriptMode::WithCiphertext)?
        .bytes)
}

/// Sender-signed candidate outer bytes. Node receipt is excluded.
///
/// # Errors
/// Returns canonical JSON errors.
pub fn candidate_outer_sender_signed_bytes(
    outer: &crate::message::outer::CandidateOuterEnvelope,
) -> Result<Vec<u8>, ProtocolError> {
    crate::message::outer::candidate_outer_sender_signed_bytes(outer)
}

/// Verify a transport envelope through the checked sender transcript.
/// The signed schema selects its transcript; a failed v2 verification never falls back.
/// # Errors
/// Refuses invalid profiles, ciphertext hash mismatches and invalid signatures.
pub fn verify_envelope_sender_signature(
    envelope: &Envelope,
    public_key: &str,
) -> Result<(), ProtocolError> {
    crate::verify_sender_signature(
        envelope,
        crate::SenderTranscriptMode::WithCiphertext,
        public_key,
    )?;
    Ok(())
}
