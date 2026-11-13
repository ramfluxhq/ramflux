// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One shared OV-GROUP-OPENING verifier. Authority remains with the original signed wrapper.
use crate::double_ratchet::DmHeader;
use crate::{CryptoError, FrankingCommitmentInput, franking_commitment};
use prost::Message as _;
use ramflux_protocol::message as g;
use zeroize::Zeroize;

/// Verify a native group opening against an already authenticated original wrapper.
/// The working `opening` is exactly `opening_key[32] || commitment_key[32]` and is
/// zeroized on every return. Registered private evidence retains its own erase lifetime.
/// The verifier reconstructs the native header, event id and AAD from `sealed`;
/// no caller-provided AAD or application event-id substitution is accepted.
/// Signer/custody/membership authority and outer C must be verified before calling.
/// # Errors
/// Refuses malformed sizes/header/id, recursive plaintext or any native commitment mismatch.
pub fn verify_group_message_opening(
    opening: &mut [u8],
    plaintext: &[u8],
    sealed: &g::GroupSealedContent,
) -> Result<(), CryptoError> {
    let result = (|| {
        if opening.len() != 64 {
            return Err(CryptoError::GroupReportOpeningMissing);
        }
        let fixed =
            |value: &[u8]| <[u8; 32]>::try_from(value).map_err(|_| CryptoError::CommitmentMismatch);
        for field in [
            &sealed.session_id,
            &sealed.sender_device_hash,
            &sealed.recipient_device_hash,
            &sealed.group_state_hash,
            &sealed.header_hash,
            &sealed.ciphertext_hash,
            &sealed.key_commitment,
            &sealed.franking_commitment,
            &sealed.commitment,
            &sealed.content_commitment,
        ] {
            fixed(field)?;
        }
        if sealed.nonce.len() != 12
            || sealed.group_id.is_empty()
            || sealed.key_epoch == 0
            || !sealed.native_authority_proof.is_empty()
        {
            return Err(CryptoError::CommitmentMismatch);
        }
        let author = sealed.author.as_ref().ok_or(CryptoError::GroupReportAuthorMissing)?;
        if author.account_anchor.is_empty() || author.device_id.is_empty() {
            return Err(CryptoError::GroupReportAuthorMissing);
        }
        g::validation::scan_message("Message", plaintext, g::registry::COMPILED_LAYER)
            .map_err(|_| CryptoError::CommitmentMismatch)?;
        let message = g::Message::decode(plaintext).map_err(|_| CryptoError::CommitmentMismatch)?;
        if message.sealed_group.is_some() {
            return Err(CryptoError::CommitmentMismatch);
        }
        let session = ramflux_protocol::encode_base64url(&sealed.session_id);
        let native_id = String::from_utf8(sealed.event_id.clone())
            .map_err(|_| CryptoError::CommitmentMismatch)?;
        if native_id != format!("{session}:{}", sealed.counter) {
            return Err(CryptoError::CommitmentMismatch);
        }
        let header = DmHeader {
            ratchet_session_id: session,
            sender_device_id_hash: fixed(&sealed.sender_device_hash)?,
            recipient_device_id_hash: fixed(&sealed.recipient_device_hash)?,
            dh_ratchet_public: if sealed.ratchet_public_key.is_empty() {
                [0; 32]
            } else {
                fixed(&sealed.ratchet_public_key)?
            },
            pn: sealed.previous_chain_length,
            n: sealed.counter,
            device_epoch: sealed.device_epoch,
            message_event_id: native_id,
        };
        let canonical = header.canonical_header_bytes()?;
        if canonical != sealed.canonical_crypto_header {
            return Err(CryptoError::CommitmentMismatch);
        }
        let aad = ramflux_protocol::canonical_json_bytes(&(
            "ramflux.shared_group.sender_key.v1",
            &sealed.group_id,
            &author.account_anchor,
            &author.device_id,
            sealed.key_epoch,
            ramflux_protocol::encode_base64url(&sealed.group_state_hash),
        ))?;
        let (opening_key, remainder) =
            opening.split_first_chunk::<32>().ok_or(CryptoError::GroupReportOpeningMissing)?;
        let commitment_key =
            remainder.first_chunk::<32>().ok_or(CryptoError::GroupReportOpeningMissing)?;
        let computed = franking_commitment(&FrankingCommitmentInput {
            plaintext,
            sender_device_id_hash: &sealed.sender_device_hash,
            message_event_id: &header.message_event_id,
            canonical_header_bytes: &canonical,
            associated_data: &aad,
            ciphertext: &sealed.ciphertext,
            opening_key,
            commitment_key,
        });
        for (actual, expected) in [
            (computed.header_hash, &sealed.header_hash),
            (computed.ciphertext_hash, &sealed.ciphertext_hash),
            (computed.key_commitment, &sealed.key_commitment),
            (computed.franking_commitment, &sealed.franking_commitment),
            (computed.commitment.clone(), &sealed.commitment),
            (computed.commitment, &sealed.content_commitment),
        ] {
            if ramflux_protocol::decode_base64url(&actual)? != *expected {
                return Err(CryptoError::CommitmentMismatch);
            }
        }
        Ok(())
    })();
    opening.zeroize();
    result
}

#[cfg(test)]
mod tests;
