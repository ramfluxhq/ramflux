use std::collections::BTreeSet;

use crate::SyncError;

pub struct FrankingEvidence<'a> {
    pub plaintext: &'a [u8],
    pub sender_device_id_hash: &'a [u8],
    pub message_event_id: &'a str,
    pub canonical_header_bytes: &'a [u8],
    pub associated_data: &'a [u8],
    pub ciphertext: &'a [u8],
    pub opening_key: &'a [u8; 32],
    pub commitment_key: &'a [u8; 32],
    pub expected_commitment: &'a str,
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn verify_franking_evidence(evidence: &FrankingEvidence<'_>) -> Result<String, SyncError> {
    let commitment =
        ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
            plaintext: evidence.plaintext,
            sender_device_id_hash: evidence.sender_device_id_hash,
            message_event_id: evidence.message_event_id,
            canonical_header_bytes: evidence.canonical_header_bytes,
            associated_data: evidence.associated_data,
            ciphertext: evidence.ciphertext,
            opening_key: evidence.opening_key,
            commitment_key: evidence.commitment_key,
        });
    if commitment.commitment == evidence.expected_commitment {
        Ok(commitment.commitment)
    } else {
        Err(SyncError::FrankingVerificationFailed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct OpaqueCallSignal {
    pub call_id: String,
    pub opaque_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SignalingRelay {
    pub holds_media_key: bool,
    pub forwarded_payload_hash: String,
}

#[must_use]
pub fn relay_opaque_call_signal(signal: &OpaqueCallSignal) -> SignalingRelay {
    SignalingRelay {
        holds_media_key: false,
        forwarded_payload_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::A2I_CONTROL,
            &signal.opaque_payload,
        ),
    }
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn assert_srtp_relay_has_no_media_key(relay: &SignalingRelay) -> Result<(), SyncError> {
    if relay.holds_media_key { Err(SyncError::MediaKeyLeak) } else { Ok(()) }
}

#[must_use]
pub fn bot_revocation_targets(bot_id: &str) -> BTreeSet<String> {
    BTreeSet::from([
        format!("dm:{bot_id}"),
        format!("group:{bot_id}"),
        format!("federation:{bot_id}"),
    ])
}
