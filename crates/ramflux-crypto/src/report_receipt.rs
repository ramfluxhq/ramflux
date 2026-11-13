// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate Decision 5 node report receipt (`ramflux.franking.node_tag.v2`).
//!
//! The node signs without opening Inner. Live v1 franking stays in [`crate::franking`].
//! LP is u32 big-endian, matching report opening, not the u16 v1 helper.

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::{CryptoError, verifying_key_from_base64url};

/// Fields the accepting node signs. Inner bytes are not an input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeReportReceiptInput<'a> {
    pub node_id: &'a str,
    pub envelope_id: &'a str,
    pub authenticated_source_ref: &'a [u8],
    pub target_delivery_id: &'a str,
    pub report_commitment: &'a [u8; 32],
    pub payload_hash: &'a str,
    pub accepted_at: u64,
}

fn write_u32_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CryptoError::NodeReportReceiptTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Decision 5 v2 transcript. Does not reuse `ramflux.franking.node_tag.v1`.
///
/// # Errors
/// [`CryptoError::NodeReportReceiptTooLarge`] when a field exceeds `u32` length.
pub fn node_report_receipt_preimage(
    input: &NodeReportReceiptInput<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(ramflux_protocol::domain::FRANKING_NODE_TAG_V2.as_bytes());
    write_u32_lp(&mut preimage, input.node_id.as_bytes())?;
    write_u32_lp(&mut preimage, input.envelope_id.as_bytes())?;
    write_u32_lp(&mut preimage, input.authenticated_source_ref)?;
    write_u32_lp(&mut preimage, input.target_delivery_id.as_bytes())?;
    write_u32_lp(&mut preimage, input.report_commitment)?;
    write_u32_lp(&mut preimage, input.payload_hash.as_bytes())?;
    write_u32_lp(&mut preimage, &input.accepted_at.to_be_bytes())?;
    Ok(preimage)
}

/// Sign a v2 node report receipt with the configured node signing key.
///
/// # Errors
/// Same as [`node_report_receipt_preimage`].
pub fn sign_node_report_receipt(
    input: &NodeReportReceiptInput<'_>,
    signing_key: &SigningKey,
) -> Result<String, CryptoError> {
    let preimage = node_report_receipt_preimage(input)?;
    Ok(ramflux_protocol::encode_base64url(signing_key.sign(&preimage).to_bytes()))
}

/// Sign a v2 node report receipt from a node seed.
///
/// # Errors
/// Same as [`sign_node_report_receipt`].
pub fn sign_node_report_receipt_with_seed(
    input: &NodeReportReceiptInput<'_>,
    seed: [u8; 32],
) -> Result<String, CryptoError> {
    sign_node_report_receipt(input, &SigningKey::from_bytes(&seed))
}

/// Verify a v2 receipt using the **trusted node record** public key.
///
/// The reporter-supplied key is never an argument. Callers that pass a key from
/// the evidence blob fail the T08 trusted-key oracle.
///
/// # Errors
/// Malformed signatures, a preimage overflow, or [`CryptoError::VerifyFailed`].
pub fn verify_node_report_receipt(
    input: &NodeReportReceiptInput<'_>,
    signature_base64url: &str,
    trusted_node_public_key: &str,
) -> Result<(), CryptoError> {
    let verifying_key = verifying_key_from_base64url(trusted_node_public_key)?;
    let preimage = node_report_receipt_preimage(input)?;
    let bytes = ramflux_protocol::decode_base64url(signature_base64url)?;
    let signature_bytes: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureLength(bytes.len()))?;
    verifying_key
        .verify_strict(&preimage, &Signature::from_bytes(&signature_bytes))
        .map_err(|_err| CryptoError::VerifyFailed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::public_key_base64url_from_seed;

    fn sample() -> ([u8; 32], NodeReportReceiptInput<'static>) {
        (
            [0x71; 32],
            NodeReportReceiptInput {
                node_id: "node-v2",
                envelope_id: "env-v2",
                authenticated_source_ref: b"alice/device-a",
                target_delivery_id: "bob",
                report_commitment: &[0xC0; 32],
                payload_hash: "payload-hash",
                accepted_at: 1_760_000_000,
            },
        )
    }

    #[test]
    fn v2_transcript_does_not_reuse_v1_domain() {
        let (_, input) = sample();
        let preimage =
            node_report_receipt_preimage(&input).expect("test: encode the node receipt preimage");
        assert!(preimage.starts_with(ramflux_protocol::domain::FRANKING_NODE_TAG_V2.as_bytes()));
        assert!(
            !preimage
                .windows(ramflux_protocol::domain::FRANKING_NODE_TAG.len())
                .any(|w| { w == ramflux_protocol::domain::FRANKING_NODE_TAG.as_bytes() })
        );
    }

    #[test]
    fn trusted_node_key_verifies_and_reporter_key_is_refused() {
        let (seed, input) = sample();
        let signature =
            sign_node_report_receipt_with_seed(&input, seed).expect("test: sign the node receipt");
        let trusted = public_key_base64url_from_seed(seed);
        verify_node_report_receipt(&input, &signature, &trusted)
            .expect("test: verify against the trusted node key");
        let reporter = public_key_base64url_from_seed([0x72; 32]);
        assert!(matches!(
            verify_node_report_receipt(&input, &signature, &reporter),
            Err(CryptoError::VerifyFailed)
        ));
    }
}
