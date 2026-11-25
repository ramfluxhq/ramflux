// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-side helpers of the central beta allowlist (NN-CENTRAL-NODE-ALLOWLIST-01 sections 2.1 and 2.2):
//! the key fingerprint shown to operators and the signed message of an enrolment request.

use sha2::{Digest, Sha256};

use crate::CryptoError;

/// Domain of the fingerprint hash: `SHA-256("rfc-node-key-fp" || 0x00 || alg || key)`.
const FINGERPRINT_DOMAIN: &[u8] = b"rfc-node-key-fp";
/// Domain string of the enrolment message, including its NUL terminator.
const ENROL_DOMAIN: &[u8] = b"rfc-node-enrol\0";
/// `alg = 1`: Ed25519.
const ALG_ED25519: u8 = 1;
/// Fingerprint bytes kept from the hash (160 bits, 32 base32 characters).
const FINGERPRINT_BYTES: usize = 20;
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Characters per display group of the fingerprint.
const GROUP_LEN: usize = 4;

/// Fingerprint of a node public key: 32 lower-case base32 characters in 8 groups of 4, separated by spaces.
#[must_use]
pub fn node_key_fingerprint(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update([0_u8, ALG_ED25519]);
    hasher.update(public_key);
    let digest = hasher.finalize();
    let kept: Vec<u8> = digest.iter().take(FINGERPRINT_BYTES).copied().collect();
    let encoded = base32_lower(&kept);
    let mut grouped = String::with_capacity(encoded.len() + encoded.len() / GROUP_LEN);
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % GROUP_LEN == 0 {
            grouped.push(' ');
        }
        grouped.push(character);
    }
    grouped
}

/// The signed message of an enrolment request (section 2.1):
/// `"rfc-node-enrol" || 0x00 || u16be len(centre_id) || centre_id || u16be len(body) || body`.
///
/// # Errors
/// Returns an error when a length does not fit its `u16` prefix.
pub fn enrolment_message(centre_id: &str, body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let centre_len = u16::try_from(centre_id.len())
        .map_err(|_| CryptoError::NodeEnrolment("centre_id longer than 65535 bytes"))?;
    let body_len = u16::try_from(body.len())
        .map_err(|_| CryptoError::NodeEnrolment("enrolment body longer than 65535 bytes"))?;
    let mut message = Vec::with_capacity(ENROL_DOMAIN.len() + 4 + centre_id.len() + body.len());
    message.extend_from_slice(ENROL_DOMAIN);
    message.extend_from_slice(&centre_len.to_be_bytes());
    message.extend_from_slice(centre_id.as_bytes());
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 0x1f).unwrap_or(0);
            if let Some(character) = BASE32_LOWER.get(index) {
                out.push(char::from(*character));
            }
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 0x1f).unwrap_or(0);
        if let Some(character) = BASE32_LOWER.get(index) {
            out.push(char::from(*character));
        }
    }
    out
}
