// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner proof and reply parsing. The listener owns admission.

use ed25519_dalek::{Signer, SigningKey};

use ramflux_protocol::large_attachment::{
    OwnerAttachmentOperation, QualifiedOwner, RequesterPop, requester_digest,
};

use super::codes::{self, CODE_LAYOUT_INVALID, CODE_SEAL_FAILED, CODE_UPLOAD_REJECTED, Refusal};
use super::plane::{self, OwnerCall, Plane};

pub(crate) struct Proof {
    bytes: Vec<u8>,
    signature: [u8; 64],
}

/// # Errors
/// Returns `seal_failed` when the proof cannot be signed.
pub(crate) fn prove(
    op: &OwnerAttachmentOperation,
    owner: &QualifiedOwner,
    key: &SigningKey,
    now: u64,
) -> Result<Proof, Refusal> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let pop = RequesterPop {
        operation_hash: op.hash().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?,
        requester_digest: requester_digest(owner).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?,
        nonce,
        issued_at: now,
        expires_at: now.saturating_add(30),
        forward_digest: [0; 32],
    };
    let signature =
        key.sign(&pop.signing_bytes().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?).to_bytes();
    Ok(Proof {
        bytes: pop.canonical_bytes().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?,
        signature,
    })
}

/// # Errors
/// Returns the plane refusal, or `layout_invalid` when the transcript will not encode.
pub(crate) fn submit(
    plane: &dyn Plane,
    op: &OwnerAttachmentOperation,
    body: &[u8],
    owner: &QualifiedOwner,
    key: &SigningKey,
    now: u64,
) -> Result<Vec<u8>, Refusal> {
    let proof = prove(op, owner, key, now)?;
    let operation = op.canonical_bytes().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let call =
        OwnerCall { operation: &operation, body, proof: &proof.bytes, signature: &proof.signature };
    plane::owner_ready(&call)?;
    plane.owner(&call)
}

/// # Errors
/// Returns `upload_rejected` when the reply is not the owner result object id.
pub(crate) fn reply_object(bytes: &[u8]) -> Result<[u8; 32], Refusal> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
    codes::owner_result_code(value.get("code").and_then(serde_json::Value::as_str))?;
    let text = value
        .get("object_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(Refusal::new(CODE_UPLOAD_REJECTED))?;
    decode_hex(text)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

/// # Errors
/// Returns `upload_rejected` when `text` is not 64 hex characters.
pub(crate) fn decode_hex(text: &str) -> Result<[u8; 32], Refusal> {
    if text.len() != 64 {
        return Err(Refusal::new(CODE_UPLOAD_REJECTED));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, Refusal> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Refusal::new(CODE_UPLOAD_REJECTED)),
    }
}
