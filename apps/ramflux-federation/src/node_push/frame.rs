// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wire frames of `rfc-push-1` (central push session, federation side).
//! Request: `L:u32be || fv || alg || n:u16be || body || sig`, `L = 4 + n + 64`, signature over
//! `m = "rfc-push-request\0" || fv || alg || u16be len(centre_id) || centre_id || u16be n || body`.
//! Reply: `R:u32be || JSON`, `R <= 16384`.

use serde_json::Value;

pub(crate) const ALPN: &[u8] = b"rfc-push-1";
const DOMAIN: &[u8] = b"rfc-push-request\0";
const FRAME_VERSION: u8 = 1;
const ALG_ED25519: u8 = 1;
const SIGNATURE_LEN: usize = 64;
const PAYLOAD_HEADER_LEN: usize = 4;
/// Largest `L` (the frame after its u32 length prefix) the centre accepts.
const MAX_PAYLOAD_LEN: usize = 32_768;
pub(crate) const MAX_BODY_LEN: usize = MAX_PAYLOAD_LEN - PAYLOAD_HEADER_LEN - SIGNATURE_LEN;
/// Largest reply body `R` the centre sends.
pub(crate) const MAX_REPLY_LEN: usize = 16_384;

/// `L:u32be || fv || alg || n:u16be || body || sig`.
pub(crate) fn encode_request(
    seed: &[u8; 32],
    centre_id: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    if body.is_empty() || body.len() > MAX_BODY_LEN {
        return Err("push body outside 1..=32700 bytes".to_owned());
    }
    let centre_len = u16::try_from(centre_id.len()).map_err(|_| "centre_id too long".to_owned())?;
    let body_len = u16::try_from(body.len()).map_err(|_| "body too long".to_owned())?;
    let mut message = Vec::with_capacity(DOMAIN.len() + 4 + 2 + centre_id.len() + 2 + body.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&[FRAME_VERSION, ALG_ED25519]);
    message.extend_from_slice(&centre_len.to_be_bytes());
    message.extend_from_slice(centre_id.as_bytes());
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(body);
    let signature = ramflux_protocol::decode_base64url(
        &ramflux_crypto::sign_canonical_bytes_with_seed(&message, *seed),
    )
    .map_err(|_| "signature encoding".to_owned())?;
    if signature.len() != SIGNATURE_LEN {
        return Err("signature length".to_owned());
    }
    let payload_len = PAYLOAD_HEADER_LEN + body.len() + SIGNATURE_LEN;
    let frame_len = u32::try_from(payload_len).map_err(|_| "frame length".to_owned())?;
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&frame_len.to_be_bytes());
    frame.extend_from_slice(&[FRAME_VERSION, ALG_ED25519]);
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(body);
    frame.extend_from_slice(&signature);
    Ok(frame)
}

/// Parses `R:u32be || JSON`; anything else is a bad reply.
pub(crate) fn decode_reply(bytes: &[u8]) -> Result<Value, String> {
    let (len_bytes, json) =
        bytes.split_first_chunk::<4>().ok_or("reply shorter than its length")?;
    if u32::from_be_bytes(*len_bytes) as usize != json.len() || json.len() > MAX_REPLY_LEN {
        return Err("reply length mismatch".to_owned());
    }
    serde_json::from_slice(json).map_err(|error| format!("reply JSON: {error}"))
}
