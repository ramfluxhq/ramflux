// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verification of a central push key set body (`sv = 1`).
//!
//! The signature is Ed25519 over `"rfc-push-keyset" || 0x00 || u16be len(centre_id) || centre_id ||
//! u32be len(body) || body`, where `body` is the decoded bytes exactly as received. The body is
//! closed JSON; the sequence fence and expiry checks belong to the caller, which holds the state.

use crate::CryptoError;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// Domain of the key set signature, including its NUL terminator.
const KEYSET_DOMAIN: &[u8] = b"rfc-push-keyset\0";
/// Body format version.
pub const KEYSET_VERSION: u8 = 1;
/// Smallest and largest decoded body.
pub const MIN_KEYSET_BODY: usize = 2;
pub const MAX_KEYSET_BODY: usize = 4096;
/// Largest sequence number (`2^53 - 1`).
pub const MAX_KEYSET_SEQ: u64 = (1 << 53) - 1;

/// One verified key of a key set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeysetKey {
    pub kid: String,
    pub pk: [u8; 32],
    pub active: bool,
    pub not_after: Option<u64>,
}

/// A verified key set body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeysetBody {
    pub centre_id: String,
    pub seq: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub keys: Vec<KeysetKey>,
}

impl KeysetBody {
    /// The single `active` key, which is the only key sealers use.
    #[must_use]
    pub fn active(&self) -> Option<&KeysetKey> {
        self.keys.iter().find(|key| key.active)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyWire {
    ksv: u8,
    centre_id: String,
    seq: u64,
    issued_at: u64,
    expires_at: u64,
    keys: Vec<KeyWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyWire {
    kid: String,
    pk: String,
    state: String,
    not_after: Option<u64>,
}

/// Builds the signed message of a key set body.
///
/// # Errors
/// Returns an error when a length does not fit its prefix.
pub fn keyset_message(centre_id: &str, body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let centre_len =
        u16::try_from(centre_id.len()).map_err(|_| CryptoError::PushKeyset("centre_id"))?;
    let body_len = u32::try_from(body.len()).map_err(|_| CryptoError::PushKeyset("body"))?;
    let mut message =
        Vec::with_capacity(KEYSET_DOMAIN.len() + 2 + centre_id.len() + 4 + body.len());
    message.extend_from_slice(KEYSET_DOMAIN);
    message.extend_from_slice(&centre_len.to_be_bytes());
    message.extend_from_slice(centre_id.as_bytes());
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

/// Verifies the signature over the received body bytes and the body rules for `centre_id`.
///
/// # Errors
/// Returns [`CryptoError::PushKeyset`] for a body rule, and [`CryptoError::VerifyFailed`] for a
/// signature that does not verify under `verify_key`.
pub fn verify_keyset(
    body: &[u8],
    sig: &[u8; 64],
    centre_id: &str,
    verify_key: &[u8; 32],
) -> Result<KeysetBody, CryptoError> {
    if !(MIN_KEYSET_BODY..=MAX_KEYSET_BODY).contains(&body.len()) {
        return Err(CryptoError::PushKeyset("body_size"));
    }
    let key =
        VerifyingKey::from_bytes(verify_key).map_err(|_| CryptoError::PushKeyset("verify_key"))?;
    let message = keyset_message(centre_id, body)?;
    key.verify_strict(&message, &Signature::from_bytes(sig))
        .map_err(|_| CryptoError::VerifyFailed)?;
    parse_body(body, centre_id)
}

fn parse_body(body: &[u8], centre_id: &str) -> Result<KeysetBody, CryptoError> {
    let wire: BodyWire =
        serde_json::from_slice(body).map_err(|_| CryptoError::PushKeyset("body_json"))?;
    if wire.ksv != KEYSET_VERSION {
        return Err(CryptoError::PushKeyset("ksv"));
    }
    if wire.centre_id != centre_id {
        return Err(CryptoError::PushKeyset("centre_id"));
    }
    if wire.seq == 0 || wire.seq > MAX_KEYSET_SEQ {
        return Err(CryptoError::PushKeyset("seq"));
    }
    if wire.issued_at >= wire.expires_at {
        return Err(CryptoError::PushKeyset("validity"));
    }
    if !(1..=2).contains(&wire.keys.len()) {
        return Err(CryptoError::PushKeyset("key_count"));
    }
    let mut keys = Vec::with_capacity(wire.keys.len());
    for entry in wire.keys {
        if !kid_ok(&entry.kid) {
            return Err(CryptoError::PushKeyset("kid"));
        }
        if entry.pk.len() != 43 {
            return Err(CryptoError::PushKeyset("pk"));
        }
        let pk_bytes = ramflux_protocol::decode_base64url(&entry.pk)
            .map_err(|_| CryptoError::PushKeyset("pk"))?;
        let pk =
            <[u8; 32]>::try_from(pk_bytes.as_slice()).map_err(|_| CryptoError::PushKeyset("pk"))?;
        let active = match (entry.state.as_str(), entry.not_after) {
            ("active", None) => true,
            ("retiring", Some(_)) => false,
            _ => return Err(CryptoError::PushKeyset("state")),
        };
        keys.push(KeysetKey { kid: entry.kid, pk, active, not_after: entry.not_after });
    }
    if keys.iter().filter(|key| key.active).count() != 1 {
        return Err(CryptoError::PushKeyset("active_count"));
    }
    if keys.windows(2).any(|pair| pair[0].kid >= pair[1].kid) {
        return Err(CryptoError::PushKeyset("kid_order"));
    }
    Ok(KeysetBody {
        centre_id: wire.centre_id,
        seq: wire.seq,
        issued_at: wire.issued_at,
        expires_at: wire.expires_at,
        keys,
    })
}

fn kid_ok(kid: &str) -> bool {
    (1..=32).contains(&kid.len())
        && kid.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
