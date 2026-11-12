// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! On-disk form of one wrapped vault entry, and the associated data that binds a ciphertext
//! to its reference and wrapping key.
//!
//! Layout: `RFAV` | version 1 | key kind | security level | IV (12) | length (u16 BE) |
//! ciphertext and tag. Every header byte is also part of the associated data, so a blob moved
//! to another reference, key kind or claimed level fails authentication in the Keystore.

use super::keystore::{GCM_IV_LEN, GCM_TAG_LEN, KeyKind, MAX_SECRET_LEN, SecurityLevel, Wrapped};

const MAGIC: &[u8; 4] = b"RFAV";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 1 + GCM_IV_LEN + 2;
/// Largest encoded entry. A longer file is rejected before it is parsed.
pub(crate) const MAX_ENVELOPE_LEN: usize = HEADER_LEN + MAX_SECRET_LEN + GCM_TAG_LEN;
const AAD_DOMAIN: &[u8] = b"ramflux.android.vault.entry.v1";

/// One decoded entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Envelope {
    pub(crate) kind: KeyKind,
    pub(crate) level: SecurityLevel,
    pub(crate) wrapped: Wrapped,
}

/// The envelope is not one this version wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Associated data for one entry: domain, version, key kind, level, then the reference.
pub(crate) fn associated_data(kind: KeyKind, level: SecurityLevel, reference: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 4 + reference.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(0);
    aad.push(VERSION);
    aad.push(kind.code());
    aad.push(level.code());
    aad.extend_from_slice(reference.as_bytes());
    aad
}

impl Envelope {
    /// Encode. Fails when the ciphertext is outside the bound the decoder accepts.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Malformed> {
        let length = self.wrapped.ciphertext.len();
        if !(GCM_TAG_LEN..=MAX_SECRET_LEN + GCM_TAG_LEN).contains(&length) {
            return Err(Malformed);
        }
        let length = u16::try_from(length).map_err(|_| Malformed)?;
        let mut bytes = Vec::with_capacity(HEADER_LEN + usize::from(length));
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(self.kind.code());
        bytes.push(self.level.code());
        bytes.extend_from_slice(&self.wrapped.iv);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.wrapped.ciphertext);
        Ok(bytes)
    }

    /// Decode an exact envelope. Trailing bytes, an unknown version or kind, a software
    /// level, and a short or oversize ciphertext are all malformed.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() < HEADER_LEN || bytes.len() > MAX_ENVELOPE_LEN {
            return Err(Malformed);
        }
        let (header, ciphertext) = bytes.split_at(HEADER_LEN);
        if &header[..4] != MAGIC || header[4] != VERSION {
            return Err(Malformed);
        }
        let kind = KeyKind::from_code(header[5]).ok_or(Malformed)?;
        let level = SecurityLevel::from_code(header[6]);
        if !level.is_hardware() || level.code() != header[6] {
            return Err(Malformed);
        }
        let mut iv = [0_u8; GCM_IV_LEN];
        iv.copy_from_slice(&header[7..7 + GCM_IV_LEN]);
        let length =
            usize::from(u16::from_be_bytes([header[HEADER_LEN - 2], header[HEADER_LEN - 1]]));
        if length != ciphertext.len() || length < GCM_TAG_LEN {
            return Err(Malformed);
        }
        Ok(Self { kind, level, wrapped: Wrapped { iv, ciphertext: ciphertext.to_vec() } })
    }
}
