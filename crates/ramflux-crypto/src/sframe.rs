// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 9605 suite 5: minimal headers, metadata authentication and per-key replay admission.
//! Independently implemented from <https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4>.
use crate::CryptoError;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// IANA `SFrame` `AES_256_GCM_SHA512_128` cipher suite.
pub const SFRAME_AES_256_GCM_SHA512_128: u16 = 5;
const MAX_PLAINTEXT: usize = 64 * 1024;
const MAX_METADATA: usize = 4096;
const TAG_BYTES: usize = 16;

/// The authenticated, minimally encoded `SFrame` key identifier and counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SFrameHeader {
    pub kid: u64,
    pub counter: u64,
}
impl SFrameHeader {
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = vec![0];
        for (value, flag, shift) in [(self.kid, 0x80, 4), (self.counter, 0x08, 0)] {
            let encoded = value.to_be_bytes();
            if value < 8 {
                bytes[0] |= encoded[7] << shift;
            } else {
                let first = encoded.iter().position(|b| *b != 0).unwrap_or(7);
                let lengths = [7, 6, 5, 4, 3, 2, 1, 0];
                bytes[0] |= flag | (lengths[first] << shift);
                bytes.extend_from_slice(&encoded[first..]);
            }
        }
        bytes
    }
    /// # Errors
    /// Rejects truncation and extended integers that do not use the required minimal encoding.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), CryptoError> {
        let config = *bytes.first().ok_or(CryptoError::SFrame("empty header"))?;
        let mut at = 1;
        let mut field = |flag: u8, shift: u8| -> Result<u64, CryptoError> {
            let bits = (config >> shift) & 7;
            if config & flag == 0 {
                return Ok(u64::from(bits));
            }
            let width = usize::from(bits) + 1;
            let encoded =
                bytes.get(at..at + width).ok_or(CryptoError::SFrame("truncated header"))?;
            let mut value = [0; 8];
            value[8 - width..].copy_from_slice(encoded);
            let value = u64::from_be_bytes(value);
            if encoded[0] == 0 || value < 8 {
                return Err(CryptoError::SFrame("nonminimal header"));
            }
            at += width;
            Ok(value)
        };
        let kid = field(0x80, 4)?;
        let counter = field(0x08, 0)?;
        Ok((Self { kid, counter }, at))
    }
}
struct Key {
    key: Zeroizing<[u8; 32]>,
    salt: Zeroizing<[u8; 12]>,
}
impl Key {
    fn derive(base: &[u8], kid: u64) -> Result<Self, CryptoError> {
        if !(16..=64).contains(&base.len()) {
            return Err(CryptoError::SFrame("invalid base key length"));
        }
        let hkdf = Hkdf::<Sha512>::new(Some(&[]), base);
        let label = |prefix: &[u8]| {
            let mut out = prefix.to_vec();
            out.extend_from_slice(&kid.to_be_bytes());
            out.extend_from_slice(&SFRAME_AES_256_GCM_SHA512_128.to_be_bytes());
            out
        };
        let mut key = Zeroizing::new([0; 32]);
        let mut salt = Zeroizing::new([0; 12]);
        hkdf.expand(&label(b"SFrame 1.0 Secret key "), key.as_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hkdf.expand(&label(b"SFrame 1.0 Secret salt "), salt.as_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        Ok(Self { key, salt })
    }
    fn nonce(&self, counter: u64) -> [u8; 12] {
        let mut nonce = *self.salt;
        for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes()) {
            *a ^= b;
        }
        nonce
    }
    fn cipher(&self) -> Result<Aes256Gcm, CryptoError> {
        Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| CryptoError::AeadFailed)
    }
}
/// An encrypt-only key. It is deliberately neither cloneable nor serializable.
/// A new instance requires fresh base-key/KID material; never restart a used key's counter.
pub struct SFrameSender {
    kid: u64,
    key: Key,
    next: Option<u64>,
}
impl std::fmt::Debug for SFrameSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SFrameSender")
            .field("kid", &self.kid)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}
impl SFrameSender {
    /// # Errors
    /// Rejects base keys outside 16..=64 bytes or a failed key derivation. Calls use random 32-byte keys.
    pub fn new(base_key: &[u8], kid: u64) -> Result<Self, CryptoError> {
        Ok(Self { kid, key: Key::derive(base_key, kid)?, next: Some(0) })
    }
    /// # Errors
    /// Rejects exhausted counters, excessive input or authenticated encryption failure.
    pub fn seal(&mut self, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT || metadata.len() > MAX_METADATA {
            return Err(CryptoError::SFrame("frame byte budget"));
        }
        let counter = self.next.ok_or(CryptoError::SFrame("counter exhausted"))?;
        self.next = counter.checked_add(1);
        let mut frame = SFrameHeader { kid: self.kid, counter }.encode();
        let mut aad = frame.clone();
        aad.extend_from_slice(metadata);
        let nonce = self.key.nonce(counter);
        let encrypted = self
            .key
            .cipher()?
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| CryptoError::AeadFailed)?;
        frame.extend(encrypted);
        Ok(frame)
    }
}
/// One receiving key with a 128-counter replay window. Authentication precedes window mutation.
pub struct SFrameReceiver {
    kid: u64,
    key: Key,
    highest: Option<u64>,
    seen: u128,
}
impl std::fmt::Debug for SFrameReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SFrameReceiver")
            .field("kid", &self.kid)
            .field("highest", &self.highest)
            .finish_non_exhaustive()
    }
}
impl SFrameReceiver {
    /// # Errors
    /// Rejects invalid base key lengths or failed key derivation.
    pub fn new(base_key: &[u8], kid: u64) -> Result<Self, CryptoError> {
        Ok(Self { kid, key: Key::derive(base_key, kid)?, highest: None, seen: 0 })
    }
    /// # Errors
    /// Rejects invalid headers, another KID, replay, oversized input or failed authentication.
    pub fn open(&mut self, metadata: &[u8], frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if frame.len() > MAX_PLAINTEXT + 17 + TAG_BYTES || metadata.len() > MAX_METADATA {
            return Err(CryptoError::SFrame("frame byte budget"));
        }
        let (header, at) = SFrameHeader::decode(frame)?;
        if header.kid != self.kid || frame.len() < at + TAG_BYTES {
            return Err(CryptoError::SFrame("key or tag missing"));
        }
        if let Some(highest) = self.highest
            && header.counter <= highest
        {
            let age = highest - header.counter;
            if age >= 128 || (self.seen >> age) & 1 != 0 {
                return Err(CryptoError::SFrame("replay"));
            }
        }
        let mut aad = frame[..at].to_vec();
        aad.extend_from_slice(metadata);
        let nonce = self.key.nonce(header.counter);
        let plaintext = self
            .key
            .cipher()?
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &frame[at..], aad: &aad })
            .map_err(|_| CryptoError::AeadFailed)?;
        self.admit(header.counter);
        Ok(plaintext)
    }
    fn admit(&mut self, counter: u64) {
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.seen = 1;
            }
            Some(highest) if counter > highest => {
                self.seen = self
                    .seen
                    .checked_shl(u32::try_from(counter - highest).unwrap_or(u32::MAX))
                    .unwrap_or(0)
                    | 1;
                self.highest = Some(counter);
            }
            Some(highest) => self.seen |= 1 << (highest - counter),
        }
    }
}
#[cfg(test)]
#[path = "sframe_tests.rs"]
mod tests;
