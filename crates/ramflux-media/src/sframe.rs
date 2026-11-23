// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `SFrame` (RFC 9605): end-to-end encryption of each media payload.
//!
//! - [`Header`]: the KID / CTR header (RFC 9605 §4.3), encoded in its
//!   minimal form.
//! - [`CipherSuite`]: what a suite provides (§4.5): key derivation (§4.4.2)
//!   and AEAD sealing and opening (§4.4.3, §4.4.4). Two suites are
//!   implemented: [`AES_256_GCM_SHA512_128`] (the one CALL-01 §3 chose) and
//!   [`AES_128_GCM_SHA256_128`]; [`suite`] picks one by its IANA id, so a
//!   session names its suite and the engine never hard-codes it.
//! - [`Sender`]: one sending key (encrypt only, §4.4.1), with its counter.
//! - [`Receiver`]: decryption keys by KID, each with a replay window
//!   (§9.3: anti-replay is the application's job).
//!
//! Base keys, derived keys and salts are wiped when dropped. A failed
//! decryption says only that it failed (§4.4.4).

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// IANA id of `AES_128_GCM_SHA256_128` (RFC 9605 §8.1).
pub const AES_128_GCM_SHA256_128: u16 = 0x0004;
/// IANA id of `AES_256_GCM_SHA512_128` (RFC 9605 §8.1), the CALL-01 suite.
pub const AES_256_GCM_SHA512_128: u16 = 0x0005;

/// Nonce size of every implemented suite (`AEAD.Nn`).
pub const NONCE_LEN: usize = 12;

/// Longest header: the config byte, an 8-byte KID and an 8-byte CTR.
pub const MAX_HEADER_LEN: usize = 17;

/// Packets remembered per key for replay detection (RFC 9605 §9.3).
///
/// The width is the product receiver's [`ramflux_crypto::SFRAME_REPLAY_WINDOW`].
pub use ramflux_crypto::SFRAME_REPLAY_WINDOW as REPLAY_WINDOW;

/// The bitmap is one bit per counter, so the shared window is a multiple of 64.
const _: () = assert!(REPLAY_WINDOW >= 64 && REPLAY_WINDOW.is_multiple_of(64));

/// Why an `SFrame` operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SframeError {
    /// The suite id is not implemented.
    #[error("unsupported SFrame cipher suite {0:#06x}")]
    UnsupportedSuite(u16),
    /// The base key does not fit the suite.
    #[error("SFrame base key must not be empty")]
    EmptyKey,
    /// The header is truncated or malformed.
    #[error("malformed SFrame header")]
    Header,
    /// No key is known for the header's KID.
    #[error("no SFrame key for this KID")]
    UnknownKid,
    /// Authentication failed (wrong key, altered data or metadata).
    #[error("SFrame decryption failed")]
    Decrypt,
    /// The counter was used before, or is older than the replay window.
    #[error("SFrame replay")]
    Replay,
    /// The sending counter is exhausted: the key must be replaced.
    #[error("SFrame counter exhausted")]
    CounterExhausted,
}

/// The `SFrame` header: which key (KID) and which counter (CTR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Key id.
    pub kid: u64,
    /// Counter.
    pub ctr: u64,
}

/// Bytes needed for `value` in big-endian, without leading zeros (1..=8).
fn min_len(value: u64) -> usize {
    (8 - (value.leading_zeros() / 8) as usize).max(1)
}

impl Header {
    /// Appends the encoded header to `out` (RFC 9605 §4.3, minimal form).
    pub fn encode_into(self, out: &mut Vec<u8>) {
        let mut config = 0_u8;
        let kid_len = if self.kid < 8 {
            config |= u8::try_from(self.kid).unwrap_or(0) << 4;
            0
        } else {
            let len = min_len(self.kid);
            config |= 0x80 | (u8::try_from(len - 1).unwrap_or(0) << 4);
            len
        };
        let ctr_len = if self.ctr < 8 {
            config |= u8::try_from(self.ctr).unwrap_or(0);
            0
        } else {
            let len = min_len(self.ctr);
            config |= 0x08 | u8::try_from(len - 1).unwrap_or(0);
            len
        };
        out.push(config);
        out.extend_from_slice(&self.kid.to_be_bytes()[8 - kid_len..]);
        out.extend_from_slice(&self.ctr.to_be_bytes()[8 - ctr_len..]);
    }

    /// The encoded header.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_HEADER_LEN);
        self.encode_into(&mut out);
        out
    }

    /// Decodes a header at the start of `data`; returns it and its length.
    ///
    /// # Errors
    ///
    /// [`SframeError::Header`] when `data` is too short, or a value is not
    /// in its minimal form (a decoder that accepted other forms would let
    /// one ciphertext carry several headers).
    pub fn decode(data: &[u8]) -> Result<(Self, usize), SframeError> {
        let config = *data.first().ok_or(SframeError::Header)?;
        let mut at = 1;
        let mut field = |extended: bool, bits: u8| -> Result<u64, SframeError> {
            if !extended {
                return Ok(u64::from(bits));
            }
            let len = usize::from(bits) + 1;
            let bytes = data.get(at..at + len).ok_or(SframeError::Header)?;
            at += len;
            let value = bytes.iter().fold(0_u64, |acc, b| (acc << 8) | u64::from(*b));
            if value < 8 || min_len(value) != len {
                return Err(SframeError::Header);
            }
            Ok(value)
        };
        let kid = field(config & 0x80 != 0, (config >> 4) & 0x07)?;
        let ctr = field(config & 0x08 != 0, config & 0x07)?;
        Ok((Self { kid, ctr }, at))
    }
}

/// A key derived for one KID: it seals or opens with the counter's nonce.
pub trait KeyContext: Send {
    /// Encrypts `plaintext` with the nonce of `ctr` and authenticates `aad`.
    ///
    /// # Errors
    ///
    /// [`SframeError::Decrypt`] when the AEAD refuses (oversized input).
    fn seal(&self, ctr: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SframeError>;

    /// Decrypts and authenticates `ciphertext` (with its tag).
    ///
    /// # Errors
    ///
    /// [`SframeError::Decrypt`] on any authentication failure.
    fn open(&self, ctr: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SframeError>;
}

/// An `SFrame` cipher suite (RFC 9605 §4.5).
pub trait CipherSuite: Send + Sync {
    /// The suite's IANA id.
    fn id(&self) -> u16;
    /// Bytes the AEAD adds to each payload (`AEAD.Nt`).
    fn overhead(&self) -> usize;
    /// Derives the key and salt of `kid` from `base_key` (§4.4.2).
    ///
    /// # Errors
    ///
    /// [`SframeError::EmptyKey`] for an empty base key.
    fn derive(&self, kid: u64, base_key: &[u8]) -> Result<Box<dyn KeyContext>, SframeError>;
}

/// The suite with IANA id `id`.
///
/// # Errors
///
/// [`SframeError::UnsupportedSuite`] for any other id (the AES-CTR suites
/// are not implemented: CALL-01 uses a 128-bit GCM tag).
pub fn suite(id: u16) -> Result<&'static dyn CipherSuite, SframeError> {
    match id {
        AES_256_GCM_SHA512_128 => Ok(&Aes256GcmSha512),
        AES_128_GCM_SHA256_128 => Ok(&Aes128GcmSha256),
        other => Err(SframeError::UnsupportedSuite(other)),
    }
}

/// The HKDF labels of §4.4.2: the 8-byte KID and the 2-byte suite id.
fn labels(kid: u64, suite: u16) -> (Vec<u8>, Vec<u8>) {
    let tail: Vec<u8> = kid.to_be_bytes().into_iter().chain(suite.to_be_bytes()).collect();
    let mut key = b"SFrame 1.0 Secret key ".to_vec();
    key.extend_from_slice(&tail);
    let mut salt = b"SFrame 1.0 Secret salt ".to_vec();
    salt.extend_from_slice(&tail);
    (key, salt)
}

/// The nonce of `ctr`: the salt XOR the counter, big-endian (§4.4.3).
fn nonce(salt: &[u8; NONCE_LEN], ctr: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *salt;
    for (byte, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(ctr.to_be_bytes()) {
        *byte ^= c;
    }
    nonce
}

macro_rules! gcm_suite {
    ($(#[$meta:meta])* $suite:ident, $context:ident, $id:expr, $aead:ty, $hash:ty, $nk:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $suite;

        struct $context {
            aead: $aead,
            salt: Zeroizing<[u8; NONCE_LEN]>,
        }

        impl KeyContext for $context {
            fn seal(&self, ctr: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SframeError> {
                let nonce = nonce(&self.salt, ctr);
                self.aead
                    .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
                    .map_err(|_| SframeError::Decrypt)
            }

            fn open(&self, ctr: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SframeError> {
                let nonce = nonce(&self.salt, ctr);
                self.aead
                    .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
                    .map_err(|_| SframeError::Decrypt)
            }
        }

        impl CipherSuite for $suite {
            fn id(&self) -> u16 {
                $id
            }

            fn overhead(&self) -> usize {
                16
            }

            fn derive(&self, kid: u64, base_key: &[u8]) -> Result<Box<dyn KeyContext>, SframeError> {
                if base_key.is_empty() {
                    return Err(SframeError::EmptyKey);
                }
                let secret = Hkdf::<$hash>::new(Some(&[]), base_key);
                let (key_label, salt_label) = labels(kid, $id);
                let mut key = Zeroizing::new([0_u8; $nk]);
                let mut salt = Zeroizing::new([0_u8; NONCE_LEN]);
                secret.expand(&key_label, key.as_mut()).map_err(|_| SframeError::EmptyKey)?;
                secret.expand(&salt_label, salt.as_mut()).map_err(|_| SframeError::EmptyKey)?;
                let aead = <$aead>::new_from_slice(key.as_ref()).map_err(|_| SframeError::EmptyKey)?;
                Ok(Box::new($context { aead, salt }))
            }
        }
    };
}

gcm_suite!(
    /// `AES_256_GCM_SHA512_128` (0x0005): AES-256-GCM, HKDF-SHA-512, 128-bit tag.
    Aes256GcmSha512,
    Aes256Context,
    AES_256_GCM_SHA512_128,
    Aes256Gcm,
    Sha512,
    32
);

gcm_suite!(
    /// `AES_128_GCM_SHA256_128` (0x0004): AES-128-GCM, HKDF-SHA-256, 128-bit tag.
    Aes128GcmSha256,
    Aes128Context,
    AES_128_GCM_SHA256_128,
    Aes128Gcm,
    Sha256,
    16
);

/// A sending key: encrypts with its KID and the next counter value.
pub struct Sender {
    kid: u64,
    key: Box<dyn KeyContext>,
    next_ctr: u64,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("kid", &self.kid)
            .field("key", &"<redacted>")
            .field("next_ctr", &self.next_ctr)
            .finish()
    }
}

impl Sender {
    /// A sender for `kid` with `base_key` under `suite`. The caller's copy
    /// of the base key should be wiped after this call.
    ///
    /// # Errors
    ///
    /// As [`CipherSuite::derive`].
    pub fn new(suite: &dyn CipherSuite, kid: u64, base_key: &[u8]) -> Result<Self, SframeError> {
        Ok(Self { kid, key: suite.derive(kid, base_key)?, next_ctr: 0 })
    }

    /// The key id.
    #[must_use]
    pub fn kid(&self) -> u64 {
        self.kid
    }

    /// Encrypts one payload: the header, then the ciphertext and its tag.
    /// `metadata` is authenticated but not sent (§9.4).
    ///
    /// # Errors
    ///
    /// [`SframeError::CounterExhausted`] after 2^64 - 1 payloads.
    pub fn encrypt(&mut self, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SframeError> {
        let ctr = self.next_ctr;
        self.next_ctr = ctr.checked_add(1).ok_or(SframeError::CounterExhausted)?;
        let header = Header { kid: self.kid, ctr }.encode();
        let mut aad = Zeroizing::new(header.clone());
        aad.extend_from_slice(metadata);
        let sealed = self.key.seal(ctr, &aad, plaintext)?;
        let mut out = header;
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

/// Which counters of one key were already accepted.
#[derive(Debug, Default)]
struct ReplayWindow {
    /// The highest counter accepted, once one was.
    highest: Option<u64>,
    /// Bit `i` set: `highest - i` was accepted.
    seen: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl ReplayWindow {
    fn bit(&self, back: u64) -> bool {
        let (word, bit) = ((back / 64) as usize, back % 64);
        self.seen.get(word).is_some_and(|value| value & (1 << bit) != 0)
    }

    fn set(&mut self, back: u64) {
        let (word, bit) = ((back / 64) as usize, back % 64);
        if let Some(value) = self.seen.get_mut(word) {
            *value |= 1 << bit;
        }
    }

    fn check(&self, ctr: u64) -> Result<(), SframeError> {
        let Some(high) = self.highest else {
            return Ok(());
        };
        if ctr > high {
            return Ok(());
        }
        let age = high - ctr;
        if age >= REPLAY_WINDOW || self.bit(age) { Err(SframeError::Replay) } else { Ok(()) }
    }

    fn accept(&mut self, ctr: u64) {
        match self.highest {
            Some(high) if ctr <= high => self.set(high - ctr),
            Some(high) => {
                let shift = ctr - high;
                if shift >= REPLAY_WINDOW {
                    self.seen = Default::default();
                } else {
                    // Shift the bitmap by `shift` bits towards older counters.
                    let (words, bits) = ((shift / 64) as usize, (shift % 64) as u32);
                    let len = self.seen.len();
                    for i in (0..len).rev() {
                        let from = i.checked_sub(words);
                        let mut value =
                            from.and_then(|f| self.seen.get(f).copied()).unwrap_or(0) << bits;
                        if bits > 0
                            && let Some(lower) = from.and_then(|f| f.checked_sub(1))
                            && let Some(lower_bits) = self.seen.get(lower).copied()
                        {
                            value |= lower_bits >> (64 - bits);
                        }
                        if let Some(slot) = self.seen.get_mut(i) {
                            *slot = value;
                        }
                    }
                }
                self.highest = Some(ctr);
                self.set(0);
            }
            None => {
                self.highest = Some(ctr);
                self.set(0);
            }
        }
    }
}

struct ReceiveKey {
    key: Box<dyn KeyContext>,
    window: ReplayWindow,
}

/// Decryption keys by KID, each with its replay window.
#[derive(Default)]
pub struct Receiver {
    keys: BTreeMap<u64, ReceiveKey>,
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver").field("kids", &self.keys.keys().collect::<Vec<_>>()).finish()
    }
}

impl Receiver {
    /// An empty receiver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces, on a rekey) the decryption key of `kid`.
    ///
    /// # Errors
    ///
    /// As [`CipherSuite::derive`].
    pub fn add_key(
        &mut self,
        suite: &dyn CipherSuite,
        kid: u64,
        base_key: &[u8],
    ) -> Result<(), SframeError> {
        let key = suite.derive(kid, base_key)?;
        self.keys.insert(kid, ReceiveKey { key, window: ReplayWindow::default() });
        Ok(())
    }

    /// Forgets the key of `kid`.
    pub fn remove_key(&mut self, kid: u64) {
        self.keys.remove(&kid);
    }

    /// Decrypts one `SFrame` ciphertext; `metadata` must be what the sender
    /// authenticated. A counter is accepted once.
    ///
    /// # Errors
    ///
    /// [`SframeError::Header`], [`SframeError::UnknownKid`],
    /// [`SframeError::Replay`] or [`SframeError::Decrypt`]; the receiver's
    /// state is unchanged by a failure.
    pub fn decrypt(&mut self, metadata: &[u8], data: &[u8]) -> Result<Vec<u8>, SframeError> {
        let (header, len) = Header::decode(data)?;
        let entry = self.keys.get_mut(&header.kid).ok_or(SframeError::UnknownKid)?;
        entry.window.check(header.ctr)?;
        let mut aad = Zeroizing::new(data[..len].to_vec());
        aad.extend_from_slice(metadata);
        let plaintext = entry.key.open(header.ctr, &aad, &data[len..])?;
        entry.window.accept(header.ctr);
        Ok(plaintext)
    }
}

/// A base key that is wiped when dropped and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct BaseKey(Zeroizing<Vec<u8>>);

impl BaseKey {
    /// Wraps key bytes (the caller wipes its own copy).
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A fresh random 256-bit key.
    ///
    /// # Errors
    ///
    /// The operating system's random source failed.
    pub fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new(vec![0_u8; 32]);
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// The key bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for BaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BaseKey(<redacted>)")
    }
}

impl Zeroize for BaseKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_len_counts_significant_bytes() {
        assert_eq!(min_len(0), 1);
        assert_eq!(min_len(8), 1);
        assert_eq!(min_len(0xff), 1);
        assert_eq!(min_len(0x100), 2);
        assert_eq!(min_len(u64::MAX), 8);
    }

    #[test]
    fn replay_window_accepts_each_counter_once() {
        let mut window = ReplayWindow::default();
        let high = REPLAY_WINDOW + 200;
        let inside = high - (REPLAY_WINDOW - 50);
        for ctr in [5, 3, 9, 4, inside, high] {
            assert_eq!(window.check(ctr), Ok(()), "{ctr}");
            window.accept(ctr);
            assert_eq!(window.check(ctr), Err(SframeError::Replay), "{ctr}");
        }
        // The early counters fell out when the window advanced to `high`.
        assert_eq!(window.check(5), Err(SframeError::Replay));
        assert_eq!(window.check(high - 1), Ok(()));
        assert_eq!(window.check(high - (REPLAY_WINDOW - 1)), Ok(()));
        assert_eq!(window.check(high - REPLAY_WINDOW), Err(SframeError::Replay));
    }

    #[test]
    fn replay_window_shifts_across_words() {
        let mut window = ReplayWindow::default();
        window.accept(10);
        window.accept(80);
        window.accept(90);
        assert_eq!(window.check(10), Err(SframeError::Replay));
        assert_eq!(window.check(80), Err(SframeError::Replay));
        assert_eq!(window.check(81), Ok(()));
        assert_eq!(window.check(11), Ok(()));
    }
}
