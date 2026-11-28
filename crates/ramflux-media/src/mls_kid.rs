// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The `SFrame` KID of an MLS call (MLS-CALL card section 2).
//!
//! `KID = (stream << (S + E)) | (leaf << E) | (epoch mod 2^E)` with the fixed widths `S = 16`
//! (leaf bits) and `E = 4` (epoch bits), so both sides agree without knowing the tree size.
//! `stream` is 0 audio, 1 video, 2 screen (reserved). The largest KID is below `2^22`, which
//! `RFC 9605` section 4.3 encodes in at most 3 bytes.
//!
//! The KID is in the clear and unauthenticated until the AEAD opens; it carries no secret.

use thiserror::Error;

/// Bits of the epoch field.
pub const EPOCH_BITS: u32 = 4;
/// Bits of the leaf field.
pub const LEAF_BITS: u32 = 16;
/// Leaves must be below this.
pub const LEAF_LIMIT: u32 = 1 << LEAF_BITS;
/// Highest stream id.
pub const MAX_STREAM: u8 = 2;

/// Media stream of a KID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stream {
    /// Voice.
    Audio = 0,
    /// Camera video.
    Video = 1,
    /// Screen share (reserved).
    Screen = 2,
}

impl Stream {
    /// The stream with wire value `value`.
    ///
    /// # Errors
    /// [`KidError::Stream`] above [`MAX_STREAM`].
    pub fn from_u8(value: u8) -> Result<Self, KidError> {
        match value {
            0 => Ok(Self::Audio),
            1 => Ok(Self::Video),
            2 => Ok(Self::Screen),
            _ => Err(KidError::Stream),
        }
    }
}

/// Why a KID was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KidError {
    /// The stream id is above [`MAX_STREAM`].
    #[error("stream out of range")]
    Stream,
    /// The leaf index does not fit 16 bits.
    #[error("leaf out of range")]
    Leaf,
    /// The epoch field is wider than 4 bits.
    #[error("epoch bits out of range")]
    Epoch,
    /// The KID has bits above the stream field, or an unknown stream.
    #[error("kid out of range")]
    Kid,
}

/// The fields of a call KID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KidParts {
    /// Media stream.
    pub stream: Stream,
    /// Sender leaf index.
    pub leaf: u32,
    /// Low 4 bits of the sender's epoch.
    pub epoch_bits: u8,
}

/// The low [`EPOCH_BITS`] bits of `epoch`.
#[must_use]
pub fn epoch_bits(epoch: u64) -> u8 {
    u8::try_from(epoch & ((1 << EPOCH_BITS) - 1)).unwrap_or(0)
}

/// Encodes a KID from already-reduced fields.
///
/// # Errors
/// [`KidError::Leaf`] for `leaf >= 2^16`, [`KidError::Epoch`] for `epoch_bits >= 16`.
pub fn encode(stream: Stream, leaf: u32, epoch_bits: u8) -> Result<u64, KidError> {
    if leaf >= LEAF_LIMIT {
        return Err(KidError::Leaf);
    }
    if u32::from(epoch_bits) >= (1 << EPOCH_BITS) {
        return Err(KidError::Epoch);
    }
    Ok((u64::from(stream as u8) << (LEAF_BITS + EPOCH_BITS))
        | (u64::from(leaf) << EPOCH_BITS)
        | u64::from(epoch_bits))
}

/// Encodes the KID of `leaf` in `epoch` (reduced mod 16 here).
///
/// # Errors
/// [`KidError::Leaf`] for `leaf >= 2^16`.
pub fn encode_for_epoch(stream: Stream, leaf: u32, epoch: u64) -> Result<u64, KidError> {
    encode(stream, leaf, epoch_bits(epoch))
}

/// Splits a KID.
///
/// # Errors
/// [`KidError::Kid`] when the KID has bits above the stream field or an unknown stream.
pub fn decode(kid: u64) -> Result<KidParts, KidError> {
    let stream_raw = kid >> (LEAF_BITS + EPOCH_BITS);
    let stream = u8::try_from(stream_raw).map_err(|_| KidError::Kid)?;
    let stream = Stream::from_u8(stream).map_err(|_| KidError::Kid)?;
    let leaf = u32::try_from((kid >> EPOCH_BITS) & u64::from(LEAF_LIMIT - 1))
        .map_err(|_| KidError::Kid)?;
    Ok(KidParts { stream, leaf, epoch_bits: epoch_bits(kid) })
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test fixtures")]
mod tests {
    use super::*;
    use crate::sframe::{AES_256_GCM_SHA512_128, Header, Receiver, Sender, suite};

    #[test]
    fn layout_is_stream_leaf_epoch() {
        assert_eq!(encode(Stream::Audio, 0, 0), Ok(0));
        assert_eq!(encode(Stream::Audio, 1, 2), Ok(0x12));
        assert_eq!(encode(Stream::Video, 3, 5), Ok((1 << 20) | (3 << 4) | 5));
        assert_eq!(encode(Stream::Screen, 0xFFFF, 0xF), Ok((2 << 20) | 0xF_FFFF));
        assert_eq!(encode_for_epoch(Stream::Audio, 7, 0x1_0013), Ok((7 << 4) | 3));
    }

    #[test]
    fn round_trips() {
        for stream in [Stream::Audio, Stream::Video, Stream::Screen] {
            for leaf in [0, 1, 255, 256, 3000, 0xFFFF] {
                for bits in 0..16 {
                    let kid = encode(stream, leaf, bits).unwrap_or(u64::MAX);
                    assert_eq!(decode(kid), Ok(KidParts { stream, leaf, epoch_bits: bits }));
                }
            }
        }
    }

    #[test]
    fn bounds_are_refused() {
        assert_eq!(encode(Stream::Audio, LEAF_LIMIT, 0), Err(KidError::Leaf));
        assert_eq!(encode(Stream::Audio, u32::MAX, 0), Err(KidError::Leaf));
        assert_eq!(encode(Stream::Audio, 0, 16), Err(KidError::Epoch));
        assert_eq!(Stream::from_u8(3), Err(KidError::Stream));
        assert_eq!(decode(3 << 20), Err(KidError::Kid));
        assert_eq!(decode(1 << 22), Err(KidError::Kid));
        assert_eq!(decode(u64::MAX), Err(KidError::Kid));
    }

    #[test]
    fn largest_kid_header_is_three_bytes() {
        let kid = encode(Stream::Screen, 0xFFFF, 0xF).unwrap_or(0);
        let header = Header { kid, ctr: 0 };
        let encoded = header.encode();
        assert_eq!(encoded.len(), 1 + 3);
        assert_eq!(Header::decode(&encoded), Ok((header, encoded.len())));
    }

    /// RFC 9605 Appendix C.1 cases whose KID is a call KID decode to the same value and re-encode
    /// to the same header.
    #[test]
    fn rfc_c1_header_vectors_in_range_round_trip() {
        let vectors = include_str!("../tests/vectors/rfc9605_c1_headers.txt");
        let mut seen = 0;
        for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let Some(kid_text) = line.split(' ').next() else { continue };
            let Ok(kid) = u64::from_str_radix(kid_text.trim_start_matches("0x"), 16) else {
                continue;
            };
            let Ok(parts) = decode(kid) else { continue };
            assert_eq!(encode(parts.stream, parts.leaf, parts.epoch_bits), Ok(kid), "{line}");
            seen += 1;
        }
        assert!(seen > 0);
    }

    #[test]
    fn kid_keys_a_sender_and_receiver() {
        let suite = suite(AES_256_GCM_SHA512_128).expect("suite 5");
        let base = [7_u8; 32];
        let kid = encode_for_epoch(Stream::Video, 4, 21).unwrap_or(0);
        let mut sender = Sender::new(suite, kid, &base).expect("sender");
        let mut receiver = Receiver::new();
        receiver.add_key(suite, kid, &base).expect("key");
        let packet = sender.encrypt(b"aad", b"frame").expect("seal");
        let opened = receiver.decrypt(b"aad", &packet).expect("open");
        assert_eq!(opened.as_slice(), b"frame");
    }
}
