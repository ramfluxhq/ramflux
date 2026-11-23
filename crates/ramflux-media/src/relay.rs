// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Datagrams to and from the relay allocation.
//!
//! Towards the relay each datagram carries the allocation token in front of
//! the media packet: a 4-byte big-endian token length, the token, then the
//! packet (the framing of the product's opaque media relay,
//! `ramflux-node-core` `encode_turn_media_relay_packet`). The relay checks
//! the token, binds the sender's address to its allocation, and forwards
//! the packet alone to the peer's allocation; so what arrives here is a
//! bare packet. The token is opaque to the client: the daemon issues it.
//!
//! An empty token means no relay (a direct endpoint, used by tests): the
//! packet is sent bare.

/// Largest datagram the relay accepts (its UDP payload limit).
pub const MAX_DATAGRAM: usize = 65_507;

/// Bytes of the token length prefix.
pub const LENGTH_PREFIX: usize = 4;

/// The datagram that carries `packet` to the relay under `token`.
#[must_use]
pub fn frame(token: &[u8], packet: &[u8]) -> Vec<u8> {
    if token.is_empty() {
        return packet.to_vec();
    }
    let len = u32::try_from(token.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(LENGTH_PREFIX + token.len() + packet.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(token);
    out.extend_from_slice(packet);
    out
}

/// Splits a framed datagram into its token and packet (what a relay does;
/// used by the tests' stand-in relay).
#[must_use]
pub fn unframe(datagram: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(datagram.get(..LENGTH_PREFIX)?.try_into().ok()?) as usize;
    let end = LENGTH_PREFIX.checked_add(len)?;
    (len > 0 && end <= datagram.len()).then(|| (&datagram[LENGTH_PREFIX..end], &datagram[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_bare_without_token() {
        let datagram = frame(b"{\"token\":1}", b"media");
        assert_eq!(&datagram[..4], &11_u32.to_be_bytes());
        assert_eq!(unframe(&datagram), Some((&b"{\"token\":1}"[..], &b"media"[..])));
        assert_eq!(frame(b"", b"media"), b"media");
        assert_eq!(unframe(&[0, 0, 0, 9, 1]), None);
        assert_eq!(unframe(&[0, 0, 0, 0, 1]), None);
    }
}
