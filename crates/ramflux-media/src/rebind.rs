// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Moving this side's relay binding to a new address (CALL-01 r2).
//!
//! The relay pins each side of a lease to the source address of its first
//! token-framed datagram. When this device's address changes (a NAT
//! rebinding, a network change), the relay does not follow on the token
//! alone: it sends a raw return-routability challenge to the new address,
//! naming the address it observed (the public NAT mapping, not the local
//! socket address):
//!
//! ```text
//! challenge = "RFVC" || cookie[32] || new_addr_bytes
//! new_addr_bytes = family_u8 || IP_octets || UDP_port_u16be
//! family = 4 with 4 IPv4 octets (43 bytes), or 6 with 16 IPv6 octets (55)
//! ```
//!
//! This side answers from that address, within five seconds, in the usual
//! token framing ([`crate::relay::frame`]), with an HMAC under its private
//! rebind key that binds the lease, its side, the cookie and the address:
//!
//! ```text
//! tag = HMAC-SHA256(rebind_key, "ramflux.voice.rebind.v1" || lease_id[16]
//!                   || side_u8 || cookie[32] || new_addr_bytes)[0..16]
//! response = "RFVE" || cookie[32] || tag[16]
//! ```
//!
//! Only that answer moves the pin: someone holding a copy of the token
//! and the cookie cannot. The relay consumes it; the peer never sees it.
//! Ordinary media carries no per-packet MAC. Moving the binding changes
//! nothing else: the `SFrame` sender keeps its counter and the receiver its
//! replay window (the keys are never set up again).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The challenge's magic.
pub const CHALLENGE_MAGIC: &[u8; 4] = b"RFVC";
/// The response's magic.
pub const RESPONSE_MAGIC: &[u8; 4] = b"RFVE";
/// The HMAC domain separation label.
pub const LABEL: &[u8] = b"ramflux.voice.rebind.v1";
/// Bytes of the cookie.
pub const COOKIE_LEN: usize = 32;
/// Bytes of the truncated tag.
pub const TAG_LEN: usize = 16;
/// Bytes of a response payload.
pub const RESPONSE_LEN: usize = 4 + COOKIE_LEN + TAG_LEN;
/// Bytes of an IPv4 challenge.
pub const CHALLENGE_V4_LEN: usize = 4 + COOKIE_LEN + 1 + 4 + 2;
/// Bytes of an IPv6 challenge.
pub const CHALLENGE_V6_LEN: usize = 4 + COOKIE_LEN + 1 + 16 + 2;

/// This side's rebinding credential: the lease, its side, its private
/// rebind key. Wiped on drop, never printed.
#[derive(PartialEq, Eq)]
pub struct Rebind {
    lease_id: [u8; 16],
    side: u8,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Rebind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rebind").field("side", &self.side).finish_non_exhaustive()
    }
}

/// A challenge the relay sent: its cookie and the address it observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge<'a> {
    /// The cookie to echo.
    pub cookie: &'a [u8; COOKIE_LEN],
    /// The observed address as the relay encoded it (family, IP, port).
    pub address: &'a [u8],
}

/// Reads a raw datagram as a rebinding challenge; `None` when it is not
/// one (an RTP packet starts with version 2, never with `RFVC`).
#[must_use]
pub fn challenge(datagram: &[u8]) -> Option<Challenge<'_>> {
    let rest = datagram.strip_prefix(CHALLENGE_MAGIC)?;
    let (cookie, address) = rest.split_at_checked(COOKIE_LEN)?;
    let well_formed = match address.first() {
        Some(4) => datagram.len() == CHALLENGE_V4_LEN,
        Some(6) => datagram.len() == CHALLENGE_V6_LEN,
        _ => false,
    };
    if !well_formed {
        return None;
    }
    Some(Challenge { cookie: cookie.try_into().ok()?, address })
}

impl Rebind {
    /// The credential of `side` (0 caller, 1 callee) on `lease_id`.
    /// `None` for a side other than 0 or 1.
    /// The key is copied into a buffer wiped on drop.
    #[must_use]
    pub fn new(lease_id: [u8; 16], side: u8, key: &[u8; 32]) -> Option<Self> {
        (side <= 1).then(|| Self { lease_id, side, key: Zeroizing::new(*key) })
    }

    /// This device's side.
    #[must_use]
    pub fn side(&self) -> u8 {
        self.side
    }

    /// The truncated tag for `cookie` and the observed `address` bytes.
    #[must_use]
    pub fn tag(&self, cookie: &[u8; COOKIE_LEN], address: &[u8]) -> [u8; TAG_LEN] {
        // HMAC-SHA256 accepts every key length. A refusal is a broken
        // dependency: the relay will not accept an all-zero tag.
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.key.as_slice()) else {
            return [0_u8; TAG_LEN];
        };
        mac.update(LABEL);
        mac.update(&self.lease_id);
        mac.update(&[self.side]);
        mac.update(cookie);
        mac.update(address);
        let full = mac.finalize().into_bytes();
        let mut tag = [0_u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        tag
    }

    /// The response payload to `challenge` (`RFVE || cookie || tag`), to
    /// send in the token framing from the socket the challenge reached.
    #[must_use]
    pub fn response(&self, challenge: &Challenge<'_>) -> [u8; RESPONSE_LEN] {
        let mut out = [0_u8; RESPONSE_LEN];
        out[..4].copy_from_slice(RESPONSE_MAGIC);
        out[4..4 + COOKIE_LEN].copy_from_slice(challenge.cookie);
        out[4 + COOKIE_LEN..].copy_from_slice(&self.tag(challenge.cookie, challenge.address));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counting<const N: usize>(from: u8) -> [u8; N] {
        std::array::from_fn(|i| from.wrapping_add(u8::try_from(i % 256).unwrap_or(0)))
    }

    fn v4_challenge() -> Vec<u8> {
        let mut c = CHALLENGE_MAGIC.to_vec();
        c.extend_from_slice(&counting::<32>(32));
        c.extend_from_slice(&[4, 203, 0, 113, 7]);
        c.extend_from_slice(&54_321_u16.to_be_bytes());
        c
    }

    #[test]
    fn challenges_are_recognised_only_well_formed() {
        let c = v4_challenge();
        assert_eq!(c.len(), CHALLENGE_V4_LEN);
        let read = challenge(&c).expect("challenge");
        assert_eq!(read.cookie, &counting::<32>(32));
        assert_eq!(read.address, &[4, 203, 0, 113, 7, 0xd4, 0x31]);
        // Wrong length for the family, unknown family, not a challenge.
        assert_eq!(challenge(&c[..42]), None);
        let mut v6_sized = c.clone();
        v6_sized.extend_from_slice(&[0; 12]);
        assert_eq!(challenge(&v6_sized), None);
        let mut family = c.clone();
        family[36] = 5;
        assert_eq!(challenge(&family), None);
        assert_eq!(challenge(b"RFVE"), None);
        assert_eq!(challenge(&[0x80, 111, 0, 1]), None);
    }

    #[test]
    fn sides_other_than_caller_and_callee_are_refused() {
        assert!(Rebind::new([0; 16], 2, &[0; 32]).is_none());
        let rebind = Rebind::new([0; 16], 1, &[7; 32]).expect("callee");
        let printed = format!("{rebind:?}");
        assert!(printed.contains("side: 1") && !printed.contains('7'), "{printed}");
    }
}
