// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical address-bound, truncated HMAC proof for opaque voice relay rebinding.
use crate::CryptoError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;
fn mac(
    key: &[u8; 32],
    lease_id: &str,
    side: u8,
    cookie: &[u8; 32],
    address: SocketAddr,
) -> Result<Hmac<Sha256>, CryptoError> {
    let lease = ramflux_protocol::decode_base64url(lease_id)
        .map_err(|_| CryptoError::VoiceRebind("voice lease id"))?;
    if lease.len() != 16 || side > 1 {
        return Err(CryptoError::VoiceRebind("voice rebind scope"));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::HkdfFailed)?;
    mac.update(b"ramflux.voice.rebind.v1");
    mac.update(&lease);
    mac.update(&[side]);
    mac.update(cookie);
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            mac.update(&[4]);
            mac.update(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            mac.update(&[6]);
            mac.update(&ip.octets());
        }
    }
    mac.update(&address.port().to_be_bytes());
    Ok(mac)
}
/// First 16 HMAC-SHA256 bytes; lease id is decoded 16 bytes, side is one byte, address is family/IP/port.
/// # Errors
/// Rejects invalid lease ids and sides.
pub fn voice_rebind_tag(
    key: &[u8; 32],
    lease_id: &str,
    side: u8,
    cookie: &[u8; 32],
    address: SocketAddr,
) -> Result<[u8; 16], CryptoError> {
    let result = mac(key, lease_id, side, cookie, address)?.finalize().into_bytes();
    let mut tag = [0; 16];
    tag.copy_from_slice(&result[..16]);
    Ok(tag)
}
/// Verifies exactly 16 tag bytes in constant time.
/// # Errors
/// Rejects invalid scope or any mismatched/truncated proof.
pub fn verify_voice_rebind_tag(
    key: &[u8; 32],
    lease_id: &str,
    side: u8,
    cookie: &[u8; 32],
    address: SocketAddr,
    tag: &[u8],
) -> Result<(), CryptoError> {
    if tag.len() != 16 {
        return Err(CryptoError::AeadFailed);
    }
    mac(key, lease_id, side, cookie, address)?
        .verify_truncated_left(tag)
        .map_err(|_| CryptoError::AeadFailed)
}

/// Builds an HMAC echo using the relay-observed public source, including NAT port mapping.
/// # Errors
/// Rejects malformed challenges and invalid lease scopes.
pub fn voice_rebind_response(
    key: &[u8; 32],
    lease_id: &str,
    side: u8,
    challenge: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !challenge.starts_with(b"RFVC") {
        return Err(CryptoError::AeadFailed);
    }
    let address = match (challenge.get(36), challenge.len()) {
        (Some(4), 43) => SocketAddr::new(
            std::net::Ipv4Addr::new(challenge[37], challenge[38], challenge[39], challenge[40])
                .into(),
            u16::from_be_bytes([challenge[41], challenge[42]]),
        ),
        (Some(6), 55) => {
            let mut ip = [0; 16];
            ip.copy_from_slice(&challenge[37..53]);
            SocketAddr::new(
                std::net::Ipv6Addr::from(ip).into(),
                u16::from_be_bytes([challenge[53], challenge[54]]),
            )
        }
        _ => return Err(CryptoError::AeadFailed),
    };
    let mut cookie = [0; 32];
    cookie.copy_from_slice(&challenge[4..36]);
    let mut response = b"RFVE".to_vec();
    response.extend_from_slice(&cookie);
    response.extend_from_slice(&voice_rebind_tag(key, lease_id, side, &cookie, address)?);
    Ok(response)
}

#[cfg(test)]
#[path = "voice_rebind_tests.rs"]
mod tests;
