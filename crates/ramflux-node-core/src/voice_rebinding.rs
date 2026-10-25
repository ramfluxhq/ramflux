// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A token authorizes media; changing its pinned source additionally requires return routability.
use super::{NodeCoreError, Side, SocketAddr, VoiceRoute};
const CHALLENGE_TTL: u64 = 5;
const CHALLENGE: &[u8; 4] = b"RFVC";
const RESPONSE: &[u8; 4] = b"RFVE";
pub(super) struct Challenge {
    address: SocketAddr,
    cookie: [u8; 32],
    expires_at: u64,
}
pub(super) fn admit<'a>(
    side: &mut Side,
    lease_id: &str,
    index: u8,
    source: SocketAddr,
    payload: &[u8],
    now: u64,
) -> Result<Option<VoiceRoute<'a>>, NodeCoreError> {
    if side.source.is_none() {
        if payload.starts_with(RESPONSE) {
            return Ok(Some(VoiceRoute::Drop));
        }
        side.source = Some(source);
    }
    if side.source == Some(source) {
        return Ok(payload.starts_with(RESPONSE).then_some(VoiceRoute::Drop));
    }
    if let Some(challenge) = &side.challenge
        && now < challenge.expires_at
    {
        if source == challenge.address
            && payload.len() == 52
            && payload.starts_with(RESPONSE)
            && payload[4..36] == challenge.cookie
            && ramflux_crypto::verify_voice_rebind_tag(
                &side.rebind_key,
                lease_id,
                index,
                &challenge.cookie,
                source,
                &payload[36..],
            )
            .is_ok()
        {
            side.source = Some(source);
            side.challenge = None;
        }
        return Ok(Some(VoiceRoute::Drop));
    }
    let cookie =
        ramflux_crypto::random_32().map_err(|_| super::refused("voice entropy unavailable"))?;
    side.challenge =
        Some(Challenge { address: source, cookie, expires_at: now.saturating_add(CHALLENGE_TTL) });
    let mut packet = Vec::with_capacity(55);
    packet.extend_from_slice(CHALLENGE);
    packet.extend_from_slice(&cookie);
    match source.ip() {
        std::net::IpAddr::V4(ip) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            packet.push(6);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&source.port().to_be_bytes());
    Ok(Some(VoiceRoute::Challenge { target: source, packet }))
}
