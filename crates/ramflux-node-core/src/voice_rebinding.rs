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
#[derive(Clone, Copy)]
pub(super) struct Admission<'lease, 'packet> {
    pub lease_id: &'lease str,
    pub index: u8,
    pub source: SocketAddr,
    pub payload: &'packet [u8],
    pub now: u64,
    pub challenge_allowed: bool,
}
pub(super) fn authenticates_pending(side: &Side, admission: Admission<'_, '_>) -> bool {
    let Admission { lease_id, index, source, payload, now, .. } = admission;
    side.challenge.as_ref().is_some_and(|challenge| {
        now < challenge.expires_at
            && source == challenge.address
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
    })
}
pub(super) fn admit<'packet>(
    side: &mut Side,
    admission: Admission<'_, 'packet>,
) -> Result<Option<VoiceRoute<'packet>>, NodeCoreError> {
    let Admission { lease_id: _, index: _, source, payload, now, challenge_allowed } = admission;
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
        if authenticates_pending(side, admission) {
            side.source = Some(source);
            side.challenge = None;
        }
        return Ok(Some(VoiceRoute::Drop));
    }
    if !challenge_allowed {
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
