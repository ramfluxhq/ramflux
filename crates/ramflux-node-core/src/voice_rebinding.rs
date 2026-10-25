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
            && payload.len() == 36
            && payload.starts_with(RESPONSE)
            && payload[4..] == challenge.cookie
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
    let mut packet = [0; 36];
    packet[..4].copy_from_slice(CHALLENGE);
    packet[4..].copy_from_slice(&cookie);
    // The smallest authenticated input is 36 bytes; the reply cannot amplify its byte count.
    Ok(Some(VoiceRoute::Challenge { target: source, packet }))
}
