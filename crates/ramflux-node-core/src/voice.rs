// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded production voice leases and opaque UDP forwarding; no media keys enter this module.
use crate::NodeCoreError;
use ramflux_protocol::{CallEndpoint, VoiceAllocation, VoiceAllocationRequest, VoiceLeaseConsent};
use std::{collections::BTreeMap, net::SocketAddr};
pub const VOICE_LEASE_SECONDS: u64 = 60;
pub const VOICE_PACKET_MAX_BYTES: usize = 1400;
const MAX_ALLOCATIONS: usize = 4096;
const ACCOUNT_LIMIT: usize = 2;
const MAX_LEASE_LIFETIME: u64 = 4 * 60 * 60;
const BYTES_PER_SECOND: usize = 128 * 1024;
const UNPINNED_BYTES_PER_SECOND: usize = 4 * 1024;
const MIN_REBIND_CHALLENGE_DATAGRAM_BYTES: usize = 60;
fn refused(message: &str) -> NodeCoreError {
    NodeCoreError::Unauthorized(message.into())
}
struct Side {
    token: String,
    rebind_key: zeroize::Zeroizing<[u8; 32]>,
    source: Option<SocketAddr>,
    second: u64,
    bytes: usize,
    unpinned_second: u64,
    unpinned_bytes: usize,
    challenge: Option<rebinding::Challenge>,
}
struct Lease {
    scope: VoiceAllocationRequest,
    id: String,
    consent: Option<VoiceLeaseConsent>,
    expires_at: u64,
    hard_expires_at: u64,
    sides: [Side; 2],
}
/// Credentials and source bindings are RAM-only. Restart drops all leases and fails closed.
#[derive(Default)]
pub struct VoiceRelayState {
    leases: BTreeMap<(String, String), Lease>,
    tokens: BTreeMap<String, ((String, String), usize)>,
    usage: quota::Usage,
}
impl VoiceRelayState {
    /// Allocates or recovers an exact scope owned by the authenticated node.
    /// # Errors
    /// Rejects changed scope, malformed identities and exhausted global/account capacity.
    pub fn allocate(
        &mut self,
        owner: &str,
        scope: &VoiceAllocationRequest,
        endpoint: &str,
        now: u64,
    ) -> Result<VoiceAllocation, NodeCoreError> {
        validate_voice_scope(scope)?;
        if owner.is_empty() || endpoint.is_empty() {
            return Err(refused("voice owner or endpoint missing"));
        }
        self.expire(now);
        let key = (owner.to_owned(), scope.call_id.clone());
        if let Some(lease) = self.leases.get(&key) {
            if &lease.scope != scope {
                return Err(refused("voice scope changed"));
            }
            return Ok(allocation(lease, endpoint, 0));
        }
        if self.leases.len() >= MAX_ALLOCATIONS
            || self.account_usage(&scope.caller) >= ACCOUNT_LIMIT
        {
            return Err(refused("voice allocation capacity exhausted"));
        }
        let sides = [new_side(now)?, new_side(now)?];
        if sides[0].token == sides[1].token
            || sides.iter().any(|s| self.tokens.contains_key(&s.token))
        {
            return Err(refused("voice credential collision"));
        }
        let lease = Lease {
            scope: scope.clone(),
            id: ramflux_protocol::encode_base64url(
                &ramflux_crypto::random_32().map_err(|_| refused("voice entropy unavailable"))?
                    [..16],
            ),
            consent: None,
            expires_at: now.saturating_add(VOICE_LEASE_SECONDS),
            hard_expires_at: now.saturating_add(MAX_LEASE_LIFETIME),
            sides,
        };
        let response = allocation(&lease, endpoint, 0);
        self.tokens.insert(lease.sides[0].token.clone(), (key.clone(), 0));
        self.usage.charge(&lease.scope.caller);
        self.leases.insert(key, lease);
        Ok(response)
    }
    /// Claims only the callee's secrets after gateway verification of its device-signed consent.
    /// # Errors
    /// Rejects changed lease scope/deadline, expired leases and exhausted callee capacity.
    pub fn accept_verified(
        &mut self,
        owner: &str,
        consent: &VoiceLeaseConsent,
        endpoint: &str,
        now: u64,
    ) -> Result<VoiceAllocation, NodeCoreError> {
        self.expire(now);
        let key = (owner.to_owned(), consent.scope.call_id.clone());
        let lease = self.leases.get(&key).ok_or_else(|| refused("voice lease unavailable"))?;
        if lease.id != consent.lease_id
            || lease.scope != consent.scope
            || consent.expires_at != lease.hard_expires_at
            || now >= consent.expires_at
        {
            return Err(refused("voice consent binding changed"));
        }
        if let Some(old) = &lease.consent {
            if old != consent {
                return Err(refused("voice consent changed"));
            }
            return Ok(allocation(lease, endpoint, 1));
        }
        if self.account_usage(&lease.scope.callee) >= ACCOUNT_LIMIT {
            return Err(refused("voice callee capacity exhausted"));
        }
        let lease = self.leases.get_mut(&key).ok_or_else(|| refused("voice lease unavailable"))?;
        lease.consent = Some(consent.clone());
        self.usage.charge(&lease.scope.callee);
        self.tokens.insert(lease.sides[1].token.clone(), (key, 1));
        Ok(allocation(lease, endpoint, 1))
    }
    /// Renews only the exact consent previously verified and committed by the gateway.
    /// # Errors
    /// Rejects a different, absent or expired consent.
    pub fn renew_consented(
        &mut self,
        owner: &str,
        consent: &VoiceLeaseConsent,
        now: u64,
    ) -> Result<u64, NodeCoreError> {
        if self
            .leases
            .get(&(owner.to_owned(), consent.scope.call_id.clone()))
            .and_then(|l| l.consent.as_ref())
            != Some(consent)
        {
            return Err(refused("voice consent unavailable"));
        }
        self.renew(owner, &consent.scope, now)
    }
    /// Renews authorization only from the live caller's authenticated home node.
    /// # Errors
    /// Rejects absent, expired or changed scopes.
    pub fn renew(
        &mut self,
        owner: &str,
        scope: &VoiceAllocationRequest,
        now: u64,
    ) -> Result<u64, NodeCoreError> {
        self.expire(now);
        let lease = self
            .leases
            .get_mut(&(owner.into(), scope.call_id.clone()))
            .ok_or_else(|| refused("voice lease unavailable"))?;
        if &lease.scope != scope {
            return Err(refused("voice scope changed"));
        }
        if lease.consent.is_none() {
            return Err(refused("voice consent required"));
        }
        if now >= lease.hard_expires_at {
            return Err(refused("voice maximum lifetime reached"));
        }
        lease.expires_at = now.saturating_add(VOICE_LEASE_SECONDS).min(lease.hard_expires_at);
        Ok(lease.expires_at)
    }
    /// Releases a matching scope idempotently.
    /// # Errors
    /// Rejects an existing call id with different participants.
    pub fn release(
        &mut self,
        owner: &str,
        scope: &VoiceAllocationRequest,
    ) -> Result<(), NodeCoreError> {
        let key = (owner.into(), scope.call_id.clone());
        if let Some(lease) = self.leases.get(&key) {
            if &lease.scope != scope {
                return Err(refused("voice scope changed"));
            }
            for side in &lease.sides {
                self.tokens.remove(&side.token);
            }
        }
        if let Some(lease) = self.leases.remove(&key) {
            self.usage.release(&lease);
        }
        Ok(())
    }
    /// Authenticates a datagram and learns only its own source. Empty payloads maintain NAT.
    /// # Errors
    /// Rejects malformed/expired credentials, private targets, bandwidth excess.
    pub fn route<'a>(
        &mut self,
        packet: &'a [u8],
        source: SocketAddr,
        now: u64,
        allow_private: bool,
    ) -> Result<Option<(SocketAddr, &'a [u8])>, NodeCoreError> {
        match self.route_with_rebinding(packet, source, now, allow_private)? {
            VoiceRoute::Forward { target, packet } => Ok(Some((target, packet))),
            VoiceRoute::Drop | VoiceRoute::Challenge { .. } => Ok(None),
        }
    }
    /// Routes opaque media or a bounded return-routability challenge; see `route` for admission.
    /// # Errors
    /// Rejects malformed credentials, expired leases, private sources and exhausted budgets.
    pub fn route_with_rebinding<'a>(
        &mut self,
        packet: &'a [u8],
        source: SocketAddr,
        now: u64,
        allow_private: bool,
    ) -> Result<VoiceRoute<'a>, NodeCoreError> {
        let (token, payload) = decode_voice_datagram(packet)?;
        if !allow_private && !crate::relay_socket_target_allowed(source, &[]) {
            return Err(refused("voice source forbidden"));
        }
        let (key, i) =
            self.tokens.get(&token).ok_or_else(|| refused("voice credential unavailable"))?.clone();
        // Packet admission touches only its own lease. General expiry runs in the periodic sweep
        // and allocation path, so unauthenticated UDP traffic cannot scan all active calls.
        if self.leases.get(&key).is_some_and(|lease| now >= lease.expires_at) {
            if let Some(lease) = self.leases.remove(&key) {
                self.usage.release(&lease);
                for side in lease.sides {
                    self.tokens.remove(&side.token);
                }
            }
            return Err(refused("voice lease unavailable"));
        }
        let lease = self.leases.get(&key).ok_or_else(|| refused("voice lease unavailable"))?;
        if i == 1 && lease.consent.is_none() {
            return Err(refused("voice consent required"));
        }
        let lease = self.leases.get_mut(&key).ok_or_else(|| refused("voice lease unavailable"))?;
        let side = &mut lease.sides[i];
        let pinned = side.source == Some(source);
        if pinned {
            charge_window(
                &mut side.second,
                &mut side.bytes,
                now,
                packet.len(),
                BYTES_PER_SECOND,
                "voice bandwidth exhausted",
            )?;
        } else {
            charge_window(
                &mut side.unpinned_second,
                &mut side.unpinned_bytes,
                now,
                packet.len(),
                UNPINNED_BYTES_PER_SECOND,
                "voice unpinned bandwidth exhausted",
            )?;
        }
        if let Some(result) = rebinding::admit(
            side,
            rebinding::Admission {
                lease_id: &lease.id,
                index: u8::try_from(i).unwrap_or(0),
                source,
                payload,
                now,
                challenge_allowed: packet.len() >= MIN_REBIND_CHALLENGE_DATAGRAM_BYTES,
            },
        )? {
            return Ok(result);
        }
        if payload.is_empty() {
            return Ok(VoiceRoute::Drop);
        }
        let Some(target) = lease.sides[1 - i].source else {
            return Ok(VoiceRoute::Drop);
        };
        if !allow_private && !crate::relay_socket_target_allowed(target, &[]) {
            return Err(refused("voice target forbidden"));
        }
        Ok(VoiceRoute::Forward { target, packet: payload })
    }
    fn account_usage(&self, account: &CallEndpoint) -> usize {
        self.usage.count(account)
    }
    /// Expires credentials with their lease; live allocations are never evicted for admission.
    pub fn expire(&mut self, now: u64) {
        self.leases.retain(|_, lease| {
            let live = now < lease.expires_at;
            if !live {
                self.usage.release(lease);
                for s in &lease.sides {
                    self.tokens.remove(&s.token);
                }
            }
            live
        });
    }
}
fn new_side(now: u64) -> Result<Side, NodeCoreError> {
    Ok(Side {
        token: ramflux_protocol::encode_base64url(
            ramflux_crypto::random_32().map_err(|_| refused("voice entropy unavailable"))?,
        ),
        rebind_key: zeroize::Zeroizing::new(
            ramflux_crypto::random_32().map_err(|_| refused("voice entropy unavailable"))?,
        ),
        source: None,
        second: now,
        bytes: 0,
        unpinned_second: now,
        unpinned_bytes: 0,
        challenge: None,
    })
}
fn charge_window(
    second: &mut u64,
    bytes: &mut usize,
    now: u64,
    packet_bytes: usize,
    limit: usize,
    exhausted: &str,
) -> Result<(), NodeCoreError> {
    if now != *second {
        *second = now;
        *bytes = 0;
    }
    let next = bytes.saturating_add(packet_bytes);
    if next > limit {
        return Err(refused(exhausted));
    }
    *bytes = next;
    Ok(())
}
fn allocation(l: &Lease, endpoint: &str, side: usize) -> VoiceAllocation {
    VoiceAllocation {
        lease_id: l.id.clone(),
        endpoint: endpoint.into(),
        side: u8::try_from(side).unwrap_or(0),
        token: l.sides[side].token.clone(),
        rebind_key: ramflux_protocol::encode_base64url(l.sides[side].rebind_key.as_ref()),
        expires_at: l.expires_at,
        hard_expires_at: l.hard_expires_at,
    }
}
fn same_account(a: &CallEndpoint, b: &CallEndpoint) -> bool {
    a.principal_id == b.principal_id && a.root_public_key == b.root_public_key
}
/// Checks immutable scope shape independently of transport authentication.
/// # Errors
/// Rejects non-128-bit call ids, malformed roots, oversized labels and self-calls.
pub fn validate_voice_scope(s: &VoiceAllocationRequest) -> Result<(), NodeCoreError> {
    if !ramflux_protocol::decode_base64url(&s.call_id).is_ok_and(|id| id.len() == 16) {
        return Err(refused("voice call id must contain 128 random bits"));
    }
    for e in [&s.caller, &s.callee] {
        if e.principal_id.is_empty()
            || e.device_id.is_empty()
            || e.principal_id.len() > 512
            || e.device_id.len() > 512
            || !ramflux_protocol::decode_base64url(&e.root_public_key).is_ok_and(|k| k.len() == 32)
        {
            return Err(refused("voice endpoint invalid"));
        }
    }
    if same_account(&s.caller, &s.callee) {
        return Err(refused("voice self-call forbidden"));
    }
    Ok(())
}
/// Desktop framing: u32 token length, opaque token bytes, then unmodified RTP/SFrame bytes.
/// # Errors
/// Rejects malformed credentials and oversized payloads.
pub fn encode_voice_datagram(token: &str, payload: &[u8]) -> Result<Vec<u8>, NodeCoreError> {
    let token = ramflux_protocol::decode_base64url(token)
        .map_err(|_| refused("voice credential invalid"))?;
    if token.len() != 32 || payload.len() > VOICE_PACKET_MAX_BYTES {
        return Err(refused("voice datagram size rejected"));
    }
    let mut result = Vec::with_capacity(36 + payload.len());
    result.extend_from_slice(&32_u32.to_be_bytes());
    result.extend_from_slice(&token);
    result.extend_from_slice(payload);
    Ok(result)
}
fn decode_voice_datagram(p: &[u8]) -> Result<(String, &[u8]), NodeCoreError> {
    if p.len() < 36 || p.len() > 36 + VOICE_PACKET_MAX_BYTES || p[..4] != 32_u32.to_be_bytes() {
        return Err(refused("voice datagram framing rejected"));
    }
    Ok((ramflux_protocol::encode_base64url(&p[4..36]), &p[36..]))
}

#[cfg(test)]
#[path = "voice_tests.rs"]
mod tests;

/// A data-plane decision; challenges are never forwarded as media.
#[derive(Debug, PartialEq, Eq)]
pub enum VoiceRoute<'a> {
    Drop,
    Forward { target: SocketAddr, packet: &'a [u8] },
    Challenge { target: SocketAddr, packet: Vec<u8> },
}
#[path = "voice_rebinding.rs"]
mod rebinding;

#[path = "voice_quota.rs"]
mod quota;
