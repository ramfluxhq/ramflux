// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded production voice leases and opaque UDP forwarding; no media keys enter this module.
use crate::NodeCoreError;
use ramflux_protocol::{CallEndpoint, VoiceAllocation, VoiceAllocationRequest};
use std::{collections::BTreeMap, net::SocketAddr};
pub const VOICE_LEASE_SECONDS: u64 = 60;
pub const VOICE_PACKET_MAX_BYTES: usize = 1400;
const MAX_ALLOCATIONS: usize = 4096;
const ACCOUNT_LIMIT: usize = 2;
const BYTES_PER_SECOND: usize = 128 * 1024;
fn refused(message: &str) -> NodeCoreError {
    NodeCoreError::Unauthorized(message.into())
}
struct Side {
    token: String,
    source: Option<SocketAddr>,
    second: u64,
    bytes: usize,
}
struct Lease {
    scope: VoiceAllocationRequest,
    expires_at: u64,
    sides: [Side; 2],
}
/// Credentials and source bindings are RAM-only. Restart drops all leases and fails closed.
#[derive(Default)]
pub struct VoiceRelayState {
    leases: BTreeMap<(String, String), Lease>,
    tokens: BTreeMap<String, ((String, String), usize)>,
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
            return Ok(allocation(lease, endpoint));
        }
        if self.leases.len() >= MAX_ALLOCATIONS
            || [&scope.caller, &scope.callee].into_iter().any(|a| {
                self.leases
                    .values()
                    .filter(|l| {
                        same_account(a, &l.scope.caller) || same_account(a, &l.scope.callee)
                    })
                    .count()
                    >= ACCOUNT_LIMIT
            })
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
            expires_at: now.saturating_add(VOICE_LEASE_SECONDS),
            sides,
        };
        let response = allocation(&lease, endpoint);
        for (i, s) in lease.sides.iter().enumerate() {
            self.tokens.insert(s.token.clone(), (key.clone(), i));
        }
        self.leases.insert(key, lease);
        Ok(response)
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
        lease.expires_at = now.saturating_add(VOICE_LEASE_SECONDS);
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
        self.leases.remove(&key);
        Ok(())
    }
    /// Authenticates a datagram and learns only its own source. Empty payloads maintain NAT.
    /// # Errors
    /// Rejects malformed/expired credentials, private targets, clock rollback and bandwidth excess.
    pub fn route<'a>(
        &mut self,
        packet: &'a [u8],
        source: SocketAddr,
        now: u64,
        allow_private: bool,
    ) -> Result<Option<(SocketAddr, &'a [u8])>, NodeCoreError> {
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
                for side in lease.sides {
                    self.tokens.remove(&side.token);
                }
            }
            return Err(refused("voice lease unavailable"));
        }
        let lease = self.leases.get_mut(&key).ok_or_else(|| refused("voice lease unavailable"))?;
        let side = &mut lease.sides[i];
        if now < side.second {
            return Err(refused("voice clock rollback"));
        }
        if now != side.second {
            side.second = now;
            side.bytes = 0;
        }
        let bytes = side.bytes.saturating_add(packet.len());
        if bytes > BYTES_PER_SECOND {
            return Err(refused("voice bandwidth exhausted"));
        }
        side.bytes = bytes;
        side.source = Some(source);
        if payload.is_empty() {
            return Ok(None);
        }
        let Some(target) = lease.sides[1 - i].source else {
            return Ok(None);
        };
        if !allow_private && !crate::relay_socket_target_allowed(target, &[]) {
            return Err(refused("voice target forbidden"));
        }
        Ok(Some((target, payload)))
    }
    /// Expires credentials with their lease; live allocations are never evicted for admission.
    pub fn expire(&mut self, now: u64) {
        self.leases.retain(|_, lease| {
            let live = now < lease.expires_at;
            if !live {
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
        source: None,
        second: now,
        bytes: 0,
    })
}
fn allocation(l: &Lease, endpoint: &str) -> VoiceAllocation {
    VoiceAllocation {
        endpoint: endpoint.into(),
        caller_token: l.sides[0].token.clone(),
        callee_token: l.sides[1].token.clone(),
        expires_at: l.expires_at,
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
