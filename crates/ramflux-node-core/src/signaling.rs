// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    NodeCoreError, SIGNALING_STATE_KEY, SIGNALING_STATE_TABLE, load_snapshot, open_redb_with_table,
    save_snapshot,
};
use hmac::{Hmac, Mac};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<sha2::Sha256>;

pub const DEFAULT_TURN_CREDENTIAL_TTL_SECS: u64 = 600;
pub const MAX_TURN_ALLOCATIONS_PER_USERNAME: usize = 2;
pub const MAX_TURN_ALLOCATIONS_PER_CALL_SESSION: usize = 8;
pub const MAX_SRTP_FLOWS_PER_CALL_SESSION: usize = 4;
pub const MAX_TURN_ALLOCATE_PER_IDENTITY_PER_MINUTE: u32 = 30;
pub const MAX_TURN_ALLOCATE_PER_SOURCE_IP_PER_MINUTE: u32 = 60;
pub const DEFAULT_TURN_ALLOCATION_BANDWIDTH_BPS: u64 = 2_000_000;
pub const DEFAULT_TURN_ALLOCATION_BURST_BPS: u64 = 4_000_000;
pub const DEFAULT_TURN_CALL_SESSION_BANDWIDTH_BPS: u64 = 6_000_000;
pub const DEFAULT_TURN_NODE_WIDE_BANDWIDTH_BPS: u64 = 100_000_000;
pub const DEFAULT_TURN_NODE_WIDE_MAX_ALLOCATIONS: usize = 500;
pub const TURN_MEDIA_RELAY_PACKET_MAX_BYTES: usize = 65_507;
pub const TURN_MEDIA_RELAY_HEADER_MAX_BYTES: usize = 16 * 1024;
const TURN_USERNAME_PARTS: usize = 4;
const TURN_MEDIA_RELAY_PACKET_HEADER_LEN_BYTES: usize = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CallSessionLifecycle {
    Pending,
    Active,
    Draining,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpaqueCallSession {
    pub call_id: String,
    pub caller_device_hash: String,
    pub callee_device_hash: String,
    pub allowed_peer_hashes: BTreeSet<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub lifecycle: CallSessionLifecycle,
    pub opaque_envelope_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnAllocation {
    pub allocation_id: String,
    pub call_id: String,
    pub username_hash: String,
    pub identity_hash: String,
    pub peer_hash: String,
    pub source_ip_hash: String,
    pub relay_address: String,
    pub bandwidth_limit_bps: u64,
    pub burst_limit_bps: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub bytes_relayed: u64,
    pub packets_relayed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SrtpRelayFlowState {
    Active,
    Draining,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SrtpRelayFlow {
    pub flow_id: String,
    pub call_session_id: String,
    pub allocation_id_a: String,
    pub allocation_id_b: String,
    pub peer_hash_a: String,
    pub peer_hash_b: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub last_activity_at: u64,
    pub state: SrtpRelayFlowState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnMediaRelayToken {
    pub call_id: String,
    pub allocation_id: String,
    pub target_allocation_id: String,
    pub flow_id: String,
    pub identity_hash: String,
    pub peer_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub mac: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnMediaRelayPacketHeader {
    pub token: TurnMediaRelayToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnMediaRelayPacket {
    pub header: TurnMediaRelayPacketHeader,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct TurnMediaRelayEnsureContext<'a> {
    pub service_key: &'a [u8],
    pub source_ip_hash: &'a str,
    pub relay_address: &'a str,
    pub now: u64,
    pub policy: &'a TurnQuotaPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnCredentialParts {
    pub call_session_id_hash: String,
    pub device_id_hash: String,
    pub issued_at: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnCredentialReplayCache {
    seen_nonce_expires_at: BTreeMap<String, u64>,
    max_entries: usize,
}

impl Default for TurnCredentialReplayCache {
    fn default() -> Self {
        Self { seen_nonce_expires_at: BTreeMap::new(), max_entries: 4096 }
    }
}

impl TurnCredentialReplayCache {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self { seen_nonce_expires_at: BTreeMap::new(), max_entries }
    }

    /// # Errors
    /// Returns an error when the nonce has already been accepted in the active TTL window.
    pub fn accept_once(
        &mut self,
        nonce_key: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.evict_expired(now);
        if self.seen_nonce_expires_at.contains_key(nonce_key) {
            return Err(NodeCoreError::ReplayGuard("turn credential nonce replay".to_owned()));
        }
        if self.seen_nonce_expires_at.len() >= self.max_entries
            && let Some(oldest_key) = self
                .seen_nonce_expires_at
                .iter()
                .min_by_key(|(_nonce, expires_at)| *expires_at)
                .map(|(nonce, _expires_at)| nonce.clone())
        {
            self.seen_nonce_expires_at.remove(&oldest_key);
        }
        self.seen_nonce_expires_at.insert(nonce_key.to_owned(), expires_at);
        Ok(())
    }

    pub fn evict_expired(&mut self, now: u64) {
        self.seen_nonce_expires_at.retain(|_nonce, expires_at| *expires_at > now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen_nonce_expires_at.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen_nonce_expires_at.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnQuotaPolicy {
    pub max_allocations_per_username: usize,
    pub max_allocations_per_call_session: usize,
    pub max_flows_per_call_session: usize,
    pub max_allocate_per_identity_per_minute: u32,
    pub max_allocate_per_source_ip_per_minute: u32,
    pub allocation_bandwidth_bps: u64,
    pub allocation_burst_bps: u64,
    pub call_session_bandwidth_bps: u64,
    pub node_wide_bandwidth_bps: u64,
    pub node_wide_max_allocations: usize,
}

impl Default for TurnQuotaPolicy {
    fn default() -> Self {
        Self {
            max_allocations_per_username: MAX_TURN_ALLOCATIONS_PER_USERNAME,
            max_allocations_per_call_session: MAX_TURN_ALLOCATIONS_PER_CALL_SESSION,
            max_flows_per_call_session: MAX_SRTP_FLOWS_PER_CALL_SESSION,
            max_allocate_per_identity_per_minute: MAX_TURN_ALLOCATE_PER_IDENTITY_PER_MINUTE,
            max_allocate_per_source_ip_per_minute: MAX_TURN_ALLOCATE_PER_SOURCE_IP_PER_MINUTE,
            allocation_bandwidth_bps: DEFAULT_TURN_ALLOCATION_BANDWIDTH_BPS,
            allocation_burst_bps: DEFAULT_TURN_ALLOCATION_BURST_BPS,
            call_session_bandwidth_bps: DEFAULT_TURN_CALL_SESSION_BANDWIDTH_BPS,
            node_wide_bandwidth_bps: DEFAULT_TURN_NODE_WIDE_BANDWIDTH_BPS,
            node_wide_max_allocations: DEFAULT_TURN_NODE_WIDE_MAX_ALLOCATIONS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignalingState {
    calls_by_id: BTreeMap<String, OpaqueCallSession>,
    allocations_by_id: BTreeMap<String, TurnAllocation>,
    srtp_flows_by_id: BTreeMap<String, SrtpRelayFlow>,
    #[serde(default)]
    turn_allocation_sources: BTreeMap<String, String>,
    turn_replay_cache: TurnCredentialReplayCache,
    identity_allocate_window: BTreeMap<String, RateWindow>,
    source_ip_allocate_window: BTreeMap<String, RateWindow>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct RateWindow {
    window_start: u64,
    count: u32,
}

impl SignalingState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit_opaque_call_envelope(&mut self, session: OpaqueCallSession) {
        self.calls_by_id.insert(session.call_id.clone(), session);
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn activate_call(&mut self, call_id: &str) -> Result<(), NodeCoreError> {
        let call = self
            .calls_by_id
            .get_mut(call_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(call_id.to_owned()))?;
        call.lifecycle = CallSessionLifecycle::Active;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn allocate_turn(&mut self, allocation: TurnAllocation) -> Result<(), NodeCoreError> {
        self.allocate_turn_with_policy(allocation, &TurnQuotaPolicy::default())
    }

    /// # Errors
    /// Returns an error when the call session is missing/inactive, the peer is not allowed, the
    /// allocation exceeds the call TTL, or a TURN quota would be exceeded.
    pub fn allocate_turn_with_policy(
        &mut self,
        allocation: TurnAllocation,
        policy: &TurnQuotaPolicy,
    ) -> Result<(), NodeCoreError> {
        let call = self
            .calls_by_id
            .get(&allocation.call_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(allocation.call_id.clone()))?;
        if call.lifecycle != CallSessionLifecycle::Active {
            return Err(NodeCoreError::SessionNotFound(allocation.call_id.clone()));
        }
        if allocation.expires_at > call.expires_at {
            return Err(NodeCoreError::TtlExpired { envelope_id: allocation.allocation_id });
        }
        if !call.allowed_peer_hashes.contains(&allocation.peer_hash) {
            return Err(NodeCoreError::SessionNotFound(allocation.peer_hash));
        }
        self.enforce_allocation_quota(&allocation, policy)?;
        self.allocations_by_id.insert(allocation.allocation_id.clone(), allocation);
        Ok(())
    }

    /// # Errors
    /// Returns an error when the username is malformed, the call is not active, the credential is
    /// expired, the MAC is invalid, or the nonce was already used.
    pub fn validate_turn_credential(
        &mut self,
        username: &str,
        password: &str,
        service_key: &[u8],
        now: u64,
    ) -> Result<TurnCredentialParts, NodeCoreError> {
        let parts = parse_turn_username(username)?;
        let call = self
            .calls_by_id
            .get(&parts.call_session_id_hash)
            .ok_or_else(|| NodeCoreError::SessionNotFound(parts.call_session_id_hash.clone()))?;
        if call.lifecycle != CallSessionLifecycle::Active || now >= call.expires_at {
            return Err(NodeCoreError::TtlExpired {
                envelope_id: parts.call_session_id_hash.clone(),
            });
        }
        let max_expires_at =
            parts.issued_at.saturating_add(DEFAULT_TURN_CREDENTIAL_TTL_SECS).min(call.expires_at);
        if parts.issued_at > now || now > max_expires_at {
            return Err(NodeCoreError::TtlExpired {
                envelope_id: parts.call_session_id_hash.clone(),
            });
        }
        let expected = turn_credential_password(service_key, username)?;
        if !constant_time_eq(expected.as_bytes(), password.as_bytes()) {
            return Err(NodeCoreError::ItestHttp("turn credential mac rejected".to_owned()));
        }
        let nonce_key =
            format!("{}:{}:{}", parts.call_session_id_hash, parts.device_id_hash, parts.nonce);
        self.turn_replay_cache.accept_once(&nonce_key, max_expires_at, now)?;
        Ok(parts)
    }

    /// # Errors
    /// Returns an error when the identity or source-IP allocation rate limit is exceeded.
    pub fn record_allocate_attempt(
        &mut self,
        identity_hash: &str,
        source_ip_hash: &str,
        now: u64,
        policy: &TurnQuotaPolicy,
    ) -> Result<(), NodeCoreError> {
        increment_rate_window(
            self.identity_allocate_window.entry(identity_hash.to_owned()).or_default(),
            now,
            policy.max_allocate_per_identity_per_minute,
        )?;
        increment_rate_window(
            self.source_ip_allocate_window.entry(source_ip_hash.to_owned()).or_default(),
            now,
            policy.max_allocate_per_source_ip_per_minute,
        )
    }

    /// # Errors
    /// Returns an error when either allocation is missing, allocations belong to different calls,
    /// the call is inactive, or the call-session SRTP flow quota is exceeded.
    pub fn bind_srtp_relay_flow(
        &mut self,
        flow_id: impl Into<String>,
        allocation_id_a: &str,
        allocation_id_b: &str,
        now: u64,
        policy: &TurnQuotaPolicy,
    ) -> Result<SrtpRelayFlow, NodeCoreError> {
        let allocation_a = self
            .allocations_by_id
            .get(allocation_id_a)
            .ok_or_else(|| NodeCoreError::SessionNotFound(allocation_id_a.to_owned()))?;
        let allocation_b = self
            .allocations_by_id
            .get(allocation_id_b)
            .ok_or_else(|| NodeCoreError::SessionNotFound(allocation_id_b.to_owned()))?;
        if allocation_a.call_id != allocation_b.call_id {
            return Err(NodeCoreError::SessionNotFound(allocation_b.call_id.clone()));
        }
        let call = self
            .calls_by_id
            .get(&allocation_a.call_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(allocation_a.call_id.clone()))?;
        if call.lifecycle != CallSessionLifecycle::Active {
            return Err(NodeCoreError::SessionNotFound(call.call_id.clone()));
        }
        let active_flows = self
            .srtp_flows_by_id
            .values()
            .filter(|flow| {
                flow.call_session_id == call.call_id && flow.state == SrtpRelayFlowState::Active
            })
            .count();
        if active_flows >= policy.max_flows_per_call_session {
            return Err(NodeCoreError::ItestHttp(
                "turn call session flow quota reached".to_owned(),
            ));
        }
        let expires_at = allocation_a.expires_at.min(allocation_b.expires_at).min(call.expires_at);
        let flow = SrtpRelayFlow {
            flow_id: flow_id.into(),
            call_session_id: call.call_id.clone(),
            allocation_id_a: allocation_id_a.to_owned(),
            allocation_id_b: allocation_id_b.to_owned(),
            peer_hash_a: allocation_a.peer_hash.clone(),
            peer_hash_b: allocation_b.peer_hash.clone(),
            created_at: now,
            expires_at,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            last_activity_at: now,
            state: SrtpRelayFlowState::Active,
        };
        self.srtp_flows_by_id.insert(flow.flow_id.clone(), flow.clone());
        Ok(flow)
    }

    /// # Errors
    /// Returns an error when the flow is missing/expired/inactive or the source allocation is not
    /// one of the two allocations bound to the flow.
    pub fn relay_srtp_packet(
        &mut self,
        flow_id: &str,
        from_allocation_id: &str,
        payload_len: usize,
        now: u64,
    ) -> Result<String, NodeCoreError> {
        let flow = self
            .srtp_flows_by_id
            .get_mut(flow_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(flow_id.to_owned()))?;
        if flow.state != SrtpRelayFlowState::Active || now >= flow.expires_at {
            return Err(NodeCoreError::TtlExpired { envelope_id: flow_id.to_owned() });
        }
        let bytes = u64::try_from(payload_len)
            .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
        let target = if from_allocation_id == flow.allocation_id_a {
            flow.bytes_a_to_b = flow.bytes_a_to_b.saturating_add(bytes);
            flow.packets_a_to_b = flow.packets_a_to_b.saturating_add(1);
            flow.allocation_id_b.clone()
        } else if from_allocation_id == flow.allocation_id_b {
            flow.bytes_b_to_a = flow.bytes_b_to_a.saturating_add(bytes);
            flow.packets_b_to_a = flow.packets_b_to_a.saturating_add(1);
            flow.allocation_id_a.clone()
        } else {
            return Err(NodeCoreError::SessionNotFound(from_allocation_id.to_owned()));
        };
        flow.last_activity_at = now;
        if let Some(allocation) = self.allocations_by_id.get_mut(from_allocation_id) {
            allocation.bytes_relayed = allocation.bytes_relayed.saturating_add(bytes);
            allocation.packets_relayed = allocation.packets_relayed.saturating_add(1);
        }
        Ok(target)
    }

    /// # Errors
    /// Returns an error when the token MAC, TTL, allocation binding, or flow binding is invalid.
    pub fn validate_turn_media_relay_token(
        &self,
        token: &TurnMediaRelayToken,
        service_key: &[u8],
        now: u64,
    ) -> Result<(), NodeCoreError> {
        if token.issued_at > now || now >= token.expires_at {
            return Err(NodeCoreError::TtlExpired { envelope_id: token.allocation_id.clone() });
        }
        let expected = turn_media_relay_token_mac(service_key, token)?;
        if !constant_time_eq(expected.as_bytes(), token.mac.as_bytes()) {
            return Err(NodeCoreError::ItestHttp("turn media relay token mac rejected".to_owned()));
        }
        let allocation = self
            .allocations_by_id
            .get(&token.allocation_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(token.allocation_id.clone()))?;
        if token.expires_at > allocation.expires_at || now >= allocation.expires_at {
            return Err(NodeCoreError::TtlExpired { envelope_id: token.allocation_id.clone() });
        }
        if allocation.identity_hash != token.identity_hash
            || allocation.peer_hash != token.peer_hash
        {
            return Err(NodeCoreError::SessionNotFound(token.allocation_id.clone()));
        }
        let flow = self
            .srtp_flows_by_id
            .get(&token.flow_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(token.flow_id.clone()))?;
        if flow.state != SrtpRelayFlowState::Active || now >= flow.expires_at {
            return Err(NodeCoreError::TtlExpired { envelope_id: token.flow_id.clone() });
        }
        if flow.call_session_id != allocation.call_id
            || (flow.allocation_id_a != token.allocation_id
                && flow.allocation_id_b != token.allocation_id)
        {
            return Err(NodeCoreError::SessionNotFound(token.flow_id.clone()));
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when the token is invalid, the source address attempts to hijack a bound
    /// allocation, or the flow cannot relay from this allocation.
    pub fn validate_turn_media_packet(
        &mut self,
        token: &TurnMediaRelayToken,
        source_addr: SocketAddr,
        payload_len: usize,
        service_key: &[u8],
        now: u64,
    ) -> Result<String, NodeCoreError> {
        self.validate_turn_media_relay_token(token, service_key, now)?;
        self.validate_or_bind_turn_allocation_source(&token.allocation_id, source_addr)?;
        self.relay_srtp_packet(&token.flow_id, &token.allocation_id, payload_len, now)
    }

    /// # Errors
    /// Returns an error when the token is invalid or the implied call/allocation/flow violates
    /// TURN quota or permission constraints.
    pub fn ensure_turn_media_relay_state(
        &mut self,
        token: &TurnMediaRelayToken,
        context: TurnMediaRelayEnsureContext<'_>,
    ) -> Result<(), NodeCoreError> {
        validate_turn_media_relay_token_signature(token, context.service_key, context.now)?;
        if !self.calls_by_id.contains_key(&token.call_id) {
            let allowed_peer_hashes =
                BTreeSet::from([token.peer_hash.clone(), token.identity_hash.clone()]);
            self.submit_opaque_call_envelope(OpaqueCallSession {
                call_id: token.call_id.clone(),
                caller_device_hash: token.identity_hash.clone(),
                callee_device_hash: token.peer_hash.clone(),
                allowed_peer_hashes,
                created_at: token.issued_at,
                expires_at: token.expires_at,
                lifecycle: CallSessionLifecycle::Active,
                opaque_envelope_hash: "media_relay_opaque_call".to_owned(),
            });
        }
        if !self.allocations_by_id.contains_key(&token.allocation_id) {
            self.allocate_turn_with_policy(
                TurnAllocation {
                    allocation_id: token.allocation_id.clone(),
                    call_id: token.call_id.clone(),
                    username_hash: format!("media:{}", token.allocation_id),
                    identity_hash: token.identity_hash.clone(),
                    peer_hash: token.peer_hash.clone(),
                    source_ip_hash: context.source_ip_hash.to_owned(),
                    relay_address: context.relay_address.to_owned(),
                    bandwidth_limit_bps: context.policy.allocation_bandwidth_bps,
                    burst_limit_bps: context.policy.allocation_burst_bps,
                    created_at: token.issued_at,
                    expires_at: token.expires_at,
                    bytes_relayed: 0,
                    packets_relayed: 0,
                },
                context.policy,
            )?;
        }
        if !self.allocations_by_id.contains_key(&token.target_allocation_id) {
            self.allocate_turn_with_policy(
                TurnAllocation {
                    allocation_id: token.target_allocation_id.clone(),
                    call_id: token.call_id.clone(),
                    username_hash: format!("media:{}", token.target_allocation_id),
                    identity_hash: token.peer_hash.clone(),
                    peer_hash: token.identity_hash.clone(),
                    source_ip_hash: "media-relay-target-pending".to_owned(),
                    relay_address: context.relay_address.to_owned(),
                    bandwidth_limit_bps: context.policy.allocation_bandwidth_bps,
                    burst_limit_bps: context.policy.allocation_burst_bps,
                    created_at: token.issued_at,
                    expires_at: token.expires_at,
                    bytes_relayed: 0,
                    packets_relayed: 0,
                },
                context.policy,
            )?;
        }
        if !self.srtp_flows_by_id.contains_key(&token.flow_id) {
            self.bind_srtp_relay_flow(
                token.flow_id.clone(),
                &token.allocation_id,
                &token.target_allocation_id,
                context.now,
                context.policy,
            )?;
        }
        Ok(())
    }

    #[must_use]
    pub fn turn_allocation_source(&self, allocation_id: &str) -> Option<&str> {
        self.turn_allocation_sources.get(allocation_id).map(String::as_str)
    }

    #[must_use]
    pub fn expire_turn_media_state(&mut self, now: u64) -> Vec<String> {
        let expired_allocations = self
            .allocations_by_id
            .iter()
            .filter(|(_allocation_id, allocation)| allocation.expires_at <= now)
            .map(|(allocation_id, _allocation)| allocation_id.clone())
            .collect::<Vec<_>>();
        for allocation_id in &expired_allocations {
            self.allocations_by_id.remove(allocation_id);
            self.turn_allocation_sources.remove(allocation_id);
        }
        self.srtp_flows_by_id.retain(|_flow_id, flow| {
            flow.expires_at > now
                && self.allocations_by_id.contains_key(&flow.allocation_id_a)
                && self.allocations_by_id.contains_key(&flow.allocation_id_b)
        });
        expired_allocations
    }

    #[must_use]
    pub fn call(&self, call_id: &str) -> Option<&OpaqueCallSession> {
        self.calls_by_id.get(call_id)
    }

    #[must_use]
    pub fn allocation(&self, allocation_id: &str) -> Option<&TurnAllocation> {
        self.allocations_by_id.get(allocation_id)
    }

    #[must_use]
    pub fn srtp_flow(&self, flow_id: &str) -> Option<&SrtpRelayFlow> {
        self.srtp_flows_by_id.get(flow_id)
    }

    #[must_use]
    pub fn active_call_count(&self) -> usize {
        self.calls_by_id
            .values()
            .filter(|call| call.lifecycle == CallSessionLifecycle::Active)
            .count()
    }

    #[must_use]
    pub fn srtp_media_key_visible(&self, call_id: &str) -> bool {
        let _call_exists = self.calls_by_id.contains_key(call_id);
        false
    }

    fn enforce_allocation_quota(
        &self,
        allocation: &TurnAllocation,
        policy: &TurnQuotaPolicy,
    ) -> Result<(), NodeCoreError> {
        if self.allocations_by_id.len() >= policy.node_wide_max_allocations {
            return Err(NodeCoreError::ItestHttp(
                "turn node allocation circuit breaker open".to_owned(),
            ));
        }
        let node_bandwidth: u64 =
            self.allocations_by_id.values().map(|allocation| allocation.bandwidth_limit_bps).sum();
        if node_bandwidth.saturating_add(allocation.bandwidth_limit_bps)
            > policy.node_wide_bandwidth_bps
        {
            return Err(NodeCoreError::ItestHttp(
                "turn node bandwidth circuit breaker open".to_owned(),
            ));
        }
        let per_username = self
            .allocations_by_id
            .values()
            .filter(|existing| existing.username_hash == allocation.username_hash)
            .count();
        if per_username >= policy.max_allocations_per_username {
            return Err(NodeCoreError::ItestHttp(
                "turn username allocation quota reached".to_owned(),
            ));
        }
        let per_call = self
            .allocations_by_id
            .values()
            .filter(|existing| existing.call_id == allocation.call_id)
            .count();
        if per_call >= policy.max_allocations_per_call_session {
            return Err(NodeCoreError::ItestHttp(
                "turn call session allocation quota reached".to_owned(),
            ));
        }
        let call_bandwidth: u64 = self
            .allocations_by_id
            .values()
            .filter(|existing| existing.call_id == allocation.call_id)
            .map(|allocation| allocation.bandwidth_limit_bps)
            .sum();
        if call_bandwidth.saturating_add(allocation.bandwidth_limit_bps)
            > policy.call_session_bandwidth_bps
        {
            return Err(NodeCoreError::ItestHttp(
                "turn call session bandwidth quota reached".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_or_bind_turn_allocation_source(
        &mut self,
        allocation_id: &str,
        source_addr: SocketAddr,
    ) -> Result<(), NodeCoreError> {
        let source = source_addr.to_string();
        if let Some(bound_source) = self.turn_allocation_sources.get(allocation_id) {
            if bound_source != &source {
                return Err(NodeCoreError::ItestHttp(
                    "turn allocation source address mismatch".to_owned(),
                ));
            }
            return Ok(());
        }
        self.turn_allocation_sources.insert(allocation_id.to_owned(), source);
        Ok(())
    }
}

#[must_use]
pub fn turn_username(parts: &TurnCredentialParts) -> String {
    format!(
        "{}:{}:{}:{}",
        parts.call_session_id_hash, parts.device_id_hash, parts.issued_at, parts.nonce
    )
}

/// # Errors
/// Returns an error when the username does not follow
/// `call_session_id_hash:device_id_hash:issued_at:nonce`.
pub fn parse_turn_username(username: &str) -> Result<TurnCredentialParts, NodeCoreError> {
    let parts = username.split(':').collect::<Vec<_>>();
    if parts.len() != TURN_USERNAME_PARTS || parts.iter().any(|part| part.is_empty()) {
        return Err(NodeCoreError::ItestHttp("invalid turn username format".to_owned()));
    }
    let issued_at =
        parts[2].parse::<u64>().map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(TurnCredentialParts {
        call_session_id_hash: parts[0].to_owned(),
        device_id_hash: parts[1].to_owned(),
        issued_at,
        nonce: parts[3].to_owned(),
    })
}

/// # Errors
/// Returns an error when the HMAC key cannot be initialized.
pub fn turn_credential_password(
    service_key: &[u8],
    username: &str,
) -> Result<String, NodeCoreError> {
    let mut mac = HmacSha256::new_from_slice(service_key)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    mac.update(username.as_bytes());
    Ok(ramflux_protocol::encode_base64url(mac.finalize().into_bytes()))
}

/// # Errors
/// Returns an error when canonical serialization fails.
pub fn turn_media_relay_token_canonical_bytes(
    token: &TurnMediaRelayToken,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = token.clone();
    canonical.mac.clear();
    serde_json::to_vec(&canonical).map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the token MAC, TTL, or validity window is invalid.
pub fn validate_turn_media_relay_token_signature(
    token: &TurnMediaRelayToken,
    service_key: &[u8],
    now: u64,
) -> Result<(), NodeCoreError> {
    if token.issued_at > now || now >= token.expires_at {
        return Err(NodeCoreError::TtlExpired { envelope_id: token.allocation_id.clone() });
    }
    if token.allocation_id == token.target_allocation_id {
        return Err(NodeCoreError::ItestHttp(
            "turn media relay target allocation must differ from source".to_owned(),
        ));
    }
    let expected = turn_media_relay_token_mac(service_key, token)?;
    if !constant_time_eq(expected.as_bytes(), token.mac.as_bytes()) {
        return Err(NodeCoreError::ItestHttp("turn media relay token mac rejected".to_owned()));
    }
    Ok(())
}

/// # Errors
/// Returns an error when the HMAC key cannot be initialized or canonical serialization fails.
pub fn turn_media_relay_token_mac(
    service_key: &[u8],
    token: &TurnMediaRelayToken,
) -> Result<String, NodeCoreError> {
    let mut mac = HmacSha256::new_from_slice(service_key)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    mac.update(&turn_media_relay_token_canonical_bytes(token)?);
    Ok(ramflux_protocol::encode_base64url(mac.finalize().into_bytes()))
}

/// # Errors
/// Returns an error when the token MAC cannot be computed.
pub fn sign_turn_media_relay_token(
    service_key: &[u8],
    mut token: TurnMediaRelayToken,
) -> Result<TurnMediaRelayToken, NodeCoreError> {
    token.mac.clear();
    token.mac = turn_media_relay_token_mac(service_key, &token)?;
    Ok(token)
}

/// # Errors
/// Returns an error when the header cannot be serialized or the packet exceeds the UDP limit.
pub fn encode_turn_media_relay_packet(
    header: &TurnMediaRelayPacketHeader,
    payload: &[u8],
) -> Result<Vec<u8>, NodeCoreError> {
    let header_bytes = serde_json::to_vec(header)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    if header_bytes.len() > TURN_MEDIA_RELAY_HEADER_MAX_BYTES {
        return Err(NodeCoreError::ItestHttp("turn media relay header too large".to_owned()));
    }
    let total_len = TURN_MEDIA_RELAY_PACKET_HEADER_LEN_BYTES
        .saturating_add(header_bytes.len())
        .saturating_add(payload.len());
    if total_len > TURN_MEDIA_RELAY_PACKET_MAX_BYTES {
        return Err(NodeCoreError::ItestHttp("turn media relay packet too large".to_owned()));
    }
    let header_len = u32::try_from(header_bytes.len())
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&header_len.to_be_bytes());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// # Errors
/// Returns an error when the packet is malformed or exceeds the bounded media relay frame sizes.
pub fn decode_turn_media_relay_packet(
    packet: &[u8],
) -> Result<TurnMediaRelayPacket, NodeCoreError> {
    if packet.len() > TURN_MEDIA_RELAY_PACKET_MAX_BYTES {
        return Err(NodeCoreError::ItestHttp("turn media relay packet too large".to_owned()));
    }
    if packet.len() < TURN_MEDIA_RELAY_PACKET_HEADER_LEN_BYTES {
        return Err(NodeCoreError::ItestHttp("turn media relay packet missing header".to_owned()));
    }
    let header_len =
        u32::from_be_bytes(packet[..TURN_MEDIA_RELAY_PACKET_HEADER_LEN_BYTES].try_into().map_err(
            |source: std::array::TryFromSliceError| NodeCoreError::ItestHttp(source.to_string()),
        )?) as usize;
    if header_len == 0 || header_len > TURN_MEDIA_RELAY_HEADER_MAX_BYTES {
        return Err(NodeCoreError::ItestHttp("turn media relay header length rejected".to_owned()));
    }
    let header_end = TURN_MEDIA_RELAY_PACKET_HEADER_LEN_BYTES.saturating_add(header_len);
    if header_end > packet.len() {
        return Err(NodeCoreError::ItestHttp("turn media relay packet truncated".to_owned()));
    }
    let header =
        serde_json::from_slice(&packet[TURN_MEDIA_RELAY_PACKET_HEADER_LEN_BYTES..header_end])
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(TurnMediaRelayPacket { header, payload: packet[header_end..].to_vec() })
}

#[must_use]
pub fn relay_target_allowed(addr: IpAddr, internal_mesh_addrs: &[IpAddr]) -> bool {
    let normalized = normalize_ipv4_mapped(addr);
    if internal_mesh_addrs.iter().copied().map(normalize_ipv4_mapped).any(|ip| ip == normalized) {
        return false;
    }
    match normalized {
        IpAddr::V4(ip) => relay_target_v4_allowed(ip),
        IpAddr::V6(ip) => relay_target_v6_allowed(ip),
    }
}

#[must_use]
pub fn relay_socket_target_allowed(addr: SocketAddr, internal_mesh_addrs: &[IpAddr]) -> bool {
    relay_target_allowed(addr.ip(), internal_mesh_addrs)
}

fn relay_target_v4_allowed(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || octets == [169, 254, 169, 254]
    {
        return false;
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return false;
    }
    true
}

fn relay_target_v6_allowed(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
    {
        return false;
    }
    true
}

fn normalize_ipv4_mapped(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

fn increment_rate_window(
    window: &mut RateWindow,
    now: u64,
    limit: u32,
) -> Result<(), NodeCoreError> {
    let minute = now / 60;
    if window.window_start != minute {
        window.window_start = minute;
        window.count = 0;
    }
    if window.count >= limit {
        return Err(NodeCoreError::ItestHttp("turn allocate rate limited".to_owned()));
    }
    window.count = window.count.saturating_add(1);
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right.iter()).fold(0_u8, |acc, (left, right)| acc | (left ^ right)) == 0
}

pub struct SignalingRedbStore {
    db: redb::Database,
}

impl SignalingRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let db = open_redb_with_table(path, SIGNALING_STATE_TABLE)?;
        Ok(Self { db })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_state(&self, state: &SignalingState) -> Result<(), NodeCoreError> {
        save_snapshot(&self.db, SIGNALING_STATE_TABLE, SIGNALING_STATE_KEY, state)
    }

    /// # Errors
    /// Returns an error when the persisted signaling state cannot be read.
    pub fn load_state(&self) -> Result<Option<SignalingState>, NodeCoreError> {
        load_snapshot(&self.db, SIGNALING_STATE_TABLE, SIGNALING_STATE_KEY)
    }
}
