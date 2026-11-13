// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

#[path = "gateway_replay_policy.rs"]
mod replay_policy;
pub use replay_policy::{
    GATEWAY_REPLAY_MEMORY_LIMIT_BYTES, GATEWAY_REPLAY_PAGE_CACHE_BYTES, GatewayReplayConfig,
};
#[path = "gateway_replay_gc.rs"]
mod replay_gc;
#[path = "gateway_replay_journal.rs"]
mod replay_journal;
#[path = "gateway_session_overlay.rs"]
mod session_overlay;
pub use session_overlay::GatewaySessionCheckpoint;
#[path = "gateway_pre_auth.rs"]
mod pre_auth_state;
#[path = "gateway_store_format.rs"]
mod store_format;
#[path = "gateway_write_admission.rs"]
mod write_admission;
pub use pre_auth_state::{GatewayAdmissionCheckpoint, PRE_AUTH_CHECKPOINT_SECONDS};
pub use write_admission::{
    GATEWAY_NETWORK_WRITE_LIMIT, GatewayManagementAdmission, GatewayWriteAdmission,
};

use crate::{
    GATEWAY_CHALLENGE_STATE_KEY, GATEWAY_PRE_AUTH_POLICY_KEY, GATEWAY_STATE_TABLE,
    GatewayPreAuthChallengeResponse, GatewayPreAuthDecision, GatewayPreAuthMetrics,
    GatewayPreAuthPolicy, NodeCoreError, NodeReplayGuardState, PRE_AUTH_PROTOCOL_VERSION,
    PreAuthChallenge, load_snapshot, open_redb_with_table, save_snapshot, save_snapshot_batch,
    serialize_snapshot_value,
};
use hmac::{Hmac, KeyInit, Mac};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GatewaySessionLifecycle {
    Connect,
    Authed,
    Live,
    Draining,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewaySession {
    pub session_id: String,
    pub target_delivery_id: String,
    pub device_id: String,
    pub opened_at: u64,
    pub last_heartbeat_at: u64,
    pub lifecycle: GatewaySessionLifecycle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayResumeTokenMetadata {
    pub resume_token_hash: String,
    pub session_id: String,
    pub target_delivery_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub issued_at: u64,
    pub token_mac: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResumeToken {
    pub token: String,
    pub metadata: GatewayResumeTokenMetadata,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayResumeIssueInput<'a> {
    pub session_id: &'a str,
    pub target_delivery_id: &'a str,
    pub device_id: &'a str,
    pub device_epoch: u64,
    pub issued_at: u64,
    pub window_seconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayResumeValidateInput<'a> {
    pub resume_token_hash: &'a str,
    pub previous_session_id: &'a str,
    pub target_delivery_id: &'a str,
    pub device_id: &'a str,
    pub device_epoch: u64,
    pub now: u64,
    pub window_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GatewayFrame {
    Deliver { session_id: String, envelope_id: String, payload_hash: String },
    Drain { session_id: String },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayState {
    challenges_by_id: BTreeMap<String, PreAuthChallenge>,
    sessions_by_id: BTreeMap<String, GatewaySession>,
    frames_by_session: BTreeMap<String, Vec<GatewayFrame>>,
    #[serde(default)]
    pre_auth_policy: GatewayPreAuthPolicy,
    #[serde(default)]
    pre_auth_metrics: GatewayPreAuthMetrics,
    #[serde(default)]
    pre_auth_handshakes_by_source_ip: BTreeMap<String, Vec<u64>>,
    #[serde(skip)]
    pre_auth_policy_revision: u64,
    #[serde(skip)]
    pre_auth_committed_floor: u64,
    #[serde(skip)]
    pre_auth_checkpoint_stalled: bool,
    #[serde(skip)]
    retention_cursors: [Option<String>; 3],
    #[serde(skip)]
    pre_auth_expiry: BTreeSet<(u64, String)>,
    #[serde(skip)]
    pre_auth_expiry_by_source: BTreeMap<String, u64>,
    #[serde(skip)]
    pre_auth_runtime_deadline: Option<u64>,
    #[serde(skip)]
    pre_auth_restart_until: u64,
    #[serde(default)]
    pre_auth_time_floor: u64,
    #[serde(skip)]
    pre_auth_cookie_key: Option<crate::RedactedString>,
    #[serde(default)]
    replay_guard_state: NodeReplayGuardState,
    #[serde(default)]
    resume_token_index_by_hash: BTreeMap<String, GatewayResumeTokenMetadata>,
}

impl GatewayState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue_challenge(&mut self, challenge: PreAuthChallenge) {
        self.challenges_by_id.insert(challenge.challenge_id.clone(), challenge);
    }

    /// # Errors
    /// Rejects invalid policy bounds without changing live debt or resume secrets.
    pub fn set_pre_auth_policy(
        &mut self,
        policy: GatewayPreAuthPolicy,
    ) -> Result<(), NodeCoreError> {
        pre_auth_state::validate_policy(&policy)?;
        self.pre_auth_policy_revision = self
            .pre_auth_policy_revision
            .checked_add(1)
            .ok_or(NodeCoreError::PreAuthConfigInvalid)?;
        self.pre_auth_policy = policy;
        self.trim_pre_auth_debt();
        Ok(())
    }

    /// Install the policy from an already validated and durably committed snapshot.
    /// Retains live counters, debt and resume-signing bytes; no validation can fail after commit.
    pub fn install_committed_pre_auth_policy_from(&mut self, committed: &Self) {
        let mut policy = committed.pre_auth_policy.clone();
        policy.cookie_secret = self.pre_auth_policy.cookie_secret.clone();
        self.pre_auth_policy = policy;
        self.pre_auth_policy_revision = committed.pre_auth_policy_revision;
        self.trim_pre_auth_debt();
    }

    fn trim_pre_auth_debt(&mut self) {
        let rate = self.pre_auth_policy.per_source_ip_handshake_rate.min(60) as usize;
        for events in self.pre_auth_handshakes_by_source_ip.values_mut() {
            if events.len() > rate {
                events.drain(..events.len() - rate);
            }
        }
    }

    /// Narrow predicate for causal admission observers; does not expose source data in logs.
    #[must_use]
    pub fn has_pre_auth_source(&self, source: &str) -> bool {
        self.pre_auth_handshakes_by_source_ip.contains_key(source)
    }

    #[must_use]
    pub const fn pre_auth_policy(&self) -> &GatewayPreAuthPolicy {
        &self.pre_auth_policy
    }

    #[must_use]
    pub const fn pre_auth_metrics(&self) -> &GatewayPreAuthMetrics {
        &self.pre_auth_metrics
    }

    #[must_use]
    pub fn pre_auth_read_timeout(&self) -> Duration {
        Duration::from_millis(self.pre_auth_policy.auth_deadline_ms.max(1))
    }

    pub fn record_slowloris_timeout(&mut self) {
        self.pre_auth_metrics.slowloris_auth_timeout =
            self.pre_auth_metrics.slowloris_auth_timeout.saturating_add(1);
    }

    pub fn replay_guard_state_mut(&mut self) -> &mut NodeReplayGuardState {
        &mut self.replay_guard_state
    }

    /// # Errors
    /// Returns an error when the source is rate-limited or presents an invalid cookie.
    pub fn check_pre_auth(
        &mut self,
        source_ip_hash: &str,
        cookie: Option<&str>,
        now: u64,
    ) -> Result<GatewayPreAuthDecision, NodeCoreError> {
        if !self.pre_auth_policy.enabled {
            return Ok(GatewayPreAuthDecision::Accepted);
        }
        self.validate_pre_auth_configuration()?;
        if now < self.pre_auth_time_floor {
            return Err(NodeCoreError::PreAuthClockRollback);
        }
        self.pre_auth_time_floor = now;
        let window_start = now.saturating_sub(self.pre_auth_policy.window_seconds);
        if now <= self.pre_auth_restart_until && self.pre_auth_restart_until != 0 {
            return Err(NodeCoreError::PreAuthCapacity);
        }
        // Fixed work per Open, even when an entire source set expires at once.
        for _ in 0..16 {
            let Some((at, source)) = self.pre_auth_expiry.first() else { break };
            if *at >= window_start {
                break;
            }
            let source = source.clone();
            self.pre_auth_expiry.pop_first();
            self.pre_auth_handshakes_by_source_ip.remove(&source);
            self.pre_auth_expiry_by_source.remove(&source);
        }
        if (!self.pre_auth_handshakes_by_source_ip.contains_key(source_ip_hash)
            && self.pre_auth_handshakes_by_source_ip.len() >= 4096)
            || (!self.pre_auth_expiry_by_source.contains_key(source_ip_hash)
                && self.pre_auth_expiry_by_source.len() >= 4096)
        {
            return Err(NodeCoreError::PreAuthCapacity);
        }
        let cookie_secret =
            self.pre_auth_cookie_key.as_ref().ok_or(NodeCoreError::PreAuthConfigInvalid)?.as_str();
        let entries =
            self.pre_auth_handshakes_by_source_ip.entry(source_ip_hash.to_owned()).or_default();
        if let Some(at) = self.pre_auth_expiry_by_source.insert(source_ip_hash.to_owned(), now) {
            self.pre_auth_expiry.remove(&(at, source_ip_hash.to_owned()));
        }
        entries.retain(|timestamp| *timestamp >= window_start);
        // Reserve the latest timestamp before any return path, including challenge/error.
        self.pre_auth_expiry.insert((now, source_ip_hash.to_owned()));
        let rate = self.pre_auth_policy.per_source_ip_handshake_rate as usize;
        // Only the newest `rate` events affect the sliding-window threshold.
        // Also bound buckets restored from snapshots written before this cap.
        if entries.len() > rate {
            entries.drain(..entries.len() - rate);
            entries.shrink_to_fit();
        }
        if entries.len() < rate {
            entries.push(now);
            return Ok(GatewayPreAuthDecision::Accepted);
        }
        match cookie {
            Some(cookie)
                if verify_pre_auth_cookie(
                    source_ip_hash,
                    PRE_AUTH_PROTOCOL_VERSION,
                    cookie,
                    now,
                    self.pre_auth_policy.cookie_ttl_seconds,
                    cookie_secret,
                ) =>
            {
                // A valid cookie permits admission, not unbounded history growth.
                // Refresh the oldest slot so recent retries still fill the window.
                if !entries.is_empty() {
                    entries.remove(0);
                    entries.push(now);
                }
                Ok(GatewayPreAuthDecision::Accepted)
            }
            Some(_cookie) => {
                self.pre_auth_metrics.pre_auth_cookie_failed =
                    self.pre_auth_metrics.pre_auth_cookie_failed.saturating_add(1);
                Err(NodeCoreError::ItestHttp("invalid pre-auth cookie".to_owned()))
            }
            None => {
                self.pre_auth_metrics.pre_auth_cookie_required =
                    self.pre_auth_metrics.pre_auth_cookie_required.saturating_add(1);
                self.pre_auth_metrics.deviceproof_rate_limited =
                    self.pre_auth_metrics.deviceproof_rate_limited.saturating_add(1);
                let cookie = sign_pre_auth_cookie(
                    source_ip_hash,
                    PRE_AUTH_PROTOCOL_VERSION,
                    now,
                    cookie_secret,
                );
                Ok(GatewayPreAuthDecision::Challenge(GatewayPreAuthChallengeResponse {
                    challenge: "pre_auth_cookie_required".to_owned(),
                    pre_auth_cookie: cookie,
                    retry_after_ms: 0,
                }))
            }
        }
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn consume_challenge(&mut self, challenge_id: &str, now: u64) -> Result<(), NodeCoreError> {
        let challenge = self
            .challenges_by_id
            .get_mut(challenge_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(challenge_id.to_owned()))?;
        if challenge.used || challenge.expires_at <= now {
            return Err(NodeCoreError::StaleSessionUpdate {
                target_delivery_id: challenge_id.to_owned(),
            });
        }
        challenge.used = true;
        Ok(())
    }

    pub fn open_session(&mut self, session: GatewaySession) {
        self.sessions_by_id.insert(session.session_id.clone(), session);
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_live(&mut self, session_id: &str, heartbeat_at: u64) -> Result<(), NodeCoreError> {
        let session = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(session_id.to_owned()))?;
        session.lifecycle = GatewaySessionLifecycle::Live;
        session.last_heartbeat_at = heartbeat_at;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn deliver(&mut self, frame: GatewayFrame) -> Result<(), NodeCoreError> {
        let session_id = match &frame {
            GatewayFrame::Deliver { session_id, .. } | GatewayFrame::Drain { session_id } => {
                session_id.clone()
            }
        };
        if !self.sessions_by_id.contains_key(&session_id) {
            return Err(NodeCoreError::SessionNotFound(session_id));
        }
        self.frames_by_session.entry(session_id).or_default().push(frame);
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn drain(&mut self, session_id: &str) -> Result<(), NodeCoreError> {
        let session = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(session_id.to_owned()))?;
        session.lifecycle = GatewaySessionLifecycle::Draining;
        self.frames_by_session
            .entry(session_id.to_owned())
            .or_default()
            .push(GatewayFrame::Drain { session_id: session_id.to_owned() });
        Ok(())
    }

    #[must_use]
    pub fn session(&self, session_id: &str) -> Option<&GatewaySession> {
        self.sessions_by_id.get(session_id)
    }

    pub fn issue_resume_token(&mut self, input: GatewayResumeIssueInput<'_>) -> GatewayResumeToken {
        self.expire_resume_tokens(input.issued_at, input.window_seconds);
        let mac = gateway_resume_token_mac(
            &self.pre_auth_policy.cookie_secret,
            &GatewayResumeMacInput {
                session_id: input.session_id,
                target_delivery_id: input.target_delivery_id,
                device_id: input.device_id,
                device_epoch: input.device_epoch,
                issued_at: input.issued_at,
            },
        );
        let token = format!(
            "v1.{}.{}.{}",
            ramflux_protocol::encode_base64url(input.session_id.as_bytes()),
            input.issued_at,
            ramflux_protocol::encode_base64url(mac)
        );
        let resume_token_hash = gateway_resume_token_hash(&token);
        let metadata = GatewayResumeTokenMetadata {
            resume_token_hash: resume_token_hash.clone(),
            session_id: input.session_id.to_owned(),
            target_delivery_id: input.target_delivery_id.to_owned(),
            device_id: input.device_id.to_owned(),
            device_epoch: input.device_epoch,
            issued_at: input.issued_at,
            token_mac: ramflux_protocol::encode_base64url(mac),
        };
        self.resume_token_index_by_hash.insert(resume_token_hash, metadata.clone());
        GatewayResumeToken { token, metadata }
    }

    pub fn validate_resume_token_hash(
        &mut self,
        input: GatewayResumeValidateInput<'_>,
    ) -> Option<GatewayResumeTokenMetadata> {
        self.expire_resume_tokens(input.now, input.window_seconds);
        let metadata = self.resume_token_index_by_hash.get(input.resume_token_hash)?;
        if metadata.session_id != input.previous_session_id
            || metadata.target_delivery_id != input.target_delivery_id
            || metadata.device_id != input.device_id
            || metadata.device_epoch != input.device_epoch
            || input.now < metadata.issued_at
            || input.now.saturating_sub(metadata.issued_at) > input.window_seconds
        {
            return None;
        }
        let session = self.sessions_by_id.get(input.previous_session_id)?;
        if session.target_delivery_id != input.target_delivery_id
            || session.device_id != input.device_id
            || session.lifecycle == GatewaySessionLifecycle::Closed
        {
            return None;
        }
        let expected_mac = gateway_resume_token_mac(
            &self.pre_auth_policy.cookie_secret,
            &GatewayResumeMacInput {
                session_id: &metadata.session_id,
                target_delivery_id: &metadata.target_delivery_id,
                device_id: &metadata.device_id,
                device_epoch: metadata.device_epoch,
                issued_at: metadata.issued_at,
            },
        );
        let expected_mac = ramflux_protocol::encode_base64url(expected_mac);
        if !constant_time_eq(expected_mac.as_bytes(), metadata.token_mac.as_bytes()) {
            return None;
        }
        Some(metadata.clone())
    }

    /// Visit at most 64 rows in each metadata family; the timer never scans all sessions.
    pub fn prune_retained_sessions_bounded(
        &mut self,
        now: u64,
        window: u64,
        mut active: impl FnMut(&GatewaySession) -> bool,
    ) {
        self.replay_guard_state.prune(i64::try_from(now).unwrap_or(i64::MAX));
        for id in next_retention_keys(&self.sessions_by_id, &mut self.retention_cursors[0]) {
            if self.sessions_by_id.get(&id).is_some_and(|session| {
                session.lifecycle == GatewaySessionLifecycle::Closed
                    || (!active(session) && now.saturating_sub(session.last_heartbeat_at) > window)
            }) {
                self.sessions_by_id.remove(&id);
                self.frames_by_session.remove(&id);
            }
        }
        for hash in
            next_retention_keys(&self.resume_token_index_by_hash, &mut self.retention_cursors[1])
        {
            if self.resume_token_index_by_hash.get(&hash).is_some_and(|token| {
                !self.sessions_by_id.contains_key(&token.session_id)
                    || now < token.issued_at
                    || now.saturating_sub(token.issued_at) > window
            }) {
                self.resume_token_index_by_hash.remove(&hash);
            }
        }
        for id in next_retention_keys(&self.challenges_by_id, &mut self.retention_cursors[2]) {
            if self
                .challenges_by_id
                .get(&id)
                .is_some_and(|challenge| challenge.used || challenge.expires_at <= now)
            {
                self.challenges_by_id.remove(&id);
            }
        }
    }

    /// Expire disconnected/closed sessions, their frame queues, challenges and resume indexes.
    pub fn prune_retained_sessions(
        &mut self,
        now: u64,
        window: u64,
        active: &BTreeSet<String>,
    ) -> usize {
        self.replay_guard_state.prune(i64::try_from(now).unwrap_or(i64::MAX));
        let before = self.sessions_by_id.len();
        self.sessions_by_id.retain(|id, session| {
            session.lifecycle != GatewaySessionLifecycle::Closed
                && (active.contains(id) || now.saturating_sub(session.last_heartbeat_at) <= window)
        });
        self.frames_by_session.retain(|id, _| self.sessions_by_id.contains_key(id));
        self.resume_token_index_by_hash
            .retain(|_, token| self.sessions_by_id.contains_key(&token.session_id));
        self.expire_resume_tokens(now, window);
        self.challenges_by_id.retain(|_, challenge| !challenge.used && challenge.expires_at > now);
        self.pre_auth_handshakes_by_source_ip.retain(|_, events| {
            events.retain(|at| now.saturating_sub(*at) <= self.pre_auth_policy.window_seconds);
            !events.is_empty()
        });
        before - self.sessions_by_id.len()
    }

    pub fn expire_resume_tokens(&mut self, now: u64, window_seconds: u64) {
        self.resume_token_index_by_hash.retain(|_hash, metadata| {
            now >= metadata.issued_at && now.saturating_sub(metadata.issued_at) <= window_seconds
        });
    }

    #[must_use]
    pub fn queued_frame_count(&self, session_id: &str) -> usize {
        self.frames_by_session.get(session_id).map_or(0, Vec::len)
    }
}

fn next_retention_keys<T>(rows: &BTreeMap<String, T>, cursor: &mut Option<String>) -> Vec<String> {
    let keys: Vec<String> = match cursor.as_ref() {
        Some(start) => rows
            .range((std::ops::Bound::Excluded(start.clone()), std::ops::Bound::Unbounded))
            .take(64)
            .map(|(key, _)| key.clone())
            .collect(),
        None => rows.keys().take(64).cloned().collect(),
    };
    *cursor = if keys.len() == 64 { keys.last().cloned() } else { None };
    keys
}

#[must_use]
pub fn gateway_resume_token_hash(token: &str) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.gateway.resume_token.v1", token.as_bytes())
}

struct GatewayResumeMacInput<'a> {
    session_id: &'a str,
    target_delivery_id: &'a str,
    device_id: &'a str,
    device_epoch: u64,
    issued_at: u64,
}

fn gateway_resume_token_mac(secret: &str, input: &GatewayResumeMacInput<'_>) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return [0_u8; 32];
    };
    mac.update(b"ramflux.gateway.resume_token.v1");
    mac.update(&[0]);
    mac.update(&(input.session_id.len() as u64).to_be_bytes());
    mac.update(input.session_id.as_bytes());
    mac.update(&(input.target_delivery_id.len() as u64).to_be_bytes());
    mac.update(input.target_delivery_id.as_bytes());
    mac.update(&(input.device_id.len() as u64).to_be_bytes());
    mac.update(input.device_id.as_bytes());
    mac.update(&input.device_epoch.to_be_bytes());
    mac.update(&input.issued_at.to_be_bytes());
    mac.finalize().into_bytes().into()
}

#[must_use]
pub fn sign_pre_auth_cookie(
    source_ip_hash: &str,
    protocol_version: &str,
    timestamp: u64,
    secret: &str,
) -> String {
    let mac = pre_auth_cookie_mac(source_ip_hash, protocol_version, timestamp, secret);
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&mac);
    ramflux_protocol::encode_base64url(bytes)
}

#[must_use]
pub fn verify_pre_auth_cookie(
    source_ip_hash: &str,
    protocol_version: &str,
    cookie: &str,
    now: u64,
    ttl_seconds: u64,
    secret: &str,
) -> bool {
    let Ok(bytes) = ramflux_protocol::decode_base64url(cookie) else {
        return false;
    };
    let Some(timestamp_bytes) = bytes.get(..8) else {
        return false;
    };
    let Some(mac) = bytes.get(8..) else {
        return false;
    };
    if mac.len() != 32 {
        return false;
    }
    let Ok(timestamp_array) = <[u8; 8]>::try_from(timestamp_bytes) else {
        return false;
    };
    let timestamp = u64::from_be_bytes(timestamp_array);
    if timestamp > now || now.saturating_sub(timestamp) > ttl_seconds {
        return false;
    }
    let expected = pre_auth_cookie_mac(source_ip_hash, protocol_version, timestamp, secret);
    constant_time_eq(mac, &expected)
}

#[must_use]
pub fn now_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn pre_auth_cookie_mac(
    source_ip_hash: &str,
    protocol_version: &str,
    timestamp: u64,
    secret: &str,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    write_len_prefixed(&mut bytes, source_ip_hash.as_bytes());
    write_len_prefixed(&mut bytes, protocol_version.as_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    write_len_prefixed(&mut bytes, secret.as_bytes());
    ramflux_crypto::blake3_256("ramflux.pre_auth_cookie.v1", &bytes)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right.iter()).fold(0_u8, |acc, (left, right)| acc | (left ^ right)) == 0
}

fn write_len_prefixed(output: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
}

pub struct GatewayRedbStore {
    db: redb::Database,
    path: PathBuf,
    replay_config: std::sync::Mutex<Option<GatewayReplayConfig>>,
    write_gate: std::sync::Mutex<()>,
    network_admission: std::sync::Mutex<write_admission::Pending>,
    management_pending: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "durability-test-hooks"))]
    writer_attempt: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    #[cfg(any(test, feature = "durability-test-hooks"))]
    admission_commit_pause: std::sync::Mutex<Option<AdmissionCommitPause>>,
    #[cfg(any(test, feature = "durability-test-hooks"))]
    fail_pre_auth_commit: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "durability-test-hooks"))]
    durable_commits: std::sync::atomic::AtomicUsize,
    #[cfg(any(test, feature = "durability-test-hooks"))]
    full_snapshot_commits: std::sync::atomic::AtomicUsize,
}

#[cfg(any(test, feature = "durability-test-hooks"))]
struct AdmissionCommitPause {
    started: Box<dyn FnOnce() -> Result<(), NodeCoreError> + Send>,
    release: std::sync::mpsc::Receiver<()>,
}

/// Acquire before the gateway state mutex; durable I/O then happens after releasing state.
pub struct GatewayStoreWriter<'a> {
    store: &'a GatewayRedbStore,
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl GatewayStoreWriter<'_> {
    /// # Errors
    /// Returns storage errors; caller must release its state lock before committing.
    pub fn save_auth_replay(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        self.store.save_auth_replay_unlocked(source, request, now)
    }
    /// # Errors
    /// Returns invalid snapshot, stale policy or storage errors.
    pub fn save_admission_checkpoint(
        &self,
        checkpoint: &GatewayAdmissionCheckpoint,
    ) -> Result<(), NodeCoreError> {
        self.store.save_admission_checkpoint_unlocked(checkpoint)
    }
    /// # Errors
    /// Returns serialization or storage errors.
    pub fn save_session_checkpoint(
        &self,
        checkpoint: &GatewaySessionCheckpoint,
    ) -> Result<(), NodeCoreError> {
        self.store.save_session_checkpoint_unlocked(checkpoint)
    }
    /// Remove at most 64 expired session rows and 64 token rows outside the state lock.
    /// # Errors
    /// Returns storage errors.
    pub fn prune_session_rows(&self, now: u64, window: u64) -> Result<(), NodeCoreError> {
        self.store.prune_session_rows_unlocked(now, window)
    }
    /// # Errors
    /// Returns serialization or storage errors for an explicit full checkpoint.
    pub fn save_state(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        self.store.save_state_unlocked(state)
    }
}

impl GatewayRedbStore {
    /// Serialize durable writers without blocking ordinary state operations on disk I/O.
    /// # Errors
    /// Returns an error if a writer panicked while owning the serialization gate.
    pub fn write_guard(&self) -> Result<GatewayStoreWriter<'_>, NodeCoreError> {
        #[cfg(any(test, feature = "durability-test-hooks"))]
        if let Some(observer) = self
            .writer_attempt
            .lock()
            .map_err(|_| NodeCoreError::Redb("writer observer poisoned".into()))?
            .take()
        {
            let _ = observer.send(());
        }
        let guard = self
            .write_gate
            .lock()
            .map_err(|_| NodeCoreError::Redb("gateway writer poisoned".into()))?;
        Ok(GatewayStoreWriter { store: self, _guard: guard })
    }

    /// Observe the next writer acquisition attempt, before it can wait for the gate.
    /// # Errors
    /// Returns a poisoned test-observer error.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn observe_next_writer_attempt(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), NodeCoreError> {
        *self
            .writer_attempt
            .lock()
            .map_err(|_| NodeCoreError::Redb("writer observer poisoned".into()))? = Some(observer);
        Ok(())
    }

    /// Pause one real checkpoint after its writes and before its durable commit.
    /// # Errors
    /// Returns a poisoned test-hook mutex error.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn pause_next_admission_commit(
        &self,
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), NodeCoreError> {
        *self
            .admission_commit_pause
            .lock()
            .map_err(|_| NodeCoreError::Redb("checkpoint hook poisoned".into()))? =
            Some(AdmissionCommitPause {
                started: Box::new(move || {
                    started
                        .send(())
                        .map_err(|_| NodeCoreError::Redb("checkpoint observer gone".into()))
                }),
                release,
            });
        Ok(())
    }

    /// Pause a real commit with a bounded observer channel.
    /// # Errors
    /// Returns a poisoned test-hook error.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn pause_next_admission_commit_bounded(
        &self,
        started: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), NodeCoreError> {
        *self
            .admission_commit_pause
            .lock()
            .map_err(|_| NodeCoreError::Redb("checkpoint hook poisoned".into()))? =
            Some(AdmissionCommitPause {
                started: Box::new(move || {
                    started
                        .try_send(())
                        .map_err(|_| NodeCoreError::Redb("checkpoint observer unavailable".into()))
                }),
                release,
            });
        Ok(())
    }

    #[cfg(any(test, feature = "durability-test-hooks"))]
    fn record_incremental_commit(&self) {
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.durable_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "durability-test-hooks"))]
    fn before_admission_commit(&self) -> Result<(), NodeCoreError> {
        #[cfg(any(test, feature = "durability-test-hooks"))]
        {
            let pause = self
                .admission_commit_pause
                .lock()
                .map_err(|_| NodeCoreError::Redb("checkpoint hook poisoned".into()))?
                .take();
            if let Some(pause) = pause {
                (pause.started)()?;
                pause
                    .release
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|_| NodeCoreError::Redb("checkpoint release unavailable".into()))?;
            }
            if self.fail_pre_auth_commit.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(NodeCoreError::Redb("injected pre-auth commit failure".into()));
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let path = path.as_ref().to_path_buf();
        let db = store_format::open(&path)?;
        Ok(Self {
            db,
            path,
            replay_config: std::sync::Mutex::new(None),
            write_gate: std::sync::Mutex::new(()),
            network_admission: std::sync::Mutex::new(write_admission::Pending::default()),
            management_pending: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "durability-test-hooks"))]
            writer_attempt: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "durability-test-hooks"))]
            admission_commit_pause: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "durability-test-hooks"))]
            fail_pre_auth_commit: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "durability-test-hooks"))]
            durable_commits: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(any(test, feature = "durability-test-hooks"))]
            full_snapshot_commits: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    /// Callers commit signed-request evidence with `save_auth_replay`; this explicit
    /// checkpoint never serializes or writes the replay map.
    pub fn save_state(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        self.write_guard()?.save_state(state)
    }

    fn save_state_unlocked(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        let mut entries =
            vec![(GATEWAY_CHALLENGE_STATE_KEY, serialize_snapshot_value(&state.challenges_by_id)?)];
        entries.extend(state.pre_auth_entries()?);
        self.save_full_gateway_entries(&entries, state)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.full_snapshot_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// # Errors
    /// Returns an error when policy and admission clock state cannot be committed together.
    pub fn save_pre_auth_hot(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        let _writer = self.write_guard()?;
        self.save_gateway_entries(&state.pre_auth_entries()?)
    }

    fn save_gateway_entries(&self, entries: &[(&str, Vec<u8>)]) -> Result<(), NodeCoreError> {
        save_snapshot_batch(&self.db, GATEWAY_STATE_TABLE, entries, || {
            #[cfg(any(test, feature = "durability-test-hooks"))]
            if self.fail_pre_auth_commit.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(NodeCoreError::Redb("injected pre-auth commit failure".into()));
            }
            Ok(())
        })?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.durable_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Number of successful gateway snapshot commits for durability witnesses.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn durable_commit_count(&self) -> usize {
        self.durable_commits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Number of successful full snapshots, to calibrate incremental auth tests.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn full_snapshot_commit_count(&self) -> usize {
        self.full_snapshot_commits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Abort the next real admission transaction after its writes, before commit.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn fail_next_pre_auth_commit(&self) {
        self.fail_pre_auth_commit.store(true, std::sync::atomic::Ordering::Release);
    }

    /// # Errors
    /// Returns an error when the persisted gateway state cannot be read.
    pub fn load_state(&self) -> Result<Option<GatewayState>, NodeCoreError> {
        self.load_state_configured(None)
    }

    /// Restore using validated runtime policy before interpreting persisted admission debt.
    /// # Errors
    /// Rejects invalid runtime policy, malformed snapshots and storage failures.
    pub fn load_state_with_pre_auth_config(
        &self,
        config: &crate::GatewayPreAuthConfig,
    ) -> Result<Option<GatewayState>, NodeCoreError> {
        self.load_state_configured(Some(config))
    }

    fn load_state_configured(
        &self,
        config: Option<&crate::GatewayPreAuthConfig>,
    ) -> Result<Option<GatewayState>, NodeCoreError> {
        let saved_policy: Option<GatewayPreAuthPolicy> =
            load_snapshot(&self.db, GATEWAY_STATE_TABLE, GATEWAY_PRE_AUTH_POLICY_KEY)?;
        let initialized = saved_policy.is_some();
        let sessions_by_id = self.load_sessions()?;
        let mut state = GatewayState {
            challenges_by_id: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_CHALLENGE_STATE_KEY,
            )?
            .unwrap_or_default(),
            sessions_by_id,
            frames_by_session: self.load_frames()?,
            pre_auth_policy: saved_policy.unwrap_or_default(),
            pre_auth_metrics: GatewayPreAuthMetrics::default(),
            pre_auth_handshakes_by_source_ip: BTreeMap::new(),
            pre_auth_time_floor: 0,
            pre_auth_cookie_key: None,
            pre_auth_policy_revision: 0,
            pre_auth_committed_floor: 0,
            pre_auth_checkpoint_stalled: false,
            retention_cursors: [None, None, None],
            pre_auth_expiry: BTreeSet::new(),
            pre_auth_expiry_by_source: BTreeMap::new(),
            pre_auth_runtime_deadline: None,
            pre_auth_restart_until: 0,
            replay_guard_state: NodeReplayGuardState::new(),
            resume_token_index_by_hash: self.load_tokens()?,
        };
        if let Some(config) = config {
            state.configure_pre_auth_policy(config)?;
        } else if pre_auth_state::validate_policy(&state.pre_auth_policy).is_err() {
            state.configure_pre_auth_policy(&crate::GatewayPreAuthConfig::default())?;
        }
        self.load_pre_auth_admission(&mut state)?;
        state.trim_pre_auth_debt();
        if !initialized
            && state.sessions_by_id.is_empty()
            && !self.has_replay_entries()?
            && state.pre_auth_time_floor == 0
            && state.pre_auth_handshakes_by_source_ip.is_empty()
            && state.pre_auth_metrics == GatewayPreAuthMetrics::default()
        {
            return Ok(None);
        }
        Ok(Some(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_retries_bound_bucket_and_preserve_sliding_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut state = GatewayState::new();
        state.set_fixture_pre_auth_cookie_key();
        state.set_pre_auth_policy(GatewayPreAuthPolicy {
            enabled: true,
            per_source_ip_handshake_rate: 3,
            window_seconds: 60,
            cookie_ttl_seconds: 60,
            ..GatewayPreAuthPolicy::default()
        })?;
        for _ in 0..3 {
            assert_eq!(state.check_pre_auth("peer", None, 100)?, GatewayPreAuthDecision::Accepted);
        }
        let GatewayPreAuthDecision::Challenge(challenge) =
            state.check_pre_auth("peer", None, 100)?
        else {
            return Err("expected cookie challenge at the threshold".into());
        };
        for now in 101..=108 {
            assert_eq!(
                state.check_pre_auth("peer", Some(&challenge.pre_auth_cookie), now)?,
                GatewayPreAuthDecision::Accepted
            );
            assert_eq!(state.pre_auth_handshakes_by_source_ip["peer"].len(), 3);
        }
        assert_eq!(state.pre_auth_handshakes_by_source_ip["peer"], [106, 107, 108]);
        assert!(matches!(
            state.check_pre_auth("peer", None, 162)?,
            GatewayPreAuthDecision::Challenge(_)
        ));
        assert!(state.check_pre_auth("peer", Some("invalid"), 162).is_err());
        assert_eq!(state.check_pre_auth("peer", None, 169)?, GatewayPreAuthDecision::Accepted);
        assert_eq!(state.pre_auth_handshakes_by_source_ip["peer"], [169]);
        Ok(())
    }

    #[test]
    fn cookie_retries_bound_restored_and_zero_rate_buckets()
    -> Result<(), Box<dyn std::error::Error>> {
        for rate in [0, 3] {
            let mut state = GatewayState::new();
            state.set_fixture_pre_auth_cookie_key();
            state.set_pre_auth_policy(GatewayPreAuthPolicy {
                enabled: true,
                per_source_ip_handshake_rate: rate,
                ..GatewayPreAuthPolicy::default()
            })?;
            state.pre_auth_handshakes_by_source_ip.insert("peer".into(), vec![100; 12]);
            let cookie = sign_pre_auth_cookie(
                "peer",
                PRE_AUTH_PROTOCOL_VERSION,
                100,
                &state.pre_auth_policy.cookie_secret,
            );
            assert_eq!(
                state.check_pre_auth("peer", Some(&cookie), 100)?,
                GatewayPreAuthDecision::Accepted
            );
            assert_eq!(state.pre_auth_handshakes_by_source_ip["peer"].len(), rate as usize);
            assert!(matches!(
                state.check_pre_auth("peer", None, 100)?,
                GatewayPreAuthDecision::Challenge(_)
            ));
        }
        Ok(())
    }

    #[test]
    fn gateway_resume_token_mac_golden_preserves_persisted_bytes() {
        let input = GatewayResumeMacInput {
            session_id: "session-golden",
            target_delivery_id: "delivery-golden",
            device_id: "device-golden",
            device_epoch: 7,
            issued_at: 1_700_000_000,
        };
        let mac = gateway_resume_token_mac("golden-service-key", &input);
        let hex: String = mac
            .iter()
            .flat_map(|byte| {
                let digits = b"0123456789abcdef";
                [
                    char::from(digits[usize::from(byte >> 4)]),
                    char::from(digits[usize::from(byte & 15)]),
                ]
            })
            .collect();
        assert_eq!(hex, "483eacd95f43a47f4584d68a93bb99085d49d3c4749849c2c60800fdba029d19");
    }
}
