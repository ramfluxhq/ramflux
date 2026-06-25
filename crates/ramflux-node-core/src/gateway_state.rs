// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::{
    GATEWAY_CHALLENGE_STATE_KEY, GATEWAY_DELIVERY_FRAME_QUEUE_KEY, GATEWAY_PRE_AUTH_METRICS_KEY,
    GATEWAY_PRE_AUTH_POLICY_KEY, GATEWAY_PRE_AUTH_RATE_STATE_KEY, GATEWAY_REPLAY_GUARD_STATE_KEY,
    GATEWAY_RESUME_TOKEN_INDEX_KEY, GATEWAY_SESSION_CHECKPOINT_KEY, GATEWAY_STATE_TABLE,
    GatewayPreAuthChallengeResponse, GatewayPreAuthDecision, GatewayPreAuthMetrics,
    GatewayPreAuthPolicy, NodeCoreError, NodeReplayGuardState, PRE_AUTH_PROTOCOL_VERSION,
    PreAuthChallenge, load_snapshot, open_redb_with_table, save_snapshot, save_snapshot_batch,
    serialize_snapshot_value,
};
use hmac::{Hmac, Mac};
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

    pub fn set_pre_auth_policy(&mut self, policy: GatewayPreAuthPolicy) {
        self.pre_auth_policy = policy;
        self.pre_auth_handshakes_by_source_ip.clear();
        self.pre_auth_metrics = GatewayPreAuthMetrics::default();
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
        let window_start = now.saturating_sub(self.pre_auth_policy.window_seconds);
        let entries =
            self.pre_auth_handshakes_by_source_ip.entry(source_ip_hash.to_owned()).or_default();
        entries.retain(|timestamp| *timestamp >= window_start);
        if entries.len() < self.pre_auth_policy.per_source_ip_handshake_rate as usize {
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
                    &self.pre_auth_policy.cookie_secret,
                ) =>
            {
                entries.push(now);
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
                    &self.pre_auth_policy.cookie_secret,
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
}

impl GatewayRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let db = open_redb_with_table(path, GATEWAY_STATE_TABLE)?;
        Ok(Self { db })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_state(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_CHALLENGE_STATE_KEY,
            &state.challenges_by_id,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_SESSION_CHECKPOINT_KEY,
            &state.sessions_by_id,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_DELIVERY_FRAME_QUEUE_KEY,
            &state.frames_by_session,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_PRE_AUTH_POLICY_KEY,
            &state.pre_auth_policy,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_PRE_AUTH_METRICS_KEY,
            &state.pre_auth_metrics,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_PRE_AUTH_RATE_STATE_KEY,
            &state.pre_auth_handshakes_by_source_ip,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_REPLAY_GUARD_STATE_KEY,
            &state.replay_guard_state,
        )?;
        save_snapshot(
            &self.db,
            GATEWAY_STATE_TABLE,
            GATEWAY_RESUME_TOKEN_INDEX_KEY,
            &state.resume_token_index_by_hash,
        )
    }

    /// # Errors
    /// Returns an error when the pre-auth hot state cannot be serialized or persisted.
    pub fn save_pre_auth_hot(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        self.save_gateway_entries(&[
            (GATEWAY_PRE_AUTH_METRICS_KEY, serialize_snapshot_value(&state.pre_auth_metrics)?),
            (
                GATEWAY_PRE_AUTH_RATE_STATE_KEY,
                serialize_snapshot_value(&state.pre_auth_handshakes_by_source_ip)?,
            ),
        ])
    }

    /// # Errors
    /// Returns an error when the pre-auth challenge state cannot be serialized or persisted.
    pub fn save_pre_auth_with_challenges(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        self.save_gateway_entries(&[
            (GATEWAY_PRE_AUTH_METRICS_KEY, serialize_snapshot_value(&state.pre_auth_metrics)?),
            (
                GATEWAY_PRE_AUTH_RATE_STATE_KEY,
                serialize_snapshot_value(&state.pre_auth_handshakes_by_source_ip)?,
            ),
            (GATEWAY_CHALLENGE_STATE_KEY, serialize_snapshot_value(&state.challenges_by_id)?),
        ])
    }

    /// # Errors
    /// Returns an error when the pre-auth metrics state cannot be serialized or persisted.
    pub fn save_pre_auth_metrics_only(&self, state: &GatewayState) -> Result<(), NodeCoreError> {
        self.save_gateway_entries(&[(
            GATEWAY_PRE_AUTH_METRICS_KEY,
            serialize_snapshot_value(&state.pre_auth_metrics)?,
        )])
    }

    fn save_gateway_entries(&self, entries: &[(&str, Vec<u8>)]) -> Result<(), NodeCoreError> {
        save_snapshot_batch(&self.db, GATEWAY_STATE_TABLE, entries)
    }

    /// # Errors
    /// Returns an error when the persisted gateway state cannot be read.
    pub fn load_state(&self) -> Result<Option<GatewayState>, NodeCoreError> {
        let Some(sessions_by_id) =
            load_snapshot(&self.db, GATEWAY_STATE_TABLE, GATEWAY_SESSION_CHECKPOINT_KEY)?
        else {
            return Ok(None);
        };
        Ok(Some(GatewayState {
            challenges_by_id: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_CHALLENGE_STATE_KEY,
            )?
            .unwrap_or_default(),
            sessions_by_id,
            frames_by_session: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_DELIVERY_FRAME_QUEUE_KEY,
            )?
            .unwrap_or_default(),
            pre_auth_policy: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_PRE_AUTH_POLICY_KEY,
            )?
            .unwrap_or_default(),
            pre_auth_metrics: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_PRE_AUTH_METRICS_KEY,
            )?
            .unwrap_or_default(),
            pre_auth_handshakes_by_source_ip: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_PRE_AUTH_RATE_STATE_KEY,
            )?
            .unwrap_or_default(),
            replay_guard_state: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_REPLAY_GUARD_STATE_KEY,
            )?
            .unwrap_or_default(),
            resume_token_index_by_hash: load_snapshot(
                &self.db,
                GATEWAY_STATE_TABLE,
                GATEWAY_RESUME_TOKEN_INDEX_KEY,
            )?
            .unwrap_or_default(),
        }))
    }
}
