// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    GatewayRelayTokenV3IssueRequest, GatewayRelayTokenV3IssueResponse, IdentityRegisterRequest,
    IdentityRegistrationResponse, InboxCursorResponse, InboxEntry,
    ItestMvp10OwnDeviceFanoutResponse, PrekeyPublishRequest, PrekeyResponse,
    RelayTokenIssueRequest, RelayTokenIssueResponse,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreAuthChallenge {
    pub challenge_id: String,
    pub source_ip_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub used: bool,
}

pub const PRE_AUTH_PROTOCOL_VERSION: &str = "ramflux.itest.http.v1";
pub const DEFAULT_PRE_AUTH_COOKIE_SECRET: &str = "ramflux-itest-pre-auth-cookie-secret-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayPreAuthPolicy {
    pub enabled: bool,
    pub per_source_ip_handshake_rate: u32,
    pub window_seconds: u64,
    pub cookie_ttl_seconds: u64,
    pub auth_deadline_ms: u64,
    pub cookie_secret: String,
}

impl Default for GatewayPreAuthPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            per_source_ip_handshake_rate: u32::MAX,
            window_seconds: 60,
            cookie_ttl_seconds: 60,
            auth_deadline_ms: 5_000,
            cookie_secret: DEFAULT_PRE_AUTH_COOKIE_SECRET.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayPreAuthMetrics {
    pub pre_auth_cookie_required: u64,
    pub pre_auth_cookie_failed: u64,
    pub deviceproof_rate_limited: u64,
    pub slowloris_auth_timeout: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayPreAuthChallengeResponse {
    pub challenge: String,
    pub pre_auth_cookie: String,
    pub retry_after_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayPreAuthDecision {
    Accepted,
    Challenge(GatewayPreAuthChallengeResponse),
}

pub const GATEWAY_SESSION_PROTOCOL_VERSION: &str = "ramflux.gateway_session.v1";
pub const GATEWAY_OPEN_HASH_DOMAIN: &str = "ramflux.gateway.open.v1";
pub const GATEWAY_DEVICE_PROOF_HASH_DOMAIN: &str = "ramflux.gateway.device_proof.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayOpenFrame {
    pub protocol_version: String,
    pub transport_kind: String,
    pub client_instance_id: String,
    pub device_id: String,
    pub target_delivery_id: String,
    pub stream_nonce: String,
    pub previous_session_id: Option<String>,
    pub resume_token_hash: Option<String>,
    pub last_seen_inbox_seq: Option<u64>,
    pub max_inflight_downstream: u32,
    pub max_inflight_upstream: u32,
    pub pre_auth_cookie: Option<String>,
    pub pre_auth_now: Option<u64>,
    pub source_ip_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayAuthFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub device_proof: ramflux_protocol::DeviceProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewaySubmitFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayOwnDeviceFanoutFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub principal_id: String,
    pub source_device_id: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayOwnDeviceFanoutDelivery {
    pub device_id: String,
    pub target_delivery_id: String,
    pub outcome: String,
    pub inbox_seq: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayOwnDeviceFanoutResponse {
    pub principal_id: String,
    pub source_device_id: String,
    pub delivered: Vec<GatewayOwnDeviceFanoutDelivery>,
}

impl From<ItestMvp10OwnDeviceFanoutResponse> for GatewayOwnDeviceFanoutResponse {
    fn from(response: ItestMvp10OwnDeviceFanoutResponse) -> Self {
        Self {
            principal_id: response.principal_id,
            source_device_id: response.source_device_id,
            delivered: response
                .delivered
                .into_iter()
                .map(|delivery| GatewayOwnDeviceFanoutDelivery {
                    device_id: delivery.device_id,
                    target_delivery_id: delivery.target_delivery_id,
                    outcome: delivery.outcome,
                    inbox_seq: delivery.inbox_seq,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayResumeFrame {
    pub target_delivery_id: String,
    pub after_inbox_seq: u64,
    pub limit: usize,
    pub resume_token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewaySessionEstablishedFrame {
    pub session_id: String,
    pub gateway_id: String,
    pub accepted_cursor: Option<InboxCursorResponse>,
    pub resume_token: String,
    pub resume_window_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum GatewayClientFrame {
    Open { open: GatewayOpenFrame },
    Auth { auth: GatewayAuthFrame },
    Submit { submit: GatewaySubmitFrame },
    OwnDeviceFanout { fanout: GatewayOwnDeviceFanoutFrame },
    IdentityRegister { request: IdentityRegisterRequest },
    PrekeyPublish { request: PrekeyPublishRequest },
    PrekeyFetch { device_id: String },
    RelayTokenIssue { request: RelayTokenIssueRequest },
    RelayTokenV3Issue { request: Box<GatewayRelayTokenV3IssueRequest> },
    Ack { ack: ramflux_protocol::Ack },
    Cursor { target_delivery_id: String },
    Resume { resume: GatewayResumeFrame },
    Nack { nack: ramflux_protocol::Nack },
    Heartbeat { now: u64 },
    Close { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum GatewayServerFrame {
    SessionEstablished { session: GatewaySessionEstablishedFrame },
    Deliver { entry: InboxEntry },
    OwnDeviceFanout { response: GatewayOwnDeviceFanoutResponse },
    IdentityRegistered { response: IdentityRegistrationResponse },
    PrekeyPublished { response: PrekeyResponse },
    Prekey { response: PrekeyResponse },
    RelayTokenIssued { response: RelayTokenIssueResponse },
    RelayTokenV3Issued { response: Box<GatewayRelayTokenV3IssueResponse> },
    Ack { cursor: InboxCursorResponse },
    Cursor { cursor: Option<InboxCursorResponse> },
    Resume { entries: Vec<InboxEntry> },
    Nack { reason: String },
    Heartbeat { now: u64 },
    Drain { session_id: String, reason: String },
    InBandWake { target_delivery_id: String, delivery_class: ramflux_protocol::DeliveryClass },
    Close { reason: String },
}
