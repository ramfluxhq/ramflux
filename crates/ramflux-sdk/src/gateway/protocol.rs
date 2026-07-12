// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

const GATEWAY_SESSION_AUTH_TTL_SECONDS: i64 = 300;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GatewayQuicEndpointConfig {
    pub bind_addr: SocketAddr,
    pub gateway_addr: SocketAddr,
    pub server_name: String,
    pub ca_cert: PathBuf,
    pub principal_id: String,
    pub device_id: String,
    pub target_delivery_id: String,
    pub prekey_http_url: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GatewayTcpTlsEndpointConfig {
    pub bind_addr: SocketAddr,
    pub gateway_addr: SocketAddr,
    pub server_name: String,
    pub ca_cert: PathBuf,
    pub principal_id: String,
    pub device_id: String,
    pub target_delivery_id: String,
    pub prekey_http_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewaySessionTransportKind {
    Auto,
    Quic,
    TcpTls,
}

struct GatewaySessionConfigParts {
    transport_kind: GatewaySessionTransportKind,
    bind_addr: SocketAddr,
    gateway_addr: SocketAddr,
    tcp_gateway_addr: Option<SocketAddr>,
    server_name: String,
    ca_cert: PathBuf,
    principal_id: String,
    device_id: String,
    target_delivery_id: String,
    prekey_http_url: Option<String>,
}

impl GatewaySessionTransportKind {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic_quinn",
            Self::TcpTls => "tcp_tls",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GatewaySessionConfig {
    pub transport_kind: GatewaySessionTransportKind,
    pub bind_addr: SocketAddr,
    pub gateway_addr: SocketAddr,
    pub tcp_gateway_addr: Option<SocketAddr>,
    pub server_name: String,
    pub ca_cert: PathBuf,
    pub client_instance_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub prekey_http_url: Option<String>,
    pub device_epoch: u64,
    pub branch_proof_hash: String,
    pub device_branch: Option<std::sync::Arc<ramflux_crypto::DeviceBranch>>,
    pub target_delivery_id: String,
    pub capability_scope: Vec<String>,
    pub auth_expires_at: i64,
    pub now: i64,
    pub timeout: Duration,
    pub quic_fallback_timeout: Duration,
    pub previous_session_id: Option<String>,
    pub resume_token: Option<String>,
    pub last_seen_inbox_seq: u64,
    pub pre_auth_cookie: Option<String>,
    pub pre_auth_now: Option<u64>,
    pub source_ip_hash: Option<String>,
    pub max_inflight_downstream: u32,
    pub max_inflight_upstream: u32,
}

impl GatewaySessionConfig {
    #[must_use]
    pub fn quic(endpoint: GatewayQuicEndpointConfig) -> Self {
        Self::from_parts(GatewaySessionConfigParts {
            transport_kind: GatewaySessionTransportKind::Quic,
            bind_addr: endpoint.bind_addr,
            gateway_addr: endpoint.gateway_addr,
            tcp_gateway_addr: None,
            server_name: endpoint.server_name,
            ca_cert: endpoint.ca_cert,
            principal_id: endpoint.principal_id,
            device_id: endpoint.device_id,
            target_delivery_id: endpoint.target_delivery_id,
            prekey_http_url: endpoint.prekey_http_url,
        })
    }

    #[must_use]
    pub fn auto(endpoint: GatewayQuicEndpointConfig) -> Self {
        let tcp_gateway_addr = endpoint.gateway_addr;
        Self::from_parts(GatewaySessionConfigParts {
            transport_kind: GatewaySessionTransportKind::Auto,
            bind_addr: endpoint.bind_addr,
            gateway_addr: endpoint.gateway_addr,
            tcp_gateway_addr: Some(tcp_gateway_addr),
            server_name: endpoint.server_name,
            ca_cert: endpoint.ca_cert,
            principal_id: endpoint.principal_id,
            device_id: endpoint.device_id,
            target_delivery_id: endpoint.target_delivery_id,
            prekey_http_url: endpoint.prekey_http_url,
        })
    }

    #[must_use]
    pub fn tcp_tls(endpoint: GatewayTcpTlsEndpointConfig) -> Self {
        Self::from_parts(GatewaySessionConfigParts {
            transport_kind: GatewaySessionTransportKind::TcpTls,
            bind_addr: endpoint.bind_addr,
            gateway_addr: endpoint.gateway_addr,
            tcp_gateway_addr: Some(endpoint.gateway_addr),
            server_name: endpoint.server_name,
            ca_cert: endpoint.ca_cert,
            principal_id: endpoint.principal_id,
            device_id: endpoint.device_id,
            target_delivery_id: endpoint.target_delivery_id,
            prekey_http_url: endpoint.prekey_http_url,
        })
    }

    #[must_use]
    pub const fn with_tcp_gateway_addr(mut self, gateway_addr: SocketAddr) -> Self {
        self.tcp_gateway_addr = Some(gateway_addr);
        self
    }

    #[must_use]
    pub const fn with_quic_fallback_timeout(mut self, timeout: Duration) -> Self {
        self.quic_fallback_timeout = timeout;
        self
    }

    fn from_parts(parts: GatewaySessionConfigParts) -> Self {
        let now = now_unix_timestamp();
        Self {
            transport_kind: parts.transport_kind,
            bind_addr: parts.bind_addr,
            gateway_addr: parts.gateway_addr,
            tcp_gateway_addr: parts.tcp_gateway_addr,
            server_name: parts.server_name,
            ca_cert: parts.ca_cert,
            client_instance_id: format!("rf_sdk_{}", parts.device_id),
            principal_id: parts.principal_id,
            device_id: parts.device_id,
            prekey_http_url: parts.prekey_http_url,
            device_epoch: 1,
            branch_proof_hash: "sdk_branch_proof_hash".to_owned(),
            device_branch: None,
            target_delivery_id: parts.target_delivery_id,
            capability_scope: vec!["gateway.session".to_owned()],
            auth_expires_at: now.saturating_add(GATEWAY_SESSION_AUTH_TTL_SECONDS),
            now,
            timeout: Duration::from_secs(10),
            quic_fallback_timeout: Duration::from_millis(1_500),
            previous_session_id: None,
            resume_token: None,
            last_seen_inbox_seq: 0,
            pre_auth_cookie: None,
            pre_auth_now: None,
            source_ip_hash: None,
            max_inflight_downstream: 64,
            max_inflight_upstream: 64,
        }
    }

    pub(crate) fn refresh_auth_window(&mut self) {
        self.now = now_unix_timestamp();
        self.auth_expires_at = self.now.saturating_add(GATEWAY_SESSION_AUTH_TTL_SECONDS);
    }

    #[must_use]
    pub fn with_device_branch(mut self, branch: ramflux_crypto::DeviceBranch) -> Self {
        self.principal_id.clone_from(&branch.principal_id);
        self.device_id.clone_from(&branch.device_id);
        self.device_epoch = branch.device_epoch;
        self.device_branch = Some(std::sync::Arc::new(branch));
        self
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
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

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayAuthFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub device_proof: ramflux_protocol::DeviceProof,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewaySubmitFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayOwnDeviceFanoutFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub principal_id: String,
    pub source_device_id: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayOwnDeviceFanoutDelivery {
    pub device_id: String,
    pub target_delivery_id: String,
    pub outcome: String,
    pub inbox_seq: Option<u64>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayOwnDeviceFanoutResponse {
    pub principal_id: String,
    pub source_device_id: String,
    pub delivered: Vec<GatewayOwnDeviceFanoutDelivery>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayResumeFrame {
    pub target_delivery_id: String,
    pub after_inbox_seq: u64,
    pub limit: usize,
    pub resume_token: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayRelayTokenIssueBody {
    pub(crate) object_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) chunk_id: String,
    pub(crate) recipient_device_hash: String,
    pub(crate) owner_signing_key_id: String,
    pub(crate) owner_public_key: String,
    pub(crate) capability: SdkObjectRelayCapability,
    pub(crate) delete_after_ack: bool,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) object_permission_envelope: SdkObjectPermissionEnvelope,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayRelayTokenIssueRequest {
    pub(crate) signed_request: ramflux_protocol::SignedRequest,
    pub(crate) body: GatewayRelayTokenIssueBody,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayRelayTokenIssueResponse {
    pub(crate) relay_token: SdkRelayToken,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayRelayTokenV3IssueRequest {
    pub(crate) signed_request: ramflux_protocol::SignedRequest,
    pub(crate) body: SdkRelayTokenV3IssueBody,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct SdkRelayTokenV3IssueBody {
    pub(crate) requester_device_id: String,
    pub(crate) requester_device_hash: String,
    pub(crate) requester_public_key: String,
    pub(crate) requester_device_epoch: u64,
    pub(crate) owner_signing_key_id: String,
    pub(crate) owner_public_key: String,
    pub(crate) owner_home_node_id: String,
    pub(crate) owner_principal_id: String,
    pub(crate) owner_device_epoch: u64,
    pub(crate) issuer_node_id: String,
    pub(crate) gateway_instance_id: String,
    pub(crate) audience_node_id: String,
    pub(crate) relay_instance_id: Option<String>,
    pub(crate) object_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) chunk_id: String,
    pub(crate) capabilities: Vec<ramflux_protocol::ObjectRelayCapability>,
    pub(crate) authorization_kind: ramflux_protocol::RelayAuthorizationKind,
    pub(crate) authorization_binding_hash: String,
    pub(crate) delete_after_ack: bool,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) nonce: String,
    pub(crate) issuer_certificate: ramflux_protocol::GatewayIssuerCertificate,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayRelayTokenV3IssueResponse {
    pub(crate) relay_token: ramflux_protocol::RelayTokenV3,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewaySessionEstablishedFrame {
    pub session_id: String,
    pub gateway_id: String,
    pub accepted_cursor: Option<GatewayCursor>,
    pub resume_token: String,
    pub resume_window_seconds: u64,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum GatewayClientFrame {
    Open { open: GatewayOpenFrame },
    Auth { auth: GatewayAuthFrame },
    Submit { submit: GatewaySubmitFrame },
    OwnDeviceFanout { fanout: GatewayOwnDeviceFanoutFrame },
    IdentityRegister { request: SdkIdentityRegisterRequest },
    PrekeyPublish { request: SdkPrekeyPublishRequest },
    PrekeyFetch { device_id: String },
    RelayTokenIssue { request: GatewayRelayTokenIssueRequest },
    RelayTokenV3Issue { request: Box<GatewayRelayTokenV3IssueRequest> },
    Ack { ack: ramflux_protocol::Ack },
    Cursor { target_delivery_id: String },
    Resume { resume: GatewayResumeFrame },
    Nack { nack: ramflux_protocol::Nack },
    Heartbeat { now: u64 },
    Close { reason: String },
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum GatewayServerFrame {
    SessionEstablished { session: GatewaySessionEstablishedFrame },
    Deliver { entry: GatewayInboxEntry },
    OwnDeviceFanout { response: GatewayOwnDeviceFanoutResponse },
    IdentityRegistered { response: SdkIdentityRegistrationResponse },
    PrekeyPublished { response: SdkPrekeyResponse },
    Prekey { response: SdkPrekeyResponse },
    RelayTokenIssued { response: GatewayRelayTokenIssueResponse },
    RelayTokenV3Issued { response: Box<GatewayRelayTokenV3IssueResponse> },
    Ack { cursor: GatewayCursor },
    Cursor { cursor: Option<GatewayCursor> },
    Resume { entries: Vec<GatewayInboxEntry> },
    Nack { reason: String },
    Heartbeat { now: u64 },
    Drain { session_id: String, reason: String },
    InBandWake { target_delivery_id: String, delivery_class: ramflux_protocol::DeliveryClass },
    Close { reason: String },
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayInboxEntry {
    pub inbox_seq: u64,
    pub target_delivery_id: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayCursor {
    pub target_delivery_id: String,
    pub inbox_seq: u64,
    pub last_envelope_id: Option<String>,
    pub acked_envelope_ids: Vec<String>,
    pub nacked_envelope_ids: std::collections::BTreeMap<String, ramflux_protocol::NackReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySessionState {
    pub session_id: String,
    pub gateway_id: String,
    pub resume_token: String,
    pub resume_window_seconds: u64,
    pub accepted_inbox_seq: u64,
}
