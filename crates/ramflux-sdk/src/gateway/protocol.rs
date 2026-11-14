// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use std::sync::Arc;

const GATEWAY_SESSION_AUTH_TTL_SECONDS: i64 = 300;

/// Admit a candidate outer frame only after activation; live frames stay on the existing codecs.
///
/// # Errors
/// Profile or frame-cap refusals when the v1 generation is live.
#[expect(dead_code, reason = "S10a P06 dormant until P24")]
pub(crate) fn admit_candidate_outer_frame(
    frame: &[u8],
) -> Result<ramflux_protocol::message::outer::CandidateOuterEnvelope, SdkError> {
    if !ramflux_protocol::schema_profile::schema_v1_live() {
        return Err(SdkError::InboundRejected("candidate outer is dormant".into()));
    }
    ramflux_transport::decode_candidate_outer_frame(frame)
        .map_err(|error| SdkError::InboundRejected(error.to_string()))
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewaySessionTransportKind {
    Auto,
    #[serde(rename = "quic_quinn")]
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
    pub(crate) pairing_admission: Option<Arc<ramflux_storage::PairingAdmissionReader>>,
    pub(crate) custody_networking_pending: bool,
    pub(crate) custody: Option<super::GatewayCustodyConfig>,
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
    pub(crate) source_identity: Option<ramflux_crypto::RootQualifiedDeviceRef>,
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
    /// Deprecated and ignored by the gateway; retained for wire compatibility.
    /// Admission time comes from the server clock.
    pub pre_auth_now: Option<u64>,
    /// Deprecated and ignored by the gateway; retained for wire compatibility.
    /// Admission source comes from the observed transport peer.
    pub source_ip_hash: Option<String>,
    pub max_inflight_downstream: u32,
    pub max_inflight_upstream: u32,
    /// Desired routes, one per provider. Alert and `VoIP` are separate registrations.
    pub push_routes: BTreeMap<super::GatewayPushProvider, super::GatewayPushRouteRegistration>,
    /// Providers whose delete-one the node has not confirmed.
    pub push_route_clears: BTreeSet<super::GatewayPushProvider>,
    /// Delete-all is still unconfirmed. It is a barrier over every provider.
    pub push_route_clear_pending: bool,
    /// Backoff for the delete-all barrier.
    pub push_route_retry: super::PushRouteRetry,
    /// Per-provider backoff. A refusal on one provider does not delay another.
    pub push_route_retries: BTreeMap<super::GatewayPushProvider, super::PushRouteRetry>,
    /// Last push route control sequence (milliseconds, strictly increasing).
    pub push_route_last_seq: u64,
    /// Advertise the session-push capability in the signed scope. Production sets this
    /// from the receive-activation discriminator (Activated iff advertised). Test
    /// constructors may set it directly for negotiation unit tests without a DB.
    pub(crate) session_push_advertise: bool,
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
            custody_networking_pending: false,
            custody: None,
            pairing_admission: None,
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
            source_identity: None,
            target_delivery_id: parts.target_delivery_id,
            capability_scope: vec![
                "gateway.session".to_owned(),
                ramflux_protocol::GATEWAY_FORWARD_ACK_CAPABILITY.to_owned(),
                ramflux_protocol::CALL_RESOLUTION_CAPABILITY.to_owned(),
            ],
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
            push_routes: BTreeMap::new(),
            push_route_clears: BTreeSet::new(),
            push_route_clear_pending: false,
            push_route_retry: super::PushRouteRetry::default(),
            push_route_retries: BTreeMap::new(),
            push_route_last_seq: 0,
            session_push_advertise: false,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn with_session_push_advertise(mut self, advertise: bool) -> Self {
        self.session_push_advertise = advertise;
        self
    }

    pub(crate) fn refresh_auth_window(&mut self) {
        self.now = now_unix_timestamp();
        self.auth_expires_at = self.now.saturating_add(GATEWAY_SESSION_AUTH_TTL_SECONDS);
    }

    /// Configure gateway authentication from this account's owned root and device.
    /// # Errors
    /// Rejects missing or inconsistent account identity state.
    pub fn with_account_identity(
        mut self,
        client: &crate::RamfluxClient,
    ) -> Result<Self, crate::SdkError> {
        if let Some(account) = &client.born_v3_account {
            let custody = self.custody.as_ref().ok_or(crate::SdkError::NetworkingPending)?;
            if custody.account_id != account.local_account_id()
                || custody.account_root != client.account_index()?.root()
            {
                return Err(crate::SdkError::CustodySetupInvalid);
            }
            self.principal_id.clone_from(&account.record().body.principal_id);
            self.device_branch = None;
            self.source_identity = None;
            self.custody_networking_pending = false;
            self.pairing_admission =
                Some(Arc::new(client.account_db()?.pairing_admission_reader()));
            return Ok(self);
        }
        client.require_legacy_networking()?;
        self.with_owned_device(
            client.identity_root.as_ref().ok_or(crate::SdkError::IdentityRootMissing)?,
            client.device_branch.as_ref().ok_or(crate::SdkError::IdentityRootMissing)?.clone(),
        )
    }

    /// Select born-v3 authority without permitting any transport attempt or legacy proof.
    #[must_use]
    pub fn with_born_v3_account(mut self, account: &crate::custody::BornAccount) -> Self {
        self.custody_networking_pending = true;
        self.principal_id.clone_from(&account.record().body.principal_id);
        self.device_branch = None;
        self.source_identity = None;
        self
    }

    /// Authenticate this account through native v3 proof before entering the ordinary engine.
    #[must_use]
    pub fn with_native_custody(mut self, custody: super::GatewayCustodyConfig) -> Self {
        self.custody = Some(custody);
        self.custody_networking_pending = false;
        self.device_branch = None;
        self.source_identity = None;
        self
    }

    /// Bind gateway attribution to a device under the account's owned root.
    /// # Errors
    /// Rejects a root/branch mismatch or an invalid device name.
    pub fn with_owned_device(
        self,
        root: &ramflux_crypto::IdentityRoot,
        branch: ramflux_crypto::DeviceBranch,
    ) -> Result<Self, crate::SdkError> {
        if self.custody.is_some() {
            return Err(crate::SdkError::CustodyModeDowngrade);
        }
        if self.custody_networking_pending {
            return Err(crate::SdkError::NetworkingPending);
        }
        let source_identity =
            ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(root, &branch)?;
        let mut config = self.with_device_branch(branch);
        config.source_identity = Some(source_identity);
        Ok(config)
    }

    #[must_use]
    fn with_device_branch(mut self, branch: ramflux_crypto::DeviceBranch) -> Self {
        self.source_identity = None;
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
    /// Deprecated and ignored by the gateway; retained for wire compatibility.
    /// Admission time comes from the server clock.
    pub pre_auth_now: Option<u64>,
    /// Deprecated and ignored by the gateway; retained for wire compatibility.
    /// Admission source comes from the observed transport peer.
    pub source_ip_hash: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayAuthFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub device_proof: ramflux_protocol::DeviceProof,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
#[serde(from = "ramflux_protocol::CallSubmitCarrier")]
pub struct GatewaySubmitFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub envelope: ramflux_protocol::Envelope,
    /// Caller-signed call intent. Absent on every submit that is not a one-to-one call.
    /// Boxed so `GatewayClientFrame::Submit` stays within the enum size budget.
    pub call_intent: Option<Box<ramflux_protocol::SignedCallIntentV1>>,
    /// Wake id the authenticated device is resolving. The id alone is not authority.
    pub wake_id: Option<String>,
    /// Call reference bound into the encrypted control before it was signed.
    pub call_ref: Option<String>,
    /// `answer`, `reject`, or `end` from an authenticated participant.
    pub call_terminal: Option<String>,
    /// Correlation authenticated by the complete call submission body.
    pub call_context: Option<ramflux_protocol::CallSubmitContext>,
}

impl From<ramflux_protocol::CallSubmitCarrier> for GatewaySubmitFrame {
    fn from(value: ramflux_protocol::CallSubmitCarrier) -> Self {
        Self {
            signed_request: value.signed_request,
            envelope: value.envelope,
            call_intent: value.call_intent,
            wake_id: value.wake_id,
            call_ref: value.call_ref,
            call_terminal: value.call_terminal,
            call_context: value.call_context,
        }
    }
}
impl serde::Serialize for GatewaySubmitFrame {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(
            &ramflux_protocol::CallSubmitCarrierRef {
                signed_request: &self.signed_request,
                envelope: &self.envelope,
                call_intent: self.call_intent.as_deref(),
                wake_id: self.wake_id.as_deref(),
                call_ref: self.call_ref.as_deref(),
                call_terminal: self.call_terminal.as_deref(),
                call_context: self.call_context.as_ref(),
            },
            serializer,
        )
    }
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
    /// Present only when the call-resolution capability was negotiated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_session_generation: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayForwardAck {
    pub envelope_id: String,
    pub target_delivery_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_seq: Option<u64>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum GatewayClientFrame {
    PushRouteRegister { request: Box<super::GatewayPushRouteFrame> },
    PushRouteDeregister { request: Box<super::GatewayPushRouteDeregistrationFrame> },
    VoiceLease { request: Box<ramflux_protocol::VoiceLeaseFrame> },
    Open { open: GatewayOpenFrame },
    Auth { auth: GatewayAuthFrame },
    Submit { submit: GatewaySubmitFrame },
    OwnDeviceFanout { fanout: GatewayOwnDeviceFanoutFrame },
    IdentityRegister { request: SdkIdentityRegisterRequest },
    PrekeyPublish { request: SdkPrekeyPublishRequest },
    PrekeyFetch { device_id: String },
    PrincipalManifestFetch { principal_id: String },
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
    PushRouteRegistered {
        expires_at: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    PushRouteRefused {
        request_id: String,
        reason: String,
        #[serde(default)]
        code: super::GatewayPushRouteRefusal,
    },
    PushRouteDeregistered {
        request_id: String,
        removed: u64,
    },
    VoiceLease {
        response: Box<ramflux_protocol::VoiceLeaseResponse>,
    },
    SessionEstablished {
        session: GatewaySessionEstablishedFrame,
    },
    Deliver {
        entry: GatewayInboxEntry,
    },
    ForwardAck {
        ack: GatewayForwardAck,
    },
    OwnDeviceFanout {
        response: GatewayOwnDeviceFanoutResponse,
    },
    IdentityRegistered {
        response: SdkIdentityRegistrationResponse,
    },
    PrincipalManifest {
        response: ramflux_protocol::PrincipalLookupResponse<serde_json::Value>,
    },
    IdentityRegistrationRejected {
        reason_code: ramflux_protocol::IdentityDirectoryReason,
    },
    PrekeyPublished {
        response: SdkPrekeyResponse,
    },
    Prekey {
        response: SdkPrekeyResponse,
    },
    RelayTokenIssued {
        response: GatewayRelayTokenIssueResponse,
    },
    RelayTokenV3Issued {
        response: Box<GatewayRelayTokenV3IssueResponse>,
    },
    Ack {
        cursor: GatewayCursor,
    },
    Cursor {
        cursor: Option<GatewayCursor>,
    },
    Resume {
        entries: Vec<GatewayInboxEntry>,
    },
    Nack {
        reason: String,
    },
    Heartbeat {
        now: u64,
    },
    Drain {
        session_id: String,
        reason: String,
    },
    InBandWake {
        target_delivery_id: String,
        delivery_class: ramflux_protocol::DeliveryClass,
    },
    Ephemeral {
        envelope: ramflux_protocol::Envelope,
        expires_at_ms: u64,
    },
    EphemeralResult {
        envelope_id: String,
        /// Outcome and reason, coupled when the received bytes are decoded.
        #[serde(flatten)]
        result: ramflux_protocol::ephemeral::EphemeralSubmitResult,
    },
    Close {
        reason: String,
    },
    /// Authenticated call resolution. The wake may be finished while media stays open.
    CallResolved {
        context: ramflux_protocol::CallSubmitContext,
        state: ramflux_protocol::CallResolutionState,
        media_allowed: bool,
        wake_resolved: bool,
    },
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayInboxEntry {
    /// True when the old home accepted this submit by forwarding it to the new home.
    #[serde(default, skip_serializing_if = "is_false")]
    pub forwarded: bool,
    pub inbox_seq: u64,
    pub target_delivery_id: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
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
    pub call_session_generation: Option<String>,
    pub session_id: String,
    pub gateway_id: String,
    pub resume_token: String,
    pub resume_window_seconds: u64,
    pub accepted_inbox_seq: u64,
}

#[cfg(test)]
#[path = "protocol_ephemeral_tests.rs"]
mod ephemeral_result_tests;
