// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::GatewaySessionTransportKind;
use crate::prelude::*;

pub struct GatewaySessionEngine {
    pub(crate) config: GatewaySessionConfig,
    _transport: GatewaySessionClientTransport,
    pub(crate) stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    pub(crate) session: GatewaySessionState,
    request_counter: u64,
    pub(crate) pending_deliveries: VecDeque<PendingDelivery>,
    pub(crate) buffered_bytes: usize,
    pub(crate) deferred_frames: VecDeque<GatewayServerFrame>,
    #[cfg(test)]
    pub(crate) buffer_stats: super::host_frames::BufferStats,
    pub(crate) last_frame_bytes: usize,
    pub(crate) frame_timeout: Duration,
    pub(crate) wire_writes: u64,
    pub(crate) terminal_reason: Option<crate::bus::connection_manager::DisconnectReason>,
    pub(crate) host: Option<super::host_frames::HostFrames>,
    pub(crate) push_route_expires_at: Option<u64>,
    pub(crate) pending_push_route: Option<super::push_route::PendingPushRoute>,
    /// Negotiated at establishment; read by the capable operations of later parts.
    #[allow(dead_code)]
    pub(crate) mode: super::session_push::SessionMode,
}

/// One buffered delivery. `push` is set only for a negotiated-session deliver.
pub(crate) struct PendingDelivery {
    pub(crate) entry: GatewayInboxEntry,
    #[allow(dead_code)]
    pub(crate) push: Option<super::session_push::PushMeta>,
    #[allow(dead_code)]
    pub(crate) bytes: usize,
}

pub(crate) enum GatewaySessionClientTransport {
    #[cfg(test)]
    Injected,
    Quic {
        _client: ramflux_transport::QuicGatewayClient,
    },
    TcpTls {
        _client: ramflux_transport::TcpTlsGatewayClient,
    },
}

#[derive(Clone, Debug)]
pub struct GatewayDirectMessage {
    pub conversation_id: String,
    pub message_id: String,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub sender_id: String,
    pub recipient_device_id: Option<String>,
    /// The expected root is required whenever SDK-owned encryption admits a recipient key.
    pub recipient_principal_commitment: Option<String>,
    pub target_delivery_id: String,
    pub encrypted_body: Vec<u8>,
    pub created_at: i64,
    pub ttl: u32,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GatewayPlaintextDelivery {
    pub entry: GatewayInboxEntry,
    pub conversation_id: String,
    pub message_id: String,
    pub sender_id: String,
    pub plaintext_body_base64: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<SdkDmAttachmentImportResult>,
}

#[cfg(test)]
tokio::task_local! {
    pub(crate) static TEST_CONNECT_LIMITS: crate::bus::runtime_limits::RuntimeTimeouts;
    pub(crate) static TEST_CONNECT_OPENER: std::sync::Arc<dyn super::transport_opener::TransportOpener>;
}

pub(crate) async fn gateway_session_timeout<T, F>(
    operation: &'static str,
    future: F,
) -> Result<T, SdkError>
where
    F: Future<Output = Result<T, SdkError>>,
{
    frame_timeout(GATEWAY_SESSION_NETWORK_TIMEOUT, operation, future).await
}

pub(crate) async fn frame_timeout<T>(
    duration: Duration,
    operation: &'static str,
    future: impl Future<Output = Result<T, SdkError>>,
) -> Result<T, SdkError> {
    match tokio::time::timeout(duration, future).await {
        Ok(result) => result,
        Err(_elapsed) => Err(SdkError::GatewaySessionRejected(format!(
            "{operation} timed out after {}s",
            duration.as_secs()
        ))),
    }
}

pub(crate) async fn connect_deadline<T>(
    deadline: Option<tokio::time::Instant>,
    future: impl Future<Output = Result<T, SdkError>>,
) -> Result<T, SdkError> {
    if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline, future).await.map_err(|_| SdkError::NodeTimeout {
            retry_after_ms: crate::node::NODE_RETRY_AFTER_MS,
        })?
    } else {
        gateway_session_timeout("gateway session connect", future).await
    }
}

/// GW-TOKEN-01-A2: build one freshly-stamped, signed gateway request.
///
/// `created_at`/`expires_at` are copied from `config.{now,auth_expires_at}`, which were otherwise set
/// exactly once at the single `connect_inner` `refresh_auth_window()` call and then frozen for the life
/// of a persistent engine. A sustained large-object upload (256 serial per-chunk token issues per
/// 16 MiB object) kept re-signing requests with that frozen `connect + 300s` deadline; once the run
/// outlived it, the gateway rejected every further token issue as `signed request expired`. Refreshing
/// the window HERE — on every gateway request — keeps each freshly-signed request inside its own 300s
/// window. It does NOT change the wire/schema, the `request_id`/`nonce` per-request uniqueness (both
/// still vary by `request_counter`), or the gateway's absolute expiry + replay checks. Kept a free
/// `pub(crate)` fn so those invariants are unit-testable without a live transport.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_gateway_signed_request(
    config: &mut GatewaySessionConfig,
    session_id: &str,
    request_counter: u64,
    method: ramflux_protocol::HttpMethod,
    path: &str,
    device_proof_hash: &str,
    body_bytes: &[u8],
) -> Result<ramflux_protocol::SignedRequest, SdkError> {
    config.refresh_auth_window();
    let device_branch = config.device_branch.as_ref().ok_or_else(|| {
        SdkError::GatewaySessionRejected(format!(
            "missing registered device branch for {}",
            config.device_id
        ))
    })?;
    let mut request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_device_signed_fields(&config.device_id, ""),
        source_device_id: config.device_id.clone(),
        request_id: format!("req_sdk_{session_id}_{request_counter}"),
        method,
        path: path.to_owned(),
        device_proof_hash: device_proof_hash.to_owned(),
        body_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            body_bytes,
        ),
        nonce: gateway_stream_nonce(config, request_counter),
        created_at: config.now,
        expires_at: config.auth_expires_at,
    };
    request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(device_branch.as_ref(), &request)?;
    Ok(request)
}

impl GatewaySessionEngine {
    /// # Errors
    /// Returns an error when the QUIC session cannot connect, authenticate, or receive
    /// `session_established`.
    pub async fn connect(config: GatewaySessionConfig) -> Result<Self, SdkError> {
        if config.custody_networking_pending {
            return Err(SdkError::NetworkingPending);
        }
        let deadline = config
            .custody
            .as_ref()
            .map(|_| tokio::time::Instant::now() + crate::bus::runtime_limits::ATTEMPT_TIMEOUT);
        Self::connect_at(config, deadline).await
    }

    pub(crate) async fn connect_at(
        config: GatewaySessionConfig,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Self, SdkError> {
        #[cfg(test)]
        let limits = TEST_CONNECT_LIMITS.try_with(Clone::clone).unwrap_or_default();
        #[cfg(not(test))]
        let limits = crate::bus::runtime_limits::RuntimeTimeouts::default();
        let opener: std::sync::Arc<dyn super::transport_opener::TransportOpener> =
            std::sync::Arc::new(super::transport_opener::ConfiguredTransport);
        #[cfg(test)]
        let opener = TEST_CONNECT_OPENER.try_with(Clone::clone).unwrap_or(opener);
        Self::connect_with_opener(config, deadline, limits, opener).await
    }

    pub(crate) async fn connect_with_opener(
        config: GatewaySessionConfig,
        deadline: Option<tokio::time::Instant>,
        limits: crate::bus::runtime_limits::RuntimeTimeouts,
        opener: std::sync::Arc<dyn super::transport_opener::TransportOpener>,
    ) -> Result<Self, SdkError> {
        if config.custody_networking_pending {
            return Err(SdkError::NetworkingPending);
        }
        let deadline = deadline.or_else(|| {
            config
                .custody
                .as_ref()
                .map(|_| tokio::time::Instant::now() + crate::bus::runtime_limits::ATTEMPT_TIMEOUT)
        });
        let connect = Self::connect_inner(config, &limits, opener);
        #[cfg(test)]
        let connect = crate::custody::retry::TEST_RETRY_BUDGET.scope(limits.retry_budget, connect);
        let mut engine = connect_deadline(deadline, Box::pin(connect)).await?;
        engine.refresh_push_route_if_due().await;
        Ok(engine)
    }

    async fn connect_inner(
        mut config: GatewaySessionConfig,
        limits: &crate::bus::runtime_limits::RuntimeTimeouts,
        opener: std::sync::Arc<dyn super::transport_opener::TransportOpener>,
    ) -> Result<Self, SdkError> {
        config.refresh_auth_window();
        let (transport, mut stream, active_transport_kind) =
            if let Some(custody) = super::custody::prepare(&config).await? {
                let endpoint = config.clone();
                let ((transport, kind), stream) = Box::pin(super::custody::authenticate(
                    custody,
                    || async {
                        let (transport, stream, kind) =
                            opener.open(endpoint.clone(), limits.transport_open).await?;
                        Ok(((transport, kind), stream))
                    },
                    &mut config,
                ))
                .await?;
                (transport, stream, kind)
            } else {
                opener.open(config.clone(), limits.transport_open).await?
            };
        config.transport_kind = active_transport_kind;
        config.refresh_auth_window();
        let open = gateway_fresh_open_frame(&config)?;
        write_gateway_client_frame(&mut *stream, &GatewayClientFrame::Open { open: open.clone() })
            .await?;
        let auth = gateway_auth_frame(&config, &open)?;
        write_gateway_client_frame(&mut *stream, &GatewayClientFrame::Auth { auth }).await?;
        let (established, established_bytes) =
            frame_timeout(limits.frame, "gateway session established", async {
                read_gateway_server_frame_bytes(&mut *stream).await
            })
            .await?;
        let (session, mode) = match established {
            GatewayServerFrame::SessionEstablished { session } => {
                let echo = super::session_push::EstablishmentEcho::from_bytes(&established_bytes)?;
                let mode = super::session_push::negotiate(config.session_push_advertise, &echo)?;
                (gateway_session_state(&session, config.last_seen_inbox_seq), mode)
            }
            GatewayServerFrame::Nack { reason } => {
                return Err(SdkError::GatewaySessionRejected(reason));
            }
            other => {
                return Err(SdkError::GatewaySessionRejected(format!(
                    "unexpected frame {other:?}"
                )));
            }
        };
        let mut engine = Self {
            config,
            _transport: transport,
            stream,
            session,
            request_counter: 1,
            pending_deliveries: VecDeque::new(),
            buffered_bytes: 0,
            deferred_frames: VecDeque::new(),
            #[cfg(test)]
            buffer_stats: super::host_frames::BufferStats::default(),
            last_frame_bytes: 0,
            frame_timeout: limits.frame,
            wire_writes: 0,
            terminal_reason: None,
            host: None,
            push_route_expires_at: None,
            pending_push_route: None,
            mode,
        };
        engine.remember_session_for_resume();
        Ok(engine)
    }

    #[cfg(test)]
    pub(crate) fn with_test_transport(
        config: GatewaySessionConfig,
        stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    ) -> Self {
        Self {
            config,
            stream,
            _transport: GatewaySessionClientTransport::Injected,
            session: GatewaySessionState {
                session_id: "test-session".to_owned(),
                gateway_id: "test-gateway".to_owned(),
                resume_token: "test-resume".to_owned(),
                resume_window_seconds: 60,
                accepted_inbox_seq: 0,
            },
            request_counter: 0,
            pending_deliveries: VecDeque::new(),
            buffered_bytes: 0,
            deferred_frames: VecDeque::new(),
            #[cfg(test)]
            buffer_stats: super::host_frames::BufferStats::default(),
            last_frame_bytes: 0,
            frame_timeout: crate::constants::GATEWAY_SESSION_NETWORK_TIMEOUT,
            wire_writes: 0,
            terminal_reason: None,
            host: None,
            push_route_expires_at: None,
            pending_push_route: None,
            mode: super::session_push::SessionMode::Legacy,
        }
    }

    #[must_use]
    pub fn config(&self) -> &GatewaySessionConfig {
        &self.config
    }

    #[must_use]
    pub fn session(&self) -> &GatewaySessionState {
        &self.session
    }

    #[must_use]
    pub fn target_delivery_id(&self) -> &str {
        &self.config.target_delivery_id
    }

    #[must_use]
    pub const fn active_transport_kind(&self) -> GatewaySessionTransportKind {
        self.config.transport_kind
    }

    /// # Errors
    /// Returns an error when the session cannot be reconnected and authenticated.
    pub async fn reconnect(&mut self, last_seen_inbox_seq: u64) -> Result<(), SdkError> {
        self.config.last_seen_inbox_seq = last_seen_inbox_seq;
        let mut replacement = Self::connect(self.config.clone()).await?;
        std::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// # Errors
    /// Returns an error when the session cannot be probed or reconnected.
    pub async fn ensure_live(&mut self, last_seen_inbox_seq: u64) -> Result<(), SdkError> {
        match tokio::time::timeout(Duration::from_secs(5), self.heartbeat()).await {
            Ok(Ok(())) => {
                self.refresh_push_route_if_due().await;
                Ok(())
            }
            Ok(Err(_)) | Err(_) => self.reconnect(last_seen_inbox_seq).await,
        }
    }

    /// # Errors
    /// Returns an error when the heartbeat cannot be written or acknowledged.
    pub async fn heartbeat(&mut self) -> Result<(), SdkError> {
        self.write_frame(&GatewayClientFrame::Heartbeat { now: gateway_heartbeat_now() }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Heartbeat).await? {
            GatewayServerFrame::Heartbeat { .. } => Ok(()),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected heartbeat frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects or cannot deliver the envelope.
    pub async fn submit_envelope(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<GatewayInboxEntry, SdkError> {
        match self.submit_envelope_classified(envelope).await? {
            Ok(entry) => Ok(entry),
            Err(refusal) => Err(SdkError::GatewaySessionRejected(refusal.reason().to_owned())),
        }
    }

    /// Submits an envelope and separates a gateway refusal that is certain to be a refusal
    /// from every other failure.
    ///
    /// The inner `Err` is produced only from a decoded legacy `nack` whose `reason` is exactly
    /// one of the three outcome strings the gateway sends. Every other failure (transport,
    /// frame timeout, call deadline, failed write, any other reason) stays in the outer `Err`
    /// and is uncertain after the write.
    ///
    /// # Errors
    /// Returns an error when the envelope cannot be written or the reply is not a submit reply.
    pub(crate) async fn submit_envelope_classified(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<Result<GatewayInboxEntry, super::session_push::SubmitRefusal>, SdkError> {
        let submit = GatewaySubmitFrame {
            signed_request: self.signed_request(
                "POST",
                "/gateway/session/submit",
                "already_authed",
                &envelope,
            )?,
            envelope,
        };
        let expected_envelope_id = submit.envelope.envelope_id.clone();
        let expected_target_delivery_id = submit.envelope.target_delivery_id.clone();
        let submitted_envelope = submit.envelope.clone();
        self.write_frame(&GatewayClientFrame::Submit { submit }).await?;
        if matches!(self.mode, super::session_push::SessionMode::Push { .. }) {
            return self.read_push_submit_reply(submitted_envelope).await;
        }
        loop {
            match self.read_submit_reply(&expected_envelope_id).await? {
                GatewayServerFrame::Deliver { entry }
                    if entry.envelope.envelope_id == expected_envelope_id =>
                {
                    return Ok(Ok(entry));
                }
                GatewayServerFrame::Deliver { entry } => {
                    self.buffer_delivery(entry);
                }
                GatewayServerFrame::InBandWake { .. } => {}
                GatewayServerFrame::ForwardAck { ack }
                    if ack.envelope_id == expected_envelope_id
                        && ack.target_delivery_id == expected_target_delivery_id =>
                {
                    return Ok(Ok(GatewayInboxEntry {
                        forwarded: true,
                        inbox_seq: ack.inbox_seq.unwrap_or(0),
                        target_delivery_id: ack.target_delivery_id,
                        envelope: submitted_envelope,
                    }));
                }
                GatewayServerFrame::ForwardAck { ack } => {
                    return Err(SdkError::GatewaySessionRejected(format!(
                        "forward acknowledgement mismatch for envelope {} target {}",
                        ack.envelope_id, ack.target_delivery_id
                    )));
                }
                GatewayServerFrame::Nack { reason } => {
                    if reason == ramflux_protocol::GATEWAY_FORWARDED_HOME_NODE_MIGRATED_REASON {
                        return Ok(Ok(GatewayInboxEntry {
                            forwarded: true,
                            inbox_seq: 0,
                            target_delivery_id: expected_target_delivery_id,
                            envelope: submitted_envelope,
                        }));
                    }
                    if let Some(refusal) = super::session_push::SubmitRefusal::from_reason(&reason)
                    {
                        return Ok(Err(refusal));
                    }
                    return Err(SdkError::GatewaySessionRejected(reason));
                }
                other => {
                    return Err(SdkError::GatewaySessionRejected(format!(
                        "expected deliver after submit, got {other:?}"
                    )));
                }
            }
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects or cannot fan out the envelope.
    pub async fn own_device_fanout(
        &mut self,
        principal_id: impl Into<String>,
        source_device_id: impl Into<String>,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<GatewayOwnDeviceFanoutResponse, SdkError> {
        let principal_id = principal_id.into();
        let source_device_id = source_device_id.into();
        let signed_body = serde_json::json!({
            "principal_id": principal_id,
            "source_device_id": source_device_id,
            "envelope": envelope,
        });
        let fanout = GatewayOwnDeviceFanoutFrame {
            signed_request: self.signed_request(
                "POST",
                "/gateway/session/own-device-fanout",
                "already_authed",
                &signed_body,
            )?,
            principal_id,
            source_device_id,
            envelope,
        };
        self.write_frame(&GatewayClientFrame::OwnDeviceFanout { fanout }).await?;
        loop {
            match self.read_reply(super::frame_dispatch::ExpectedReply::Fanout).await? {
                GatewayServerFrame::OwnDeviceFanout { response } => return Ok(response),
                GatewayServerFrame::Deliver { entry } => {
                    self.buffer_delivery(entry);
                }
                GatewayServerFrame::InBandWake { .. } => {}
                GatewayServerFrame::Nack { reason } => {
                    return Err(SdkError::GatewaySessionRejected(reason));
                }
                other => {
                    return Err(SdkError::GatewaySessionRejected(format!(
                        "expected own-device fanout response, got {other:?}"
                    )));
                }
            }
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects the ack or returns an unexpected frame.
    pub async fn ack(&mut self, mut ack: ramflux_protocol::Ack) -> Result<GatewayCursor, SdkError> {
        let receiver = self.config.source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if ack.receiver_device_id != receiver.device_id()
            || ack
                .ext
                .ext
                .get("receiver_root_commitment")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|root| root != receiver.root_commitment())
        {
            return Err(SdkError::InboundRejected("ACK receiver identity mismatch".into()));
        }
        ack.ext.ext.insert(
            "receiver_root_commitment".into(),
            serde_json::json!(receiver.root_commitment()),
        );
        let branch = self.config.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        ack.signed = sdk_device_signed_fields(receiver.device_id(), "");
        ack.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch.as_ref(), &ack)?;
        if matches!(self.mode, super::session_push::SessionMode::Push { .. }) {
            return self.push_ack(ack).await;
        }
        self.write_frame(&GatewayClientFrame::Ack { ack }).await?;
        let ack_cursor = match self.read_reply(super::frame_dispatch::ExpectedReply::Ack).await? {
            GatewayServerFrame::Ack { cursor } => {
                self.config.last_seen_inbox_seq = cursor.inbox_seq;
                Ok(cursor)
            }
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => {
                Err(SdkError::GatewaySessionRejected(format!("expected ack cursor, got {other:?}")))
            }
        }?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Cursor).await? {
            GatewayServerFrame::Cursor { cursor: Some(cursor) } => {
                self.config.last_seen_inbox_seq = cursor.inbox_seq;
                Ok(cursor)
            }
            GatewayServerFrame::Cursor { cursor: None } => Ok(ack_cursor),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected cursor after ack, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the cursor request fails.
    pub async fn cursor(&mut self) -> Result<Option<GatewayCursor>, SdkError> {
        let target_delivery_id = self.config.target_delivery_id.clone();
        self.write_frame(&GatewayClientFrame::Cursor { target_delivery_id }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Cursor).await? {
            GatewayServerFrame::Cursor { cursor } => Ok(cursor),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected cursor frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects resume or returns an unexpected frame.
    pub async fn resume_after(
        &mut self,
        after_inbox_seq: u64,
        limit: usize,
    ) -> Result<Vec<GatewayInboxEntry>, SdkError> {
        if matches!(self.mode, super::session_push::SessionMode::Push { .. }) {
            return self.push_resume_after(after_inbox_seq, limit).await;
        }
        let resume = GatewayResumeFrame {
            target_delivery_id: self.config.target_delivery_id.clone(),
            after_inbox_seq,
            limit,
            resume_token: self.session.resume_token.clone(),
        };
        self.write_frame(&GatewayClientFrame::Resume { resume }).await?;
        let mut delivered = self.take_pending_deliveries();
        loop {
            match self.read_reply(super::frame_dispatch::ExpectedReply::Resume).await? {
                GatewayServerFrame::Deliver { entry } => delivered.push(entry),
                GatewayServerFrame::InBandWake { .. } => {}
                GatewayServerFrame::Resume { entries } => {
                    delivered.extend(self.take_pending_deliveries());
                    delivered.extend(entries);
                    return Ok(dedup_gateway_entries(delivered));
                }
                GatewayServerFrame::Nack { reason } => {
                    return Err(SdkError::GatewaySessionRejected(reason));
                }
                other => {
                    return Err(SdkError::GatewaySessionRejected(format!(
                        "expected resume frame, got {other:?}"
                    )));
                }
            }
        }
    }

    /// The account receive cursor advances only through the authoritative durable inbox page.
    /// A pushed entry can be beyond that page, so merging it would skip the intervening range.
    pub(crate) async fn resume_authoritative_after(
        &mut self,
        after_inbox_seq: u64,
        limit: usize,
    ) -> Result<Vec<GatewayInboxEntry>, SdkError> {
        if matches!(self.mode, super::session_push::SessionMode::Push { .. }) {
            return self.push_resume_authoritative(after_inbox_seq, limit).await;
        }
        let resume = GatewayResumeFrame {
            target_delivery_id: self.config.target_delivery_id.clone(),
            after_inbox_seq,
            limit,
            resume_token: self.session.resume_token.clone(),
        };
        self.write_frame(&GatewayClientFrame::Resume { resume }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Resume).await? {
            GatewayServerFrame::Resume { entries } => {
                self.take_pending_deliveries();
                Ok(dedup_gateway_entries(entries))
            }
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected resume frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects identity registration.
    pub(crate) async fn register_identity(
        &mut self,
        request: SdkIdentityRegisterRequest,
    ) -> Result<SdkIdentityRegistrationResponse, SdkError> {
        self.write_frame(&GatewayClientFrame::IdentityRegister { request }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Identity).await? {
            GatewayServerFrame::IdentityRegistered { response } => Ok(response),
            GatewayServerFrame::IdentityRegistrationRejected {
                reason_code: ramflux_protocol::IdentityDirectoryReason::PrincipalIdTaken,
            } => Err(crate::ContactReason::PrincipalIdTaken.into()),
            GatewayServerFrame::IdentityRegistrationRejected {
                reason_code: ramflux_protocol::IdentityDirectoryReason::RateLimited,
            } => Err(crate::ContactReason::LookupRateLimited.into()),
            GatewayServerFrame::IdentityRegistrationRejected {
                reason_code: ramflux_protocol::IdentityDirectoryReason::DeviceIdTaken,
            } => Err(crate::ContactReason::DeviceIdTaken.into()),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected identity_registered frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects prekey publication.
    pub(crate) async fn publish_prekey_bundle(
        &mut self,
        device_id: &str,
        bundle: &ramflux_crypto::PrekeyBundle,
    ) -> Result<SdkPrekeyResponse, SdkError> {
        let request =
            SdkPrekeyPublishRequest { device_id: device_id.to_owned(), bundle: bundle.clone() };
        self.write_frame(&GatewayClientFrame::PrekeyPublish { request }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::PublishPrekey).await? {
            GatewayServerFrame::PrekeyPublished { response } => Ok(response),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected prekey_published frame, got {other:?}"
            ))),
        }
    }

    pub(crate) async fn fetch_principal_manifest(
        &mut self,
        principal: &str,
    ) -> Result<Option<SdkDeviceManifestResponse>, SdkError> {
        self.write_frame(&GatewayClientFrame::PrincipalManifestFetch {
            principal_id: principal.to_owned(),
        })
        .await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Manifest).await? {
            GatewayServerFrame::PrincipalManifest { response } => {
                if let Some(reason) = response.reason_code {
                    return Err(match reason {
                        ramflux_protocol::IdentityDirectoryReason::RateLimited => {
                            crate::ContactReason::LookupRateLimited.into()
                        }
                        ramflux_protocol::IdentityDirectoryReason::PrincipalIdAmbiguous => {
                            crate::ContactReason::PrincipalIdAmbiguous.into()
                        }
                        _ => SdkError::GatewaySessionRejected(
                            "authenticated directory session required".into(),
                        ),
                    });
                }
                response.manifest.map(serde_json::from_value).transpose().map_err(SdkError::from)
            }
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected principal_manifest frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects prekey lookup.
    pub(crate) async fn fetch_prekey_bundle(
        &mut self,
        device_id: &str,
    ) -> Result<SdkPrekeyResponse, SdkError> {
        self.write_frame(&GatewayClientFrame::PrekeyFetch { device_id: device_id.to_owned() })
            .await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::Prekey).await? {
            GatewayServerFrame::Prekey { response } => Ok(response),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected prekey frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects relay token issuance.
    // T22-A1 / RQ-04: legacy v2 gateway-issued relay token; compiled only under itest-local-mint.
    #[cfg(feature = "itest-local-mint")]
    pub(crate) async fn issue_relay_token(
        &mut self,
        body: GatewayRelayTokenIssueBody,
    ) -> Result<SdkRelayToken, SdkError> {
        let request = GatewayRelayTokenIssueRequest {
            signed_request: self.signed_request(
                "POST",
                "/relay/v1/token/issue",
                "already_authed",
                &body,
            )?,
            body,
        };
        self.write_frame(&GatewayClientFrame::RelayTokenIssue { request }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::RelayToken).await? {
            GatewayServerFrame::RelayTokenIssued { response } => Ok(response.relay_token),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected relay_token_issued frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects v3 relay-token issuance or the response frame is
    /// not the expected v3 token frame.
    #[allow(dead_code)]
    pub(crate) async fn issue_relay_token_v3(
        &mut self,
        body: SdkRelayTokenV3IssueBody,
    ) -> Result<ramflux_protocol::RelayTokenV3, SdkError> {
        let request = GatewayRelayTokenV3IssueRequest {
            signed_request: self.signed_request(
                "POST",
                "/relay/v1/token/v3/issue",
                "already_authed",
                &body,
            )?,
            body,
        };
        self.write_frame(&GatewayClientFrame::RelayTokenV3Issue { request: Box::new(request) })
            .await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::RelayTokenV3).await? {
            GatewayServerFrame::RelayTokenV3Issued { response } => Ok(response.relay_token),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected relay_token_v3_issued frame, got {other:?}"
            ))),
        }
    }

    /// Allocates, renews or releases a production voice lease over the authenticated live session.
    /// # Errors
    /// Rejects transport, signature, caller binding or relay admission failures.
    pub async fn voice_lease(
        &mut self,
        body: ramflux_protocol::VoiceLeaseRequest,
    ) -> Result<ramflux_protocol::VoiceLeaseResponse, SdkError> {
        let request = ramflux_protocol::VoiceLeaseFrame {
            signed_request: self.signed_request(
                "POST",
                "/voice/v1/lease",
                "already_authed",
                &body,
            )?,
            body,
        };
        self.write_frame(&GatewayClientFrame::VoiceLease { request: Box::new(request) }).await?;
        match self.read_reply(super::frame_dispatch::ExpectedReply::VoiceLease).await? {
            GatewayServerFrame::VoiceLease { response } => Ok(*response),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            _ => Err(SdkError::GatewaySessionRejected("expected voice lease response".into())),
        }
    }

    /// # Errors
    /// Returns an error when the close frame cannot be written.
    pub async fn close(&mut self, reason: &str) -> Result<(), SdkError> {
        self.write_frame(&GatewayClientFrame::Close { reason: reason.to_owned() }).await?;
        self.stream.finish()?;
        Ok(())
    }

    pub(crate) fn signed_request<T>(
        &mut self,
        method: &str,
        path: &str,
        device_proof_hash: &str,
        body: &T,
    ) -> Result<ramflux_protocol::SignedRequest, SdkError>
    where
        T: serde::Serialize,
    {
        let method = match method {
            "POST" => ramflux_protocol::HttpMethod::POST,
            "GET" => ramflux_protocol::HttpMethod::GET,
            "PUT" => ramflux_protocol::HttpMethod::PUT,
            "DELETE" => ramflux_protocol::HttpMethod::DELETE,
            other => {
                return Err(SdkError::GatewaySessionRejected(format!(
                    "unsupported method {other}"
                )));
            }
        };
        let body_bytes = ramflux_protocol::canonical_json_bytes(body)?;
        let request = build_gateway_signed_request(
            &mut self.config,
            &self.session.session_id,
            self.request_counter,
            method,
            path,
            device_proof_hash,
            &body_bytes,
        )?;
        self.request_counter = self.request_counter.saturating_add(1);
        Ok(request)
    }

    fn remember_session_for_resume(&mut self) {
        self.config.previous_session_id = Some(self.session.session_id.clone());
        self.config.resume_token = Some(self.session.resume_token.clone());
        self.config.last_seen_inbox_seq = self.session.accepted_inbox_seq;
    }
}

pub(crate) async fn open_gateway_session_transport(
    config: &GatewaySessionConfig,
) -> Result<
    (
        GatewaySessionClientTransport,
        Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
        GatewaySessionTransportKind,
    ),
    SdkError,
> {
    match config.transport_kind {
        GatewaySessionTransportKind::Auto => {
            match open_quic_gateway_session_transport(config, config.quic_fallback_timeout).await {
                Ok((transport, stream)) => {
                    Ok((transport, stream, GatewaySessionTransportKind::Quic))
                }
                Err(quic_error) => {
                    tracing::warn!(
                        error = %quic_error,
                        gateway_addr = %config.gateway_addr,
                        tcp_gateway_addr = %config.tcp_gateway_addr.unwrap_or(config.gateway_addr),
                        "gateway QUIC unavailable; falling back to TCP-TLS"
                    );
                    let (transport, stream) =
                        open_tcp_tls_gateway_session_transport(config).await?;
                    Ok((transport, stream, GatewaySessionTransportKind::TcpTls))
                }
            }
        }
        GatewaySessionTransportKind::Quic => {
            let (transport, stream) =
                open_quic_gateway_session_transport(config, config.timeout).await?;
            Ok((transport, stream, GatewaySessionTransportKind::Quic))
        }
        GatewaySessionTransportKind::TcpTls => {
            let (transport, stream) = open_tcp_tls_gateway_session_transport(config).await?;
            Ok((transport, stream, GatewaySessionTransportKind::TcpTls))
        }
    }
}

async fn open_quic_gateway_session_transport(
    config: &GatewaySessionConfig,
    timeout: Duration,
) -> Result<
    (GatewaySessionClientTransport, Box<dyn ramflux_transport::GatewaySessionTransport + Send>),
    SdkError,
> {
    let mut client = ramflux_transport::QuicGatewayClient::connect(
        config.bind_addr,
        config.gateway_addr,
        &config.server_name,
        &config.ca_cert,
        timeout,
    )
    .await?;
    client.set_session_timeout(config.timeout);
    let stream = client.open_bidi_stream().await?;
    Ok((GatewaySessionClientTransport::Quic { _client: client }, Box::new(stream)))
}

async fn open_tcp_tls_gateway_session_transport(
    config: &GatewaySessionConfig,
) -> Result<
    (GatewaySessionClientTransport, Box<dyn ramflux_transport::GatewaySessionTransport + Send>),
    SdkError,
> {
    let (client, stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        config.bind_addr,
        config.tcp_gateway_addr.unwrap_or(config.gateway_addr),
        &config.server_name,
        &config.ca_cert,
        config.timeout,
    )
    .await?;
    Ok((GatewaySessionClientTransport::TcpTls { _client: client }, Box::new(stream)))
}

pub(crate) async fn write_gateway_client_frame(
    stream: &mut (dyn ramflux_transport::GatewaySessionTransport + Send),
    frame: &GatewayClientFrame,
) -> Result<(), SdkError> {
    ramflux_transport::write_gateway_session_json(stream, frame).await.map_err(SdkError::from)
}

/// Reads one frame and keeps its bytes for the second (echo) decode of the establishment.
async fn read_gateway_server_frame_bytes(
    stream: &mut (dyn ramflux_transport::GatewaySessionTransport + Send),
) -> Result<(GatewayServerFrame, Vec<u8>), SdkError> {
    let body = ramflux_transport::GatewaySessionFrameSource::recv_frame(stream)
        .await
        .map_err(SdkError::from)?;
    let frame = ramflux_protocol::parse_i_json(&body)
        .map_err(ramflux_transport::TransportError::from)
        .map_err(SdkError::from)?;
    Ok((frame, body))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod a2_signed_request_freshness_tests {
    use super::*;

    // A config whose auth window is stamped far in the PAST — i.e. a persistent session that connected
    // long ago and never refreshed, reproducing the GW-TOKEN-01-A0 frozen-deadline condition.
    fn aged_config() -> GatewaySessionConfig {
        let mut config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
            gateway_addr: "127.0.0.1:443".parse().expect("gateway addr"),
            server_name: "localhost".to_owned(),
            ca_cert: PathBuf::from("test-ca.pem"),
            principal_id: "principal_test".to_owned(),
            device_id: "device_test".to_owned(),
            target_delivery_id: "target_test".to_owned(),
            prekey_http_url: None,
        })
        .with_owned_device(
            &ramflux_crypto::create_identity_root("principal_test", [0x91; 32]),
            ramflux_crypto::create_device_branch("principal_test", "device_test", 1, [7_u8; 32]),
        )
        .expect("owned test device");
        // Freeze the window in the deep past (as if connected long ago and never refreshed).
        config.now = 1_000;
        config.auth_expires_at = 1_300; // 1_000 + 300s, long expired vs wall clock.
        config
    }

    // DoD #1: after the auth window has aged, the next signed request must carry a FRESH
    // created_at/expires_at (its own 300s window from now), NOT the frozen connect-time value.
    #[test]
    fn signed_request_restamps_a_fresh_window_after_aging() {
        let mut config = aged_config();
        let frozen_expires = config.auth_expires_at;
        let req = build_gateway_signed_request(
            &mut config,
            "session_test",
            0,
            ramflux_protocol::HttpMethod::POST,
            "/relay/v1/token/issue",
            "already_authed",
            b"body",
        )
        .expect("build");
        let wall = crate::time::now_unix_timestamp();
        // The frozen deadline is gone: the new request is stamped from a refreshed window.
        assert!(
            req.created_at >= wall - 5,
            "created_at must be fresh (near now), got {}",
            req.created_at
        );
        assert!(req.expires_at > frozen_expires, "expires_at must advance past the frozen value");
        assert_eq!(req.expires_at - req.created_at, 300, "window stays exactly the 300s TTL");
        // The client never emits an already-expired request; the gateway's absolute check is untouched.
        assert!(req.expires_at > wall, "a freshly-stamped request is not expired");
        // config itself was refreshed (so a subsequent request also starts fresh).
        assert_eq!(config.now, req.created_at);
        assert_eq!(config.auth_expires_at, req.expires_at);
    }

    // DoD #2 (+ CTRL-113a): refreshing the window feeds config.now into gateway_stream_nonce, so we must
    // prove consecutive requests still have UNIQUE request_id / nonce / replay_tuple, and that the same
    // request's replay tuple is stable (so the gateway replay guard still fail-closes on a true replay).
    #[test]
    fn consecutive_requests_keep_unique_replay_identity_after_refresh() {
        let mut config = aged_config();
        let r0 = build_gateway_signed_request(
            &mut config,
            "session_test",
            0,
            ramflux_protocol::HttpMethod::POST,
            "/relay/v1/token/issue",
            "already_authed",
            b"body",
        )
        .expect("r0");
        let r1 = build_gateway_signed_request(
            &mut config,
            "session_test",
            1,
            ramflux_protocol::HttpMethod::POST,
            "/relay/v1/token/issue",
            "already_authed",
            b"body",
        )
        .expect("r1");
        assert_ne!(r0.request_id, r1.request_id, "request_id must be unique per counter");
        assert_ne!(
            r0.nonce, r1.nonce,
            "nonce must be unique per counter even at the same refreshed now"
        );
        assert_ne!(
            r0.replay_tuple_key(config.source_identity.as_ref().expect("owned identity"))
                .expect("replay key"),
            r1.replay_tuple_key(config.source_identity.as_ref().expect("owned identity"))
                .expect("replay key"),
            "replay_tuple must be unique so the guard never coalesces two distinct requests"
        );
        // A true replay of the SAME request yields the SAME tuple → the guard still fail-closes on it.
        assert_eq!(
            r0.replay_tuple_key(config.source_identity.as_ref().expect("owned identity"))
                .expect("replay key"),
            r0.replay_tuple_key(config.source_identity.as_ref().expect("owned identity"))
                .expect("replay key")
        );
    }
}
