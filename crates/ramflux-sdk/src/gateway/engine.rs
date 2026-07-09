// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::GatewaySessionTransportKind;
use crate::prelude::*;

pub struct GatewaySessionEngine {
    pub(crate) config: GatewaySessionConfig,
    _transport: GatewaySessionClientTransport,
    stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    session: GatewaySessionState,
    request_counter: u64,
    pending_deliveries: VecDeque<GatewayInboxEntry>,
}

enum GatewaySessionClientTransport {
    Quic { _client: ramflux_transport::QuicGatewayClient },
    TcpTls { _client: ramflux_transport::TcpTlsGatewayClient },
}

#[derive(Clone, Debug)]
pub struct GatewayDirectMessage {
    pub conversation_id: String,
    pub message_id: String,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub sender_id: String,
    pub recipient_device_id: Option<String>,
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

pub(crate) async fn gateway_session_timeout<T, F>(
    operation: &'static str,
    future: F,
) -> Result<T, SdkError>
where
    F: Future<Output = Result<T, SdkError>>,
{
    match tokio::time::timeout(GATEWAY_SESSION_NETWORK_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_elapsed) => Err(SdkError::GatewaySessionRejected(format!(
            "{operation} timed out after {}s",
            GATEWAY_SESSION_NETWORK_TIMEOUT.as_secs()
        ))),
    }
}

impl GatewaySessionEngine {
    /// # Errors
    /// Returns an error when the QUIC session cannot connect, authenticate, or receive
    /// `session_established`.
    pub async fn connect(config: GatewaySessionConfig) -> Result<Self, SdkError> {
        gateway_session_timeout("gateway session connect", Self::connect_inner(config)).await
    }

    async fn connect_inner(mut config: GatewaySessionConfig) -> Result<Self, SdkError> {
        config.refresh_auth_window();
        let (transport, mut stream, active_transport_kind) =
            open_gateway_session_transport(&config).await?;
        config.transport_kind = active_transport_kind;
        let open = gateway_fresh_open_frame(&config)?;
        write_gateway_client_frame(&mut *stream, &GatewayClientFrame::Open { open: open.clone() })
            .await?;
        let auth = gateway_auth_frame(&config, &open)?;
        write_gateway_client_frame(&mut *stream, &GatewayClientFrame::Auth { auth }).await?;
        let established = gateway_session_timeout("gateway session established", async {
            read_gateway_server_frame(&mut *stream).await
        })
        .await?;
        let session = match established {
            GatewayServerFrame::SessionEstablished { session } => {
                gateway_session_state(&session, config.last_seen_inbox_seq)
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
        };
        engine.remember_session_for_resume();
        Ok(engine)
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
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => self.reconnect(last_seen_inbox_seq).await,
        }
    }

    /// # Errors
    /// Returns an error when the heartbeat cannot be written or acknowledged.
    pub async fn heartbeat(&mut self) -> Result<(), SdkError> {
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::Heartbeat { now: gateway_heartbeat_now() },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
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
        write_gateway_client_frame(&mut *self.stream, &GatewayClientFrame::Submit { submit })
            .await?;
        loop {
            match self.read_gateway_frame("submit response").await? {
                GatewayServerFrame::Deliver { entry }
                    if entry.envelope.envelope_id == expected_envelope_id =>
                {
                    return Ok(entry);
                }
                GatewayServerFrame::Deliver { entry } => {
                    self.pending_deliveries.push_back(entry);
                }
                GatewayServerFrame::InBandWake { .. } => {}
                GatewayServerFrame::Nack { reason } => {
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
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::OwnDeviceFanout { fanout },
        )
        .await?;
        loop {
            match self.read_gateway_frame("own-device fanout response").await? {
                GatewayServerFrame::OwnDeviceFanout { response } => return Ok(response),
                GatewayServerFrame::Deliver { entry } => {
                    self.pending_deliveries.push_back(entry);
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
    pub async fn ack(&mut self, ack: ramflux_protocol::Ack) -> Result<GatewayCursor, SdkError> {
        write_gateway_client_frame(&mut *self.stream, &GatewayClientFrame::Ack { ack }).await?;
        let ack_cursor = match self.read_non_deliver_frame().await? {
            GatewayServerFrame::Ack { cursor } => {
                self.config.last_seen_inbox_seq = cursor.inbox_seq;
                Ok(cursor)
            }
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => {
                Err(SdkError::GatewaySessionRejected(format!("expected ack cursor, got {other:?}")))
            }
        }?;
        match self.read_non_deliver_frame().await? {
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
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::Cursor { target_delivery_id },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
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
        let resume = GatewayResumeFrame {
            target_delivery_id: self.config.target_delivery_id.clone(),
            after_inbox_seq,
            limit,
            resume_token: self.session.resume_token.clone(),
        };
        write_gateway_client_frame(&mut *self.stream, &GatewayClientFrame::Resume { resume })
            .await?;
        let mut delivered = self.take_pending_deliveries();
        loop {
            match self.read_gateway_frame("resume response").await? {
                GatewayServerFrame::Deliver { entry } => delivered.push(entry),
                GatewayServerFrame::InBandWake { .. } => {}
                GatewayServerFrame::Resume { entries } => {
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

    /// # Errors
    /// Returns an error when the gateway rejects identity registration.
    pub(crate) async fn register_identity(
        &mut self,
        request: SdkIdentityRegisterRequest,
    ) -> Result<SdkIdentityRegistrationResponse, SdkError> {
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::IdentityRegister { request },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
            GatewayServerFrame::IdentityRegistered { response } => Ok(response),
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
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::PrekeyPublish { request },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
            GatewayServerFrame::PrekeyPublished { response } => Ok(response),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected prekey_published frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects prekey lookup.
    pub(crate) async fn fetch_prekey_bundle(
        &mut self,
        device_id: &str,
    ) -> Result<SdkPrekeyResponse, SdkError> {
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::PrekeyFetch { device_id: device_id.to_owned() },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
            GatewayServerFrame::Prekey { response } => Ok(response),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected prekey frame, got {other:?}"
            ))),
        }
    }

    /// # Errors
    /// Returns an error when the gateway rejects relay token issuance.
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
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::RelayTokenIssue { request },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
            GatewayServerFrame::RelayTokenIssued { response } => Ok(response.relay_token),
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected relay_token_issued frame, got {other:?}"
            ))),
        }
    }

    async fn read_non_deliver_frame(&mut self) -> Result<GatewayServerFrame, SdkError> {
        loop {
            match self.read_gateway_frame("gateway frame").await? {
                GatewayServerFrame::Deliver { entry } => self.pending_deliveries.push_back(entry),
                GatewayServerFrame::InBandWake { .. } => {}
                frame => return Ok(frame),
            }
        }
    }

    async fn read_gateway_frame(
        &mut self,
        operation: &'static str,
    ) -> Result<GatewayServerFrame, SdkError> {
        gateway_session_timeout(operation, async {
            read_gateway_server_frame(&mut *self.stream).await
        })
        .await
    }

    fn take_pending_deliveries(&mut self) -> Vec<GatewayInboxEntry> {
        self.pending_deliveries.drain(..).collect()
    }

    /// # Errors
    /// Returns an error when the close frame cannot be written.
    pub async fn close(&mut self, reason: &str) -> Result<(), SdkError> {
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::Close { reason: reason.to_owned() },
        )
        .await?;
        self.stream.finish()?;
        Ok(())
    }

    fn signed_request<T>(
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
        let device_branch = self.config.device_branch.as_ref().ok_or_else(|| {
            SdkError::GatewaySessionRejected(format!(
                "missing registered device branch for {}",
                self.config.device_id
            ))
        })?;
        let mut request = ramflux_protocol::SignedRequest {
            schema: "ramflux.signed_request.v1".to_owned(),
            version: 1,
            domain: "ramflux.signed_request.v1".to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: sdk_device_signed_fields(&self.config.device_id, ""),
            source_device_id: self.config.device_id.clone(),
            request_id: format!("req_sdk_{}_{}", self.session.session_id, self.request_counter),
            method,
            path: path.to_owned(),
            device_proof_hash: device_proof_hash.to_owned(),
            body_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::ENVELOPE,
                &body_bytes,
            ),
            nonce: gateway_stream_nonce(&self.config, self.request_counter),
            created_at: self.config.now,
            expires_at: self.config.auth_expires_at,
        };
        self.request_counter = self.request_counter.saturating_add(1);
        request.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            device_branch.as_ref(),
            &request,
        )?;
        Ok(request)
    }

    fn remember_session_for_resume(&mut self) {
        self.config.previous_session_id = Some(self.session.session_id.clone());
        self.config.resume_token = Some(self.session.resume_token.clone());
        self.config.last_seen_inbox_seq = self.session.accepted_inbox_seq;
    }
}

async fn open_gateway_session_transport(
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

async fn write_gateway_client_frame(
    stream: &mut (dyn ramflux_transport::GatewaySessionTransport + Send),
    frame: &GatewayClientFrame,
) -> Result<(), SdkError> {
    ramflux_transport::write_gateway_session_json(stream, frame).await.map_err(SdkError::from)
}

async fn read_gateway_server_frame(
    stream: &mut (dyn ramflux_transport::GatewaySessionTransport + Send),
) -> Result<GatewayServerFrame, SdkError> {
    ramflux_transport::read_gateway_session_json(stream).await.map_err(SdkError::from)
}
