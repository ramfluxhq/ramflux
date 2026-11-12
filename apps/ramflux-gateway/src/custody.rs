// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client-facing TLS observation by a separately authorized node proxy.
use crate::GatewayQuicContext;
use ramflux_crypto::custody::{
    VerifiedNodeRecord, branch_exporter_hash, sign_proxy_acceptance, verify_node_identity_record,
};
use ramflux_protocol::custody::{
    BindingMode, CUSTODY_RPC_PATH, CustodyClientFrame, CustodyMeshRequest, CustodyRefusal,
    CustodyServerFrame, CustodySession, MAX_CUSTODY_FRAME_BYTES, decode,
};
use ramflux_transport::{GatewayTcpTlsStream, read_custody_tcp_frame, write_custody_tcp_frame};
use std::{collections::BTreeSet, time::Duration};
use zeroize::Zeroizing;
const IO_TIMEOUT: Duration = Duration::from_secs(330);
pub(crate) fn is_open(bytes: &[u8]) -> bool {
    ramflux_protocol::parse_i_json::<serde_json::Value>(bytes).is_ok_and(|v| {
        v.get("frame_type").and_then(serde_json::Value::as_str) == Some("custody_open")
    })
}
/// A connection-local grant issued by the receiving router after native possession proof.
/// No public fields or deserialization can manufacture a handoff from client JSON.
pub(crate) struct GatewayGrant {
    session: CustodySession,
    deadline: std::time::Instant,
    /// Set only by the web listener's own connection state, never from client bytes.
    web: bool,
}
/// Every listener accepts only its own `Open.transport_kind` class: the web names are
/// refused on the native listeners and are the only names accepted on the web listener.
#[must_use]
pub(crate) fn transport_kind_allowed(kind: &str, web: bool) -> bool {
    if web {
        kind == ramflux_protocol::custody::TRANSPORT_KIND_WEBSOCKET
    } else {
        kind != ramflux_protocol::custody::TRANSPORT_KIND_WEBSOCKET
            && kind != ramflux_protocol::custody::TRANSPORT_KIND_WEBTRANSPORT
    }
}
/// The web mode exists only on the web listener, and the web listener speaks no other
/// mode (so `no_channel_binding` stays refused there too).
#[must_use]
pub(crate) fn listener_accepts_mode(mode: BindingMode, web_listener: bool) -> bool {
    (mode == BindingMode::WebOriginBound) == web_listener
}
impl GatewayGrant {
    #[cfg(test)]
    pub(crate) fn from_test_session(session: CustodySession) -> Self {
        Self { session, deadline: std::time::Instant::now() + Duration::from_secs(60), web: false }
    }
    #[cfg(test)]
    pub(crate) fn from_test_web_session(session: CustodySession) -> Self {
        Self { session, deadline: std::time::Instant::now() + Duration::from_secs(60), web: true }
    }
    /// Whether this grant was issued on the web listener after a `web_origin_bound` proof.
    pub(crate) fn is_web(&self) -> bool {
        self.web
    }
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.deadline
    }
    pub(crate) fn session(&self) -> &CustodySession {
        &self.session
    }
    pub(crate) fn live(&self, now: u64) -> bool {
        self.session.expires_at > now && std::time::Instant::now() < self.deadline
    }
}

struct Proxy {
    node: VerifiedNodeRecord,
    signer: Option<ed25519_dalek::SigningKey>,
    connection: String,
    mode: BindingMode,
    /// The context this gateway authored for a web connection; `None` on native listeners.
    web: Option<ramflux_protocol::custody::WebOriginBindingV1>,
    session_ids: BTreeSet<String>,
    handoff_session: Option<GatewayGrant>,
    router: Option<crate::RouterMeshClient>,
    auth_deadline: tokio::time::Instant,
    authenticated: bool,
}
async fn rpc(
    context: &GatewayQuicContext,
    request: &CustodyMeshRequest,
) -> anyhow::Result<CustodyServerFrame> {
    Ok(crate::router_post_json_async(&context.router, CUSTODY_RPC_PATH, request).await?)
}
impl Proxy {
    async fn open(
        context: &GatewayQuicContext,
        bytes: &[u8],
        web: Option<ramflux_protocol::custody::WebOriginBindingV1>,
    ) -> anyhow::Result<(Self, CustodyServerFrame)> {
        let auth_deadline =
            tokio::time::Instant::now() + ramflux_node_core::custody_auth_timeout()?;
        let open: CustodyClientFrame = decode(bytes, 4096)?;
        let CustodyClientFrame::CustodyOpen { binding_mode: mode } = open else {
            anyhow::bail!("expected custody preface")
        };
        if mode == BindingMode::DirectExporter {
            anyhow::bail!("gateway cannot advertise direct router exporter binding")
        }
        // Listener separation, both directions: the web mode exists only on the web
        // listener, and the web listener speaks no other mode. No setting overrides this.
        if !listener_accepts_mode(mode, web.is_some()) {
            anyhow::bail!("binding mode does not belong to this listener")
        }
        let node = rpc(context, &CustodyMeshRequest::NodeIdentity { record_hash: None }).await?;
        let CustodyServerFrame::NodeIdentity { record, audience, .. } = node else {
            anyhow::bail!("custody unavailable")
        };
        let trusted = std::env::var("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY")?;
        let node = verify_node_identity_record(
            &record,
            &context.node_id,
            &trusted,
            ramflux_node_core::now_unix_seconds(),
        )?;
        if !node.envelope().body.channel_binding_modes.contains(&mode) {
            anyhow::bail!("binding mode not advertised")
        }
        if let Some(binding) = web.as_ref()
            && !node.envelope().body.web_listeners.iter().any(|listener| {
                listener.url == binding.listener_url
                    && listener.origins.iter().any(|origin| *origin == binding.origin)
            })
        {
            anyhow::bail!("web listener or origin not advertised by the node record")
        }
        if mode == BindingMode::NoChannelBinding {
            if std::env::var("RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING").as_deref() != Ok("1") {
                anyhow::bail!("unbound custody not opted in")
            }
            crate::ingress_log::record(crate::ingress_log::Event::NoChannelBinding);
        }
        // Both proxied modes need a node-authorised proxy signing key.
        let signer = if matches!(mode, BindingMode::HomeRelayReceipt | BindingMode::WebOriginBound)
        {
            let encoded = Zeroizing::new(std::env::var("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED")?);
            let bytes = Zeroizing::new(ramflux_protocol::decode_base64url(&encoded)?);
            if bytes.len() != 32 {
                anyhow::bail!("proxy seed must contain 32 bytes")
            }
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(&bytes);
            let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
            let public = ramflux_protocol::encode_base64url(signer.verifying_key().to_bytes());
            if !node.envelope().body.proxy_keys.iter().any(|k| {
                k.public_key == public
                    && k.proxy_id == context.gateway_id
                    && k.audiences.contains(&audience)
            }) {
                anyhow::bail!("proxy key is not authorized by the receiving node")
            }
            Some(signer)
        } else {
            None
        };
        let response = CustodyServerFrame::NodeIdentity {
            record,
            audience,
            binding_mode: mode,
            proxy_key_custody: signer.as_ref().map(|_| "software".into()),
        };
        Ok((
            Self {
                node,
                signer,
                connection: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                mode,
                web,
                session_ids: BTreeSet::new(),
                handoff_session: None,
                router: Some(context.router.clone()),
                auth_deadline,
                authenticated: false,
            },
            response,
        ))
    }
    async fn frame(
        &mut self,
        context: &GatewayQuicContext,
        frame: CustodyClientFrame,
        observed: Option<&str>,
        permit: &ramflux_node_core::CustodyIngressPermit,
    ) -> anyhow::Result<CustodyServerFrame> {
        let principal = if let CustodyClientFrame::Prove { proof, .. } = &frame {
            Some(proof.body.device_ref.account_anchor.clone())
        } else {
            None
        };
        let request = match self.prepare(frame, observed, context.remote_addr.ip()) {
            Ok(request) => request,
            Err(error) => {
                if let Some(code) = error.downcast_ref::<CustodyRefusal>() {
                    return Ok(CustodyServerFrame::Refused {
                        code: code.clone(),
                        capacity: None,
                        retry: None,
                    });
                }
                return Err(error);
            }
        };
        let result = rpc(context, &request).await?;
        if matches!(
            result,
            CustodyServerFrame::Published { .. }
                | CustodyServerFrame::Registered { .. }
                | CustodyServerFrame::SessionEstablished { .. }
        ) {
            let principal = principal.ok_or_else(|| anyhow::anyhow!("unexpected proof result"))?;
            if let Err(refusal) = permit.mark_authenticated(&principal) {
                return Ok(refusal.into_frame());
            }
            self.authenticated = true;
        }
        if let CustodyServerFrame::SessionEstablished { session } = &result {
            // A connection retains only its latest session; an old id cannot become a bearer.
            self.session_ids.clear();
            self.session_ids.insert(session.session_id.clone());
            let remaining =
                session.expires_at.saturating_sub(ramflux_node_core::now_unix_seconds()).min(300);
            self.handoff_session = Some(GatewayGrant {
                session: session.clone(),
                deadline: std::time::Instant::now() + Duration::from_secs(remaining),
                web: self.web.is_some(),
            });
        } else if matches!(result, CustodyServerFrame::Closed) {
            self.session_ids.clear();
            self.handoff_session = None;
        }
        Ok(result)
    }
    fn prepare(
        &self,
        frame: CustodyClientFrame,
        observed: Option<&str>,
        source: std::net::IpAddr,
    ) -> anyhow::Result<CustodyMeshRequest> {
        let request = match frame {
            CustodyClientFrame::NodeIdentity { record_hash } => {
                CustodyMeshRequest::NodeIdentity { record_hash }
            }
            CustodyClientFrame::Challenge { device_ref, action } => CustodyMeshRequest::Challenge {
                device_ref,
                action,
                binding_mode: self.mode,
                client_source: source.to_string(),
                connection_id: self.connection.clone(),
            },
            CustodyClientFrame::Prove { action, proof } => {
                if proof.body.binding_mode != self.mode {
                    anyhow::bail!("custody mode changed")
                }
                let actual = observed
                    .ok_or_else(|| anyhow::anyhow!("client-facing exporter unavailable"))?;
                if actual != proof.body.transport_binding {
                    return Err(CustodyRefusal::BindingRefused.into());
                }
                let receipt = if matches!(
                    self.mode,
                    BindingMode::HomeRelayReceipt | BindingMode::WebOriginBound
                ) {
                    Some(Box::new(sign_proxy_acceptance(
                        self.signer.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("authorized proxy signer unavailable")
                        })?,
                        &self.node,
                        &proof,
                        actual,
                        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                        ramflux_node_core::now_unix_seconds(),
                    )?))
                } else {
                    None
                };
                if let Some(context) = self.web.clone() {
                    CustodyMeshRequest::ProveWeb {
                        action,
                        proof,
                        receipt: receipt
                            .ok_or_else(|| anyhow::anyhow!("web proof requires a proxy receipt"))?,
                        context,
                        connection_id: self.connection.clone(),
                    }
                } else {
                    CustodyMeshRequest::Prove {
                        action,
                        proof,
                        receipt,
                        connection_id: self.connection.clone(),
                    }
                }
            }
            CustodyClientFrame::Request { session_id, request, action } => {
                if !self.session_ids.contains(&session_id) {
                    return Err(CustodyRefusal::SessionRequired.into());
                }
                CustodyMeshRequest::Request {
                    connection_id: self.connection.clone(),
                    session_id,
                    request,
                    action,
                }
            }
            CustodyClientFrame::CustodyOpen { .. } | CustodyClientFrame::GatewayHandoff { .. } => {
                return Err(CustodyRefusal::InvalidInput.into());
            }
        };
        Ok(request)
    }
}
fn nonce(frame: &CustodyClientFrame) -> anyhow::Result<Option<[u8; 32]>> {
    let CustodyClientFrame::Prove { proof, .. } = frame else { return Ok(None) };
    let bytes = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?;
    Ok(Some(bytes.try_into().map_err(|_| anyhow::anyhow!("invalid challenge context"))?))
}
type Limiter = std::sync::Arc<ramflux_node_core::CustodyIngressLimiter>;
#[derive(Clone)]
pub(crate) struct Pools {
    pub(crate) tcp: Limiter,
    pub(crate) quic: Limiter,
    /// Separate admission pool for the web listener, sized like a native listener.
    #[cfg(feature = "web-ingress")]
    pub(crate) web: Limiter,
}
#[cfg(feature = "web-ingress")]
#[path = "custody_web.rs"]
pub(crate) mod web;
pub(crate) fn initialize() -> anyhow::Result<Option<Pools>> {
    initialize_if_configured(std::env::var_os("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY").as_deref(), || {
        let settings = ramflux_node_core::CustodyPoolSettings::from_env()?;
        #[cfg(feature = "web-ingress")]
        let listeners = 2 + usize::from(crate::web_ingress::configured());
        #[cfg(not(feature = "web-ingress"))]
        let listeners = 2;
        ramflux_node_core::custody_listener_resources(settings, listeners)?;
        Ok(Pools {
            tcp: settings.limiter(),
            quic: settings.limiter(),
            #[cfg(feature = "web-ingress")]
            web: settings.limiter(),
        })
    })
}
fn initialize_if_configured(
    key: Option<&std::ffi::OsStr>,
    initialize: impl FnOnce() -> anyhow::Result<Pools>,
) -> anyhow::Result<Option<Pools>> {
    if key.is_none_or(std::ffi::OsStr::is_empty) {
        return Ok(None);
    }
    initialize().map(Some)
}
pub(crate) fn unavailable() -> CustodyServerFrame {
    CustodyServerFrame::Refused { code: CustodyRefusal::Unsupported, capacity: None, retry: None }
}
pub(crate) async fn admit_tcp(
    stream: &mut GatewayTcpTlsStream,
    source: std::net::IpAddr,
    pools: Option<&Pools>,
) -> anyhow::Result<Option<ramflux_node_core::CustodyIngressPermit>> {
    let response = if let Some(pools) = pools {
        match pools.tcp.acquire(source, None, std::time::Instant::now()) {
            Ok(permit) => return Ok(Some(permit)),
            Err(refusal) => refusal.into_frame(),
        }
    } else {
        unavailable()
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        write_custody_tcp_frame(stream, &serde_json::to_vec(&response)?),
    )
    .await??;
    Ok(None)
}
pub(crate) async fn admit_quic(
    send: &mut quinn::SendStream,
    connection: &quinn::Connection,
    limiter: &Limiter,
    captured_peer: std::net::IpAddr,
    started: std::time::Instant,
) -> anyhow::Result<Option<ramflux_node_core::CustodyIngressPermit>> {
    let refusal = match limiter.acquire(captured_peer, Some(connection.stable_id()), started) {
        Ok(permit) => return Ok(Some(permit)),
        Err(refusal) => refusal.into_frame(),
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        write_custody_tcp_frame(send, &serde_json::to_vec(&refusal)?),
    )
    .await??;
    send.finish()?;
    Ok(None)
}
impl Proxy {
    fn handoff(&mut self, session_id: &str) -> anyhow::Result<GatewayGrant> {
        let grant = self
            .handoff_session
            .take()
            .filter(|grant| {
                grant.session.session_id == session_id
                    && self.session_ids.contains(session_id)
                    && grant.live(ramflux_node_core::now_unix_seconds())
            })
            .ok_or(CustodyRefusal::SessionRequired)?;
        self.session_ids.clear();
        Ok(grant)
    }
    fn deadline(&self) -> tokio::time::Instant {
        if self.authenticated {
            tokio::time::Instant::now() + IO_TIMEOUT
        } else {
            self.auth_deadline
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        let Some(router) = self.router.clone() else { return };
        let request = CustodyMeshRequest::Disconnect { connection_id: self.connection.clone() };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let result = crate::router_post_json_async::<_, CustodyServerFrame>(
                    &router,
                    CUSTODY_RPC_PATH,
                    &request,
                );
                let _ = tokio::time::timeout(Duration::from_secs(2), result).await;
            });
        }
    }
}
async fn tcp_inner(
    mut stream: GatewayTcpTlsStream,
    context: GatewayQuicContext,
    first: &[u8],
    capacity: ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<()> {
    let run = async {
        let (mut proxy, response) = tokio::time::timeout_at(
            tokio::time::Instant::from_std(capacity.auth_deadline()),
            Proxy::open(&context, first, None),
        )
        .await??;
        proxy.auth_deadline = tokio::time::Instant::from_std(capacity.auth_deadline());
        tokio::time::timeout_at(
            proxy.deadline(),
            write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?),
        )
        .await??;
        for _ in 0..2048 {
            let deadline = proxy.deadline();
            let bytes =
                tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut stream)).await??;
            let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
            if let CustodyClientFrame::GatewayHandoff { session_id } = &frame {
                let grant = proxy.handoff(session_id)?;
                let first = tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut stream))
                    .await??;
                let first = ramflux_protocol::parse_i_json(&first)?;
                let (recv, send) = tokio::io::split(stream);
                drop(proxy);
                return Box::pin(crate::session::handle_gateway_custody_session_transport(
                    Box::new(send),
                    Box::new(recv),
                    context,
                    first,
                    grant,
                ))
                .await;
            }
            let observed = nonce(&frame)?
                .map(|nonce| {
                    ramflux_transport::custody_tcp_exporter(&stream, &nonce)
                        .map(|exporter| branch_exporter_hash(&exporter))
                })
                .transpose()?;
            let response = tokio::time::timeout_at(
                deadline,
                proxy.frame(&context, frame, observed.as_deref(), &capacity),
            )
            .await??;
            let saturated =
                matches!(response, CustodyServerFrame::Refused { code: CustodyRefusal::Busy, .. });
            tokio::time::timeout_at(
                deadline,
                write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?),
            )
            .await??;
            if saturated {
                return Ok(());
            }
        }
        Ok(())
    };
    tokio::select! {
        biased;
        () = capacity.revoked() => anyhow::bail!("custody admission revoked"),
        result = run => result,
    }
}
async fn quic_inner(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connection: quinn::Connection,
    context: GatewayQuicContext,
    first: &[u8],
    capacity: ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<()> {
    let run = async {
        let (mut proxy, response) = tokio::time::timeout_at(
            tokio::time::Instant::from_std(capacity.auth_deadline()),
            Proxy::open(&context, first, None),
        )
        .await??;
        proxy.auth_deadline = tokio::time::Instant::from_std(capacity.auth_deadline());
        tokio::time::timeout_at(
            proxy.deadline(),
            write_custody_tcp_frame(&mut send, &serde_json::to_vec(&response)?),
        )
        .await??;
        for _ in 0..2048 {
            let deadline = proxy.deadline();
            let bytes =
                tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut recv)).await??;
            let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
            if let CustodyClientFrame::GatewayHandoff { session_id } = &frame {
                let grant = proxy.handoff(session_id)?;
                let first =
                    tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut recv)).await??;
                let first = ramflux_protocol::parse_i_json(&first)?;

                drop(proxy);
                return Box::pin(crate::session::handle_gateway_custody_session_transport(
                    Box::new(send),
                    Box::new(recv),
                    context,
                    first,
                    grant,
                ))
                .await;
            }
            let observed = nonce(&frame)?
                .map(|nonce| {
                    ramflux_transport::custody_quic_exporter(&connection, &nonce)
                        .map(|exporter| branch_exporter_hash(&exporter))
                })
                .transpose()?;
            let response = tokio::time::timeout_at(
                deadline,
                proxy.frame(&context, frame, observed.as_deref(), &capacity),
            )
            .await??;
            let saturated =
                matches!(response, CustodyServerFrame::Refused { code: CustodyRefusal::Busy, .. });
            tokio::time::timeout_at(
                deadline,
                write_custody_tcp_frame(&mut send, &serde_json::to_vec(&response)?),
            )
            .await??;
            if saturated {
                send.finish()?;
                return Ok(());
            }
        }
        Ok(())
    };
    tokio::select! {
        biased;
        () = capacity.revoked() => anyhow::bail!("custody admission revoked"),
        result = run => result,
    }
}

pub(crate) async fn tcp(
    stream: GatewayTcpTlsStream,
    context: GatewayQuicContext,
    first: &[u8],
    capacity: ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<()> {
    tokio::time::timeout(
        Duration::from_mins(15),
        Box::pin(tcp_inner(stream, context, first, capacity)),
    )
    .await?
}
pub(crate) async fn quic(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    connection: quinn::Connection,
    context: GatewayQuicContext,
    first: &[u8],
    capacity: ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<()> {
    tokio::time::timeout(
        Duration::from_mins(15),
        Box::pin(quic_inner(send, recv, connection, context, first, capacity)),
    )
    .await?
}

#[cfg(test)]
#[path = "custody_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
mod listener_separation_tests {
    use super::{GatewayGrant, listener_accepts_mode, transport_kind_allowed};
    use ramflux_protocol::custody::{BindingMode, CustodySession, DeviceRef};

    fn session(mode: BindingMode) -> CustodySession {
        CustodySession {
            session_id: "session".to_owned(),
            device_ref: DeviceRef {
                account_anchor: "anchor".to_owned(),
                device_id: "device".to_owned(),
                device_epoch: 1,
            },
            target_delivery_id: "target".to_owned(),
            record_hash: "record".to_owned(),
            proof_hash: "proof".to_owned(),
            binding_mode: mode,
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn web_origin_bound_mode_is_refused_on_quic_and_tcp_tls() {
        assert!(!listener_accepts_mode(BindingMode::WebOriginBound, false));
        assert!(listener_accepts_mode(BindingMode::HomeRelayReceipt, false));
        assert!(listener_accepts_mode(BindingMode::NoChannelBinding, false));
    }

    #[test]
    fn no_channel_binding_stays_refused_on_web_listener() {
        assert!(listener_accepts_mode(BindingMode::WebOriginBound, true));
        assert!(!listener_accepts_mode(BindingMode::NoChannelBinding, true));
        assert!(!listener_accepts_mode(BindingMode::HomeRelayReceipt, true));
        assert!(!listener_accepts_mode(BindingMode::DirectExporter, true));
    }

    #[test]
    fn open_with_websocket_transport_kind_is_refused_on_native_listeners() {
        assert!(!transport_kind_allowed("websocket", false));
        assert!(!transport_kind_allowed("webtransport", false));
        assert!(transport_kind_allowed("quic_quinn", false));
        assert!(transport_kind_allowed("tcp_tls", false));
    }

    #[test]
    fn open_with_non_websocket_transport_kind_is_refused_on_web_listener() {
        assert!(transport_kind_allowed("websocket", true));
        for kind in ["quic_quinn", "tcp_tls", "webtransport", "WebSocket", ""] {
            assert!(!transport_kind_allowed(kind, true), "{kind}");
        }
    }

    #[test]
    fn grant_carrier_comes_from_the_listener_not_from_the_session_body() {
        // A native grant stays native even if its session body names the web mode.
        assert!(!GatewayGrant::from_test_session(session(BindingMode::WebOriginBound)).is_web());
        assert!(GatewayGrant::from_test_web_session(session(BindingMode::WebOriginBound)).is_web());
    }
}
