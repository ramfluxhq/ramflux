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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;
const IO_TIMEOUT: Duration = Duration::from_secs(330);
pub(crate) const CLOSE_DRAIN_CAP: usize = 64 * 1024;
const CLOSE_DRAIN_BUDGET: Duration = Duration::from_millis(200);
const CLOSE_WRITE_BUDGET: Duration = Duration::from_secs(1);
pub(crate) const MAX_CUSTODY_SESSION_FRAMES: usize = 2048;

/// Values read once from the process environment. Tests substitute a copy on the task.
#[derive(Clone)]
struct OpenMaterial {
    node_public_key: Option<String>,
    allow_unbound: bool,
    proxy_seed: Option<Zeroizing<String>>,
}

fn material_from_env() -> OpenMaterial {
    OpenMaterial {
        node_public_key: std::env::var("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY").ok(),
        allow_unbound: std::env::var("RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING").ok().as_deref()
            == Some("1"),
        proxy_seed: std::env::var("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED").ok().map(Zeroizing::new),
    }
}

fn current_material() -> OpenMaterial {
    #[cfg(test)]
    if let Ok(material) = TEST_OPEN_MATERIAL.try_with(Clone::clone) {
        return material;
    }
    material_from_env()
}

#[cfg(test)]
enum TestRpc {
    Fail,
    Frame(CustodyServerFrame),
}

#[cfg(test)]
tokio::task_local! {
    static TEST_OPEN_MATERIAL: OpenMaterial;
    static TEST_RPC: std::cell::RefCell<std::collections::VecDeque<TestRpc>>;
}

#[cfg(test)]
fn take_test_rpc() -> Option<anyhow::Result<CustodyServerFrame>> {
    let step = TEST_RPC.try_with(|queue| queue.borrow_mut().pop_front()).ok().flatten()?;
    Some(match step {
        TestRpc::Fail => Err(CustodyRefusal::AuthorityUnavailable.into()),
        TestRpc::Frame(frame) => Ok(frame),
    })
}

pub(crate) fn log_refusal(code: &CustodyRefusal) {
    tracing::warn!(reason = code.reason_code(), "custody connection refused");
}

fn classify_custody_close(error: &anyhow::Error) -> CustodyRefusal {
    if let Some(code) = error.downcast_ref::<CustodyRefusal>() {
        return code.clone();
    }
    if error.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
        return CustodyRefusal::AbortedRetrySafe;
    }
    CustodyRefusal::InvalidInput
}

fn refused(code: &CustodyRefusal) -> CustodyServerFrame {
    CustodyServerFrame::Refused { code: code.clone(), capacity: None, retry: None }
}

/// Drop already-buffered client bytes so a later close is a FIN, not a kernel RST.
pub(crate) async fn drain_unread<R>(reader: &mut R)
where
    R: AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + CLOSE_DRAIN_BUDGET;
    let mut total = 0usize;
    let mut buf = [0u8; 4096];
    while total < CLOSE_DRAIN_CAP {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let room = CLOSE_DRAIN_CAP - total;
        let take = room.min(buf.len());
        match tokio::time::timeout(
            left.min(Duration::from_millis(50)),
            reader.read(&mut buf[..take]),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => total = total.saturating_add(n),
        }
    }
}

async fn shutdown_write<W>(writer: &mut W)
where
    W: AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(CLOSE_WRITE_BUDGET, writer.shutdown()).await;
}

async fn finish_tcp(stream: &mut GatewayTcpTlsStream) {
    drain_unread(stream).await;
    shutdown_write(stream).await;
}

async fn refuse_tcp(stream: &mut GatewayTcpTlsStream, code: &CustodyRefusal) {
    log_refusal(code);
    if let Ok(bytes) = serde_json::to_vec(&refused(code)) {
        let _ =
            tokio::time::timeout(CLOSE_WRITE_BUDGET, write_custody_tcp_frame(stream, &bytes)).await;
    }
    finish_tcp(stream).await;
}

async fn finish_quic(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) {
    drain_unread(recv).await;
    let _ = send.finish();
}

pub(crate) async fn refuse_quic(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: &CustodyRefusal,
) {
    log_refusal(code);
    if let Ok(bytes) = serde_json::to_vec(&refused(code)) {
        let _ =
            tokio::time::timeout(CLOSE_WRITE_BUDGET, write_custody_tcp_frame(send, &bytes)).await;
    }
    finish_quic(send, recv).await;
}
pub(crate) fn is_open(bytes: &[u8]) -> bool {
    ramflux_protocol::parse_i_json::<serde_json::Value>(bytes).is_ok_and(|v| {
        v.get("frame_type").and_then(serde_json::Value::as_str) == Some("custody_open")
    })
}
/// A connection-local grant issued by the receiving router after native possession proof.
/// No public fields or deserialization can manufacture a handoff from client JSON.
pub(crate) struct GatewayGrant {
    session: CustodySession,
    connection_id: String,
    deadline: std::time::Instant,
}
impl GatewayGrant {
    fn deadline_for(expires_at: u64) -> std::time::Instant {
        let remaining = expires_at
            .saturating_sub(ramflux_node_core::now_unix_seconds())
            .min(ramflux_node_core::NATIVE_SESSION_GRANT_SECONDS);
        std::time::Instant::now() + Duration::from_secs(remaining)
    }
    fn granted(session: CustodySession, connection_id: String) -> Self {
        let deadline = Self::deadline_for(session.expires_at);
        Self { session, connection_id, deadline }
    }
    #[cfg(test)]
    pub(crate) fn from_test_session(session: CustodySession) -> Self {
        Self {
            session,
            connection_id: String::new(),
            deadline: std::time::Instant::now() + Duration::from_secs(60),
        }
    }
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.deadline
    }
    pub(crate) fn session(&self) -> &CustodySession {
        &self.session
    }
    pub(crate) fn connection_id(&self) -> &str {
        &self.connection_id
    }
    pub(crate) fn live(&self, now: u64) -> bool {
        self.session.expires_at > now && std::time::Instant::now() < self.deadline
    }
    pub(crate) fn replace_renewed(&mut self, session: CustodySession) {
        self.deadline = Self::deadline_for(session.expires_at);
        self.session = session;
    }
}

struct Proxy {
    node: VerifiedNodeRecord,
    signer: Option<ed25519_dalek::SigningKey>,
    connection: String,
    mode: BindingMode,
    session_ids: BTreeSet<String>,
    handoff_session: Option<GatewayGrant>,
    router: Option<crate::RouterMeshClient>,
    auth_deadline: tokio::time::Instant,
    authenticated: bool,
    /// Set only once the session is about to take the lease, so a failed handoff still disconnects.
    handed_off: bool,
}
async fn rpc(
    context: &GatewayQuicContext,
    request: &CustodyMeshRequest,
) -> anyhow::Result<CustodyServerFrame> {
    #[cfg(test)]
    if let Some(scripted) = take_test_rpc() {
        return scripted;
    }
    Ok(crate::router_post_json_async(&context.router, CUSTODY_RPC_PATH, request).await?)
}
impl Proxy {
    async fn open(
        context: &GatewayQuicContext,
        bytes: &[u8],
    ) -> anyhow::Result<(Self, CustodyServerFrame)> {
        let material = current_material();
        let auth_deadline = tokio::time::Instant::now()
            + ramflux_node_core::custody_auth_timeout()
                .map_err(|_| CustodyRefusal::AuthorityUnavailable)?;
        let open: CustodyClientFrame =
            decode(bytes, 4096).map_err(|_| CustodyRefusal::InvalidInput)?;
        let CustodyClientFrame::CustodyOpen { binding_mode: mode } = open else {
            return Err(CustodyRefusal::InvalidInput.into());
        };
        if mode == BindingMode::DirectExporter {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        let node = rpc(context, &CustodyMeshRequest::NodeIdentity { record_hash: None })
            .await
            .map_err(|_| CustodyRefusal::AuthorityUnavailable)?;
        let CustodyServerFrame::NodeIdentity { record, audience, .. } = node else {
            return Err(CustodyRefusal::AuthorityUnavailable.into());
        };
        let Some(trusted) = material.node_public_key.as_deref() else {
            return Err(CustodyRefusal::AuthorityUnavailable.into());
        };
        let node = verify_node_identity_record(
            &record,
            &context.node_id,
            trusted,
            ramflux_node_core::now_unix_seconds(),
        )
        .map_err(|_| CustodyRefusal::AuthorityUnavailable)?;
        if !node.envelope().body.channel_binding_modes.contains(&mode) {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        if mode == BindingMode::NoChannelBinding {
            if !material.allow_unbound {
                return Err(CustodyRefusal::BindingRefused.into());
            }
            crate::ingress_log::record(crate::ingress_log::Event::NoChannelBinding);
        }
        let signer = if mode == BindingMode::HomeRelayReceipt {
            let Some(encoded) = material.proxy_seed.as_ref() else {
                return Err(CustodyRefusal::InvalidInput.into());
            };
            let bytes = Zeroizing::new(
                ramflux_protocol::decode_base64url(encoded)
                    .map_err(|_| CustodyRefusal::InvalidInput)?,
            );
            if bytes.len() != 32 {
                return Err(CustodyRefusal::InvalidInput.into());
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
                return Err(CustodyRefusal::BindingRefused.into());
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
                connection: ramflux_protocol::encode_base64url(
                    ramflux_crypto::random_32()
                        .map_err(|_| CustodyRefusal::AuthorityUnavailable)?,
                ),
                mode,
                session_ids: BTreeSet::new(),
                handoff_session: None,
                router: Some(context.router.clone()),
                auth_deadline,
                authenticated: false,
                handed_off: false,
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
            self.handoff_session =
                Some(GatewayGrant::granted(session.clone(), self.connection.clone()));
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
                    return Err(CustodyRefusal::BindingRefused.into());
                }
                let actual = observed.ok_or(CustodyRefusal::BindingRefused)?;
                if actual != proof.body.transport_binding {
                    return Err(CustodyRefusal::BindingRefused.into());
                }
                let receipt = if self.mode == BindingMode::HomeRelayReceipt {
                    Some(Box::new(sign_proxy_acceptance(
                        self.signer.as_ref().ok_or(CustodyRefusal::AuthorityUnavailable)?,
                        &self.node,
                        &proof,
                        actual,
                        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                        ramflux_node_core::now_unix_seconds(),
                    )?))
                } else {
                    None
                };
                CustodyMeshRequest::Prove {
                    action,
                    proof,
                    receipt,
                    connection_id: self.connection.clone(),
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
    let bytes = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)
        .map_err(|_| CustodyRefusal::InvalidInput)?;
    Ok(Some(bytes.try_into().map_err(|_| CustodyRefusal::InvalidInput)?))
}
type Limiter = std::sync::Arc<ramflux_node_core::CustodyIngressLimiter>;
#[derive(Clone)]
pub(crate) struct Pools {
    pub(crate) tcp: Limiter,
    pub(crate) quic: Limiter,
}
pub(crate) fn initialize() -> anyhow::Result<Option<Pools>> {
    initialize_if_configured(std::env::var_os("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY").as_deref(), || {
        let settings = ramflux_node_core::CustodyPoolSettings::from_env()?;
        ramflux_node_core::custody_listener_resources(settings, 2)?;
        Ok(Pools { tcp: settings.limiter(), quic: settings.limiter() })
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
    if let CustodyServerFrame::Refused { code, .. } = &response {
        log_refusal(code);
    }
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ =
            tokio::time::timeout(CLOSE_WRITE_BUDGET, write_custody_tcp_frame(stream, &bytes)).await;
    }
    finish_tcp(stream).await;
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
    if let CustodyServerFrame::Refused { code, .. } = &refusal {
        log_refusal(code);
    }
    if let Ok(bytes) = serde_json::to_vec(&refusal) {
        let _ =
            tokio::time::timeout(CLOSE_WRITE_BUDGET, write_custody_tcp_frame(send, &bytes)).await;
    }
    let _ = send.finish();
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
    /// The session guard now owns the lease. Drop must not disconnect it.
    fn retain_after_handoff(&mut self) {
        self.handed_off = true;
    }
    fn deadline(&self) -> tokio::time::Instant {
        if self.authenticated {
            tokio::time::Instant::now() + IO_TIMEOUT
        } else {
            self.auth_deadline
        }
    }
}
fn spawn_disconnect(router: crate::RouterMeshClient, connection_id: String) {
    if connection_id.is_empty() {
        return;
    }
    let request = CustodyMeshRequest::Disconnect { connection_id };
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
impl Drop for Proxy {
    fn drop(&mut self) {
        if self.handed_off {
            return;
        }
        let Some(router) = self.router.clone() else { return };
        spawn_disconnect(router, std::mem::take(&mut self.connection));
    }
}
/// Removes the router lease when the gateway session that kept it ends.
pub(crate) struct NativeLeaseGuard {
    router: crate::RouterMeshClient,
    connection_id: String,
}
impl Drop for NativeLeaseGuard {
    fn drop(&mut self) {
        spawn_disconnect(self.router.clone(), std::mem::take(&mut self.connection_id));
    }
}
pub(crate) fn hold_native_lease(
    context: &crate::GatewayQuicContext,
    grant: Option<&GatewayGrant>,
) -> Option<NativeLeaseGuard> {
    let connection_id = grant?.connection_id().to_owned();
    if connection_id.is_empty() {
        return None;
    }
    Some(NativeLeaseGuard { router: context.router.clone(), connection_id })
}
enum DriveEnd {
    Finished,
    Handoff { grant: Box<GatewayGrant>, first: Box<ramflux_node_core::GatewayClientFrame> },
}

fn custody_deadline_error(code: CustodyRefusal) -> anyhow::Error {
    anyhow::Error::from(code)
}

async fn write_deadline(
    deadline: tokio::time::Instant,
    write: impl std::future::Future<Output = Result<(), ramflux_transport::TransportError>>,
) -> anyhow::Result<()> {
    tokio::time::timeout_at(deadline, write)
        .await
        .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?
        .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))
}

async fn tcp_drive(
    stream: &mut GatewayTcpTlsStream,
    context: &GatewayQuicContext,
    first: &[u8],
    capacity: &ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<DriveEnd> {
    let (mut proxy, response) = tokio::time::timeout_at(
        tokio::time::Instant::from_std(capacity.auth_deadline()),
        Proxy::open(context, first),
    )
    .await
    .map_err(|_| custody_deadline_error(CustodyRefusal::AuthorityUnavailable))??;
    proxy.auth_deadline = tokio::time::Instant::from_std(capacity.auth_deadline());
    let encoded = serde_json::to_vec(&response).map_err(|_| CustodyRefusal::InvalidInput)?;
    write_deadline(proxy.deadline(), write_custody_tcp_frame(stream, &encoded)).await?;
    for _ in 0..MAX_CUSTODY_SESSION_FRAMES {
        let deadline = proxy.deadline();
        let bytes = tokio::time::timeout_at(deadline, read_custody_tcp_frame(stream))
            .await
            .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?
            .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?;
        let frame: CustodyClientFrame =
            decode(&bytes, MAX_CUSTODY_FRAME_BYTES).map_err(|_| CustodyRefusal::InvalidInput)?;
        if let CustodyClientFrame::GatewayHandoff { session_id } = &frame {
            let grant = proxy.handoff(session_id)?;
            let first = tokio::time::timeout_at(deadline, read_custody_tcp_frame(stream))
                .await
                .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?
                .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?;
            let first =
                ramflux_protocol::parse_i_json(&first).map_err(|_| CustodyRefusal::InvalidInput)?;
            proxy.retain_after_handoff();
            return Ok(DriveEnd::Handoff { grant: Box::new(grant), first: Box::new(first) });
        }
        let observed = nonce(&frame)?
            .map(|nonce| {
                ramflux_transport::custody_tcp_exporter(stream, &nonce)
                    .map(|exporter| branch_exporter_hash(&exporter))
            })
            .transpose()
            .map_err(|_| CustodyRefusal::BindingRefused)?;
        let response = tokio::time::timeout_at(
            deadline,
            proxy.frame(context, frame, observed.as_deref(), capacity),
        )
        .await
        .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))??;
        let saturated =
            matches!(response, CustodyServerFrame::Refused { code: CustodyRefusal::Busy, .. });
        let encoded = serde_json::to_vec(&response).map_err(|_| CustodyRefusal::InvalidInput)?;
        write_deadline(deadline, write_custody_tcp_frame(stream, &encoded)).await?;
        if saturated {
            if let CustodyServerFrame::Refused { code, .. } = &response {
                log_refusal(code);
            }
            return Ok(DriveEnd::Finished);
        }
    }
    Err(custody_deadline_error(CustodyRefusal::FrameLimit))
}

async fn quic_drive(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    connection: &quinn::Connection,
    context: &GatewayQuicContext,
    first: &[u8],
    capacity: &ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<DriveEnd> {
    let (mut proxy, response) = tokio::time::timeout_at(
        tokio::time::Instant::from_std(capacity.auth_deadline()),
        Proxy::open(context, first),
    )
    .await
    .map_err(|_| custody_deadline_error(CustodyRefusal::AuthorityUnavailable))??;
    proxy.auth_deadline = tokio::time::Instant::from_std(capacity.auth_deadline());
    let encoded = serde_json::to_vec(&response).map_err(|_| CustodyRefusal::InvalidInput)?;
    write_deadline(proxy.deadline(), write_custody_tcp_frame(send, &encoded)).await?;
    for _ in 0..MAX_CUSTODY_SESSION_FRAMES {
        let deadline = proxy.deadline();
        let bytes = tokio::time::timeout_at(deadline, read_custody_tcp_frame(recv))
            .await
            .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?
            .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?;
        let frame: CustodyClientFrame =
            decode(&bytes, MAX_CUSTODY_FRAME_BYTES).map_err(|_| CustodyRefusal::InvalidInput)?;
        if let CustodyClientFrame::GatewayHandoff { session_id } = &frame {
            let grant = proxy.handoff(session_id)?;
            let first = tokio::time::timeout_at(deadline, read_custody_tcp_frame(recv))
                .await
                .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?
                .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))?;
            let first =
                ramflux_protocol::parse_i_json(&first).map_err(|_| CustodyRefusal::InvalidInput)?;
            proxy.retain_after_handoff();
            return Ok(DriveEnd::Handoff { grant: Box::new(grant), first: Box::new(first) });
        }
        let observed = nonce(&frame)?
            .map(|nonce| {
                ramflux_transport::custody_quic_exporter(connection, &nonce)
                    .map(|exporter| branch_exporter_hash(&exporter))
            })
            .transpose()
            .map_err(|_| CustodyRefusal::BindingRefused)?;
        let response = tokio::time::timeout_at(
            deadline,
            proxy.frame(context, frame, observed.as_deref(), capacity),
        )
        .await
        .map_err(|_| custody_deadline_error(CustodyRefusal::AbortedRetrySafe))??;
        let saturated =
            matches!(response, CustodyServerFrame::Refused { code: CustodyRefusal::Busy, .. });
        let encoded = serde_json::to_vec(&response).map_err(|_| CustodyRefusal::InvalidInput)?;
        write_deadline(deadline, write_custody_tcp_frame(send, &encoded)).await?;
        if saturated {
            if let CustodyServerFrame::Refused { code, .. } = &response {
                log_refusal(code);
            }
            return Ok(DriveEnd::Finished);
        }
    }
    Err(custody_deadline_error(CustodyRefusal::FrameLimit))
}

async fn supervise<F>(
    capacity: &ramflux_node_core::CustodyIngressPermit,
    drive: F,
) -> anyhow::Result<DriveEnd>
where
    F: std::future::Future<Output = anyhow::Result<DriveEnd>>,
{
    let session_deadline = tokio::time::Instant::now() + Duration::from_mins(15);
    let drive = drive;
    tokio::pin!(drive);
    tokio::select! {
        biased;
        () = capacity.revoked() => Err(custody_deadline_error(CustodyRefusal::AbortedRetrySafe)),
        () = tokio::time::sleep_until(session_deadline) => {
            Err(custody_deadline_error(CustodyRefusal::AbortedRetrySafe))
        }
        result = &mut drive => result,
    }
}

pub(crate) async fn tcp(
    mut stream: GatewayTcpTlsStream,
    context: GatewayQuicContext,
    first: &[u8],
    capacity: ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<()> {
    let outcome = {
        let drive = tcp_drive(&mut stream, &context, first, &capacity);
        supervise(&capacity, drive).await
    };
    match outcome {
        Ok(DriveEnd::Finished) => {
            finish_tcp(&mut stream).await;
            Ok(())
        }
        Ok(DriveEnd::Handoff { grant, first }) => {
            let (recv, send) = tokio::io::split(stream);
            Box::pin(crate::session::handle_gateway_custody_session_transport(
                Box::new(send),
                Box::new(recv),
                context,
                *first,
                *grant,
            ))
            .await
        }
        Err(error) => {
            refuse_tcp(&mut stream, &classify_custody_close(&error)).await;
            Ok(())
        }
    }
}

pub(crate) async fn quic(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connection: quinn::Connection,
    context: GatewayQuicContext,
    first: &[u8],
    capacity: ramflux_node_core::CustodyIngressPermit,
) -> anyhow::Result<()> {
    let outcome = {
        let drive = quic_drive(&mut send, &mut recv, &connection, &context, first, &capacity);
        supervise(&capacity, drive).await
    };
    match outcome {
        Ok(DriveEnd::Finished) => {
            finish_quic(&mut send, &mut recv).await;
            Ok(())
        }
        Ok(DriveEnd::Handoff { grant, first }) => {
            Box::pin(crate::session::handle_gateway_custody_session_transport(
                Box::new(send),
                Box::new(recv),
                context,
                *first,
                *grant,
            ))
            .await
        }
        Err(error) => {
            refuse_quic(&mut send, &mut recv, &classify_custody_close(&error)).await;
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "custody_close_tests.rs"]
mod close_tests;
#[cfg(test)]
#[path = "custody_tests.rs"]
pub(crate) mod tests;
