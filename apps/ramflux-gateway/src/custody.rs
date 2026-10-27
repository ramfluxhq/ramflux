// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client-facing TLS observation by a separately authorized node proxy.
use crate::GatewayQuicContext;
use ramflux_crypto::custody::{
    VerifiedNodeRecord, branch_exporter_hash, sign_proxy_acceptance, verify_node_identity_record,
};
use ramflux_protocol::custody::{
    BindingMode, CUSTODY_RPC_PATH, CustodyClientFrame, CustodyMeshRequest, CustodyRefusal,
    CustodyServerFrame, MAX_CUSTODY_FRAME_BYTES, decode,
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
struct Proxy {
    node: VerifiedNodeRecord,
    signer: Option<ed25519_dalek::SigningKey>,
    connection: String,
    mode: BindingMode,
    session_ids: BTreeSet<String>,
    router: Option<crate::RouterMeshClient>,
    auth_deadline: tokio::time::Instant,
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
        if mode == BindingMode::NoChannelBinding {
            if std::env::var("RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING").as_deref() != Ok("1") {
                anyhow::bail!("unbound custody not opted in")
            }
            tracing::warn!(node_id=%context.node_id,peer=%context.remote_addr,"custody connection explicitly uses no_channel_binding");
        }
        let signer = if mode == BindingMode::HomeRelayReceipt {
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
                session_ids: BTreeSet::new(),
                router: Some(context.router.clone()),
                auth_deadline,
            },
            response,
        ))
    }
    async fn frame(
        &mut self,
        context: &GatewayQuicContext,
        frame: CustodyClientFrame,
        observed: Option<&str>,
    ) -> anyhow::Result<CustodyServerFrame> {
        let request = match self.prepare(frame, observed, context.remote_addr.ip()) {
            Ok(request) => request,
            Err(error) => {
                if let Some(code) = error.downcast_ref::<CustodyRefusal>() {
                    return Ok(CustodyServerFrame::Refused { code: code.clone() });
                }
                return Err(error);
            }
        };
        let result = rpc(context, &request).await?;
        if let CustodyServerFrame::SessionEstablished { session } = &result {
            // A connection retains only its latest session; an old id cannot become a bearer.
            self.session_ids.clear();
            self.session_ids.insert(session.session_id.clone());
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
                let receipt = if self.mode == BindingMode::HomeRelayReceipt {
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
            CustodyClientFrame::CustodyOpen { .. } => {
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
fn capacity() -> &'static std::sync::Arc<ramflux_node_core::CustodyIngressLimiter> {
    static LIMIT: std::sync::OnceLock<std::sync::Arc<ramflux_node_core::CustodyIngressLimiter>> =
        std::sync::OnceLock::new();
    LIMIT.get_or_init(|| ramflux_node_core::CustodyIngressLimiter::new(32))
}
impl Proxy {
    fn deadline(&self) -> tokio::time::Instant {
        if self.session_ids.is_empty() {
            self.auth_deadline
        } else {
            tokio::time::Instant::now() + IO_TIMEOUT
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
) -> anyhow::Result<()> {
    let capacity = capacity()
        .acquire(context.remote_addr.ip(), None, std::time::Instant::now())
        .ok_or_else(|| anyhow::anyhow!("custody source budget exhausted"))?;
    if capacity.is_revoked() {
        anyhow::bail!("custody admission revoked")
    }
    let (mut proxy, response) = tokio::time::timeout(
        ramflux_node_core::custody_auth_timeout()?,
        Proxy::open(&context, first),
    )
    .await??;
    tokio::time::timeout_at(
        proxy.deadline(),
        write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?),
    )
    .await??;
    for _ in 0..2048 {
        if capacity.is_revoked() {
            anyhow::bail!("custody admission revoked")
        }
        let deadline = proxy.deadline();
        let bytes =
            tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut stream)).await??;
        let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let observed = nonce(&frame)?
            .map(|nonce| {
                ramflux_transport::custody_tcp_exporter(&stream, &nonce)
                    .map(|exporter| branch_exporter_hash(&exporter))
            })
            .transpose()?;
        let response =
            tokio::time::timeout_at(deadline, proxy.frame(&context, frame, observed.as_deref()))
                .await??;
        if matches!(&response, CustodyServerFrame::SessionEstablished { .. }) {
            capacity.mark_authenticated();
        }
        tokio::time::timeout_at(
            deadline,
            write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?),
        )
        .await??;
    }
    Ok(())
}
async fn quic_inner(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connection: quinn::Connection,
    context: GatewayQuicContext,
    first: &[u8],
) -> anyhow::Result<()> {
    let capacity = capacity()
        .acquire(context.remote_addr.ip(), Some(connection.stable_id()), std::time::Instant::now())
        .ok_or_else(|| anyhow::anyhow!("custody source or connection budget exhausted"))?;
    if capacity.is_revoked() {
        anyhow::bail!("custody admission revoked")
    }
    let (mut proxy, response) = tokio::time::timeout(
        ramflux_node_core::custody_auth_timeout()?,
        Proxy::open(&context, first),
    )
    .await??;
    tokio::time::timeout_at(
        proxy.deadline(),
        write_custody_tcp_frame(&mut send, &serde_json::to_vec(&response)?),
    )
    .await??;
    for _ in 0..2048 {
        if capacity.is_revoked() {
            anyhow::bail!("custody admission revoked")
        }
        let deadline = proxy.deadline();
        let bytes = tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut recv)).await??;
        let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let observed = nonce(&frame)?
            .map(|nonce| {
                ramflux_transport::custody_quic_exporter(&connection, &nonce)
                    .map(|exporter| branch_exporter_hash(&exporter))
            })
            .transpose()?;
        let response =
            tokio::time::timeout_at(deadline, proxy.frame(&context, frame, observed.as_deref()))
                .await??;
        if matches!(&response, CustodyServerFrame::SessionEstablished { .. }) {
            capacity.mark_authenticated();
        }
        tokio::time::timeout_at(
            deadline,
            write_custody_tcp_frame(&mut send, &serde_json::to_vec(&response)?),
        )
        .await??;
    }
    Ok(())
}

pub(crate) async fn tcp(
    stream: GatewayTcpTlsStream,
    context: GatewayQuicContext,
    first: &[u8],
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_mins(15), Box::pin(tcp_inner(stream, context, first)))
        .await?
}
pub(crate) async fn quic(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    connection: quinn::Connection,
    context: GatewayQuicContext,
    first: &[u8],
) -> anyhow::Result<()> {
    tokio::time::timeout(
        Duration::from_mins(15),
        Box::pin(quic_inner(send, recv, connection, context, first)),
    )
    .await?
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
