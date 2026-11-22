// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each custody early close writes its typed refusal and a TLS `close_notify`.
#![allow(clippy::large_futures)]
use super::tests::{Fixture, tcp_pair};
use super::{
    OpenMaterial, Pools, TEST_OPEN_MATERIAL, TEST_RPC, TestRpc, admit_tcp, tcp, unavailable,
};
use ramflux_crypto::custody::sign_node_identity_record;
use ramflux_protocol::custody::{
    BindingMode, CustodyClientFrame, CustodyRefusal, CustodyServerFrame, NodeIdentityRecord,
    ProxyKey, ReceiptKeyStatus, decode,
};
use ramflux_transport::{GatewayTcpTlsStream, read_custody_tcp_frame, write_custody_tcp_frame};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn material(key: Option<&str>, unbound: bool, seed: Option<&str>) -> OpenMaterial {
    OpenMaterial {
        node_public_key: key.map(str::to_owned),
        allow_unbound: unbound,
        proxy_seed: seed.map(|value| Zeroizing::new(value.to_owned())),
    }
}

fn signed_record(
    modes: Vec<BindingMode>,
    with_proxy: bool,
) -> Result<(ramflux_protocol::custody::Envelope<NodeIdentityRecord>, String)> {
    let now = ramflux_node_core::now_unix_seconds();
    let node_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let proxy_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public = ramflux_protocol::encode_base64url(node_key.verifying_key().to_bytes());
    let proxy_keys = if with_proxy {
        vec![ProxyKey {
            key_id: ramflux_protocol::encode_base64url([10; 32]),
            public_key: ramflux_protocol::encode_base64url(proxy_key.verifying_key().to_bytes()),
            not_before: now - 1,
            sign_until: now + 300,
            overlap_until: now + 605_100,
            status: ReceiptKeyStatus::Active,
            proxy_id: "ramflux-gateway".into(),
            audiences: vec!["close-node".into()],
        }]
    } else {
        vec![]
    };
    let record = sign_node_identity_record(
        &node_key,
        NodeIdentityRecord {
            schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: "close-node".into(),
            node_signing_public_key: public.clone(),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: now,
            receipt_keys: vec![],
            revoked_receipt_key_ids: vec![],
            proxy_keys,
            revoked_proxy_key_ids: vec![],
            channel_binding_modes: modes,
        },
    )?;
    Ok((record, public))
}

fn identity(
    record: ramflux_protocol::custody::Envelope<NodeIdentityRecord>,
    mode: BindingMode,
) -> CustodyServerFrame {
    CustodyServerFrame::NodeIdentity {
        record: Box::new(record),
        audience: "close-node".into(),
        binding_mode: mode,
        proxy_key_custody: Some("software".into()),
    }
}

fn context() -> Result<(ramflux_test_support::TestPath, crate::GatewayQuicContext)> {
    let root = ramflux_test_support::TestPath::new()?;
    let store_path = root.join("gateway.redb");
    let store = Arc::new(ramflux_node_core::GatewayRedbStore::open(&store_path)?);
    let config = ramflux_node_core::NodeServiceConfig {
        send_authority: None,
        node_id: "close-node".to_owned(),
        service_id: "ramflux-gateway".to_owned(),
        redb_path: "gateway.redb".to_owned(),
        node_service_signing_seed_b64url: None,
        gateway_client_capabilities: None,
        mesh: ramflux_node_core::MeshConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            ca_cert: "ca.pem".to_owned(),
            service_cert: "gateway.pem".to_owned(),
            service_key: "gateway-key.pem".to_owned(),
            allowed_service_ids: ["ramflux-gateway".to_owned()].into_iter().collect(),
            endpoints: [("ramflux-router".to_owned(), "127.0.0.1:1".to_owned())]
                .into_iter()
                .collect(),
        },
        gateway: Some(ramflux_node_core::GatewayConfig {
            replay:
                ramflux_node_core::test_support::federation_fixtures::gateway_replay_fixture_config(
                ),
            pre_auth: None,
            public_listen_addr: "127.0.0.1:0".to_owned(),
        }),
        signaling: None,
        relay: None,
    };
    Ok(crate::GatewayQuicContext {
        custody: None,
        node_id: "close-node".to_owned(),
        gateway_id: "ramflux-gateway".to_owned(),
        peers: crate::GatewayPeerDirectory::empty(&config),
        router: crate::RouterMeshClient {
            endpoint: "127.0.0.1:1".to_owned(),
            server_name: "ramflux-router".to_owned(),
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: "ca.pem".into(),
                service_cert: "gateway.pem".into(),
                service_key: "gateway-key.pem".into(),
            },
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: None,
        },
        notify: crate::NotifyHttpClient {
            endpoint: "http://127.0.0.1:1".to_owned(),
            signer: ramflux_node_core::NodeServiceSigningKey::from_seed([0x42; 32]),
            mesh: None,
            wake_calls: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        },
        state: Arc::new(Mutex::new(ramflux_node_core::GatewayState::new())),
        store,
        hub: Arc::new(crate::GatewaySessionHub::default()),
        remote_addr: "127.0.0.1:50000".parse()?,
    })
    .map(|gateway| (root, gateway))
}

fn permit() -> Result<ramflux_node_core::CustodyIngressPermit> {
    let limiter = ramflux_node_core::CustodyIngressLimiter::new(4);
    Ok(limiter.acquire("127.0.0.1".parse()?, None, std::time::Instant::now())?)
}

async fn deadline<T>(work: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(std::time::Duration::from_secs(5), work).await?
}

async fn write_bytes(stream: &mut GatewayTcpTlsStream, body: &[u8]) -> Result {
    write_custody_tcp_frame(stream, body).await?;
    Ok(())
}

async fn read_codes(stream: &mut GatewayTcpTlsStream, expected: &[CustodyRefusal]) -> Result {
    let mut index = 0;
    loop {
        let bytes = read_custody_tcp_frame(stream).await?;
        let frame: CustodyServerFrame =
            decode(&bytes, ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES)?;
        match frame {
            CustodyServerFrame::NodeIdentity { .. } => {}
            CustodyServerFrame::Refused { code, .. } => {
                let Some(want) = expected.get(index) else {
                    return Err(format!("unexpected refusal {code:?}").into());
                };
                if &code != want {
                    return Err(format!("refusal {code:?} != {want:?}").into());
                }
                index += 1;
                if index == expected.len() {
                    return Ok(());
                }
            }
            other => return Err(format!("unexpected custody frame {other:?}").into()),
        }
    }
}

async fn assert_close_notify(stream: &mut GatewayTcpTlsStream) -> Result {
    let mut buf = [0u8; 8];
    match stream.read(&mut buf).await {
        Ok(0) => Ok(()),
        other => Err(format!("expected TLS close_notify EOF, got {other:?}").into()),
    }
}

async fn pipeline(stream: &mut GatewayTcpTlsStream, frames: &[Vec<u8>]) -> Result {
    for frame in frames {
        write_bytes(stream, frame).await?;
    }
    write_bytes(stream, &vec![b'x'; 4300]).await?;
    stream.flush().await?;
    Ok(())
}

async fn run_tcp(
    preface: Vec<u8>,
    follow: Vec<Vec<u8>>,
    opened: OpenMaterial,
    rpc: Vec<TestRpc>,
    revoke: bool,
    expected: Vec<CustodyRefusal>,
) -> Result {
    let fixture = Fixture::new()?;
    let (mut client, mut server) = tcp_pair(&fixture).await?;
    let mut frames = vec![preface.clone()];
    frames.extend(follow);
    pipeline(&mut client, &frames).await?;
    let read = read_custody_tcp_frame(&mut server).await?;
    if read != preface {
        return Err("server did not observe the pipelined preface".into());
    }
    let held = permit()?;
    if revoke {
        held.revoke();
    }
    let (root, gateway) = context()?;
    TEST_OPEN_MATERIAL
        .scope(
            opened,
            TEST_RPC.scope(
                std::cell::RefCell::new(std::collections::VecDeque::from(rpc)),
                async move {
                    let result: Result = tcp(server, gateway, &read, held)
                        .await
                        .map_err(|error| error.to_string().into());
                    result
                },
            ),
        )
        .await?;
    drop(root);
    read_codes(&mut client, &expected).await?;
    assert_close_notify(&mut client).await
}

fn home_open() -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&CustodyClientFrame::CustodyOpen {
        binding_mode: BindingMode::HomeRelayReceipt,
    })?)
}

fn ready_material(public: &str) -> OpenMaterial {
    material(Some(public), false, Some(&ramflux_protocol::encode_base64url([9; 32])))
}

async fn refused_open(
    mode: BindingMode,
    opened: OpenMaterial,
    rpc: Vec<TestRpc>,
    code: CustodyRefusal,
) -> Result {
    let preface = serde_json::to_vec(&CustodyClientFrame::CustodyOpen { binding_mode: mode })?;
    deadline(run_tcp(preface, vec![], opened, rpc, false, vec![code])).await
}

#[tokio::test]
async fn admit_without_pools_refuses_unsupported_and_closes() -> Result {
    deadline(async {
        let fixture = Fixture::new()?;
        let (mut client, mut server) = tcp_pair(&fixture).await?;
        pipeline(&mut client, &[]).await?;
        let admitted = admit_tcp(&mut server, "127.0.0.1".parse()?, None).await?;
        if admitted.is_some() {
            return Err("unconfigured custody admitted a connection".into());
        }
        read_codes(&mut client, &[CustodyRefusal::Unsupported]).await?;
        assert_eq!(unavailable(), super::refused(&CustodyRefusal::Unsupported));
        assert_close_notify(&mut client).await
    })
    .await
}

#[tokio::test]
async fn admit_when_saturated_refuses_busy_and_closes() -> Result {
    deadline(async {
        let fixture = Fixture::new()?;
        let (mut client, mut server) = tcp_pair(&fixture).await?;
        pipeline(&mut client, &[]).await?;
        let limiter = ramflux_node_core::CustodyIngressLimiter::new(1);
        let held = limiter.acquire("198.51.100.8".parse()?, None, std::time::Instant::now())?;
        let pools = Pools { tcp: Arc::clone(&limiter), quic: Arc::clone(&limiter) };
        let admitted = admit_tcp(&mut server, "198.51.100.8".parse()?, Some(&pools)).await?;
        drop(held);
        if admitted.is_some() {
            return Err("a full handshake pool admitted another custody connection".into());
        }
        let bytes = read_custody_tcp_frame(&mut client).await?;
        let frame: CustodyServerFrame = decode(&bytes, 4096)?;
        let CustodyServerFrame::Refused { code, retry, .. } = frame else {
            return Err(format!("busy admission did not refuse: {frame:?}").into());
        };
        if code != CustodyRefusal::Busy || retry.is_none() {
            return Err(format!("busy admission lost its retry hint: {code:?} {retry:?}").into());
        }
        assert_close_notify(&mut client).await
    })
    .await
}

#[tokio::test]
async fn bad_preface_refuses_invalid_input_and_closes() -> Result {
    deadline(run_tcp(
        b"not-a-custody-frame".to_vec(),
        vec![],
        material(None, false, None),
        vec![],
        false,
        vec![CustodyRefusal::InvalidInput],
    ))
    .await
}

#[tokio::test]
async fn direct_exporter_refuses_binding_and_closes() -> Result {
    refused_open(
        BindingMode::DirectExporter,
        material(None, false, None),
        vec![],
        CustodyRefusal::BindingRefused,
    )
    .await
}

#[tokio::test]
async fn node_identity_rpc_failure_refuses_authority_and_closes() -> Result {
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(None, false, None),
        vec![TestRpc::Fail],
        CustodyRefusal::AuthorityUnavailable,
    )
    .await
}

#[tokio::test]
async fn node_identity_wrong_frame_refuses_authority_and_closes() -> Result {
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(None, false, None),
        vec![TestRpc::Frame(CustodyServerFrame::Closed)],
        CustodyRefusal::AuthorityUnavailable,
    )
    .await
}

#[tokio::test]
async fn missing_node_key_refuses_authority_and_closes() -> Result {
    let (record, _) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(None, false, None),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        CustodyRefusal::AuthorityUnavailable,
    )
    .await
}

#[tokio::test]
async fn untrusted_node_key_refuses_authority_and_closes() -> Result {
    let (record, _) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let wrong = ramflux_protocol::encode_base64url([1; 32]);
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(Some(&wrong), false, None),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        CustodyRefusal::AuthorityUnavailable,
    )
    .await
}

#[tokio::test]
async fn unadvertised_mode_refuses_binding_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::NoChannelBinding], false)?;
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(Some(&public), false, None),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        CustodyRefusal::BindingRefused,
    )
    .await
}

#[tokio::test]
async fn unbound_without_opt_in_refuses_binding_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::NoChannelBinding], false)?;
    refused_open(
        BindingMode::NoChannelBinding,
        material(Some(&public), false, None),
        vec![TestRpc::Frame(identity(record, BindingMode::NoChannelBinding))],
        CustodyRefusal::BindingRefused,
    )
    .await
}

#[tokio::test]
async fn missing_proxy_seed_refuses_invalid_input_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(Some(&public), false, None),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        CustodyRefusal::InvalidInput,
    )
    .await
}

#[tokio::test]
async fn short_proxy_seed_refuses_invalid_input_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let short = ramflux_protocol::encode_base64url([1, 2, 3]);
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(Some(&public), false, Some(&short)),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        CustodyRefusal::InvalidInput,
    )
    .await
}

#[tokio::test]
async fn unauthorized_proxy_key_refuses_binding_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let other = ramflux_protocol::encode_base64url([7; 32]);
    refused_open(
        BindingMode::HomeRelayReceipt,
        material(Some(&public), false, Some(&other)),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        CustodyRefusal::BindingRefused,
    )
    .await
}

#[tokio::test]
async fn handoff_without_session_refuses_session_required_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let follow =
        serde_json::to_vec(&CustodyClientFrame::GatewayHandoff { session_id: "missing".into() })?;
    deadline(run_tcp(
        home_open()?,
        vec![follow],
        ready_material(&public),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        false,
        vec![CustodyRefusal::SessionRequired],
    ))
    .await
}

#[tokio::test]
async fn undecodable_followup_refuses_invalid_input_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    deadline(run_tcp(
        home_open()?,
        vec![b"{}".to_vec()],
        ready_material(&public),
        vec![TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt))],
        false,
        vec![CustodyRefusal::InvalidInput],
    ))
    .await
}

#[tokio::test]
async fn router_busy_after_open_refuses_busy_and_closes() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let follow = serde_json::to_vec(&CustodyClientFrame::NodeIdentity { record_hash: None })?;
    deadline(run_tcp(
        home_open()?,
        vec![follow],
        ready_material(&public),
        vec![
            TestRpc::Frame(identity(record, BindingMode::HomeRelayReceipt)),
            TestRpc::Frame(super::refused(&CustodyRefusal::Busy)),
        ],
        false,
        vec![CustodyRefusal::Busy],
    ))
    .await
}

#[tokio::test]
async fn revoked_admission_refuses_aborted_and_closes() -> Result {
    deadline(run_tcp(
        home_open()?,
        vec![],
        material(None, false, None),
        vec![],
        true,
        vec![CustodyRefusal::AbortedRetrySafe],
    ))
    .await
}

#[derive(Clone, Copy)]
enum ProbeMode {
    /// One short read, then every later read fills the whole offered buffer.
    Excess,
    Partial(usize),
    Stall,
}

struct Probe {
    peer: usize,
    filled: usize,
    mode: ProbeMode,
    offers: Vec<(usize, usize)>,
}

impl AsyncRead for Probe {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let offered = buf.remaining();
        this.offers.push((offered, this.filled));
        let room = match this.mode {
            ProbeMode::Stall if this.filled > 0 => return Poll::Pending,
            ProbeMode::Stall => 1,
            ProbeMode::Excess if this.filled == 0 => 1,
            ProbeMode::Partial(chunk) => chunk,
            ProbeMode::Excess => offered,
        };
        let room = room.min(this.peer).min(offered);
        if room == 0 {
            return Poll::Ready(Ok(()));
        }
        let scratch = [0x5a_u8; 4096];
        buf.put_slice(&scratch[..room]);
        this.peer -= room;
        this.filled += room;
        Poll::Ready(Ok(()))
    }
}

fn cap_respected(probe: &Probe) -> bool {
    probe.offers.iter().all(|(offered, before)| {
        before < &super::CLOSE_DRAIN_CAP && *offered <= super::CLOSE_DRAIN_CAP - before
    })
}

async fn drained(mode: ProbeMode, peer: usize) -> Probe {
    let mut probe = Probe { peer, filled: 0, mode, offers: Vec::new() };
    super::drain_unread(&mut probe).await;
    probe
}

#[tokio::test]
async fn drain_respects_the_byte_cap_on_partial_excess_and_stall() -> Result {
    deadline(async {
        let cap = super::CLOSE_DRAIN_CAP;
        let excess = drained(ProbeMode::Excess, cap + 4096).await;
        let partial = drained(ProbeMode::Partial(3), cap + 4096).await;
        let stall = drained(ProbeMode::Stall, cap + 4096).await;
        if excess.filled != cap || !cap_respected(&excess) {
            return Err(format!(
                "excess drain filled {} offers {:?}",
                excess.filled, excess.offers
            )
            .into());
        }
        if partial.filled != cap || !cap_respected(&partial) || partial.offers.len() < 3 {
            return Err(format!("partial drain filled {}", partial.filled).into());
        }
        if stall.filled != 1 || !cap_respected(&stall) {
            return Err(format!("stall drain filled {}", stall.filled).into());
        }
        Ok(())
    })
    .await
}

fn limit_script(open: CustodyServerFrame) -> Vec<TestRpc> {
    let mut rpc = Vec::with_capacity(super::MAX_CUSTODY_SESSION_FRAMES + 1);
    rpc.push(TestRpc::Frame(open));
    for _ in 0..super::MAX_CUSTODY_SESSION_FRAMES {
        rpc.push(TestRpc::Frame(CustodyServerFrame::Closed));
    }
    rpc
}

async fn read_frame_limit(stream: &mut GatewayTcpTlsStream) -> Result {
    let mut opened = false;
    let mut closed = 0usize;
    loop {
        let bytes = read_custody_tcp_frame(stream).await?;
        let frame: CustodyServerFrame =
            decode(&bytes, ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES)?;
        match frame {
            CustodyServerFrame::NodeIdentity { .. } if !opened => opened = true,
            CustodyServerFrame::Closed => closed += 1,
            CustodyServerFrame::Refused { code: CustodyRefusal::FrameLimit, .. }
                if opened && closed == super::MAX_CUSTODY_SESSION_FRAMES =>
            {
                return assert_close_notify(stream).await;
            }
            other => {
                return Err(format!("frame limit saw {other:?} after {closed} closed").into());
            }
        }
    }
}

#[tokio::test]
async fn tcp_frame_limit_refuses_after_successful_responses() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let follow = serde_json::to_vec(&CustodyClientFrame::NodeIdentity { record_hash: None })?;
    deadline(async move {
        let fixture = Fixture::new()?;
        let (mut client, mut server) = tcp_pair(&fixture).await?;
        let mut frames = vec![home_open()?];
        frames.extend(vec![follow; super::MAX_CUSTODY_SESSION_FRAMES]);
        pipeline(&mut client, &frames).await?;
        let read = read_custody_tcp_frame(&mut server).await?;
        let held = permit()?;
        let (root, gateway) = context()?;
        TEST_OPEN_MATERIAL
            .scope(
                ready_material(&public),
                TEST_RPC.scope(
                    std::cell::RefCell::new(std::collections::VecDeque::from(limit_script(
                        identity(record, BindingMode::HomeRelayReceipt),
                    ))),
                    async move {
                        let result: Result = tcp(server, gateway, &read, held)
                            .await
                            .map_err(|error| error.to_string().into());
                        result
                    },
                ),
            )
            .await?;
        drop(root);
        read_frame_limit(&mut client).await
    })
    .await
}

struct QuicPair {
    _server: quinn::Endpoint,
    _client: quinn::Endpoint,
    outgoing: quinn::Connection,
    incoming: quinn::Connection,
}

async fn quic_ends(fixture: &Fixture, narrow: bool) -> Result<QuicPair> {
    let server = quinn::Endpoint::server(
        ramflux_transport::quic_gateway_server_config(fixture.tls())?,
        "127.0.0.1:0".parse()?,
    )?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    let mut config = ramflux_transport::quic_gateway_client_config(&fixture.tls().ca_cert)?;
    if narrow {
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(1));
        config.transport_config(Arc::new(transport));
    }
    client.set_default_client_config(config);
    let outgoing = client.connect(server.local_addr()?, "localhost")?;
    let incoming = async { server.accept().await.ok_or("incoming")?.await.map_err(Into::into) };
    let (outgoing, incoming): (_, Result<quinn::Connection>) = tokio::join!(outgoing, incoming);
    Ok(QuicPair { _server: server, _client: client, outgoing: outgoing?, incoming: incoming? })
}

fn poll_once<T>(read: Pin<&mut impl std::future::Future<Output = T>>) -> Poll<T> {
    let waker = std::task::Waker::noop();
    let mut context = Context::from_waker(waker);
    read.poll(&mut context)
}

#[tokio::test]
async fn quic_unsupported_refusal_is_bounded_without_credit_and_finishes_with_credit() -> Result {
    deadline(async {
        let fixture = Fixture::new()?;
        let narrow = quic_ends(&fixture, true).await?;
        let (mut tx, mut rx) = narrow.outgoing.open_bi().await?;
        write_bytes_quic(&mut tx, &home_open()?).await?;
        let (root, gateway) = context()?;
        let admitted = std::time::Instant::now();
        let (send, recv) = narrow.incoming.accept_bi().await?;
        crate::session::handle_gateway_quic_stream_with_connection(
            send,
            recv,
            gateway,
            narrow.incoming.clone(),
            admitted,
        )
        .await
        .map_err(|error| error.to_string())?;
        drop(root);
        let read = read_custody_tcp_frame(&mut rx);
        tokio::pin!(read);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        // One byte of receive credit cannot carry the length prefix. The bounded
        // write then finishes the stream, so the client sees early EOF.
        match poll_once(read.as_mut()) {
            Poll::Pending => {}
            Poll::Ready(Ok(frame)) => {
                return Err(format!(
                    "one byte of stream credit still delivered a refusal frame: {frame:?}"
                )
                .into());
            }
            Poll::Ready(Err(error)) => {
                let message = error.to_string();
                if !message.contains("early eof") {
                    return Err(format!(
                        "withheld credit failed before the bounded close: {message}"
                    )
                    .into());
                }
            }
        }
        drop(narrow);
        let pair = quic_ends(&fixture, false).await?;
        let (mut tx, mut rx) = pair.outgoing.open_bi().await?;
        write_bytes_quic(&mut tx, &home_open()?).await?;
        let (root, gateway) = context()?;
        let admitted = std::time::Instant::now();
        let incoming = pair.incoming.clone();
        let server = async {
            let (send, recv) = incoming.accept_bi().await?;
            let result: Result = crate::session::handle_gateway_quic_stream_with_connection(
                send, recv, gateway, incoming, admitted,
            )
            .await
            .map_err(|error| error.to_string().into());
            result
        };
        let client = async {
            let bytes = read_custody_tcp_frame(&mut rx).await?;
            let frame: CustodyServerFrame = decode(&bytes, 4096)?;
            if frame != unavailable() {
                return Err(format!("unconfigured quic did not refuse: {frame:?}").into());
            }
            match rx.read(&mut [0]).await {
                Ok(None) => Ok(()),
                other => Err(format!("expected FIN after unsupported, got {other:?}").into()),
            }
        };
        let (server, client) = tokio::join!(server, client);
        drop(root);
        server?;
        client
    })
    .await
}

async fn write_bytes_quic(send: &mut quinn::SendStream, body: &[u8]) -> Result {
    write_custody_tcp_frame(send, body).await?;
    Ok(())
}

#[tokio::test]
async fn quic_frame_limit_refuses_after_successful_responses() -> Result {
    let (record, public) = signed_record(vec![BindingMode::HomeRelayReceipt], true)?;
    let follow = serde_json::to_vec(&CustodyClientFrame::NodeIdentity { record_hash: None })?;
    deadline(async move {
        let fixture = Fixture::new()?;
        let pair = quic_ends(&fixture, false).await?;
        let (mut tx, mut rx) = pair.outgoing.open_bi().await?;
        write_bytes_quic(&mut tx, &home_open()?).await?;
        for _ in 0..super::MAX_CUSTODY_SESSION_FRAMES {
            write_bytes_quic(&mut tx, &follow).await?;
        }
        let (root, gateway) = context()?;
        let held = permit()?;
        let opened = ready_material(&public);
        let rpc = limit_script(identity(record, BindingMode::HomeRelayReceipt));
        let incoming = pair.incoming.clone();
        let server = async move {
            let (send, mut recv) = incoming.accept_bi().await?;
            let first = read_custody_tcp_frame(&mut recv).await?;
            let result: Result = TEST_OPEN_MATERIAL
                .scope(
                    opened,
                    TEST_RPC.scope(
                        std::cell::RefCell::new(std::collections::VecDeque::from(rpc)),
                        async move {
                            let result: Result =
                                super::quic(send, recv, incoming, gateway, &first, held)
                                    .await
                                    .map_err(|error| error.to_string().into());
                            result
                        },
                    ),
                )
                .await;
            result
        };
        let client = async {
            let mut opened = false;
            let mut closed = 0usize;
            loop {
                let bytes = read_custody_tcp_frame(&mut rx).await?;
                let frame: CustodyServerFrame =
                    decode(&bytes, ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES)?;
                match frame {
                    CustodyServerFrame::NodeIdentity { .. } if !opened => opened = true,
                    CustodyServerFrame::Closed => closed += 1,
                    CustodyServerFrame::Refused { code: CustodyRefusal::FrameLimit, .. }
                        if opened && closed == super::MAX_CUSTODY_SESSION_FRAMES =>
                    {
                        return match rx.read(&mut [0]).await {
                            Ok(None) => Ok(()),
                            other => {
                                Err(format!("expected FIN after frame limit, got {other:?}").into())
                            }
                        };
                    }
                    other => {
                        return Err(format!("quic frame limit saw {other:?} after {closed}").into());
                    }
                }
            }
        };
        let (server, client) = tokio::join!(server, client);
        drop(root);
        server?;
        client
    })
    .await
}
