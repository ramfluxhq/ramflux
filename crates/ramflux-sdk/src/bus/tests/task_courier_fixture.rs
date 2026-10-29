// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Loopback TLS gateway that counts real session opens and serves verified manifests.

use crate::bus::runtime_tests;
use crate::client::identity_authority::test_support::{public_manifest, sign_manifest};
use crate::prelude::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(super) type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
pub(super) struct Gateway {
    pub sessions: BTreeMap<String, usize>,
    pub sent: Vec<ramflux_protocol::Envelope>,
    pub inbox: Vec<GatewayInboxEntry>,
    pub acked: BTreeSet<String>,
    pub manifests: BTreeMap<String, Value>,
    pub protocol_errors: Vec<String>,
}

pub(super) struct Fixture {
    pub root: PathBuf,
    pub source: LocalBusAccountState,
    pub peer: LocalBusAccountState,
    pub sibling: LocalBusAccountState,
    pub gateway: Arc<Mutex<Gateway>>,
    _server: tokio::task::JoinHandle<()>,
}

fn account(root: &Path, id: &str) -> Result<LocalBusAccountState, SdkError> {
    runtime_tests::account(root, id, None, Arc::new(AtomicBool::new(false)))
}

pub(super) fn seed_pair(a: &RamfluxClient, b: &RamfluxClient) -> Result<(), SdkError> {
    let ai = a.owned_device_identity()?;
    let bi = b.owned_device_identity()?;
    let send = ramflux_crypto::DmSession::initiator(
        [17; 32],
        dm_device_id_hash(ai.device_id()),
        dm_device_id_hash(bi.device_id()),
        [3; 32],
    )?;
    let recv = ramflux_crypto::DmSession::recipient(
        [17; 32],
        dm_device_id_hash(bi.device_id()),
        dm_device_id_hash(ai.device_id()),
        [3; 32],
    )?;
    a.persist_pair(&ai, &bi, &[4; 32], &send)?;
    b.persist_pair(&bi, &ai, &[4; 32], &recv)?;
    Ok(())
}

impl Fixture {
    pub async fn new(label: &str) -> Case<Self> {
        let root = runtime_tests::root(label);
        let mut source = account(&root.join("source"), "sender")?;
        let peer = account(&root.join("peer"), "peer")?;
        let mut sibling = account(&root.join("sibling"), "sender")?;
        sibling.client.create_device_branch("sender", "device-sibling", 1, [77; 32]);
        let mut own = public_manifest(&source.client)?;
        let mut sibling_manifest = public_manifest(&sibling.client)?;
        sibling_manifest.devices[0].target_delivery_id = "sibling".into();
        own.devices.extend(sibling_manifest.devices);
        sign_manifest(source.client.identity_root.as_ref().ok_or("root")?, &mut own, 2)?;
        let remote = public_manifest(&peer.client)?;
        source.principal_commitment = own.principal_commitment.clone();
        for local in [&source, &peer, &sibling] {
            local.client.persist_identity_directory(&own)?;
            local.client.persist_identity_directory(&remote)?;
            local.client.account_db()?.establish_friend_link(
                "test-friend",
                &own.principal_commitment,
                &remote.principal_commitment,
            )?;
            for conversation in ["healthy", "stalled"] {
                local.client.account_db()?.persist_client_record(
                    "conversation",
                    conversation,
                    &json!({"kind":"direct","participants":["sender","peer"]}),
                )?;
            }
        }
        seed_pair(&source.client, &peer.client)?;
        seed_pair(&source.client, &sibling.client)?;
        let gateway = Arc::new(Mutex::new(Gateway {
            manifests: BTreeMap::from([
                (own.principal_commitment.clone(), serde_json::to_value(own)?),
                (remote.principal_commitment.clone(), serde_json::to_value(remote)?),
            ]),
            ..Gateway::default()
        }));
        let certified = rcgen::generate_simple_self_signed(vec!["test-gateway".into()])?;
        std::fs::write(root.join("ca.pem"), certified.cert.pem())?;
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let shared = gateway.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let shared = shared.clone();
                connections.spawn(async move {
                    if let Ok(mut stream) = acceptor.accept(tcp).await
                        && let Err(error) = serve(&mut stream, &shared).await
                        && error
                            .downcast_ref::<std::io::Error>()
                            .is_none_or(|error| error.kind() != std::io::ErrorKind::UnexpectedEof)
                        && let Ok(mut gateway) = shared.lock()
                    {
                        gateway.protocol_errors.push(error.to_string());
                    }
                });
            }
        });
        let config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: address,
            server_name: "test-gateway".into(),
            ca_cert: root.join("ca.pem"),
            principal_id: "sender".into(),
            device_id: "device-sender".into(),
            target_delivery_id: "sender".into(),
            prekey_http_url: None,
        })
        .with_account_identity(&source.client)?;
        source.engine = None;
        source.put_engine(GatewaySessionEngine::connect(config).await?);
        Ok(Self { root, source, peer, sibling, gateway, _server: server })
    }

    pub async fn inbound(&mut self) -> Case<String> {
        use crate::bus::dispatch::task_transport::{Target, seal};
        let target = Target {
            device: "device-sender".into(),
            identity: self.source.client.owned_device_identity()?,
            delivery: "sender".into(),
            federation: None,
            own: false,
        };
        let mut engine = self.peer.take_live_engine().await?;
        let dm = seal(
            &self.peer,
            &mut engine,
            &target,
            "healthy",
            b"courier stays responsive",
            crate::client::routed::Route::direct(),
        )
        .await?;
        let caller = crate::client::call::state::LiveCall::outgoing(
            ramflux_protocol::encode_base64url([8; 16]),
            "healthy".into(),
            self.peer.client.call_local_endpoint()?,
            vec![self.source.client.call_local_endpoint()?],
            now_unix_timestamp(),
        )?;
        let mut control = caller.pending[0].clone();
        control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &crate::client::call::signing_bytes(&control)?,
            self.peer.client.device_branch.as_ref().ok_or("peer device")?,
        );
        let call = seal(
            &self.peer,
            &mut engine,
            &target,
            "healthy",
            &crate::client::call::bytes(&control)?,
            crate::client::routed::Route::control(),
        )
        .await?;
        self.peer.put_engine(engine);
        let mut gateway = self.gateway.lock().map_err(|_| "gateway")?;
        for (index, delivery) in [dm, call].into_iter().enumerate() {
            gateway.inbox.push(GatewayInboxEntry {
                forwarded: false,
                inbox_seq: u64::try_from(index + 1)?,
                target_delivery_id: "sender".into(),
                envelope: delivery.envelope,
            });
        }
        Ok(control.call_id)
    }
}

async fn serve(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    shared: &Arc<Mutex<Gateway>>,
) -> Case {
    loop {
        let size = stream.read_u32().await?;
        if size > 4 * 1024 * 1024 {
            return Err("oversized test frame".into());
        }
        let mut bytes = vec![0; usize::try_from(size)?];
        stream.read_exact(&mut bytes).await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let response = if let Some(path) = value["path"].as_str() {
            let commitment = path.strip_prefix("/mvp1/device-manifest/").unwrap_or("");
            let body = shared
                .lock()
                .map_err(|_| "gateway")?
                .manifests
                .get(commitment)
                .cloned()
                .unwrap_or(Value::Null);
            json!({"status":if body.is_null(){404}else{200},"body":body})
        } else {
            let frame: GatewayClientFrame = serde_json::from_value(value)?;
            let response = match frame {
                GatewayClientFrame::Open { open } => {
                    *shared
                        .lock()
                        .map_err(|_| "gateway")?
                        .sessions
                        .entry(open.device_id)
                        .or_default() += 1;
                    continue;
                }
                GatewayClientFrame::Auth { .. } => GatewayServerFrame::SessionEstablished {
                    session: crate::gateway::GatewaySessionEstablishedFrame {
                        session_id: "courier-session".into(),
                        gateway_id: "test-gateway".into(),
                        accepted_cursor: None,
                        resume_token: "courier-resume".into(),
                        resume_window_seconds: 60,
                    },
                },
                GatewayClientFrame::Heartbeat { now } => GatewayServerFrame::Heartbeat { now },
                GatewayClientFrame::Resume { .. } => {
                    let gateway = shared.lock().map_err(|_| "gateway")?;
                    GatewayServerFrame::Resume {
                        entries: gateway
                            .inbox
                            .iter()
                            .filter(|e| !gateway.acked.contains(&e.envelope.envelope_id))
                            .cloned()
                            .collect(),
                    }
                }
                GatewayClientFrame::Submit { submit } => {
                    shared.lock().map_err(|_| "gateway")?.sent.push(submit.envelope.clone());
                    GatewayServerFrame::Deliver {
                        entry: GatewayInboxEntry {
                            forwarded: false,
                            inbox_seq: 1,
                            target_delivery_id: submit.envelope.target_delivery_id.clone(),
                            envelope: submit.envelope,
                        },
                    }
                }
                GatewayClientFrame::OwnDeviceFanout { fanout } => own_copy_response(fanout)?,
                GatewayClientFrame::Close { .. } => return Ok(()),
                GatewayClientFrame::Ack { ack } => {
                    let cursor = acknowledged_cursor(shared, ack)?;
                    let response =
                        serde_json::to_vec(&GatewayServerFrame::Ack { cursor: cursor.clone() })?;
                    stream.write_u32(u32::try_from(response.len())?).await?;
                    stream.write_all(&response).await?;
                    GatewayServerFrame::Cursor { cursor: Some(cursor) }
                }
                other => {
                    return Err(format!(
                        "unexpected test gateway frame {}",
                        serde_json::to_value(other)?["frame_type"]
                    )
                    .into());
                }
            };
            serde_json::to_value(response)?
        };
        let bytes = serde_json::to_vec(&response)?;
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
    }
}

fn own_copy_response(
    fanout: crate::gateway::GatewayOwnDeviceFanoutFrame,
) -> Case<GatewayServerFrame> {
    let bytes = ramflux_protocol::decode_base64url(&fanout.envelope.encrypted_payload)?;
    let payload = bytes
        .strip_prefix(crate::client::own_device_copy::PREFIX)
        .ok_or("own-copy payload prefix")?;
    let packet: crate::client::own_device_copy::OwnDeviceMessage = serde_json::from_slice(payload)?;
    Ok(GatewayServerFrame::OwnDeviceFanout {
        response: crate::GatewayOwnDeviceFanoutResponse {
            principal_id: fanout.principal_id,
            source_device_id: fanout.source_device_id,
            delivered: packet
                .slots
                .into_iter()
                .map(|slot| crate::GatewayOwnDeviceFanoutDelivery {
                    device_id: slot.recipient_device_id,
                    target_delivery_id: "sibling".into(),
                    outcome: "online".into(),
                    inbox_seq: Some(1),
                })
                .collect(),
        },
    })
}

fn acknowledged_cursor(
    shared: &Arc<Mutex<Gateway>>,
    ack: ramflux_protocol::Ack,
) -> Case<GatewayCursor> {
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    gateway.acked.insert(ack.envelope_id.clone());
    let inbox_seq = gateway
        .inbox
        .iter()
        .find(|entry| entry.envelope.envelope_id == ack.envelope_id)
        .map_or(0, |entry| entry.inbox_seq);
    Ok(GatewayCursor {
        target_delivery_id: "sender".into(),
        inbox_seq,
        last_envelope_id: Some(ack.envelope_id.clone()),
        acked_envelope_ids: vec![ack.envelope_id],
        nacked_envelope_ids: BTreeMap::new(),
    })
}
