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

#[derive(Clone)]
pub(super) struct Hold {
    pub entered: tokio::sync::mpsc::UnboundedSender<()>,
    pub release: Arc<tokio::sync::Notify>,
}
impl Hold {
    async fn wait(&self) {
        let released = self.release.notified();
        let _ = self.entered.send(());
        released.await;
    }
}

#[derive(Default)]
pub(super) struct Gateway {
    pub sessions: BTreeMap<String, usize>,
    pub sent: Vec<ramflux_protocol::Envelope>,
    /// Every submitted envelope, whatever the gateway answered.
    pub attempts: Vec<ramflux_protocol::Envelope>,
    /// Nacks every submit with this exact reason.
    pub nack_submit: Option<String>,
    /// The first this-many submits are answered normally before `nack_submit` applies.
    pub nack_after: usize,
    /// Reads every submit (it is recorded in `attempts`) and never answers it.
    pub stall_submit: bool,
    pub inbox: Vec<GatewayInboxEntry>,
    pub acked: BTreeSet<String>,
    /// Raw `ack_batch` sequence count (every wire send, including duplicates).
    pub ack_sends: usize,
    /// Last seen inbox target, kept after the router row is cleared so `ack_batch` can reply.
    pub ack_target: String,
    /// When set, `ack_batch` fails so the actor records Uncertain.
    pub ack_fail: bool,
    pub resumes: Vec<u64>,
    /// Caps `resume_page` entries so tests can observe page-sized catch-up (yield every 16).
    pub resume_page_size: Option<usize>,
    /// Optional issued seq so a loss-only page can still report a high-water mark.
    pub resume_issued: Option<u64>,
    /// Known-loss intervals returned on every `resume_page` until cleared.
    pub resume_losses: Vec<(u64, u64, &'static str)>,
    /// Inclusive oversize sequence advertised on `resume_page` (`NeedPoint`).
    pub oversize_next: Option<u64>,
    /// Sequences served by `fetch_entry`.
    pub fetches: Vec<u64>,
    pub manifests: BTreeMap<String, Value>,
    pub protocol_errors: Vec<String>,
    pub ack_hold: Option<Arc<AckHold>>,
    pub prekey_hold: Option<Arc<GatewayHold>>,
    pub submit_hold: Option<Arc<GatewayHold>>,
    pub priority_submit_hold: Option<Hold>,
    pub receipt_bypass: bool,
    pub resume_hold: Option<Hold>,
    pub manifest_requests: Vec<String>,
    pub manifest_hold: Option<(String, Arc<GatewayHold>)>,
}

impl Gateway {
    fn manifest_response(&mut self, path: &str) -> Value {
        let commitment = path.strip_prefix("/mvp1/device-manifest/").unwrap_or("");
        self.manifest_requests.push(commitment.into());
        let body = self.manifests.get(commitment).cloned().unwrap_or(Value::Null);
        json!({"status":if body.is_null(){404}else{200},"body":body})
    }
}

#[derive(Default)]
pub(super) struct GatewayHold {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
    pub seen: std::sync::atomic::AtomicBool,
}
pub(super) type AckHold = GatewayHold;

pub(super) struct Fixture {
    pub root: PathBuf,
    pub source: LocalBusAccountState,
    pub peer: LocalBusAccountState,
    pub sibling: LocalBusAccountState,
    /// A second device of the peer principal, present only for `with_second_peer`.
    /// Read only by the durability-gated refusal tests; other builds never read it.
    #[cfg_attr(not(feature = "durability-test-hooks"), allow(dead_code))]
    pub peer2: Option<LocalBusAccountState>,
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
        Box::pin(Self::build(label, false, None)).await
    }

    /// `second_peer` adds a second peer device so a control plan has three targets.
    #[allow(clippy::too_many_lines)]
    pub async fn build(
        label: &str,
        second_peer: bool,
        frame_timeout: Option<Duration>,
    ) -> Case<Self> {
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
        let mut remote = public_manifest(&peer.client)?;
        let mut peer2 =
            if second_peer { Some(account(&root.join("peer2"), "peer")?) } else { None };
        if let Some(second) = &mut peer2 {
            second.client.create_device_branch("peer", "device-peer2", 1, [78; 32]);
            let mut manifest = public_manifest(&second.client)?;
            manifest.devices[0].target_delivery_id = "peer2".into();
            remote.devices.extend(manifest.devices);
            sign_manifest(peer.client.identity_root.as_ref().ok_or("root")?, &mut remote, 2)?;
        }
        source.principal_commitment = own.principal_commitment.clone();
        for local in
            [Some(&source), Some(&peer), Some(&sibling), peer2.as_ref()].into_iter().flatten()
        {
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
        if let Some(second) = &peer2 {
            seed_pair(&source.client, &second.client)?;
        }
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
        let mut config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
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
        config.timeout = Duration::from_secs(600);
        config.quic_fallback_timeout = Duration::from_secs(600);
        source.engine = None;
        let mut engine = GatewaySessionEngine::connect(config).await?;
        if let Some(frame_timeout) = frame_timeout {
            engine.frame_timeout = frame_timeout;
        }
        source.install_test_session(engine);
        Ok(Self { root, source, peer, sibling, peer2, gateway, _server: server })
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
        let mut engine = self.peer.session_client().await?;
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
        self.peer.install_test_session(engine);
        let mut gateway = self.gateway.lock().map_err(|_| "gateway")?;
        gateway.ack_target = self.source.target_delivery_id.clone();
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

#[allow(clippy::too_many_lines)]
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
            public_lookup(path, shared).await?
        } else if value["frame_type"].as_str() == Some("ack_batch") {
            let hold = { shared.lock().map_err(|_| "gateway")?.ack_hold.take() };
            if let Some(hold) = hold {
                hold.seen.store(true, std::sync::atomic::Ordering::SeqCst);
                hold.entered.notify_one();
                hold.release.notified().await;
            }
            ack_batch_response(shared, &value)?
        } else if value["frame_type"].as_str() == Some("resume")
            && value.get("incarnation_id").is_some()
        {
            resume_page_response(shared, &value)?
        } else if value["frame_type"].as_str() == Some("fetch_entry") {
            fetch_entry_response(shared, &value)?
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
                GatewayClientFrame::Auth { auth } => {
                    let advertised = auth.device_proof.capability_scope.iter().any(|capability| {
                        capability == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY
                    });
                    let bytes = serde_json::to_vec(&established_session(advertised))?;
                    stream.write_u32(u32::try_from(bytes.len())?).await?;
                    stream.write_all(&bytes).await?;
                    stream.flush().await?;
                    continue;
                }
                GatewayClientFrame::Heartbeat { now } => GatewayServerFrame::Heartbeat { now },
                GatewayClientFrame::Resume { resume } => {
                    let hold = shared.lock().map_err(|_| "gateway")?.resume_hold.take();
                    if let Some(hold) = hold {
                        let _ = hold.entered.send(());
                        hold.release.notified().await;
                    }
                    let mut gateway = shared.lock().map_err(|_| "gateway")?;
                    gateway.resumes.push(resume.after_inbox_seq);
                    GatewayServerFrame::Resume {
                        entries: gateway
                            .inbox
                            .iter()
                            .filter(|e| {
                                e.inbox_seq > resume.after_inbox_seq
                                    && !gateway.acked.contains(&e.envelope.envelope_id)
                            })
                            .take(resume.limit)
                            .cloned()
                            .collect(),
                    }
                }
                GatewayClientFrame::PrekeyFetch { device_id } => {
                    let hold = { shared.lock().map_err(|_| "gateway")?.prekey_hold.take() };
                    wait_at(hold).await;
                    GatewayServerFrame::Prekey { response: prekey(shared, &device_id)? }
                }
                GatewayClientFrame::Submit { submit } => {
                    let hold = {
                        let gateway = shared.lock().map_err(|_| "gateway")?;
                        if gateway.receipt_bypass
                            && submit.envelope.envelope_id.starts_with("receipt_evt_")
                        {
                            None
                        } else {
                            gateway.submit_hold.clone()
                        }
                    };
                    wait_at(hold).await;
                    let hold = {
                        let gateway = shared.lock().map_err(|_| "gateway")?;
                        if gateway.receipt_bypass
                            && submit.envelope.envelope_id.starts_with("receipt_evt_")
                        {
                            None
                        } else {
                            gateway.priority_submit_hold.clone()
                        }
                    };
                    if let Some(hold) = hold {
                        hold.wait().await;
                    }
                    let (stall, refused) = {
                        let mut gateway = shared.lock().map_err(|_| "gateway")?;
                        gateway.attempts.push(submit.envelope.clone());
                        let later = gateway.attempts.len() > gateway.nack_after;
                        (gateway.stall_submit, gateway.nack_submit.clone().filter(|_| later))
                    };
                    if stall {
                        return std::future::pending().await;
                    }
                    if let Some(reason) = refused {
                        GatewayServerFrame::Nack { reason }
                    } else {
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
                }
                GatewayClientFrame::OwnDeviceFanout { fanout } => own_copy_response(fanout)?,
                GatewayClientFrame::Close { .. } => return Ok(()),
                GatewayClientFrame::Ack { ack } => {
                    let hold = { shared.lock().map_err(|_| "gateway")?.ack_hold.take() };
                    if let Some(hold) = hold {
                        hold.seen.store(true, std::sync::atomic::Ordering::SeqCst);
                        hold.entered.notify_one();
                        hold.release.notified().await;
                    }
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

async fn wait_at(hold: Option<Arc<GatewayHold>>) {
    if let Some(hold) = hold {
        hold.seen.store(true, std::sync::atomic::Ordering::SeqCst);
        hold.entered.notify_one();
        hold.release.notified().await;
    }
}
fn prekey(shared: &Arc<Mutex<Gateway>>, selector: &str) -> Case<crate::prekey::SdkPrekeyResponse> {
    let qualified = ramflux_protocol::parse_qualified_device_id(selector)?;
    let gateway = shared.lock().map_err(|_| "gateway")?;
    for value in gateway.manifests.values() {
        let manifest: crate::SdkDeviceManifestResponse = serde_json::from_value(value.clone())?;
        for device in manifest.devices {
            let matches = qualified.as_ref().map_or(device.device_id == selector, |(root, raw)| {
                *root == manifest.principal_commitment && *raw == device.device_id
            });
            if matches {
                return Ok(crate::prekey::SdkPrekeyResponse {
                    device_id: selector.into(),
                    bundle: Some(device.prekey_bundle),
                    principal_commitment: manifest.principal_commitment,
                    target_delivery_id: Some(device.target_delivery_id),
                });
            }
        }
    }
    Err("unknown prekey selector".into())
}

async fn public_lookup(path: &str, shared: &Arc<Mutex<Gateway>>) -> Case<Value> {
    let commitment = path.strip_prefix("/mvp1/device-manifest/").unwrap_or("");
    let hold = {
        let mut gateway = shared.lock().map_err(|_| "gateway")?;
        if gateway.manifest_hold.as_ref().is_some_and(|(root, _)| root == commitment) {
            gateway.manifest_hold.take().map(|(_, hold)| hold)
        } else {
            None
        }
    };
    if let Some(hold) = hold {
        hold.entered.notify_one();
        hold.release.notified().await;
    }
    Ok(shared.lock().map_err(|_| "gateway")?.manifest_response(path))
}

pub(super) fn own_copy_response(
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

fn resume_page_response(shared: &Arc<Mutex<Gateway>>, value: &Value) -> Case<Value> {
    let incarnation_id = value["incarnation_id"].as_str().ok_or("resume incarnation")?.to_owned();
    let after = value["resume"]["after_inbox_seq"].as_u64().ok_or("resume after")?;
    let limit = usize::try_from(value["resume"]["limit"].as_u64().ok_or("resume limit")?)?;
    let target = value["resume"]["target_delivery_id"].as_str().ok_or("resume target")?.to_owned();
    let retain_until = now_unix_timestamp() + 300;
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    gateway.resumes.push(after);
    let take = gateway.resume_page_size.unwrap_or(limit);
    let issued = gateway
        .resume_issued
        .or_else(|| gateway.inbox.last().map(|entry| entry.inbox_seq))
        .unwrap_or(after);
    let oversize_next = gateway.oversize_next.filter(|seq| *seq > after);
    let entries: Vec<Value> = gateway
        .inbox
        .iter()
        .filter(|entry| {
            entry.inbox_seq > after
                && !gateway.acked.contains(&entry.envelope.envelope_id)
                && oversize_next != Some(entry.inbox_seq)
        })
        .take(take)
        .map(|entry| json!({ "entry": entry, "retain_until": retain_until }))
        .collect();
    let known_losses: Vec<Value> = gateway
        .resume_losses
        .iter()
        .map(|(from_seq, to_seq, reason)| {
            json!({ "from_seq": from_seq, "to_seq": to_seq, "reason": reason })
        })
        .collect();
    let loss_high = gateway.resume_losses.iter().map(|(_, to_seq, _)| *to_seq).max();
    let entry_high = entries.last().and_then(|entry| entry["entry"]["inbox_seq"].as_u64());
    let covered = entry_high.max(loss_high).unwrap_or(after);
    Ok(json!({
        "frame_type": "resume_page",
        "target_delivery_id": target,
        "incarnation_id": incarnation_id,
        "after_inbox_seq": after,
        "covered_through_seq": covered,
        "issued_inbox_seq": issued,
        "settled_through_seq": 0,
        "entries": entries,
        "known_losses": known_losses,
        "oversize_next": oversize_next,
        "more": covered < issued,
    }))
}

fn fetch_entry_response(shared: &Arc<Mutex<Gateway>>, value: &Value) -> Case<Value> {
    let incarnation_id = value["incarnation_id"].as_str().ok_or("fetch incarnation")?.to_owned();
    let seq = value["inbox_seq"].as_u64().ok_or("fetch seq")?;
    let retain_until = now_unix_timestamp() + 300;
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    gateway.fetches.push(seq);
    let entry = gateway
        .inbox
        .iter()
        .find(|row| row.inbox_seq == seq)
        .cloned()
        .ok_or("fetch missing entry")?;
    Ok(json!({
        "frame_type": "entry",
        "incarnation_id": incarnation_id,
        "record": { "entry": entry, "retain_until": retain_until },
    }))
}

fn ack_batch_response(shared: &Arc<Mutex<Gateway>>, value: &Value) -> Case<Value> {
    let incarnation_id =
        value["incarnation_id"].as_str().ok_or("ack_batch incarnation")?.to_owned();
    let seqs: Vec<u64> = value["inbox_seqs"]
        .as_array()
        .ok_or("ack_batch inbox_seqs")?
        .iter()
        .map(|seq| seq.as_u64().ok_or("ack_batch seq"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    if gateway.ack_fail {
        return Err("ack_batch failed".into());
    }
    gateway.ack_sends = gateway.ack_sends.saturating_add(seqs.len());
    if gateway.ack_target.is_empty() {
        gateway.ack_target = gateway
            .inbox
            .first()
            .map_or_else(|| "sender".into(), |entry| entry.target_delivery_id.clone());
    }
    let mut acked_ids = Vec::new();
    let mut last_seq = 0_u64;
    for seq in &seqs {
        last_seq = *seq;
        let id = gateway
            .inbox
            .iter()
            .find(|entry| entry.inbox_seq == *seq)
            .map_or_else(|| format!("seq:{seq}"), |entry| entry.envelope.envelope_id.clone());
        gateway.acked.insert(id.clone());
        acked_ids.push(id);
    }
    let cursor = GatewayCursor {
        target_delivery_id: gateway.ack_target.clone(),
        inbox_seq: last_seq,
        last_envelope_id: acked_ids.last().cloned(),
        acked_envelope_ids: acked_ids,
        nacked_envelope_ids: BTreeMap::new(),
    };
    let results: Vec<Value> = seqs
        .iter()
        .map(|seq| json!({"inbox_seq": seq, "outcome": "acked", "reason": null}))
        .collect();
    Ok(json!({
        "frame_type": "ack_batch",
        "incarnation_id": incarnation_id,
        "cursor": cursor,
        "results": results,
    }))
}

/// Echo session-push on `session_established` only when Auth advertised the capability.
fn established_session(advertised: bool) -> Value {
    let mut session = json!({
        "session_id": "courier-session",
        "gateway_id": "test-gateway",
        "accepted_cursor": null,
        "resume_token": "courier-resume",
        "resume_window_seconds": 60,
    });
    if advertised {
        session["capabilities"] = json!([ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY]);
        session["inbox_incarnation_id"] = json!("0123456789abcdef0123456789abcdef");
    }
    json!({ "frame_type": "session_established", "session": session })
}

fn acknowledged_cursor(
    shared: &Arc<Mutex<Gateway>>,
    ack: ramflux_protocol::Ack,
) -> Case<GatewayCursor> {
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    gateway.ack_sends = gateway.ack_sends.saturating_add(1);
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
