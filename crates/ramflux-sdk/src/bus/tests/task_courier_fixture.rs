// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Loopback TLS gateway that counts real session opens and serves verified manifests.

use crate::bus::runtime_tests;
use crate::prelude::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[path = "task_courier_custody.rs"]
mod native;
pub(super) type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Canonical scope of the two deterministic accounts owned by this transport fixture.
pub(super) fn direct_conversation(client: &RamfluxClient) -> Result<String, SdkError> {
    client
        .account_db()?
        .load_actor_state("fixture/direct-conversation")?
        .ok_or_else(|| SdkError::LocalBus("test: fixture canonical conversation missing".into()))
}

/// Seal typed fixture content through the live compact transport; labels never become DM IDs.
pub(super) async fn seal_content(
    account: &LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    target: &crate::bus::dispatch::task_transport::Target,
    content: ramflux_protocol::message::Content,
    envelope_id: Option<&str>,
    created_at: Option<i64>,
) -> Result<crate::bus::task_delivery::Delivery, SdkError> {
    seal_content_with_identity(account, engine, target, content, envelope_id, created_at)
        .await
        .map(|(delivery, _)| delivery)
}

pub(super) async fn seal_content_with_identity(
    account: &LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    target: &crate::bus::dispatch::task_transport::Target,
    content: ramflux_protocol::message::Content,
    envelope_id: Option<&str>,
    created_at: Option<i64>,
) -> Result<(crate::bus::task_delivery::Delivery, String), SdkError> {
    let own = account.client.owned_device_identity()?;
    let scope = ramflux_protocol::message::dm_scope::derive(
        own.root_commitment(),
        target.identity.root_commitment(),
    )
    .map_err(|error| SdkError::InboundRejected(error.to_string()))?;
    let identity = account.client.allocate_generated_identity(
        &scope,
        u64::try_from(now_unix_timestamp()).unwrap_or_default().saturating_mul(1_000),
        false,
    )?;
    let mut message = GatewayDirectMessage {
        conversation_id: scope,
        message_id: ramflux_protocol::encode_base64url(&identity.id),
        envelope_id: envelope_id
            .map_or_else(crate::new_surface_message_id, |id| Ok(id.to_owned()))?,
        source_principal_id: engine.config().principal_id.clone(),
        sender_id: own.device_id().into(),
        recipient_device_id: Some(target.device.clone()),
        recipient_principal_commitment: Some(target.identity.root_commitment().into()),
        target_delivery_id: target.delivery.clone(),
        encrypted_body: Vec::new(),
        created_at: created_at.unwrap_or_else(now_unix_timestamp),
        ttl: 300,
    };
    let inner = RamfluxClient::encode_generated_inner(identity, &content)?;
    let route = crate::client::routed::Route::from_inner(&inner)?;
    let sealed = Box::pin(account.client.seal_routed_as(engine, &message, &inner, route)).await?;
    let envelope =
        crate::dm::gateway_generated_envelope_from_sealed(engine.config(), &mut message, sealed)?;
    if matches!(content.value, Some(ramflux_protocol::message::content::Value::Message(_))) {
        assert!(
            envelope.ext.ext.contains_key(ramflux_protocol::message::original_header::EXT_KEY),
            "test: Message producer must retain its signed origin commitment"
        );
    }
    Ok((crate::bus::task_delivery::Delivery { envelope, federation: None }, message.message_id))
}
pub(super) async fn seal_message(
    account: &LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    target: &crate::bus::dispatch::task_transport::Target,
    _scenario: &str,
    text: &[u8],
    _route: crate::client::routed::Route,
) -> Result<crate::bus::task_delivery::Delivery, SdkError> {
    let text =
        std::str::from_utf8(text).map_err(|_| SdkError::InboundRejected("fixture text".into()))?;
    seal_content(
        account,
        engine,
        target,
        ramflux_protocol::message::Content {
            value: Some(ramflux_protocol::message::content::Value::Message(
                ramflux_protocol::message::Message { text: text.into(), ..Default::default() },
            )),
        },
        None,
        None,
    )
    .await
}

#[derive(Clone)]
pub(super) struct Hold {
    pub entered: tokio::sync::mpsc::Sender<()>,
    pub release: Arc<tokio::sync::Notify>,
}
impl Hold {
    async fn wait(&self) {
        let released = self.release.notified();
        let _ = self.entered.try_send(());
        released.await;
    }
}

/// Whether an envelope id is carried by an own-device copy row.
pub(super) type OwnCopyProbe = Box<dyn Fn(&str) -> bool + Send>;

#[derive(Default)]
pub(super) struct Gateway {
    pub sessions: BTreeMap<String, usize>,
    pub sent: Vec<ramflux_protocol::Envelope>,
    /// Every submitted envelope, whatever the gateway answered.
    pub attempts: Vec<ramflux_protocol::Envelope>,
    /// Recognises an envelope id carried by an own-device copy row of the submitting account.
    /// Checked at submit time, when that row necessarily exists.
    pub own_copy_probe: Option<OwnCopyProbe>,
    /// Submitted envelopes the probe recognised: own-device copies, not task courier attempts.
    pub own_copies: BTreeSet<String>,
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
    /// Some(count) forces Compat and drops legacy ACKs; count advances before wire close.
    pub compat_ack_loss: Option<usize>,
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
    pub prekey_hold_target: Option<String>,
    pub submit_hold: Option<Arc<GatewayHold>>,
    pub submit_hold_target: Option<String>,
    pub priority_submit_hold: Option<Hold>,
    pub receipt_bypass: bool,
    pub resume_hold: Option<Hold>,
    pub manifest_requests: Vec<String>,
    pub manifest_hold: Option<(String, Arc<GatewayHold>)>,
    /// Node incarnation echoed on Push `session_established`. Default is the scripted E.
    pub inbox_incarnation: Option<String>,
    /// When set, Submit/ACK/resume bind the real router store.
    pub router_sources: BTreeMap<String, ramflux_crypto::RootQualifiedDeviceRef>,
    pub router:
        Option<(Arc<ramflux_node_core::RouterCore>, Arc<ramflux_node_core::RouterRedbStore>)>,
}

impl Gateway {
    /// Envelopes the task courier submitted, without the own-device copies the same account
    /// sends through this gateway.
    #[cfg(feature = "durability-test-hooks")]
    pub fn task_attempts(&self) -> usize {
        self.attempts.iter().filter(|e| !self.own_copies.contains(&e.envelope_id)).count()
    }

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
    pub source: LocalBusAccountState,
    pub peer: LocalBusAccountState,
    pub sibling: LocalBusAccountState,
    _stalled: LocalBusAccountState,
    /// A second device of the peer principal, present only for `with_second_peer`.
    /// Read only by the durability-gated refusal tests; other builds never read it.
    #[cfg_attr(not(feature = "durability-test-hooks"), allow(dead_code))]
    pub peer2: Option<LocalBusAccountState>,
    pub gateway: Arc<Mutex<Gateway>>,
    _server: tokio::task::JoinHandle<()>,
    pub root: ramflux_test_support::TestPath,
}

pub(super) fn open_source(
    root: &Path,
    config: &GatewaySessionConfig,
) -> Result<LocalBusAccountState, SdkError> {
    let custody = config.custody.as_ref().ok_or(SdkError::CustodyVaultUnavailable)?;
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.unlock_account("sender", b"native fixture data passphrase")?;
    client.initialize_born_v3_branch_for_fixture(&config.device_id, custody.vault.as_ref())?;
    Ok(LocalBusAccountState::disconnected(
        client,
        config.clone(),
        config
            .source_identity
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .root_commitment()
            .into(),
    ))
}

pub(super) fn seed_pair(a: &RamfluxClient, b: &RamfluxClient) -> Result<(), SdkError> {
    let ai = a.owned_device_identity()?;
    let bi = b.owned_device_identity()?;
    let send = ramflux_crypto::DmSession::initiator(
        [17; 32],
        dm_device_id_hash(ai.device_id()),
        dm_device_id_hash(bi.device_id()),
        [3; 32],
    )?
    .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
    let recv = ramflux_crypto::DmSession::recipient(
        [17; 32],
        dm_device_id_hash(bi.device_id()),
        dm_device_id_hash(ai.device_id()),
        [3; 32],
    )?
    .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
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
        use crate::client::native_test_support::{
            Fixture as Native, activation_send::tests::publish_layer_four, bus,
        };
        let root = runtime_tests::root(label);
        let mut native_source = Box::pin(Native::with_principal_at(
            root.child("source"),
            "sender",
            "device-sender",
            "sender",
        ))
        .await?;
        Box::pin(publish_layer_four(&mut native_source)).await?;
        let mut source = native_source.into_bus();
        let mut native_peer =
            Box::pin(Native::with_principal_at(root.child("peer"), "peer", "device-peer", "peer"))
                .await?;
        Box::pin(publish_layer_four(&mut native_peer)).await?;
        let mut peer = native_peer.into_bus();

        let sibling = Box::pin(bus::sibling(&mut source, "sender", "device-sibling")).await?;
        let own =
            source.client.native_bus_fixture.as_ref().ok_or("native source")?.manifest.clone();
        let peer2 = if second_peer {
            Some(Box::pin(bus::sibling(&mut peer, "peer", "device-peer2")).await?)
        } else {
            None
        };
        let remote =
            peer.client.native_bus_fixture.as_ref().ok_or("native peer fixture")?.manifest.clone();
        let config = peer.gateway_config.clone();
        peer.install_test_session(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(NativeNoNetwork),
        ));
        let native_source = Native::take_bus(&mut source)?;
        let native_peer = Native::take_bus(&mut peer)?;
        native_source.accept_peer(&native_peer)?;
        native_peer.accept_peer(&native_source)?;
        source = native_source.into_bus();
        peer = native_peer.into_bus();
        let config = peer.gateway_config.clone();
        peer.install_test_session(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(NativeNoNetwork),
        ));
        source.principal_commitment = own.principal_commitment.clone();
        for local in
            [Some(&source), Some(&peer), Some(&sibling), peer2.as_ref()].into_iter().flatten()
        {
            local.client.persist_fetched_identity_directory(&own)?;
            local.client.persist_fetched_identity_directory(&remote)?;
            local.client.account_db()?.establish_friend_link(
                "test-friend",
                &own.principal_commitment,
                &remote.principal_commitment,
            )?;
            let canonical = ramflux_protocol::message::dm_scope::derive(
                &own.principal_commitment,
                &remote.principal_commitment,
            )?;
            local
                .client
                .account_db()?
                .persist_actor_state("fixture/direct-conversation", &canonical)?;
            for conversation in ["healthy", "stalled", canonical.as_str()] {
                local.client.account_db()?.persist_client_record(
                    "conversation",
                    conversation,
                    &json!({"kind":"direct","group_id":null,"participants":["sender","peer"],"participant_roots":[own.principal_commitment,remote.principal_commitment]}),
                )?;
            }
        }
        seed_pair(&source.client, &peer.client)?;
        seed_pair(&source.client, &sibling.client)?;
        if let Some(second) = &peer2 {
            seed_pair(&source.client, &second.client)?;
        }
        let mut stalled =
            Box::pin(Native::with_principal("stalled-peer", "device-stalled-peer", "stalled-peer"))
                .await?;
        Box::pin(publish_layer_four(&mut stalled)).await?;
        let stalled = stalled.into_bus();
        let stalled_manifest =
            stalled.client.native_bus_fixture.as_ref().ok_or("stalled fixture")?.manifest.clone();
        source.client.persist_fetched_identity_directory(&stalled_manifest)?;
        let scope = ramflux_protocol::message::dm_scope::derive(
            &own.principal_commitment,
            &stalled_manifest.principal_commitment,
        )?;
        source.client.account_db()?.persist_actor_state("fixture/stalled-conversation", &scope)?;
        source.client.account_db()?.persist_client_record("conversation", &scope, &json!({"kind":"direct","group_id":null,"participants":["sender","stalled-peer"],"participant_roots":[own.principal_commitment,stalled_manifest.principal_commitment]}))?;
        source.client.establish_friend_link(
            "stalled-task-link",
            &own.principal_commitment,
            &stalled_manifest.principal_commitment,
        )?;
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
        let native = Arc::new(native::NativeGateway::new(&root)?);
        let shared = gateway.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let shared = shared.clone();
                let native = native.clone();
                connections.spawn(async move {
                    if let Ok(stream) = acceptor.accept(tcp).await
                        && let Err(error) = serve(stream, &shared, &native).await
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
            target_delivery_id: source.gateway_config.target_delivery_id.clone(),
            prekey_http_url: None,
        })
        .with_native_custody(crate::GatewayCustodyConfig {
            node_id: "node".into(),
            node_public_key: ramflux_crypto::fixture_public_key_base64url(),
            ..source.gateway_config.custody.clone().ok_or("native source custody")?
        })
        .with_account_identity(&source.client)?;
        let session_hold = frame_timeout.unwrap_or(Duration::from_secs(600));
        config.timeout = session_hold;
        config.quic_fallback_timeout = session_hold;
        source.engine = None;
        let mut engine = GatewaySessionEngine::connect(config).await?;
        if let Some(frame_timeout) = frame_timeout {
            engine.frame_timeout = frame_timeout;
        }
        source.install_test_session(engine);
        Ok(Self { source, peer, sibling, peer2, gateway, _stalled: stalled, _server: server, root })
    }

    pub async fn inbound(&mut self) -> Case<String> {
        use crate::bus::dispatch::task_transport::Target;
        let target = Target {
            device: "device-sender".into(),
            identity: self.source.client.owned_device_identity()?,
            delivery: self.source.gateway_config.target_delivery_id.clone(),
            federation: None,
            own: false,
        };
        let mut engine = self.peer.session_client().await?;
        let dm = seal_message(
            &self.peer,
            &mut engine,
            &target,
            "healthy",
            b"courier stays responsive",
            crate::client::routed::Route::direct(),
        )
        .await?;
        let caller = crate::client::call::state::LiveCall::outgoing(
            ramflux_protocol::encode_base64url(
                ramflux_crypto::random_32()?.first_chunk::<16>().ok_or("random call id")?,
            ),
            ramflux_protocol::message::dm_scope::derive(
                self.peer.client.owned_device_identity()?.root_commitment(),
                target.identity.root_commitment(),
            )?,
            self.peer.client.call_local_endpoint()?,
            vec![self.source.client.call_local_endpoint()?],
            now_unix_timestamp(),
        )?;
        let mut control = caller.pending[0].clone();
        let bound = crate::client::call::intent::bind_call_intent(
            &self.peer,
            &control,
            &crate::client::call::intent::IntentTarget {
                device_id: target.device.clone(),
                qualified_device: target.identity.storage_key().to_owned(),
                epoch: self
                    .source
                    .client
                    .device_branch
                    .as_ref()
                    .ok_or("source device")?
                    .device_epoch,
                delivery_id: target.delivery.clone(),
            },
            now_unix_timestamp().unsigned_abs(),
        )?
        .ok_or("test: inbound Start missing")?;
        control.call_ref = Some(bound.signed.body.call_ref.clone());
        control.call_start = Some(bound.signed.clone());
        control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &crate::client::call::signing_bytes(&control)?,
            self.peer.client.device_branch.as_ref().ok_or("peer device")?,
        );
        let call = seal_content(
            &self.peer,
            &mut engine,
            &target,
            ramflux_protocol::message::Content {
                value: Some(ramflux_protocol::message::content::Value::Call(
                    crate::client::generated_call::native::from_native(&control)?,
                )),
            },
            Some(&bound.envelope_id),
            Some(control.created_at),
        )
        .await?;
        self.peer.install_test_session(engine);
        let mut gateway = self.gateway.lock().map_err(|_| "gateway")?;
        gateway.ack_target = self.source.target_delivery_id.clone();
        for (index, delivery) in [dm, call].into_iter().enumerate() {
            gateway.inbox.push(GatewayInboxEntry {
                forwarded: false,
                inbox_seq: u64::try_from(index + 1)?,
                target_delivery_id: self.source.gateway_config.target_delivery_id.clone(),
                envelope: delivery.envelope,
            });
        }
        Ok(control.call_id)
    }
}

#[allow(clippy::too_many_lines)]
async fn serve(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    shared: &Arc<Mutex<Gateway>>,
    native: &native::NativeGateway,
) -> Case {
    const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
    let connection = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let _disconnect = native::Connection(native, connection.clone());
    let mut native_session = None;
    let mut push = false;
    let mut call_generation: Option<String> = None;
    let mut session_target = String::new();
    let mut session_incarnation = String::new();
    loop {
        let size = stream.read_u32().await?;
        if size > MAX_FRAME_BYTES {
            return Err("oversized test frame".into());
        }
        let mut bytes = vec![0; usize::try_from(size.min(MAX_FRAME_BYTES))?];
        stream.read_exact(&mut bytes).await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if let Ok(frame) =
            serde_json::from_value::<ramflux_protocol::custody::CustodyClientFrame>(value.clone())
        {
            if let ramflux_protocol::custody::CustodyClientFrame::GatewayHandoff { session_id } =
                frame
            {
                assert_eq!(
                    native_session.as_deref(),
                    Some(session_id.as_str()),
                    "native handoff requires the admitted session"
                );
            } else {
                let response = native.dispatch(&stream, &connection, frame)?;
                if let ramflux_protocol::custody::CustodyServerFrame::SessionEstablished {
                    session,
                } = &response
                {
                    native_session = Some(session.session_id.clone());
                }
                ramflux_transport::write_gateway_session_json(&mut stream, &response).await?;
            }
            continue;
        }
        let response = if let Some(path) = value["path"].as_str() {
            public_lookup(path, shared).await?
        } else if value["frame_type"].as_str() == Some("ack_batch") {
            let hold = { shared.lock().map_err(|_| "gateway")?.ack_hold.take() };
            if let Some(hold) = hold {
                hold.seen.store(true, std::sync::atomic::Ordering::SeqCst);
                hold.entered.notify_one();
                hold.release.notified().await;
            }
            ack_batch_response(shared, &value, &session_target).await?
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
                    session_target = open.target_delivery_id.clone();
                    *shared
                        .lock()
                        .map_err(|_| "gateway")?
                        .sessions
                        .entry(open.device_id)
                        .or_default() += 1;
                    continue;
                }
                GatewayClientFrame::Auth { auth } => {
                    call_generation =
                        if auth.device_proof.capability_scope.iter().any(|capability| {
                            capability == ramflux_protocol::CALL_RESOLUTION_CAPABILITY
                        }) {
                            Some(ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?))
                        } else {
                            None
                        };
                    let advertised = auth.device_proof.capability_scope.iter().any(|capability| {
                        capability == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY
                    });
                    let advertised = advertised
                        && shared.lock().map_err(|_| "gateway")?.compat_ack_loss.is_none();
                    push = advertised;
                    let incarnation = {
                        let gateway = shared.lock().map_err(|_| "gateway")?;
                        if let Some((router, store)) = &gateway.router {
                            router.prepare_publication_target(store, &session_target)?;
                            Some(store.initialize_inbox(&session_target)?)
                        } else {
                            gateway.inbox_incarnation.clone()
                        }
                    };
                    session_incarnation = incarnation
                        .clone()
                        .unwrap_or_else(|| "0123456789abcdef0123456789abcdef".into());
                    let bytes = serde_json::to_vec(&established_session(
                        advertised,
                        incarnation.as_deref(),
                        call_generation.as_deref(),
                    ))?;
                    stream.write_u32(u32::try_from(bytes.len())?).await?;
                    stream.write_all(&bytes).await?;
                    stream.flush().await?;
                    continue;
                }
                GatewayClientFrame::Heartbeat { now } => GatewayServerFrame::Heartbeat { now },
                GatewayClientFrame::Resume { resume } => {
                    let hold = shared.lock().map_err(|_| "gateway")?.resume_hold.take();
                    if let Some(hold) = hold {
                        let _ = hold.entered.try_send(());
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
                    let hold = {
                        let mut gateway = shared.lock().map_err(|_| "gateway")?;
                        if gateway
                            .prekey_hold_target
                            .as_deref()
                            .is_none_or(|target| target == device_id)
                        {
                            gateway.prekey_hold.take()
                        } else {
                            None
                        }
                    };
                    wait_at(hold).await;
                    GatewayServerFrame::Prekey { response: prekey(shared, &device_id)? }
                }
                GatewayClientFrame::Submit { submit } => {
                    let hold = {
                        let gateway = shared.lock().map_err(|_| "gateway")?;
                        if (gateway.receipt_bypass
                            && submit.envelope.envelope_id.starts_with("receipt_evt_"))
                            || gateway
                                .submit_hold_target
                                .as_deref()
                                .is_some_and(|target| target != submit.envelope.target_delivery_id)
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
                        let id = submit.envelope.envelope_id.as_str();
                        if gateway.own_copy_probe.as_ref().is_some_and(|probe| probe(id)) {
                            gateway.own_copies.insert(id.to_owned());
                        }
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
                        let routed = record_router_submit(shared, &submit.envelope).await?;
                        refuse_fixture_call(&mut stream, &submit, call_generation.as_deref())
                            .await?;
                        if push {
                            let (_, inbox_seq) = routed.unwrap_or((session_incarnation.clone(), 1));
                            let incarnation_id = &session_incarnation;
                            let accepted = json!({
                                "frame_type": "submit_accepted",
                                "incarnation_id": incarnation_id,
                                "envelope_id": submit.envelope.envelope_id,
                                "target_delivery_id": submit.envelope.target_delivery_id,
                                "inbox_seq": inbox_seq,
                            });
                            let bytes = serde_json::to_vec(&accepted)?;
                            stream.write_u32(u32::try_from(bytes.len())?).await?;
                            stream.write_all(&bytes).await?;
                            stream.flush().await?;
                            continue;
                        }
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
                    let lose = {
                        let mut gateway = shared.lock().map_err(|_| "gateway")?;
                        if let Some(count) = &mut gateway.compat_ack_loss {
                            *count += 1;
                            true
                        } else {
                            false
                        }
                    };
                    if lose {
                        return Err("injected legacy ACK loss".into());
                    }
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
pub(super) fn prekey(
    shared: &Arc<Mutex<Gateway>>,
    selector: &str,
) -> Case<crate::prekey::SdkPrekeyResponse> {
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

pub(super) fn resume_page_response(shared: &Arc<Mutex<Gateway>>, value: &Value) -> Case<Value> {
    let incarnation_id = value["incarnation_id"].as_str().ok_or("resume incarnation")?.to_owned();
    let after = value["resume"]["after_inbox_seq"].as_u64().ok_or("resume after")?;
    let limit = usize::try_from(value["resume"]["limit"].as_u64().ok_or("resume limit")?)?;
    let target = value["resume"]["target_delivery_id"].as_str().ok_or("resume target")?.to_owned();
    let retain_until = now_unix_timestamp() + 300;
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    gateway.resumes.push(after);
    let take = gateway.resume_page_size.unwrap_or(limit);
    if let Some((router, _store)) = &gateway.router {
        let page = router.resume_page(&target, after, take, now_unix_timestamp())?;
        return Ok(serde_json::to_value(page)?);
    }
    let issued = gateway
        .resume_issued
        .or_else(|| {
            gateway
                .inbox
                .iter()
                .filter(|entry| entry.target_delivery_id == target)
                .map(|entry| entry.inbox_seq)
                .max()
        })
        .unwrap_or(after);
    let oversize_next = gateway.oversize_next.filter(|seq| *seq > after);
    let entries: Vec<Value> = gateway
        .inbox
        .iter()
        .filter(|entry| {
            entry.target_delivery_id == target
                && entry.inbox_seq > after
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

fn record_acked_seqs(gateway: &mut Gateway, seqs: &[u64], target: &str) {
    gateway.ack_sends = gateway.ack_sends.saturating_add(seqs.len());
    for seq in seqs {
        if let Some(id) = gateway
            .inbox
            .iter()
            .find(|entry| entry.inbox_seq == *seq && entry.target_delivery_id == target)
            .map(|entry| entry.envelope.envelope_id.clone())
        {
            gateway.acked.insert(id);
        }
    }
}

async fn ack_batch_response(
    shared: &Arc<Mutex<Gateway>>,
    value: &Value,
    session_target: &str,
) -> Case<Value> {
    let incarnation_id =
        value["incarnation_id"].as_str().ok_or("ack_batch incarnation")?.to_owned();
    let seqs: Vec<u64> = value["inbox_seqs"]
        .as_array()
        .ok_or("ack_batch inbox_seqs")?
        .iter()
        .map(|seq| seq.as_u64().ok_or("ack_batch seq"))
        .collect::<Result<Vec<_>, _>>()?;
    let bound = {
        let gateway = shared.lock().map_err(|_| "gateway")?;
        if gateway.ack_fail {
            return Err("ack_batch failed".into());
        }
        gateway.router.clone()
    };
    if let Some((router, store)) = bound {
        let target = session_target.to_owned();
        let publication = ramflux_node_core::publication::capture(|| {
            router.session_ack_batch(
                &store,
                &ramflux_node_core::SessionAckBatchRequest {
                    target_delivery_id: target.clone(),
                    incarnation_id: incarnation_id.clone(),
                    inbox_seqs: seqs.clone(),
                },
            )
        })?;
        let response = publication.published().await?;
        let mut gateway = shared.lock().map_err(|_| "gateway")?;
        record_acked_seqs(&mut gateway, &seqs, &target);
        let results: Vec<Value> = response
            .results
            .iter()
            .map(|result| {
                json!({
                    "inbox_seq": result.inbox_seq,
                    "outcome": result.outcome,
                    "reason": result.reason,
                })
            })
            .collect();
        return Ok(json!({
            "frame_type": "ack_batch",
            "incarnation_id": response.incarnation_id,
            "cursor": serde_json::to_value(&response.cursor)?,
            "results": results,
        }));
    }
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
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

/// Scheduling tests admit the control but retain media hold without native call authority.
async fn refuse_fixture_call(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    submit: &GatewaySubmitFrame,
    generation: Option<&str>,
) -> Case {
    let Some(context) = &submit.call_context else { return Ok(()) };
    context.validate()?;
    if generation != Some(context.session_generation.as_str())
        || context.session_id != "courier-session"
        || context.request_id != submit.signed_request.request_id
        || context.envelope_id != submit.envelope.envelope_id
    {
        return Err("test: call submit did not bind its authenticated scheduling session".into());
    }
    let frame = GatewayServerFrame::CallResolved {
        context: context.clone(),
        state: ramflux_protocol::CallResolutionState::Cancelled,
        media_allowed: false,
        wake_resolved: true,
    };
    let bytes = serde_json::to_vec(&frame)?;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}

/// Echo session-push on `session_established` only when Auth advertised the capability.
fn established_session(
    advertised: bool,
    incarnation: Option<&str>,
    call_generation: Option<&str>,
) -> Value {
    let mut session = json!({
        "session_id": "courier-session",
        "gateway_id": "test-gateway",
        "accepted_cursor": null,
        "resume_token": "courier-resume",
        "resume_window_seconds": 60,
    });
    if let Some(generation) = call_generation {
        session["call_session_generation"] = json!(generation);
    }
    if advertised {
        session["capabilities"] = json!([ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY]);
        session["inbox_incarnation_id"] =
            json!(incarnation.unwrap_or("0123456789abcdef0123456789abcdef"));
    }
    json!({ "frame_type": "session_established", "session": session })
}

pub(super) async fn publish_router_envelope(
    router: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: ramflux_protocol::Envelope,
) -> Result<ramflux_node_core::InboxEntry, ramflux_node_core::NodeCoreError> {
    router.prepare_publication_target(store, &envelope.target_delivery_id)?;
    let replay = ramflux_node_core::envelope_replay_tuple_key(source, &envelope);
    let expiry = envelope.created_at.checked_add(i64::from(envelope.ttl)).ok_or_else(|| {
        ramflux_node_core::NodeCoreError::Redb("fixture replay expiry overflow".into())
    })?;
    let now = now_unix_timestamp();
    let admission = store.admit_sender_retry(source, &envelope, now)?;
    let (owner, retry) = match admission {
        ramflux_node_core::sender_retry::RetryAdmission::Owner(owner) => (Some(owner), None),
        ramflux_node_core::sender_retry::RetryAdmission::Accepted(retry) => (None, Some(retry)),
        ramflux_node_core::sender_retry::RetryAdmission::Waiting(waiter) => {
            (None, Some(waiter.resolved().await?))
        }
    };
    let operation = ramflux_node_core::publication::capture(|| {
        if let Some(retry) = retry {
            let assignment = ramflux_node_core::publication::await_sender_retry(
                &store.publication_core()?,
                retry,
            )?;
            return Ok(ramflux_node_core::InboxEntry {
                inbox_seq: assignment.inbox_seq,
                target_delivery_id: assignment.target_delivery_id,
                envelope,
            });
        }
        let owner = owner.ok_or_else(|| {
            ramflux_node_core::NodeCoreError::Redb("test: retry owner missing".into())
        })?;
        owner.bind(&envelope.target_delivery_id)?;
        let entry = match router.submit_envelope(source, envelope) {
            ramflux_node_core::RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
            ramflux_node_core::RouterSubmitOutcome::Online(online) => {
                ramflux_node_core::InboxEntry {
                    inbox_seq: online.inbox_seq,
                    target_delivery_id: online.target_delivery_id,
                    envelope: online.envelope,
                }
            }
            other => {
                return Err(ramflux_node_core::NodeCoreError::Redb(format!(
                    "fixture router submit {other:?}"
                )));
            }
        };
        store.record_submission_increment_for_sender(
            &replay,
            expiry,
            Some(&entry),
            Some(source.root_commitment()),
        )?;
        owner.accepted_entry(store, source.root_commitment(), &entry, now);
        Ok(entry)
    })?;
    operation.published().await
}

async fn record_router_submit(
    shared: &Arc<Mutex<Gateway>>,
    envelope: &ramflux_protocol::Envelope,
) -> Case<Option<(String, u64)>> {
    let (router, store, source) = {
        let gateway = shared.lock().map_err(|_| "gateway")?;
        let Some((router, store)) = gateway.router.clone() else {
            return Ok(None);
        };
        let source = gateway
            .router_sources
            .get(&envelope.source_device_id)
            .ok_or("router source identity")?
            .clone();
        (router, store, source)
    };
    router.prepare_publication_target(&store, &envelope.target_delivery_id)?;
    let incarnation = store.initialize_inbox(&envelope.target_delivery_id)?;
    let entry = publish_router_envelope(&router, &store, &source, envelope.clone()).await?;
    let sequence = entry.inbox_seq;
    let mut gateway = shared.lock().map_err(|_| "gateway")?;
    if !gateway.inbox.iter().any(|old| {
        old.target_delivery_id == entry.target_delivery_id
            && old.envelope.envelope_id == entry.envelope.envelope_id
    }) {
        gateway.inbox.push(GatewayInboxEntry {
            forwarded: false,
            inbox_seq: sequence,
            target_delivery_id: entry.target_delivery_id,
            envelope: entry.envelope,
        });
    }
    Ok(Some((incarnation, sequence)))
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

/// Inbound preparation owns cached verified keys; any unexpected peer I/O fails the fixture.
struct NativeNoNetwork;
impl ramflux_transport::GatewaySessionFrameSink for NativeNoNetwork {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> ramflux_transport::GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic(
                "test: unexpected inbound preparation I/O".into(),
            ))
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NativeNoNetwork {
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn recv_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic(
                "test: unexpected inbound preparation reply".into(),
            ))
        })
    }
}
