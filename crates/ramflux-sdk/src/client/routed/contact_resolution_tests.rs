// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-contact resolution through the public bus and certificate-verified directory requests.
use super::*;
use crate::bus::protocol::{LocalBusFrame, LocalBusFrameKind};
use crate::bus::state::{LocalBusAccountState, LocalBusDaemonState};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct Directory {
    captured: Arc<std::sync::Mutex<Vec<ramflux_protocol::Envelope>>>,
    incoming: Arc<std::sync::Mutex<Vec<GatewayInboxEntry>>>,
    acknowledged: Arc<std::sync::Mutex<Option<crate::GatewayCursor>>>,
    addr: std::net::SocketAddr,
    ca: PathBuf,
    records: Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>,
    unavailable: Arc<AtomicBool>,
    manifest_fetches: Arc<std::sync::atomic::AtomicUsize>,
    server: tokio::task::JoinHandle<Result<(), SdkError>>,
    /// Account roots must outlive the bus clients that store their databases.
    anchors: Vec<crate::custody::tests::Root>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Directory {
    async fn new(a: &Fixture, b: &Fixture) -> Result<Self, SdkError> {
        Self::from_records(&a.root, vec![super::r9::manifest(a)?, super::r9::manifest(b)?]).await
    }
    async fn from_records(
        root: &Path,
        manifests: Vec<crate::prekey::SdkDeviceManifestResponse>,
    ) -> Result<Self, SdkError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["directory.test".into()])
            .map_err(|e| invalid(&e.to_string()))?;
        let ca = root.join("directory.pem");
        std::fs::write(&ca, cert.cert.pem())?;
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .map_err(|e| invalid(&e.to_string()))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let records = Arc::new(std::sync::Mutex::new(manifests));
        let observed = records.clone();
        let unavailable = Arc::new(AtomicBool::new(false));
        let failure = unavailable.clone();
        let manifest_fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetches = manifest_fetches.clone();
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            while let Ok((socket, _)) = listener.accept().await {
                let stream = tokio_rustls::TlsStream::Server(acceptor.accept(socket).await?);
                let (mut recv, mut send) = tokio::io::split(stream);
                let request: ramflux_transport::GatewayQuicRequest =
                    ramflux_transport::read_gateway_session_json(&mut recv).await?;
                assert_eq!(request.method, "GET");

                fetches.fetch_add(1, Ordering::SeqCst);
                let commitment = request.path.strip_prefix("/mvp1/device-manifest/");
                assert!(commitment.is_some(), "names require the authenticated frame");
                let body = {
                    let records = observed.lock().map_err(|_| invalid("directory mutex"))?;
                    records
                        .iter()
                        .find(|m| commitment == Some(m.principal_commitment.as_str()))
                        .map(serde_json::to_value)
                        .transpose()?
                        .unwrap_or(Value::Null)
                };
                ramflux_transport::write_gateway_session_json(
                    &mut send,
                    &ramflux_transport::GatewayQuicResponse {
                        status: if failure.load(Ordering::SeqCst) { 503 } else { 200 },
                        body,
                    },
                )
                .await?;
            }
            Ok(())
        });
        Ok(Self {
            captured: Arc::default(),
            incoming: Arc::default(),
            acknowledged: Arc::default(),
            addr,
            ca,
            records,
            unavailable,
            manifest_fetches,
            server,
            anchors: Vec::new(),
        })
    }
    fn config(&self, f: &Fixture) -> Result<GatewaySessionConfig, SdkError> {
        let mut c = f.config()?;
        c.transport_kind = GatewaySessionTransportKind::TcpTls;
        c.gateway_addr = self.addr;
        c.tcp_gateway_addr = Some(self.addr);
        c.server_name = "directory.test".into();
        c.ca_cert = self.ca.clone();
        Ok(c)
    }
}
// The bus account already owns an authenticated session. Raw TLS requests below
// remain available only for hash-addressed manifests, never for name lookup.
struct DirectorySession {
    captured: Arc<std::sync::Mutex<Vec<ramflux_protocol::Envelope>>>,
    incoming: Arc<std::sync::Mutex<Vec<GatewayInboxEntry>>>,
    acknowledged: Arc<std::sync::Mutex<Option<crate::GatewayCursor>>>,
    records: Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>,
    unavailable: Arc<AtomicBool>,
    responses: VecDeque<Vec<u8>>,
}
impl DirectorySession {
    fn reply(
        &mut self,
        response: &GatewayServerFrame,
    ) -> Result<(), ramflux_transport::TransportError> {
        let cursor = match response {
            GatewayServerFrame::Ack { cursor } => Some(cursor.clone()),
            _ => None,
        };
        self.responses.push_back(serde_json::to_vec(response)?);
        if let Some(cursor) = cursor {
            self.responses.push_back(serde_json::to_vec(&GatewayServerFrame::Cursor {
                cursor: Some(cursor),
            })?);
        }
        Ok(())
    }

    fn prekey_response(
        &self,
        device_id: &str,
    ) -> Result<GatewayServerFrame, ramflux_transport::TransportError> {
        let address = ramflux_protocol::parse_qualified_device_id(device_id)
            .map_err(|error| ramflux_transport::TransportError::Quic(error.to_string()))?;
        let raw = address.as_ref().map_or(device_id, |(_, raw)| raw.as_str());
        let records = self
            .records
            .lock()
            .map_err(|_| ramflux_transport::TransportError::Quic("directory mutex".into()))?;
        let entry = records
            .iter()
            .filter(|m| address.as_ref().is_none_or(|(root, _)| *root == m.principal_commitment))
            .flat_map(|m| m.devices.iter())
            .find(|d| d.device_id == raw)
            .ok_or_else(|| {
                ramflux_transport::TransportError::Quic("prekey fixture missing".into())
            })?;
        Ok(GatewayServerFrame::Prekey {
            response: crate::prekey::SdkPrekeyResponse {
                device_id: raw.into(),
                principal_commitment: entry.principal_commitment.clone(),
                bundle: Some(entry.prekey_bundle.clone()),
                target_delivery_id: Some(entry.target_delivery_id.clone()),
            },
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSink for DirectorySession {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let frame: GatewayClientFrame = serde_json::from_slice(body)?;
            if self.unavailable.load(Ordering::SeqCst)
                && matches!(frame, GatewayClientFrame::PrincipalManifestFetch { .. })
            {
                return Err(ramflux_transport::TransportError::Quic("directory offline".into()));
            }
            let response = match frame {
                GatewayClientFrame::PrincipalManifestFetch { principal_id } => {
                    let manifest = self
                        .records
                        .lock()
                        .map_err(|_| {
                            ramflux_transport::TransportError::Quic("directory mutex".into())
                        })?
                        .iter()
                        .find(|m| m.principal_id == principal_id)
                        .map(serde_json::to_value)
                        .transpose()?;
                    GatewayServerFrame::PrincipalManifest {
                        response: ramflux_protocol::PrincipalLookupResponse {
                            manifest,
                            reason_code: None,
                        },
                    }
                }
                GatewayClientFrame::Submit { submit } => {
                    self.captured
                        .lock()
                        .map_err(|_| {
                            ramflux_transport::TransportError::Quic("capture mutex".into())
                        })?
                        .push(submit.envelope.clone());
                    GatewayServerFrame::Deliver { entry: delivered_entry(submit.envelope) }
                }
                GatewayClientFrame::PrekeyFetch { device_id } => {
                    self.prekey_response(&device_id)?
                }
                GatewayClientFrame::IdentityRegister { .. } => {
                    GatewayServerFrame::IdentityRegistrationRejected {
                        reason_code: ramflux_protocol::IdentityDirectoryReason::RateLimited,
                    }
                }
                GatewayClientFrame::Heartbeat { now } => GatewayServerFrame::Heartbeat { now },
                GatewayClientFrame::Resume { resume } => {
                    let entries = self
                        .incoming
                        .lock()
                        .map_err(|_| ramflux_transport::TransportError::Quic("inbox lock".into()))?
                        .iter()
                        .filter(|entry| entry.inbox_seq > resume.after_inbox_seq)
                        .take(resume.limit)
                        .cloned()
                        .collect();
                    GatewayServerFrame::Resume { entries }
                }
                GatewayClientFrame::Ack { ack } => {
                    let mut incoming = self.incoming.lock().map_err(|_| {
                        ramflux_transport::TransportError::Quic("inbox lock".into())
                    })?;
                    let seq = incoming
                        .iter()
                        .find(|entry| entry.envelope.envelope_id == ack.envelope_id)
                        .map_or(0, |entry| entry.inbox_seq);
                    incoming.retain(|entry| entry.envelope.envelope_id != ack.envelope_id);
                    let mut saved = self.acknowledged.lock().map_err(|_| {
                        ramflux_transport::TransportError::Quic("cursor lock".into())
                    })?;
                    let cursor = crate::GatewayCursor {
                        target_delivery_id: "bob".into(),
                        inbox_seq: seq.max(saved.as_ref().map_or(0, |cursor| cursor.inbox_seq)),
                        last_envelope_id: Some(ack.envelope_id.clone()),
                        acked_envelope_ids: vec![ack.envelope_id],
                        nacked_envelope_ids: BTreeMap::new(),
                    };
                    *saved = Some(cursor.clone());
                    GatewayServerFrame::Ack { cursor }
                }
                GatewayClientFrame::Cursor { .. } => GatewayServerFrame::Cursor {
                    cursor: self
                        .acknowledged
                        .lock()
                        .map_err(|_| ramflux_transport::TransportError::Quic("cursor lock".into()))?
                        .clone(),
                },
                _ => {
                    return Err(ramflux_transport::TransportError::Quic(
                        "unexpected directory frame".into(),
                    ));
                }
            };
            self.reply(&response)
        })
    }
}

fn delivered_entry(envelope: ramflux_protocol::Envelope) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    }
}
impl ramflux_transport::GatewaySessionFrameSource for DirectorySession {
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        // Replies are queued only after a request; this fixture has no unsolicited traffic.
        Box::pin(std::future::pending())
    }

    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            self.responses.pop_front().ok_or_else(|| {
                ramflux_transport::TransportError::Quic("empty directory session".into())
            })
        })
    }
}
fn native_account(error: Box<dyn std::error::Error>) -> SdkError {
    let message = error.to_string();
    drop(error);
    invalid(&message)
}

fn born_state(
    a: &mut crate::client::native_test_support::Fixture,
    b: &mut crate::client::native_test_support::Fixture,
    d: &Directory,
) -> Result<LocalBusDaemonState, SdkError> {
    let mut accounts = BTreeMap::new();
    for fixture in [&mut *a, &mut *b] {
        let mut config = fixture.config.clone();
        config.transport_kind = GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = d.addr;
        config.tcp_gateway_addr = Some(d.addr);
        config.server_name = "directory.test".into();
        config.ca_cert.clone_from(&d.ca);
        let engine = GatewaySessionEngine::with_test_transport(
            config,
            Box::new(DirectorySession {
                captured: d.captured.clone(),
                incoming: d.incoming.clone(),
                acknowledged: d.acknowledged.clone(),
                records: d.records.clone(),
                unavailable: d.unavailable.clone(),
                responses: VecDeque::new(),
            }),
        );
        let id = fixture.client.account_db()?.local_account_id.clone();
        accounts.insert(
            id,
            LocalBusAccountState::new(
                std::mem::take(&mut fixture.client),
                engine,
                fixture.manifest.principal_commitment.clone(),
            ),
        );
    }
    Ok(LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(a.root.0.join("bus.sock"), &a.root.0),
        accounts,
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    })
}

fn seal_native(
    sender: &crate::client::native_test_support::Fixture,
    receiver: &crate::client::native_test_support::Fixture,
    id: &str,
    conversation: &str,
    body: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: sender.manifest.principal_id.clone(),
        sender_id: sender.config.device_id.clone(),
        recipient_device_id: Some(receiver.config.device_id.clone()),
        recipient_principal_commitment: Some(receiver.manifest.principal_commitment.clone()),
        target_delivery_id: receiver.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let local = sender.client.owned_device_identity()?;
    let remote = receiver.client.owned_device_identity()?;
    let (mut session, header, bundle) = sender.client.new_send_pair(
        &local,
        &message,
        receiver.client.load_x3dh_private_state(&remote)?.bundle,
    )?;
    let sealed = sender.client.seal_routed_with_route(
        &message,
        body,
        Route::direct(),
        SealPair {
            local: &sender.config.device_id,
            remote: remote.storage_key(),
            session: &mut session,
            header,
            bundle,
        },
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed.packet)?;
    let mut envelope = gateway_direct_message_envelope_sealed(
        &sender.config,
        &message,
        None,
        sealed.committed_a0.as_deref(),
    )?;
    crate::dm::add_message_metadata_commitment(
        &sender.config,
        &mut envelope,
        sealed.metadata_commitment,
    )?;
    envelope.source_principal_id.clone_from(&message.source_principal_id);
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &envelope,
    )?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.config.target_delivery_id.clone(),
        envelope,
    })
}

fn install_born(
    directory: &Directory,
    fixture: &mut crate::client::native_test_support::Fixture,
) -> LocalBusAccountState {
    let mut config = fixture.config.clone();
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = directory.addr;
    config.tcp_gateway_addr = Some(directory.addr);
    config.server_name = "directory.test".into();
    config.ca_cert.clone_from(&directory.ca);
    let engine = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(DirectorySession {
            captured: directory.captured.clone(),
            incoming: directory.incoming.clone(),
            acknowledged: directory.acknowledged.clone(),
            records: directory.records.clone(),
            unavailable: directory.unavailable.clone(),
            responses: VecDeque::new(),
        }),
    );
    LocalBusAccountState::new(
        std::mem::take(&mut fixture.client),
        engine,
        fixture.manifest.principal_commitment.clone(),
    )
}

async fn born_member(
    directory: &mut Directory,
    id: &str,
) -> Result<LocalBusAccountState, SdkError> {
    let mut fixture = crate::client::native_test_support::Fixture::named(id, id, id)
        .await
        .map_err(native_account)?;
    directory.records.lock().map_err(|_| invalid("records"))?.push(fixture.manifest.clone());
    let account = install_born(directory, &mut fixture);
    directory.anchors.push(fixture.root);
    Ok(account)
}

async fn born_headless_bus(ids: &[&str]) -> Result<(Directory, LocalBusDaemonState), SdkError> {
    let mut fixtures = Vec::new();
    for id in ids {
        fixtures.push(
            crate::client::native_test_support::Fixture::headless(id, id, id, "Example Human")
                .await
                .map_err(native_account)?,
        );
    }
    assemble_born(fixtures).await
}

async fn assemble_born(
    fixtures: Vec<crate::client::native_test_support::Fixture>,
) -> Result<(Directory, LocalBusDaemonState), SdkError> {
    let root = fixtures.first().ok_or_else(|| invalid("born bus"))?.root.0.clone();
    let manifests = fixtures.iter().map(|fixture| fixture.manifest.clone()).collect::<Vec<_>>();
    let mut directory = Directory::from_records(&root, manifests).await?;
    let mut accounts = BTreeMap::new();
    for mut fixture in fixtures {
        let id = fixture.client.account_db()?.local_account_id.clone();
        accounts.insert(id, install_born(&directory, &mut fixture));
        directory.anchors.push(fixture.root);
    }
    Ok((
        directory,
        LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(root.join("bus.sock"), &root),
            accounts,
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        },
    ))
}

async fn born_bus(ids: &[&str]) -> Result<(Directory, LocalBusDaemonState), SdkError> {
    let mut fixtures = Vec::new();
    for id in ids {
        fixtures.push(
            crate::client::native_test_support::Fixture::named(id, id, id)
                .await
                .map_err(native_account)?,
        );
    }
    assemble_born(fixtures).await
}

fn state(a: &mut Fixture, b: &mut Fixture, d: &Directory) -> Result<LocalBusDaemonState, SdkError> {
    let mut accounts = BTreeMap::new();
    for f in [&mut *a, &mut *b] {
        let engine = GatewaySessionEngine::with_test_transport(
            d.config(f)?,
            Box::new(DirectorySession {
                captured: d.captured.clone(),
                incoming: d.incoming.clone(),
                acknowledged: d.acknowledged.clone(),
                records: d.records.clone(),
                unavailable: d.unavailable.clone(),
                responses: VecDeque::new(),
            }),
        );
        let commitment = super::r9::manifest(f)?.principal_commitment;
        accounts.insert(
            f.id.clone(),
            LocalBusAccountState::new(std::mem::take(&mut f.client), engine, commitment),
        );
    }
    Ok(LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(a.root.join("bus.sock"), &a.root),
        accounts,
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    })
}
fn request(id: &str, method: &str, body: Value) -> LocalBusFrame {
    LocalBusFrame {
        bus_protocol: "ramflux.local_bus.v1".into(),
        frame_id: "contact-test".into(),
        kind: LocalBusFrameKind::Request,
        request_id: "contact-test".into(),
        account_id: Some(id.into()),
        sdk_api: "contact".into(),
        method: method.into(),
        body,
        trace_id: None,
        seq: None,
        at: None,
        deadline_ms: None,
        operation_id: None,
        ok: None,
        error: None,
    }
}
async fn call(
    state: &mut LocalBusDaemonState,
    id: &str,
    method: &str,
    body: Value,
) -> Result<Value, SdkError> {
    Ok(crate::bus::dispatch::contact::dispatch_contact_bus_request(
        &request(id, method, body),
        state,
    )
    .await?
    .response_body)
}

#[tokio::test]
async fn adding_a_principal_resolves_reachability_and_safety_before_the_first_dm()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let d =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let mut s = born_state(&mut a, &mut b, &d)?;
    for (own, peer) in [("alice", "bob"), ("bob", "alice")] {
        let added = call(&mut s, own, "contact.add", json!({"principal_id":peer})).await?;
        assert_eq!(added["contact"]["principal_id"], peer);
        assert_eq!(added["contact"]["reachable"], true);
        assert_eq!(added["contact"]["verified"], false);
        let account = s.accounts.get(own).ok_or_else(|| invalid("account"))?;
        let identity = account
            .client
            .account_db()?
            .client_record("identity", peer)?
            .ok_or_else(|| invalid("identity"))?;
        assert!(identity["safety_number"].as_array().is_some_and(|n| n.len() == 12
            && n.iter().all(|group| {
                group
                    .as_str()
                    .is_some_and(|v| v.len() == 5 && v.bytes().all(|b| b.is_ascii_digit()))
            })));
        let peer_commitment =
            added["contact"]["root_commitment"].as_str().ok_or_else(|| invalid("commitment"))?;
        account.client.require_accepted_friend_link_for_dm_send(
            own,
            &account.principal_commitment,
            Some(peer),
            peer_commitment,
        )?;
        let safety = call(
            &mut s,
            own,
            "contact.safety_number",
            json!({"contact_identity_commitment":peer_commitment}),
        )
        .await?;
        assert_eq!(identity["safety_number"], safety["safety_number"]);
    }
    a.client =
        std::mem::take(&mut s.accounts.get_mut("alice").ok_or_else(|| invalid("alice"))?.client);
    b.client = std::mem::take(&mut s.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?.client);
    let alice_device = a.client.owned_device_identity()?.storage_key().to_owned();
    let recorded = b.client.account_db()?.client_record("device", &alice_device)?;
    assert_eq!(recorded.as_ref().and_then(|row| row["device_id"].as_str()), Some("alice"));
    let first = seal_native(&a, &b, "contact-first", "contact-conversation", b"hello after add")?;
    let opened = b.client.open_routed(&first, "bob")?;
    assert_eq!(opened.body.as_slice(), b"hello after add");
    b.client.persist_pair(
        &opened.local_device,
        &opened.remote_device,
        &opened.bundle_hash,
        &opened.session,
    )?;
    let entry =
        seal_native(&b, &a, "contact-reply", "contact-conversation", b"reply after accept")?;
    assert_eq!(a.client.open_routed(&entry, "alice")?.body.as_slice(), b"reply after accept");
    Ok(())
}

#[tokio::test]
async fn accepting_a_pending_request_resolves_the_requester_without_device_hints()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let d =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let mut s = born_state(&mut a, &mut b, &d)?;
    s.accounts
        .get("bob")
        .ok_or_else(|| invalid("account"))?
        .client
        .record_pending_friend_link("request", "alice", "bob")?;
    let accepted = call(&mut s, "bob", "contact.accept", json!({"link_id":"request"})).await?;
    assert_eq!(accepted["contact"]["principal_id"], "alice");
    assert_eq!(accepted["contact"]["reachable"], true);
    assert_eq!(accepted["state"], "accepted");
    let bob = s.accounts.get("bob").ok_or_else(|| invalid("bob"))?;
    let alice = bob
        .client
        .account_db()?
        .client_record("identity", "alice")?
        .ok_or_else(|| invalid("alice"))?;
    assert_eq!(accepted["requester_id"], alice["contact_identity_commitment"]);
    assert_eq!(accepted["target_id"], bob.principal_commitment);
    Ok(())
}

#[tokio::test]
async fn failed_directory_resolution_preserves_contacts_and_returns_retryable_or_typed_errors()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let d =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let mut s = born_state(&mut a, &mut b, &d)?;
    for (body, expected) in [
        (json!({"principal_id":"missing"}), crate::ContactReason::UnknownPrincipal),
        (json!({"principal_id":"alice"}), crate::ContactReason::SelfContact),
        (json!({"principal_id":"bob","card":"bad"}), crate::ContactReason::InvalidCard),
    ] {
        let error = call(&mut s, "alice", "contact.add", body)
            .await
            .err()
            .ok_or_else(|| invalid("expected error"))?;
        let wire = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(wire.code, "ValidationFailed");
        assert_eq!(wire.reason_code, Some(expected.to_string()));
    }
    d.unavailable.store(true, Ordering::SeqCst);
    let error = call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"}))
        .await
        .err()
        .ok_or_else(|| invalid("transient failure"))?;
    assert_eq!(crate::bus::io::local_bus_error_body(&error).code, "Unavailable");
    assert_eq!(
        s.accounts.get("alice").ok_or_else(|| invalid("account"))?.client.friend_links()?.len(),
        0
    );
    d.unavailable.store(false, Ordering::SeqCst);
    // D1: a transport failure retires the managed session; reconnect the fixture.
    let account = s.accounts.get_mut("alice").ok_or_else(|| invalid("account"))?;
    account.install_test_session(GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(DirectorySession {
            captured: d.captured.clone(),
            incoming: d.incoming.clone(),
            acknowledged: d.acknowledged.clone(),
            records: d.records.clone(),
            unavailable: d.unavailable.clone(),
            responses: VecDeque::new(),
        }),
    ));
    call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    let first = call(&mut s, "alice", "contact.list", json!({})).await?;
    let retry = call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    assert_eq!(retry["contact"]["request_id"], first["contacts"][0]["request_id"]);
    assert_eq!(
        s.accounts.get("alice").ok_or_else(|| invalid("account"))?.client.friend_links()?.len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn directory_root_changes_cannot_replace_an_existing_contact_pin() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let expected = super::r9::manifest(&b)?;
    a.client.persist_identity_directory(&expected)?;
    let impostor = Fixture::new("bob", 71)?;
    d.records.lock().map_err(|_| invalid("mutex"))?[1] = super::r9::manifest(&impostor)?;
    let mut s = state(&mut a, &mut b, &d)?;
    assert!(call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"})).await.is_err());
    let client = &s.accounts.get("alice").ok_or_else(|| invalid("account"))?.client;
    assert_eq!(
        client
            .account_db()?
            .client_record("identity", "bob")?
            .ok_or_else(|| invalid("identity"))?["contact_identity_commitment"],
        expected.principal_commitment
    );
    assert_eq!(client.friend_links()?.len(), 0);
    Ok(())
}

#[path = "contact_card_tests.rs"]
mod cards;

#[tokio::test]
async fn a_legacy_principal_link_becomes_reachable_without_an_unrelated_identity_lookup()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let directory =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let mut state = born_state(&mut a, &mut b, &directory)?;
    let added = call(
        &mut state,
        "alice",
        "contact.add",
        json!({"link_id":"legacy-contact","requester_id":"alice","target_id":"bob"}),
    )
    .await?;
    assert_eq!(added["state"], "accepted");
    let client = &state.accounts.get("alice").ok_or_else(|| invalid("alice"))?.client;
    let identity = client
        .account_db()?
        .client_record("identity", "bob")?
        .ok_or_else(|| invalid("adding the principal did not resolve its identity"))?;
    assert_eq!(identity["devices"].as_array().map(Vec::len), Some(1));
    assert!(client.account_db()?.client_record("device", "bob")?.is_some());
    assert!(client.account_db()?.device_directory_entry("bob")?.is_some());
    assert_eq!(identity["safety_number"].as_array().map(Vec::len), Some(12));
    assert_eq!(added["contact"]["reachable"], true);
    Ok(())
}

#[path = "contact_recovery_tests.rs"]
mod recovery;

#[tokio::test]
async fn two_hour_old_accounts_resolve_add_contacts_and_authorize_new_prekeys()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let directory =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let mut state = born_state(&mut a, &mut b, &directory)?;
    for (own, peer) in [("alice", "bob"), ("bob", "alice")] {
        let added = call(&mut state, own, "contact.add", json!({"principal_id":peer})).await?;
        assert_eq!(added["contact"]["principal_id"], peer);
        assert_eq!(added["contact"]["reachable"], true);
        let manifests = directory.records.lock().map_err(|_| invalid("directory mutex"))?;
        let manifest =
            manifests.iter().find(|m| m.principal_id == peer).ok_or_else(|| invalid("manifest"))?;
        let device = manifest.devices.first().ok_or_else(|| invalid("device"))?;
        let client = &state.accounts.get(own).ok_or_else(|| invalid("account"))?.client;
        let identity =
            client.device_identity_for_root(&manifest.principal_commitment, &device.device_id)?;
        client.verify_root_bound_prekey(&identity, &device.prekey_bundle)?;
    }
    Ok(())
}

#[path = "contact_request_tests.rs"]
mod requests;

#[path = "native_contact_transport_tests.rs"]
mod native_transport;
