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
    addr: std::net::SocketAddr,
    ca: PathBuf,
    records: Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>,
    unavailable: Arc<AtomicBool>,
    server: tokio::task::JoinHandle<Result<(), SdkError>>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Directory {
    async fn new(a: &Fixture, b: &Fixture) -> Result<Self, SdkError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["directory.test".into()])
            .map_err(|e| invalid(&e.to_string()))?;
        let ca = a.root.join("directory.pem");
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
        let records =
            Arc::new(std::sync::Mutex::new(vec![super::r9::manifest(a)?, super::r9::manifest(b)?]));
        let observed = records.clone();
        let unavailable = Arc::new(AtomicBool::new(false));
        let failure = unavailable.clone();
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            while let Ok((socket, _)) = listener.accept().await {
                let stream = tokio_rustls::TlsStream::Server(acceptor.accept(socket).await?);
                let (mut recv, mut send) = tokio::io::split(stream);
                let request: ramflux_transport::GatewayQuicRequest =
                    ramflux_transport::read_gateway_session_json(&mut recv).await?;
                assert_eq!(request.method, "GET");

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
        Ok(Self { addr, ca, records, unavailable, server })
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
    records: Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>,
    unavailable: Arc<AtomicBool>,
    responses: VecDeque<Vec<u8>>,
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
                GatewayClientFrame::IdentityRegister { .. } => {
                    GatewayServerFrame::IdentityRegistrationRejected {
                        reason_code: ramflux_protocol::IdentityDirectoryReason::RateLimited,
                    }
                }
                GatewayClientFrame::Heartbeat { now } => GatewayServerFrame::Heartbeat { now },
                GatewayClientFrame::Resume { .. } => {
                    GatewayServerFrame::Resume { entries: Vec::new() }
                }
                _ => {
                    return Err(ramflux_transport::TransportError::Quic(
                        "unexpected directory frame".into(),
                    ));
                }
            };
            self.responses.push_back(serde_json::to_vec(&response)?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for DirectorySession {
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
fn state(a: &mut Fixture, b: &mut Fixture, d: &Directory) -> Result<LocalBusDaemonState, SdkError> {
    let mut accounts = BTreeMap::new();
    for f in [&mut *a, &mut *b] {
        let engine = GatewaySessionEngine::with_test_transport(
            d.config(f)?,
            Box::new(DirectorySession {
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
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let mut s = state(&mut a, &mut b, &d)?;
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
    assert!(b.client.account_db()?.client_record("device", "alice")?.is_some());
    let first = seal(&a, &b, message("contact-first", "contact-conversation"), b"hello after add")?;
    let opened = b.client.open_routed(&first, "bob")?;
    assert_eq!(opened.body.as_slice(), b"hello after add");
    b.client.persist_pair("bob", "alice", &opened.bundle_hash, &opened.session)?;
    let mut reply = message("contact-reply", "contact-conversation");
    reply.source_principal_id = "bob".into();
    reply.sender_id = "bob".into();
    reply.recipient_device_id = Some("alice".into());
    reply.target_delivery_id = "alice".into();
    let entry = seal(&b, &a, reply, b"reply after accept")?;
    assert_eq!(a.client.open_routed(&entry, "alice")?.body.as_slice(), b"reply after accept");
    Ok(())
}

#[tokio::test]
async fn accepting_a_pending_request_resolves_the_requester_without_device_hints()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let mut s = state(&mut a, &mut b, &d)?;
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
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let mut s = state(&mut a, &mut b, &d)?;
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
    call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    let duplicate = call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"}))
        .await
        .err()
        .ok_or_else(|| invalid("duplicate"))?;
    assert!(matches!(duplicate, SdkError::ContactInput(crate::ContactReason::AlreadyContact)));
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
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
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

#[tokio::test]
async fn a_legacy_commitment_selector_cannot_be_redirected_to_a_principal_with_that_name()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let expected = super::r9::manifest(&b)?.principal_commitment;
    let impostor = Fixture::new(&expected, 81)?;
    let directory = Directory::new(&a, &b).await?;
    directory
        .records
        .lock()
        .map_err(|_| invalid("directory mutex"))?
        .push(super::r9::manifest(&impostor)?);
    let mut state = state(&mut a, &mut b, &directory)?;
    let added = call(
        &mut state,
        "alice",
        "contact.add",
        json!({"link_id":"commitment-contact","requester_id":"alice","target_id":expected}),
    )
    .await?;
    assert_eq!(added["contact"]["principal_id"], "bob");
    assert_eq!(added["contact"]["root_commitment"], expected);
    let client = &state.accounts.get("alice").ok_or_else(|| invalid("alice"))?.client;
    assert!(client.account_db()?.client_record("identity", &expected)?.is_none());
    assert!(client.account_db()?.client_record("device", "bob")?.is_some());
    Ok(())
}

#[path = "contact_recovery_tests.rs"]
mod recovery;
