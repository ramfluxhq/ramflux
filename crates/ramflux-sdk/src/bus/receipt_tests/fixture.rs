// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Two independent daemon accounts connected by an in-process authenticated-envelope mailbox.
use crate::bus::{actor::AccountInitializer, supervisor::Supervisor};
use crate::prelude::*;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use serde_json::json;
use std::sync::{Arc, Mutex};
pub(super) type Shared = Arc<Mutex<Mailbox>>;
pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Default)]
pub(super) struct Mailbox {
    pub messages: Vec<GatewayInboxEntry>,
    pub submissions: Vec<ramflux_protocol::Envelope>,
    pub acked: BTreeSet<(String, String)>,
    pub lose_ack: bool,
    pub stall_receipts: bool,
    pub reject_id: Option<String>,
}
#[derive(Clone)]
pub(super) struct Spec {
    pub root: PathBuf,
    pub principal: String,
    pub device: String,
    pub seed: u8,
}
impl Spec {
    pub fn new(root: &Path, principal: &str, seed: u8) -> Self {
        Self {
            root: root.join(principal),
            principal: principal.into(),
            device: format!("device-{principal}"),
            seed,
        }
    }
    pub fn client(&self, index: Option<AccountIndex>) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.account_index = index;
        client.create_identity_root(&self.principal, [self.seed; 32]);
        client.create_device_branch(&self.principal, &self.device, 1, [self.seed + 1; 32]);
        client.open_account_index(&self.root)?;
        if client.account_index()?.account(&self.principal).is_err() {
            client.create_account(&self.principal, &client.surface_local_root_commitment()?)?;
        }
        client.unlock_account(&self.principal, b"receipt-test")?;
        client.initialize_and_publish_prekey_bundle(
            &client.surface_local_root_commitment()?,
            &self.device,
            &self.device,
            [self.seed + 1; 32],
            None,
        )?;
        client.persist_identity_directory(
            &crate::client::identity_authority::test_support::manifest(&client)?,
        )?;
        Ok(client)
    }
    pub fn config(&self, client: &RamfluxClient) -> Result<GatewaySessionConfig, SdkError> {
        GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::IdentityRootMissing)?,
            gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::IdentityRootMissing)?,
            server_name: "receipt-test".into(),
            ca_cert: self.root.join("ca.pem"),
            principal_id: self.principal.clone(),
            device_id: self.device.clone(),
            target_delivery_id: self.device.clone(),
            prekey_http_url: None,
        })
        .with_account_identity(client)
    }
    pub fn account(
        &self,
        index: Option<AccountIndex>,
        mail: Shared,
    ) -> Result<LocalBusAccountState, SdkError> {
        let client = self.client(index)?;
        let config = self.config(&client)?;
        let root = client.surface_local_root_commitment()?;
        Ok(LocalBusAccountState::new(
            client,
            GatewaySessionEngine::with_test_transport(
                config,
                Box::new(Gateway { target: self.device.clone(), mail, last: None, cursor: None }),
            ),
            root,
        ))
    }
    pub fn daemon(&self, mail: Shared) -> Result<Rc<Supervisor>, SdkError> {
        let spec = self.clone();
        let initialize: AccountInitializer = Box::new(move |index| spec.account(Some(index), mail));
        let daemon = Supervisor::from_initializers(
            &LocalBusConfig::new(self.root.join("daemon.sock"), &self.root),
            vec![(self.principal.clone(), initialize)],
            None,
        )?;
        daemon.start_test_event_router();
        Ok(daemon)
    }
    pub fn trust(&self, client: &RamfluxClient, other: &Spec) -> Result<(), SdkError> {
        let peer = other.client(None)?;
        let manifest = crate::client::identity_authority::test_support::manifest(&peer)?;
        client.persist_identity_directory(&manifest)?;
        let identity = other.identity()?;
        let db = client.account_db()?;
        let mut row = db.client_device_record(&identity)?.ok_or(SdkError::IdentityRootMissing)?;
        row["label"] = json!("Laptop");
        db.persist_client_record("device", identity.storage_key(), &row)?;
        if self.principal != other.principal {
            db.establish_friend_link(
                &format!("friend:{}", other.principal),
                &client.surface_local_root_commitment()?,
                &manifest.principal_commitment,
            )?;
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<ramflux_crypto::RootQualifiedDeviceRef, SdkError> {
        Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
            &ramflux_crypto::create_identity_root(&self.principal, [self.seed; 32]),
            &ramflux_crypto::create_device_branch(
                &self.principal,
                &self.device,
                1,
                [self.seed + 1; 32],
            ),
        )?)
    }
    pub fn message(&self, to: &Spec, id: &str) -> GatewayDirectMessage {
        GatewayDirectMessage {
            conversation_id: "thread".into(),
            message_id: id.into(),
            envelope_id: id.into(),
            source_principal_id: self.principal.clone(),
            sender_id: self.device.clone(),
            recipient_device_id: Some(to.device.clone()),
            recipient_principal_commitment: Some(ramflux_crypto::identity_root_commitment(
                &ramflux_crypto::create_identity_root(&to.principal, [to.seed; 32])
                    .signing_key
                    .verifying_key(),
            )),
            target_delivery_id: to.device.clone(),
            encrypted_body: vec![],
            created_at: now_unix_timestamp(),
            ttl: 600,
        }
    }
}
pub(super) fn seed_pair(a: &Spec, b: &Spec) -> TestResult {
    let one = a.client(None)?;
    let two = b.client(None)?;
    a.trust(&one, a)?;
    a.trust(&one, b)?;
    b.trust(&two, a)?;
    b.trust(&two, b)?;
    let sender = ramflux_crypto::DmSession::initiator(
        [17; 32],
        dm_device_id_hash(&a.device),
        dm_device_id_hash(&b.device),
        [3; 32],
    )?;
    let receiver = ramflux_crypto::DmSession::recipient(
        [17; 32],
        dm_device_id_hash(&b.device),
        dm_device_id_hash(&a.device),
        [3; 32],
    )?;
    one.persist_pair(&a.identity()?, &b.identity()?, &[4; 32], &sender)?;
    two.persist_pair(&b.identity()?, &a.identity()?, &[4; 32], &receiver)?;
    for client in [&one, &two] {
        client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":[a.principal,b.principal]}),
        )?;
    }
    Ok(())
}
pub(super) async fn socket(
    spec: &Spec,
    daemon: Rc<Supervisor>,
) -> Result<(LocalBusClient, tokio::task::JoinHandle<Result<(), SdkError>>), SdkError> {
    let path = spec.root.join("observer.sock");
    let listener = UnixListener::bind(&path)?;
    let client = LocalBusClient::connect(&path).await?;
    let (stream, _) = listener.accept().await?;
    let task = tokio::task::spawn_local(crate::bus::connection::handle(stream, daemon, 1));
    std::fs::remove_file(path)?;
    Ok((client, task))
}
pub(super) async fn delivered(
    client: &LocalBusClient,
    principal: &str,
    id: &str,
    count: usize,
) -> Result<serde_json::Value, SdkError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let body = client
            .request_frame(LocalBusFrame::request(
                "observe",
                Some(principal.into()),
                "test",
                "message.read",
                json!({"conversation_id":"thread"}),
            ))
            .await?;
        if body["messages"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row["message_id"] == id
                    && row["receipts"].as_array().is_some_and(|receipts| {
                        receipts.iter().filter(|r| r["state"] == "delivered").count() == count
                    })
            })
        }) {
            return Ok(body);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SdkError::LocalBus(format!(
                "delivery timeout for {id}; receipts: {:?}",
                body["messages"].as_array().map(|rows| rows
                    .iter()
                    .map(|row| (&row["message_id"], &row["receipts"]))
                    .collect::<Vec<_>>())
            )));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
struct Gateway {
    target: String,
    mail: Shared,
    last: Option<GatewayClientFrame>,
    cursor: Option<GatewayCursor>,
}
type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;
impl GatewaySessionFrameSink for Gateway {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            let frame =
                serde_json::from_slice(bytes).map_err(|e| TransportError::Quic(e.to_string()))?;
            let stall = {
                let mail = self
                    .mail
                    .lock()
                    .map_err(|_| TransportError::Quic("mailbox poisoned".into()))?;
                mail.stall_receipts && matches!(frame, GatewayClientFrame::Submit { .. })
            };
            if stall {
                return std::future::pending().await;
            }
            self.last = Some(frame);
            Ok(())
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for Gateway {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            if let Some(cursor) = self.cursor.take() {
                return serde_json::to_vec(&GatewayServerFrame::Cursor { cursor: Some(cursor) })
                    .map_err(|e| TransportError::Quic(e.to_string()));
            }
            let frame = match self.last.take() {
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                Some(GatewayClientFrame::Submit { submit }) => {
                    let mut mail = self
                        .mail
                        .lock()
                        .map_err(|_| TransportError::Quic("mailbox poisoned".into()))?;
                    let envelope = submit.envelope;
                    mail.submissions.push(envelope.clone());
                    if mail.reject_id.as_deref() == Some(envelope.envelope_id.as_str()) {
                        return Err(TransportError::Quic("injected receipt refusal".into()));
                    }
                    let entry = if let Some(existing) = mail.messages.iter().find(|e| {
                        e.envelope.source_device_id == envelope.source_device_id
                            && e.envelope.envelope_id == envelope.envelope_id
                            && e.target_delivery_id == envelope.target_delivery_id
                    }) {
                        existing.clone()
                    } else {
                        let entry = GatewayInboxEntry {
                            inbox_seq: u64::try_from(mail.messages.len() + 1)
                                .map_err(|e| TransportError::Quic(e.to_string()))?,
                            target_delivery_id: envelope.target_delivery_id.clone(),
                            envelope,
                        };
                        mail.messages.push(entry.clone());
                        entry
                    };
                    if mail.lose_ack {
                        mail.lose_ack = false;
                        return Err(TransportError::Quic("injected lost submit response".into()));
                    }
                    GatewayServerFrame::Deliver { entry }
                }
                Some(GatewayClientFrame::Resume { resume }) => {
                    let mail = self
                        .mail
                        .lock()
                        .map_err(|_| TransportError::Quic("mailbox poisoned".into()))?;
                    GatewayServerFrame::Resume {
                        entries: mail
                            .messages
                            .iter()
                            .filter(|e| {
                                e.target_delivery_id == self.target
                                    && e.inbox_seq > resume.after_inbox_seq
                                    && !mail.acked.contains(&(
                                        self.target.clone(),
                                        e.envelope.envelope_id.clone(),
                                    ))
                            })
                            .take(resume.limit)
                            .cloned()
                            .collect(),
                    }
                }
                Some(GatewayClientFrame::Ack { ack }) => {
                    let mut mail = self
                        .mail
                        .lock()
                        .map_err(|_| TransportError::Quic("mailbox poisoned".into()))?;
                    let seq = mail
                        .messages
                        .iter()
                        .find(|e| {
                            e.target_delivery_id == self.target
                                && e.envelope.envelope_id == ack.envelope_id
                        })
                        .map_or(0, |e| e.inbox_seq);
                    mail.acked.insert((self.target.clone(), ack.envelope_id.clone()));
                    let cursor = GatewayCursor {
                        target_delivery_id: self.target.clone(),
                        inbox_seq: seq,
                        last_envelope_id: Some(ack.envelope_id.clone()),
                        acked_envelope_ids: vec![ack.envelope_id],
                        nacked_envelope_ids: BTreeMap::new(),
                    };
                    self.cursor = Some(cursor.clone());
                    GatewayServerFrame::Ack { cursor }
                }
                _ => GatewayServerFrame::Nack { reason: "unexpected receipt fixture frame".into() },
            };
            serde_json::to_vec(&frame).map_err(|e| TransportError::Quic(e.to_string()))
        })
    }
}

pub(super) async fn explicit_noop(
    receiver: &Spec,
    peer: &Spec,
    mail: Shared,
    state: &str,
    sent: usize,
) -> TestResult {
    let daemon = receiver.daemon(mail.clone())?;
    let (bus, server) = socket(receiver, Rc::clone(&daemon)).await?;
    let response = bus
        .request_frame(LocalBusFrame::request(
            "explicit",
            Some(receiver.principal.clone()),
            "test",
            "message.receipt.delivered",
            json!({
                "conversation_id": "thread", "message_id": "dm-one",
                "receiver_device_id": receiver.device, "recipient_device_id": peer.device,
                "target_delivery_id": peer.device,
            }),
        ))
        .await?;
    assert_eq!(response["delivery_receipt_state"], state);
    assert_eq!(response["already_sent"], state == "sent");
    assert_eq!(response["scope"], if state == "sent" { "network_e2ee" } else { "daemon_queue" });
    let read = bus
        .request_frame(LocalBusFrame::request(
            "read",
            Some(receiver.principal.clone()),
            "test",
            "message.read",
            json!({"conversation_id": "thread"}),
        ))
        .await?;
    assert_eq!(read["messages"][0]["sender_device_id"], peer.device);
    assert!(
        read["messages"][0]["sender_device_display"]
            .as_str()
            .is_some_and(|s| s.starts_with("Laptop@"))
    );
    assert_eq!(
        mail.lock()
            .map_err(|_| "mailbox")?
            .submissions
            .iter()
            .filter(|e| e.source_device_id == receiver.device)
            .count(),
        sent
    );
    daemon.shutdown().await?;
    drop(bus);
    server.abort();
    let _ = server.await;
    drop(daemon);
    Ok(())
}
