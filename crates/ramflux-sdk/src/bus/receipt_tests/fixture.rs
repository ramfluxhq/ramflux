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
    /// The real gateway replay guard (TTL, future-skew and replay checks) when installed.
    pub guard: Option<ramflux_node_core::NodeReplayGuardState>,
    /// Known senders the guard binds an envelope to.
    pub guard_sources: Vec<ramflux_crypto::RootQualifiedDeviceRef>,
    prekeys: BTreeMap<String, crate::prekey::SdkPrekeyResponse>,
}
#[derive(Clone)]
pub(super) struct Spec {
    pub root: PathBuf,
    pub principal: String,
    pub device: String,
    vault: Arc<crate::custody::tests::TestVault>,
    events: Arc<Mutex<BTreeMap<String, String>>>,
    directory: Arc<Mutex<BTreeMap<String, crate::SdkDeviceManifestResponse>>>,
}
impl Spec {
    pub fn new(root: &Path, principal: &str, _seed: u8) -> Self {
        Self {
            root: root.join(principal),
            principal: principal.into(),
            device: format!("device-{principal}"),
            vault: Arc::new(crate::custody::tests::TestVault::default()),
            events: Arc::new(Mutex::new(BTreeMap::new())),
            directory: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    pub fn client(&self, index: Option<AccountIndex>) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.account_index = index;
        client.open_account_index(&self.root)?;
        if !crate::custody::account_exists(&self.root, &self.principal)? {
            let now = crate::custody::network_now()?;
            let mut input = crate::custody::tests::input(&self.principal);
            input.principal_id.clone_from(&self.principal);
            input.device_id.clone_from(&self.device);
            let mut ceremony = crate::custody::CreationCeremony::begin(&self.root, input, now)?;
            let phrase = ceremony.show_once()?;
            let positions = ceremony.hidden_challenge()?;
            let answers = crate::custody::tests::words(&phrase, positions)
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            let account = ceremony.confirm(&answers, self.vault.as_ref(), now)?;
            client.bind_device_unlock(
                std::path::Path::new(&self.root),
                self.vault.as_ref(),
                &self.principal,
                crate::client::device_unlock::DeviceSecret::Create,
            )?;
            client.seal_new_account_data(
                &self.principal,
                &account.record().body.account_anchor,
                b"receipt-test",
            )?;
            crate::custody::tests::mark_live(&self.root, &self.principal, now)
                .map_err(|_| SdkError::CustodySetupInvalid)?;
        }
        client.unlock_account(&self.principal, b"receipt-test")?;
        client.initialize_born_v3_branch_for_fixture(&self.device, self.vault.as_ref())?;
        client.persist_observed_identity_directory_now(&self.manifest(&client)?)?;
        let directory = self
            .directory
            .lock()
            .map_err(|_| SdkError::LocalBus("test: directory poisoned".into()))?;
        assert!(directory.len() <= 8, "bounded receipt live directory");
        for manifest in directory.values() {
            client.persist_observed_identity_directory_now(manifest)?;
        }
        Ok(client)
    }

    pub fn manifest(
        &self,
        client: &RamfluxClient,
    ) -> Result<crate::SdkDeviceManifestResponse, SdkError> {
        let account = client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
        let identity = client.owned_device_identity()?;
        crate::SdkDeviceManifestResponse::from_native(ramflux_protocol::custody::CustodyManifest {
            publication: account.publication(),
            custodian_publication: None,
            devices: vec![ramflux_protocol::custody::CustodyManifestDevice {
                device_ref: ramflux_protocol::custody::DeviceRef {
                    account_anchor: identity.root_commitment().into(),
                    device_id: self.device.clone(),
                    device_epoch: 1,
                },
                target_delivery_id: identity.storage_key().into(),
                prekey_bundle: serde_json::to_value(
                    client.load_x3dh_private_state(&identity)?.bundle,
                )?,
                message_layer: None,
            }],
        })
    }

    pub fn config(&self, client: &RamfluxClient) -> Result<GatewaySessionConfig, SdkError> {
        let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::IdentityRootMissing)?,
            gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::IdentityRootMissing)?,
            server_name: "receipt-test".into(),
            ca_cert: self.root.join("ca.pem"),
            principal_id: self.principal.clone(),
            device_id: self.device.clone(),
            target_delivery_id: client.owned_device_identity()?.storage_key().into(),
            prekey_http_url: None,
        })
        .with_native_custody(crate::GatewayCustodyConfig {
            account_root: self.root.clone(),
            account_id: self.principal.clone(),
            node_id: "receipt-node".into(),
            node_public_key: ramflux_protocol::encode_base64url([7; 32]),
            vault: self.vault.clone(),
        });
        let mut config = config.with_account_identity(client)?;
        config.device_branch = Some(Arc::new(
            client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
        ));
        config.source_identity = Some(client.owned_device_identity()?);
        Ok(config)
    }
    pub fn account(
        &self,
        index: Option<AccountIndex>,
        mail: Shared,
    ) -> Result<LocalBusAccountState, SdkError> {
        let client = self.client(index)?;
        let config = self.config(&client)?;
        let mut manifests = self
            .directory
            .lock()
            .map_err(|_| SdkError::LocalBus("test: directory poisoned".into()))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        manifests.push(self.manifest(&client)?);
        {
            let mut mailbox =
                mail.lock().map_err(|_| SdkError::LocalBus("test: mailbox poisoned".into()))?;
            for manifest in manifests {
                for device in manifest.devices {
                    mailbox.prekeys.insert(
                        device.target_delivery_id.clone(),
                        crate::prekey::SdkPrekeyResponse {
                            device_id: device.device_id,
                            target_delivery_id: Some(device.target_delivery_id),
                            principal_commitment: manifest.principal_commitment.clone(),
                            bundle: Some(device.prekey_bundle),
                        },
                    );
                }
            }
        }
        let root = client.surface_local_root_commitment()?;
        let reconnect = mail.clone();
        let mut account = LocalBusAccountState::new(
            client,
            GatewaySessionEngine::with_test_transport(
                config.clone(),
                Box::new(Gateway {
                    target: config.target_delivery_id.clone(),
                    mail,
                    last: None,
                    cursor: None,
                }),
            ),
            root,
        );
        account.test_connector = Some(Arc::new(ReceiptConnector {
            mail: reconnect,
            target: account.target_delivery_id.clone(),
        }));
        Ok(account)
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
        let manifest = other.manifest(&peer)?;
        self.directory
            .lock()
            .map_err(|_| SdkError::LocalBus("test: directory poisoned".into()))?
            .insert(manifest.principal_commitment.clone(), manifest.clone());
        client.persist_observed_identity_directory_now(&manifest)?;
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
    /// Enrols `self` as a second native device of `primary`'s account and returns the merged
    /// two-device manifest. The sibling lives under `self.root` with the receipt passphrase and
    /// its own vault, so `erasure_audit::open` reads it exactly like any other receipt account.
    pub fn enroll_sibling_of(
        &self,
        primary: &Spec,
        source: &RamfluxClient,
    ) -> Result<crate::SdkDeviceManifestResponse, Box<dyn std::error::Error>> {
        let mut native =
            *primary.manifest(source)?.custody.ok_or("test: native primary manifest")?;
        let record = native.publication.record.clone();
        let key = primary
            .vault
            .primary_for_public_key(&record.body.master_certificate.body.self_signing_public_key)?;
        let now = crate::custody::network_now()?.max(record.body.issued_at);
        let current = ramflux_crypto::custody::verify_record(&record, now, None, None)?;
        let mut seeds = zeroize::Zeroizing::new([0_u8; 64]);
        getrandom::fill(&mut *seeds).map_err(|_| SdkError::CustodyRandomUnavailable)?;
        let signing: [u8; 32] = seeds[..32].try_into()?;
        let agreement: [u8; 32] = seeds[32..].try_into()?;
        let branch =
            ramflux_crypto::create_device_branch(&primary.principal, &self.device, 1, signing);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed(agreement);
        let mut certificate = record.body.devices[0]
            .branch_certificate
            .as_ref()
            .ok_or("test: primary branch certificate")?
            .body
            .clone();
        certificate.device_id.clone_from(&self.device);
        certificate.branch_signing_public_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
        certificate.agreement_identity_public_key =
            ramflux_protocol::encode_base64url(&agreement.public);
        certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let message_layer = ramflux_crypto::custody::sign_enrollment_layer(&branch, &certificate)?;
        native.publication.record =
            key.enroll_device(&current, key.certify_branch(certificate)?, message_layer, now)?;
        crate::custody::accept_publication(
            &primary.root,
            &primary.principal,
            &ramflux_protocol::custody::CustodyAuthority {
                publication: native.publication.clone(),
                custodian_publication: None,
            },
            now,
        )?;
        std::fs::create_dir_all(&self.root)?;
        crate::custody::install_sibling_fixture(crate::custody::SiblingSetup {
            root: &self.root,
            id: &self.principal,
            device: &self.device,
            record: native.publication.record.clone(),
            branch: &seeds,
            vault: self.vault.as_ref(),
            passphrase: b"receipt-test",
            now,
        })?;
        let sibling = self.client(None)?;
        native.devices.extend(
            self.manifest(&sibling)?.custody.ok_or("test: native sibling manifest")?.devices,
        );
        let full = crate::SdkDeviceManifestResponse::from_native(native)?;
        source.persist_observed_identity_directory_now(&full)?;
        sibling.persist_observed_identity_directory_now(&full)?;
        for spec in [primary, self] {
            spec.directory
                .lock()
                .map_err(|_| SdkError::LocalBus("test: directory poisoned".into()))?
                .insert(full.principal_commitment.clone(), full.clone());
        }
        Ok(full)
    }
    pub fn identity(&self) -> Result<ramflux_crypto::RootQualifiedDeviceRef, SdkError> {
        let account = crate::custody::load_account(
            &self.root,
            &self.principal,
            crate::custody::network_now()?,
        )?;
        Ok(ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
            account.verified(),
            &self.device,
        )?)
    }
    pub fn conversation(&self, to: &Spec) -> Result<String, SdkError> {
        ramflux_protocol::message::dm_scope::derive(
            self.identity()?.root_commitment(),
            to.identity()?.root_commitment(),
        )
        .map_err(|error| SdkError::InboundRejected(error.to_string()))
    }
    pub fn prepare_group(
        &self,
        client: &RamfluxClient,
        group: &str,
        conversation: &str,
        peers: &[(&Spec, &RamfluxClient)],
    ) -> Result<(), SdkError> {
        assert!(peers.len() <= 8, "bounded native receipt group");
        let own = self.identity()?;
        let primary = client
            .born_v3_account
            .as_ref()
            .ok_or(SdkError::CustodySetupInvalid)?
            .group_primary(self.vault.as_ref())?;
        let mut state = client.shared_group_create_with_primary(
            group,
            conversation,
            None,
            own.storage_key(),
            Some(&primary),
        )?;
        for (peer, receiver) in peers {
            self.trust(client, peer)?;
            peer.trust(receiver, self)?;
            state = client.shared_group_change_with_primary(
                group,
                own.storage_key(),
                ramflux_protocol::group_state::GroupStateChange::Add {
                    member: receiver.owned_group_actor(peer.identity()?.storage_key())?.identity,
                    role: ramflux_protocol::SharedGroupRole::Member,
                },
                Some(&primary),
            )?;
        }
        for (peer, receiver) in peers {
            receiver.accept_shared_group_state(&state, peer.identity()?.storage_key())?;
        }
        Ok(())
    }

    pub async fn send_group_text(
        &self,
        account: &mut LocalBusAccountState,
        group: &str,
        operation: &str,
        text: &str,
    ) -> Result<String, SdkError> {
        let conversation = account
            .client
            .account_db()?
            .shared_group_state(group)?
            .ok_or(SdkError::CustodySetupInvalid)?
            .view()
            .conversation_id
            .clone();
        let content = ramflux_protocol::message::Content {
            value: Some(ramflux_protocol::message::content::Value::Message(
                ramflux_protocol::message::Message { text: text.into(), ..Default::default() },
            )),
        };
        let mut manifests = self
            .directory
            .lock()
            .map_err(|_| SdkError::LocalBus("test: directory poisoned".into()))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        manifests.push(self.manifest(&account.client)?);
        let directory = crate::client::native_test_support::directory::Directory::new(manifests)
            .await
            .map_err(|error| SdkError::LocalBus(format!("test: group directory: {error}")))?;
        directory.configure_session(&mut account.gateway_config);
        if let Some(engine) = account.engine.as_mut() {
            directory.configure_session(&mut engine.config);
        }
        let request = LocalBusFrame::request(
            "group-receipt-fixture",
            Some(self.principal.clone()),
            "group",
            "group.send",
            json!({"group_id":group,"conversation_id":conversation,"message_id":operation,"sender_id":self.device,"content":content,"encrypted_body_base64":""}),
        );
        let sent =
            Box::pin(crate::bus::dispatch::group::dispatch_group_send_request(&request, account))
                .await?;
        let id = sent.response_body["message_id"]
            .as_str()
            .ok_or_else(|| SdkError::LocalBus("test: group event id missing".into()))?
            .to_owned();
        self.events
            .lock()
            .map_err(|_| SdkError::LocalBus("test: event map poisoned".into()))?
            .insert(operation.into(), id.clone());
        Ok(id)
    }

    pub async fn send_text(
        &self,
        client: &RamfluxClient,
        engine: &mut impl GatewaySessionAccess,
        message: GatewayDirectMessage,
        text: &[u8],
    ) -> Result<GatewayInboxEntry, SdkError> {
        let operation = message.message_id.clone();
        let text = std::str::from_utf8(text)
            .map_err(|_| SdkError::InboundRejected("test: UTF-8 text".into()))?;
        let (id, entry) = Box::pin(client.send_generated_content_via_gateway(
            engine,
            message,
            &ramflux_protocol::message::Content {
                value: Some(ramflux_protocol::message::content::Value::Message(
                    ramflux_protocol::message::Message { text: text.into(), ..Default::default() },
                )),
            },
        ))
        .await?;
        self.events
            .lock()
            .map_err(|_| SdkError::LocalBus("test: event map poisoned".into()))?
            .insert(operation, id);
        Ok(entry)
    }
    pub fn event(&self, operation: &str) -> Result<String, SdkError> {
        self.events
            .lock()
            .map_err(|_| SdkError::LocalBus("test: event map poisoned".into()))?
            .get(operation)
            .cloned()
            .ok_or_else(|| SdkError::LocalBus("test: authored event missing".into()))
    }
    pub fn message(&self, to: &Spec, id: &str) -> GatewayDirectMessage {
        let peer = to.identity().expect("test: receipt peer custody authority");
        GatewayDirectMessage {
            conversation_id: self.conversation(to).expect("test: canonical receipt conversation"),
            message_id: id.into(),
            envelope_id: id.into(),
            source_principal_id: self.principal.clone(),
            sender_id: self.device.clone(),
            recipient_device_id: Some(to.device.clone()),
            recipient_principal_commitment: Some(peer.root_commitment().into()),
            target_delivery_id: peer.storage_key().into(),
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
    )?
    .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
    let receiver = ramflux_crypto::DmSession::recipient(
        [17; 32],
        dm_device_id_hash(&b.device),
        dm_device_id_hash(&a.device),
        [3; 32],
    )?
    .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
    one.persist_pair(&a.identity()?, &b.identity()?, &[4; 32], &sender)?;
    two.persist_pair(&b.identity()?, &a.identity()?, &[4; 32], &receiver)?;
    for client in [&one, &two] {
        client.account_db()?.persist_client_record(
            "conversation",
            &a.conversation(b)?,
            &json!({"kind":"direct","group_id":null,"participants":[a.principal,b.principal],"participant_roots":[a.identity()?.root_commitment(),b.identity()?.root_commitment()]}),
        )?;
    }
    Ok(())
}
pub(super) async fn socket(
    spec: &Spec,
    daemon: Rc<Supervisor>,
) -> Result<(LocalBusClient, tokio::task::JoinHandle<Result<(), SdkError>>), SdkError> {
    let path = spec.root.join("observer.sock");
    #[cfg(unix)]
    let listener = UnixListener::bind(&path)?;
    #[cfg(windows)]
    let listener = crate::platform::listener::bind(&path)?;
    let client = LocalBusClient::connect(&path).await?;
    #[cfg(unix)]
    let (stream, _) = listener.accept().await?;
    #[cfg(windows)]
    let stream = {
        use crate::platform::listener::BusListener as _;
        listener.accept().await?
    };
    let task = tokio::task::spawn_local(crate::bus::connection::handle(stream, daemon, 1));
    std::fs::remove_file(path)?;
    Ok((client, task))
}
pub(super) async fn delivered(
    client: &LocalBusClient,
    principal: &str,
    id: &str,
    conversation: &str,
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
                json!({"conversation_id":conversation,"read_model":true}),
            ))
            .await?;
        if body["messages"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row["id"] == id
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
struct ReceiptConnector {
    mail: Shared,
    target: String,
}
impl crate::bus::connection_manager::SessionConnector for ReceiptConnector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        _: tokio::time::Instant,
    ) -> crate::bus::connection_manager::SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            Ok(GatewaySessionEngine::with_test_transport(
                config,
                Box::new(Gateway {
                    target: self.target.clone(),
                    mail: self.mail.clone(),
                    last: None,
                    cursor: None,
                }),
            ))
        })
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
                Some(GatewayClientFrame::PrekeyFetch { device_id }) => {
                    let response = self
                        .mail
                        .lock()
                        .map_err(|_| TransportError::Quic("mailbox poisoned".into()))?
                        .prekeys
                        .get(&device_id)
                        .cloned()
                        .ok_or_else(|| {
                            TransportError::Quic("test: native prekey missing".into())
                        })?;
                    GatewayServerFrame::Prekey { response }
                }
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                Some(GatewayClientFrame::Submit { submit }) => self.submit(submit)?,
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
                None => return std::future::pending().await,
                Some(_) => {
                    GatewayServerFrame::Nack { reason: "unexpected receipt fixture frame".into() }
                }
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
                "conversation_id": peer.conversation(receiver)?, "message_id": peer.event("dm-one")?,
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
            json!({"conversation_id": peer.conversation(receiver)?, "read_model":true}),
        ))
        .await?;
    assert_eq!(read["messages"][0]["author"]["device_id"], peer.device);
    assert_eq!(read["messages"][0]["author"]["account_anchor"], peer.identity()?.root_commitment());
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

impl Gateway {
    fn submit(
        &mut self,
        submit: crate::GatewaySubmitFrame,
    ) -> Result<GatewayServerFrame, TransportError> {
        let mut mail =
            self.mail.lock().map_err(|_| TransportError::Quic("mailbox poisoned".into()))?;
        let envelope = submit.envelope;
        mail.submissions.push(envelope.clone());
        if mail.reject_id.as_deref() == Some(envelope.envelope_id.as_str()) {
            return Err(TransportError::Quic("injected receipt refusal".into()));
        }
        if mail.guard.is_some() {
            let source = mail
                .guard_sources
                .iter()
                .find(|s| {
                    s.device_id() == envelope.source_device_id
                        || s.storage_key() == envelope.source_device_id
                })
                .cloned()
                .ok_or_else(|| TransportError::Quic("test: unknown guard source".into()))?;
            if let Some(guard) = mail.guard.as_mut() {
                guard
                    .accept_envelope_once(&source, &envelope, now_unix_timestamp())
                    .map_err(|error| TransportError::Quic(format!("gateway guard: {error}")))?;
            }
        }
        let entry = if let Some(existing) = mail.messages.iter().find(|e| {
            e.envelope.source_device_id == envelope.source_device_id
                && e.envelope.envelope_id == envelope.envelope_id
                && e.target_delivery_id == envelope.target_delivery_id
        }) {
            existing.clone()
        } else {
            let entry = GatewayInboxEntry {
                forwarded: false,
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
        Ok(GatewayServerFrame::Deliver { entry })
    }
}
