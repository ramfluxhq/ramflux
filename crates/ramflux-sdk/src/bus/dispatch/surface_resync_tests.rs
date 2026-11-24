// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group recovery is a bounded pair reply, without group broadcasts or unrelated timeline writes.
use super::*;
use crate::bus::runtime_tests;
use crate::client::surface::SurfaceSender;
use crate::client::surface::test_support::{create_frame, native_transport_config, text_snapshot};
use std::sync::{Arc, Mutex};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Group {
    source: LocalBusAccountState,
    peers: Vec<LocalBusAccountState>,
    config: GatewaySessionConfig,
    directory: tokio::task::JoinHandle<()>,
    create: Carrier,
    baseline: usize,
    _root: ramflux_test_support::TestPath,
}
impl Group {
    async fn new(grouped: bool) -> TestResult<Self> {
        let root = runtime_tests::root("surface-private-resync");
        let (mut clients, vault) =
            crate::client::surface::test_support::owned_terminals_with_vault(&root).await?;
        let author_sibling = clients.remove(1);
        let source_client = clients.remove(0);
        clients.push(author_sibling);
        let (conversation, epoch) =
            Self::establish_conversation(&source_client, &clients, vault.as_ref(), grouped)?;
        let mut manifests = BTreeMap::new();
        for client in std::iter::once(&source_client).chain(&clients) {
            let manifest = client.local_own_copy_manifest()?;
            manifests
                .insert(manifest.principal_commitment.clone(), serde_json::to_value(manifest)?);
        }
        let (address, directory) = super::fixture::directory(&root, manifests).await?;
        let branch = source_client.device_branch.as_ref().ok_or("source branch")?;
        let config = native_transport_config(
            GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
                bind_addr: "127.0.0.1:0".parse()?,
                gateway_addr: address,
                server_name: "test-gateway".into(),
                ca_cert: root.join("ca.pem"),
                principal_id: branch.principal_id.clone(),
                device_id: branch.device_id.clone(),
                target_delivery_id: branch.device_id.clone(),
                prekey_http_url: None,
            }),
            &source_client,
        )?;
        let snapshot = text_snapshot("surface", "中文 é 🦀", "");
        let request = crate::SurfaceSendRequest::event(&create_frame(&conversation, &snapshot)?)?;
        let create = source_client.sign_surface_carrier(Carrier {
            typed: None,
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            posted_at: None,
            updated_at: None,
            payload_kind: PayloadKind::Event,
            conversation_id: conversation,
            surface_id: "surface".into(),
            message_id: request.message_id,
            sender_principal_id: branch.principal_id.clone(),
            sender_device_id: branch.device_id.clone(),
            author_principal_id: branch.principal_id.clone(),
            wire_base64: request.wire_base64,
            signature: String::new(),
            snapshot: None,
        })?;
        assert!(source_client.stage_surface_outgoing(&create, epoch)?.accepted, "author create");
        for client in &clients {
            Self::prepare_peer(&source_client, client, &create, epoch)?;
        }
        let delta = super::own_tests::append(&source_client, &create, 2)?;
        assert!(
            source_client.stage_surface_outgoing(&delta, epoch)?.accepted,
            "author advances without recipient delivery"
        );
        let wrap = |client: RamfluxClient| -> TestResult<LocalBusAccountState> {
            let branch = client.device_branch.as_ref().ok_or("branch")?;
            let mut endpoint = config.clone();
            endpoint.principal_id = branch.principal_id.clone();
            endpoint.device_id = branch.device_id.clone();
            endpoint.target_delivery_id = branch.device_id.clone();
            endpoint = native_transport_config(endpoint, &client)?;
            let commitment = client.local_own_copy_manifest()?.principal_commitment;
            let engine = GatewaySessionEngine::with_test_transport(
                endpoint,
                Box::new(super::fixture::RecordingGateway::new(Arc::default())),
            );
            Ok(LocalBusAccountState::new(client, engine, commitment))
        };
        let mut source = wrap(source_client)?;
        // Setup authored two ordinary events, which legitimately queue sibling copies.
        // Finish that work before observing the private resync request/reply exchange.
        assert_eq!(
            crate::bus::own_device_copy::flush(&mut source).await?,
            2,
            "the initial create and delta must finish their own-device submission"
        );
        let peers = clients.into_iter().map(wrap).collect::<TestResult<Vec<_>>>()?;
        if grouped {
            Self::settle_group_setup(&mut source, &peers).await?;
        }
        let baseline = peers
            .get(2)
            .ok_or("unrelated peer missing")?
            .client
            .direct_messages(&create.conversation_id)?
            .len();
        Ok(Self { source, peers, config, directory, create, baseline, _root: root })
    }
    async fn settle_group_setup(
        source: &mut LocalBusAccountState,
        peers: &[LocalBusAccountState],
    ) -> TestResult {
        // Run the production couriers independently; the fixture serves only their
        // writer checkpoints and observes committed destination completion.
        let expected = peers
            .iter()
            .map(|peer| {
                let identity = peer.client.owned_device_identity()?;
                Ok((identity.root_commitment().to_owned(), identity.device_id().to_owned()))
            })
            .collect::<Result<BTreeSet<_>, SdkError>>()?;
        let key = format!("group-beacon/{}", ramflux_protocol::encode_base64url("group"));
        let session = source.session_client().await?;
        source.apply_session_metadata(session);
        let context = source.connection.as_ref().ok_or("setup connection")?.test_context();
        let generation = context.generation;
        let (sender, mut receive) = tokio::sync::mpsc::channel(8);
        let requests = Box::pin(crate::bus::couriers::runner::run(
            context.clone(),
            sender.clone(),
            "group-requests",
            crate::bus::shared_group_sync::request_pass,
        ));
        let deliveries = Box::pin(crate::bus::couriers::runner::run(
            context.clone(),
            sender.clone(),
            "group-delivery",
            crate::bus::shared_group_sync::deliver_pass,
        ));
        let staging = Box::pin(crate::bus::couriers::runner::run(
            context,
            sender,
            "group-stage",
            |_, writer| async move {
                writer
                    .apply(|account| crate::bus::shared_group_sync::stage(account).map(|n| n > 0))
                    .await
            },
        ));
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut couriers = Box::pin(async move {
                tokio::join!(requests, deliveries, staging);
            });
            loop {
                tokio::select! {
                    () = &mut couriers => return Err("setup couriers stopped before completion".into()),
                    work = receive.recv() => match work {
                        Some(crate::bus::connection_manager::AccountWork::Courier(work))
                            if work.generation == generation => work.apply(source),
                        _ => return Err("unexpected setup courier checkpoint".into()),
                    }
                }
                let db = source.client.account_db()?;
                let Some(beacon) = db
                    .load_actor_state::<crate::client::shared_group::BeaconRecord>(&key)?
                else {
                    continue;
                };
                if !beacon.delivered.is_subset(&expected) {
                    return Err("native group setup served an unexpected destination".into());
                }
                if beacon.delivered == expected && Self::send_intents_idle(db)? {
                    break;
                }
            }
            drop(couriers);
            // No fixture peer sends the confirmation that would end the sender's bounded retry of
            // the unconfirmed grant (#590); resync is measured without that unrelated resend.
            source.client.account_db()?.remove_actor_state(&format!(
                "group-state/send/{}",
                ramflux_protocol::encode_base64url("group")
            ))?;
            Self::require_setup_quiescent(source).await
        })
        .await
        .map_err(|_| "native group setup did not serve every destination before resync")?
    }

    /// Every group-state send intent is parked until a future retry. An unconfirmed grant keeps
    /// its intent after delivery (#590), so an empty namespace no longer marks setup complete.
    fn send_intents_idle(db: &ramflux_storage::AccountDb) -> Result<bool, SdkError> {
        let now = now_unix_timestamp();
        Ok(db.list_actor_states::<Value>("group-state/send/")?.iter().all(|intent| {
            intent["round_active"] == false && intent["next_at"].as_i64().is_some_and(|at| at > now)
        }))
    }

    async fn require_setup_quiescent(source: &mut LocalBusAccountState) -> TestResult {
        let submitted = crate::bus::sync_driver::run(source).await?;
        if submitted != 0 {
            return Err(format!(
                "the native group setup must be quiescent before resync; unexpected driver activity: {submitted}"
            )
            .into());
        }
        Ok(())
    }
    fn establish_conversation(
        source: &RamfluxClient,
        peers: &[RamfluxClient],
        vault: &crate::custody::tests::TestVault,
        grouped: bool,
    ) -> TestResult<(String, Option<u64>)> {
        if grouped {
            let conversation = "surface_group_thread";
            let epoch = Self::establish_group(source, peers, vault, conversation)?;
            return Ok((conversation.into(), Some(epoch)));
        }
        let author = source.owned_device_identity()?.root_commitment().to_owned();
        let human = peers
            .first()
            .ok_or("human peer")?
            .owned_device_identity()?
            .root_commitment()
            .to_owned();
        let conversation = ramflux_protocol::message::dm_scope::derive(&author, &human)?;
        for client in std::iter::once(source).chain(peers) {
            client.account_db()?.persist_client_record(
                "conversation",
                &conversation,
                &json!({"kind":"direct","group_id":null,"participants":["author","human"],
                    "participant_roots":[author,human]}),
            )?;
            client.establish_friend_link("native-resync", &author, &human)?;
        }
        Ok((conversation, None))
    }
    fn establish_group(
        source_client: &RamfluxClient,
        clients: &[RamfluxClient],
        vault: &crate::custody::tests::TestVault,
        conversation: &str,
    ) -> TestResult<u64> {
        let source_identity = source_client.owned_device_identity()?;
        let primary = vault.primary_for_public_key(
            &source_client
                .born_v3_account
                .as_ref()
                .ok_or("source account")?
                .record()
                .body
                .master_certificate
                .body
                .self_signing_public_key,
        )?;
        let mut state = source_client.shared_group_create_with_primary(
            "group",
            conversation,
            None,
            source_identity.storage_key(),
            Some(&primary),
        )?;
        for client in clients {
            let identity = client.owned_device_identity()?;
            let member = client.owned_group_actor(identity.storage_key())?.identity;
            state = source_client.shared_group_change_with_primary(
                "group",
                source_identity.storage_key(),
                ramflux_protocol::GroupStateChange::Add {
                    member,
                    role: ramflux_protocol::SharedGroupRole::Member,
                },
                Some(&primary),
            )?;
        }
        for client in clients {
            assert!(
                client.accept_shared_group_state(
                    &state,
                    client.owned_device_identity()?.storage_key()
                )?,
                "each peer must accept the primary-signed native group state",
            );
        }
        Ok(state.view().epoch)
    }
    fn prepare_peer(
        source_client: &RamfluxClient,
        client: &RamfluxClient,
        create: &Carrier,
        epoch: Option<u64>,
    ) -> TestResult {
        let source_identity = source_client.owned_device_identity()?;
        let source_device = source_identity.device_id().to_owned();
        crate::client::native_test_support::bus::seed_pair(source_client, client)?;
        assert!(
            client
                .project_surface_message(
                    &create.conversation_id,
                    &create.message_id,
                    SurfaceSender {
                        principal: &create.sender_principal_id,
                        device: &source_device,
                        envelope_id: "native-create",
                        expires_at: None,
                        group_epoch: epoch,
                    },
                    &create.bytes()?,
                    false
                )?
                .ok_or("create projection")?
                .accepted,
            "native own-agent create"
        );
        client.send_direct_message(
            &create.conversation_id,
            "initial-visible",
            &source_device,
            b"encrypted",
        )?;
        Ok(())
    }
    fn peer_config(&self, index: usize) -> TestResult<GatewaySessionConfig> {
        let branch =
            self.peers[index].client.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let mut config = self.config.clone();
        config.principal_id = branch.principal_id.clone();
        config.device_id = branch.device_id.clone();
        config.target_delivery_id = branch.device_id.clone();
        config = native_transport_config(config, &self.peers[index].client)?;
        Ok(config)
    }
    async fn request(&mut self, index: usize) -> TestResult<ramflux_protocol::Envelope> {
        let config = self.peer_config(index)?;
        let peer = &mut self.peers[index];
        let reference = self.create.surface_reference()?;
        let mut view =
            peer.client.account_db()?.client_record("surface", &reference)?.ok_or("view")?;
        view["out_of_sync"] = json!(true);
        peer.client.account_db()?.persist_client_record("surface", &reference, &view)?;
        peer.client
            .account_db()?
            .persist_actor_state(&crate::client::surface::key("out_of_sync", &reference), &2_u64)?;
        // Exercise the author limiter even if a requester bypasses its local UI limiter.
        peer.client
            .account_db()?
            .remove_actor_state(&crate::client::surface::key("resync_requested", &reference))?;
        let sent = Arc::new(Mutex::new(Vec::new()));
        peer.install_test_session(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(super::fixture::RecordingGateway::new(Arc::clone(&sent))),
        ));
        assert_eq!(
            super::super::surface::request_resync(peer, &reference).await?["submitted_devices"],
            1
        );
        let result = sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first()
            .cloned()
            .ok_or("request")?;
        Ok(result)
    }
}
#[tokio::test]
async fn setup_quiescence_rejects_an_unexpected_queued_request() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(30),
        Box::pin(async {
            let mut group = Box::pin(Group::new(true)).await?;
            let request = group.request(0).await?;
            let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
            gateway.inbox.push(GatewayInboxEntry {
                forwarded: false,
                inbox_seq: 1,
                target_delivery_id: request.target_delivery_id.clone(),
                envelope: request,
            });
            group.source.install_test_session(GatewaySessionEngine::with_test_transport(
                group.config.clone(),
                Box::new(gateway),
            ));
            let error = Group::require_setup_quiescent(&mut group.source)
                .await
                .expect_err("the quiescence check must reject a real queued resync request");
            assert!(
                error.to_string().contains("unexpected driver activity: 1"),
                "the queued packet must fail the zero-activity check: {error}"
            );
            group.directory.abort();
            Ok(())
        }),
    )
    .await
    .map_err(|_| "negative quiescence check did not finish")?
}
#[tokio::test]
async fn two_group_requesters_receive_two_pair_replies_and_no_other_member_or_author_rows()
-> TestResult {
    let mut group = Box::pin(Group::new(true)).await?;
    let before = group.source.client.direct_messages(&group.create.conversation_id)?.len();
    let requests = vec![group.request(0).await?, group.request(1).await?];
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = super::fixture::RecordingGateway::new(Arc::clone(&replies));
    let own = Arc::clone(&gateway.own);
    gateway.inbox = requests
        .into_iter()
        .enumerate()
        .map(|(i, envelope)| GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(i + 1).unwrap_or(0),
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        })
        .collect();
    group.source.install_test_session(GatewaySessionEngine::with_test_transport(
        group.config.clone(),
        Box::new(gateway),
    ));
    assert_eq!(crate::bus::sync_driver::run(&mut group.source).await?, 2);
    for _ in 0..2 {
        assert!(
            crate::bus::couriers::test_pass::drive(
                &mut group.source,
                crate::bus::couriers::surface::pass,
            )
            .await?
        );
    }
    let frames = replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(frames.len(), 2);
    assert!(
        own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty(),
        "private resync replies must never be copied to the author's other devices"
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    for index in 0..2 {
        let config = group.peer_config(index)?;
        let envelope = frames
            .iter()
            .find(|e| e.target_delivery_id == config.target_delivery_id)
            .ok_or("targeted reply")?
            .clone();
        let mut engine = GatewaySessionEngine::with_test_transport(
            config,
            Box::new(super::fixture::RecordingGateway::new(Arc::default())),
        );
        let peer = &mut group.peers[index];
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 3,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        peer.client.apply_routed_entry(&mut engine, &pool, &entry).await?;
        assert_eq!(peer.client.surface_get("surface", 0, None)?["version"], 2);
    }
    assert_eq!(group.source.client.direct_messages(&group.create.conversation_id)?.len(), before);
    assert_eq!(
        group.peers[2].client.direct_messages(&group.create.conversation_id)?.len(),
        group.baseline,
        "a reply addressed to two requesters must not write rows for other members"
    );
    assert_eq!(group.peers[2].client.surface_get("surface", 0, None)?["version"], 1);
    assert_eq!(
        group.source.client.account_db()?.actor_state_usage("surface/resync_answered/")?.0,
        1
    );
    assert_eq!(
        group.source.client.account_db()?.actor_state_usage("surface/resync-response/")?.0,
        0
    );
    let duplicate = group.request(0).await?;
    let mut gateway = super::fixture::RecordingGateway::new(Arc::clone(&replies));
    gateway.inbox.push(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 3,
        target_delivery_id: duplicate.target_delivery_id.clone(),
        envelope: duplicate,
    });
    group.source.install_test_session(GatewaySessionEngine::with_test_transport(
        group.config,
        Box::new(gateway),
    ));
    assert_eq!(crate::bus::sync_driver::run(&mut group.source).await?, 1);
    assert_eq!(replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 2);
    group.directory.abort();
    drop(group.peers);
    drop(group.source);
    Ok(())
}

pub(super) async fn native_pair_resync() -> TestResult {
    let mut pair = Box::pin(Group::new(false)).await?;
    let before = pair.source.client.direct_messages(&pair.create.conversation_id)?.len();
    let request = pair.request(0).await?;
    assert_eq!(
        super::super::surface::request_resync(
            &mut pair.peers[0],
            &pair.create.surface_reference()?
        )
        .await?["rate_limited"],
        true,
        "repeated UI requests remain bounded"
    );
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = super::fixture::RecordingGateway::new(replies.clone());
    gateway.inbox.push(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: request.target_delivery_id.clone(),
        envelope: request,
    });
    pair.source.install_test_session(GatewaySessionEngine::with_test_transport(
        pair.config.clone(),
        Box::new(gateway),
    ));
    assert_eq!(
        crate::bus::sync_driver::run(&mut pair.source).await?,
        1,
        "authenticated pair request must be consumed"
    );
    assert!(
        crate::bus::couriers::surface::drive_once(&mut pair.source).await?,
        "private reply must be delivered"
    );
    let peer_config = pair.peer_config(0)?;
    let reply = replies
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|e| e.target_delivery_id == peer_config.target_delivery_id)
        .cloned()
        .ok_or("private reply")?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let mut receiver = GatewaySessionEngine::with_test_transport(
        peer_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let incoming = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 2,
        target_delivery_id: reply.target_delivery_id.clone(),
        envelope: reply,
    };
    pair.peers[0].client.apply_routed_entry(&mut receiver, &pool, &incoming).await?;
    let view = pair.peers[0].client.surface_get("surface", 0, None)?;
    assert_eq!(view["version"], 2, "resync must recover the missed version");
    assert_eq!(view["out_of_sync"], false, "valid resync clears the recovery fence");
    assert_eq!(
        view["surface_hash"],
        pair.source.client.surface_get("surface", 0, None)?["surface_hash"],
        "recipient and author commit the same signed base"
    );
    assert_eq!(
        pair.source.client.direct_messages(&pair.create.conversation_id)?.len(),
        before,
        "resync controls never add timeline rows"
    );
    assert!(
        pair.source
            .client
            .account_db()?
            .actor_state_key_page("surface/resync-response/", 100)?
            .is_empty(),
        "acknowledged replies leave no pending courier row"
    );
    pair.directory.abort();
    Ok(())
}
