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
    _root: ramflux_test_support::TestPath,
}
impl Group {
    async fn new() -> TestResult<Self> {
        let root = runtime_tests::root("surface-private-resync");
        let mut clients = crate::client::surface::test_support::owned_terminals(&root).await?;
        let author_sibling = clients.remove(1);
        let source_client = clients.remove(0);
        clients.push(author_sibling);
        let source_identity = source_client.owned_device_identity()?;
        let source_device =
            source_client.device_branch.as_ref().ok_or("source branch")?.device_id.clone();
        source_client.create_group("group", source_identity.storage_key())?;
        let identities = clients
            .iter()
            .map(RamfluxClient::owned_device_identity)
            .collect::<Result<Vec<_>, _>>()?;
        for identity in &identities {
            source_client.add_group_member("group", identity.storage_key(), "member")?;
        }
        let epoch = source_client.group_state("group")?.group_epoch;
        let mut manifests = BTreeMap::new();
        for client in std::iter::once(&source_client).chain(&clients) {
            let manifest = client.local_own_copy_manifest()?;
            manifests
                .insert(manifest.principal_commitment.clone(), serde_json::to_value(manifest)?);
            client.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &json!({"kind":"group","group_id":"group"}),
            )?;
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
        let request = crate::SurfaceSendRequest::event(&create_frame("thread", &snapshot)?)?;
        let create = source_client.sign_surface_carrier(Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            posted_at: None,
            updated_at: None,
            payload_kind: PayloadKind::Event,
            conversation_id: "thread".into(),
            surface_id: "surface".into(),
            message_id: request.message_id,
            sender_principal_id: branch.principal_id.clone(),
            sender_device_id: branch.device_id.clone(),
            author_principal_id: branch.principal_id.clone(),
            wire_base64: request.wire_base64,
            signature: String::new(),
            snapshot: None,
        })?;
        assert!(
            source_client.stage_surface_outgoing(&create, Some(epoch))?.accepted,
            "author create"
        );
        for (index, client) in clients.iter().enumerate() {
            let local = client.device_branch.as_ref().ok_or("peer branch")?;
            client.account_db()?.upsert_group_local_membership_snapshot(
                "group",
                epoch,
                128,
                "none",
                client.owned_device_identity()?.storage_key(),
                "member",
                1,
            )?;
            client.account_db()?.upsert_group_member_snapshot(
                "group",
                source_identity.storage_key(),
                "owner",
                1,
            )?;
            for identity in &identities {
                client.account_db()?.upsert_group_member_snapshot(
                    "group",
                    identity.storage_key(),
                    "member",
                    1,
                )?;
            }
            client.pin_local_group_member("group")?;
            client.pin_joined_group_member("group", source_identity.storage_key())?;
            let seed = [u8::try_from(index + 1)?; 32];
            let send = ramflux_crypto::DmSession::initiator(
                seed,
                dm_device_id_hash(&source_device),
                dm_device_id_hash(&local.device_id),
                [3; 32],
            )?;
            let recv = ramflux_crypto::DmSession::recipient(
                seed,
                dm_device_id_hash(&local.device_id),
                dm_device_id_hash(&source_device),
                [3; 32],
            )?;
            source_client.persist_pair(
                &source_identity,
                &client.owned_device_identity()?,
                &[4; 32],
                &send,
            )?;
            client.persist_pair(
                &client.owned_device_identity()?,
                &source_identity,
                &[4; 32],
                &recv,
            )?;
            assert!(
                client
                    .project_surface_message(
                        "thread",
                        &create.message_id,
                        SurfaceSender {
                            principal: &create.sender_principal_id,
                            device: &source_device,
                            envelope_id: "native-create",
                            expires_at: None,
                            group_epoch: Some(epoch),
                        },
                        &create.bytes()?,
                        false
                    )?
                    .ok_or("create projection")?
                    .accepted,
                "native own-agent create"
            );
            client.send_direct_message(
                "thread",
                "initial-visible",
                &source_device,
                b"encrypted",
            )?;
        }
        let delta = super::own_tests::append(&source_client, &create, 2)?;
        assert!(
            source_client.stage_surface_outgoing(&delta, Some(epoch))?.accepted,
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
        Ok(Self { source, peers, config, directory, create, _root: root })
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
async fn two_group_requesters_receive_two_pair_replies_and_no_other_member_or_author_rows()
-> TestResult {
    let mut group = Box::pin(Group::new()).await?;
    let before = group.source.client.direct_messages("thread")?.len();
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
        peer.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
        assert_eq!(peer.client.surface_get("surface", 0, None)?["version"], 2);
    }
    assert_eq!(group.source.client.direct_messages("thread")?.len(), before);
    assert_eq!(group.peers[2].client.direct_messages("thread")?.len(), 1);
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
    let mut pair = Box::pin(Group::new()).await?;
    let author_root = pair.source.client.owned_device_identity()?.root_commitment().to_owned();
    for account in std::iter::once(&pair.source).chain(&pair.peers) {
        account.client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":["author","human"]}),
        )?;
        if account.client.device_branch.as_ref().ok_or("branch")?.principal_id == "human" {
            let human_root = account.client.owned_device_identity()?.root_commitment().to_owned();
            account.client.establish_friend_link("native-resync", &author_root, &human_root)?;
            pair.source.client.establish_friend_link("native-resync", &author_root, &human_root)?;
        }
    }
    let before = pair.source.client.direct_messages("thread")?.len();
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
    pair.peers[0].client.apply_routed_entry(&mut receiver, &pool, &incoming, false).await?;
    let view = pair.peers[0].client.surface_get("surface", 0, None)?;
    assert_eq!(view["version"], 2, "resync must recover the missed version");
    assert_eq!(view["out_of_sync"], false, "valid resync clears the recovery fence");
    assert_eq!(
        view["surface_hash"],
        pair.source.client.surface_get("surface", 0, None)?["surface_hash"],
        "recipient and author commit the same signed base"
    );
    assert_eq!(
        pair.source.client.direct_messages("thread")?.len(),
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
