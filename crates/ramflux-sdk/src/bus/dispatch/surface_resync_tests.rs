// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group recovery is a bounded pair reply, without group broadcasts or unrelated timeline writes.
use super::*;
use crate::bus::runtime_tests;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Group {
    root: PathBuf,
    source: LocalBusAccountState,
    peers: Vec<LocalBusAccountState>,
    config: GatewaySessionConfig,
    directory: tokio::task::JoinHandle<()>,
    create: Carrier,
}
impl Group {
    async fn new() -> TestResult<Self> {
        let root = runtime_tests::root("surface-private-resync");
        let mut source = runtime_tests::account(
            &root.join("source"),
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let peers = super::tests::members(&root, &source, 3)?;
        let (config, directory) =
            super::tests::directory_config(&root, &mut source, &peers).await?;
        source.client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"group","group_id":"group"}),
        )?;
        let captured = Arc::new(Mutex::new(Vec::new()));
        source.put_engine(GatewaySessionEngine::with_test_transport(
            config.clone(),
            Box::new(super::fixture::RecordingGateway::new(Arc::clone(&captured))),
        ));
        let wire = crate::SurfaceSendRequest::event(
            "thread",
            1,
            &A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
                surface_id: "surface".into(),
                surface_type: SurfaceType::StatusPanel,
                catalog: "basic".into(),
                catalog_version: "1".into(),
                fallback_text: "中文 é 🦀".into(),
                fallback_markdown: None,
                components: vec![json!({"id":"result","text":""})],
                data_model: serde_json::Map::default(),
                allowed_actions: Vec::new(),
            }),
        )?;
        let mut create = super::dm_tests::create_carrier(&source.client)?;
        create.wire_base64 = wire.wire_base64;
        create.snapshot = None;
        source.client.attach_surface_snapshot(&mut create)?;
        create = source.client.sign_surface_carrier(create)?;
        send(&mut source, &create).await?;
        let frames = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let mut deliveries = Vec::new();
        for peer in &peers {
            let principal = &peer
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .principal_id;
            deliveries.extend(
                frames
                    .iter()
                    .filter(|frame| &frame.target_delivery_id == principal)
                    .cloned()
                    .map(|envelope| super::tests::Delivery { envelope }),
            );
        }
        super::tests::assert_receivers(
            &peers,
            &deliveries,
            source.client.group_state("group")?.group_epoch,
            1,
        )?;
        for peer in &peers {
            peer.client.persist_identity_directory(&super::fixture::manifest(&source.client)?)?;
            let branch = peer.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let envelope = frames
                .iter()
                .rev()
                .find(|e| e.target_delivery_id == branch.principal_id)
                .ok_or("delivery")?
                .clone();
            let entry = GatewayInboxEntry {
                forwarded: false,
                inbox_seq: 2,
                target_delivery_id: envelope.target_delivery_id.clone(),
                envelope,
            };
            let opened = peer.client.open_routed(&entry, &branch.device_id)?;
            peer.client.persist_pair(
                &opened.local_device,
                &opened.remote_device,
                &opened.bundle_hash,
                &opened.session,
            )?;
            peer.client.send_direct_message(
                "thread",
                "initial-visible",
                "device-sender",
                b"encrypted",
            )?;
        }
        let delta = super::own_tests::append(&source.client, &create, 2)?;
        send(&mut source, &delta).await?;
        Ok(Self { root, source, peers, config, directory, create })
    }
    fn peer_config(&self, index: usize) -> TestResult<GatewaySessionConfig> {
        let branch =
            self.peers[index].client.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let mut config = self.config.clone();
        config.principal_id = branch.principal_id.clone();
        config.device_id = branch.device_id.clone();
        config.target_delivery_id = branch.principal_id.clone();
        config = config.with_account_identity(&self.peers[index].client)?;
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
        peer.put_engine(GatewaySessionEngine::with_test_transport(
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
    group.source.put_engine(GatewaySessionEngine::with_test_transport(
        group.config.clone(),
        Box::new(gateway),
    ));
    assert_eq!(crate::bus::sync_driver::run(&mut group.source).await?, 2);
    let frames = replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(frames.len(), 2);
    assert!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty());
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    for index in 0..2 {
        let config = group.peer_config(index)?;
        let envelope = frames
            .iter()
            .find(|e| e.target_delivery_id == config.principal_id)
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
    group
        .source
        .put_engine(GatewaySessionEngine::with_test_transport(group.config, Box::new(gateway)));
    assert_eq!(crate::bus::sync_driver::run(&mut group.source).await?, 1);
    assert_eq!(replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 2);
    group.directory.abort();
    drop(group.peers);
    drop(group.source);
    std::fs::remove_dir_all(group.root)?;
    Ok(())
}
