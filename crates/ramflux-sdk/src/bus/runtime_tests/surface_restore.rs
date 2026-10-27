// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reads admitted during restore use the same methods and persisted surface as warm readers.
use super::{AccountActor, AccountCommand, ActorResponse};
use crate::bus::runtime_tests;
use crate::client::surface::{Carrier, PayloadKind};
use crate::prelude::*;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::oneshot;

fn persisted_surface(root: &Path) -> Result<Value, SdkError> {
    let account = runtime_tests::account(root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let create = crate::SurfaceSendRequest::event(
        "thread",
        1,
        &A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
            surface_id: "surface".into(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "Persisted".into(),
            fallback_markdown: None,
            components: vec![json!({"id":"result","text":"saved"})],
            data_model: serde_json::Map::default(),
            allowed_actions: Vec::new(),
        }),
    )?;
    let mut carrier = Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: "thread".into(),
        surface_id: "surface".into(),
        message_id: create.message_id,
        sender_principal_id: "alice".into(),
        sender_device_id: "device-alice".into(),
        author_principal_id: "alice".into(),
        wire_base64: create.wire_base64,
        signature: String::new(),
        snapshot: None,
    };
    account.client.attach_surface_snapshot(&mut carrier)?;
    let carrier = account.client.sign_surface_carrier(carrier)?;
    assert!(account.client.stage_surface_outgoing(&carrier, None)?.accepted);
    account.client.surface_get("surface", 0, None)
}
fn command(method: &str, body: Value, outbound: mpsc::Sender<LocalBusFrame>) -> AccountCommand {
    AccountCommand {
        private: None,
        request: LocalBusFrame::request(method, Some("alice".into()), "surface", method, body),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: false,
        nodes: None,
        outbound,
        reply: None,
    }
}
fn enqueue(
    actor: &AccountActor,
    mut command: AccountCommand,
) -> Result<oneshot::Receiver<Result<ActorResponse, SdkError>>, SdkError> {
    let (sender, receiver) = oneshot::channel();
    command.reply = Some(sender);
    actor.sender.try_send(command).map_err(|error| SdkError::LocalBus(error.to_string()))?;
    Ok(receiver)
}
#[tokio::test]
async fn surface_reads_queued_during_restart_restore_match_warm_reader_results()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-restore");
    let expected = persisted_surface(&root)?;
    assert_eq!(expected["version"], 1);
    let index = AccountIndex::open(&root)?;
    let (events, mut batches) = mpsc::channel::<crate::bus::events::EventBatch>(64);
    let event_router = tokio::spawn(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let actor = AccountActor::start(
        "alice".into(),
        LocalBusConfig::new(root.join("bus.sock"), &root),
        crate::node::NodeStore::default(),
        index,
        events,
    )?;
    assert!(!actor.is_open(), "restore has not installed the reader pool yet");
    let (outbound, _outbound) = mpsc::channel(8);
    // Reproduce the admitted mailbox path explicitly, so the regression has no timing-dependent sleeps.
    // These requests selected the mailbox while the reader pool was absent; unlock runs first.
    let unlock = enqueue(
        &actor,
        command("account.unlock", json!({"passphrase":"actor-test-secret"}), outbound.clone()),
    )?;
    let get =
        enqueue(&actor, command("surface.get", json!({"surface_id":"surface"}), outbound.clone()))?;
    let list = enqueue(
        &actor,
        command("surface.list", json!({"conversation_id":"thread"}), outbound.clone()),
    )?;
    let directory =
        enqueue(&actor, command("identity.directory", json!({"limit":32}), outbound.clone()))?;
    unlock.await??;
    let queued_get = get.await?;
    let queued_list = list.await?;
    let queued_directory = directory.await?;
    // Stop before checking outcomes so a red regression also closes every reader and writer DB.
    let warm_get = actor
        .request(command("surface.get", json!({"surface_id":"surface"}), outbound.clone()))
        .await?;
    let warm_list = actor
        .request(command("surface.list", json!({"conversation_id":"thread"}), outbound))
        .await?;
    actor.stop().await?;
    drop(actor);
    event_router.await?;
    std::fs::remove_dir_all(root)?;
    assert_eq!(warm_get.body, expected);
    assert_eq!(queued_get?.body, expected);
    assert_eq!(queued_list?.body, warm_list.body);
    assert_eq!(warm_list.body["surfaces"].as_array().map(Vec::len), Some(1));
    assert!(queued_directory?.body["identities"].is_array());
    Ok(())
}

#[tokio::test]
async fn surface_get_and_list_survive_repeated_socket_daemon_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-restore-socket");
    let expected = persisted_surface(&root)?;
    let socket = root.join("bus.sock");
    for _ in 0..2 {
        let (shutdown, receiver) = watch::channel(false);
        let daemon = serve_local_bus_until(LocalBusConfig::new(&socket, &root), receiver);
        let reads = async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut bus = loop {
                if let Ok(bus) = LocalBusClient::connect(&socket).await {
                    break bus;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err("socket did not arrive".into());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };
            loop {
                let status = bus.request(None, "daemon", "daemon.status", json!({})).await?;
                if status["accounts"] == 1 {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err("account did not restore".into());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let get = bus
                .request(
                    Some("alice".into()),
                    "surface",
                    "surface.get",
                    json!({"surface_id":"surface"}),
                )
                .await?;
            let list = bus
                .request(
                    Some("alice".into()),
                    "surface",
                    "surface.list",
                    json!({"conversation_id":"thread"}),
                )
                .await?;
            assert_eq!(get, expected);
            assert_eq!(list["surfaces"].as_array().map(Vec::len), Some(1));
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        let client = async {
            let outcome = tokio::time::timeout(Duration::from_secs(10), reads).await;
            shutdown.send_replace(true);
            outcome?
        };
        let (daemon, client) = tokio::join!(daemon, client);
        daemon?;
        client?;
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}
