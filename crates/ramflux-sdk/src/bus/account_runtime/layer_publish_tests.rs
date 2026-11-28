// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! MEDIA-LAYER-DECL-01 against the real account runtime: the real `apply_connection_work` arm
//! serves every courier checkpoint, so the generation fence, writer ordering and cancellation are
//! the production ones. Every case runs under the shared component watchdog and bounded channels.
use super::*;
use crate::bus::connection_manager::tests::fixture;
use crate::bus::couriers::layer_publish::{pass_with, prepare};
use crate::bus::couriers::writer::Writer;
use crate::client::native_test_support::{Fixture, TestResult};
use std::sync::Arc;
use tokio::sync::Notify;

async fn within<T>(future: impl std::future::Future<Output = TestResult<T>>) -> TestResult<T> {
    crate::client::native_test_support::watchdog::within(
        tokio::task::LocalSet::new().run_until(future),
    )
    .await
    .map_err(|_| "test: deadline exceeded")?
}

/// A live primary with a real connection handle bound to a real runtime and a recording
/// gateway: whatever the account seals and submits for real is inspectable.
struct Rig {
    runtime: AccountRuntime,
    handle: crate::bus::connection_manager::ConnectionHandle,
    _io: crate::bus::connection_manager::tests::SessionIo,
    sealed: Arc<std::sync::Mutex<Vec<crate::bus::test_gateway::Sealed>>>,
    peer: Fixture,
    sender: (String, String),
    _root: crate::custody::tests::Root,
    _directory: tokio::task::JoinHandle<()>,
}

async fn harness(id: &str) -> TestResult<Rig> {
    let mut fixture = Fixture::new(id).await?;
    let peer = Fixture::new(&format!("{id}-peer")).await?;
    let now = crate::custody::network_now()?;
    let account_id = fixture.client.account_db()?.local_account_id.clone();
    crate::custody::tests::mark_live(&fixture.root.0, &account_id, now)?;
    fixture.client.initialize_born_v3_branch("primary", fixture.vault.clone()).await?;
    fixture.client.persist_observed_identity_directory_now(&peer.manifest)?;
    fixture.client.establish_friend_link(
        "layer-link",
        &fixture.manifest.principal_commitment,
        &peer.manifest.principal_commitment,
    )?;
    fixture.client.scaffold_seal_without_fetch.set(false);
    let anchor = fixture.manifest.principal_commitment.clone();
    let sender = (fixture.manifest.principal_id.clone(), anchor.clone());
    let (recorder, sealed) = crate::bus::test_gateway::Recorder::new(Some((
        peer.manifest.principal_commitment.clone(),
        peer.client.load_x3dh_private_state(&peer.client.owned_device_identity()?)?.bundle,
    )));
    let Fixture { client, mut config, root, .. } = fixture;
    // Every new send fetches the peer's current authority: serve it from a real directory.
    let (address, directory) = crate::bus::dispatch::surface_transport::fixture::directory(
        &root.0,
        std::collections::BTreeMap::from([(
            peer.manifest.principal_commitment.clone(),
            serde_json::to_value(&peer.manifest)?,
        )]),
    )
    .await?;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = root.0.join("ca.pem");
    let engine = crate::GatewaySessionEngine::with_test_transport(config, Box::new(recorder));
    let mut account = LocalBusAccountState::new(client, engine, anchor);
    let (handle, io) = fixture_connection().await?;
    account.connection = Some(handle.clone());
    let (runtime, _commands, _stop, _observed) = super::tests::runtime(account, &root.0);
    Ok(Rig { runtime, handle, _io: io, sealed, peer, sender, _root: root, _directory: directory })
}

/// A real `message.submit` body to the peer's primary device.
fn floor_body(rig: &Rig, text: &str) -> TestResult<crate::LocalBusMessageSubmitRequest> {
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &rig.sender.1,
        &rig.peer.manifest.principal_commitment,
    )?;
    Ok(serde_json::from_value(serde_json::json!({
        "conversation_id": conversation, "message_id": format!("m-{text}"),
        "envelope_id": format!("e-{text}"), "source_principal_id": rig.sender.0,
        "sender_id": "primary",
        "recipient_principal_commitment": rig.peer.manifest.principal_commitment,
        "recipient_device_id": rig.peer.config.device_id,
        "target_delivery_id": rig.peer.config.target_delivery_id,
        "encrypted_body_base64": "",
        "plaintext_body_base64": ramflux_protocol::encode_base64url(text.as_bytes()),
        "created_at": crate::time::now_unix_timestamp(), "ttl": 60
    }))?)
}

async fn fixture_connection() -> TestResult<(
    crate::bus::connection_manager::ConnectionHandle,
    crate::bus::connection_manager::tests::SessionIo,
)> {
    fixture().await
}

/// Serve real courier checkpoints until `done` fires or the task ends.
async fn serve<T>(
    runtime: &mut AccountRuntime,
    mut task: tokio::task::JoinHandle<T>,
) -> TestResult<T> {
    loop {
        tokio::select! {
            biased;
            outcome = &mut task => return Ok(outcome?),
            work = runtime.recv_connection_work() => {
                let work = work.ok_or("test: connection work closed")?;
                runtime.apply_connection_work(work).await?;
            }
        }
    }
}

async fn serve_until(runtime: &mut AccountRuntime, ready: &Notify) -> TestResult {
    loop {
        tokio::select! {
            biased;
            () = ready.notified() => return Ok(()),
            work = runtime.recv_connection_work() => {
                let work = work.ok_or("test: connection work closed")?;
                runtime.apply_connection_work(work).await?;
            }
        }
    }
}

fn head_state(runtime: &AccountRuntime) -> TestResult<Option<(String, String)>> {
    let account = runtime.state.accounts.get("sender").ok_or("test: account")?;
    Ok(account.client.account_db()?.pairing_head()?.map(|head| (head.kind, head.state)))
}

fn declared(runtime: &AccountRuntime) -> bool {
    runtime.state.accounts.get("sender").is_some_and(|account| {
        account.client.born_v3_account.as_deref().is_some_and(|born| {
            born.record().body.devices.iter().any(|device| device.message_layer.is_some())
        })
    })
}

#[tokio::test]
async fn held_publish_keeps_the_real_actor_serving_floor_sends_and_a_stale_session_apply_is_dropped()
-> TestResult {
    within(Box::pin(async {
        let mut rig = Box::pin(harness("layer-real-actor")).await?;
        let handle = rig.handle.clone();
        let writer = Writer::new(rig.runtime.connection_sender.clone(), handle.generation());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let held = {
            let (writer, started, release) =
                (writer.clone(), Arc::clone(&started), Arc::clone(&release));
            tokio::spawn(async move {
                pass_with(writer, move |input| async move {
                    started.notify_one();
                    release.notified().await;
                    Ok(ramflux_protocol::custody::object_hash(&input.publication().record)?)
                })
                .await
            })
        };
        serve_until(&mut rig.runtime, &started)
            .await
            .map_err(|e| format!("step serve_until: {e}"))?;
        assert_eq!(
            head_state(&rig.runtime)?,
            Some(("layer_update".into(), "submitted".into())),
            "the candidate must be durable and submitted before Publish starts"
        );
        // A real floor send: the account seals generation-1 content and the gateway receives it
        // while the Publish is still held.
        let body = floor_body(&rig, "floor")?;
        let account = rig.runtime.state.accounts.get_mut("sender").ok_or("test: account")?;
        // The ordinary send path runs over the account's gateway engine (the recording gateway);
        // the scripted connection handle only fences courier checkpoints.
        let connection = account.connection.take();
        let sent =
            Box::pin(crate::bus::dispatch::message::submit_conversation_message(account, body))
                .await
                .map_err(|e| format!("step floor send: {e:?}"));
        account.connection = connection;
        sent?;
        assert!(!held.is_finished(), "the layer Publish must still be held while the send ran");
        {
            let sealed = rig.sealed.lock().map_err(|_| "test: recorder poisoned")?;
            assert_eq!(
                sealed.len(),
                1,
                "exactly one sealed copy must reach the gateway: {sealed:?}"
            );
            assert_eq!(
                sealed[0].target_delivery_id, rig.peer.config.target_delivery_id,
                "the sealed copy must address the peer's device"
            );
            assert!(sealed[0].payload_bytes > 0, "the sealed payload must carry ciphertext");
        }
        // The session is replaced while Publish is held: the late Apply must be dropped.
        let (replacement, _replacement_io) = fixture_connection().await?;
        rig.runtime
            .state
            .accounts
            .get_mut("sender")
            .ok_or("test: account")?
            .connection
            .replace(replacement.clone());
        release.notify_one();
        let late = serve(&mut rig.runtime, held).await?;
        assert!(late.is_err(), "an Apply carrying the old generation must be refused: {late:?}");
        assert!(!declared(&rig.runtime), "a stale-session Apply must install nothing");
        assert_eq!(
            head_state(&rig.runtime)?,
            Some(("layer_update".into(), "submitted".into())),
            "the submitted row must survive for recovery"
        );
        // The new session resumes the very same candidate and completes it.
        let new_writer =
            Writer::new(rig.runtime.connection_sender.clone(), replacement.generation());
        let resumed = tokio::spawn(async move {
            pass_with(new_writer, |input| async move {
                Ok(ramflux_protocol::custody::object_hash(&input.publication().record)?)
            })
            .await
        });
        assert!(serve(&mut rig.runtime, resumed).await??, "the new session must complete it");
        assert!(declared(&rig.runtime), "the resumed candidate must be installed");
        assert_eq!(head_state(&rig.runtime)?, None, "the journal row must be retired");
        handle.stop().await;
        replacement.stop().await;
        Ok(())
    }))
    .await
}

static STARTED: Notify = Notify::const_new();

async fn held_pass(
    _context: crate::bus::connection_manager::SessionContext,
    writer: Writer,
) -> Result<bool, crate::SdkError> {
    pass_with(writer, |_input| async {
        STARTED.notify_one();
        std::future::pending::<Result<String, crate::SdkError>>().await
    })
    .await
}

#[tokio::test]
async fn lock_or_stop_cancels_the_real_courier_leaving_no_lock_and_a_resumable_row() -> TestResult {
    within(Box::pin(async {
        let mut rig = Box::pin(harness("layer-real-stop")).await?;
        let handle = rig.handle.clone();
        let sender = rig.runtime.connection_sender.clone();
        let context = handle.test_context();
        let child = tokio::spawn(crate::bus::couriers::runner::run(
            context,
            sender.clone(),
            "layer-publish",
            held_pass,
        ));
        serve_until(&mut rig.runtime, &STARTED).await?;
        // Stop is the same cancellation that Lock and teardown deliver to every session child.
        handle.stop().await;
        serve(&mut rig.runtime, child).await?;
        assert_eq!(
            head_state(&rig.runtime)?,
            Some(("layer_update".into(), "submitted".into())),
            "cancellation must keep the submitted row"
        );
        // No signing or authority lock survived the cancelled await: both are available now.
        let account = rig.runtime.state.accounts.get_mut("sender").ok_or("test: account")?;
        let born = account.client.born_v3_account.as_deref().ok_or("test: native")?;
        let config = account.gateway_config.custody.clone().ok_or("test: custody")?;
        drop(born.group_primary(config.vault.as_ref())?);
        drop(crate::custody::pairing::activate::authority_lock(
            &config.account_root,
            &config.account_id,
        )?);
        let resumed = prepare(account)?.ok_or("test: resume plan")?;
        assert!(!resumed.expected().is_empty(), "the same candidate must resume");
        Ok(())
    }))
    .await
}
