// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real deferred uploads wait for durable actor checkpoints and reject stale generations.

use super::fixture::{Case, Fixture};
use super::receive_ack::{Started, command, controls, start};
use super::relay_fixture::{Observe, Relay, Step};
use crate::bus::transfer_slots::test_hooks::{Held, Hook};
use crate::prelude::*;
use serde_json::json;
use std::{rc::Rc, sync::Arc};
use tokio::sync::oneshot;

const OBJECT: &str = "checkpoint-upload";
const OPERATION: &str = "checkpoint-upload-operation";
fn finish() -> crate::bus::actor::AccountCommand {
    let mut request =
        command("object.put.finish", json!({"object_id":OBJECT,"operation_id":OPERATION}));
    request.request.operation_id = Some("generic-upload-receipt".into());
    request
}
struct Upload {
    started: Started,
    relay: Relay,
    held: Held,
    hook: Arc<Hook>,
    reader: Rc<AccountDb>,
    result: tokio::task::JoinHandle<Result<crate::bus::actor::ActorResponse, SdkError>>,
}
async fn held_upload() -> Case<Upload> {
    let mut fixture = Box::pin(Fixture::new("transfer-upload-checkpoints")).await?;
    let reader = Rc::new(fixture.source.client.account_db()?.open_reader()?);
    let query = Rc::clone(&reader);
    let observe: Observe = Rc::new(move |step, index, _| {
        if step == Step::Put && index > 0 {
            let row = query
                .object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD))?
                .ok_or("PUT preceded durable U1")?;
            assert!(
                row.completed_chunks.contains(&(index - 1)),
                "next PUT preceded prior durable bitmap"
            );
        }
        Ok(())
    });
    let relay = Relay::start(observe).await?;
    configure_upload_relay(&mut fixture, &relay)?;
    let (hook, mut capture) = Hook::upload_chunk(0);
    fixture.source.test_transfer_hook = Some(Arc::clone(&hook));
    let started = Box::pin(start(fixture)).await?;
    begin_upload(&started.actor, &relay).await?;
    let actor = started.actor.clone();
    let mut result = tokio::task::spawn_local(async move { actor.request(finish()).await });
    let held = wait_for_upload_checkpoint(&mut capture, &mut result, &relay).await?;
    Ok(Upload { started, relay, held, hook, reader, result })
}
async fn wait_for_upload_checkpoint(
    capture: &mut tokio::sync::mpsc::UnboundedReceiver<Held>,
    result: &mut tokio::task::JoinHandle<Result<crate::bus::actor::ActorResponse, SdkError>>,
    relay: &Relay,
) -> Case<Held> {
    tokio::select! {
        held = tokio::time::timeout(Duration::from_secs(10), capture.recv()) => {
            match held {
                Ok(Some(held)) => Ok(held),
                other => {
                    let state = relay.state.lock().map_err(|_| "relay")?;
                    Err(format!("U1 was not captured ({}); requests={:?}, relay errors={:?}",
                        if other.is_err() { "deadline expired" } else { "channel closed" }, state.requests, state.errors).into())
                }
            }
        }
        finished = result => {
            let state = relay.state.lock().map_err(|_| "relay")?;
            let finished = finished.map(|result| result.map(|reply| reply.body));
            Err(format!("upload ended before U1: {finished:?}; requests={:?}, relay errors={:?}", state.requests, state.errors).into())
        }
    }
}
fn configure_upload_relay(fixture: &mut Fixture, relay: &Relay) -> Case {
    let mut options = parse_relay_transfer_options(Some(relay.endpoint.clone()), None, None)?
        .ok_or("fixture relay options")?;
    options.token_provider = RelayTokenProvider::LocalMint { relay_service_key: vec![41; 32] };
    fixture.source.client.node_relay_options = Some(options);
    Ok(())
}
async fn begin_upload(actor: &crate::bus::actor::AccountActor, relay: &Relay) -> Case {
    let plaintext = vec![42; 512];
    let begin = json!({"object_id":OBJECT,"operation_id":OPERATION,"total_len":plaintext.len(),
        "plaintext_hash":ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT,&plaintext),
        "chunk_size":128,"protocol_version":1,"relay_endpoint":relay.endpoint,
        "relay_service_key_base64":ramflux_protocol::encode_base64url([41;32])});
    actor.request(command("object.put.begin", begin)).await?;
    actor
        .request(command(
            "object.put.chunk",
            json!({"operation_id":OPERATION,"offset":0,
        "data_base64":ramflux_protocol::encode_base64url(&plaintext)}),
        ))
        .await?;
    Ok(())
}
fn durable_chunks(reader: &AccountDb) -> Case<Vec<u32>> {
    Ok(reader
        .object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD))?
        .map_or_else(Vec::new, |row| row.completed_chunks))
}
fn upload_snapshot(reader: &AccountDb) -> Case<serde_json::Value> {
    Ok(json!({
        "operation":reader.object_operation(OBJECT)?,
        "transfer":reader.object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD))?,
        "chunks":durable_chunks(reader)?,
    }))
}
async fn cleanup(started: Started, reader: Rc<AccountDb>, relay: Relay) -> Case {
    started.actor.stop().await?;
    let root = started.root.clone();
    drop(started.actor);
    started.router.await?;
    drop(reader);
    drop(relay);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn upload_waits_for_u1_before_the_next_put_and_replays_its_committed_result() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Upload { started, relay, held, reader, result, .. } =
                Box::pin(held_upload()).await?;
            assert!(held.upload_ack_is_open());
            assert_eq!(durable_chunks(&reader)?, Vec::<u32>::new());
            assert!(!result.is_finished());
            controls(&started.actor).await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(relay.state.lock().map_err(|_| "relay")?.requests, vec![(Step::Put, 0)]);
            assert!(durable_chunks(&reader)?.is_empty(), "hold must precede U1 persistence");
            held.release().await?;
            let response = result.await??;
            let row = reader.object_operation(OBJECT)?.ok_or("operation")?;
            assert_eq!(row.state, OBJECT_OPERATION_COMMITTED);
            let transfer =
                reader.object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD))?.ok_or("transfer")?;
            assert_eq!(transfer.state, "complete");
            assert_eq!(u32::try_from(transfer.completed_chunks.len())?, transfer.total_chunks);
            assert_eq!(
                crate::bus::mutation_intent::MutationIntent::new(&finish().request)?
                    .lookup(&reader)?,
                Some(response.body.clone()),
                "the deferred reply must follow durable complete_operation",
            );
            let before = relay.state.lock().map_err(|_| "relay")?.requests.clone();
            let replay = started.actor.request(finish()).await?;
            assert_eq!(replay.body, response.body, "lost-reply retry must replay Committed");
            assert_eq!(relay.state.lock().map_err(|_| "relay")?.requests, before);
            assert_eq!(relay.state.lock().map_err(|_| "relay")?.errors, Vec::<String>::new());
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn stale_u1_is_aborted_after_lock_and_unlock_with_other_checkpoint_inputs_still_valid() -> Case
{
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Upload { started, relay, mut held, hook, reader, result } =
                Box::pin(held_upload()).await?;
            let old = started.actor.connection_for_test().ok_or("connection")?;
            let generation = old.generation();
            started.actor.request(command("account.lock", json!({}))).await?;
            assert!(old.test_finished());
            assert!(
                hook.all_jobs_finished(),
                "lock reply must follow transfer worker cancellation"
            );
            assert!(result.await?.is_err());
            assert!(
                !held.upload_ack_is_open(),
                "the canceled worker must drop its checkpoint receiver"
            );
            // Lock retires the old actor; reopening data creates the next account generation.
            let started = Box::pin(started.restart()).await?;
            let new = started.actor.connection_for_test().ok_or("new connection")?;
            assert_ne!(new.generation(), generation);
            let operation = reader.object_operation(OBJECT)?.ok_or("operation survived lock")?;
            assert_eq!(operation.state, OBJECT_OPERATION_LOCAL_COMMITTED);
            assert!(reader.load_object::<EncryptedObject>(OBJECT)?.is_some());
            let before = upload_snapshot(&reader)?;
            let ack = held.replace_upload_ack().ok_or("upload checkpoint")?;
            held.release_to_actor(&started.actor).await?;
            assert!(ack.await?.is_err(), "stale generation must answer Abort, not Continue");
            assert_eq!(upload_snapshot(&reader)?, before);
            assert_eq!(relay.state.lock().map_err(|_| "relay")?.requests, vec![(Step::Put, 0)]);
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reads_stay_fast_during_a_slow_upload_and_lock_joins_its_worker() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let clock = tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            });
            let Upload { started, relay, held, hook, reader, result } =
                Box::pin(held_upload()).await?;
            let network = Arc::new(super::fixture::GatewayHold::default());
            relay.state.lock().map_err(|_| "relay")?.hold =
                Some((Step::Put, 1, Arc::clone(&network)));
            held.release().await?;
            network.entered.notified().await;
            assert!(!hook.all_jobs_finished());
            tokio::time::advance(Duration::from_secs(30)).await;
            assert!(!result.is_finished(), "the upload must remain held after thirty seconds");
            tokio::time::resume();
            clock.abort();
            controls(&started.actor).await?;
            let connection = started.actor.connection_for_test().ok_or("connection")?;
            let wall = std::time::Instant::now();
            started.actor.request(command("account.lock", json!({}))).await?;
            assert!(wall.elapsed() < Duration::from_secs(1));
            assert!(connection.test_finished());
            assert_eq!(
                hook.lock_workers_finished(),
                Some(true),
                "explicit lifecycle cancellation must join the worker before final actor teardown"
            );
            assert!(hook.all_jobs_finished(), "worker must be finished before lock reply");
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if relay.state.lock().map_err(|_| "relay")?.dropped.contains(&(Step::Put, 1)) {
                        return Ok::<_, Box<dyn std::error::Error>>(());
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await??;
            network.release.notify_one();
            assert!(result.await?.is_err());
            assert_eq!(durable_chunks(&reader)?, vec![0]);
            assert_eq!(
                reader.object_operation(OBJECT)?.ok_or("local operation")?.state,
                OBJECT_OPERATION_LOCAL_COMMITTED
            );
            let path =
                crate::bus::dispatch::object::object_put_spool_dir(&started.root.join("source"));
            if path.exists() {
                for account in std::fs::read_dir(path)? {
                    assert!(
                        std::fs::read_dir(account?.path())?.next().is_none(),
                        "spool and journal must be removed on cancel"
                    );
                }
            }
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn upload_relay_failure_persists_local_committed_and_last_error_at_u3() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Upload { started, relay, held, reader, result, .. } =
                Box::pin(held_upload()).await?;
            relay.state.lock().map_err(|_| "relay")?.failure = Some((Step::Put, 2));
            held.release().await?;
            assert!(result.await?.is_err());
            let operation = reader.object_operation(OBJECT)?.ok_or("operation")?;
            assert_eq!(operation.state, OBJECT_OPERATION_LOCAL_COMMITTED);
            assert!(
                operation.last_error.as_ref().is_some_and(|error| !error.is_empty()),
                "U3 must retain its retryable failure"
            );
            assert_eq!(durable_chunks(&reader)?, vec![0, 1]);
            let status = started
                .actor
                .request(command(
                    "object.put.status",
                    json!({"object_id":OBJECT,"operation_id":OPERATION}),
                ))
                .await?;
            assert_eq!(status.body["state"], OBJECT_OPERATION_LOCAL_COMMITTED);
            assert_eq!(status.body["last_error"], serde_json::to_value(operation.last_error)?);
            retry_durable_upload(&started, &reader, &relay).await?;
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}
async fn retry_durable_upload(started: &Started, reader: &AccountDb, relay: &Relay) -> Case {
    let prefix = durable_chunks(reader)?;
    let (before, _) = reader.load_object::<EncryptedObject>(OBJECT)?.ok_or("local object")?;
    relay.state.lock().map_err(|_| "relay")?.failure = None;
    begin_upload(&started.actor, relay).await?;
    let mut request = finish();
    // The object operation resumes; the failed generic receipt retains its fail-closed contract.
    request.request.operation_id = None;
    started.actor.request(request).await?;
    let (after, _) = reader.load_object::<EncryptedObject>(OBJECT)?.ok_or("adopted object")?;
    for index in prefix {
        assert_eq!(
            relay
                .state
                .lock()
                .map_err(|_| "relay")?
                .requests
                .iter()
                .filter(|(step, i)| *step == Step::Put && *i == index)
                .count(),
            1,
            "every durable chunk must be skipped on adoption"
        );
    }
    assert_eq!(before.manifest_hash, after.manifest_hash, "resume must adopt existing ciphertext");
    assert_eq!(before.nonce, after.nonce);
    assert_eq!(
        reader.object_operation(OBJECT)?.ok_or("completed operation")?.state,
        OBJECT_OPERATION_COMMITTED
    );
    assert_eq!(
        reader
            .object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD))?
            .ok_or("complete transfer")?
            .state,
        "complete"
    );
    assert_eq!(
        relay
            .state
            .lock()
            .map_err(|_| "relay")?
            .requests
            .iter()
            .filter(|(step, index)| *step == Step::Put && *index == 0)
            .count(),
        1,
        "the durable chunk must not upload twice"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn upload_caller_disconnect_preserves_local_commit_and_removes_spool_and_journal() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Upload { started, relay, held, hook, reader, result } =
                Box::pin(held_upload()).await?;
            result.abort();
            assert!(result.await.is_err(), "the request caller must disconnect");
            tokio::time::timeout(Duration::from_secs(1), async {
                while !hook.all_jobs_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            assert!(
                !held.upload_ack_is_open(),
                "the canceled job must drop its checkpoint receiver"
            );
            assert_eq!(
                reader.object_operation(OBJECT)?.ok_or("local operation")?.state,
                OBJECT_OPERATION_LOCAL_COMMITTED
            );
            assert!(reader.load_object::<EncryptedObject>(OBJECT)?.is_some());
            assert_eq!(durable_chunks(&reader)?, Vec::<u32>::new());
            assert_eq!(relay.state.lock().map_err(|_| "relay")?.requests, vec![(Step::Put, 0)]);
            assert_no_spool(&started)?;
            drop(held);
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}

fn assert_no_spool(started: &Started) -> Case {
    let path = crate::bus::dispatch::object::object_put_spool_dir(&started.root.join("source"));
    if path.exists() {
        for account in std::fs::read_dir(path)? {
            assert!(
                std::fs::read_dir(account?.path())?.next().is_none(),
                "spool and journal must be removed on cancel"
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn upload_restart_adopts_local_ciphertext_and_skips_the_durable_u1_prefix() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Upload { started, relay, held, hook, reader, result } =
                Box::pin(held_upload()).await?;
            let network = Arc::new(super::fixture::GatewayHold::default());
            relay.state.lock().map_err(|_| "relay")?.hold =
                Some((Step::Put, 1, Arc::clone(&network)));
            held.release().await?;
            tokio::time::timeout(Duration::from_secs(10), network.entered.notified()).await?;
            assert_eq!(durable_chunks(&reader)?, vec![0]);
            assert_eq!(
                reader.object_operation(OBJECT)?.ok_or("local operation")?.state,
                OBJECT_OPERATION_LOCAL_COMMITTED
            );
            let started = Box::pin(started.restart()).await?;
            assert!(result.await?.is_err());
            assert!(hook.first_job_finished());
            assert_no_spool(&started)?;
            let status = started
                .actor
                .request(command(
                    "object.put.status",
                    json!({"object_id":OBJECT,"operation_id":OPERATION}),
                ))
                .await?;
            assert_eq!(status.body["state"], OBJECT_OPERATION_LOCAL_COMMITTED);
            relay.state.lock().map_err(|_| "relay")?.hold = None;
            network.release.notify_one();
            retry_durable_upload(&started, &reader, &relay).await?;
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn upload_reopens_local_committed_before_the_first_relay_effect_and_adopts_it_once() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let mut fixture = Box::pin(Fixture::new("upload-pre-network-recovery")).await?;
            let reader = Rc::new(fixture.source.client.account_db()?.open_reader()?);
            let relay = Relay::start(Rc::new(|_, _, _| Ok(()))).await?;
            configure_upload_relay(&mut fixture, &relay)?;
            let (hook, entered, release) = Hook::upload_start();
            fixture.source.test_transfer_hook = Some(Arc::clone(&hook));
            let started = Box::pin(start(fixture)).await?;
            begin_upload(&started.actor, &relay).await?;
            let actor = started.actor.clone();
            let result = tokio::task::spawn_local(async move { actor.request(finish()).await });
            tokio::time::timeout(Duration::from_secs(10), entered).await??;
            assert_eq!(
                reader.object_operation(OBJECT)?.ok_or("local commit before first PUT")?.state,
                OBJECT_OPERATION_LOCAL_COMMITTED
            );
            assert!(reader.load_object::<EncryptedObject>(OBJECT)?.is_some());
            assert_eq!(
                relay.state.lock().map_err(|_| "relay")?.requests,
                Vec::<(Step, u32)>::new()
            );
            let started = Box::pin(started.restart()).await?;
            assert!(hook.first_job_finished());
            assert!(result.await?.is_err());
            assert!(release.send(()).is_err(), "stopped job must no longer hold the barrier");
            let status = started
                .actor
                .request(command(
                    "object.put.status",
                    json!({"object_id":OBJECT,"operation_id":OPERATION}),
                ))
                .await?;
            assert_eq!(status.body["state"], OBJECT_OPERATION_LOCAL_COMMITTED);
            assert_eq!(
                relay.state.lock().map_err(|_| "relay")?.requests,
                Vec::<(Step, u32)>::new()
            );
            retry_durable_upload(&started, &reader, &relay).await?;
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn full_upload_queue_refuses_before_generic_or_object_pending_is_written() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Fixture { root, source, peer, sibling, .. } =
                Box::pin(Fixture::new("upload-queue-before-pending")).await?;
            let (mut runtime, _, _, _) = super::runtime(source, &root.join("source"));
            let permits = (0..crate::bus::runtime_limits::TRANSFER_QUEUE)
                .map(|_| runtime.transfers.slots.reserve())
                .collect::<Result<Vec<_>, _>>()?;
            let wall = std::time::Instant::now();
            let (reply, response) = oneshot::channel();
            runtime.start_upload(finish(), reply).await?;
            let error = response.await?.err().ok_or("full queue accepted an upload")?;
            assert!(wall.elapsed() < Duration::from_secs(1));
            assert!(matches!(
                error,
                SdkError::Transport(ramflux_transport::TransportError::BackpressureRejected { .. })
            ));
            let account = runtime.state.accounts.get("sender").ok_or("account")?;
            let db = account.client.account_db()?;
            assert!(
                crate::bus::mutation_intent::MutationIntent::new(&finish().request)?
                    .lookup(db)?
                    .is_none(),
                "full transfer queue must not leave a generic Pending receipt"
            );
            assert!(
                db.object_operation(OBJECT)?.is_none(),
                "full transfer queue must not write object Pending"
            );
            drop(permits);
            runtime.transfers.stop().await;
            runtime.stop_courier().await;
            runtime.close_readers().await;
            drop(runtime);
            drop(peer);
            drop(sibling);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))))
        .await
}

#[path = "transfer_upload_erasure.rs"]
mod erasure;

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn slow_upload_completes_its_deferred_receipt_after_local_controls_remain_responsive() -> Case
{
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let clock = tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            });
            let Upload { started, relay, held, reader, result, .. } =
                Box::pin(held_upload()).await?;
            let network = Arc::new(super::fixture::GatewayHold::default());
            relay.state.lock().map_err(|_| "relay")?.hold =
                Some((Step::Put, 1, Arc::clone(&network)));
            held.release().await?;
            network.entered.notified().await;
            tokio::time::advance(Duration::from_secs(30)).await;
            assert!(!result.is_finished(), "upload must still be held after thirty seconds");
            tokio::time::resume();
            clock.abort();
            controls(&started.actor).await?;
            assert!(!result.is_finished(), "controls must finish before relay release");
            network.release.notify_one();
            let response = result.await??;
            assert_eq!(
                reader.object_operation(OBJECT)?.ok_or("completed operation")?.state,
                OBJECT_OPERATION_COMMITTED
            );
            assert_eq!(
                crate::bus::mutation_intent::MutationIntent::new(&finish().request)?
                    .lookup(&reader)?,
                Some(response.body)
            );
            assert_eq!(
                reader
                    .object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD))?
                    .ok_or("complete transfer")?
                    .state,
                "complete"
            );
            Box::pin(cleanup(started, reader, relay)).await
        }))))
        .await
}
