// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fetch restart preserves chunk and ACK progress across writer-owned durability boundaries.

use super::fixture::{Case, Fixture};
use super::receive_ack::{Started, command, controls, start};
use super::relay_fixture::{Observe, Relay, Step};
use crate::bus::transfer_slots::test_hooks::{Held, Hook};
use crate::prelude::*;
use serde_json::Value;
use std::{rc::Rc, sync::Arc};

const OBJECT: &str = "history-object";
type Reply = tokio::task::JoinHandle<Result<crate::bus::actor::ActorResponse, SdkError>>;
struct Progress {
    reader: Rc<AccountDb>,
    relay: Relay,
    total: u32,
}
enum Boundary {
    Import,
    Ack,
    Authorize,
    Slot,
}
struct Rig {
    started: Started,
    progress: Progress,
    hook: Arc<Hook>,
    capture: mpsc::UnboundedReceiver<Held>,
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_before_f2_sends_no_ack_and_restarts_from_durable_f1_chunks() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case(false)))))
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_restart_skips_durable_acks_and_repeats_only_the_unconfirmed_ack() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case(true)))))
        .await
}
fn observe(reader: Rc<AccountDb>) -> Observe {
    Rc::new(move |step, index, _| {
        if step == Step::Get {
            let state = reader
                .load_actor_state::<Value>(&format!("attachment/fetch/{OBJECT}"))?
                .ok_or("GET before F0")?;
            assert!(state["attempts"].as_u64().is_some_and(|attempts| attempts > 0));
            assert!(matches!(state["transfer_state"].as_str(), Some("fetching" | "retrying")));
            if index > 0 {
                let transfer = reader
                    .object_transfer(OBJECT, Some(OBJECT_TRANSFER_DOWNLOAD))?
                    .ok_or("GET before F1")?;
                assert!(transfer.completed_chunks.contains(&(index - 1)));
                assert!(
                    reader.actor_state_keys(&format!("attachment/chunk/{OBJECT}/"))?.len()
                        >= usize::try_from(index)?
                );
            }
        }
        if step == Step::Ack {
            assert!(
                reader.load_object::<EncryptedObject>(OBJECT)?.is_some(),
                "ACK before verified import"
            );
            assert_eq!(
                reader
                    .object_transfer(OBJECT, Some(OBJECT_TRANSFER_DOWNLOAD))?
                    .ok_or("verified transfer")?
                    .state,
                "complete"
            );
            assert_eq!(
                reader.actor_state_keys("attachment/ack/")?.len(),
                usize::try_from(index)?,
                "next ACK before F4"
            );
        }
        Ok(())
    })
}
async fn rig(boundary: Boundary) -> Case<Rig> {
    let mut fixture = Box::pin(Fixture::new("transfer-fetch-checkpoints")).await?;
    let reader = Rc::new(fixture.source.client.account_db()?.open_reader()?);
    let relay = Relay::start(observe(Rc::clone(&reader))).await?;
    let (sync, total) = super::receive_history_relay::prepare(&mut fixture, &relay)?;
    assert!(total > 1, "the ACK-restart fixture must have more than one chunk");
    fixture.source.client.account_db()?.send_direct_message(
        "fetch-thread",
        "fetch-message",
        "sender",
        b"local attachment reference",
    )?;
    fixture.source.client.persist_received_attachment_reference(
        &sync.history_ref,
        "sender",
        "fetch-thread",
        "fetch-message",
    )?;
    let (hook, capture) = match boundary {
        Boundary::Import => Hook::fetch_import(),
        Boundary::Ack => Hook::fetch_ack(1),
        Boundary::Authorize => Hook::fetch_authorize(),
        Boundary::Slot => Hook::fetch_slot(),
    };
    fixture.source.test_transfer_hook = Some(Arc::clone(&hook));
    let started = Box::pin(start(fixture)).await?;
    Ok(Rig { started, progress: Progress { reader, relay, total }, hook, capture })
}
fn fetch(started: &Started) -> Reply {
    let actor = started.actor.clone();
    tokio::task::spawn_local(async move {
        actor
            .request(command(
                "object.fetch",
                serde_json::json!({"object_id":OBJECT,"operation_id":"fetch-restart"}),
            ))
            .await
    })
}
impl Progress {
    fn before_stop(&self, held: &Held, after_ack: bool) -> Case {
        assert!(held.fetch_reply_is_open());
        assert_eq!(
            self.reader.load_object::<EncryptedObject>(OBJECT)?.is_some(),
            after_ack,
            "hold must match the selected durability boundary"
        );
        if !after_ack {
            assert!(held.import_ack_is_open());
        }
        let transfer = self
            .reader
            .object_transfer(OBJECT, Some(OBJECT_TRANSFER_DOWNLOAD))?
            .ok_or("F1 transfer")?;
        assert_eq!(u32::try_from(transfer.completed_chunks.len())?, self.total);
        assert_eq!(
            self.reader.actor_state_keys(&format!("attachment/chunk/{OBJECT}/"))?.len(),
            usize::try_from(self.total)?
        );
        let acked = self
            .relay
            .state
            .lock()
            .map_err(|_| "relay")?
            .requests
            .iter()
            .filter(|(step, _)| *step == Step::Ack)
            .count();
        assert_eq!(acked, if after_ack { 2 } else { 0 }, "no ACK may pass the selected checkpoint");
        assert_eq!(self.reader.actor_state_keys("attachment/ack/")?.len(), usize::from(after_ack));
        Ok(())
    }
    async fn available(&self) -> Case {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let errors = self.relay.state.lock().map_err(|_| "relay")?.errors.clone();
                if !errors.is_empty() {
                    return Err(format!("relay errors: {errors:?}").into());
                }
                if self
                    .reader
                    .load_actor_state::<Value>(&format!("attachment/fetch/{OBJECT}"))?
                    .is_some_and(|state| state["transfer_state"] == "available")
                {
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?
    }
    fn completed(&self, after_ack: bool) -> Case {
        let state = self.relay.state.lock().map_err(|_| "relay")?;
        assert_eq!(
            state.requests.iter().filter(|(step, _)| *step == Step::Get).count(),
            usize::try_from(self.total)?,
            "restart must reuse every durable F1 chunk"
        );
        assert_eq!(
            state.requests.iter().filter(|(step, _)| *step == Step::Ack).count(),
            usize::try_from(self.total)? + usize::from(after_ack)
        );
        if after_ack {
            assert_eq!(
                state
                    .requests
                    .iter()
                    .filter(|(step, index)| *step == Step::Ack && *index == 0)
                    .count(),
                1,
                "durable ACK0 must not repeat"
            );
            assert_eq!(
                state
                    .requests
                    .iter()
                    .filter(|(step, index)| *step == Step::Ack && *index == 1)
                    .count(),
                2,
                "only the unconfirmed ACK may repeat"
            );
        }
        assert!(self.reader.load_object::<EncryptedObject>(OBJECT)?.is_some());
        let state = self
            .reader
            .load_actor_state::<Value>(&format!("attachment/fetch/{OBJECT}"))?
            .ok_or("F6")?;
        assert!(state["attempts"].as_u64().is_some_and(|attempts| attempts >= 2));
        Ok(())
    }
}
async fn case(after_ack: bool) -> Case {
    let Rig { started, progress, hook, mut capture } =
        Box::pin(rig(if after_ack { Boundary::Ack } else { Boundary::Import })).await?;
    let first = fetch(&started);
    let held = tokio::time::timeout(Duration::from_secs(10), capture.recv())
        .await?
        .ok_or("fetch checkpoint not entered")?;
    progress.before_stop(&held, after_ack)?;
    controls(&started.actor).await?;
    let started = Box::pin(started.restart()).await?;
    assert!(first.await?.is_err());
    assert!(hook.first_job_finished(), "restart must join the previous fetch worker");
    assert!(!held.fetch_reply_is_open());
    drop(held);
    let second = fetch(&started);
    progress.available().await?;
    assert_eq!(second.await??.body["transfer_state"], "available");
    progress.completed(after_ack)?;
    started.actor.stop().await?;
    let root = started.root.clone();
    drop(started.actor);
    started.router.await?;
    drop(progress);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn erased_fetch_aborts_f3_authorization_before_any_relay_ack() -> Case {
    LocalSet::new().run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
        let Rig { started,progress,mut capture,.. }=Box::pin(rig(Boundary::Authorize)).await?;
        let first=fetch(&started);
        let held=tokio::time::timeout(Duration::from_secs(10),capture.recv()).await?.ok_or("F3 not entered")?;
        assert!(held.fetch_reply_is_open());
        assert!(progress.reader.load_object::<EncryptedObject>(OBJECT)?.is_some(),"F2 must already be durable");
        assert!(!progress.relay.state.lock().map_err(|_|"relay")?.requests.iter().any(|(step,_)|*step==Step::Ack));
        started.actor.request(command("message.delete",serde_json::json!({
            "conversation_id":"fetch-thread","message_id":"fetch-message","delete_scope":"own_devices",
            "tombstone_id":"erase-before-f3",
        }))).await?;
        assert!(progress.reader.check_object_access(OBJECT).is_err(),"erasure must precede F3 release");
        held.release().await?;
        let error=first.await?.err().ok_or("erased fetch was accepted")?;
        assert_eq!(crate::bus::io::local_bus_error_code(&error),"ObjectErased");
        assert!(!progress.relay.state.lock().map_err(|_|"relay")?.requests.iter().any(|(step,_)|*step==Step::Ack),"an erased object must never issue an ACK");
        assert!(progress.reader.check_object_access(OBJECT).is_err());
        started.actor.stop().await?;
        let root=started.root.clone();drop(started.actor);started.router.await?;drop(progress);
        std::fs::remove_dir_all(root)?;
        Ok(())
    })))).await
}

#[tokio::test(flavor = "current_thread")]
async fn failed_fetch_keeps_f1_progress_and_reports_the_fixed_transport_category() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let Rig { started, progress, .. } = Box::pin(rig(Boundary::Import)).await?;
            progress.relay.state.lock().map_err(|_| "relay")?.close_before_response =
                Some((Step::Get, 1));
            let response = fetch(&started).await??;
            assert_eq!(response.body["transfer_state"], "failed");
            assert_eq!(
                response.body["last_error"],
                "attachment transport failed; retry object.fetch"
            );
            let state = progress
                .reader
                .load_actor_state::<Value>(&format!("attachment/fetch/{OBJECT}"))?
                .ok_or("failed fetch receipt")?;
            assert_eq!(state["transfer_state"], "failed");
            assert_eq!(state["last_error"], "attachment transport failed; retry object.fetch");
            assert_eq!(
                progress
                    .reader
                    .object_transfer(OBJECT, Some(OBJECT_TRANSFER_DOWNLOAD))?
                    .ok_or("partial transfer")?
                    .completed_chunks,
                vec![0]
            );
            assert!(
                !progress
                    .relay
                    .state
                    .lock()
                    .map_err(|_| "relay")?
                    .requests
                    .iter()
                    .any(|(step, _)| *step == Step::Ack)
            );
            started.actor.stop().await?;
            let root = started.root.clone();
            drop(started.actor);
            started.router.await?;
            drop(progress);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))))
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_after_durable_f2_restarts_without_get_and_commits_its_slot_once() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            restart_imported(Boundary::Authorize),
        ))))
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_after_all_durable_f4_acks_restarts_at_f5_without_repeating_any_ack() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            restart_imported(Boundary::Slot),
        ))))
        .await
}
async fn restart_imported(boundary: Boundary) -> Case {
    let before_ack = matches!(&boundary, Boundary::Authorize);
    let Rig { started, progress, hook, mut capture } = Box::pin(rig(boundary)).await?;
    let conversation = crate::own_device_sync::own_device_sync_slot_conversation_id(
        "history-snapshot",
        OBJECT,
        "device-sender",
    );
    let checkpoint = crate::dm::dm_session_checkpoint_name(&conversation, "recv");
    let committed =
        crate::dm::dm_session_event_id(&conversation, "recv", &format!("object-slot:{OBJECT}"));
    let first = fetch(&started);
    let held = tokio::time::timeout(Duration::from_secs(10), capture.recv())
        .await?
        .ok_or("imported fetch checkpoint not entered")?;
    assert!(held.fetch_reply_is_open());
    assert!(progress.reader.load_object::<EncryptedObject>(OBJECT)?.is_some());
    assert_ne!(
        progress.reader.projection_checkpoint(&checkpoint)?,
        Some(committed.clone()),
        "F5 must still be held"
    );
    assert_eq!(
        progress
            .relay
            .state
            .lock()
            .map_err(|_| "relay")?
            .requests
            .iter()
            .filter(|(step, _)| *step == Step::Ack)
            .count(),
        if before_ack { 0 } else { usize::try_from(progress.total)? }
    );
    let started = Box::pin(started.restart()).await?;
    assert!(first.await?.is_err());
    assert!(hook.first_job_finished());
    assert!(!held.fetch_reply_is_open());
    drop(held);
    let second = fetch(&started);
    progress.available().await?;
    assert_eq!(second.await??.body["transfer_state"], "available");
    progress.completed(false)?;
    assert_eq!(progress.reader.projection_checkpoint(&checkpoint)?, Some(committed.clone()));
    let requests = progress.relay.state.lock().map_err(|_| "relay")?.requests.clone();
    assert_eq!(fetch(&started).await??.body["transfer_state"], "available");
    assert_eq!(progress.reader.projection_checkpoint(&checkpoint)?, Some(committed));
    assert_eq!(
        progress.relay.state.lock().map_err(|_| "relay")?.requests,
        requests,
        "available replay must have no relay effects"
    );
    started.actor.stop().await?;
    let root = started.root.clone();
    drop(started.actor);
    started.router.await?;
    drop(progress);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
