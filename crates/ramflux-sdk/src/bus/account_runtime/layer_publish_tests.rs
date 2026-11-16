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

/// A live primary with a real connection handle bound to a real runtime.
async fn harness(
    id: &str,
) -> TestResult<(
    AccountRuntime,
    crate::bus::connection_manager::ConnectionHandle,
    crate::bus::connection_manager::tests::SessionIo,
    crate::custody::tests::Root,
)> {
    let mut fixture = Fixture::new(id).await?;
    let now = crate::custody::network_now()?;
    let account_id = fixture.client.account_db()?.local_account_id.clone();
    crate::custody::tests::mark_live(&fixture.root.0, &account_id, now)?;
    fixture.client.initialize_born_v3_branch("primary", fixture.vault.clone()).await?;
    let anchor = fixture.manifest.principal_commitment.clone();
    let Fixture { client, config, root, .. } = fixture;
    let mut account = LocalBusAccountState::disconnected(client, config, anchor);
    let (handle, io) = fixture_connection().await?;
    account.connection = Some(handle.clone());
    let (runtime, _commands, _stop, _observed) = super::tests::runtime(account, &root.0);
    Ok((runtime, handle, io, root))
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
            work = runtime.connection_work.recv() => {
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
            work = runtime.connection_work.recv() => {
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
    within(async {
        let (mut runtime, handle, _io, _root) = harness("layer-real-actor").await?;
        let writer = Writer::new(runtime.connection_sender.clone(), handle.generation());
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
        serve_until(&mut runtime, &started).await?;
        assert_eq!(
            head_state(&runtime)?,
            Some(("layer_update".into(), "submitted".into())),
            "the candidate must be durable and submitted before Publish starts"
        );
        // A floor send needs the actor: its layer gate runs through the real writer path while
        // the Publish is held. A blocked actor would hang here until the watchdog fails the test.
        let floor = {
            let writer = writer.clone();
            tokio::spawn(async move {
                writer
                    .apply(|account| {
                        let local = account.client.owned_device_identity()?;
                        assert!(!local.device_id().is_empty(), "floor send needs the local device");
                        Ok(())
                    })
                    .await
            })
        };
        serve(&mut runtime, floor).await??;
        // The session is replaced while Publish is held: the late Apply must be dropped.
        let (replacement, _replacement_io) = fixture_connection().await?;
        runtime
            .state
            .accounts
            .get_mut("sender")
            .ok_or("test: account")?
            .connection
            .replace(replacement.clone());
        release.notify_one();
        let late = serve(&mut runtime, held).await?;
        assert!(late.is_err(), "an Apply carrying the old generation must be refused: {late:?}");
        assert!(!declared(&runtime), "a stale-session Apply must install nothing");
        assert_eq!(
            head_state(&runtime)?,
            Some(("layer_update".into(), "submitted".into())),
            "the submitted row must survive for recovery"
        );
        // The new session resumes the very same candidate and completes it.
        let new_writer = Writer::new(runtime.connection_sender.clone(), replacement.generation());
        let resumed = tokio::spawn(async move {
            pass_with(new_writer, |input| async move {
                Ok(ramflux_protocol::custody::object_hash(&input.publication().record)?)
            })
            .await
        });
        assert!(serve(&mut runtime, resumed).await??, "the new session must complete it");
        assert!(declared(&runtime), "the resumed candidate must be installed");
        assert_eq!(head_state(&runtime)?, None, "the journal row must be retired");
        handle.stop().await;
        replacement.stop().await;
        Ok(())
    })
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
    within(async {
        let (mut runtime, handle, _io, _root) = harness("layer-real-stop").await?;
        let sender = runtime.connection_sender.clone();
        let context = handle.test_context();
        let child = tokio::spawn(crate::bus::couriers::runner::run(
            context,
            sender.clone(),
            "layer-publish",
            held_pass,
        ));
        serve_until(&mut runtime, &STARTED).await?;
        // Stop is the same cancellation that Lock and teardown deliver to every session child.
        handle.stop().await;
        serve(&mut runtime, child).await?;
        assert_eq!(
            head_state(&runtime)?,
            Some(("layer_update".into(), "submitted".into())),
            "cancellation must keep the submitted row"
        );
        // No signing or authority lock survived the cancelled await: both are available now.
        let account = runtime.state.accounts.get_mut("sender").ok_or("test: account")?;
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
    })
    .await
}
