// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Command-owned preparation counts real gateway Resume frames.
use super::*;
use crate::bus::connection_manager::tests::{seeded, send};
use crate::client::native_test_support::{Fixture, TestResult};
use crate::{GatewayClientFrame, GatewayServerFrame};
use serde_json::json;
use std::rc::Rc;
use tokio::sync::oneshot;

fn receive_command() -> AccountCommand {
    let (outbound, _) = tokio::sync::mpsc::channel(1);
    AccountCommand {
        admission: None,
        private: None,
        request: crate::LocalBusFrame::request(
            "receive",
            Some("sender".into()),
            "group",
            "group.receive",
            json!({"group_id":"group", "conversation_id":"thread", "limit":32}),
        ),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    }
}

async fn setup() -> TestResult<(AccountRuntime, FixtureGuard, Rc<Cell<usize>>)> {
    let native = Fixture::with_device("receive-preparation", "device").await?;
    let primary = native
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(native.vault.as_ref())?;
    native.client.shared_group_create_with_primary(
        "group",
        "thread",
        None,
        &native.config.target_delivery_id,
        Some(&primary),
    )?;
    let mut account = LocalBusAccountState::disconnected(
        native.client,
        native.config,
        native.manifest.principal_commitment,
    );
    let (handle, mut io) = seeded(account.gateway_config.clone(), account.timeouts.clone());
    handle.require_live(std::time::Duration::from_secs(1)).await?;
    account.connection = Some(handle.clone());
    let count = Rc::new(Cell::new(0));
    let observed = count.clone();
    let responder = tokio::task::spawn_local(async move {
        while let Some(frame) = io.output.recv().await {
            if matches!(frame, GatewayClientFrame::Resume { .. }) {
                observed.set(observed.get() + 1);
                if send(&io, &GatewayServerFrame::Resume { entries: vec![] }).is_err() {
                    break;
                }
            }
        }
    });
    let (runtime, _commands, stop, _observed) =
        super::super::tests::runtime(account, &native.root.0);
    Ok((runtime, FixtureGuard { _root: native.root, handle, responder, _stop: stop }, count))
}

struct FixtureGuard {
    _root: crate::custody::tests::Root,
    handle: crate::bus::connection_manager::ConnectionHandle,
    responder: tokio::task::JoinHandle<()>,
    _stop: tokio::sync::watch::Sender<bool>,
}
impl Drop for FixtureGuard {
    fn drop(&mut self) {
        self.responder.abort();
        self.handle.request_stop(crate::bus::connection_manager::DisconnectReason::Stop);
    }
}

async fn apply_receive(runtime: &mut AccountRuntime) -> TestResult {
    let mut command = receive_command();
    let (reply, result) = oneshot::channel();
    command.reply = Some(reply);
    assert!(!runtime.apply(command).await?);
    result.await??;
    Ok(())
}

#[tokio::test]
async fn successful_group_receive_resumes_gateway_once_per_command() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let (mut runtime, _guard, count) = setup().await?;
            apply_receive(&mut runtime).await?;
            let after_first = count.get();
            apply_receive(&mut runtime).await?;
            assert_eq!(
                count.get(),
                after_first,
                "activated group.receive must not bind standalone after the actor owns the ledger"
            );
            let account = runtime.state.accounts.get_mut("sender").ok_or("account")?;
            crate::bus::dispatch::group::dispatch_group_receive_request(
                &receive_command().request,
                account,
            )
            .await?;
            assert_eq!(
                count.get(),
                after_first,
                "direct dispatch on an activated ledger must not steal the actor bind"
            );
            runtime.close_readers().await;
            Ok(())
        }))
        .await
}

mod refreshed;
