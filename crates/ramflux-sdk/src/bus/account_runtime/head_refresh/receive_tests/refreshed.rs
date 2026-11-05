// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refresh-after-sync admission and reply cancellation through the real actor.
use super::*;
use crate::bus::dispatch::surface_transport::fixture::RecordingGateway;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

type Frame<'a, T> = ramflux_transport::GatewaySessionFrameFuture<'a, T>;
struct CountedGateway {
    gateway: RecordingGateway,
    resumes: Arc<AtomicUsize>,
}
impl GatewaySessionFrameSink for CountedGateway {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> Frame<'a, ()> {
        if matches!(serde_json::from_slice(bytes), Ok(GatewayClientFrame::Resume { .. })) {
            self.resumes.fetch_add(1, Ordering::SeqCst);
        }
        self.gateway.send_frame(bytes)
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        self.gateway.finish()
    }
}
impl GatewaySessionFrameSource for CountedGateway {
    fn recv_frame(&mut self) -> Frame<'_, Vec<u8>> {
        self.gateway.recv_frame()
    }
    fn recv_idle_frame(&mut self) -> Frame<'_, Vec<u8>> {
        self.gateway.recv_idle_frame()
    }
}

struct Case {
    runtime: AccountRuntime,
    _alice: crate::custody::tests::Root,
    bob: Fixture,
    resumes: Arc<AtomicUsize>,
    refresh: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
    _stop: tokio::sync::watch::Sender<bool>,
}
impl Drop for Case {
    fn drop(&mut self) {
        self.refresh.abort();
        self.server.abort();
    }
}
async fn setup_refreshed() -> TestResult<Case> {
    let (alice, bob, entry) =
        crate::bus::dispatch::group::native_contract_tests::renamed_group_fixture().await?;
    let (address, server) = crate::bus::dispatch::surface_transport::fixture::directory(
        &alice.root.0,
        std::collections::BTreeMap::from([(
            alice.manifest.principal_commitment.clone(),
            serde_json::to_value(&alice.manifest)?,
        )]),
    )
    .await?;
    *alice.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    alice.client.persist_fetched_identity_directory(&bob.manifest)?;
    let mut config = alice.config;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = alice.root.0.join("ca.pem");
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        config.clone(),
        alice.manifest.principal_commitment,
    );
    let resumes = Arc::new(AtomicUsize::new(0));
    let mut gateway = RecordingGateway::new(Arc::default());
    gateway.ack_target.clone_from(&config.target_delivery_id);
    gateway.inbox = vec![entry];
    account.install_test_session(crate::GatewaySessionEngine::with_test_transport(
        config,
        Box::new(CountedGateway { gateway, resumes: resumes.clone() }),
    ));
    account.ensure_gateway_live().await?;
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    let (runtime, _commands, stop, _observed) =
        super::super::super::tests::runtime(account, &alice.root.0);
    let refresh = tokio::spawn(crate::bus::couriers::head_refresh::run_without_timer(
        handle.test_context(),
        runtime.connection_sender.clone(),
    ));
    Ok(Case { runtime, _alice: alice.root, bob, resumes, refresh, server, _stop: stop })
}
async fn receive(runtime: &mut AccountRuntime) -> TestResult<crate::bus::actor::ActorResponse> {
    let mut command = receive_command();
    let (reply, result) = oneshot::channel();
    command.reply = Some(reply);
    runtime.apply(command).await?;
    Ok(result.await??)
}
fn assert_message(response: &crate::bus::actor::ActorResponse) {
    assert_eq!(
        response.body["decrypted_messages"][0]["body_utf8"], "after rename",
        "receive must return the message whose refresh it waited for"
    );
    assert_eq!(response.body["messages"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn receive_applies_message_refreshed_inside_its_command() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let mut case = Box::pin(setup_refreshed()).await?;
            let response = receive(&mut case.runtime).await?;
            assert_message(&response);
            assert_eq!(
                case.resumes.load(Ordering::SeqCst),
                2,
                "refresh wait requires dispatch replay"
            );
            case.runtime.close_readers().await;
            case.runtime.stop_connection().await;
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn cancelled_apply_cannot_prepare_retry_that_waits_for_refresh() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let mut case = Box::pin(setup_refreshed()).await?;
            let (entered, ready) = oneshot::channel();
            let (_release, held) = oneshot::channel();
            case.runtime.receive_gate_hook = Some((entered, held));
            let mut command = receive_command();
            let (reply, result) = oneshot::channel();
            command.reply = Some(reply);
            {
                let apply = case.runtime.apply(command);
                tokio::pin!(apply);
                tokio::select! {
                    result = &mut apply => {
                        return Err(format!(
                            "apply returned before cancellation: {result:?}"
                        ).into());
                    }
                    ready = ready => {
                        ready?;
                    }
                }
                drop(result); // The production apply select observes reply.closed().
                assert!(!apply.await?);
            }
            assert_eq!(case.resumes.load(Ordering::SeqCst), 1);
            let account = case.runtime.state.accounts.get_mut("sender").ok_or("account")?;
            assert!(
                account.client.direct_messages("thread")?.is_empty(),
                "cancelled dispatch must not apply the ready message"
            );
            *account.client.native_head_freshness.borrow_mut() =
                crate::client::identity_authority::NativeHeadFreshness::default();
            account.client.persist_fetched_identity_directory(&case.bob.manifest)?;
            let before = case.resumes.load(Ordering::SeqCst);
            let response = receive(&mut case.runtime).await?;
            assert_message(&response);
            assert_eq!(
                case.resumes.load(Ordering::SeqCst) - before,
                2,
                "retry must sync before and after its own refresh wait"
            );
            case.runtime.close_readers().await;
            case.runtime.stop_connection().await;
            Ok(())
        }))
        .await
}
