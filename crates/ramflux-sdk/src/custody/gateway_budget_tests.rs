// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Standalone engine deadlines are isolated from manager and shorter admission/frame timers.

use super::Fixture;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
use crate::gateway::transport_opener::{ConfiguredTransport, OpenFuture, TransportOpener};
use crate::{GatewaySessionConfig, GatewaySessionEngine, GatewaySessionTransportKind, SdkError};
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource,
    GatewaySessionTransport, TransportError,
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

#[derive(Default)]
struct Observation {
    entered: Arc<tokio::sync::Notify>,
    dropped: AtomicBool,
}
struct ObservedStream {
    stream: Box<dyn GatewaySessionTransport + Send>,
    observed: Arc<Observation>,
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        self.observed.dropped.store(true, Ordering::Release);
    }
}
impl GatewaySessionFrameSink for ObservedStream {
    fn verify_custody_certificate_pin(
        &self,
        expected: &str,
    ) -> std::result::Result<(), TransportError> {
        self.stream.verify_custody_certificate_pin(expected)
    }
    fn custody_exporter(&self, nonce: &[u8; 32]) -> std::result::Result<[u8; 32], TransportError> {
        self.stream.custody_exporter(nonce)
    }
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        self.stream.send_frame(frame)
    }
    fn finish(&mut self) -> std::result::Result<(), TransportError> {
        self.stream.finish()
    }
}
impl GatewaySessionFrameSource for ObservedStream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.stream.recv_frame()
    }
    fn recv_idle_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.stream.recv_idle_frame()
    }
    fn recv_idle_custody_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.stream.recv_idle_custody_frame()
    }
    fn recv_custody_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.stream.recv_custody_frame()
    }
}
struct ObservedOpener(Arc<Observation>);
impl TransportOpener for ObservedOpener {
    fn open(&self, config: GatewaySessionConfig, timeout: Duration) -> OpenFuture<'_> {
        let observed = Arc::clone(&self.0);
        Box::pin(async move {
            let (transport, stream, kind) = ConfiguredTransport.open(config, timeout).await?;
            Ok((
                transport,
                Box::new(ObservedStream { stream, observed })
                    as Box<dyn GatewaySessionTransport + Send>,
                kind,
            ))
        })
    }
}
#[derive(Clone, Copy)]
pub(super) enum Origin {
    PublicClient,
    ExplicitEngine,
    FrameProduction,
    FrameIsolated,
    Manager,
    ManagerFrame,
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn standalone_native_client_derives_its_own_120_second_deadline() -> Result {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            native_case(Origin::PublicClient),
        ))))
        .await
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn engine_helper_enforces_an_explicit_120_second_deadline_without_a_manager() -> Result {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            native_case(Origin::ExplicitEngine),
        ))))
        .await
}
pub(super) async fn native_config(
    fixture: &Fixture,
    origin: Origin,
) -> Result<(crate::RamfluxClient, GatewaySessionConfig)> {
    let network = &fixture.config;
    let account = crate::custody::load_account(
        &network.account_root,
        &network.account_id,
        crate::custody::network_now()?,
    )?;
    let anchor = account.record().body.account_anchor.clone();
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(&network.account_root)?;
    client.seal_new_account_data(&network.account_id, &anchor, b"native budget fixture")?;
    client.unlock_account(&network.account_id, b"native budget fixture")?;
    client.initialize_born_v3_branch("primary", fixture.vault.clone()).await?;
    let endpoint = crate::GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: network.gateway_address,
        server_name: network.server_name.clone(),
        ca_cert: network.ca_certificate.clone(),
        principal_id: account.record().body.principal_id.clone(),
        device_id: "primary".into(),
        target_delivery_id: ramflux_protocol::qualified_device_id(&anchor, "primary")?,
        prekey_http_url: None,
    };
    let mut config = GatewaySessionConfig::auto(endpoint)
        .with_native_custody(crate::GatewayCustodyConfig {
            account_root: network.account_root.clone(),
            account_id: network.account_id.clone(),
            node_id: network.node_id.clone(),
            node_public_key: network.node_public_key.clone(),
            vault: fixture.vault.clone(),
        })
        .with_account_identity(&client)?;
    config.tcp_gateway_addr = Some(network.gateway_address);
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.timeout = if matches!(origin, Origin::FrameProduction | Origin::ManagerFrame) {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(600)
    };
    config.quic_fallback_timeout = Duration::from_secs(600);
    Ok((client, config))
}
fn assert_deadline_error(origin: Origin, error: SdkError) {
    if matches!(origin, Origin::FrameIsolated) {
        assert!(
            matches!(error,SdkError::GatewaySessionRejected(reason) if reason.contains("gateway session established timed out after 15s"))
        );
    } else if matches!(origin, Origin::FrameProduction) {
        assert!(
            matches!(&error, SdkError::GatewaySessionRejected(_))
                || matches!(&error,SdkError::Transport(TransportError::Io(reason)) if reason.kind()==std::io::ErrorKind::TimedOut),
            "{error}"
        );
    } else {
        assert!(
            matches!(error, SdkError::NodeTimeout { .. }),
            "native attempt did not use its enclosing deadline"
        );
    }
}
async fn native_case(origin: Origin) -> Result {
    let clock = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let fixture = Box::pin(Fixture::with_mode(&[], true))
        .await
        .map_err(|error| error as Box<dyn std::error::Error>)?;
    let (client, config) = native_config(&fixture, origin).await?;
    let mut limits = if matches!(origin, Origin::FrameProduction | Origin::ManagerFrame) {
        crate::bus::runtime_limits::RuntimeTimeouts::default()
    } else {
        crate::bus::runtime_limits::RuntimeTimeouts::held_for_test()
    };
    let expected =
        if matches!(origin, Origin::FrameProduction | Origin::FrameIsolated | Origin::ManagerFrame)
        {
            limits.frame = Duration::from_secs(15);
            Duration::from_secs(15)
        } else {
            Duration::from_secs(120)
        };
    let observed = Arc::new(Observation::default());
    fixture.script.lock().map_err(|_| "script lock")?.hold_established =
        Some(Arc::clone(&observed.entered));
    let opener: Arc<dyn TransportOpener> = Arc::new(ObservedOpener(Arc::clone(&observed)));
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(120);
    let manager = if matches!(origin, Origin::Manager | Origin::ManagerFrame) {
        let mut limits = limits.clone();
        limits.attempt = Duration::from_secs(120);
        Some(crate::bus::connection_manager::ConnectionHandle::start_with(
            config.clone(),
            None,
            limits.clone(),
            Arc::new(EngineConnector { limits, opener: Arc::clone(&opener) }),
            None,
        ))
    } else {
        None
    };
    let mut connect: Pin<
        Box<dyn Future<Output = std::result::Result<GatewaySessionEngine, SdkError>> + '_>,
    > = match origin {
        Origin::Manager | Origin::ManagerFrame => {
            let handle = manager.as_ref().ok_or("manager")?;
            Box::pin(async move {
                while handle.snapshot().phase
                    != crate::bus::connection_manager::ConnectionPhase::Backoff
                {
                    tokio::task::yield_now().await;
                }
                Err(SdkError::NodeTimeout { retry_after_ms: crate::node::NODE_RETRY_AFTER_MS })
            })
        }
        Origin::PublicClient => Box::pin(
            crate::gateway::engine::TEST_CONNECT_LIMITS.scope(
                limits,
                crate::gateway::engine::TEST_CONNECT_OPENER
                    .scope(opener, client.connect_gateway_session(config)),
            ),
        ),
        Origin::ExplicitEngine | Origin::FrameProduction | Origin::FrameIsolated => Box::pin(
            GatewaySessionEngine::connect_with_opener(config, Some(deadline), limits, opener),
        ),
    };
    tokio::select! {
        ()=observed.entered.notified()=>{},
        result=&mut connect=>return Err(format!("native connect ended before its held frame: {:?}",result.err()).into()),
    }
    tokio::time::advance(
        expected.checked_sub(Duration::from_secs(1)).ok_or("invalid fixture deadline")?,
    )
    .await;
    assert!(
        std::future::poll_fn(|context| Poll::Ready(connect.as_mut().poll(context).is_pending()))
            .await
    );
    assert!(!observed.dropped.load(Ordering::Acquire));
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = connect.await;
    let error = result.err().ok_or("held establishment unexpectedly succeeded")?;
    assert_deadline_error(origin, error);
    if let Some(manager) = &manager {
        assert_eq!(
            manager.snapshot().phase,
            crate::bus::connection_manager::ConnectionPhase::Backoff
        );
        assert!(manager.snapshot().next_retry_at_ms.is_some());
        assert!(manager.metadata().is_none());
        manager.stop().await;
    }
    assert_eq!(start.elapsed(), expected);
    assert!(observed.dropped.load(Ordering::Acquire));
    assert_released_lease(&fixture.config.account_root, &fixture.config.account_id)?;
    clock.abort();
    fixture.server.abort();
    Ok(())
}

fn assert_released_lease(root: &std::path::Path, account: &str) -> Result {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("custody_accounts").join(account).join(".network.lock"))?;
    fs2::FileExt::try_lock_exclusive(&file)?;
    fs2::FileExt::unlock(&file)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn held_native_establishment_fails_at_the_production_fifteen_second_bound() -> Result {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            native_case(Origin::FrameProduction),
        ))))
        .await
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn establishment_wrapper_has_its_own_fifteen_second_bound_with_other_timers_held() -> Result {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            native_case(Origin::FrameIsolated),
        ))))
        .await
}

struct EngineConnector {
    limits: crate::bus::runtime_limits::RuntimeTimeouts,
    opener: Arc<dyn TransportOpener>,
}
impl crate::bus::connection_manager::SessionConnector for EngineConnector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: tokio::time::Instant,
    ) -> crate::bus::connection_manager::SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(GatewaySessionEngine::connect_with_opener(
            config,
            Some(deadline),
            self.limits.clone(),
            Arc::clone(&self.opener),
        ))
    }
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn manager_and_engine_compose_to_the_same_120_second_deadline() -> Result {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            native_case(Origin::Manager),
        ))))
        .await
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn production_native_establishment_timeout_moves_the_manager_to_backoff() -> Result {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            native_case(Origin::ManagerFrame),
        ))))
        .await
}
