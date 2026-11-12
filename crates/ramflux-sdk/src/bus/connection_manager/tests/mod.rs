// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministic host-level fixtures keep every competing deadline outside the race.

use super::{
    ConnectionHandle, GatewaySessionConfig, GatewaySessionEngine, RuntimeTimeouts,
    SessionConnector, SessionFuture,
};
use crate::{GatewayClientFrame, GatewayQuicEndpointConfig, GatewayServerFrame, SdkError};
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

mod attempt;
mod ephemeral_host;
mod events;
mod host;
mod lifecycle;
#[cfg(feature = "itest-fingerprint")]
mod partial_frame;
mod resume;

pub(crate) struct SessionIo {
    pub input: mpsc::UnboundedSender<Vec<u8>>,
    pub output: mpsc::UnboundedReceiver<GatewayClientFrame>,
    /// The exact bytes of every client frame, as written.
    pub raw: mpsc::UnboundedReceiver<Vec<u8>>,
}
struct ScriptedStream {
    input: mpsc::UnboundedReceiver<Vec<u8>>,
    output: mpsc::UnboundedSender<GatewayClientFrame>,
    raw: mpsc::UnboundedSender<Vec<u8>>,
}

/// The raw bytes of the `envelope` member of a written `submit` frame (its last member).
pub(crate) fn submitted_envelope_bytes(frame: &[u8]) -> Option<&[u8]> {
    const KEY: &[u8] = b",\"envelope\":";
    let start = frame.windows(KEY.len()).rposition(|window| window == KEY)? + KEY.len();
    frame.strip_suffix(b"}}").map(|body| &body[start.min(body.len())..])
}
impl GatewaySessionFrameSink for ScriptedStream {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            let frame = serde_json::from_slice(bytes)?;
            let _ = self.raw.send(bytes.to_vec());
            self.output.send(frame).map_err(|_| TransportError::ShutdownDraining)
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for ScriptedStream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move { self.input.recv().await.ok_or(TransportError::ShutdownDraining) })
    }
}
struct Connector {
    sessions: mpsc::UnboundedSender<SessionIo>,
    frame: Duration,
}
impl SessionConnector for Connector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        let (input, receive) = mpsc::unbounded_channel();
        let (send, output) = mpsc::unbounded_channel();
        let (raw_send, raw) = mpsc::unbounded_channel();
        let mut engine = GatewaySessionEngine::with_test_transport(
            config,
            Box::new(ScriptedStream { input: receive, output: send, raw: raw_send }),
        );
        engine.frame_timeout = self.frame;
        let result = self
            .sessions
            .send(SessionIo { input, output, raw })
            .map(|()| engine)
            .map_err(|_| SdkError::GatewaySessionNotEstablished);
        Box::pin(std::future::ready(result))
    }
}
pub(crate) fn config() -> Result<GatewaySessionConfig, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("host-principal", [21; 32]);
    let branch = ramflux_crypto::create_device_branch("host-principal", "host-device", 1, [22; 32]);
    Ok(GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: "127.0.0.1:443".parse()?,
        server_name: "localhost".into(),
        ca_cert: "fixture.pem".into(),
        principal_id: "host-principal".into(),
        device_id: "host-device".into(),
        target_delivery_id: "host-target".into(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch)?)
}
fn limits() -> RuntimeTimeouts {
    let mut limits = RuntimeTimeouts::default();
    let held = Duration::from_secs(600);
    limits.network_wait = held;
    limits.attempt = held;
    limits.call = held;
    limits.receipt = held;
    limits.task_approval = held;
    limits.task_submit = held;
    limits.http = held;

    limits.command = held;
    limits.post_claim = held;
    limits.frame = held;
    limits.transport_open = held;
    limits.retry_budget = held;
    limits.receive_min = held;
    limits.receive_max = held;
    limits.sync = held;
    limits.fetch = held;
    limits.keepalive_idle = held;
    limits.keepalive_call = held;
    assert_eq!(limits.retry_budget, held, "the fixture must not introduce a competing retry timer");
    limits
}
pub(crate) async fn fixture() -> Result<(ConnectionHandle, SessionIo), Box<dyn std::error::Error>> {
    let (handle, mut receive) = reconnecting_fixture(limits())?;
    let io = receive.recv().await.ok_or("connector did not enter")?;
    handle.require_live(Duration::from_secs(600)).await?;
    Ok((handle, io))
}
struct NegotiatedEphemeralConnector(Connector);
impl SessionConnector for NegotiatedEphemeralConnector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            let mut engine = self.0.connect(config, deadline).await?;
            engine.ephemeral_negotiated = true;
            Ok(engine)
        })
    }
}

pub(crate) async fn ephemeral_fixture_for(
    config: GatewaySessionConfig,
) -> Result<(ConnectionHandle, SessionIo), Box<dyn std::error::Error>> {
    let limits = limits();
    let frame = limits.frame;
    let (sessions, mut receive) = mpsc::unbounded_channel();
    let handle = ConnectionHandle::start_with(
        config,
        None,
        limits,
        Arc::new(NegotiatedEphemeralConnector(Connector { sessions, frame })),
        None,
    );
    let io = receive.recv().await.ok_or("connector did not enter")?;
    handle.require_live(Duration::from_secs(600)).await?;
    Ok((handle, io))
}

pub(crate) fn reconnecting_fixture(
    limits: RuntimeTimeouts,
) -> Result<(ConnectionHandle, mpsc::UnboundedReceiver<SessionIo>), Box<dyn std::error::Error>> {
    let (sessions, receive) = mpsc::unbounded_channel();
    let frame = limits.frame;
    let handle = ConnectionHandle::start_with(
        config()?,
        None,
        limits,
        Arc::new(Connector { sessions, frame }),
        None,
    );
    Ok((handle, receive))
}

pub(crate) async fn wait_bulk_held(handle: &ConnectionHandle, held: usize) {
    for _ in 0..10_000 {
        if handle.places.available_permits() == super::CALL_QUEUE.saturating_sub(held) {
            return;
        }
        tokio::task::yield_now().await;
    }
    let actual = super::CALL_QUEUE.saturating_sub(handle.places.available_permits());
    assert_eq!(actual, held, "bulk places held {actual}, want {held}");
}

pub(crate) fn send(
    io: &SessionIo,
    frame: &GatewayServerFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    io.input.send(serde_json::to_vec(frame)?)?;
    Ok(())
}
pub(crate) fn entry(id: &str, sequence: u64) -> Result<crate::GatewayInboxEntry, SdkError> {
    Ok(serde_json::from_value(
        serde_json::json!({"inbox_seq":sequence,"target_delivery_id":"host-target","envelope":{"schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1","signing_key_id":"source-device","signature_alg":"ed25519","signature":"fixture","envelope_id":id,"source_principal_id":"source","source_device_id":"source-device","target_delivery_id":"host-target","delivery_class":"opaque_event","priority":"normal","ttl":600,"created_at":1,"encrypted_payload":"opaque","payload_hash":"opaque"}}),
    )?)
}

fn arm_watchdog(
    budget: Duration,
) -> (std::sync::mpsc::Sender<()>, tokio::sync::oneshot::Receiver<()>) {
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    let (expired, deadline) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        if matches!(cancelled.recv_timeout(budget), Err(std::sync::mpsc::RecvTimeoutError::Timeout))
        {
            let _ = expired.send(());
        }
    });
    (cancel, deadline)
}

pub(crate) async fn watchdog(
    future: impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cancel, deadline) = arm_watchdog(Duration::from_secs(30));
    let result = tokio::select! {
        result = future => result,
        _ = deadline => Err("30-second real-time test watchdog expired".into()),
    };
    drop(cancel);
    result
}

pub(crate) async fn watchdog_for(
    budget: Duration,
    future: impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cancel, deadline) = arm_watchdog(budget);
    let secs = budget.as_secs();
    let result = tokio::select! {
        result = future => result,
        _ = deadline => Err(format!("{secs}-second real-time test watchdog expired").into()),
    };
    drop(cancel);
    result
}

/// A pre-established scripted transport keeps actor deadline tests free of admission I/O.
pub(crate) fn seeded(
    config: GatewaySessionConfig,
    limits: RuntimeTimeouts,
) -> (ConnectionHandle, SessionIo) {
    let (engine, io) = seeded_engine(config.clone(), &limits);
    let (sessions, _unused) = mpsc::unbounded_channel();
    let frame = limits.frame;
    let handle = ConnectionHandle::start_with(
        config,
        Some(engine),
        limits,
        Arc::new(Connector { sessions, frame }),
        None,
    );
    (handle, io)
}

pub(crate) fn seeded_engine(
    config: GatewaySessionConfig,
    limits: &RuntimeTimeouts,
) -> (GatewaySessionEngine, SessionIo) {
    let (input, receive) = mpsc::unbounded_channel();
    let (send, output) = mpsc::unbounded_channel();
    let (raw_send, raw) = mpsc::unbounded_channel();
    let mut engine = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(ScriptedStream { input: receive, output: send, raw: raw_send }),
    );
    engine.frame_timeout = limits.frame;
    (engine, SessionIo { input, output, raw })
}
