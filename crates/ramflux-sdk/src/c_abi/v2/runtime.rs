// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A dedicated current-thread runtime hosts the shared supervisor; FFI never executes business logic.

use super::state::{MAX_OPERATIONS, Operation, Shared};
use super::{RamfluxV2Status, failure};
use crate::{LocalBusConfig, SdkError};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

pub(super) struct Command {
    pub id: u64,
    pub bytes: Zeroizing<Vec<u8>>,
    pub operation: Arc<Operation>,
    pub deadline_ms: Option<u64>,
}

pub(super) struct Client {
    pub commands: mpsc::Sender<Command>,
    pub shared: Arc<Shared>,
    shutdown: watch::Sender<bool>,
    done: Mutex<std::sync::mpsc::Receiver<Result<(), SdkError>>>,
}

impl Client {
    pub fn start(config: LocalBusConfig) -> Result<Arc<Self>, SdkError> {
        let (commands, receiver) = mpsc::channel(MAX_OPERATIONS);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (ready, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done) = std::sync::mpsc::sync_channel(1);
        let shared = Arc::new(Shared::default());
        let worker_shared = Arc::clone(&shared);
        let worker_shutdown = shutdown.clone();
        std::thread::Builder::new().name("ramflux-c-abi-v2".into()).spawn(move || {
            let result = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                tokio::task::LocalSet::new().block_on(&runtime, async {
                    run(
                        config,
                        receiver,
                        shutdown_rx,
                        worker_shutdown,
                        ready,
                        Arc::clone(&worker_shared),
                    )
                    .await
                })
            })();
            worker_shared.close();
            let _ = done_tx.send(result);
        })?;
        if let Ok(result) = ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
            result?;
        } else {
            let _ = shutdown.send(true);
            return Err(SdkError::LocalBus("supervisor startup timed out".into()));
        }
        Ok(Arc::new(Self { commands, shared, shutdown, done: Mutex::new(done) }))
    }

    pub fn close(&self) -> Result<(), SdkError> {
        let _ = self.shutdown.send(true);
        self.done
            .lock()
            .map_err(|_| SdkError::LocalBus("close lock poisoned".into()))?
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| SdkError::LocalBus("supervisor close timed out".into()))?
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn run(
    config: LocalBusConfig,
    commands: mpsc::Receiver<Command>,
    shutdown: watch::Receiver<bool>,
    stop: watch::Sender<bool>,
    ready: std::sync::mpsc::SyncSender<Result<(), SdkError>>,
    shared: Arc<Shared>,
) -> Result<(), SdkError> {
    // Bounded byte carrier; framing, custody ceremonies and response ordering are shared.
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (server_ready, initialized) = oneshot::channel();
    let server = tokio::task::spawn_local(crate::bus::inprocess::serve(
        config,
        server_stream,
        shutdown.clone(),
        server_ready,
    ));
    let result = initialized.await.map_err(|_| SdkError::LocalBus("startup failed".into()))?;
    let started = result.is_ok();
    let _ = ready.send(result);
    if !started {
        return server.await.map_err(|e| SdkError::LocalBus(e.to_string()))?;
    }
    let (reader, writer) = tokio::io::split(client_stream);
    let write_shared = Arc::clone(&shared);
    let writer_shutdown = shutdown.clone();
    let write_task = tokio::task::spawn_local(async move {
        write_commands(commands, writer, writer_shutdown, &write_shared).await
    });
    let read_result = read_responses(reader, shutdown, &shared).await;
    let _ = stop.send(true);
    write_task.abort();
    let _ = write_task.await;
    let stopped = server.await.map_err(|e| SdkError::LocalBus(e.to_string()))?;
    stopped.and(read_result)
}

async fn write_commands(
    mut commands: mpsc::Receiver<Command>,
    mut writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    mut shutdown: watch::Receiver<bool>,
    shared: &Shared,
) -> Result<(), SdkError> {
    loop {
        let command = tokio::select! {
            _ = shutdown.changed() => break,
            command = commands.recv() => match command { Some(command) => command, None => break },
        };
        let cancelled = {
            let mut state = command
                .operation
                .state
                .lock()
                .map_err(|_| SdkError::LocalBus("operation lock poisoned".into()))?;
            if state.cancelled {
                true
            } else if command
                .deadline_ms
                .is_some_and(|deadline| u128::from(deadline) <= super::super::current_millis())
            {
                drop(state);
                shared.complete(command.id, serde_json::json!({
                        "code":10,"message":"request deadline exceeded before admission","effects":"none"
                    }));
                continue;
            } else {
                state.admitted = true;
                false
            }
        };
        if cancelled {
            shared.complete(
                command.id,
                failure(RamfluxV2Status::Cancelled, "cancelled before admission", "none"),
            );
            continue;
        }
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::bus::io::write_encoded_local_bus_frame(&mut writer, &command.bytes),
        )
        .await;
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                shared.failed(command.id, &error);
                return Err(error);
            }
            Err(_) => return Err(SdkError::LocalBus("carrier write timed out".into())),
        }
    }
    Ok(())
}

async fn read_responses(
    mut reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut shutdown: watch::Receiver<bool>,
    shared: &Shared,
) -> Result<(), SdkError> {
    loop {
        let bytes = tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            result = crate::bus::io::read_encoded_local_bus_frame(&mut reader) => match result {
                Ok(bytes) => bytes, Err(error) => break Err(error),
            },
        };
        // The authenticated in-process server emits both ordinary bus and compatibility
        // custody envelopes. Preserve either representation, including unknown business data.
        let mut frame: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(frame) => frame,
            Err(error) => break Err(SdkError::from(error)),
        };
        let legacy = frame.get("protocol").and_then(serde_json::Value::as_str)
            == Some("ramflux.local_bus.custody.v1");
        let kind = frame.get("kind").and_then(serde_json::Value::as_str);
        if legacy || matches!(kind, Some("response" | "error")) {
            if let Some(id) = frame
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| id.parse::<u64>().ok())
            {
                let error = if legacy {
                    frame.get("result").and_then(|v| v.get("code"))
                } else {
                    frame.get("error").and_then(|v| v.get("code"))
                };
                let failed = kind == Some("error")
                    || (legacy
                        && frame
                            .get("result")
                            .and_then(|v| v.get("state"))
                            .and_then(serde_json::Value::as_str)
                            == Some("error"));
                let code = error
                    .and_then(serde_json::Value::as_str)
                    .map_or(if failed { 16 } else { 0 }, super::error_code);
                shared.complete(id, serde_json::json!({"code":code,"response":frame}));
            }
        } else {
            shared.push_event(bytes.to_vec());
        }
        crate::bus::inprocess::erase_value(&mut frame);
    }
}
