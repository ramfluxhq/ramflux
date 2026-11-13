// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A dedicated current-thread runtime hosts the shared supervisor; FFI never executes business logic.

use super::state::{MAX_OPERATIONS, Operation, Shared};
use super::{RamfluxV2Status, failure};
use crate::{LocalBusConfig, LocalBusFrame, LocalBusFrameKind, SdkError};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

pub(super) struct Command {
    pub id: u64,
    pub bytes: Zeroizing<Vec<u8>>,
    pub operation: Arc<Operation>,
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
        match ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(result) => result?,
            Err(_) => {
                let _ = shutdown.send(true);
                return Err(SdkError::LocalBus("supervisor startup timed out".into()));
            }
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
    mut commands: mpsc::Receiver<Command>,
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
    let (mut reader, mut writer) = tokio::io::split(client_stream);
    let write_shared = Arc::clone(&shared);
    let mut writer_shutdown = shutdown.clone();
    let write_task = tokio::task::spawn_local(async move {
        loop {
            let command = tokio::select! {
                _ = writer_shutdown.changed() => break,
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
                } else {
                    state.admitted = true;
                    false
                }
            };
            if cancelled {
                write_shared.complete(
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
                    write_shared.failed(command.id, &error);
                    return Err(error);
                }
                Err(_) => return Err(SdkError::LocalBus("carrier write timed out".into())),
            }
        }
        Ok::<_, SdkError>(())
    });
    let mut reader_shutdown = shutdown;
    let read_result = loop {
        let frame: LocalBusFrame = tokio::select! {
            _ = reader_shutdown.changed() => break Ok(()),
            result = crate::bus::io::read_local_bus_frame(&mut reader) => match result {
                Ok(frame) => frame, Err(error) => break Err(error),
            },
        };
        match frame.kind {
            LocalBusFrameKind::Response | LocalBusFrameKind::Error => {
                if let Ok(id) = frame.request_id.parse::<u64>() {
                    let code =
                        frame.error.as_ref().map_or(0, |error| super::error_code(&error.code));
                    shared.complete(id, serde_json::json!({"code":code,"response":frame}));
                }
            }
            _ => match serde_json::to_vec(&frame) {
                Ok(bytes) => shared.push_event(bytes),
                Err(error) => break Err(SdkError::from(error)),
            },
        }
    };
    let _ = stop.send(true);
    write_task.abort();
    let _ = write_task.await;
    let stopped = server.await.map_err(|e| SdkError::LocalBus(e.to_string()))?;
    stopped.and(read_result)
}
