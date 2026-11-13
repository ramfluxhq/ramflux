// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A dedicated current-thread runtime hosts the shared supervisor; FFI never executes business logic.

use super::state::{MAX_OPERATIONS, Operation, Shared};
use super::{RamfluxV2Status, failure};
use crate::{LocalBusConfig, SdkError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
    done: Mutex<CloseCompletion>,
    close_wait: Duration,
    pub closing: AtomicBool,
    pub data_root: std::path::PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CloseResult {
    Done,
    TimedOut,
    Pending,
}

struct CloseCompletion {
    receiver: std::sync::mpsc::Receiver<Result<(), SdkError>>,
    terminal: Option<Result<(), Arc<SdkError>>>,
}

impl CloseCompletion {
    fn wait(&mut self, first: bool, deadline: Duration) -> Result<CloseResult, Arc<SdkError>> {
        if let Some(terminal) = &self.terminal {
            return terminal.as_ref().map(|()| CloseResult::Done).map_err(Arc::clone);
        }
        let received = if first {
            self.receiver.recv_timeout(deadline)
        } else {
            self.receiver.try_recv().map_err(|error| match error {
                std::sync::mpsc::TryRecvError::Empty => std::sync::mpsc::RecvTimeoutError::Timeout,
                std::sync::mpsc::TryRecvError::Disconnected => {
                    std::sync::mpsc::RecvTimeoutError::Disconnected
                }
            })
        };
        match received {
            Ok(result) => self.terminal = Some(result.map_err(Arc::new)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Ok(if first { CloseResult::TimedOut } else { CloseResult::Pending });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.terminal = Some(Err(Arc::new(SdkError::LocalBus(
                    "supervisor exited without shutdown completion".into(),
                ))));
            }
        }
        self.terminal
            .as_ref()
            .ok_or_else(|| Arc::new(SdkError::LocalBus("shutdown completion missing".into())))?
            .as_ref()
            .map(|()| CloseResult::Done)
            .map_err(Arc::clone)
    }
}

#[cfg(test)]
pub(super) use crate::bus::inprocess::ShutdownGate;

struct Worker {
    config: LocalBusConfig,
    commands: mpsc::Receiver<Command>,
    shutdown: watch::Receiver<bool>,
    stop: watch::Sender<bool>,
    ready: std::sync::mpsc::SyncSender<Result<(), SdkError>>,
    shared: Arc<Shared>,
    #[cfg(test)]
    gate: Option<ShutdownGate>,
}

impl Client {
    pub fn start(config: LocalBusConfig) -> Result<Arc<Self>, SdkError> {
        Self::start_inner(
            config,
            Duration::from_secs(10),
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    pub fn start_delayed(
        config: LocalBusConfig,
        gate: ShutdownGate,
    ) -> Result<Arc<Self>, SdkError> {
        Self::start_inner(config, Duration::ZERO, Some(gate))
    }

    fn start_inner(
        config: LocalBusConfig,
        close_wait: Duration,
        #[cfg(test)] gate: Option<ShutdownGate>,
    ) -> Result<Arc<Self>, SdkError> {
        let data_root = config.data_root.clone();
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
                    run(Worker {
                        config,
                        commands: receiver,
                        shutdown: shutdown_rx,
                        stop: worker_shutdown,
                        ready,
                        shared: Arc::clone(&worker_shared),
                        #[cfg(test)]
                        gate,
                    })
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
        let data_root = match std::fs::canonicalize(data_root) {
            Ok(root) => root,
            Err(error) => {
                let _ = shutdown.send(true);
                return Err(error.into());
            }
        };
        Ok(Arc::new(Self {
            data_root,
            commands,
            shared,
            shutdown,
            done: Mutex::new(CloseCompletion { receiver: done, terminal: None }),
            close_wait,
            closing: AtomicBool::new(false),
        }))
    }

    pub fn close(&self) -> Result<CloseResult, Arc<SdkError>> {
        let first = !self.closing.swap(true, Ordering::AcqRel);
        let _ = self.shutdown.send(true);
        self.done
            .lock()
            .map_err(|_| Arc::new(SdkError::LocalBus("close lock poisoned".into())))?
            .wait(first, self.close_wait)
    }

    pub fn shutdown_confirmed(&self) -> Result<bool, SdkError> {
        self.done
            .lock()
            .map(|state| state.terminal.is_some())
            .map_err(|_| SdkError::LocalBus("close lock poisoned".into()))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn run(worker: Worker) -> Result<(), SdkError> {
    let Worker {
        config,
        commands,
        shutdown,
        stop,
        ready,
        shared,
        #[cfg(test)]
        gate,
    } = worker;
    // Bounded byte carrier; framing, custody ceremonies and response ordering are shared.
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (server_ready, initialized) = oneshot::channel();
    let server_shutdown = shutdown.clone();
    let server = tokio::task::spawn_local(crate::bus::inprocess::serve(
        config,
        server_stream,
        server_shutdown,
        server_ready,
        #[cfg(test)]
        gate,
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
                Ok(bytes) => bytes,
                Err(_) if *shutdown.borrow() => break Ok(()),
                Err(error) => break Err(error),
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
        let mut stop_requested = false;
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
                stop_requested = code == 0
                    && frame.get("method").and_then(serde_json::Value::as_str)
                        == Some("daemon.stop");
                shared.complete(id, serde_json::json!({"code":code,"response":frame}));
            }
        } else {
            shared.push_event(bytes.to_vec());
        }
        crate::bus::inprocess::erase_value(&mut frame);
        if stop_requested {
            break Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_failure_is_cached_for_every_retry() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send(Err(SdkError::DataRootInUse)).expect("test: terminal failure");
        let mut completion = CloseCompletion { receiver, terminal: None };
        let first = completion.wait(true, Duration::ZERO).expect_err("test: real failure expected");
        let retry =
            completion.wait(false, Duration::ZERO).expect_err("test: failure must remain failed");
        assert!(Arc::ptr_eq(&first, &retry), "retries must reuse the retained terminal error");
    }
}
