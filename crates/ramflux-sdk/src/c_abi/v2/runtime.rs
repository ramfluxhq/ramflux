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
    pub method: String,
    pub account_id: Option<String>,
}

impl Command {
    pub(super) fn carrier(
        id: u64,
        bytes: Zeroizing<Vec<u8>>,
        operation: Arc<Operation>,
        deadline_ms: Option<u64>,
    ) -> Self {
        Self { id, bytes, operation, deadline_ms, method: String::new(), account_id: None }
    }
}

pub(super) struct Client {
    pub commands: mpsc::Sender<Command>,
    pub shared: Arc<Shared>,
    lifecycle: mpsc::Sender<crate::bus::inprocess::LifecycleRequest>,
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
    lifecycle: mpsc::Receiver<crate::bus::inprocess::LifecycleRequest>,
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
        let (lifecycle, lifecycle_rx) = mpsc::channel(4);
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
                        lifecycle: lifecycle_rx,
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
            lifecycle,
            shutdown,
            done: Mutex::new(CloseCompletion { receiver: done, terminal: None }),
            close_wait,
            closing: AtomicBool::new(false),
        }))
    }

    pub fn close(&self) -> Result<CloseResult, Arc<SdkError>> {
        let first = !self.closing.swap(true, Ordering::AcqRel);
        let _ = self.shutdown.send(true);
        let mut done = if first {
            self.done
                .lock()
                .map_err(|_| Arc::new(SdkError::LocalBus("close lock poisoned".into())))?
        } else {
            match self.done.try_lock() {
                Ok(done) => done,
                Err(std::sync::TryLockError::WouldBlock) => return Ok(CloseResult::Pending),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(Arc::new(SdkError::LocalBus("close lock poisoned".into())));
                }
            }
        };
        done.wait(first, self.close_wait)
    }

    #[cfg(test)]
    pub(super) fn test_holding_close_lock<T>(&self, action: impl FnOnce() -> T) -> T {
        let _guard = self.done.lock().expect("test: hold the real close mutex");
        action()
    }

    pub(super) fn drive_lifecycle(&self, resume: bool, wait: Duration) -> Result<(), DriveError> {
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        let request = crate::bus::inprocess::LifecycleRequest { resume, reply };
        if self.lifecycle.blocking_send(request).is_err() {
            return Err(DriveError::Failed(SdkError::LocalBus("lifecycle channel closed".into())));
        }
        match response.recv_timeout(wait) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(DriveError::Failed(error)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(DriveError::TimedOut),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(DriveError::Failed(SdkError::LocalBus("lifecycle reply lost".into())))
            }
        }
    }

    pub fn shutdown_confirmed(&self) -> Result<bool, SdkError> {
        match self.done.try_lock() {
            Ok(mut state) => {
                let _ = state.wait(false, Duration::ZERO);
                Ok(state.terminal.is_some())
            }
            Err(std::sync::TryLockError::WouldBlock) => Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err(SdkError::LocalBus("close lock poisoned".into()))
            }
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn run(worker: Worker) -> Result<(), SdkError> {
    let Worker {
        mut config,
        commands,
        lifecycle,
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
    config.credential_callback = shared.credentials.callback_flag();
    let server = tokio::task::spawn_local(crate::bus::inprocess::serve(
        config,
        server_stream,
        server_shutdown,
        lifecycle,
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
    // One slot per admitted operation, so a reply can queue while the writer finishes a frame.
    let (replies_tx, replies_rx) = mpsc::channel(MAX_OPERATIONS);
    let write_task = tokio::task::spawn_local(async move {
        write_commands(commands, writer, writer_shutdown, replies_rx, &write_shared).await
    });
    let read_result = read_responses(reader, shutdown, replies_tx, &shared).await;
    let _ = stop.send(true);
    write_task.abort();
    let _ = write_task.await;
    let stopped = server.await.map_err(|e| SdkError::LocalBus(e.to_string()))?;
    stopped.and(read_result)
}

enum WriteAction {
    Skip,
    Cancel,
    Send,
}

pub(super) enum DriveError {
    TimedOut,
    Failed(SdkError),
}

async fn write_commands(
    mut commands: mpsc::Receiver<Command>,
    mut writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    mut shutdown: watch::Receiver<bool>,
    mut replies: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    shared: &Shared,
) -> Result<(), SdkError> {
    loop {
        let command = tokio::select! {
            biased;
            reply = replies.recv() => {
                let Some(reply) = reply else { break };
                super::credential::write_private(&mut writer, &reply).await?;
                continue;
            }
            _ = shutdown.changed() => break,
            command = commands.recv() => match command { Some(command) => command, None => break },
        };
        let action = {
            let mut state = command
                .operation
                .state
                .lock()
                .map_err(|_| SdkError::LocalBus("operation lock poisoned".into()))?;
            if state.result.is_some() || state.slot == super::state::ResultSlot::Frozen {
                WriteAction::Skip
            } else if shared.suspended.load(Ordering::Acquire) {
                let effects = if state.admitted { "unknown" } else { "none" };
                state.slot = super::state::ResultSlot::Frozen;
                state.result = Some(super::state::suspended_bytes(effects));
                WriteAction::Skip
            } else if state.cancelled {
                WriteAction::Cancel
            } else if command
                .deadline_ms
                .is_some_and(|deadline| u128::from(deadline) <= super::super::current_millis())
            {
                drop(state);
                shared.complete(command.id, serde_json::json!({"code":10,"effects":"none"}));
                WriteAction::Skip
            } else {
                state.admitted = true;
                WriteAction::Send
            }
        };
        match action {
            WriteAction::Skip => continue,
            WriteAction::Cancel => {
                shared.complete(command.id, failure(RamfluxV2Status::Cancelled, "none"));
                continue;
            }
            WriteAction::Send => {}
        }
        note_parent(&command, shared)?;
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

fn note_parent(command: &Command, shared: &Shared) -> Result<(), SdkError> {
    if command.method.is_empty() {
        return Ok(());
    }
    if let Err(error) =
        shared.credentials.note(command.id, &command.method, command.account_id.as_deref())
    {
        shared.failed(command.id, &error);
        return Err(error);
    }
    Ok(())
}

async fn read_responses(
    mut reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut shutdown: watch::Receiver<bool>,
    replies: mpsc::Sender<Zeroizing<Vec<u8>>>,
    shared: &Shared,
) -> Result<(), SdkError> {
    loop {
        let bytes = match super::credential::next_public_frame(
            &mut reader,
            &mut shutdown,
            &replies,
            &shared.credentials,
        )
        .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break Ok(()),
            Err(_) if *shutdown.borrow() => break Ok(()),
            Err(error) => break Err(error),
        };
        let mut frame: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(frame) => frame,
            Err(error) => break Err(SdkError::from(error)),
        };
        if super::host_key::answer(&frame, shared, &replies).await? {
            crate::bus::inprocess::erase_value(&mut frame);
            continue;
        }
        crate::bus::inprocess::erase_value(&mut frame);
        if handle_public(shared, &bytes)? {
            break Ok(());
        }
    }
}

fn refusal_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Code 16 is the unmapped class. Keep the bus refusal string as `name` so a client can
/// tell Replay from an unrelated internal failure without a new numeric status.
fn name_unmapped_refusal(frame: &mut serde_json::Value, code: i32) {
    if code != super::super::RamfluxErrorCode::Internal as i32 {
        return;
    }
    for key in ["error", "result"] {
        let Some(object) = frame.get_mut(key).and_then(serde_json::Value::as_object_mut) else {
            continue;
        };
        if object.get("name").and_then(serde_json::Value::as_str).is_some_and(refusal_token) {
            continue;
        }
        let Some(bus) = object.get("code").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !refusal_token(bus) {
            continue;
        }
        object.insert("name".to_owned(), serde_json::Value::String(bus.to_owned()));
    }
}

fn handle_public(shared: &Shared, bytes: &[u8]) -> Result<bool, SdkError> {
    // The authenticated in-process server emits both ordinary bus and compatibility
    // custody envelopes. Preserve either representation, including unknown business data.
    let mut frame: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(frame) => frame,
        Err(error) => return Err(SdkError::from(error)),
    };
    let legacy = frame.get("protocol").and_then(serde_json::Value::as_str)
        == Some("ramflux.local_bus.custody.v1");
    let kind = frame.get("kind").and_then(serde_json::Value::as_str);
    let generation = frame
        .get("subscription_generation")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<u64>().ok());
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
            name_unmapped_refusal(&mut frame, code);
            stop_requested = code == 0
                && frame.get("method").and_then(serde_json::Value::as_str) == Some("daemon.stop");
            if code == 0
                && matches!(
                    frame.get("method").and_then(serde_json::Value::as_str),
                    Some("subscription.open" | "bus.subscribe")
                )
            {
                let generation =
                    generation.filter(|generation| *generation != 0).ok_or_else(|| {
                        SdkError::LocalBus("subscription reply missing generation".into())
                    })?;
                let current = shared
                    .subscription
                    .lock()
                    .map_err(|_| SdkError::LocalBus("subscription lock poisoned".into()))?;
                // Keep admission and activation atomic with cancellation (subscription -> events).
                if *current == Some(id) {
                    shared.activate_generation(
                        generation,
                        frame
                            .get("account_id")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned),
                    );
                }
            }
            let completed = if let Some(generation) = generation {
                serde_json::json!({"code":code,"response":frame,"subscription_generation":generation.to_string()})
            } else {
                serde_json::json!({"code":code,"response":frame})
            };
            shared.complete(id, completed);
        }
    } else if !is_credential_request(&frame) {
        // A prompt that escaped the credential bridge has no subscription generation.
        // Treating it as an event closes the worker.
        let generation = generation
            .ok_or_else(|| SdkError::LocalBus("event missing subscription generation".into()))?;
        super::native_error::frame(&mut frame);
        shared.push_event(serde_json::to_vec(&frame)?, generation);
    }
    crate::bus::inprocess::erase_value(&mut frame);
    Ok(stop_requested)
}

fn is_credential_request(frame: &serde_json::Value) -> bool {
    frame.get("method").and_then(serde_json::Value::as_str) == Some("device.credential.request")
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
