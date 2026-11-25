// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-minted memory carrier for the same supervisor and connection dispatcher as the socket.

use super::supervisor::Supervisor;
use crate::platform::listener::{BusStream, PeerCred};
use crate::{LocalBusConfig, SdkError};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{oneshot, watch};

#[cfg(test)]
pub(crate) struct ShutdownGate {
    pub entered: std::sync::mpsc::SyncSender<()>,
    pub release: std::sync::Arc<tokio::sync::Notify>,
}

struct MemoryStream(DuplexStream);
impl BusStream for MemoryStream {
    type ReadHalf = ReadHalf<DuplexStream>;
    type WriteHalf = WriteHalf<DuplexStream>;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self.0)
    }

    fn subscription_generations(&self) -> bool {
        true
    }

    fn accepts_credential_prompt(&self) -> bool {
        // Connect samples this once, before the host can register a callback.
        // Unlock reads that registration directly.
        false
    }

    fn matches_peer(&self, _expected: PeerCred) -> Result<(), SdkError> {
        // This stream can only be minted inside the host process; it has no listener.
        Ok(())
    }
}

pub(crate) struct LifecycleRequest {
    pub resume: bool,
    /// Only check for live calls; no lifecycle change and no completion callback.
    pub probe: bool,
    pub complete: Box<dyn FnOnce(bool, bool) + Send>,
    pub reply: std::sync::mpsc::SyncSender<Result<(), SdkError>>,
}

pub(crate) async fn serve(
    config: LocalBusConfig,
    stream: DuplexStream,
    shutdown: (watch::Receiver<bool>, watch::Sender<bool>),
    mut lifecycle: tokio::sync::mpsc::Receiver<LifecycleRequest>,
    ready: oneshot::Sender<Result<(), SdkError>>,
    #[cfg(test)] gate: Option<ShutdownGate>,
) -> Result<(), SdkError> {
    let (mut shutdown, handoff_stop) = shutdown;
    let supervisor = match initialize(config).await {
        Ok(supervisor) => supervisor,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    let mut background = tokio::task::JoinSet::new();
    if let Err(error) = supervisor.hydrate(&mut background) {
        let _ = ready.send(Err(error));
        background.abort_all();
        while background.join_next().await.is_some() {}
        supervisor.shutdown().await?;
        return Ok(());
    }
    let _ = ready.send(Ok(()));
    let mut connection = tokio::task::spawn_local(super::connection::handle(
        MemoryStream(stream),
        std::rc::Rc::clone(&supervisor),
        1,
    ));
    let mut stopping = supervisor.stop_requested();
    let mut connection_finished = false;
    let mut lifecycle_open = true;
    let mut lease_error = None;
    let mut lease_poll = tokio::time::interval(super::session_lease::POLL);
    lease_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut media_tick = tokio::time::interval(crate::client::call::media_owner::MEDIA_TICK);
    media_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = media_tick.tick() => {
                // A failed journal append keeps its mark, so the next tick retries the row.
                let _ = supervisor.media_tick().await;
            }
            _ = lease_poll.tick(), if supervisor.config.session_lease.is_some() => {
                match super::session_lease::handoff_requested(&supervisor.config.data_root) {
                    Ok(false) => {},
                    Ok(true) => {
                        // Tell the carrier this EOF is an intentional shutdown before closing it.
                        handoff_stop.send_replace(true);
                        break;
                    },
                    Err(error) => { lease_error = Some(error); break; },
                }
            }
            _ = shutdown.changed() => break,
            _ = stopping.changed() => break,
            _ = &mut connection => { connection_finished = true; break; },
            () = supervisor.reap_lifecycle_tasks() => {},
            request = lifecycle.recv(), if lifecycle_open => {
                lifecycle_open = drive_lifecycle(&supervisor, request).await;
            },
        }
    }
    let explicit_stop = *stopping.borrow();
    supervisor.close_lifecycle_admission();
    let stop_result = if explicit_stop {
        let mut response = supervisor.stop_response();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !*response.borrow() {
                response
                    .changed()
                    .await
                    .map_err(|_| SdkError::LocalBus("stop response lost".into()))?;
            }
            Ok::<_, SdkError>(())
        })
        .await
        .map_err(|_| SdkError::LocalBus("stop response timed out".into()))?
    } else {
        Ok(())
    };
    #[cfg(test)]
    if let Some(gate) = gate {
        let _ = gate.entered.try_send(());
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), gate.release.notified()).await;
    }
    if !connection_finished {
        connection.abort();
        let _ = connection.await;
    }
    supervisor.disconnect(1);
    background.abort_all();
    while background.join_next().await.is_some() {}
    supervisor.shutdown().await?;
    stop_result?;
    lease_error.map_or(Ok(()), Err)
}

async fn initialize(config: LocalBusConfig) -> Result<std::rc::Rc<Supervisor>, SdkError> {
    std::fs::create_dir_all(&config.data_root)?;
    super::daemon::set_owner_only_dir_permissions(&config.data_root)?;
    let lease = match config.session_lease {
        Some(lease) => super::session_lease::acquire(&config.data_root, lease).await?,
        None => super::data_root_lock::DataRootLock::acquire(&config.data_root)?,
    };
    crate::custody::reconcile_incomplete_markers(&config.data_root, &lease)?;
    let supervisor = Supervisor::new(config)?;
    *supervisor.root_lease.borrow_mut() = Some(lease);
    Ok(supervisor)
}

async fn drive_lifecycle(
    supervisor: &std::rc::Rc<Supervisor>,
    request: Option<LifecycleRequest>,
) -> bool {
    let Some(request) = request else { return false };
    if request.probe {
        let result = match supervisor.live_call_busy().await {
            Ok(true) => Err(super::background::live_call_refused()),
            Ok(false) => Ok(()),
            Err(error) => Err(error),
        };
        let _ = request.reply.send(result);
        return true;
    }
    let result = if request.resume {
        supervisor.resume_for_background().await
    } else {
        supervisor.suspend_for_background().await
    };
    // The worker owns completion even when the FFI caller has timed out.
    (request.complete)(
        supervisor.config.background.load(std::sync::atomic::Ordering::Acquire),
        result.is_ok(),
    );
    let _ = request.reply.send(result);
    true
}

pub(crate) fn method_names() -> Vec<&'static str> {
    let mut names = super::method_table::METHODS
        .iter()
        .map(|method| method.name)
        .filter(|name| !name.contains("itest"))
        .collect::<Vec<_>>();
    names.extend(crate::backup::BACKUP_JOB_METHODS.iter().copied());
    names.extend([
        "account.custody.begin",
        "account.custody.show_once",
        "account.custody.hidden_challenge",
        "account.custody.confirm",
        "account.custody.cancel",
        "account.create.begin",
        "account.create.show_once",
        "account.create.hidden_challenge",
        "account.create.confirm",
        "account.create.cancel",
        "account.recover.begin",
        "account.recover.confirm",
        "account.recover.cancel",
        "agent.create",
        "agent.creation.decide",
        "agent.operation.get",
        "agent.list",
        "agent.get",
        "agent.host.manage",
        "agent.persona.edit",
        "agent.access.set",
        "agent.watch",
        "agent.delete",
        "agent.retire",
        "subscription.close",
    ]);
    names.sort_unstable();
    names.dedup();
    names
}

/// Encode using the canonical bus representation and erase the temporary request body.
pub(crate) fn encode_request(mut frame: crate::LocalBusFrame) -> Result<Vec<u8>, SdkError> {
    let result = super::io::encode_local_bus_frame(&frame);
    super::secrets::wipe(&mut frame.body);
    result
}

/// Erase temporary business values, including secret ceremony responses.
pub(crate) fn erase_value(value: &mut serde_json::Value) {
    super::secrets::wipe(value);
}
