// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervisor entry for the in-process carrier: the socket daemon's startup and accept loop
//! with no socket. One call owns the data-root lock and every store until it returns.

use super::supervisor::Supervisor;
use crate::platform::in_process::InProcessListener;
use crate::platform::listener::BusListener;
use crate::prelude::*;
use tokio::task::JoinSet;

/// Start-up outcome, reported once to the host thread that is waiting in `start`/`resume`.
pub(crate) type Ready = std::sync::mpsc::SyncSender<Result<(), SdkError>>;

/// Run the supervisor on the calling thread until `shutdown` fires. The thread is the same
/// shape as the socket daemon's: a current-thread runtime and a `LocalSet`.
///
/// # Errors
/// Returns an error when the runtime cannot be built or the supervisor fails while draining.
pub(crate) fn run_thread(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
    listener: InProcessListener,
    ready: Ready,
) -> Result<(), SdkError> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let local_set = LocalSet::new();
    local_set.block_on(&runtime, serve(config, shutdown, listener, ready))
}

async fn serve(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
    listener: InProcessListener,
    ready: Ready,
) -> Result<(), SdkError> {
    let mut background = JoinSet::new();
    let opened = open(config, &mut background).and_then(|supervisor| {
        let owner = listener.owner()?;
        Ok((supervisor, owner))
    });
    let (supervisor, owner) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            background.abort_all();
            while background.join_next().await.is_some() {}
            // The host reports this error from `start`; the thread itself ended cleanly.
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    tracing::info!("embedded local bus supervisor ready");
    let _ = ready.send(Ok(()));
    let result = super::connection::accept(listener, owner, supervisor, shutdown).await;
    background.abort_all();
    while background.join_next().await.is_some() {}
    result
}

fn open(config: LocalBusConfig, background: &mut JoinSet<()>) -> Result<Rc<Supervisor>, SdkError> {
    let root_lease = super::data_root_lock::DataRootLock::acquire(&config.data_root)?;
    crate::custody::reconcile_incomplete_markers(&config.data_root, &root_lease)?;
    let _ = std::fs::remove_dir_all(object_get_spool_dir(&config.data_root));
    let supervisor = Supervisor::new(config)?;
    *supervisor.root_lease.borrow_mut() = Some(root_lease);
    supervisor.hydrate(background)?;
    Ok(supervisor)
}
