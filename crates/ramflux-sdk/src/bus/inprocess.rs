// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-minted memory carrier for the same supervisor and connection dispatcher as the socket.

use super::supervisor::Supervisor;
use crate::platform::listener::{BusStream, PeerCred};
use crate::{LocalBusConfig, SdkError};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{oneshot, watch};

struct MemoryStream(DuplexStream);
impl BusStream for MemoryStream {
    type ReadHalf = ReadHalf<DuplexStream>;
    type WriteHalf = WriteHalf<DuplexStream>;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self.0)
    }

    fn matches_peer(&self, _expected: PeerCred) -> Result<(), SdkError> {
        // This stream can only be minted inside the host process; it has no listener.
        Ok(())
    }
}

pub(crate) async fn serve(
    config: LocalBusConfig,
    stream: DuplexStream,
    mut shutdown: watch::Receiver<bool>,
    ready: oneshot::Sender<Result<(), SdkError>>,
) -> Result<(), SdkError> {
    let initialized = (|| {
        std::fs::create_dir_all(&config.data_root)?;
        super::daemon::set_owner_only_dir_permissions(&config.data_root)?;
        let lease = super::data_root_lock::DataRootLock::acquire(&config.data_root)?;
        crate::custody::reconcile_incomplete_markers(&config.data_root, &lease)?;
        let supervisor = Supervisor::new(config)?;
        *supervisor.root_lease.borrow_mut() = Some(lease);
        Ok::<_, SdkError>(supervisor)
    })();
    let supervisor = match initialized {
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
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = stopping.changed() => break,
            _ = &mut connection => { connection_finished = true; break; },
            () = supervisor.reap_lifecycle_tasks() => {},
        }
    }
    supervisor.close_lifecycle_admission();
    if !connection_finished {
        connection.abort();
        let _ = connection.await;
    }
    supervisor.disconnect(1);
    background.abort_all();
    while background.join_next().await.is_some() {}
    supervisor.shutdown().await
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
