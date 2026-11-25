// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local Unix socket that notify uses to hand wake batches to the push session.
//! One request and one reply per connection, both `u32be length || JSON`.
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ramflux_node_core::push_handoff::{
    HANDOFF_VERSION, HandoffReply, HandoffRequest, HandoffStatus, MAX_HANDOFF_FRAME, MAX_WAKES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use super::session::{PushShared, reply_status, send_wakes};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Notify waits 12 s in total; the batch itself is bounded by the centre reply timeout.
const BATCH_TIMEOUT: Duration = Duration::from_secs(11);
/// Concurrent handoff connections; a connection over the limit is dropped at once.
const MAX_HANDOFF_TASKS: usize = 64;

/// Serves the handoff socket. The socket lives in a directory that is mode 0700 and owned by the
/// current user, so no other user can reach it whatever mode the socket file gets at bind time
/// (no chmod-after-bind window). Peers must also present the same uid (`SO_PEERCRED`).
pub(crate) async fn serve(socket: PathBuf, shared: Arc<PushShared>) -> Result<(), String> {
    prepare_parent(&socket)?;
    match std::fs::symlink_metadata(&socket) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(&socket)
                .map_err(|error| format!("remove stale socket: {error}"))?;
        }
        Ok(_) => return Err("handoff_socket exists and is not a socket".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("handoff_socket: {error}")),
    }
    let listener =
        UnixListener::bind(&socket).map_err(|error| format!("bind handoff socket: {error}"))?;
    // The socket is created by this process, so its owner is the effective uid we serve as.
    let owner =
        std::fs::metadata(&socket).map_err(|error| format!("handoff socket: {error}"))?.uid();
    let dir_owner =
        socket.parent().and_then(|parent| std::fs::metadata(parent).ok()).map(|meta| meta.uid());
    if dir_owner != Some(owner) {
        return Err("handoff directory is not owned by this user".to_owned());
    }
    let limit = Arc::new(Semaphore::new(MAX_HANDOFF_TASKS));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if stream.peer_cred().map(|cred| cred.uid()).ok() != Some(owner) {
                    tracing::warn!("handoff connection from another uid refused");
                    continue;
                }
                let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                    tracing::warn!("handoff connection refused: too many in flight");
                    continue;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let _permit = permit;
                    handle(stream, shared).await;
                });
            }
            Err(error) => {
                tracing::warn!(%error, "handoff accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// The socket directory is created with mode 0700 when absent; an existing directory must have no
/// group or other permission bits at all.
fn prepare_parent(socket: &Path) -> Result<(), String> {
    let parent = socket.parent().ok_or("handoff_socket has no parent directory")?;
    if !parent.exists() {
        std::fs::create_dir_all(parent).map_err(|error| format!("handoff directory: {error}"))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("handoff directory mode: {error}"))?;
    }
    let mode = std::fs::metadata(parent)
        .map_err(|error| format!("handoff directory: {error}"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err("handoff directory must be mode 0700".to_owned());
    }
    Ok(())
}

async fn handle(mut stream: UnixStream, shared: Arc<PushShared>) {
    let reply = match tokio::time::timeout(IO_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => {
            match tokio::time::timeout(BATCH_TIMEOUT, send_wakes(&shared, &request.wakes)).await {
                Ok(reply) => reply,
                Err(_) => reply_status(
                    HandoffStatus::Unavailable,
                    Some("timeout"),
                    Some(2000),
                    Vec::new(),
                ),
            }
        }
        Ok(Err(why)) => reply_status(HandoffStatus::Rejected, Some(why), None, Vec::new()),
        Err(_) => return,
    };
    if let Err(error) = write_reply(&mut stream, &reply).await {
        tracing::warn!(%error, "handoff reply not written");
    }
}

async fn read_request(stream: &mut UnixStream) -> Result<HandoffRequest, &'static str> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.map_err(|_| "malformed")?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_HANDOFF_FRAME {
        return Err("too_large");
    }
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body).await.map_err(|_| "malformed")?;
    let request: HandoffRequest = serde_json::from_slice(&body).map_err(|_| "malformed")?;
    if request.v != HANDOFF_VERSION {
        return Err("unsupported");
    }
    if request.wakes.is_empty() || request.wakes.len() > MAX_WAKES {
        return Err("malformed");
    }
    Ok(request)
}

async fn write_reply(stream: &mut UnixStream, reply: &HandoffReply) -> std::io::Result<()> {
    let body = serde_json::to_vec(reply).map_err(std::io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(std::io::Error::other)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}
