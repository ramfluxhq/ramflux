// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Socket framing, request multiplexing and connection-scoped cancellation.

use super::supervisor::Supervisor;
use crate::prelude::*;
use tokio::task::JoinSet;

pub(super) async fn serve(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    std::fs::create_dir_all(&config.data_root)?;
    set_owner_only_dir_permissions(&config.data_root)?;
    let _ = std::fs::remove_dir_all(object_get_spool_dir(&config.data_root));
    if let Some(parent) = config.socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path)?;
    }
    let listener = UnixListener::bind(&config.socket_path)?;
    set_owner_only_file_permissions(&config.socket_path)?;
    let uid = std::fs::metadata(&config.socket_path)?.uid();
    let supervisor = Supervisor::new(config)?;
    let mut background = JoinSet::new();
    supervisor.hydrate(&mut background)?;
    let result = accept(listener, uid, supervisor, shutdown).await;
    background.abort_all();
    while background.join_next().await.is_some() {}
    result
}

pub(super) async fn accept(
    listener: UnixListener,
    uid: u32,
    supervisor: Rc<Supervisor>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    let socket = super::socket::SocketFile::new(&listener)?;
    let mut stopping = supervisor.stop_requested();
    let mut connections = JoinSet::new();
    let mut next = 1_u64;
    let mut last_peer_warning = None;
    loop {
        tokio::select! {
            _ = stopping.changed() => break,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if let Err(error) = verify_local_bus_peer(&stream, uid) {
                    let now = std::time::Instant::now();
                    if last_peer_warning.is_none_or(|last| now.duration_since(last) >= std::time::Duration::from_secs(60)) {
                        tracing::warn!(%error, "local bus peer verification failed; connection rejected");
                        last_peer_warning = Some(now);
                    }
                    continue;
                }
                let supervisor = Rc::clone(&supervisor);
                let id = next;
                next = next.checked_add(1).ok_or_else(|| SdkError::LocalBus("connection id exhausted".to_owned()))?;
                connections.spawn_local(async move { handle(stream, supervisor, id).await });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Ok(Err(error)) = result { tracing::warn!(%error, "local bus connection ended"); }
            }
        }
    }
    drop(listener);
    if let Some(socket) = &socket {
        socket.remove()?;
    }
    if *stopping.borrow() {
        let mut response = supervisor.stop_response();
        while !*response.borrow() {
            if response.changed().await.is_err() {
                break;
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    supervisor.shutdown().await
}

pub(super) async fn handle(
    stream: UnixStream,
    supervisor: Rc<Supervisor>,
    id: u64,
) -> Result<(), SdkError> {
    let (mut reader, writer) = stream.into_split();
    let (incoming, mut frames) = mpsc::channel(64);
    let (disconnect, mut disconnected) = watch::channel(false);
    let reader_task = tokio::task::spawn_local(async move {
        loop {
            let frame =
                read_local_bus_frame(&mut reader).await.map(super::custody_setup::Incoming::new);
            let failed = frame.is_err();
            if incoming.try_send(frame).is_err() || failed {
                break;
            }
        }
        let _ = disconnect.send(true);
    });
    let (outbound, receiver) = mpsc::channel::<LocalBusFrame>(64);
    let (secrets, secret_receiver) = mpsc::channel::<zeroize::Zeroizing<Vec<u8>>>(1);
    let writer_task = tokio::task::spawn_local(write_responses(
        writer,
        receiver,
        secret_receiver,
        Rc::clone(&supervisor),
        id,
    ));
    let _cleanup =
        ConnectionTasks { reader: reader_task.abort_handle(), writer: writer_task.abort_handle() };
    let mut connection = LocalBusConnectionState::new(id, outbound.clone());
    let mut requests = JoinSet::new();
    let mut inflight = BTreeSet::new();
    let mut ceremony: Option<crate::custody::CreationCeremony> = None;
    let mut recovery: Option<crate::custody::RecoveryCeremony> = None;
    let result = loop {
        tokio::select! {
            _ = disconnected.changed() => break Ok(()),
            () = tokio::time::sleep_until(ceremony.as_ref().map_or_else(|| tokio::time::Instant::now()+std::time::Duration::from_secs(3600), |c| c.deadline().into())), if ceremony.as_ref().is_some_and(|pending| !pending.is_expired()) => { if let Some(pending) = ceremony.as_mut() { pending.expire(); } },
            frame = frames.recv(), if requests.len() < 64 => {
                let mut incoming = match frame {
                    None => break Ok(()),
                    Some(frame) => match frame {
                    Ok(request) => request,
                    Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
                    Err(error) => break Err(error),
                    },
                };
                if super::custody_setup::handles(&incoming.frame()?.method) {
                    let bytes = custody_response(
                        &mut incoming,
                        &supervisor,
                        &mut ceremony,
                        &mut recovery,
                        &mut disconnected,
                    )
                    .await?;
                    tokio::time::timeout(Duration::from_secs(10),secrets.send(bytes)).await.map_err(|_|closed())?.map_err(|_|closed())?;
                    continue;
                }
                let request = incoming.take()?;
                if let Err(error) = super::requests::deadline(&request) {
                    outbound.send(local_bus_error(&request,&error)).await.map_err(|_| closed())?;
                    continue;
                }
                if request.kind != LocalBusFrameKind::Request {
                    outbound.send(local_bus_error(&request, &SdkError::LocalBus("expected request frame".to_owned()))).await.map_err(|_| closed())?;
                    continue;
                }
                if !inflight.insert(request.request_id.clone()) {
                    outbound.send(local_bus_error(&request, &SdkError::LocalBus("duplicate in-flight request_id".to_owned()))).await.map_err(|_| closed())?;
                    continue;
                }
                if matches!(request.method.as_str(),"bus.subscribe"|"subscription.open") {
                    if let Err(error)=configure_subscription(&supervisor,&mut connection,&request).await {
                        outbound.send(local_bus_error(&request,&error)).await.map_err(|_|closed())?;
                    }
                    inflight.remove(&request.request_id);
                    continue;
                }
                let context = LocalBusConnectionState {
                    connection_id: id, outbound: outbound.clone(), topics: connection.topics.clone(),
                    attended_account_id: connection.attended_account_id.clone(), pending_events: Vec::new(),
                };
                requests.spawn_local(super::requests::respond(request, Rc::clone(&supervisor), context));
            }
            Some(result) = requests.join_next(), if !requests.is_empty() => {
                match result {
                    Ok((id, result)) => { inflight.remove(&id); if let Err(error) = result { break Err(error); } }
                    Err(error) => break Err(SdkError::LocalBus(format!("request task failed: {error}"))),
                }
            }
        }
    };
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    supervisor.disconnect(id);
    reader_task.abort();
    let _ = reader_task.await;
    writer_task.abort();
    let _ = writer_task.await;
    result
}

async fn custody_response(
    incoming: &mut super::custody_setup::Incoming,
    supervisor: &Supervisor,
    ceremony: &mut Option<crate::custody::CreationCeremony>,
    recovery: &mut Option<crate::custody::RecoveryCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    let frame = incoming.frame()?;
    if frame.method == "account.create.begin"
        && !frame.account_id.as_deref().is_some_and(|id| supervisor.account_is_open(id))
    {
        return super::custody_response::error(frame, &SdkError::LocalBusPermissionDenied);
    }
    if frame.method.starts_with("account.recover.") {
        return super::recovery::respond(frame, supervisor, recovery, disconnected).await;
    }
    if frame.method == "account.create.confirm" {
        return super::creation_confirm::respond(frame, supervisor, ceremony, disconnected).await;
    }
    super::custody_setup::respond(frame, &supervisor.config, ceremony)
}

async fn configure_subscription(
    supervisor: &Supervisor,
    connection: &mut LocalBusConnectionState,
    request: &LocalBusFrame,
) -> Result<(), SdkError> {
    if request.body.get("attended_frontend").and_then(serde_json::Value::as_bool).unwrap_or(false) {
        connection.attended_account_id.clone_from(&request.account_id);
    }
    if request.account_id.is_none() {
        return supervisor.subscribe_backup_stream(request.clone(), connection).await;
    }
    if request.method == "bus.subscribe" {
        return supervisor.subscribe_stream(request.clone(), connection).await;
    }
    let body: LocalBusSubscriptionOpenRequest = serde_json::from_value(request.body.clone())?;
    connection.topics.extend(body.topics);
    if let Some(account) = request.account_id.clone() {
        supervisor.subscribe(connection, account);
    }
    connection
        .outbound
        .send(local_bus_response(request, serde_json::json!({"subscribed":true})))
        .await
        .map_err(|_| closed())?;
    Ok(())
}

fn closed() -> SdkError {
    SdkError::LocalBus("local bus connection closed".to_owned())
}

struct ConnectionTasks {
    reader: tokio::task::AbortHandle,
    writer: tokio::task::AbortHandle,
}
impl Drop for ConnectionTasks {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

struct WriterStopped {
    supervisor: Rc<Supervisor>,
    connection: u64,
}
impl Drop for WriterStopped {
    fn drop(&mut self) {
        self.supervisor.finish_stop_connection(self.connection);
    }
}

async fn write_responses(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut receiver: mpsc::Receiver<LocalBusFrame>,
    mut secret_receiver: mpsc::Receiver<zeroize::Zeroizing<Vec<u8>>>,
    supervisor: Rc<Supervisor>,
    id: u64,
) -> Result<(), SdkError> {
    let _lifetime = WriterStopped { supervisor: Rc::clone(&supervisor), connection: id };
    loop {
        let frame = tokio::select! {
            bytes = secret_receiver.recv() => {
                let Some(bytes) = bytes else { break; };
                tokio::time::timeout(Duration::from_secs(10),super::io::write_encoded_local_bus_frame(&mut writer,&bytes)).await.map_err(|_|closed())??;
                continue;
            }
            frame = receiver.recv() => frame,
        };
        let Some(frame) = frame else {
            break;
        };
        write_local_bus_frame(&mut writer, &frame).await?;
        if frame.method == "daemon.stop" {
            supervisor.finish_stop_response(id, &frame.request_id);
        }
    }
    Ok(())
}
