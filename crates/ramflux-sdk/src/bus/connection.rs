// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Socket framing, request multiplexing and connection-scoped cancellation.

use super::supervisor::Supervisor;
use crate::platform::listener::{BusListener, BusStream};
use crate::prelude::*;
use std::sync::Arc;
use tokio::task::JoinSet;

pub(super) async fn serve(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    // Windows creates the root with an owner-only access list, refuses a roaming profile path
    // and a root another user owns.
    #[cfg(windows)]
    crate::platform::fs::ensure_data_root(&config.data_root)?;
    #[cfg(not(windows))]
    {
        std::fs::create_dir_all(&config.data_root)?;
        set_owner_only_dir_permissions(&config.data_root)?;
    }
    let root_lease = super::data_root_lock::DataRootLock::acquire(&config.data_root)?;
    crate::custody::reconcile_incomplete_markers(&config.data_root, &root_lease)?;
    let _ = std::fs::remove_dir_all(object_get_spool_dir(&config.data_root));
    if let Some(parent) = config.socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path)?;
    }
    let listener = crate::platform::listener::bind(&config.socket_path)?;
    let owner = listener.owner()?;
    let supervisor = Supervisor::new(config)?;
    *supervisor.root_lease.borrow_mut() = Some(root_lease);
    let mut background = JoinSet::new();
    supervisor.hydrate(&mut background)?;
    tracing::info!(socket = %supervisor.config.socket_path.display(), "local bus daemon ready");
    let result = accept(listener, owner, supervisor, shutdown).await;
    background.abort_all();
    while background.join_next().await.is_some() {}
    result
}

pub(super) async fn accept<L: BusListener>(
    listener: L,
    owner: crate::platform::listener::PeerCred,
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
            () = supervisor.reap_lifecycle_tasks() => {},
            _ = stopping.changed() => break,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let stream = accepted?;
                if let Err(error) = stream.matches_peer(owner) {
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
    let explicit_stop = *stopping.borrow();
    supervisor.close_lifecycle_admission();
    drop(listener);
    if let Some(socket) = &socket {
        socket.remove()?;
    }
    if explicit_stop {
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

pub(super) async fn handle<S: crate::platform::listener::BusStream>(
    stream: S,
    supervisor: Rc<Supervisor>,
    id: u64,
) -> Result<(), SdkError> {
    let generations = stream.subscription_generations();
    let (reader, writer) = stream.into_halves();
    let (outbound, receiver) = super::outbound::LocalBusOutbound::channel(64, generations);
    let credential_input =
        super::credentials::connection(supervisor.config.data_root.clone(), id, outbound.clone());
    let reader_credentials = credential_input.channel();
    let host_credentials = Arc::clone(&reader_credentials);
    let RequestReader { task: reader_task, mut frames, mut disconnected } =
        spawn_request_reader(reader, reader_credentials, id);
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
    connection.credential_channel = Some(credential_input.channel());
    let mut requests = JoinSet::new();
    let mut inflight = BTreeSet::new();
    let mut ceremony: Option<crate::custody::CreationCeremony> = None;
    let mut recovery: Option<crate::custody::RecoveryCeremony> = None;
    let result = loop {
        tokio::select! {
            _ = disconnected.changed() => break Ok(()),
            () = tokio::time::sleep_until(ceremony_deadline(ceremony.as_ref())), if ceremony_pending(ceremony.as_ref()) => {
                if let Some(pending) = ceremony.as_mut() {
                    pending.expire();
                }
            },
            frame = frames.recv(), if requests.len() < 64 => {
                let step = admit_frame(
                    frame,
                    &mut AdmitState {
                        supervisor: &supervisor,
                        host_credentials: &host_credentials,
                        ceremony: &mut ceremony,
                        recovery: &mut recovery,
                        disconnected: &mut disconnected,
                        secrets: &secrets,
                        outbound: &outbound,
                        inflight: &mut inflight,
                        connection: &mut connection,
                        requests: &mut requests,
                    },
                )
                .await?;
                if let Admit::Done(done) = step {
                    break done;
                }
            }
            Some(finished) = requests.join_next(), if !requests.is_empty() => {
                if let Some(error) = task_error(finished, &mut inflight) {
                    break Err(error);
                }
            }
        }
    };
    finish_connection(credential_input, requests, &supervisor, id, reader_task, writer_task).await;
    result
}

async fn finish_connection(
    credential_input: super::credentials::ConnectionInput,
    mut requests: JoinSet<(String, Result<(), SdkError>)>,
    supervisor: &Rc<Supervisor>,
    id: u64,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<Result<(), SdkError>>,
) {
    credential_input.close();
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    supervisor.disconnect(id);
    reader_task.abort();
    let _ = reader_task.await;
    writer_task.abort();
    let _ = writer_task.await;
}

enum Admit {
    Stay,
    Done(Result<(), SdkError>),
}

struct AdmitState<'a> {
    supervisor: &'a Rc<Supervisor>,
    host_credentials:
        &'a Arc<crate::custody::pairing::private_credential::PrivateCredentialChannel>,
    ceremony: &'a mut Option<crate::custody::CreationCeremony>,
    recovery: &'a mut Option<crate::custody::RecoveryCeremony>,
    disconnected: &'a mut watch::Receiver<bool>,
    secrets: &'a mpsc::Sender<zeroize::Zeroizing<Vec<u8>>>,
    outbound: &'a super::outbound::LocalBusOutbound,
    inflight: &'a mut BTreeSet<String>,
    connection: &'a mut LocalBusConnectionState,
    requests: &'a mut JoinSet<(String, Result<(), SdkError>)>,
}

fn ceremony_pending(ceremony: Option<&crate::custody::CreationCeremony>) -> bool {
    ceremony.is_some_and(|pending| !pending.is_expired())
}

fn ceremony_deadline(ceremony: Option<&crate::custody::CreationCeremony>) -> tokio::time::Instant {
    ceremony.map_or_else(
        || tokio::time::Instant::now() + std::time::Duration::from_secs(3600),
        |pending| pending.deadline().into(),
    )
}

fn task_error(
    finished: Result<(String, Result<(), SdkError>), tokio::task::JoinError>,
    inflight: &mut BTreeSet<String>,
) -> Option<SdkError> {
    match finished {
        Ok((id, Ok(()))) => {
            inflight.remove(&id);
            None
        }
        Ok((id, Err(error))) => {
            inflight.remove(&id);
            Some(error)
        }
        Err(error) => Some(SdkError::LocalBus(format!("request task failed: {error}"))),
    }
}

async fn admit_frame(
    frame: Option<Result<super::custody_setup::Incoming, SdkError>>,
    state: &mut AdmitState<'_>,
) -> Result<Admit, SdkError> {
    let mut incoming = match frame {
        None => return Ok(Admit::Done(Ok(()))),
        Some(Ok(request)) => request,
        Some(Err(SdkError::Io(error))) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(Admit::Done(Ok(())));
        }
        Some(Err(error)) => return Ok(Admit::Done(Err(error))),
    };
    if let Some(bytes) = local_method(
        &mut incoming,
        state.supervisor,
        state.host_credentials,
        state.ceremony,
        state.recovery,
        state.disconnected,
    )
    .await?
    {
        tokio::time::timeout(Duration::from_secs(10), state.secrets.send(bytes))
            .await
            .map_err(|_| closed())?
            .map_err(|_| closed())?;
        return Ok(Admit::Stay);
    }
    let mut request = incoming.take()?;
    if let Err(error) = super::requests::deadline(&request) {
        state.outbound.send(rejected_request(&mut request, &error)).await.map_err(|_| closed())?;
        return Ok(Admit::Stay);
    }
    if request.kind != LocalBusFrameKind::Request {
        let error = SdkError::LocalBus("expected request frame".to_owned());
        state.outbound.send(rejected_request(&mut request, &error)).await.map_err(|_| closed())?;
        return Ok(Admit::Stay);
    }
    if !state.inflight.insert(request.request_id.clone()) {
        let error = SdkError::LocalBus("duplicate in-flight request_id".to_owned());
        state.outbound.send(rejected_request(&mut request, &error)).await.map_err(|_| closed())?;
        return Ok(Admit::Stay);
    }
    if subscription_method(&request.method) {
        if let Err(error) =
            configure_subscription(state.supervisor, state.connection, &request).await
        {
            state
                .outbound
                .send(rejected_request(&mut request, &error))
                .await
                .map_err(|_| closed())?;
        }
        state.inflight.remove(&request.request_id);
        return Ok(Admit::Stay);
    }
    let mut context = state.connection.clone();
    context.pending_events.clear();
    context.outbound = context.outbound.for_account(request.account_id.as_deref());
    state.requests.spawn_local(super::requests::respond(
        request,
        Rc::clone(state.supervisor),
        context,
    ));
    Ok(Admit::Stay)
}

async fn local_method(
    incoming: &mut super::custody_setup::Incoming,
    supervisor: &Rc<Supervisor>,
    channel: &Arc<crate::custody::pairing::private_credential::PrivateCredentialChannel>,
    ceremony: &mut Option<crate::custody::CreationCeremony>,
    recovery: &mut Option<crate::custody::RecoveryCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, SdkError> {
    let method = incoming.frame()?.method.clone();
    if method == "agent.host.manage" {
        return Ok(Some(super::host_manage::respond(incoming, Arc::clone(channel)).await?));
    }
    if super::custody_setup::handles(&method) || super::agent_methods::handles(&method) {
        return Ok(Some(
            custody_response(incoming, supervisor, ceremony, recovery, disconnected).await?,
        ));
    }
    Ok(None)
}

struct RequestReader {
    task: tokio::task::JoinHandle<()>,
    frames: mpsc::Receiver<Result<super::custody_setup::Incoming, SdkError>>,
    disconnected: watch::Receiver<bool>,
}
fn spawn_request_reader<R: tokio::io::AsyncRead + Unpin + 'static>(
    reader: R,
    credentials: Arc<crate::custody::pairing::private_credential::PrivateCredentialChannel>,
    connection: u64,
) -> RequestReader {
    let (incoming, frames) = mpsc::channel(64);
    let (disconnect, disconnected) = watch::channel(false);
    let task = tokio::task::spawn_local(read_requests(
        reader,
        credentials,
        connection,
        incoming,
        disconnect,
    ));
    RequestReader { task, frames, disconnected }
}

async fn read_requests<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    reader_credentials: Arc<crate::custody::pairing::private_credential::PrivateCredentialChannel>,
    id: u64,
    incoming: mpsc::Sender<Result<super::custody_setup::Incoming, SdkError>>,
    disconnect: watch::Sender<bool>,
) {
    loop {
        let frame = match super::credentials::read_frame(&mut reader, &reader_credentials, id).await
        {
            Ok(None) => continue,
            Ok(Some(frame)) => Ok(super::custody_setup::Incoming::new(frame)),
            Err(error) => Err(error),
        };
        let failed = frame.is_err();
        if incoming.try_send(frame).is_err() || failed {
            break;
        }
    }
    reader_credentials.close();
    let _ = disconnect.send(true);
}

async fn custody_response(
    incoming: &mut super::custody_setup::Incoming,
    supervisor: &Supervisor,
    ceremony: &mut Option<crate::custody::CreationCeremony>,
    recovery: &mut Option<crate::custody::RecoveryCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    let frame = incoming.frame()?;
    if super::agent_methods::handles(&frame.method) {
        return super::agent_methods::respond(frame, supervisor).await;
    }
    if frame.method.starts_with("account.recover.") {
        return super::recovery::respond(frame, supervisor, recovery, disconnected).await;
    }
    if frame.method == "account.create.confirm" {
        return super::creation_confirm::respond(frame, supervisor, ceremony, disconnected).await;
    }
    let lease = supervisor.root_lease.borrow().clone();
    super::custody_setup::respond(frame, &supervisor.config, ceremony, lease).await
}

fn subscription_method(method: &str) -> bool {
    matches!(method, "bus.subscribe" | "subscription.open")
        || (cfg!(feature = "c-abi") && method == "subscription.close")
}

pub(super) async fn configure_subscription(
    supervisor: &Supervisor,
    connection: &mut LocalBusConnectionState,
    request: &LocalBusFrame,
) -> Result<(), SdkError> {
    #[cfg(feature = "c-abi")]
    if request.method == "subscription.close" {
        supervisor.disconnect(connection.connection_id);
        connection.topics.clear();
        connection.attended_account_id = None;
        connection
            .outbound
            .send(local_bus_response(request, serde_json::json!({"subscribed":false})))
            .await
            .map_err(|_| closed())?;
        return Ok(());
    }
    connection.outbound = connection.outbound.subscribe(request.account_id.clone())?;
    if request.body.get("attended_frontend").and_then(serde_json::Value::as_bool).unwrap_or(false) {
        connection.attended_account_id.clone_from(&request.account_id);
    }
    if super::pairing::events::requested(request) {
        return supervisor.subscribe_pairing_stream(request.clone(), connection).await;
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

fn rejected_request(request: &mut LocalBusFrame, error: &SdkError) -> LocalBusFrame {
    let response = local_bus_error(request, error);
    super::secrets::wipe(&mut request.body);
    response
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

async fn write_responses<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: super::outbound::Receiver,
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
        let Some(mut frame) = frame else {
            break;
        };
        if frame.frame.method == "search.query" && frame.frame.ok == Some(true) {
            let encoded = (|| -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
                let completion = supervisor.resolve_search_completion(&frame.frame, id)?;
                frame.frame.body = serde_json::to_value(completion.take()?)?;
                let encoded = super::io::encode_local_bus_frame(&frame.frame);
                super::secrets::wipe(&mut frame.frame.body);
                let encoded = zeroize::Zeroizing::new(encoded?);
                completion.check_current()?;
                Ok(encoded)
            })();
            match encoded {
                Ok(bytes) => {
                    tokio::time::timeout(
                        Duration::from_secs(10),
                        super::io::write_encoded_local_bus_frame(&mut writer, &bytes),
                    )
                    .await
                    .map_err(|_| closed())??;
                }
                Err(error) => {
                    frame.frame = super::io::local_bus_error(&frame.frame, &error);
                    write_local_bus_frame(&mut writer, &frame.frame).await?;
                }
            }
            continue;
        }
        if crate::search::capability::is_method(&frame.frame.method) {
            let encoded = super::io::encode_local_bus_frame(&frame.frame);
            super::secrets::wipe(&mut frame.frame.body);
            let encoded = zeroize::Zeroizing::new(encoded?);
            tokio::time::timeout(
                Duration::from_secs(10),
                super::io::write_encoded_local_bus_frame(&mut writer, &encoded),
            )
            .await
            .map_err(|_| closed())??;
            continue;
        }
        super::outbound::write(&mut writer, &frame).await?;
        if frame.frame.method == "daemon.stop" {
            supervisor.finish_stop_response(id, &frame.frame.request_id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod non_unix_seam {
    use super::accept;
    use crate::platform::listener::{BusListener, StubListener};
    use crate::prelude::*;

    #[test]
    fn core_compiles_against_a_non_unix_listener() {
        fn core_accept<L: BusListener>(
            listener: L,
            owner: crate::platform::listener::PeerCred,
            supervisor: Rc<crate::bus::supervisor::Supervisor>,
            shutdown: watch::Receiver<bool>,
        ) -> impl Future<Output = Result<(), SdkError>> {
            accept(listener, owner, supervisor, shutdown)
        }
        fn core_socket<L: BusListener>(
            listener: &L,
        ) -> Result<Option<super::super::socket::SocketFile>, SdkError> {
            super::super::socket::SocketFile::new(listener)
        }
        let _ = core_accept::<StubListener>;
        let _ = core_socket::<StubListener>;
    }
}
