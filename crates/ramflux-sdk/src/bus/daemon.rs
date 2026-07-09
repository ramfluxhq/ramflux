// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

const LOCAL_BUS_OUTBOUND_CAPACITY: usize = 64;

pub async fn serve_local_bus(config: LocalBusConfig) -> Result<(), SdkError> {
    let (_sender, receiver) = watch::channel(false);
    serve_local_bus_until(config, receiver).await
}

/// # Errors
/// Returns an error when the daemon socket cannot be bound or a bus request fails.
pub async fn serve_local_bus_until(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new().name("ramflux-local-bus".to_owned()).spawn(move || {
        let result = run_local_bus_thread(config, shutdown);
        let _ = result_tx.send(result);
    })?;
    result_rx.await.map_err(|error| {
        SdkError::LocalBus(format!("local bus thread exited without result: {error}"))
    })?
}

fn run_local_bus_thread(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let local_set = LocalSet::new();
    local_set.block_on(&runtime, serve_local_bus_until_local(config, shutdown))
}

async fn serve_local_bus_until_local(
    config: LocalBusConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    std::fs::create_dir_all(&config.data_root)?;
    set_owner_only_dir_permissions(&config.data_root)?;
    if let Some(parent) = config.socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path)?;
    }
    let listener = UnixListener::bind(&config.socket_path)?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;
    let socket_uid = std::fs::metadata(&config.socket_path)?.uid();
    let mut state = LocalBusDaemonState {
        config,
        accounts: BTreeMap::new(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    hydrate_local_bus_accounts(&mut state).await?;
    let state = Rc::new(Mutex::new(state));
    serve_local_bus_accept_loop(listener, socket_uid, state, shutdown).await
}

async fn serve_local_bus_accept_loop(
    listener: UnixListener,
    socket_uid: u32,
    state: Rc<Mutex<LocalBusDaemonState>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    let mut next_connection_id = 1_u64;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    return Ok(());
                }
                if changed.is_err() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _addr) = accepted?;
                verify_local_bus_peer(&stream, socket_uid)?;
                let connection_id = next_connection_id;
                next_connection_id = next_connection_id.saturating_add(1);
                let state = Rc::clone(&state);
                tokio::task::spawn_local(async move {
                    let connection = Box::pin(handle_local_bus_connection(
                        stream,
                        state,
                        connection_id,
                    ));
                    if let Err(error) = connection.await {
                        tracing::warn!(%error, "local bus connection ended with error");
                    }
                });
            }
        }
    }
}

pub(crate) fn local_bus_accounts_dir(data_root: &Path) -> PathBuf {
    data_root.join("local_bus_accounts")
}

pub(crate) fn local_bus_account_manifest_path(data_root: &Path, local_account_id: &str) -> PathBuf {
    local_bus_accounts_dir(data_root).join(format!("{local_account_id}.json"))
}

pub(crate) fn set_owner_only_dir_permissions(path: &Path) -> Result<(), SdkError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn set_owner_only_file_permissions(path: &Path) -> Result<(), SdkError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(crate) fn read_local_bus_account_manifest(
    path: &Path,
) -> Result<LocalBusPersistedAccount, SdkError> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn write_local_bus_account_manifest(
    data_root: &Path,
    manifest: &LocalBusPersistedAccount,
) -> Result<(), SdkError> {
    let accounts_dir = local_bus_accounts_dir(data_root);
    std::fs::create_dir_all(&accounts_dir)?;
    set_owner_only_dir_permissions(&accounts_dir)?;
    let path = local_bus_account_manifest_path(data_root, &manifest.local_account_id);
    let tmp_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(manifest)?;
    if tmp_path.exists() {
        std::fs::remove_file(&tmp_path)?;
    }
    let mut tmp_file =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp_path)?;
    tmp_file.write_all(&bytes)?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    set_owner_only_file_permissions(&tmp_path)?;
    std::fs::rename(tmp_path, &path)?;
    set_owner_only_file_permissions(&path)?;
    Ok(())
}

pub(crate) async fn hydrate_local_bus_accounts(
    state: &mut LocalBusDaemonState,
) -> Result<(), SdkError> {
    let accounts_dir = local_bus_accounts_dir(&state.config.data_root);
    if !accounts_dir.exists() {
        return Ok(());
    }
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(accounts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
            match read_local_bus_account_manifest(&path) {
                Ok(manifest) => manifests.push(manifest),
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping unreadable local bus account manifest");
                }
            }
        }
    }
    manifests.sort_by(|left, right| left.local_account_id.cmp(&right.local_account_id));
    for manifest in manifests {
        match restore_local_bus_account(state, &manifest).await {
            Ok(response) => {
                state.active_account_id = Some(response.local_account_id);
            }
            Err(error) => {
                tracing::warn!(
                    account_id = %manifest.local_account_id,
                    %error,
                    "skipping local bus account manifest after local restore failure"
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn restore_local_bus_account(
    state: &mut LocalBusDaemonState,
    manifest: &LocalBusPersistedAccount,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    restore_local_bus_account_impl(state, manifest, true, None).await
}

pub(crate) async fn restore_local_bus_account_offline(
    state: &mut LocalBusDaemonState,
    manifest: &LocalBusPersistedAccount,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    restore_local_bus_account_impl(state, manifest, false, None).await
}

pub(crate) async fn restore_local_bus_account_with_passphrase(
    state: &mut LocalBusDaemonState,
    manifest: &LocalBusPersistedAccount,
    passphrase: &str,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    restore_local_bus_account_impl(state, manifest, true, Some(passphrase)).await
}

async fn restore_local_bus_account_impl(
    state: &mut LocalBusDaemonState,
    manifest: &LocalBusPersistedAccount,
    connect_gateway: bool,
    passphrase_override: Option<&str>,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root(&manifest.principal_id, manifest.root_seed);
    client.create_device_branch(
        &manifest.principal_id,
        &manifest.device_id,
        1,
        manifest.device_seed,
    );
    client.open_account_index(&state.config.data_root)?;
    client.set_active_account(&manifest.local_account_id)?;
    let account_secret = passphrase_override.unwrap_or(&manifest.account_secret);
    client.unlock_account(&manifest.local_account_id, account_secret.as_bytes())?;
    let gateway = GatewaySessionConfig::auto(manifest.gateway.clone()).with_device_branch(
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
    );
    let engine = if connect_gateway {
        match client.connect_gateway_session(gateway.clone()).await {
            Ok(engine) => Some(engine),
            Err(error) => {
                tracing::warn!(
                    account_id = %manifest.local_account_id,
                    %error,
                    "local bus account restored without live gateway session"
                );
                None
            }
        }
    } else {
        None
    };
    let response = LocalBusAccountCreateResponse {
        local_account_id: manifest.local_account_id.clone(),
        principal_id: manifest.principal_id.clone(),
        principal_commitment: manifest.principal_commitment.clone(),
        device_id: manifest.device_id.clone(),
        target_delivery_id: manifest.target_delivery_id.clone(),
        client_mode: manifest.client_mode.clone(),
        session_id: engine.as_ref().map_or_else(
            || "disconnected".to_owned(),
            |engine| engine.session().session_id.clone(),
        ),
        active_transport_kind: engine.as_ref().map_or_else(
            || "disconnected".to_owned(),
            |engine| engine.active_transport_kind().wire_name().to_owned(),
        ),
    };
    let mut account = match engine {
        Some(engine) => {
            LocalBusAccountState::new(client, engine, manifest.principal_commitment.clone())
        }
        None => LocalBusAccountState::disconnected(
            client,
            gateway,
            manifest.principal_commitment.clone(),
        ),
    };
    hydrate_local_bot_records(&mut account)?;
    hydrate_local_mcp_state(&mut account)?;
    hydrate_local_object_state(&mut account)?;
    state.accounts.insert(manifest.local_account_id.clone(), account);
    Ok(response)
}

pub(crate) fn verify_local_bus_peer(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<(), SdkError> {
    let peer = stream.peer_cred()?;
    if peer.uid() == expected_uid { Ok(()) } else { Err(SdkError::LocalBusPermissionDenied) }
}

pub(crate) async fn handle_local_bus_connection(
    stream: UnixStream,
    state: Rc<Mutex<LocalBusDaemonState>>,
    connection_id: u64,
) -> Result<(), SdkError> {
    let (mut reader, mut writer) = stream.into_split();
    let (outbound, mut outbound_rx) = mpsc::channel::<LocalBusFrame>(LOCAL_BUS_OUTBOUND_CAPACITY);
    let writer_task = tokio::task::spawn_local(async move {
        while let Some(frame) = outbound_rx.recv().await {
            local_bus_trace_frame("BUS-WRITE-IN", connection_id, &frame);
            write_local_bus_frame(&mut writer, &frame).await?;
            local_bus_trace_frame("BUS-WROTE", connection_id, &frame);
        }
        Ok::<(), SdkError>(())
    });
    let mut connection = LocalBusConnectionState::new(connection_id, outbound.clone());
    let result = loop {
        let request = match read_local_bus_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                break Ok(());
            }
            Err(error) => break Err(error),
        };
        local_bus_trace_frame("BUS-RX", connection.connection_id, &request);
        let (response, events) = {
            let mut state = state.lock().await;
            local_bus_trace_request("BUS-DISPATCH-IN", connection.connection_id, &request);
            let result =
                Box::pin(dispatch_local_bus_request(&request, &mut state, &mut connection)).await;
            local_bus_trace_request_ok(
                "BUS-DISPATCH-OUT",
                connection.connection_id,
                &request,
                result.is_ok(),
            );
            match result {
                Ok(LocalBusDispatchResult { response_body, event }) => {
                    let response = local_bus_response(&request, response_body);
                    let mut events = Vec::new();
                    if let Some(event) = event {
                        events.push(event);
                    }
                    events.extend(connection.drain_events());
                    (response, events)
                }
                Err(error) => {
                    let response = local_bus_error(&request, &error);
                    let events = connection.drain_events();
                    (response, events)
                }
            }
        };
        local_bus_trace_request("BUS-RESP-SEND-IN", connection.connection_id, &request);
        outbound.send(response).await.map_err(|_error| {
            SdkError::LocalBus("local bus outbound response channel closed".to_owned())
        })?;
        local_bus_trace_request("BUS-RESP-QUEUED", connection.connection_id, &request);
        if !events.is_empty() {
            local_bus_trace_request_events(
                "BUS-BROADCAST-IN",
                connection.connection_id,
                &request,
                events.len(),
            );
            state.lock().await.broadcast_events(&events);
            local_bus_trace_request_events(
                "BUS-BROADCAST-OUT",
                connection.connection_id,
                &request,
                events.len(),
            );
        }
    };
    {
        let mut state = state.lock().await;
        state.unregister_connection(connection.connection_id);
        if let Some(account_id) = connection.attended_account_id.take() {
            state.attended_accounts.remove(&account_id);
        }
    }
    drop(connection);
    drop(outbound);
    match writer_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if result.is_ok() {
                return Err(error);
            }
        }
        Err(error) => {
            if result.is_ok() {
                return Err(SdkError::LocalBus(format!("local bus writer task failed: {error}")));
            }
        }
    }
    result
}

fn local_bus_trace_frame(message: &str, connection_id: u64, frame: &LocalBusFrame) {
    local_bus_trace(
        message,
        format!(
            "conn={connection_id} kind={:?} method={} request_id={}",
            frame.kind, frame.method, frame.request_id
        ),
    );
}

fn local_bus_trace_request(message: &str, connection_id: u64, request: &LocalBusFrame) {
    local_bus_trace(
        message,
        format!("conn={connection_id} method={} request_id={}", request.method, request.request_id),
    );
}

fn local_bus_trace_request_ok(
    message: &str,
    connection_id: u64,
    request: &LocalBusFrame,
    ok: bool,
) {
    local_bus_trace(
        message,
        format!(
            "conn={connection_id} method={} request_id={} ok={ok}",
            request.method, request.request_id
        ),
    );
}

fn local_bus_trace_request_events(
    message: &str,
    connection_id: u64,
    request: &LocalBusFrame,
    events: usize,
) {
    local_bus_trace(
        message,
        format!(
            "conn={connection_id} method={} request_id={} events={events}",
            request.method, request.request_id
        ),
    );
}

pub(crate) struct LocalBusDispatchResult {
    pub(crate) response_body: serde_json::Value,
    pub(crate) event: Option<LocalBusFrame>,
}

pub(crate) async fn dispatch_local_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    if request.kind != LocalBusFrameKind::Request {
        return Err(SdkError::LocalBus("expected request frame".to_owned()));
    }
    match request.method.as_str() {
        "subscription.open" => {
            let body: LocalBusSubscriptionOpenRequest =
                serde_json::from_value(request.body.clone())?;
            if request
                .body
                .get("attended_frontend")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                let account_id = request_account_id(request)?.to_owned();
                state.attended_accounts.insert(account_id.clone());
                connection.attended_account_id = Some(account_id);
            }
            connection.topics.extend(body.topics);
            if let Some(account_id) = request.account_id.clone() {
                state.register_subscription(connection, account_id);
            }
            Ok(local_bus_ok(serde_json::json!({ "subscribed": true })))
        }
        method if method.starts_with("account.") => {
            dispatch_account_bus_request(request, state).await
        }
        method if method.starts_with("message.") => {
            Box::pin(dispatch_message_bus_request(request, state, connection)).await
        }
        method if method.starts_with("conversation.") => {
            Box::pin(dispatch_message_bus_request(request, state, connection)).await
        }
        method if method.starts_with("contact.") => {
            dispatch_contact_bus_request(request, state).await
        }
        method if method.starts_with("device.") => {
            dispatch_device_bus_request(request, state).await
        }
        method if method.starts_with("group.") => {
            Box::pin(dispatch_group_bus_request(request, state)).await
        }
        method if method.starts_with("object.") => {
            Box::pin(dispatch_object_bus_request(request, state)).await
        }
        method if method.starts_with("call.") => dispatch_call_bus_request(request, state),
        method if method.starts_with("bot.") => dispatch_bot_bus_request(request, state),
        method if method.starts_with("a2i.") => dispatch_a2i_bus_request(request, state).await,
        method if method.starts_with("a2ui.") => {
            dispatch_a2ui_bus_request(request, state, connection)
        }
        method if method.starts_with("mcp.") => {
            dispatch_mcp_bus_request(request, state, connection)
        }
        method if method.starts_with("grant.") => {
            dispatch_grant_bus_request(request, state, connection)
        }
        method if method.starts_with("daemon.") => dispatch_daemon_bus_request(request, state),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        std::env::temp_dir()
            .join(format!("ramflux-sdk-bus-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn test_state() -> Rc<Mutex<LocalBusDaemonState>> {
        let root = temp_root("fanout");
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_fanout_test", [0x21; 32]);
        client.create_device_branch("principal_fanout_test", "device_fanout_test", 1, [0x22; 32]);
        client.open_account_index(&root).expect("open account index");
        client.create_account("acct", "principal_fanout_test").expect("create account");
        client.set_active_account("acct").expect("set active account");
        client.unlock_account("acct", b"fanout-test-secret").expect("unlock account");
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("valid bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("valid gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_fanout_test".to_owned(),
            device_id: "device_fanout_test".to_owned(),
            target_delivery_id: "target_fanout_test".to_owned(),
            prekey_http_url: None,
        });
        Rc::new(Mutex::new(LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("bus.sock"), root),
            accounts: BTreeMap::from([(
                "acct".to_owned(),
                LocalBusAccountState::disconnected(
                    client,
                    gateway,
                    "principal_fanout_test".to_owned(),
                ),
            )]),
            active_account_id: Some("acct".to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }))
    }

    fn request(request_id: &str, method: &str, body: serde_json::Value) -> LocalBusFrame {
        LocalBusFrame::request(request_id, Some("acct".to_owned()), "mcp", method, body)
    }

    async fn send_request(
        stream: &mut UnixStream,
        request_id: &str,
        method: &str,
        body: serde_json::Value,
    ) -> LocalBusFrame {
        let frame = request(request_id, method, body);
        write_local_bus_frame(stream, &frame).await.expect("write request");
        loop {
            let response = read_local_bus_frame(stream).await.expect("read response");
            if response.request_id == request_id && response.kind != LocalBusFrameKind::Event {
                return response;
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_bus_fanout_pushes_mcp_approval_to_other_connection() {
        LocalSet::new()
            .run_until(async {
                let state = test_state();
                let (mut client_a, server_a) = UnixStream::pair().expect("pair a");
                let (mut client_b, server_b) = UnixStream::pair().expect("pair b");
                let task_a = tokio::task::spawn_local(handle_local_bus_connection(
                    server_a,
                    Rc::clone(&state),
                    1,
                ));
                let task_b = tokio::task::spawn_local(handle_local_bus_connection(
                    server_b,
                    Rc::clone(&state),
                    2,
                ));

                let subscribed = send_request(
                    &mut client_a,
                    "req_sub",
                    "subscription.open",
                    serde_json::json!({
                        "topics": ["mcp.approval.request"],
                        "attended_frontend": true,
                    }),
                )
                .await;
                assert_eq!(subscribed.kind, LocalBusFrameKind::Response);

                let added = send_request(
                    &mut client_b,
                    "req_add",
                    "mcp.server.add",
                    serde_json::json!({
                        "server_id": "srv",
                        "command": "stdio",
                        "tool_name": "echo",
                        "capability": "external_tool_invoke",
                        "tool_scope": "echo",
                        "risk_level": "low",
                    }),
                )
                .await;
                assert_eq!(added.kind, LocalBusFrameKind::Response);

                let call = send_request(
                    &mut client_b,
                    "req_call",
                    "mcp.tool.started",
                    serde_json::json!({
                        "server_id": "srv",
                        "tool_name": "echo",
                        "arguments": {"text": "hello"},
                        "operation_origin": "ai_mcp",
                    }),
                )
                .await;
                assert_eq!(call.body["status"], "approval_required");

                let event = tokio::time::timeout(
                    Duration::from_secs(1),
                    read_local_bus_frame(&mut client_a),
                )
                .await
                .expect("fanout event timed out")
                .expect("fanout event read");
                assert_eq!(event.kind, LocalBusFrameKind::Event);
                assert_eq!(event.method, "mcp.approval.request");
                assert_eq!(event.body["event_type"], "mcp.approval.request");
                assert_eq!(
                    event.body["tool_manifest_set_hash"],
                    added.body["tool_manifest_set_hash"]
                );

                drop(client_a);
                drop(client_b);
                task_a.await.expect("task a join").expect("task a ok");
                task_b.await.expect("task b join").expect("task b ok");
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_bus_daemon_accept_loop_fans_out_mcp_approval_to_second_socket_client() {
        let temp_root = std::env::temp_dir().join(format!(
            "rfmf_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        let socket_path = temp_root.join("rfd.sock");
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let listener = UnixListener::bind(&socket_path).expect("bind test local bus socket");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("set socket permissions");
        let socket_uid = std::fs::metadata(&socket_path).expect("socket metadata").uid();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let local_set = LocalSet::new();
        let server = local_set.run_until(serve_local_bus_accept_loop(
            listener,
            socket_uid,
            test_state(),
            shutdown_rx,
        ));
        let client_flow = async {
            let mut subscriber = connect_test_client(&socket_path).await;
            let mut actor = connect_test_client(&socket_path).await;

            timeout_bus_request(
                "subscription.open",
                subscriber.request(
                    Some("acct".to_owned()),
                    "subscription",
                    "subscription.open",
                    &serde_json::json!({
                        "topics": ["mcp.approval.request"],
                        "attended_frontend": true,
                    }),
                ),
            )
            .await;
            let added = timeout_bus_request(
                "mcp.server.add",
                actor.request(
                    Some("acct".to_owned()),
                    "mcp",
                    "mcp.server.add",
                    &serde_json::json!({
                        "server_id": "srv",
                        "command": "stdio",
                        "tool_name": "echo",
                        "capability": "external_tool_invoke",
                        "tool_scope": "echo",
                        "risk_level": "low",
                    }),
                ),
            )
            .await;
            let call = timeout_bus_request(
                "mcp.tool.started",
                actor.request(
                    Some("acct".to_owned()),
                    "mcp",
                    "mcp.tool.started",
                    &serde_json::json!({
                        "server_id": "srv",
                        "tool_name": "echo",
                        "arguments": {"text": "hello"},
                        "operation_origin": "ai_mcp",
                    }),
                ),
            )
            .await;
            assert_eq!(call["status"], "approval_required");
            let event = tokio::time::timeout(Duration::from_secs(2), subscriber.next_event())
                .await
                .expect("fanout event timed out")
                .expect("fanout event read");
            assert_eq!(event.method, "mcp.approval.request");
            assert_eq!(event.body["event_type"], "mcp.approval.request");
            assert_eq!(
                event.body["tool_manifest_set_hash"],
                call["approval"]["details"]["tool_manifest_set_hash"]
            );
            assert_eq!(event.body["tool_manifest_set_hash"], added["tool_manifest_set_hash"]);
            shutdown_tx.send(true).expect("shutdown daemon");
        };
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let (server_result, ()) = tokio::join!(server, client_flow);
            server_result.expect("server result");
        })
        .await;
        let _ = std::fs::remove_dir_all(&temp_root);
        result.expect("daemon accept-loop MCP fanout flow timed out");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_bus_public_entry_runs_on_dedicated_local_runtime_thread() {
        let temp_root = std::env::temp_dir().join(format!(
            "rfle_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        let socket_path = temp_root.join("rfd.sock");
        let data_root = temp_root.join("data");
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server =
            serve_local_bus_until(LocalBusConfig::new(&socket_path, data_root), shutdown_rx);
        let client_flow = async {
            let mut client = connect_test_client(&socket_path).await;
            let status = timeout_bus_request(
                "daemon.status",
                client.request(None, "daemon", "daemon.status", &serde_json::json!({})),
            )
            .await;
            assert_eq!(status["accounts"], 0);
            assert_eq!(
                status["socket_path"].as_str(),
                Some(socket_path.to_string_lossy().as_ref())
            );
            shutdown_tx.send(true).expect("shutdown daemon");
        };
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let (server_result, ()) = tokio::join!(server, client_flow);
            server_result.expect("server result");
        })
        .await;
        let _ = std::fs::remove_dir_all(&temp_root);
        result.expect("public local bus entry flow timed out");
    }

    async fn connect_test_client(socket_path: &Path) -> LocalBusClient {
        for _attempt in 0..500 {
            match LocalBusClient::connect(socket_path).await {
                Ok(client) => return client,
                Err(_error) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("timed out connecting test local bus client");
    }

    async fn timeout_bus_request<'a>(
        label: &'static str,
        request: impl Future<Output = Result<serde_json::Value, SdkError>> + 'a,
    ) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .unwrap_or_else(|_elapsed| panic!("{label} timed out"))
            .unwrap_or_else(|error| panic!("{label} failed: {error}"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_bus_backpressure_removes_slow_subscriber_without_blocking() {
        let (outbound, mut inbound) = mpsc::channel(1);
        let mut state = LocalBusDaemonState {
            config: LocalBusConfig::new("bus.sock", "data"),
            accounts: BTreeMap::new(),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::from([(
                7,
                LocalBusSubscriber {
                    account_id: "acct".to_owned(),
                    topics: BTreeSet::from(["mcp.approval.request".to_owned()]),
                    outbound,
                },
            )]),
        };
        let event = local_bus_event(
            &request("req", "mcp.tool.started", serde_json::json!({})),
            "acct",
            "mcp",
            "mcp.approval.request",
            serde_json::json!({"event_type": "mcp.approval.request"}),
        );
        state.broadcast_events(&[event.clone(), event]);
        assert!(state.subscribers.is_empty());
        assert_eq!(
            inbound.try_recv().expect("first event delivered").method,
            "mcp.approval.request"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_bus_unregister_removes_subscription() {
        let (outbound, mut inbound) = mpsc::channel(1);
        let mut state = LocalBusDaemonState {
            config: LocalBusConfig::new("bus.sock", "data"),
            accounts: BTreeMap::new(),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::from([(
                9,
                LocalBusSubscriber {
                    account_id: "acct".to_owned(),
                    topics: BTreeSet::from(["mcp.approval.request".to_owned()]),
                    outbound,
                },
            )]),
        };
        state.unregister_connection(9);
        let event = local_bus_event(
            &request("req", "mcp.tool.started", serde_json::json!({})),
            "acct",
            "mcp",
            "mcp.approval.request",
            serde_json::json!({"event_type": "mcp.approval.request"}),
        );
        state.broadcast_events(&[event]);
        assert!(matches!(
            inbound.try_recv(),
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
