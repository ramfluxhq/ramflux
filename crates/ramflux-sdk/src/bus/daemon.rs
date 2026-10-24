// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

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
    super::connection::serve(config, shutdown).await
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
    std::fs::File::open(&accounts_dir)?.sync_all()?;
    std::fs::File::open(data_root)?.sync_all()?;
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
    client.account_index = state.account_index.clone();
    if state.account_index.is_some() {
        client.object_store.set_cache_capacity(8);
    }
    client.create_identity_root(&manifest.principal_id, manifest.root_seed);
    client.create_device_branch(
        &manifest.principal_id,
        &manifest.device_id,
        1,
        manifest.device_seed,
    );
    client.open_account_index(&state.config.data_root)?;
    if state.account_index.is_none() {
        client.set_active_account(&manifest.local_account_id)?;
    }
    let account_secret = passphrase_override.unwrap_or(&manifest.account_secret);
    client.unlock_account(&manifest.local_account_id, account_secret.as_bytes())?;
    if let (Some(id), Some(relay)) = (&manifest.node_id, &manifest.node_relay) {
        client.node_relay_options = Some(
            crate::node::profile_relay_options(
                id,
                relay,
                &manifest.gateway.ca_cert,
                &manifest.principal_id,
            )
            .await?,
        );
    }
    let mut gateway = GatewaySessionConfig::auto(manifest.gateway.clone()).with_device_branch(
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
    );
    if let Some(addr) = manifest.node_tcp_addr {
        gateway = gateway.with_tcp_gateway_addr(addr);
    }
    let mut account =
        LocalBusAccountState::disconnected(client, gateway, manifest.principal_commitment.clone());
    account.activation_pending = manifest.activation_pending;
    hydrate_local_bot_records(&mut account)?;
    hydrate_local_mcp_state(&mut account)?;
    hydrate_local_object_state(&mut account)?;
    // T25-A5 (OBJ-IPC-01): rehydrate durable-journaled in-flight UPLOAD spools so a mid-upload rfd
    // crash resumes from the durable offset instead of re-uploading from zero (replaces the blanket
    // startup sweep). Fail-closed per pair; never re-commits an object A2 already owns.
    rehydrate_object_put_spools(&mut account, &state.config.data_root, &manifest.local_account_id)?;
    state.accounts.insert(manifest.local_account_id.clone(), account);
    let account = local_bus_account_mut(state, &manifest.local_account_id)?;
    if connect_gateway && let Err(error) = account.ensure_gateway_live().await {
        tracing::warn!(account_id = %manifest.local_account_id,%error,"local bus account restored without live gateway session");
    }
    Ok(local_bus_account_response(manifest, account))
}

pub(crate) fn verify_local_bus_peer(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<(), SdkError> {
    let peer = stream.peer_cred()?;
    if peer.uid() == expected_uid { Ok(()) } else { Err(SdkError::LocalBusPermissionDenied) }
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
        method if method.starts_with("node.") => {
            crate::bus::dispatch::node::dispatch_node_bus_request(request, state).await
        }
        method if method.starts_with("account.") => {
            dispatch_account_bus_request(request, state).await
        }
        "surface.send" | "surface.action" => {
            crate::bus::dispatch::surface::dispatch_surface(request, state, connection).await
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
            Box::pin(dispatch_device_bus_request(request, state)).await
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

    use crate::bus::connection::{
        accept as serve_local_bus_accept_loop, handle as handle_local_bus_connection,
    };

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        std::env::temp_dir()
            .join(format!("ramflux-sdk-bus-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn test_state() -> Rc<crate::bus::supervisor::Supervisor> {
        let root = temp_root("fanout");
        let config = LocalBusConfig::new(root.join("bus.sock"), &root);
        let initialize: crate::bus::actor::AccountInitializer = Box::new(move |index| {
            let mut client = RamfluxClient::new();
            client.account_index = Some(index);
            client.create_identity_root("principal_fanout_test", [0x21; 32]);
            client.create_device_branch(
                "principal_fanout_test",
                "device_fanout_test",
                1,
                [0x22; 32],
            );
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
            Ok(LocalBusAccountState::disconnected(
                client,
                gateway,
                "principal_fanout_test".to_owned(),
            ))
        });
        crate::bus::supervisor::Supervisor::from_initializers(
            &config,
            vec![("acct".to_owned(), initialize)],
            Some("acct".to_owned()),
        )
        .expect("start test supervisor")
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
                    serde_json::json!({
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
                    serde_json::json!({
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
                    serde_json::json!({
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
                client.request(None, "daemon", "daemon.status", serde_json::json!({})),
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
            account_index: None,
            nodes: crate::node::NodeStore::default(),
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
            account_index: None,
            nodes: crate::node::NodeStore::default(),
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
