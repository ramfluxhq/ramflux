// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

const ACCOUNT_ID: &str = "acct_mcp";
const PRINCIPAL_ID: &str = "principal_mcp_test";
const DEVICE_ID: &str = "device_mcp_test";
const FUTURE_EXPIRES_AT: i64 = 4_000_000_000;

fn gateway_config() -> GatewaySessionConfig {
    GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().expect("valid bind addr"),
        gateway_addr: "127.0.0.1:1".parse().expect("valid gateway addr"),
        server_name: "ramflux-gateway".to_owned(),
        ca_cert: PathBuf::from("ca.pem"),
        principal_id: PRINCIPAL_ID.to_owned(),
        device_id: DEVICE_ID.to_owned(),
        target_delivery_id: "target_mcp_test".to_owned(),
        prekey_http_url: None,
    })
}

fn unlocked_client(root: &Path) -> RamfluxClient {
    let mut client = RamfluxClient::new();
    client.create_identity_root(PRINCIPAL_ID, [0x11; 32]);
    client.create_device_branch(PRINCIPAL_ID, DEVICE_ID, 1, [0x12; 32]);
    client.open_account_index(root).expect("open account index");
    client.set_active_account(ACCOUNT_ID).expect("set active account");
    client.unlock_account(ACCOUNT_ID, b"mcp-test-secret").expect("unlock account");
    client
}

fn test_state_named(test_name: &str) -> (tempfile::TempDir, LocalBusDaemonState) {
    let temp = tempfile::Builder::new()
        .prefix(&format!("ramflux-sdk-mcp-{test_name}-"))
        .tempdir()
        .expect("test: create MCP directory");
    let root = temp.path().to_path_buf();
    let mut client = RamfluxClient::new();
    client.create_identity_root(PRINCIPAL_ID, [0x11; 32]);
    client.create_device_branch(PRINCIPAL_ID, DEVICE_ID, 1, [0x12; 32]);
    client.open_account_index(&root).expect("open account index");
    client.create_account(ACCOUNT_ID, "principal_mcp_test").expect("create account");
    client.set_active_account(ACCOUNT_ID).expect("set active account");
    client.unlock_account(ACCOUNT_ID, b"mcp-test-secret").expect("unlock account");
    let gateway = gateway_config();
    let account =
        LocalBusAccountState::disconnected(client, gateway, "principal_mcp_test".to_owned());
    (
        temp,
        LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(root.join("bus.sock"), root.clone()),
            accounts: BTreeMap::from([(ACCOUNT_ID.to_owned(), account)]),
            active_account_id: Some(ACCOUNT_ID.to_owned()),
            attended_accounts: BTreeSet::from([ACCOUNT_ID.to_owned()]),
            subscribers: BTreeMap::new(),
        },
    )
}

fn test_state() -> (tempfile::TempDir, LocalBusDaemonState) {
    test_state_named("grant-mcp")
}

fn test_connection(connection_id: u64) -> LocalBusConnectionState {
    let (outbound, _inbound) = mpsc::channel(8);
    LocalBusConnectionState::new(connection_id, outbound)
}

fn request(method: &str, body: serde_json::Value) -> LocalBusFrame {
    LocalBusFrame::request("req_test", Some(ACCOUNT_ID.to_owned()), "mcp", method, body)
}

fn install_tool(
    state: &mut LocalBusDaemonState,
    server_id: &str,
    tool_name: &str,
    capability: McpCapability,
    tool_scope: Option<&str>,
    risk_level: RiskLevel,
) {
    let mut connection = test_connection(1);
    let frame = request(
        "mcp.server.add",
        serde_json::json!({
            "server_id": server_id,
            "command": "stdio",
            "tool_name": tool_name,
            "capability": capability,
            "tool_scope": tool_scope,
            "risk_level": risk_level,
        }),
    );
    dispatch_mcp_bus_request(&frame, state, &mut connection).expect("install tool");
}

fn account(state: &LocalBusDaemonState) -> &LocalBusAccountState {
    state.accounts.get(ACCOUNT_ID).expect("test account exists")
}

fn account_mut(state: &mut LocalBusDaemonState) -> &mut LocalBusAccountState {
    state.accounts.get_mut(ACCOUNT_ID).expect("test account exists")
}

#[test]
fn mcp_approval_request_event_and_audit_are_canonical() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "echo",
        McpCapability::ReadConversation,
        Some("echo"),
        RiskLevel::Low,
    );
    let mut connection = test_connection(1);
    connection.topics.insert("mcp.approval.request".to_owned());
    let frame = request(
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "echo",
            "arguments": {"text": "hello"},
            "operation_origin": "ai_mcp",
        }),
    );
    let result = dispatch_mcp_bus_request(&frame, &mut state, &mut connection).expect("tool call");
    assert_eq!(result.response_body["status"], "approval_required");
    let events = connection.drain_events();
    let approval_event = events
        .iter()
        .find(|event| event.method == "mcp.approval.request")
        .expect("approval request event");
    assert_eq!(approval_event.body["event_type"], "mcp.approval.request");
    assert_eq!(approval_event.body["registry_hash"], account(&state).mcp_registry.registry_hash());
    assert_eq!(
        approval_event.body["tool_manifest_set_hash"],
        account(&state).mcp_registry.tool_manifest_set_hash()
    );
    assert!(
        account(&state)
            .mcp_audit_log
            .iter()
            .any(|record| record.event_type == "mcp.approval.request"
                && record.event_body == approval_event.body)
    );
}

#[test]
fn mcp_approval_granted_and_denied_events_are_canonical() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "echo",
        McpCapability::ReadConversation,
        Some("echo"),
        RiskLevel::Low,
    );
    let create = request(
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "echo",
            "arguments": {},
            "operation_origin": "ai_mcp",
        }),
    );
    let mut create_connection = test_connection(1);
    let approval = dispatch_mcp_bus_request(&create, &mut state, &mut create_connection)
        .expect("create approval")
        .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id");

    let mut grant_connection = test_connection(2);
    grant_connection.topics.insert("mcp.approval.granted".to_owned());
    let grant = request("grant.approve", serde_json::json!({ "approval_id": approval_id }));
    dispatch_grant_bus_request(&grant, &mut state, &mut grant_connection).expect("approve grant");
    let granted = grant_connection.drain_events();
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].method, "mcp.approval.granted");
    assert_eq!(granted[0].body["event_type"], "mcp.approval.granted");
    assert!(
        granted[0].body["tool_manifest_set_hash"]
            .as_str()
            .is_some_and(|hash| { hash == account(&state).mcp_registry.tool_manifest_set_hash() })
    );

    let create_second = request(
        "grant.request",
        serde_json::json!({
            "grant_id": "grant_deny",
            "server_id": "srv",
            "tool_name": "echo",
            "capability": serde_json::Value::Null,
            "full_delegation": false,
        }),
    );
    let mut request_connection = test_connection(3);
    let denial_approval =
        dispatch_grant_bus_request(&create_second, &mut state, &mut request_connection)
            .expect("create denial approval")
            .response_body["approval"]
            .clone();
    let denial_id = denial_approval["approval_id"].as_str().expect("denial id");
    let mut deny_connection = test_connection(4);
    deny_connection.topics.insert("mcp.approval.denied".to_owned());
    let deny = request("grant.deny", serde_json::json!({ "approval_id": denial_id }));
    dispatch_grant_bus_request(&deny, &mut state, &mut deny_connection).expect("deny grant");
    let denied = deny_connection.drain_events();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].method, "mcp.approval.denied");
    assert_eq!(denied[0].body["event_type"], "mcp.approval.denied");
    assert_eq!(denied[0].body["status"], "denied");
}

#[test]
fn mcp_registry_grant_and_audit_survive_account_reload() {
    let (temp, mut state) = test_state_named("mcp-reload");
    let root = temp.path().to_path_buf();
    install_tool(
        &mut state,
        "srv",
        "notes",
        McpCapability::ReadConversation,
        Some("thread:1"),
        RiskLevel::Low,
    );
    let registry_hash = account(&state).mcp_registry.registry_hash().to_owned();
    let tool_manifest_set_hash = account(&state).mcp_registry.tool_manifest_set_hash().to_owned();
    let started = request(
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "notes",
            "arguments": {"text": "hello"},
            "operation_origin": "ai_mcp",
        }),
    );
    let pending = dispatch_mcp_bus_request(&started, &mut state, &mut test_connection(1))
        .expect("first tool call creates approval");
    assert_eq!(pending.response_body["status"], "approval_required");
    let approval_id =
        pending.response_body["approval"]["approval_id"].as_str().expect("approval id").to_owned();
    let approved = dispatch_grant_bus_request(
        &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
        &mut state,
        &mut test_connection(2),
    )
    .expect("approve grant");
    assert_eq!(approved.response_body["state"]["revoked"], false);
    assert!(
        account(&state)
            .mcp_audit_log
            .iter()
            .any(|record| record.event_type == "mcp.approval.granted")
    );

    let restored_client = unlocked_client(&root);
    let mut restored_account = LocalBusAccountState::disconnected(
        restored_client,
        gateway_config(),
        "principal_mcp_test".to_owned(),
    );
    hydrate_local_mcp_state(&mut restored_account).expect("hydrate mcp state");
    assert_eq!(restored_account.mcp_registry.registry_hash(), registry_hash);
    assert_eq!(restored_account.mcp_registry.tool_manifest_set_hash(), tool_manifest_set_hash);
    assert_eq!(restored_account.mcp_grants.len(), 1);
    assert!(
        restored_account
            .mcp_audit_log
            .iter()
            .any(|record| record.event_type == "mcp.approval.request")
    );

    let mut restored_state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus-restored.sock"), root),
        accounts: BTreeMap::from([(ACCOUNT_ID.to_owned(), restored_account)]),
        active_account_id: Some(ACCOUNT_ID.to_owned()),
        attended_accounts: BTreeSet::from([ACCOUNT_ID.to_owned()]),
        subscribers: BTreeMap::new(),
    };
    let invoked = dispatch_mcp_bus_request(&started, &mut restored_state, &mut test_connection(3))
        .expect("authorized invoke after reload");
    assert_eq!(invoked.response_body["status"], "ok");
    assert_eq!(invoked.response_body["result"], "srv:notes");
}

#[test]
fn mcp_standing_auto_approval_allows_low_risk_and_survives_reload() {
    let (temp, mut state) = test_state_named("mcp-standing");
    let root = temp.path().to_path_buf();
    install_tool(
        &mut state,
        "srv",
        "notes",
        McpCapability::ReadConversation,
        Some("thread:standing"),
        RiskLevel::Low,
    );
    let create = request(
        "grant.create_standing_approval",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "notes",
            "tool_scope": "thread:standing",
            "ttl_seconds": 3600,
        }),
    );
    let standing = dispatch_grant_bus_request(&create, &mut state, &mut test_connection(1))
        .expect("create standing approval")
        .response_body;
    assert_eq!(standing["server_id"], "srv");
    assert_eq!(standing["tool_name"], "notes");
    assert_eq!(standing["revoked"], false);

    let started = request(
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "notes",
            "arguments": {"text": "auto"},
            "operation_origin": "ai_mcp",
        }),
    );
    let mut invoke_connection = test_connection(2);
    invoke_connection.topics.insert("mcp.standing_auto_approval.invoked".to_owned());
    let invoked = dispatch_mcp_bus_request(&started, &mut state, &mut invoke_connection)
        .expect("standing invoke");
    assert_eq!(invoked.response_body["status"], "ok");
    assert_eq!(invoked.response_body["standing_approval_id"], standing["standing_approval_id"]);
    assert!(account(&state).mcp_pending_approvals.is_empty());
    assert!(
        account(&state)
            .mcp_audit_log
            .iter()
            .any(|record| record.event_type == "mcp.standing_auto_approval.invoked"
                && record.outcome == "allowed")
    );

    let restored_client = unlocked_client(&root);
    let mut restored_account = LocalBusAccountState::disconnected(
        restored_client,
        gateway_config(),
        "principal_mcp_test".to_owned(),
    );
    hydrate_local_mcp_state(&mut restored_account).expect("hydrate mcp state");
    assert_eq!(restored_account.mcp_standing_approvals.len(), 1);
    let mut restored_state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus-restored.sock"), root),
        accounts: BTreeMap::from([(ACCOUNT_ID.to_owned(), restored_account)]),
        active_account_id: Some(ACCOUNT_ID.to_owned()),
        attended_accounts: BTreeSet::from([ACCOUNT_ID.to_owned()]),
        subscribers: BTreeMap::new(),
    };
    let restored_invoked =
        dispatch_mcp_bus_request(&started, &mut restored_state, &mut test_connection(3))
            .expect("standing invoke after reload");
    assert_eq!(restored_invoked.response_body["status"], "ok");
    assert!(account(&restored_state).mcp_pending_approvals.is_empty());
}

#[test]
fn mcp_standing_auto_approval_respects_risk_floor_revoke_and_expiry() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "notes",
        McpCapability::ReadConversation,
        Some("thread:standing"),
        RiskLevel::Low,
    );
    install_tool(
        &mut state,
        "srv",
        "shell",
        McpCapability::ExternalToolInvoke,
        Some("shell"),
        RiskLevel::High,
    );
    let create = request(
        "grant.create_standing_approval",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "notes",
            "tool_scope": "thread:standing",
        }),
    );
    let standing = dispatch_grant_bus_request(&create, &mut state, &mut test_connection(1))
        .expect("create standing")
        .response_body;
    let standing_id = standing["standing_approval_id"].as_str().expect("standing id").to_owned();

    let revoke = request(
        "grant.revoke_standing_approval",
        serde_json::json!({ "standing_approval_id": standing_id }),
    );
    dispatch_grant_bus_request(&revoke, &mut state, &mut test_connection(2))
        .expect("revoke standing");
    let started = request(
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "notes",
            "arguments": {},
            "operation_origin": "ai_mcp",
        }),
    );
    let revoked_result = dispatch_mcp_bus_request(&started, &mut state, &mut test_connection(3))
        .expect("revoked standing falls back to approval");
    assert_eq!(revoked_result.response_body["status"], "approval_required");

    let create_expiring = request(
        "grant.create_standing_approval",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "notes",
            "tool_scope": "thread:standing",
            "ttl_seconds": 1,
        }),
    );
    let expiring =
        dispatch_grant_bus_request(&create_expiring, &mut state, &mut test_connection(4))
            .expect("create expiring standing")
            .response_body["standing_approval_id"]
            .as_str()
            .expect("expiring standing id")
            .to_owned();
    account_mut(&mut state)
        .mcp_standing_approvals
        .get_mut(&expiring)
        .expect("expiring standing")
        .expires_at = 1;
    let expired_result = dispatch_mcp_bus_request(&started, &mut state, &mut test_connection(5))
        .expect("expired standing falls back to approval");
    assert_eq!(expired_result.response_body["status"], "approval_required");

    let high_create = request(
        "grant.create_standing_approval",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "shell",
            "tool_scope": "shell",
        }),
    );
    let high_rejected =
        dispatch_grant_bus_request(&high_create, &mut state, &mut test_connection(6));
    assert!(matches!(high_rejected, Err(SdkError::CapabilityDenied(_))));
    let high_call = request(
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv",
            "tool_name": "shell",
            "arguments": {"cmd": "echo nope"},
            "operation_origin": "ai_mcp",
        }),
    );
    let high_result = dispatch_mcp_bus_request(&high_call, &mut state, &mut test_connection(7))
        .expect("high risk still requires approval");
    assert_eq!(high_result.response_body["status"], "approval_required");
    assert_eq!(high_result.response_body["approval"]["confirmation_mode"], "remote_app");
}

#[test]
fn high_and_critical_mcp_grants_are_single_use_remote_app_confirmations() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "shell",
        McpCapability::RunShell,
        Some("shell"),
        RiskLevel::High,
    );
    install_tool(
        &mut state,
        "srv",
        "node_admin",
        McpCapability::ManageNode,
        Some("node"),
        RiskLevel::Critical,
    );

    let high_approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "shell",
                "arguments": {"cmd": "echo hello"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(1),
    )
    .expect("create high approval")
    .response_body["approval"]
        .clone();
    assert_eq!(high_approval["confirmation_mode"], "remote_app");
    assert_eq!(high_approval["details"]["single_use"], true);
    let high_grant = sign_test_remote_grant(&state, &high_approval);
    dispatch_mcp_bus_request(
        &request("mcp.approval.granted", serde_json::to_value(high_grant).expect("grant json")),
        &mut state,
        &mut test_connection(2),
    )
    .expect("approve high grant");

    let first = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "shell",
                "arguments": {"cmd": "echo hello"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(3),
    )
    .expect("single-use high grant should allow one matching invoke");
    assert_eq!(first.response_body["status"], "ok");
    let grant_id = high_approval["details"]["requested_grant_id"].as_str().map_or_else(
        || format!("grant_{}", high_approval["approval_id"].as_str().expect("approval id")),
        str::to_owned,
    );
    assert!(
        account(&state).mcp_grants.get(&grant_id).is_some_and(|grant| grant.state.revoked),
        "single-use high grant must be consumed after first invoke"
    );

    let second = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "shell",
                "arguments": {"cmd": "echo hello"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(4),
    )
    .expect("consumed high grant should require a fresh approval");
    assert_eq!(second.response_body["status"], "approval_required");
    assert_eq!(second.response_body["approval"]["confirmation_mode"], "remote_app");

    let critical = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "node_admin",
                "arguments": {"op": "rotate-node-key"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(5),
    )
    .expect("create critical approval");
    assert_eq!(critical.response_body["approval"]["risk_level"], "critical");
    assert_eq!(critical.response_body["approval"]["details"]["single_use"], true);
}

fn sign_test_remote_grant(
    state: &LocalBusDaemonState,
    approval: &serde_json::Value,
) -> LocalBusMcpApprovalGrantRequest {
    let approval: LocalMcpApprovalRecord =
        serde_json::from_value(approval.clone()).expect("approval record");
    let body = mcp_grant_signing_body(account(state), &approval).expect("signing body");
    let branch =
        ramflux_crypto::create_device_branch(PRINCIPAL_ID, "app_device_mcp_test", 1, [0xA6; 32]);
    let signature = ramflux_crypto::sign_with_device_branch(&branch, &body).expect("signature");
    LocalBusMcpApprovalGrantRequest {
        approval_id: approval.approval_id,
        signed_by_device_id: branch.device_id.clone(),
        signer_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        signature,
    }
}

#[test]
fn mcp_grant_signature_uses_stored_approval_expiry() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "notes",
        McpCapability::ReadConversation,
        Some("thread:expiry"),
        RiskLevel::Low,
    );
    let approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(1),
    )
    .expect("create approval")
    .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id");
    let approval_expires_at = approval["expires_at"].as_i64().expect("approval expires_at");
    assert!(approval_expires_at > now_unix_timestamp());

    let grant: LocalMcpGrantRecord = serde_json::from_value(
        dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut test_connection(2),
        )
        .expect("approve grant")
        .response_body,
    )
    .expect("grant record");

    assert_eq!(grant.signing_body.expires_at, approval_expires_at);
    assert_eq!(grant.state.expires_at, approval_expires_at);
    assert!(mcp_verify_grant_signature(&grant).is_ok());
}

#[test]
fn expired_mcp_grant_is_rejected_even_with_valid_signature() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "notes",
        McpCapability::ReadConversation,
        Some("thread:expired"),
        RiskLevel::Low,
    );
    let approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(1),
    )
    .expect("create approval")
    .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id").to_owned();
    let expired_at = now_unix_timestamp().saturating_sub(1);
    let pending = account_mut(&mut state)
        .mcp_pending_approvals
        .get_mut(&approval_id)
        .expect("pending approval");
    pending.expires_at = expired_at;
    pending.details["expires_at"] = serde_json::json!(expired_at);

    let grant: LocalMcpGrantRecord = serde_json::from_value(
        dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut test_connection(2),
        )
        .expect("approve expired grant")
        .response_body,
    )
    .expect("expired grant record");
    assert_eq!(grant.signing_body.expires_at, expired_at);
    assert!(mcp_verify_grant_signature(&grant).is_ok());

    let error = match dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(3),
    ) {
        Ok(_) => panic!("expired grant must not authorize invoke"),
        Err(error) => error,
    };
    assert!(matches!(error, SdkError::GrantInvalidated));
}

#[test]
fn mcp_tool_started_completed_and_failed_events_are_canonical() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "echo",
        McpCapability::ReadConversation,
        Some("echo"),
        RiskLevel::Low,
    );
    let mut create_connection = test_connection(1);
    let approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut create_connection,
    )
    .expect("create approval")
    .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id");
    let mut approve_connection = test_connection(2);
    dispatch_grant_bus_request(
        &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
        &mut state,
        &mut approve_connection,
    )
    .expect("approve grant");

    let mut connection = test_connection(3);
    connection.topics.extend([
        "mcp.tool.started".to_owned(),
        "mcp.tool.completed".to_owned(),
        "mcp.tool.failed".to_owned(),
    ]);
    let granted_result = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {"text": "ok"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut connection,
    )
    .expect("invoke granted tool");
    assert_eq!(granted_result.response_body["status"], "ok");
    assert_eq!(granted_result.response_body["result"], "srv:echo");
    assert_eq!(granted_result.response_body["output"]["echo"]["text"], "ok");
    let events = connection.drain_events();
    assert_eq!(
        events.iter().map(|event| event.method.as_str()).collect::<Vec<_>>(),
        ["mcp.tool.started", "mcp.tool.completed",]
    );
    assert!(events.iter().all(|event| event.body["tool_manifest_set_hash"]
        == account(&state).mcp_registry.tool_manifest_set_hash()));

    install_tool(&mut state, "srv", "shell", McpCapability::RunShell, None, RiskLevel::High);
    let registry_hash = account(&state).mcp_registry.registry_hash().to_owned();
    let tool_manifest_set_hash = account(&state).mcp_registry.tool_manifest_set_hash().to_owned();
    account_mut(&mut state).mcp_grants.insert(
        "grant_full".to_owned(),
        LocalMcpGrantRecord {
            grant_id: "grant_full".to_owned(),
            state: McpGrantState {
                server_id: "wildcard".to_owned(),
                tool_name: "wildcard".to_owned(),
                tool_scope: Some("wildcard".to_owned()),
                registry_hash: registry_hash.clone(),
                tool_manifest_set_hash: tool_manifest_set_hash.clone(),
                full_delegation: true,
                allowed_capabilities: BTreeSet::new(),
                revoked: false,
                expires_at: FUTURE_EXPIRES_AT,
            },
            signed_by_device_id: "device_mcp_test".to_owned(),
            signer_public_key: String::new(),
            signature: String::new(),
            signing_body: LocalMcpGrantSigningBody {
                task_binding: None,
                approval_id: "approval_full".to_owned(),
                grant_id: "grant_full".to_owned(),
                server_id: "wildcard".to_owned(),
                tool_name: "wildcard".to_owned(),
                tool_scope: Some("wildcard".to_owned()),
                capability: McpCapability::ExternalToolInvoke,
                registry_hash,
                tool_manifest_set_hash,
                full_delegation: true,
                single_use: false,
                arguments_hash: None,
                expires_at: FUTURE_EXPIRES_AT,
            },
            confirmation_mode: "remote_app".to_owned(),
        },
    );
    let mut failed_connection = test_connection(4);
    failed_connection.topics.extend(["mcp.tool.started".to_owned(), "mcp.tool.failed".to_owned()]);
    let error = match dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "shell",
                "arguments": {"cmd": "id"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut failed_connection,
    ) {
        Ok(_) => panic!("high-risk full delegation unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, SdkError::CapabilityDenied(_)));
    let failed = failed_connection.drain_events();
    assert_eq!(
        failed.iter().map(|event| event.method.as_str()).collect::<Vec<_>>(),
        ["mcp.tool.started", "mcp.tool.failed",]
    );
    assert_eq!(failed[1].body["error"]["code"], "CapabilityDenied");
}

#[test]
fn mcp_valid_grant_wins_over_stale_grant_for_same_capability() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "echo",
        McpCapability::ReadConversation,
        Some("echo"),
        RiskLevel::Low,
    );
    let approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {"text": "needs approval"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(1),
    )
    .expect("create approval")
    .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id");
    let approved = dispatch_grant_bus_request(
        &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
        &mut state,
        &mut test_connection(2),
    )
    .expect("approve grant")
    .response_body;
    let valid_grant: LocalMcpGrantRecord =
        serde_json::from_value(approved).expect("valid grant json");
    let mut stale_grant = valid_grant;
    stale_grant.grant_id = "aaa_stale_grant".to_owned();
    stale_grant.state.tool_manifest_set_hash = "stale_manifest_hash".to_owned();
    stale_grant.signing_body.tool_manifest_set_hash = "stale_manifest_hash".to_owned();
    account_mut(&mut state).mcp_grants.insert(stale_grant.grant_id.clone(), stale_grant);

    let result = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {"text": "ok"},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(3),
    )
    .expect("valid grant should not be shadowed by stale grant");
    assert_eq!(result.response_body["status"], "ok");
    assert_eq!(result.response_body["result"], "srv:echo");
}

#[test]
fn mcp_server_add_clamps_low_risk_override_for_high_default_capability() {
    let (_temp, mut state) = test_state();
    install_tool(&mut state, "srv", "shell", McpCapability::RunShell, None, RiskLevel::Low);
    let manifest = account(&state)
        .mcp_registry
        .tools()
        .into_iter()
        .find(|tool| tool.server_id == "srv" && tool.tool_name == "shell")
        .expect("stored shell manifest");
    assert_eq!(manifest.declared_risk, RiskLevel::High);
    assert_eq!(manifest.effective_risk(), RiskLevel::High);
}

#[test]
fn mcp_grant_scope_does_not_cover_other_tool_with_same_capability() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv_a",
        "tool_x",
        McpCapability::ReadConversation,
        Some("thread_a"),
        RiskLevel::Low,
    );
    install_tool(
        &mut state,
        "srv_b",
        "tool_y",
        McpCapability::ReadConversation,
        Some("thread_b"),
        RiskLevel::Low,
    );
    let approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv_a",
                "tool_name": "tool_x",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(1),
    )
    .expect("create scoped approval")
    .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id");
    dispatch_grant_bus_request(
        &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
        &mut state,
        &mut test_connection(2),
    )
    .expect("approve scoped grant");

    let result = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv_b",
                "tool_name": "tool_y",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(3),
    )
    .expect("other tool should require its own approval");
    assert_eq!(result.response_body["status"], "approval_required");
}

#[test]
fn mcp_grant_scope_is_covered_by_device_signature() {
    let (_temp, mut state) = test_state();
    install_tool(
        &mut state,
        "srv",
        "echo",
        McpCapability::ReadConversation,
        Some("thread_a"),
        RiskLevel::Low,
    );
    let approval = dispatch_mcp_bus_request(
        &request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        ),
        &mut state,
        &mut test_connection(1),
    )
    .expect("create approval")
    .response_body["approval"]
        .clone();
    let approval_id = approval["approval_id"].as_str().expect("approval id");
    let mut grant: LocalMcpGrantRecord = serde_json::from_value(
        dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut test_connection(2),
        )
        .expect("approve grant")
        .response_body,
    )
    .expect("grant record");
    assert!(mcp_verify_grant_signature(&grant).is_ok());

    grant.signing_body.tool_scope = Some("thread_b".to_owned());
    assert!(mcp_verify_grant_signature(&grant).is_err());
}
