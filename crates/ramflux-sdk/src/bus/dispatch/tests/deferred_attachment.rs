// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise retryable body operations through the real mutation coordinator.
use super::*;
use crate::bus::actor::AccountCommand;
use serde_json::json;

fn test_root() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    std::env::temp_dir().join(format!("rf-fetch-bus-{}-{unique}", std::process::id()))
}

fn make_state(root: &Path) -> Result<LocalBusDaemonState, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root("recipient", [0x51; 32]);
    client.create_device_branch("recipient", "device", 1, [0x52; 32]);
    client.open_account_index(root)?;
    client.create_account("account", "commitment")?;
    client.unlock_account("account", b"secret")?;
    client.account_db()?.persist_actor_state("attachment/reference/object", &json!({"reference":{
        "schema":"ramflux.sdk.dm_attachment_ref.v1","version":1,"object_id":"object",
        "manifest_hash":"manifest","plaintext_hash":"hash","cipher_size":16,"chunk_size":32,
        "total_chunks":1,"relay_endpoint":"https://relay.invalid","key_slot":{
            "schema":"ramflux.sdk.object_key_slot.dm.v1","version":1,"object_id":"object",
            "conversation_id":"slot","recipient_device_id":"device","x3dh":null,
            "ciphertext":{"session_id":"slot","counter":0,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[]}
        }
    }}))?;
    // An absent CA fails before opening a network connection.
    let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::GatewaySessionNotEstablished)?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::GatewaySessionNotEstablished)?,
        server_name: "localhost".to_owned(),
        ca_cert: root.join("absent-ca.pem"),
        principal_id: "recipient".to_owned(),
        device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        prekey_http_url: None,
    });
    Ok(LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root.to_path_buf()),
        accounts: BTreeMap::from([(
            "account".to_owned(),
            LocalBusAccountState::disconnected(client, gateway, "commitment".to_owned()),
        )]),
        active_account_id: Some("account".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    })
}

#[tokio::test]
async fn frame_receipt_cache_does_not_make_a_fetch_failure_terminal() -> Result<(), SdkError> {
    let root = test_root();
    let mut state = make_state(&root)?;
    for attempt in 1..=2 {
        let mut request = LocalBusFrame::request(
            "request",
            Some("account".to_owned()),
            "object",
            "object.fetch",
            json!({"object_id":"object","operation_id":"fetch-op"}),
        );
        request.operation_id = Some("fetch-op".to_owned());
        let (outbound, _events) = mpsc::channel(16);
        let command = AccountCommand {
            backup: None,
            request,
            connection_id: 1,
            topics: BTreeSet::new(),
            attended: true,
            nodes: None,
            outbound,
            reply: None,
        };
        let response =
            Box::pin(crate::bus::mutations::execute(&mut state, "account", &command)).await?;
        assert_eq!(response.body["transfer_state"], "failed");
        let saved: serde_json::Value = state
            .accounts
            .get("account")
            .ok_or(SdkError::AccountDbNotUnlocked)?
            .client
            .account_db()?
            .load_actor_state("attachment/fetch/object")?
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        assert_eq!(saved["attempts"], attempt, "generic cache must not replay the first failure");
    }
    let mut request = LocalBusFrame::request(
        "invalid",
        Some("account".to_owned()),
        "object",
        "object.fetch",
        json!({"object_id":"object","operation_id":"fetch-op"}),
    );
    request.operation_id = Some(String::new());
    let (outbound, _events) = mpsc::channel(16);
    let command = AccountCommand {
        backup: None,
        request,
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    };
    assert!(
        Box::pin(crate::bus::mutations::execute(&mut state, "account", &command)).await.is_err()
    );
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn fetched_attachment_reads_are_local_with_a_saved_node_profile() -> Result<(), SdkError> {
    let root = test_root();
    let mut state = make_state(&root)?;
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    account.client.node_relay_options =
        parse_relay_transfer_options(Some("https://relay.invalid".to_owned()), None, None)?;
    assert!(read_relay_options(account, "object", None, None, None)?.is_some());
    account.client.put_encrypted_object("object", b"local bytes")?;
    account.client.account_db()?.persist_actor_state("attachment/fetch/object", &json!({
        "object_id":"object","operation_id":"fetch-op","transfer_state":"available","last_error":null,"attempts":1,
    }))?;
    assert!(read_relay_options(account, "object", None, None, None)?.is_none());
    assert!(
        read_relay_options(
            account,
            "object",
            Some("https://relay.invalid".to_owned()),
            None,
            None
        )?
        .is_some()
    );
    let request = LocalBusFrame::request(
        "read",
        Some("account".to_owned()),
        "object",
        "object.get",
        json!({"object_id":"object"}),
    );
    let read =
        Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(&request, &mut state))
            .await?;
    assert_eq!(
        read.response_body["plaintext_base64"],
        ramflux_protocol::encode_base64url(b"local bytes")
    );
    let request = LocalBusFrame::request(
        "begin",
        Some("account".to_owned()),
        "object",
        "object.get.begin",
        json!({"object_id":"object","operation_id":"read-local","protocol_version":1}),
    );
    let begin =
        Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(&request, &mut state))
            .await?;
    assert_eq!(begin.response_body["total_len"], b"local bytes".len());
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
