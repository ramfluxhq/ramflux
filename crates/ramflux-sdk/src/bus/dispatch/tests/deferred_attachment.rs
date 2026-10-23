// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise retryable body operations through the real mutation coordinator.
use super::*;
use crate::bus::actor::AccountCommand;
use serde_json::json;

#[tokio::test]
async fn frame_receipt_cache_does_not_make_a_fetch_failure_terminal() -> Result<(), SdkError> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    let root = std::env::temp_dir().join(format!("rf-fetch-bus-{}-{unique}", std::process::id()));
    let mut client = RamfluxClient::new();
    client.create_identity_root("recipient", [0x51; 32]);
    client.create_device_branch("recipient", "device", 1, [0x52; 32]);
    client.open_account_index(&root)?;
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
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root.clone()),
        accounts: BTreeMap::from([(
            "account".to_owned(),
            LocalBusAccountState::disconnected(client, gateway, "commitment".to_owned()),
        )]),
        active_account_id: Some("account".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
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
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
