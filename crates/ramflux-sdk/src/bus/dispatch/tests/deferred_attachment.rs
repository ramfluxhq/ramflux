// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise retryable body operations through the real mutation coordinator.
use super::*;
use crate::bus::actor::AccountCommand;
use serde_json::json;

fn test_root() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    std::env::temp_dir().join(format!("rf-fetch-bus-{}-{unique}-{sequence}", std::process::id()))
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

// Deletion fixtures need an admitted message reference, as real receive supplies.
fn admit_deletion_reference(client: &RamfluxClient) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let reference: serde_json::Value = db
        .load_actor_state("attachment/reference/object")?
        .ok_or(SdkError::AccountDbNotUnlocked)?;
    db.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: "deletion-fixture-reference",
            wire_id: "object",
            manifest_hash: "manifest",
            selector: "object",
            message_id: "attachment-message",
            reference: &reference,
            metadata: &json!({"owner":"owner","message_id":"attachment-message"}),
        },
    )?;
    Ok(())
}

#[tokio::test]
async fn deleted_attachment_receipt_is_not_retried() -> Result<(), SdkError> {
    let root = test_root();
    let mut state = make_state(&root)?;
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    assert_eq!(
        account.client.account_db()?.pending_received_attachment_ids(i64::MAX, 64)?,
        vec!["object"]
    );
    admit_deletion_reference(&account.client)?;
    account.client.account_db()?.set_object_tombstoned("object")?;
    let request = LocalBusFrame::request(
        "fetch",
        None,
        "object",
        "object.fetch",
        json!({"object_id":"object","operation_id":"deleted-fetch"}),
    );
    let result = dispatch_until(account, &request, Some(tokio::time::Instant::now())).await?;
    assert_eq!(result.response_body["transfer_state"], "failed");
    assert_eq!(result.response_body["last_error"], crate::error::ATTACHMENT_DELETED);
    assert_eq!(result.response_body["retryable"], false);
    assert!(
        account.client.account_db()?.pending_received_attachment_ids(i64::MAX, 64)?.is_empty(),
        "the scheduler must not requeue the nonretryable failure"
    );
    account.client.account_db()?.persist_actor_state(
        "attachment/fetch/object",
        &json!({
            "object_id":"object","operation_id":"interrupted","transfer_state":"fetching",
            "last_error":null,"attempts":1,"retryable":true,
        }),
    )?;
    account.client.recover_received_attachment_fetches()?;
    let recovered = account
        .client
        .received_attachment_status("object")?
        .ok_or(SdkError::AccountDbNotUnlocked)?;
    assert_eq!(recovered["last_error"], crate::error::ATTACHMENT_DELETED);
    assert_eq!(recovered["retryable"], false);
    assert_eq!(
        account.client.account_db()?.pending_received_attachment_ids(i64::MAX, 64)?,
        Vec::<String>::new()
    );
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn object_get_preserves_tombstoned_error_for_a_locally_deleted_ordinary_object()
-> Result<(), SdkError> {
    let root = test_root();
    let mut state = make_state(&root)?;
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    account.client.put_encrypted_object("ordinary-object", b"ordinary local bytes")?;
    account.client.tombstone_object("ordinary-object")?;
    let request = LocalBusFrame::request(
        "read",
        Some("account".into()),
        "object",
        "object.get",
        json!({"object_id":"ordinary-object"}),
    );
    let result =
        Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(&request, &mut state))
            .await;
    assert!(matches!(result, Err(SdkError::Sync(SyncError::ObjectTombstoned))));
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn deleted_attachment_page_fetch_preserves_typed_error() -> Result<(), SdkError> {
    let root = test_root();
    let mut state = make_state(&root)?;
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    // Start with a real retryable fetch failure to retain the generic failure outcome.
    let failed = account.client.fail_received_attachment_fetch("object", "page-fetch").await?;
    assert!(matches!(
        crate::bus::attachment_scheduler::ensure_page_attachment_available(&failed),
        Err(SdkError::LocalBus(_))
    ));
    admit_deletion_reference(&account.client)?;
    account.client.account_db()?.set_object_tombstoned("object")?;
    let request = LocalBusFrame::request(
        "fetch",
        None,
        "object",
        "object.fetch",
        json!({"object_id":"object","operation_id":"page-fetch"}),
    );
    let receipt = dispatch_until(account, &request, None).await?.response_body;
    let error = crate::bus::attachment_scheduler::ensure_page_attachment_available(&receipt)
        .err()
        .ok_or_else(|| SdkError::LocalBus("deleted page fetch succeeded".into()))?;
    assert!(matches!(error, SdkError::AttachmentDeleted));
    assert_eq!(crate::bus::io::local_bus_error_code(&error), "AttachmentDeleted");
    assert_eq!(error.to_string(), crate::error::ATTACHMENT_DELETED);
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
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
            admission: None,
            private: None,
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
        admission: None,
        private: None,
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

#[tokio::test(start_paused = true)]
async fn deleted_attachment_receipt_survives_scheduler_deadline() -> Result<(), SdkError> {
    let root = test_root();
    let mut account = crate::bus::runtime_tests::account(
        &root,
        "terminal",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let engine = account.session_client().await?;
    let receipt = json!({"transfer_state":"failed",
        "last_error":crate::error::ATTACHMENT_DELETED,"retryable":false});
    let result = finish_fetch(
        &mut account,
        engine,
        "object",
        Ok(Ok(receipt.clone())),
        Some(tokio::time::Instant::now()),
    )?;
    assert_eq!(
        result.response_body, receipt,
        "a terminal receipt must not become a retryable deadline error"
    );
    assert!(account.has_pooled_engine());
    drop(account);
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

#[tokio::test(start_paused = true)]
async fn scheduler_deadline_preserves_resume_before_retiring_the_borrowed_gateway_engine()
-> Result<(), SdkError> {
    let root = test_root();
    let mut account = crate::bus::runtime_tests::account(
        &root,
        "deadline",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut engine = account.session_client().await?;
    engine.test_update_resume("current-session", "current-resume").await?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        std::future::pending::<Result<serde_json::Value, SdkError>>(),
    )
    .await;
    let error = finish_fetch(&mut account, engine, "object", result, None)
        .err()
        .ok_or_else(|| SdkError::LocalBus("deadline unexpectedly succeeded".into()))?;
    assert!(
        matches!(error, SdkError::LocalBus(reason) if reason == "attachment fetch deferred; retry object.fetch")
    );
    assert!(!account.has_pooled_engine(), "an interrupted frame stream cannot be reused");
    assert_eq!(account.gateway_config.previous_session_id.as_deref(), Some("current-session"));
    assert_eq!(account.gateway_config.resume_token.as_deref(), Some("current-resume"));
    let saved = account
        .client
        .projection_checkpoint(LocalBusAccountState::GATEWAY_RESUME_CHECKPOINT)?
        .ok_or_else(|| SdkError::LocalBus("missing saved resume".into()))?;
    let saved: serde_json::Value = serde_json::from_str(&saved)?;
    assert_eq!(saved["previous_session_id"], "current-session");
    assert_eq!(saved["resume_token"], "current-resume");
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn simultaneous_attachment_and_engine_deadlines_preserve_resume_and_retry()
-> Result<(), SdkError> {
    let root = test_root();
    let mut account = crate::bus::runtime_tests::account(
        &root,
        "race",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let engine = account.session_client().await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let inner_expired = std::cell::Cell::new(false);
    let result = run_fetch(&mut account, engine, "object", Some(deadline), async |client, engine| {
        engine.test_update_resume("same-tick-session","same-tick-resume").await?;
        client.account_db()?.persist_actor_state("attachment/fetch/object", &json!({
            "object_id":"object","operation_id":"fetch-op","transfer_state":"fetching",
            "last_error":null,"attempts":1,
        }))?;
        let engine_timeout = tokio::time::timeout_at(
            deadline, std::future::pending::<Result<(), SdkError>>(),
        ).await;
        inner_expired.set(engine_timeout.is_err());
        Ok(json!({"transfer_state":"failed","last_error":"attachment transport failed; retry object.fetch"}))
    }).await;
    assert!(inner_expired.get(), "the engine timeout must win the inner-first poll");
    assert!(
        matches!(result, Err(SdkError::LocalBus(text)) if text == "attachment fetch deferred; retry object.fetch")
    );
    assert!(!account.has_pooled_engine(), "a timed-out stream must be retired");
    assert_eq!(account.gateway_config.previous_session_id.as_deref(), Some("same-tick-session"));
    assert_eq!(account.gateway_config.resume_token.as_deref(), Some("same-tick-resume"));
    let state: serde_json::Value = account
        .client
        .account_db()?
        .load_actor_state("attachment/fetch/object")?
        .ok_or(SdkError::AccountDbNotUnlocked)?;
    assert_eq!(state["transfer_state"], "failed");
    let mut spare = crate::bus::runtime_tests::account(
        &root.join("spare"),
        "race",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut resumed = spare.engine.take().ok_or(SdkError::GatewaySessionNotEstablished)?;
    resumed.config = account.gateway_config.clone();
    account.install_test_session(resumed);
    let resumed = account.session_client().await?;
    let retry = run_fetch(
        &mut account,
        resumed,
        "object",
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(20)),
        async |_, engine| {
            assert_eq!(engine.config.resume_token.as_deref(), Some("same-tick-resume"));
            Ok(json!({"transfer_state":"available"}))
        },
    )
    .await?;
    assert_eq!(retry.response_body["transfer_state"], "available");
    assert!(account.has_pooled_engine());
    drop(account);
    drop(spare);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "deferred_attachment/local_first.rs"]
mod local_first;
