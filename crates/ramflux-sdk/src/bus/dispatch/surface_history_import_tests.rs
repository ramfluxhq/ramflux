// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The retired device-sync IPC refuses before any cached receipt, object or session work.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn retired_relay_keys_refuse_device_sync_ipc_before_cached_receipts_or_session_work()
-> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(20), Box::pin(async {
        let directory = tempfile::TempDir::new()?;
        let root = directory.path();
        let mut source = runtime_tests::account(
            &root.join("source"), "sender", None, Arc::new(AtomicBool::new(false)),
        )?;
        let (target, _config, _receiver, server) =
            super::own_tests::sibling_fixture(root, &mut source).await?;
        source.client.send_direct_message(
            "history-thread", "history-message", "device-sender", b"ciphertext",
        )?;
        // The retired carrier is refused before the envelope is read, so any JSON object stands in.
        let envelope = json!({"schema":"retired.device_sync.envelope","snapshot_id":"history-retry"});
        server.abort();
        let receipt = "own-device/imported/retired-cached-receipt";
        target.client.account_db()?.persist_actor_state(receipt, &json!({"retired_cached_receipt":true}))?;
        let before = serde_json::to_value(target.client.account_db()?.load_actor_state::<Value>(receipt)?)?;
        let messages = serde_json::to_value(target.client.direct_messages("history-thread")?)?;
        let engine_present = target.engine.is_some();
        let mut state = LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("bus.sock"), root),
            account_index: None, nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([("target".into(), target)]),
            active_account_id: Some("target".into()), attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        for (method, body) in [
            ("device.sync.export", json!({"target_device_id":"device-sender","relay_endpoint":"quic://127.0.0.1:1","relay_service_key_base64":"retired-test-key","chunk_size":4096})),
            ("device.sync.import", json!({"envelope":envelope,"relay_service_key_base64":"retired-test-key"})),
        ] {
            let request = LocalBusFrame::request("retired-sync", Some("target".into()), "device", method, body);
            let error = super::super::device::dispatch_device_bus_request(&request, &mut state)
                .await.err().ok_or("test: retired key was accepted by device sync IPC")?;
            match error {
                SdkError::CapabilityDenied(message) if method == "device.sync.export" => {
                    assert_eq!(message, "relay service keys are unsupported; use gateway-issued QUIC tokens");
                },
                SdkError::GeneratedRefused { code, reason } if method == "device.sync.import" => {
                    assert_eq!(code, crate::error::GeneratedRefusalCode::Content);
                    assert!(reason.contains("retired object history carrier"),
                        "device sync must refuse the retired carrier: {reason}");
                },
                other => return Err(format!("test: unexpected device sync refusal: {other}").into()),
            }
            let account = state.accounts.get("target").ok_or("test: target account")?;
            assert_eq!(account.engine.is_some(), engine_present, "refusal must not create a session");
            assert!(account.relay_quic_pool.is_none(), "refusal must not create a relay pool");
            assert_eq!(serde_json::to_value(account.client.account_db()?.load_actor_state::<Value>(receipt)?)?, before, "refusal must preserve the cached receipt");
            assert_eq!(serde_json::to_value(account.client.direct_messages("history-thread")?)?, messages, "refusal must preserve imported history");
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })).await?
}
