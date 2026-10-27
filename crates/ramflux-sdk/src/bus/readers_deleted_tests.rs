// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deleted rows stay narrow through both public message reader methods.

use super::*;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn list_and_read_project_deleted_peer_and_own_rows_without_identity() -> TestResult {
    let root = crate::bus::runtime_tests::root("deleted-message-readers");
    let index = AccountIndex::open(&root)?;
    index.create_account("account", "principal")?;
    let key = ramflux_storage::AccountDbKey::derive("account", b"deleted-reader-secret");
    let db = AccountDb::open(&index, "account", &key)?;
    db.send_direct_message("thread", "peer", "peer-device-secret", b"peer-body")?;
    db.send_direct_message("thread", "own", "principal", b"own-body")?;
    db.delete_direct_message("thread", "peer", "local", "peer-tombstone")?;
    db.delete_direct_message("thread", "own", "local", "own-tombstone")?;

    for method in ["message.list", "message.read"] {
        let request = LocalBusFrame::request(
            method,
            Some("account".to_owned()),
            "client",
            method,
            json!({"conversation_id":"thread"}),
        );
        let response = test_account_reader_request(&db, request).await?;
        let messages = response["messages"].as_array().ok_or("messages")?;
        assert_eq!(messages.len(), 2);
        for is_own in [false, true] {
            let message =
                messages.iter().find(|message| message["is_own"] == is_own).ok_or("ownness")?;
            assert_eq!(
                message,
                &json!({"message_id":message["message_id"],"deleted":true,"created_at":message["created_at"],"conversation_id":"thread","is_own":is_own})
            );
        }
        let encoded = serde_json::to_string(messages)?;
        for secret in ["peer-device-secret", "peer-body", "principal", "own-body"] {
            assert!(!encoded.contains(secret));
        }
    }
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
