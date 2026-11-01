// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native CLI selectors resolve consistently for sending and reading a signed group.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn native_cli_conversation_selector_resolves_to_signed_group_thread() -> TestResult {
    let owner = crate::client::native_test_support::Fixture::new("cli-conversation").await?;
    let primary = owner.vault.primary_for_public_key(
        &owner
            .manifest
            .custody
            .as_ref()
            .ok_or("custody")?
            .publication
            .record
            .body
            .master_certificate
            .body
            .self_signing_public_key,
    )?;
    owner.client.shared_group_create_with_primary(
        "group",
        "group",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    assert_eq!(
        crate::bus::group_conversation::resolve(&owner.client, "group", "operator-conversation")?,
        "group"
    );
    let mut body: LocalBusGroupSendRequest = serde_json::from_value(serde_json::json!({
        "group_id":"group", "conversation_id":"operator-conversation", "message_id":"message",
        "sender_id":owner.config.principal_id, "encrypted_body_base64":"",
    }))?;
    normalize_native_group_request(&mut body, &owner.config, &owner.client)?;
    assert_eq!(body.sender_id, owner.config.device_id);
    assert_eq!(body.conversation_id, "group");
    body.sender_id = "foreign-principal".into();
    assert!(normalize_native_group_request(&mut body, &owner.config, &owner.client).is_err());
    let legacy_root = runtime_tests::root("legacy-cli-conversation");
    let legacy =
        runtime_tests::account(&legacy_root, "legacy", None, Arc::new(AtomicBool::new(false)))?;
    assert_eq!(
        crate::bus::group_conversation::resolve(&legacy.client, "group", "legacy-thread")?,
        "legacy-thread"
    );
    drop(legacy);
    std::fs::remove_dir_all(legacy_root)?;
    Ok(())
}

#[tokio::test]
async fn native_send_and_read_capture_only_the_signed_group_link() -> TestResult {
    let owner = crate::client::native_test_support::Fixture::new("cli-capture").await?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "group",
        "group",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let account = LocalBusAccountState::disconnected(
        owner.client,
        owner.config,
        owner.manifest.principal_commitment,
    );
    for method in ["group.send", "group.read", "group.receive"] {
        let db = account.client.account_db()?;
        // Reproduce metadata left by an earlier CLI send/read before upgrading the daemon.
        db.persist_client_record(
            "group",
            "group",
            &serde_json::json!({
                "conversation_id":null, "conversation_ids":["group", "operator-thread"],
                "custom":"preserved",
            }),
        )?;
        let request = LocalBusFrame::request(
            "capture",
            Some("owner".into()),
            "ramflux.sdk.v1",
            method,
            serde_json::json!({"group_id":"group", "conversation_id":"operator-thread"}),
        );
        crate::bus::read_model::capture(&account, &request, &serde_json::json!({}))?;
        let db = account.client.account_db()?;
        let link = db.client_record("group", "group")?.ok_or("group link")?;
        assert_eq!(link["conversation_id"], "group", "{method}: {link}");
        assert_eq!(link["conversation_ids"], serde_json::json!(["group"]));
        assert_eq!(link["custom"], "preserved");
        assert!(db.client_record("conversation", "operator-thread")?.is_none());
        assert_eq!(
            db.client_record("conversation", "group")?.ok_or("thread")?["group_id"],
            "group"
        );
    }
    Ok(())
}
