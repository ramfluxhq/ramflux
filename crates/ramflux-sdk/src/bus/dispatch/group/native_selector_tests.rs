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
        group_receive_conversation(&owner.client, "group", "operator-conversation")?,
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
        group_receive_conversation(&legacy.client, "group", "legacy-thread")?,
        "legacy-thread"
    );
    drop(legacy);
    std::fs::remove_dir_all(legacy_root)?;
    Ok(())
}
