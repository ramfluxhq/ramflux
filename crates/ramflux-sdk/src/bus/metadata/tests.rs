// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::prelude::*;
use serde_json::{Value, json};

fn account() -> Value {
    json!({"local_account_id":"local", "principal_id":"principal", "principal_commitment":"commitment",
        "device_id":"device", "target_delivery_id":"target", "account_secret":"test-secret",
        "root_seed":vec![0_u8;32], "device_seed":vec![1_u8;32], "client_mode":"attended_cli"})
}
fn attachment() -> Value {
    json!({"object_id":"object", "plaintext_base64":"", "chunk_size":4096, "relay_endpoint":"quic://relay.example:443"})
}

#[test]
fn absent_metadata_round_trips_without_new_wire_fields() -> Result<(), SdkError> {
    let request: LocalBusAccountCreateRequest = serde_json::from_value(account())?;
    assert!(request.label.is_none() && request.kind.is_none());
    let encoded = serde_json::to_value(request)?;
    assert!(encoded.get("label").is_none() && encoded.get("kind").is_none());
    let request: LocalBusMessageAttachmentInput = serde_json::from_value(attachment())?;
    assert!(request.name.is_none() && request.mime.is_none());
    let encoded = serde_json::to_value(request)?;
    assert!(encoded.get("name").is_none() && encoded.get("mime").is_none());
    Ok(())
}

#[test]
fn account_label_counts_characters_and_kind_is_closed() -> Result<(), SdkError> {
    let mut body = account();
    for kind in ["human", "headless_ai", "bot", "workflow"] {
        body["label"] = json!("🦀".repeat(64));
        body["kind"] = json!(kind);
        let typed: LocalBusAccountCreateRequest = serde_json::from_value(body.clone())?;
        assert_eq!(typed.label.as_ref().map(|label| label.chars().count()), Some(64));
        assert_eq!(serde_json::to_value(typed.kind)?, json!(kind));
        let manifest = LocalBusPersistedAccount::from_create_request(&typed);
        assert_eq!(manifest.label, typed.label);
        assert_eq!(manifest.kind.as_deref(), Some(kind));
    }
    body["label"] = json!("🦀".repeat(65));
    assert!(serde_json::from_value::<LocalBusAccountCreateRequest>(body.clone()).is_err());
    body["label"] = Value::Null;
    for invalid in [json!("robot"), json!(1), json!([])] {
        body["kind"] = invalid;
        assert!(serde_json::from_value::<LocalBusAccountCreateRequest>(body.clone()).is_err());
    }
    Ok(())
}

#[test]
fn attachment_filename_is_bounded_and_never_a_path() -> Result<(), SdkError> {
    let mut body = attachment();
    body["name"] = json!("a".repeat(255));
    let typed: LocalBusMessageAttachmentInput = serde_json::from_value(body.clone())?;
    assert_eq!(typed.name.as_ref().map(String::len), Some(255));
    for name in [
        "a".repeat(256),
        "é".repeat(128),
        "dir/file".to_owned(),
        "dir\\file".to_owned(),
        "file\nname".to_owned(),
        "file\0name".to_owned(),
        "file\u{7f}".to_owned(),
        "file\u{85}".to_owned(),
    ] {
        body["name"] = json!(name);
        assert!(serde_json::from_value::<LocalBusMessageAttachmentInput>(body.clone()).is_err());
    }
    body["name"] = json!(1);
    assert!(serde_json::from_value::<LocalBusMessageAttachmentInput>(body).is_err());
    Ok(())
}

#[test]
fn attachment_mime_accepts_media_types_and_parameters_only() -> Result<(), SdkError> {
    let mut body = attachment();
    for valid in [
        "text/plain",
        "image/png",
        "application/octet-stream",
        "text/plain; charset=utf-8",
        "text/plain; title=\"two words\"",
    ] {
        body["mime"] = json!(valid);
        let typed: LocalBusMessageAttachmentInput = serde_json::from_value(body.clone())?;
        assert_eq!(typed.mime.as_deref(), Some(valid));
    }
    for invalid in [
        json!(""),
        json!("text"),
        json!("/plain"),
        json!("text/"),
        json!("text/plain;"),
        json!("text/plain; "),
        json!("*/*"),
        json!("text/*"),
        json!("text/plain\r\nInjected: yes"),
        json!(5),
        json!(format!("text/plain; title={}", "a".repeat(1024))),
    ] {
        body["mime"] = invalid;
        assert!(
            serde_json::from_value::<LocalBusMessageAttachmentInput>(body.clone()).is_err(),
            "invalid MIME accepted: {}",
            body["mime"]
        );
    }
    Ok(())
}

#[test]
fn invalid_attachment_metadata_is_rejected_before_dispatch() {
    let mut body = json!({"conversation_id":"thread","message_id":"message","envelope_id":"envelope",
        "source_principal_id":"principal","sender_id":"device","target_delivery_id":"target",
        "encrypted_body_base64":"", "created_at":1,"ttl":60,"attachments":[attachment()]});
    body["attachments"][0]["name"] = json!("../unsafe");
    let request = LocalBusFrame::request(
        "invalid",
        Some("local".to_owned()),
        "message",
        "message.submit",
        body,
    );
    assert!(crate::bus::read_model::validate(&request).is_err());
}
