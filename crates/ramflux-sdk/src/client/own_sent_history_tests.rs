// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated `OwnSentMessage` eight-field codec, source-bound aliases and restore fences (S10a P18).
#![allow(clippy::too_many_lines, clippy::expect_used)]
use super::*;
use crate::client::own_device_sync::tests::{bundle, client_with_account, envelope};
use ramflux_protocol::message as g;
use ramflux_storage::MessageReplayReference;
use serde_json::json;

fn source(
    client: &RamfluxClient,
    device: &str,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, SdkError> {
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        device,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn prefix_bytes(
    envelope: &str,
    message: &str,
    sender: &str,
    recipients: &[&str],
    conversation: &str,
    hash: Option<&[u8]>,
    authored_at: i64,
    body: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let mut bytes = PREFIX.to_vec();
    bytes.extend(serde_json::to_vec(&json!({
        "envelope_id": envelope,
        "message_id": message,
        "sender_id": sender,
        "original_recipients": recipients,
        "ciphertext_hash": hash.map(own_sent_ciphertext_hash),
        "context": {
            "conversation_id": conversation,
            "participants": ["principal_sync", "peer"],
            "group": null,
            "friend": null
        },
        "authored_at": authored_at,
        "body_base64": ramflux_protocol::encode_base64url(body)
    }))?);
    Ok(bytes)
}

fn generated_from_prefix(bytes: &[u8]) -> Result<g::OwnSentMessage, SdkError> {
    generated_own_sent_from_prefix(bytes)?
        .ok_or_else(|| invalid("expected generated own sent message"))
}

fn receive_generated(
    client: &RamfluxClient,
    device: &str,
    conversation: &str,
    at: i64,
    sent: &g::OwnSentMessage,
) -> Result<bool, SdkError> {
    client.receive_generated_own_sent(&source(client, device)?, conversation, None, at, sent)
}

fn alias_for(
    client: &RamfluxClient,
    device: &str,
    envelope: &str,
) -> Result<Option<MessageReplayReference>, SdkError> {
    let db = client.account_db()?;
    let id = own_row_id(&source(client, device)?, envelope)?;
    Ok(db.load_actor_state::<MessageReplayReference>(&alias_key(db, &id)?)?)
}

fn ciphertext_alias(
    client: &RamfluxClient,
    hash: &[u8],
) -> Result<Option<MessageReplayReference>, SdkError> {
    let db = client.account_db()?;
    Ok(db.load_actor_state::<MessageReplayReference>(&ciphertext_index_key(
        db,
        &own_sent_ciphertext_hash(hash),
    )?)?)
}

fn reopen(root: &std::path::Path) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root("principal_sync", [0x51; 32]);
    client.create_device_branch("principal_sync", "target_device_sync", 1, [0x52; 32]);
    client.open_account_index(root)?;
    client.unlock_account("acct", b"own-device-sync-test")?;
    Ok(client)
}

fn assert_deleted(client: &RamfluxClient, id: &str) -> Result<(), SdkError> {
    let row = client.direct_message_by_id(id)?.ok_or(SdkError::IdentityRootMissing)?;
    assert!(row.deleted);
    assert_eq!(row.sender_id, "");
    assert!(client.account_db()?.message_content(id)?.is_none());
    assert!(client.message_origin("direct", id)?.is_none());
    Ok(())
}

#[test]
fn own_sent_fields_and_source_bound_reconciliation_round_trip() -> Result<(), SdkError> {
    let (client, root) = client_with_account("t18-fields", "principal_sync", "target_device_sync")?;
    let body = b"original inner body";
    let ciphertext = [1_u8, 2, 3];
    let bytes = prefix_bytes(
        "copy-envelope",
        "original-message",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        42,
        body,
    )?;
    assert!(generated_own_sent_from_prefix(b"not-a-prefix")?.is_none());
    let sent = generated_from_prefix(&bytes)?;
    assert_eq!(sent.envelope_id, "copy-envelope");
    assert_eq!(sent.message_id, "original-message");
    assert_eq!(sent.sender_id, "display-label");
    assert_eq!(sent.original_recipients, Vec::<String>::new());
    assert_eq!(
        sent.ciphertext_digest.as_deref().map(ramflux_protocol::encode_base64url),
        Some(own_sent_ciphertext_hash(&ciphertext))
    );
    assert_eq!(sent.ciphertext_digest.as_ref().map(Vec::len), Some(32));
    assert_eq!(sent.authored_at, Some(42));
    assert_eq!(sent.exact_inner, body);
    assert!(!sent.exact_inner.starts_with(PREFIX));
    let context = sent.context.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    assert_eq!(context.conversation_id, "direct");
    assert_eq!(context.participants, ["principal_sync", "peer"]);
    assert!(context.group.is_none());
    assert!(context.friend.is_none());
    assert_ne!(sent.sender_id, source(&client, "source_device_sync")?.device_id());

    assert!(receive_generated(&client, "source_device_sync", "direct", 99, &sent)?);
    let rows = client.direct_messages("direct")?;
    assert_eq!(rows.len(), 1);
    let copy_id = own_row_id(&source(&client, "source_device_sync")?, "copy-envelope")?;
    assert_eq!(rows[0].message_id, copy_id);
    assert_eq!(rows[0].created_at, 42);
    assert_eq!(client.account_db()?.message_content(&copy_id)?.as_deref(), Some(body.as_slice()));
    assert!(matches!(
        alias_for(&client, "source_device_sync", "copy-envelope")?,
        Some(MessageReplayReference::Target { deleted: false, .. })
    ));

    let suppressed = generated_from_prefix(&prefix_bytes(
        "original-envelope",
        "original-message",
        "display-label",
        &["target_device_sync"],
        "direct",
        Some(&ciphertext),
        42,
        body,
    )?)?;
    assert_eq!(suppressed.original_recipients, ["target_device_sync"]);
    assert!(receive_generated(&client, "source_device_sync", "direct", 99, &suppressed)?);
    assert_eq!(client.direct_messages("direct")?.len(), 1);

    let other = generated_from_prefix(&prefix_bytes(
        "other-envelope",
        "other-original",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        42,
        body,
    )?)?;
    assert!(receive_generated(&client, "other_device_sync", "direct", 99, &other)?);
    assert_eq!(client.direct_messages("direct")?.len(), 2);
    assert!(matches!(
        ciphertext_alias(&client, &ciphertext)?,
        Some(MessageReplayReference::Ambiguous)
    ));

    let mut surface = crate::client::surface::carrier::PREFIX.to_vec();
    surface.extend(serde_json::to_vec(&json!({
        "schema": "ramflux.surface.carrier.v2",
        "content_type": "surface",
        "payload_kind": "event",
        "conversation_id": "direct",
        "surface_id": "surface",
        "message_id": "surface-message",
        "sender_principal_id": "principal_sync",
        "sender_device_id": "source_device_sync",
        "author_principal_id": "principal_sync",
        "wire_base64": "",
        "signature": "sig"
    }))?);
    let structured = generated_from_prefix(&prefix_bytes(
        "surface-envelope",
        "surface-original",
        "display-label",
        &[],
        "direct",
        None,
        42,
        &surface,
    )?)?;
    let err = receive_generated(&client, "source_device_sync", "direct", 99, &structured)
        .expect_err("structured carrier must be refused");
    assert!(format!("{err}").contains("structured own message requires signed control projection"));

    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn own_sent_raw_erasure_and_replay_reference_survive_restore_without_resurrection()
-> Result<(), SdkError> {
    let (client, root) =
        client_with_account("t18-restore", "principal_sync", "target_device_sync")?;
    let body = b"erasure canary body";
    let ciphertext = [9_u8, 8, 7];
    let sent = generated_from_prefix(&prefix_bytes(
        "live-envelope",
        "live-message",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        7,
        body,
    )?)?;
    assert!(receive_generated(&client, "source_device_sync", "direct", 1, &sent)?);
    let copy_id = own_row_id(&source(&client, "source_device_sync")?, "live-envelope")?;
    client.account_db()?.delete_direct_message("direct", &copy_id, "self", "erase-copy")?;
    assert_deleted(&client, &copy_id)?;
    assert!(matches!(
        alias_for(&client, "source_device_sync", "live-envelope")?,
        Some(MessageReplayReference::Target { deleted: true, .. })
    ));
    drop(client);

    let client = reopen(&root)?;
    assert_deleted(&client, &copy_id)?;
    assert!(matches!(
        alias_for(&client, "source_device_sync", "live-envelope")?,
        Some(MessageReplayReference::Target { deleted: true, .. })
    ));
    assert!(receive_generated(&client, "source_device_sync", "direct", 1, &sent)?);
    assert_deleted(&client, &copy_id)?;

    let mut history = bundle(
        "source_device_sync",
        "target_device_sync",
        vec![DirectMessageRecord {
            conversation_id: "direct".into(),
            message_id: copy_id.clone(),
            sender_id: "source_device_sync".into(),
            encrypted_body: ciphertext.to_vec(),
            metadata: MessageMetadata::default(),
            deleted: false,
            is_own: true,
            created_at: 7,
            receipts: Vec::new(),
        }],
        Vec::new(),
    );
    history.contents.insert(copy_id.clone(), zeroize::Zeroizing::new(body.to_vec()));
    client.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert_deleted(&client, &copy_id)?;
    assert!(matches!(
        alias_for(&client, "source_device_sync", "live-envelope")?,
        Some(MessageReplayReference::Target { deleted: true, .. })
    ));
    assert!(receive_generated(&client, "source_device_sync", "direct", 1, &sent)?);
    assert_deleted(&client, &copy_id)?;
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn own_import_race(history_first: bool) -> Result<(), SdkError> {
    let label = if history_first { "t12-history-first" } else { "t12-copy-first" };
    let (client, root) = client_with_account(label, "principal_sync", "target_device_sync")?;
    let body = b"race canary body";
    let ciphertext = [4_u8, 5, 6];
    let sent = generated_from_prefix(&prefix_bytes(
        "race-envelope",
        "live-message",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        3,
        body,
    )?)?;
    let history = bundle(
        "source_device_sync",
        "target_device_sync",
        vec![DirectMessageRecord {
            conversation_id: "direct".into(),
            message_id: "live-message".into(),
            sender_id: String::new(),
            encrypted_body: Vec::new(),
            metadata: MessageMetadata::default(),
            deleted: true,
            is_own: true,
            created_at: 3,
            receipts: Vec::new(),
        }],
        Vec::new(),
    );
    let receive = |client: &RamfluxClient| {
        receive_generated(client, "source_device_sync", "direct", 3, &sent)
    };
    if history_first {
        client.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &history,
        )?;
        receive(&client)?;
    } else {
        receive(&client)?;
        client.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &history,
        )?;
    }
    for row in client.direct_messages("direct")? {
        assert!(row.deleted);
        assert!(client.account_db()?.message_content(&row.message_id)?.is_none());
        assert!(client.message_origin("direct", &row.message_id)?.is_none());
    }
    receive(&client)?;
    for row in client.direct_messages("direct")? {
        assert!(row.deleted);
        assert!(client.account_db()?.message_content(&row.message_id)?.is_none());
    }
    drop(client);
    let client = reopen(&root)?;
    receive(&client)?;
    for row in client.direct_messages("direct")? {
        assert!(row.deleted);
        assert!(client.account_db()?.message_content(&row.message_id)?.is_none());
    }
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn raw_inner_reparse_restore_own_import_races_delete() -> Result<(), SdkError> {
    own_import_race(true)?;
    own_import_race(false)
}
