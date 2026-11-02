// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sibling tombstones erase live copies and fence late arrivals across account reopen.
use super::tests::{bundle, client_with_account, envelope};
use super::*;

fn sibling_deleted_copy_order(deletion_first: bool, copies: usize) -> Result<(), SdkError> {
    let (client, root) = client_with_account(
        if deletion_first { "sibling-delete-first" } else { "sibling-live-first" },
        "principal_sync",
        "target_device_sync",
    )?;
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        "source_device_sync",
    )?;
    let staged_at = now_unix_timestamp();
    let mut bytes = b"ramflux.own_sent_message.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&serde_json::json!({
        "envelope_id":"live-envelope","message_id":"live-message","sender_id":"source_device_sync",
        "context":{"conversation_id":"direct","participants":["principal_sync","peer"],"group":null,"friend":null},
        "ciphertext_hash":super::super::own_sent_message::own_sent_ciphertext_hash(&[1,2,3]),
        "authored_at":staged_at,
        "body_base64":ramflux_protocol::encode_base64url(b"SIBLING_DELETION_BODY_CANARY")
    }))?);
    let receive = |client: &RamfluxClient, source: &ramflux_crypto::RootQualifiedDeviceRef| {
        client.receive_own_sent_message(
            source,
            super::super::own_device_copy::OwnMessageInput {
                id: "live-envelope",
                conversation: "direct",
                group: None,
                created_at: staged_at,
                body: &bytes,
            },
        )
    };
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
            created_at: staged_at,
            receipts: Vec::new(),
        }],
        Vec::new(),
    );
    let mut copy_ids = Vec::new();
    if !deletion_first {
        for device in ["source_device_sync", "other_device_sync"].into_iter().take(copies) {
            let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
                client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                device,
            )?;
            receive(&client, &source)?;
            let id = format!(
                "routed:own:{}",
                super::super::own_device_copy::copy_id(
                    source.root_commitment(),
                    source.device_id(),
                    "live-envelope"
                )?
            );
            assert!(client.direct_message_by_id(&id)?.is_some_and(|row| !row.deleted));
            client.account_db()?.persist_message_actor_state(
                &id,
                &format!("owncopy-test/erase-canary/{device}"),
                &serde_json::json!({"body":"SIBLING_DELETION_BODY_CANARY"}),
            )?;
            copy_ids.push(id);
        }
        assert_eq!(client.direct_messages("direct")?.len(), copies);
    }
    client.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    if deletion_first {
        receive(&client, &source)?;
    }
    assert_deleted_sibling_copies(&client, &copy_ids)?;
    receive(&client, &source)?;
    assert_deleted_sibling_copies(&client, &copy_ids)?;
    drop(client);
    let mut reopened = RamfluxClient::new();
    reopened.create_identity_root("principal_sync", [0x51; 32]);
    reopened.create_device_branch("principal_sync", "target_device_sync", 1, [0x52; 32]);
    reopened.open_account_index(&root)?;
    reopened.unlock_account("acct", b"own-device-sync-test")?;
    assert_deleted_sibling_copies(&reopened, &copy_ids)?;
    // The late control is exercised inside the unchanged 600-second copy lifetime.
    assert!(now_unix_timestamp().saturating_sub(staged_at) < 600);
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_deleted_sibling_copies(
    client: &RamfluxClient,
    copies: &[String],
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let rows = client.direct_messages("direct")?;
    assert_ne!(rows, Vec::<DirectMessageRecord>::new());
    for row in rows {
        assert!(row.deleted, "sibling tombstone left a readable own-copy row");
        assert_eq!(row.sender_id, "");
        assert_eq!(row.encrypted_body, Vec::<u8>::new());
        assert!(db.message_content(&row.message_id)?.is_none());
        assert!(client.message_origin("direct", &row.message_id)?.is_none());
    }
    for copy in copies {
        assert!(client.direct_message_by_id(copy)?.is_some_and(|row| row.deleted));
    }
    assert_eq!(
        db.list_actor_states::<serde_json::Value>("owncopy-test/erase-canary/")?,
        Vec::<serde_json::Value>::new()
    );
    for prefix in
        ["own-device/sent-alias/", "own-device/sent-ciphertext/", "own-device/sent-original/"]
    {
        for reference in db.list_actor_states::<ramflux_storage::MessageReplayReference>(prefix)? {
            assert!(matches!(
                reference,
                ramflux_storage::MessageReplayReference::Target { deleted: true, .. }
                    | ramflux_storage::MessageReplayReference::Ambiguous
            ));
        }
    }
    Ok(())
}

#[test]
fn sibling_history_tombstone_erases_a_live_own_copy_and_its_footprint() -> Result<(), SdkError> {
    sibling_deleted_copy_order(false, 1)
}

#[test]
fn sibling_history_tombstone_prevents_a_late_own_copy_from_reviving_content() -> Result<(), SdkError>
{
    sibling_deleted_copy_order(true, 1)
}

#[test]
fn sibling_history_tombstone_erases_each_live_copy_of_the_same_original() -> Result<(), SdkError> {
    sibling_deleted_copy_order(false, 2)
}
