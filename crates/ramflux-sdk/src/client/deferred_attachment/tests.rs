// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

struct Fixture {
    client: RamfluxClient,
    root: PathBuf,
    reference: SdkDmAttachmentRef,
    package: SdkObjectSharePackage,
}
impl Fixture {
    fn new() -> Result<Self, SdkError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let root =
            std::env::temp_dir().join(format!("rf-deferred-{}-{unique}", std::process::id()));
        let client = open(&root, true)?;
        // Construct a real encrypted key slot using the donor's object key.
        let mut donor = RamfluxClient::new();
        let object = donor.put_encrypted_object("remote-object", b"received attachment")?;
        let key = donor.object_store.object_key(&object.object_id)?;
        let mut sender = ramflux_crypto::DmSession::initiator([7; 32], [1; 32], [2; 32], [3; 32])?;
        let receiver = ramflux_crypto::DmSession::recipient([7; 32], [2; 32], [1; 32], [3; 32])?;
        client.persist_dm_session("attachment-slot", "bootstrap", "recv", &receiver)?;
        let slot = SdkObjectKeySlot {
            schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
            version: 1,
            object_id: object.object_id.clone(),
            conversation_id: "attachment-slot".to_owned(),
            recipient_device_id: "recipient-device".to_owned(),
            x3dh: None,
            ciphertext: sender.encrypt(
                &key,
                &object_key_slot_associated_data(
                    &object.object_id,
                    "attachment-slot",
                    "recipient-device",
                ),
            )?,
        };
        let reference = SdkDmAttachmentRef {
            schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
            version: 1,
            object_id: object.object_id.clone(),
            manifest_hash: object.manifest_hash.clone(),
            plaintext_hash: object.plaintext_hash.clone(),
            cipher_size: object.ciphertext.len() as u64,
            chunk_size: 64,
            total_chunks: 1,
            relay_endpoint: "https://relay.invalid".to_owned(),
            owner_home_node_id: Some("owner.invalid".to_owned()),
            relay_audience_node_id: Some("relay.invalid".to_owned()),
            owner_principal_id: "owner".to_owned(),
            owner_device_epoch: 1,
            access_grant: None,
            key_slot: slot.clone(),
        };
        let package = SdkObjectSharePackage {
            schema: "ramflux.sdk.object_share_package.v1".to_owned(),
            version: 1,
            ciphertext_base64: ramflux_protocol::encode_base64url(&object.ciphertext),
            object,
            key_slot: slot,
        };
        client.persist_received_attachment_reference(
            &reference,
            "owner",
            "conversation",
            "message",
        )?;
        Ok(Self { client, root, reference, package })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn open(root: &Path, create: bool) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root("recipient", [0x21; 32]);
    client.create_device_branch("recipient", "recipient-device", 1, [0x22; 32]);
    client.open_account_index(root)?;
    if create {
        client.create_account("account", "commitment")?;
    }
    client.unlock_account("account", b"test-secret")?;
    Ok(client)
}

#[test]
fn reference_and_key_slot_survive_encrypted_account_reopen() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    let db_path = f.client.account_db()?.path.clone();
    let old = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(old);
    f.client = open(&f.root, false)?;
    let stored: ReceivedAttachment = f
        .client
        .account_db()?
        .load_actor_state(&reference_key("remote-object"))?
        .ok_or_else(|| SdkError::LocalBus("reference missing".to_owned()))?;
    assert_eq!(stored.reference.manifest_hash, f.reference.manifest_hash);
    assert!(
        stored.prepared_slot.is_some(),
        "content key and original slot reference must be durable"
    );
    assert!(f.client.received_attachment_prepared_slot(&stored.reference)?.is_some());
    let key = f.client.decrypt_object_key_slot(&stored.reference.key_slot)?;
    assert!(key.object_key.iter().any(|byte| *byte != 0));
    assert_eq!(
        f.client.account_db()?.client_directory_ids("object", "", 10)?,
        vec!["remote-object"]
    );
    assert_eq!(
        f.client.account_db()?.client_object_metadata("remote-object")?["transfer_state"],
        "not_fetched"
    );
    let bytes = std::fs::read(db_path)?;
    assert!(!bytes.starts_with(b"SQLite format 3"));
    assert!(!bytes.windows(b"remote-object".len()).any(|part| part == b"remote-object"));
    Ok(())
}

#[tokio::test]
async fn failed_fetch_preserves_message_then_same_operation_retries_and_replays()
-> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    f.client.account_db()?.import_direct_message_projection(DirectMessageWrite {
        conversation_id: "conversation",
        message_id: "message",
        sender_id: "owner",
        encrypted_body: b"still visible",
        metadata: &MessageMetadata::default(),
        created_at: 1,
    })?;
    let before = serde_json::to_value(f.client.account_db()?.direct_messages("conversation")?)?;
    let failed = f
        .client
        .fetch_received_with(
            "remote-object",
            "operation",
            FETCH_TIMEOUT,
            async |_client, _reference| {
                Err(SdkError::LocalBus("secret grant and key must never escape".to_owned()))
            },
        )
        .await?;
    assert_eq!(failed["transfer_state"], "failed");
    assert_eq!(
        serde_json::to_value(f.client.account_db()?.direct_messages("conversation")?)?,
        before
    );
    assert!(!failed.to_string().contains("secret grant"));
    let old = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(old);
    f.client = open(&f.root, false)?;
    let package = f.package.clone();
    let success = f
        .client
        .fetch_received_with(
            "remote-object",
            "operation",
            FETCH_TIMEOUT,
            async |client, _reference| {
                assert_eq!(
                    client
                        .received_attachment_status("remote-object")?
                        .ok_or(SdkError::AccountDbNotUnlocked)?["transfer_state"],
                    "retrying"
                );
                client.import_shared_object(&package)?;
                Ok(())
            },
        )
        .await?;
    assert_eq!(success["transfer_state"], "available");
    assert_eq!(f.client.decrypt_object("remote-object")?, b"received attachment");
    let replay = f
        .client
        .fetch_received_with(
            "remote-object",
            "operation",
            FETCH_TIMEOUT,
            async |_client, _reference| {
                Err(SdkError::LocalBus("must not run after success".to_owned()))
            },
        )
        .await?;
    assert_eq!(success, replay);
    let collision = f
        .client
        .fetch_received_with(
            "other-object",
            "operation",
            FETCH_TIMEOUT,
            async |_client, _reference| Ok(()),
        )
        .await;
    assert!(collision.is_err());
    for value in [failed, success, replay] {
        for private in ["key_slot", "access_grant", "ciphertext", "plaintext_base64", "object_key"]
        {
            assert!(!value.to_string().contains(private));
        }
    }
    Ok(())
}

#[test]
fn receive_replay_preserves_reference_and_chunk_checkpoint() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    let payload = ChunkPayload {
        chunk_index: 0,
        nonce: "nonce".to_owned(),
        ciphertext: vec![1, 2, 3],
        cipher_hash: "hash".to_owned(),
    };
    f.client.persist_received_attachment_chunk(&f.reference, &payload)?;
    f.client.persist_received_attachment_reference(
        &f.reference,
        "different-owner",
        "other-conversation",
        "other-message",
    )?;
    let old = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(old);
    f.client = open(&f.root, false)?;
    assert_eq!(f.client.received_attachment_chunk(&f.reference, 0)?, Some(payload));
    let saved = f
        .client
        .account_db()?
        .client_record("object", "remote-object")?
        .ok_or(SdkError::AccountDbNotUnlocked)?;
    assert_eq!(saved["message_id"], "message");
    assert_eq!(saved["owner"], "owner");
    Ok(())
}

#[tokio::test]
async fn deadline_and_invalid_reference_are_recorded_without_touching_messages()
-> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    let result = f
        .client
        .fetch_received_with(
            "remote-object",
            "deadline",
            Duration::from_millis(1),
            async |_client, _reference| std::future::pending().await,
        )
        .await?;
    assert_eq!(result["transfer_state"], "failed");
    assert!(result["last_error"].as_str().is_some_and(|error| error.contains("deadline")));
    let mut malformed = f.reference.clone();
    malformed.total_chunks = 4097;
    f.client.account_db()?.persist_actor_state(
        &reference_key("remote-object"),
        &ReceivedAttachment { reference: malformed, prepared_slot: None },
    )?;
    let result = f
        .client
        .fetch_received_with(
            "remote-object",
            "oversized",
            FETCH_TIMEOUT,
            async |_client, _reference| {
                Err(SdkError::LocalBus("should never invoke transport".to_owned()))
            },
        )
        .await?;
    assert_eq!(result["transfer_state"], "failed");
    assert!(!result.to_string().contains("should never invoke transport"));
    Ok(())
}

#[tokio::test]
async fn committed_slot_checkpoint_recovers_a_lost_success_receipt() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    f.client.import_shared_object(&f.package)?;
    let result = f
        .client
        .fetch_received_with(
            "remote-object",
            "recovered",
            FETCH_TIMEOUT,
            async |_client, _reference| {
                Err(SdkError::LocalBus("offline; must recover locally".to_owned()))
            },
        )
        .await?;
    assert_eq!(result["transfer_state"], "available");
    assert_eq!(f.client.received_attachment_receipt("remote-object", "recovered")?, Some(result));
    Ok(())
}

#[test]
fn interrupted_fetch_becomes_retryable_after_restart() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    f.client.persist_attachment_fetch_state(&FetchState {
        object_id: "remote-object".to_owned(),
        operation_id: "interrupted".to_owned(),
        transfer_state: "fetching".to_owned(),
        last_error: None,
        attempts: 1,
    })?;
    let old = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(old);
    f.client = open(&f.root, false)?;
    f.client.recover_received_attachment_fetches()?;
    let status = f
        .client
        .received_attachment_status("remote-object")?
        .ok_or(SdkError::AccountDbNotUnlocked)?;
    assert_eq!(status["transfer_state"], "failed");
    assert_eq!(status["retryable"], true);
    assert!(status["last_error"].as_str().is_some_and(|error| error.contains("interrupted")));
    assert!(f.client.received_attachment_receipt("remote-object", "interrupted")?.is_none());
    Ok(())
}

#[test]
fn received_attachment_reference_contains_no_live_ratchet_snapshot() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    let value: serde_json::Value = f
        .client
        .account_db()?
        .load_actor_state(&reference_key("remote-object"))?
        .ok_or_else(|| SdkError::LocalBus("missing reference".to_owned()))?;
    assert!(value["prepared_slot"].get("session").is_none());
    assert!(value["prepared_slot"].get("object_key").is_some());
    Ok(())
}

#[test]
fn a_received_object_selector_resolves_only_its_expected_manifest() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    f.client.persist_received_reference_prepared_at(
        &f.reference,
        "received:collision",
        ReferenceContext { owner: "owner", conversation: "conversation", message: "message" },
        None,
    )?;
    f.client.import_shared_object(&f.package)?;
    assert_eq!(f.client.decrypt_object("received:collision")?, b"received attachment");
    assert!(f.client.object_store_object("received:collision")?.is_some());
    let mut wrong = f.reference.clone();
    wrong.manifest_hash = "unrelated".to_owned();
    f.client.persist_received_reference_prepared_at(
        &wrong,
        "received:wrong",
        ReferenceContext { owner: "other", conversation: "other", message: "other" },
        None,
    )?;
    assert!(f.client.decrypt_object("received:wrong").is_err());
    Ok(())
}
