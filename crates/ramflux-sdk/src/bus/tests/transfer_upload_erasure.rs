// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An adopted imported payload loses its last message owner while an upload result is held.

use super::*;

fn seed_adopted_attachment(account: &LocalBusAccountState, relay: &Relay) -> Case {
    let plaintext = vec![42; 512];
    let mut donor = ramflux_sync::ObjectStore::new();
    let object = donor.put_encrypted_object(OBJECT, &plaintext)?;
    let key = donor.object_key(OBJECT)?;
    let db = account.client.account_db()?;
    db.send_direct_message("erase-upload-thread", "erase-upload-message", "sender", b"attachment")?;
    // Seed the existing imported recovery state, rather than making a standalone object erasable.
    db.register_object_reference(&ramflux_storage::ObjectReferenceOwner {
        reference_hash: "adopted-upload-reference",
        wire_id: OBJECT,
        manifest_hash: &object.manifest_hash,
        selector: OBJECT,
        message_id: "erase-upload-message",
        reference: &json!({}),
        metadata: &json!({}),
    })?;
    db.upsert_object(&ramflux_storage::ObjectWrite {
        object_id: OBJECT,
        manifest_hash: &object.manifest_hash,
        nonce: &object.nonce,
        ciphertext: &object.ciphertext,
        plaintext_hash: &object.plaintext_hash,
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&key),
        object: &object,
        updated_at: now_unix_timestamp(),
    })?;
    let body = LocalBusObjectPutRequest {
        object_id: OBJECT.into(),
        plaintext_base64: ramflux_protocol::encode_base64url(&plaintext),
        chunk_size: 128,
        relay_endpoint: Some(relay.endpoint.clone()),
        relay_service_key_base64: Some(ramflux_protocol::encode_base64url([41; 32])),
        relay_interrupt_after_chunks: None,
        operation_id: Some(OPERATION.into()),
    };
    let hash = crate::bus::dispatch::object::object_put_request_hash(
        &body,
        OPERATION,
        &object.plaintext_hash,
    )?;
    db.upsert_object_operation(&ObjectOperationWrite {
        object_id: OBJECT,
        operation_id: OPERATION,
        state: OBJECT_OPERATION_LOCAL_COMMITTED,
        request_hash: &hash,
        manifest_hash: Some(&object.manifest_hash),
        plaintext_hash: Some(&object.plaintext_hash),
        terminal_result: None,
        last_error: None,
        created_at: now_unix_timestamp(),
        updated_at: now_unix_timestamp(),
    })?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn erased_upload_drops_its_late_checkpoint_without_recreating_payload_or_operation() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("upload-erasure-fence")).await?;
    let reader = Rc::new(fixture.source.client.account_db()?.open_reader()?);
    let relay = Relay::start(Rc::new(|_, _, _| Ok(()))).await?;
    configure_upload_relay(&mut fixture, &relay)?;
    seed_adopted_attachment(&fixture.source, &relay)?;
    let (hook, mut capture) = Hook::upload_chunk(0);
    fixture.source.test_transfer_hook = Some(Arc::clone(&hook));
    let started = Box::pin(start(fixture)).await?;
    begin_upload(&started.actor, &relay).await?;
    let actor = started.actor.clone();
    let mut result = tokio::task::spawn_local(async move { actor.request(finish()).await });
    let held = wait_for_upload_checkpoint(&mut capture, &mut result, &relay).await?;
    assert!(held.upload_ack_is_open());
    assert!(reader.load_object::<EncryptedObject>(OBJECT)?.is_some());
    started
        .actor
        .request(command(
            "message.delete",
            json!({
                "conversation_id":"erase-upload-thread","message_id":"erase-upload-message",
                "delete_scope":"own_devices","tombstone_id":"erase-upload-checkpoint",
            }),
        ))
        .await?;
    assert!(reader.check_object_access(OBJECT).is_err());
    held.release().await?;
    assert!(result.await?.is_err(), "an erased upload must never complete successfully");
    assert!(matches!(
        reader.load_object::<EncryptedObject>(OBJECT),
        Err(StorageError::ObjectErased)
    ));
    assert!(
        reader.load_objects::<EncryptedObject>()?.0.is_empty(),
        "no object payload may reappear in the generic listing"
    );
    assert!(matches!(reader.object_operation(OBJECT), Err(StorageError::ObjectErased)));
    assert!(matches!(
        reader.object_transfer(OBJECT, Some(OBJECT_TRANSFER_UPLOAD)),
        Err(StorageError::ObjectErased)
    ));
    assert_eq!(relay.state.lock().map_err(|_| "relay")?.requests, vec![(Step::Put, 0)]);
    assert_no_spool(&started)?;
    Box::pin(cleanup(started, reader, relay)).await
}
