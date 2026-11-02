// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Listing a received native attachment must not put its ciphertext into a metadata frame.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn native_received_attachment_listing_avoids_ciphertext_frame_overflow() -> TestResult {
    let mut receiver = Fixture::new("attachment-list").await?;
    let mut sender = ramflux_sync::ObjectStore::new();
    let object = sender.put_encrypted_object("received-attachment", &vec![0x5a; 300_000])?;
    let key = sender.object_key(&object.object_id)?;
    // Install the same verified ciphertext/key pair persisted by the successful import path.
    let blob = receiver.client.object_store.put_received_encrypted_object_with_key(
        &object.object_id,
        &object.manifest_hash,
        &object.ciphertext,
        &object.plaintext_hash,
        key,
    );
    receiver.client.persist_object_if_unlocked(&blob, Some(&key), ObjectRetention::Imported)?;
    receiver.client.account_db()?.persist_client_record(
        "object",
        &object.object_id,
        &serde_json::json!({"direction":"incoming","owner":"sender","size":300_000}),
    )?;
    let request = LocalBusFrame::request(
        "list",
        Some("attachment-list".into()),
        "object",
        "object.list",
        serde_json::json!({}),
    );
    let error = crate::bus::dispatch::object::object_list_response(&request, &receiver.client)
        .err()
        .ok_or("legacy full-payload response exceeded the frame limit without an error")?;
    assert!(matches!(&error,SdkError::LocalBus(reason) if reason.contains("use object.directory")));
    let error_frame = crate::bus::io::local_bus_error(&request, &error);
    assert!(crate::bus::io::encode_local_bus_frame(&error_frame)?.len() < 4096);
    let directory = LocalBusFrame::request(
        "directory",
        Some("attachment-list".into()),
        "object",
        "object.directory",
        serde_json::json!({"limit":100}),
    );
    let metadata = crate::bus::read_model::read(&receiver.client, &directory)?;
    assert_eq!(metadata["objects"][0]["id"], object.object_id);
    assert_eq!(metadata["objects"][0]["direction"], "incoming");
    let frame = crate::bus::io::local_bus_response(&directory, metadata.clone());
    assert!(crate::bus::io::encode_local_bus_frame(&frame)?.len() < 4096);
    for private_field in ["ciphertext", "nonce", "key_slot", "access_grant"] {
        assert!(
            metadata["objects"][0].get(private_field).is_none(),
            "unexpected field {private_field}"
        );
    }
    assert_eq!(receiver.client.decrypt_object(&object.object_id)?.len(), 300_000);
    Ok(())
}
