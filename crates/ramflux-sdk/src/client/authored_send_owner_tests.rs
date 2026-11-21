// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The authored message and its local media owners share one storage transaction.
use super::authored_send::stop_media_owners_after;
use super::native_test_support::{Fixture, TestResult, watchdog};
use crate::prelude::*;
use prost::Message as _;
use ramflux_protocol::large_attachment as large;
use ramflux_protocol::message as g;
use ramflux_sync::ObjectStore;

fn media_ref(object_id: &str) -> Result<g::MediaRef, SdkError> {
    let manifest = large::MediaManifest {
        manifest_id: [1; 32],
        plaintext_digest: [2; 32],
        plaintext_length: 64,
        ciphertext_length: 80,
        encrypted_segment_bytes: large::SEGMENT_BYTES,
        network_chunk_bytes: 524_288,
        segment_digests: vec![[3; 32]],
        key_slots: vec![large::MediaKeySlot {
            recipient: large::QualifiedDevice {
                account_anchor: "anchor".into(),
                device_id: "device".into(),
                device_epoch: 1,
            },
            encrypted_key: vec![4; 32],
            format: 1,
            grant_id: vec![6; 32],
            read_capability: b"capability".to_vec(),
        }],
        relay_origin: "https://relay.example".into(),
        read_capability: Vec::new(),
        expires_at: 4_000_000_000,
        retention_class: "relay_retained.v1".into(),
    };
    let digest = manifest.hash().map_err(|error| SdkError::LocalBus(format!("test: {error}")))?;
    let reference = large::MediaRef {
        object_id: object_id.into(),
        manifest_digest: digest,
        mime_type: "image/png".into(),
        size: manifest.plaintext_length,
        key_slots: manifest.key_slots.clone(),
        file_name: Some("pic.png".into()),
        inline_thumbnail: None,
        large_manifest: manifest,
    };
    let bytes = reference
        .canonical_bytes()
        .map_err(|error| SdkError::LocalBus(format!("test: {error}")))?;
    g::MediaRef::decode(bytes.as_slice())
        .map_err(|error| SdkError::LocalBus(format!("test: media: {error}")))
}

fn store_object(client: &RamfluxClient, object_id: &str, plaintext: &[u8]) -> Result<(), SdkError> {
    let mut donor = ObjectStore::new();
    let object = donor
        .put_encrypted_object(object_id, plaintext)
        .map_err(|error| SdkError::LocalBus(format!("test: {error}")))?;
    let key = donor
        .object_key(object_id)
        .map_err(|error| SdkError::LocalBus(format!("test: {error}")))?;
    client.account_db()?.upsert_object(&ramflux_storage::ObjectWrite {
        object_id,
        manifest_hash: &object.manifest_hash,
        nonce: &object.nonce,
        ciphertext: &object.ciphertext,
        plaintext_hash: &object.plaintext_hash,
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&key),
        object: &object,
        updated_at: 1,
    })?;
    Ok(())
}

struct ClearFault;

impl Drop for ClearFault {
    fn drop(&mut self) {
        stop_media_owners_after(0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn media_owners_commit_with_the_message_or_roll_back() -> TestResult {
    watchdog::within(async {
        let _clear = ClearFault;
        let mut fixture = Fixture::new("owner-commit").await?;
        let first = "owner-object-a";
        let second = "owner-object-b";
        store_object(&fixture.client, first, b"first-object")?;
        store_object(&fixture.client, second, b"second-object")?;
        let own = fixture.client.own_account_anchor()?;
        let device = fixture.client.owned_device_identity()?;
        let conversation = "owner-thread";
        let now_ms = u64::try_from(now_unix_timestamp())?.saturating_mul(1_000);
        let event = fixture.client.allocate_generated_identity(conversation, now_ms, false)?;
        let message_id = ramflux_protocol::encode_base64url(&event.id);
        let content = g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "two attachments".into(),
                media: vec![media_ref(first)?, media_ref(second)?],
                ..Default::default()
            })),
        };
        let exact = RamfluxClient::encode_generated_inner(event, &content)?;
        let message = GatewayDirectMessage {
            conversation_id: conversation.into(),
            message_id: message_id.clone(),
            envelope_id: "owner-envelope".into(),
            source_principal_id: fixture.config.principal_id.clone(),
            sender_id: device.device_id().into(),
            recipient_device_id: Some(device.device_id().into()),
            recipient_principal_commitment: Some(own),
            target_delivery_id: fixture.config.target_delivery_id.clone(),
            encrypted_body: b"cipher".to_vec(),
            created_at: now_unix_timestamp(),
            ttl: 300,
        };
        stop_media_owners_after(1);
        let stopped = fixture.client.project_authored_message(&message, &exact, b"cipher");
        let error = stopped.as_ref().err();
        assert!(
            matches!(
                error,
                Some(SdkError::InboundRejected(text))
                    if text.contains("media owner registration stopped")
            ),
            "the second owner must stop the commit: {error:?}"
        );
        fixture.reopen().await?;
        assert!(
            fixture.client.direct_message_by_id(&message_id)?.is_none(),
            "a failed owner commit must not leave the message"
        );
        assert!(
            fixture.client.account_db()?.sole_owner_ciphertext(&message_id)?.is_empty(),
            "a failed owner commit must not leave the first reference"
        );
        assert_eq!(
            fixture.client.decrypt_object(first)?.as_slice(),
            b"first-object",
            "rollback must keep the unreferenced object"
        );
        assert_eq!(
            fixture.client.decrypt_object(second)?.as_slice(),
            b"second-object",
            "the second object was not registered"
        );
        stop_media_owners_after(0);
        fixture.client.project_authored_message(&message, &exact, b"cipher")?;
        let owned = fixture.client.account_db()?.sole_owner_ciphertext(&message_id)?;
        assert_eq!(owned.len(), 2, "both references commit with the message");
        assert!(owned.iter().all(|(_, length)| *length > 0), "both ciphertexts are stored");
        let tombstone = ramflux_protocol::hash_base64url("ramflux.test.local-delete.v1", b"owners");
        fixture.client.delete_direct_message(conversation, &message_id, "local", &tombstone)?;
        for object_id in [first, second] {
            let erased = fixture.client.decrypt_object(object_id);
            assert!(
                matches!(erased, Err(SdkError::ObjectErased)),
                "{object_id} last-owner delete must erase the ciphertext: {erased:?}"
            );
        }
        fixture.reopen().await?;
        for object_id in [first, second] {
            let erased = fixture.client.decrypt_object(object_id);
            assert!(
                matches!(erased, Err(SdkError::ObjectErased)),
                "{object_id} stays erased after reopen: {erased:?}"
            );
        }
        Ok(())
    })
    .await?
}
