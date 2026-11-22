// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deleted generated rows retain only public identity and tombstone state in both readers.

use super::*;
use ramflux_protocol::message as g;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn list_and_read_project_deleted_peer_and_own_rows_without_private_content() -> TestResult {
    let root = crate::bus::runtime_tests::root("deleted-message-readers");
    let index = AccountIndex::open(&root)?;
    let own_root = ramflux_crypto::create_identity_root("principal", [42; 32]);
    let own_branch = ramflux_crypto::create_device_branch("principal", "principal", 1, [43; 32]);
    let owner = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&own_root, &own_branch)?;
    index.create_account("account", owner.root_commitment())?;
    let key = ramflux_storage::AccountDbKey::derive("account", b"deleted-reader-secret");
    let db = AccountDb::open(&index, "account", &key)?;
    for (sequence, sender, body) in [
        (1, "peer-device-secret", b"peer-body".as_slice()),
        (2, "principal", b"own-body".as_slice()),
    ] {
        let author = g::QualifiedDevice {
            account_anchor: if sequence == 2 {
                owner.root_commitment().into()
            } else {
                ramflux_protocol::encode_base64url([u8::try_from(sequence)?; 32])
            },
            device_id: sender.into(),
            device_epoch: 1,
        };
        let identity = g::EventIdentity {
            id: g::identity::derive(&author, "thread", sequence)?.to_vec(),
            conversation_id: "thread".into(),
            author: Some(author),
            device_sequence: sequence,
            hlc: sequence << 16,
            ..Default::default()
        };
        let id = ramflux_protocol::encode_base64url(&identity.id);
        db.send_direct_message("thread", &id, sender, body)?;
        db.persist_message_actor_state(&id, &format!("routed/generated-identity/{id}"), &identity)?;
        if sequence == 2 {
            db.mark_generated_message_owned(&id, &owner)?;
        }
        db.delete_direct_message(
            "thread",
            &id,
            "local",
            &ramflux_protocol::encode_base64url([u8::try_from(sequence)?; 32]),
        )?;
    }

    {
        let method = "message.read";
        let request = LocalBusFrame::request(
            method,
            Some("account".to_owned()),
            "client",
            method,
            json!({"conversation_id":"thread","read_model":true}),
        );
        let response = test_account_reader_request(&db, request).await?;
        let messages = response["messages"].as_array().ok_or("messages")?;
        assert_eq!(messages.len(), 2, "both erased generated rows must remain visible");
        for is_own in [false, true] {
            let message =
                messages.iter().find(|message| message["is_own"] == is_own).ok_or("ownness")?;
            assert_eq!(message["state"], "tombstone", "erased rows keep their public placeholder");
            assert_eq!(message["kind"], "tombstone", "erased content cannot be rendered");
            for field in ["text", "content", "unsupported"] {
                assert!(message[field].is_null(), "erased row leaked {field}");
            }
            assert_eq!(
                message["erasure"]["scope"], "local",
                "local scope must survive restart readers"
            );
            assert_eq!(message["revision"], 0, "erasure removes edit state");
            for field in ["receipts", "reactions"] {
                assert_eq!(message[field], json!([]), "erasure removes {field}");
            }
        }
        let encoded = serde_json::to_string(messages)?;
        for secret in ["peer-body", "own-body"] {
            assert!(!encoded.contains(secret), "erased private body leaked through the reader");
        }
    }
    drop(db);
    drop(index);
    Ok(())
}
