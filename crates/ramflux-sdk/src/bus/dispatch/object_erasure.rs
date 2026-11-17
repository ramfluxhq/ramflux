// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Last-owner erasure reported on a successful local delete.
//!
//! The retention trigger removes ciphertext in the same statement that drops the
//! last message owner, so the byte count is measured before that statement.

use crate::SdkError;
use ramflux_storage::{AccountDb, StorageError};

pub(super) fn preview(db: &AccountDb, message_id: &str) -> Result<Vec<(String, u64)>, SdkError> {
    if message_id.is_empty() {
        return Ok(Vec::new());
    }
    Ok(db.sole_owner_ciphertext(message_id)?)
}

/// Confirms which previewed objects the delete actually erased.
///
/// # Errors
/// Returns an error when the erasure fence cannot be read.
pub(super) fn confirm(db: &AccountDb, preview: &[(String, u64)]) -> Result<(bool, u64), SdkError> {
    let mut seen = Vec::<&str>::new();
    let mut erased = false;
    let mut bytes = 0_u64;
    for (object_id, length) in preview {
        if seen.iter().any(|seen_id| *seen_id == object_id) {
            continue;
        }
        seen.push(object_id);
        match db.check_object_access(object_id) {
            Err(StorageError::ObjectErased) => {
                erased = true;
                bytes = bytes.saturating_add(*length);
            }
            Ok(()) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok((erased, bytes))
}

pub(super) fn attach(body: &mut serde_json::Value, erased: bool, bytes: u64) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    object.insert("object_erased".to_owned(), serde_json::Value::Bool(erased));
    object.insert("bytes_erased".to_owned(), serde_json::json!(bytes));
    if erased {
        object.insert("code".to_owned(), serde_json::Value::String("ObjectErased".to_owned()));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::large_futures)]
mod tests {
    use super::super::message_delete;
    use crate::prelude::*;
    use std::future::Future;

    const ACCOUNT: &str = "acct";

    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(10), future).await.expect("deadline")
    }

    fn open_state(data_root: &Path) -> LocalBusDaemonState {
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_spool_test", [0x51; 32]);
        client.create_device_branch("principal_spool_test", "device_spool_test", 1, [0x52; 32]);
        client.open_account_index(data_root).expect("open account index");
        client.create_account(ACCOUNT, "principal_spool_test").expect("create account");
        client.set_active_account(ACCOUNT).expect("set active account");
        client.unlock_account(ACCOUNT, b"spool-test-secret").expect("unlock account");
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_spool_test".to_owned(),
            device_id: "device_spool_test".to_owned(),
            target_delivery_id: "target_spool_test".to_owned(),
            prekey_http_url: None,
        });
        LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(data_root.join("bus.sock"), data_root),
            accounts: BTreeMap::from([(
                ACCOUNT.to_owned(),
                LocalBusAccountState::disconnected(
                    client,
                    gateway,
                    "principal_spool_test".to_owned(),
                ),
            )]),
            active_account_id: Some(ACCOUNT.to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    fn fixture(name: &str) -> (ramflux_test_support::TestPath, LocalBusDaemonState) {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        let root = ramflux_test_support::TestPath::new()
            .expect("fixture directory")
            .child(format!("observe-{name}-{}-{nanos}", std::process::id()));
        let state = open_state(&root);
        (root, state)
    }

    fn account(state: &mut LocalBusDaemonState) -> &mut LocalBusAccountState {
        state.accounts.get_mut(ACCOUNT).expect("account")
    }

    fn store_object(
        db: &AccountDb,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, SdkError> {
        let mut donor = ObjectStore::new();
        let object = donor.put_encrypted_object(object_id, plaintext)?;
        let key = donor.object_key(object_id)?;
        db.upsert_object(&ObjectWrite {
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
        Ok(object)
    }

    fn own(
        db: &AccountDb,
        object: &EncryptedObject,
        message_id: &str,
        reference_hash: &str,
    ) -> Result<(), SdkError> {
        db.send_direct_message("thread", message_id, "peer", b"body")?;
        db.register_object_reference(
            ramflux_storage::ObjectReferenceAdmission::FreshMessage,
            &ramflux_storage::ObjectReferenceOwner {
                reference_hash,
                wire_id: &object.object_id,
                manifest_hash: &object.manifest_hash,
                selector: &object.object_id,
                message_id,
                reference: &serde_json::json!({}),
                metadata: &serde_json::json!({}),
            },
        )?;
        Ok(())
    }

    fn package(object: &EncryptedObject) -> SdkObjectSharePackage {
        SdkObjectSharePackage {
            schema: "ramflux.sdk.object_share_package.v1".to_owned(),
            version: 1,
            object: object.clone(),
            ciphertext_base64: "!!!!".to_owned(),
            key_slot: SdkObjectKeySlot {
                schema: "slot".to_owned(),
                version: 1,
                object_id: object.object_id.clone(),
                conversation_id: "thread".to_owned(),
                recipient_device_id: "device".to_owned(),
                source_principal_commitment: None,
                x3dh: None,
                ciphertext: ramflux_crypto::DmCiphertext {
                    session_id: String::new(),
                    counter: 0,
                    nonce: [0; 12],
                    ciphertext: Vec::new(),
                    ratchet_public_key: None,
                    previous_chain_length: 0,
                    sender_device_id_hash: [0; 32],
                    recipient_device_id_hash: [0; 32],
                    device_epoch: 0,
                    message_event_id: String::new(),
                    canonical_header_bytes: Vec::new(),
                    header_hash: String::new(),
                    key_commitment: String::new(),
                    franking_commitment: String::new(),
                    commitment: String::new(),
                    ciphertext_hash: String::new(),
                },
            },
        }
    }

    async fn delete_local(
        account: &mut LocalBusAccountState,
        message_id: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let frame = LocalBusFrame::request(
            "req",
            Some(ACCOUNT.to_owned()),
            "message",
            "message.delete",
            serde_json::json!({
                "conversation_id": "thread",
                "message_id": message_id,
                "delete_scope": "local",
            }),
        );
        Ok(message_delete::dispatch(&frame, account).await?.response_body)
    }

    #[tokio::test]
    async fn tombstoned_import_is_attachment_deleted_and_a_broken_package_is_not() {
        within(async {
            let (_root, mut state) = fixture("import");
            let broken = {
                let db = account(&mut state).client.account_db().expect("db");
                let object = store_object(db, "obj-revoked", b"secret-bytes").expect("store");
                package(&object)
            };
            let before =
                account(&mut state).client.import_shared_object(&broken).expect_err("broken");
            assert!(
                matches!(before, SdkError::GeneratedRefused { .. }),
                "broken package before a tombstone must not be AttachmentDeleted: {before:?}"
            );
            account(&mut state)
                .client
                .account_db()
                .expect("db")
                .set_object_tombstoned("obj-revoked")
                .expect("tombstone");
            let refused = account(&mut state)
                .client
                .import_shared_object(&broken)
                .expect_err("tombstoned import");
            assert!(
                matches!(refused, SdkError::AttachmentDeleted),
                "tombstoned import must be AttachmentDeleted: {refused:?}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn local_delete_reports_sole_owner_bytes_and_keeps_a_shared_reference() {
        within(async {
            let (_root, mut state) = fixture("erase");
            let sole = {
                let db = account(&mut state).client.account_db().expect("db");
                let object = store_object(db, "obj-sole", b"sole-owner-bytes").expect("store");
                let bytes = u64::try_from(object.ciphertext.len()).expect("length");
                own(db, &object, "sole-message", "sole-reference").expect("own");
                bytes
            };
            let response = delete_local(account(&mut state), "sole-message").await.expect("delete");
            assert_eq!(response["object_erased"], serde_json::json!(true), "sole owner erased");
            assert_eq!(response["bytes_erased"], serde_json::json!(sole), "sole owner bytes");
            assert_eq!(response["code"], "ObjectErased", "erasure code");
            let gone = account(&mut state)
                .client
                .account_db()
                .expect("db")
                .load_object::<EncryptedObject>("obj-sole");
            assert!(
                matches!(gone, Err(StorageError::ObjectErased)),
                "sole object must be erased: {gone:?}"
            );

            let shared_len = {
                let db = account(&mut state).client.account_db().expect("db");
                let object = store_object(db, "obj-shared", b"shared-owner-bytes").expect("store");
                let bytes = object.ciphertext.len();
                own(db, &object, "shared-a", "shared-reference-a").expect("own a");
                own(db, &object, "shared-b", "shared-reference-b").expect("own b");
                bytes
            };
            let response =
                delete_local(account(&mut state), "shared-a").await.expect("delete shared");
            assert_eq!(
                response["object_erased"],
                serde_json::json!(false),
                "shared reference stays"
            );
            assert_eq!(response["bytes_erased"], serde_json::json!(0), "shared bytes stay");
            assert!(response.get("code").is_none(), "shared delete has no erasure code");
            let kept = account(&mut state)
                .client
                .account_db()
                .expect("db")
                .load_object::<EncryptedObject>("obj-shared")
                .expect("shared object")
                .expect("row");
            assert_eq!(kept.0.ciphertext.len(), shared_len, "shared ciphertext remains");
        })
        .await;
    }

    fn committed_state(data_root: &Path) -> LocalBusDaemonState {
        let mut client = RamfluxClient::new();
        let root = client.create_identity_root("principal_spool_test", [0x51; 32]);
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        client.create_device_branch("principal_spool_test", "device_spool_test", 1, [0x52; 32]);
        client.open_account_index(data_root).expect("open account index");
        client.create_account(ACCOUNT, &commitment).expect("create account");
        client.set_active_account(ACCOUNT).expect("set active account");
        client.unlock_account(ACCOUNT, b"spool-test-secret").expect("unlock account");
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_spool_test".to_owned(),
            device_id: "device_spool_test".to_owned(),
            target_delivery_id: "target_spool_test".to_owned(),
            prekey_http_url: None,
        });
        LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(data_root.join("bus.sock"), data_root),
            accounts: BTreeMap::from([(
                ACCOUNT.to_owned(),
                LocalBusAccountState::disconnected(client, gateway, commitment),
            )]),
            active_account_id: Some(ACCOUNT.to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    fn media_with_thumbnail(object_id: &str) -> ramflux_protocol::message::MediaRef {
        use prost::Message as _;
        use ramflux_protocol::large_attachment as large;
        let slots = vec![large::MediaKeySlot {
            recipient: large::QualifiedDevice {
                account_anchor: "anchor".into(),
                device_id: "device".into(),
                device_epoch: 1,
            },
            encrypted_key: vec![4; 32],
            format: 1,
            grant_id: Vec::new(),
            read_capability: Vec::new(),
        }];
        let manifest = large::MediaManifest {
            manifest_id: [1; 32],
            plaintext_digest: [2; 32],
            plaintext_length: 64,
            ciphertext_length: 80,
            encrypted_segment_bytes: large::SEGMENT_BYTES,
            network_chunk_bytes: 524_288,
            segment_digests: vec![[3; 32]],
            key_slots: slots.clone(),
            relay_origin: "https://relay.example".into(),
            read_capability: vec![5; 32],
            expires_at: 4_000_000_000,
            retention_class: "relay_retained.v1".into(),
        };
        let reference = large::MediaRef {
            object_id: object_id.into(),
            manifest_digest: manifest.hash().expect("manifest hash"),
            mime_type: "image/jpeg".into(),
            size: manifest.plaintext_length,
            key_slots: slots,
            file_name: Some("pic.jpg".into()),
            inline_thumbnail: Some(large::Thumbnail {
                mime_type: "image/jpeg".into(),
                width: 1,
                height: 1,
                encoded_image: b"thumb-bytes".to_vec(),
            }),
            large_manifest: manifest,
        };
        ramflux_protocol::message::MediaRef::decode(
            reference.canonical_bytes().expect("canonical media").as_slice(),
        )
        .expect("prost media")
    }

    #[tokio::test]
    async fn authored_media_projection_binds_the_stored_object() {
        within(async {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
            let root = ramflux_test_support::TestPath::new()
                .expect("fixture directory")
                .child(format!("observe-bind-{}-{nanos}", std::process::id()));
            let mut state = committed_state(&root);
            let stored = {
                let db = account(&mut state).client.account_db().expect("db");
                store_object(db, "obj-bind", b"bind-bytes").expect("store")
            };
            let media = media_with_thumbnail("obj-bind");
            let content = RamfluxClient::attachment_message_content("caption", &[media])
                .expect("attachment content");
            let own = account(&mut state).client.owned_device_identity().expect("owned device");
            let epoch = account(&mut state)
                .client
                .device_branch
                .as_ref()
                .expect("device branch")
                .device_epoch;
            let author = ramflux_protocol::message::QualifiedDevice {
                account_anchor: own.root_commitment().to_owned(),
                device_id: own.device_id().to_owned(),
                device_epoch: epoch,
            };
            let id = ramflux_protocol::message::identity::derive(&author, "thread", 1)
                .expect("message id");
            let identity = ramflux_protocol::message::EventIdentity {
                id: id.to_vec(),
                conversation_id: "thread".into(),
                author: Some(author),
                device_sequence: 1,
                hlc: 1,
                group_id: None,
                group_epoch: None,
            };
            let exact =
                RamfluxClient::encode_generated_inner(identity, &content).expect("encode message");
            let message_id = ramflux_protocol::encode_base64url(id);
            let gateway = GatewayDirectMessage {
                conversation_id: "thread".into(),
                message_id: message_id.clone(),
                envelope_id: "envelope".into(),
                source_principal_id: "principal_spool_test".into(),
                sender_id: own.device_id().to_owned(),
                recipient_device_id: Some(own.device_id().to_owned()),
                recipient_principal_commitment: Some(own.root_commitment().to_owned()),
                target_delivery_id: "target_spool_test".into(),
                encrypted_body: Vec::new(),
                created_at: 1,
                ttl: 300,
            };
            account(&mut state)
                .client
                .project_authored_message(&gateway, &exact, &[])
                .expect("project");
            let owned = account(&mut state)
                .client
                .account_db()
                .expect("db")
                .sole_owner_ciphertext(&message_id)
                .expect("owners");
            let bytes = u64::try_from(stored.ciphertext.len()).expect("ciphertext length");
            assert!(
                owned.iter().any(|(id, len)| id == "obj-bind" && *len == bytes),
                "local media owner was not bound to the stored ciphertext: {owned:?}"
            );
        })
        .await;
    }
}
