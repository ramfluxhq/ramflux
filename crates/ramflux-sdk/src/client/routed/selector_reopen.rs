// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated routed candidate admission and actual cached import boundaries.
#![cfg(test)]
use super::*;
use crate::dm::{SdkDmAttachmentEnvelope, SdkDmAttachmentRef};
use std::cell::RefCell;

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Default)]
struct Observation {
    imports: Vec<String>,
    registrations: usize,
    refused: usize,
    fence_at_import: Option<String>,
}
thread_local! {
    static OBSERVED: RefCell<Observation> = RefCell::default();
}
pub(in crate::client::routed) fn registered(result: &Result<(), SdkError>) {
    OBSERVED.with_borrow_mut(|o| {
        o.registrations += 1;
        o.refused += usize::from(matches!(result, Err(SdkError::ObjectErased)));
    });
}
pub(in crate::client::routed) fn import_entry(
    client: &RamfluxClient,
    reference: &SdkDmAttachmentRef,
) -> Result<(), SdkError> {
    let fence = OBSERVED.with_borrow_mut(|o| {
        o.imports.push(reference.object_id.clone());
        o.fence_at_import.as_ref() == Some(&reference.object_id)
    });
    if fence {
        client.account_db()?.retain_object(
            &reference.object_id,
            &reference.manifest_hash,
            ramflux_storage::ObjectRetention::OwnDeviceTransport,
        )?;
        client
            .account_db()?
            .retire_transport_object(&reference.object_id, &reference.manifest_hash)?;
    }
    Ok(())
}
struct Case {
    a: Fixture,
    b: Fixture,
    refs: Vec<SdkDmAttachmentRef>,
}
impl Case {
    fn new() -> Result<Self, SdkError> {
        OBSERVED.with_borrow_mut(|o| *o = Observation::default());
        let a = Fixture::new("alice", 21)?;
        let mut b = Fixture::new("bob", 31)?;
        b.client.establish_friend_link(
            "link",
            a.client.owned_device_identity()?.root_commitment(),
            b.client.owned_device_identity()?.root_commitment(),
        )?;
        let mut refs = Vec::new();
        for (n, id) in ["good-one", "refused", "good-two"].into_iter().enumerate() {
            let prepared = b.client.object_store.prepare_encrypted_object(id, id.as_bytes())?;
            let object = prepared.object().clone();
            let key = *prepared.object_key();
            let db = b.client.account_db()?;
            db.retain_object(
                id,
                &object.manifest_hash,
                ramflux_storage::ObjectRetention::OwnDeviceTransport,
            )?;
            db.upsert_object(&ramflux_storage::ObjectWrite {
                object_id: id,
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
            let _ = b.client.object_store.install_prepared_object(prepared);
            let conversation = format!("slot-{n}");
            let mut send = ramflux_crypto::DmSession::initiator(
                [7; 32],
                dm_device_id_hash("alice"),
                dm_device_id_hash("bob"),
                [3; 32],
            )?;
            let recv = ramflux_crypto::DmSession::recipient(
                [7; 32],
                dm_device_id_hash("bob"),
                dm_device_id_hash("alice"),
                [3; 32],
            )?;
            b.client.persist_dm_session(&conversation, "bootstrap", "recv", &recv)?;
            let slot = crate::SdkObjectKeySlot {
                schema: "ramflux.sdk.object_key_slot.dm.v1".into(),
                version: 1,
                object_id: id.into(),
                conversation_id: conversation.clone(),
                recipient_device_id: "bob".into(),
                source_principal_commitment: None,
                x3dh: None,
                ciphertext: send
                    .encrypt(&key, &object_key_slot_associated_data(id, &conversation, "bob"))?,
            };
            refs.push(SdkDmAttachmentRef {
                schema: "ramflux.sdk.dm_attachment_ref.v1".into(),
                version: 1,
                object_id: id.into(),
                manifest_hash: object.manifest_hash,
                plaintext_hash: object.plaintext_hash,
                cipher_size: object.ciphertext.len() as u64,
                chunk_size: 512 * 1024,
                total_chunks: 1,
                relay_endpoint: "https://relay.invalid".into(),
                owner_home_node_id: Some("home.invalid".into()),
                relay_audience_node_id: Some("relay.invalid".into()),
                owner_principal_id: "alice".into(),
                owner_device_epoch: 1,
                access_grant: None,
                key_slot: slot,
            });
        }
        Ok(Self { a, b, refs })
    }
    fn fence(&self) -> Result<(), SdkError> {
        self.b.client.account_db()?.retain_object(
            &self.refs[1].object_id,
            &self.refs[1].manifest_hash,
            ramflux_storage::ObjectRetention::OwnDeviceTransport,
        )?;
        self.b
            .client
            .account_db()?
            .retire_transport_object(&self.refs[1].object_id, &self.refs[1].manifest_hash)?;
        assert!(matches!(
            self.b
                .client
                .account_db()?
                .check_object_identity(&self.refs[1].object_id, &self.refs[1].manifest_hash),
            Err(ramflux_storage::StorageError::ObjectErased)
        ));
        Ok(())
    }
    fn entry(&self, id: &str) -> Result<GatewayInboxEntry, SdkError> {
        let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
            schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
            version: 1,
            body_base64: ramflux_protocol::encode_base64url(b"preserved text"),
            attachments: self.refs.clone(),
        })?;
        seal_as(&self.a, &self.b, message(id, "conversation"), &body, Route::attachments())
    }
    async fn receive(
        &mut self,
        entry: &GatewayInboxEntry,
        fetch: bool,
    ) -> Result<Delivery, SdkError> {
        let mut engine =
            GatewaySessionEngine::with_test_transport(self.b.config()?, Box::new(NoNetwork));
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default()
                .map_err(|e| invalid(&e.to_string()))?,
        );
        self.b.client.apply_routed_entry_candidate(&mut engine, &pool, entry, fetch).await
    }
    async fn assert_mixed(&mut self, late: bool) -> TestResult {
        if late {
            OBSERVED.with_borrow_mut(|o| o.fence_at_import = Some("refused".into()));
        } else {
            self.fence()?;
        }
        let entry = self.entry("fresh-m3")?;
        assert!(self.b.client.routed_seen_marker(&entry)?.is_none());
        let delivery = self.receive(&entry, true).await?;
        let content = delivery.plaintext.ok_or("missing valid content")?;
        assert_eq!(
            ramflux_protocol::decode_base64url(&content.plaintext_body_base64)?,
            b"preserved text"
        );
        assert_eq!(
            content.attachments.iter().map(|a| a.object_id.as_str()).collect::<Vec<_>>(),
            ["good-one", "good-two"]
        );
        OBSERVED.with_borrow(|o| {
            assert_eq!(o.registrations, 3);
            assert_eq!(o.refused, usize::from(!late));
            assert_eq!(
                o.imports,
                if late {
                    vec!["good-one", "refused", "good-two"]
                } else {
                    vec!["good-one", "good-two"]
                }
            );
        });
        assert!(self.b.client.routed_seen_marker(&entry)?.is_some());
        assert_eq!(self.b.client.account_db()?.due_inbox_retries(i64::MAX)?, Vec::<Vec<u8>>::new());
        assert!(self.receive(&entry, true).await?.plaintext.is_none());
        assert_eq!(self.b.client.direct_messages("conversation")?.len(), 1);
        Ok(())
    }
}
#[tokio::test]
async fn e16_payload_fenced_m3_refused_without_retry() -> TestResult {
    Case::new()?.assert_mixed(false).await
}
#[tokio::test]
async fn e16_routed_import_receives_only_admitted_subset() -> TestResult {
    Case::new()?.assert_mixed(false).await
}
#[tokio::test]
async fn e16_routed_receive_mixed_valid_and_fenced_attachments_auto_fetch() -> TestResult {
    Case::new()?.assert_mixed(false).await
}
#[tokio::test]
async fn e16_routed_item_fenced_between_registration_and_import_is_consumed() -> TestResult {
    Case::new()?.assert_mixed(true).await
}
#[tokio::test]
async fn e16_m2_replay_refused_without_retry() -> TestResult {
    let mut c = Case::new()?;
    let entry = c.entry("m2")?;
    c.receive(&entry, false).await?;
    let id =
        c.b.client.direct_messages("conversation")?.first().ok_or("message")?.message_id.clone();
    c.b.client.account_db()?.delete_direct_message("conversation", &id, "local", "erase")?;
    assert!(c.receive(&entry, true).await?.plaintext.is_none());
    Ok(())
}
#[tokio::test]
async fn e16_unrelated_valid_messages_progress() -> TestResult {
    let mut c = Case::new()?;
    c.assert_mixed(false).await?;
    let entry = seal(&c.a, &c.b, message("next", "conversation"), b"next text")?;
    assert!(c.receive(&entry, false).await?.plaintext.is_some());
    assert_eq!(c.b.client.direct_messages("conversation")?.len(), 2);
    Ok(())
}
#[tokio::test]
async fn e16_fresh_m3_reopens_closed_alias_via_routed_receive() -> TestResult {
    let mut c = Case::new()?;
    // A different authenticated sender already owns the shared wire identity.
    let reference = c.refs[0].clone();
    let first = c.entry("m1")?;
    c.receive(&first, false).await?;
    // Keep m1's wire while the same wire from a second sender uses its deterministic alias.
    let mut carol = Fixture::new("carol", 51)?;
    std::mem::swap(&mut c.a, &mut carol);
    for (index, r) in c.refs.iter_mut().enumerate() {
        r.owner_principal_id = "carol".into();
        let conversation = format!("carol-slot-{index}");
        let mut send = ramflux_crypto::DmSession::initiator(
            [8; 32],
            dm_device_id_hash("carol"),
            dm_device_id_hash("bob"),
            [4; 32],
        )?;
        let recv = ramflux_crypto::DmSession::recipient(
            [8; 32],
            dm_device_id_hash("bob"),
            dm_device_id_hash("carol"),
            [4; 32],
        )?;
        c.b.client.persist_dm_session(&conversation, "bootstrap", "recv", &recv)?;
        r.key_slot.conversation_id = conversation.clone();
        r.key_slot.ciphertext = send.encrypt(
            &c.b.client.object_content_key(&r.object_id)?,
            &object_key_slot_associated_data(&r.object_id, &conversation, "bob"),
        )?;
    }
    c.b.client.establish_friend_link(
        "carol-link",
        c.a.client.owned_device_identity()?.root_commitment(),
        c.b.client.owned_device_identity()?.root_commitment(),
    )?;
    let mut msg = message("m2", "carol-conversation");
    msg.source_principal_id = "carol".into();
    msg.sender_id = "carol".into();
    let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
        schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
        version: 1,
        body_base64: ramflux_protocol::encode_base64url(b"alias"),
        attachments: vec![c.refs[0].clone()],
    })?;
    let entry = seal_as(&c.a, &c.b, msg, &body, Route::attachments())?;
    let id = c
        .receive(&entry, false)
        .await
        .map_err(|e| format!("m2 receive: {e:?}"))?
        .plaintext
        .ok_or("m2")?
        .message_id;
    let alias =
        c.b.client
            .account_db()?
            .actor_state_keys("attachment/reference/received:")?
            .into_iter()
            .next()
            .ok_or("alias")?
            .trim_start_matches("attachment/reference/")
            .to_owned();
    c.b.client.account_db()?.delete_direct_message("carol-conversation", &id, "local", "erase")?;
    assert!(matches!(
        c.b.client.account_db()?.check_object_access(&alias),
        Err(ramflux_storage::StorageError::ObjectErased)
    ));
    assert_eq!(
        c.b.client.account_db()?.actor_state_keys(&format!("attachment/reference/{alias}"))?,
        Vec::<String>::new()
    );
    c.b.client
        .account_db()?
        .check_object_access(&reference.object_id)
        .map_err(|e| format!("surviving wire: {e:?}"))?;
    let mut msg = message("m3", "carol-conversation");
    msg.source_principal_id = "carol".into();
    msg.sender_id = "carol".into();
    let fresh = seal_as(&c.a, &c.b, msg, &body, Route::attachments())?;
    c.receive(&fresh, false).await.map_err(|e| format!("m3 receive: {e:?}"))?;
    c.b.client.account_db()?.check_object_access(&alias).map_err(|e| format!("m3 alias: {e:?}"))?;
    assert_ne!(
        c.b.client.account_db()?.actor_state_keys(&format!("attachment/reference/{alias}"))?,
        Vec::<String>::new()
    );
    let mut reopened = RamfluxClient::new();
    reopened.open_account_index(&c.b.root)?;
    reopened.unlock_account("bob", b"routed-test")?;
    reopened
        .account_db()?
        .check_object_access(&alias)
        .map_err(|e| format!("reopened alias: {e:?}"))?;
    assert_eq!(
        reopened.decrypt_object(&alias).map_err(|e| format!("reopened decrypt: {e:?}"))?,
        b"good-one"
    );
    Ok(())
}

fn connection(c: &Case) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    use ramflux_storage::{FileVaultSecretSource, VaultSecretSource};
    use std::fmt::Write;
    let vault = FileVaultSecretSource::new(&c.b.root).vault_secret("bob")?;
    let wrapped = c.b.client.account_index()?.load_wrapped_db_key("bob")?.ok_or("wrapped key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(&vault, b"routed-test"),
        &wrapped,
    )?;
    let sql = rusqlite::Connection::open(&c.b.client.account_db()?.path)?;
    let mut hex = String::new();
    for byte in key.bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    sql.execute_batch(&format!("PRAGMA key=\"x'{hex}'\";"))?;
    Ok(sql)
}
#[tokio::test]
async fn routed_candidate_registration_storage_failure_still_propagates() -> TestResult {
    let mut c = Case::new()?;
    let entry = c.entry("storage-failure")?;
    let sql = connection(&c)?;
    sql.execute_batch("CREATE TRIGGER refuse_reference BEFORE INSERT ON object_retention_reference BEGIN SELECT RAISE(ABORT,'reference writer failed'); END;")?;
    assert!(matches!(
        c.receive(&entry, true).await,
        Err(SdkError::Storage(ramflux_storage::StorageError::Sqlite(_)))
    ));
    assert!(c.b.client.routed_seen_marker(&entry)?.is_none());
    assert_eq!(c.b.client.direct_messages("conversation")?.len(), 0);
    Ok(())
}
#[tokio::test]
async fn routed_candidate_import_validation_failure_still_propagates() -> TestResult {
    let mut c = Case::new()?;
    c.refs[0].total_chunks = 0;
    let entry = c.entry("invalid-import")?;
    assert!(matches!(c.receive(&entry, true).await, Err(SdkError::LocalBus(_))));
    // The already committed message/ratchet cannot be rolled back by an import error.
    assert!(c.b.client.routed_seen_marker(&entry)?.is_some());
    Ok(())
}
