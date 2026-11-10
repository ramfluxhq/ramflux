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
pub(super) struct Case {
    pub(super) a: Fixture,
    pub(super) b: Fixture,
    pub(super) refs: Vec<SdkDmAttachmentRef>,
}
impl Case {
    pub(super) fn new() -> Result<Self, SdkError> {
        Self::with_consent(true)
    }
    pub(super) fn pending() -> Result<Self, SdkError> {
        Self::with_consent(false)
    }
    fn with_consent(accepted: bool) -> Result<Self, SdkError> {
        OBSERVED.with_borrow_mut(|o| *o = Observation::default());
        let a = Fixture::new("alice", 21)?;
        let mut b = Fixture::new("bob", 31)?;
        if accepted {
            b.client.establish_friend_link(
                "link",
                a.client.owned_device_identity()?.root_commitment(),
                b.client.owned_device_identity()?.root_commitment(),
            )?;
        }
        let mut refs = Vec::new();
        for (n, id) in ["good-one", "refused", "good-two"].into_iter().enumerate() {
            let prepared = b.client.object_store.prepare_encrypted_object(id, id.as_bytes())?;
            let object = prepared.object().clone();
            let key = *prepared.object_key();
            let db = b.client.account_db()?;
            // Received attachment payloads use imported ownership, not history-container lifetime.
            db.retain_object(
                id,
                &object.manifest_hash,
                ramflux_storage::ObjectRetention::Imported,
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
    fn prepare_carol(&mut self) -> Result<(), SdkError> {
        self.a = Fixture::new("carol", 51)?;
        for (index, r) in self.refs.iter_mut().enumerate() {
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
            self.b.client.persist_dm_session(&conversation, "bootstrap", "recv", &recv)?;
            r.key_slot.conversation_id = conversation.clone();
            r.key_slot.ciphertext = send.encrypt(
                &self.b.client.object_content_key(&r.object_id)?,
                &object_key_slot_associated_data(&r.object_id, &conversation, "bob"),
            )?;
        }
        self.b.client.establish_friend_link(
            "carol-link",
            self.a.client.owned_device_identity()?.root_commitment(),
            self.b.client.owned_device_identity()?.root_commitment(),
        )?;
        Ok(())
    }
    pub(super) fn fence(&self) -> Result<(), SdkError> {
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
    pub(super) fn entry(&self, id: &str) -> Result<GatewayInboxEntry, SdkError> {
        let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
            schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
            version: 1,
            body_base64: ramflux_protocol::encode_base64url(b"preserved text"),
            attachments: self.refs.clone(),
        })?;
        seal_as(&self.a, &self.b, message(id, "conversation"), &body, Route::attachments())
    }
    pub(super) async fn receive(
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
        self.b.client.apply_routed_entry(&mut engine, &pool, entry, fetch).await
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
    Box::pin(payload_fenced_is_consumed()).await
}
/// Routed receive of a message carrying a fenced reference consumes the refusal and commits.
pub(super) async fn payload_fenced_is_consumed() -> TestResult {
    let mut c = Case::new()?;
    c.fence()?;
    c.refs = vec![c.refs[1].clone()];
    let entry = c.entry("fresh-fenced-registration")?;
    assert!(c.b.client.routed_seen_marker(&entry)?.is_none());
    let delivery =
        c.receive(&entry, false).await?.plaintext.ok_or("fenced-only message missing")?;
    assert_eq!(
        ramflux_protocol::decode_base64url(&delivery.plaintext_body_base64)?,
        b"preserved text"
    );
    assert_eq!(delivery.attachments.len(), 0);
    OBSERVED.with_borrow(|o| {
        assert_eq!(o.registrations, 1, "fresh fenced input must reach registration");
        assert_eq!(o.refused, 1, "registration must observe the typed erasure");
        assert_eq!(o.imports, Vec::<String>::new(), "auto-fetch is disabled for this witness");
    });
    assert!(c.b.client.routed_seen_marker(&entry)?.is_some());
    assert!(c.b.client.direct_message_by_id(&delivery.message_id)?.is_some_and(|m| !m.deleted));
    assert_eq!(
        c.b.client.account_db()?.actor_state_keys("attachment/reference/refused")?,
        Vec::<String>::new()
    );
    assert_eq!(c.b.client.account_db()?.due_inbox_retries(i64::MAX)?, Vec::<Vec<u8>>::new());
    Ok(())
}
#[tokio::test]
async fn e16_routed_import_receives_only_admitted_subset() -> TestResult {
    let mut c = Case::new()?;
    c.fence()?;
    let rejected = c.refs[1].clone();
    // Rejected entries bracket the first survivor; admitted order differs from fixture order.
    c.refs = vec![rejected.clone(), c.refs[2].clone(), rejected, c.refs[0].clone()];
    let entry = c.entry("ordered-subset")?;
    let delivery = c.receive(&entry, true).await?.plaintext.ok_or("subset message missing")?;
    assert_eq!(
        delivery.attachments.iter().map(|r| r.object_id.as_str()).collect::<Vec<_>>(),
        ["good-two", "good-one"]
    );
    OBSERVED.with_borrow(|o| {
        assert_eq!(o.registrations, 4);
        assert_eq!(o.refused, 2);
        assert_eq!(
            o.imports,
            ["good-two", "good-one"],
            "only admitted input positions 1 and 3 may enter import"
        );
    });
    assert!(c.b.client.routed_seen_marker(&entry)?.is_some());
    assert_eq!(
        c.b.client.account_db()?.actor_state_keys("attachment/reference/refused")?,
        Vec::<String>::new()
    );
    Ok(())
}
#[tokio::test]
async fn e16_routed_receive_mixed_valid_and_fenced_attachments_auto_fetch() -> TestResult {
    Box::pin(Case::new()?.assert_mixed(false)).await
}
#[tokio::test]
async fn e16_routed_item_fenced_between_registration_and_import_is_consumed() -> TestResult {
    Box::pin(Case::new()?.assert_mixed(true)).await
}
#[tokio::test]
async fn e16_m2_replay_refused_without_retry() -> TestResult {
    let mut c = Case::new()?;
    let entry = c.entry("m2")?;
    c.receive(&entry, false).await?;
    let id =
        c.b.client.direct_messages("conversation")?.first().ok_or("message")?.message_id.clone();
    c.b.client.account_db()?.delete_direct_message("conversation", &id, "local", "erase")?;
    let registered = OBSERVED.with_borrow(|o| o.registrations);
    assert_eq!(registered, 3, "original m2 must have registered its references");
    assert!(c.receive(&entry, true).await?.plaintext.is_none());
    assert_eq!(c.b.client.account_db()?.due_inbox_retries(i64::MAX)?, Vec::<Vec<u8>>::new());
    OBSERVED.with_borrow(|o| {
        assert_eq!(o.registrations, registered, "deleted m2 replay must stop before registration");
    });
    Ok(())
}
#[tokio::test]
async fn e16_unrelated_valid_messages_progress() -> TestResult {
    let mut c = Case::new()?;
    Box::pin(c.assert_mixed(false)).await?;
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
    let m1 = c.receive(&first, false).await?.plaintext.ok_or("m1")?.message_id;
    // Keep m1's wire while the same wire from a second sender uses its deterministic alias.
    c.prepare_carol()?;
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
    let sql = connection(&c)?;
    let retained = || -> rusqlite::Result<(String, i64)> {
        sql.query_row(
            "SELECT retention_class,owner_count FROM object_retention_payload WHERE wire_id=?1",
            [&reference.object_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
    };
    assert_eq!(
        retained()?,
        ("imported".to_owned(), 2),
        "both authenticated owners must precede deletion"
    );
    c.b.client.account_db()?.delete_direct_message("carol-conversation", &id, "local", "erase")?;
    assert_eq!(retained()?, ("imported".to_owned(), 1), "m1 must retain the imported payload");
    assert!(c.b.client.direct_message_by_id(&m1)?.is_some_and(|m| !m.deleted));
    c.b.client
        .account_db()?
        .check_object_identity(&reference.object_id, &reference.manifest_hash)?;
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
    assert_eq!(retained()?, ("imported".to_owned(), 2), "fresh m3 must restore alias ownership");
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

pub(super) fn connection(c: &Case) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
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
