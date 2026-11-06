// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy receive admission is observed before real cached import and terminal checkpoints.
#![cfg(test)]
use super::selector_reopen::Case;
use super::*;
use crate::dm::{SdkDmAttachmentEnvelope, SdkDmAttachmentRef};
use std::cell::RefCell;

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Default)]
struct Observation {
    imports: Vec<String>,
    late: bool,
    registrations: usize,
    refused: usize,
}
pub(in crate::client) fn registered(result: &Result<(), SdkError>) {
    OBSERVED.with_borrow_mut(|o| {
        o.registrations += 1;
        o.refused += usize::from(matches!(result, Err(SdkError::ObjectErased)));
    });
}
thread_local! { static OBSERVED: RefCell<Observation> = RefCell::default(); }
pub(in crate::client) fn import_entry(
    client: &RamfluxClient,
    reference: &SdkDmAttachmentRef,
) -> Result<(), SdkError> {
    let late = OBSERVED.with_borrow_mut(|o| {
        o.imports.push(reference.object_id.clone());
        o.late && reference.object_id == "refused"
    });
    if late {
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
struct LegacyCase {
    c: Case,
    send: ramflux_crypto::DmSession,
}
impl LegacyCase {
    fn new() -> Result<Self, SdkError> {
        OBSERVED.with_borrow_mut(|o| *o = Observation::default());
        let c = Case::new()?;
        review::trust(&c.b, &c.a)?;
        let send = ramflux_crypto::DmSession::initiator(
            [9; 32],
            dm_device_id_hash("alice"),
            dm_device_id_hash("bob"),
            [6; 32],
        )?;
        let recv = ramflux_crypto::DmSession::recipient(
            [9; 32],
            dm_device_id_hash("bob"),
            dm_device_id_hash("alice"),
            [6; 32],
        )?;
        c.b.client.send_direct_message(
            "legacy-thread",
            "bound-history",
            "alice",
            b"prior history",
        )?;
        c.b.client.persist_dm_session("legacy-thread", "bound-history", "recv", &recv)?;
        Ok(Self { c, send })
    }
    fn entry(&mut self, id: &str, seq: u64) -> Result<GatewayInboxEntry, SdkError> {
        let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
            schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
            version: 1,
            body_base64: ramflux_protocol::encode_base64url(b"preserved legacy text"),
            attachments: self.c.refs.clone(),
        })?;
        let mut msg = message(id, "legacy-thread");
        msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
            source_principal_commitment: None,
            schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
            version: 1,
            x3dh: None,
            ciphertext: self.send.encrypt(&body, dm_associated_data("legacy-thread"))?,
        })?;
        Ok(GatewayInboxEntry {
            forwarded: false,
            inbox_seq: seq,
            target_delivery_id: "bob".into(),
            envelope: gateway_direct_message_envelope(&self.c.a.config()?, &msg, None)?,
        })
    }
    async fn receive(
        &mut self,
        entry: &GatewayInboxEntry,
        fetch: bool,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        let mut engine =
            GatewaySessionEngine::with_test_transport(self.c.b.config()?, Box::new(NoNetwork));
        let pool = review::pool()?;
        self.c
            .b
            .client
            .receive_legacy_entry(
                &mut engine,
                &pool,
                entry.clone(),
                crate::client::dm::LegacyReceive {
                    conversation_id: "legacy-thread",
                    auto_fetch_attachments: fetch,
                    relay_service_key_base64: None,
                },
            )
            .await
    }
    async fn mixed(&mut self, late: bool) -> TestResult {
        if late {
            OBSERVED.with_borrow_mut(|o| o.late = true);
        } else {
            self.c.fence()?;
        }
        let entry = self.entry("legacy-m3", 7)?;
        let before = self.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter;
        let delivery = self.receive(&entry, true).await?.ok_or("message missing")?;
        assert_eq!(
            ramflux_protocol::decode_base64url(&delivery.plaintext_body_base64)?,
            b"preserved legacy text"
        );
        assert_eq!(
            delivery.attachments.iter().map(|a| a.object_id.as_str()).collect::<Vec<_>>(),
            ["good-one", "good-two"]
        );
        OBSERVED.with_borrow(|o| {
            assert_eq!(
                o.imports,
                if late {
                    vec!["good-one", "refused", "good-two"]
                } else {
                    vec!["good-one", "good-two"]
                }
            );
        });
        assert!(self.c.b.client.recv_session_checkpoint_at("legacy-thread", "legacy-m3")?);
        let terminal = self.c.b.client.legacy_committed_key(&entry)?;
        assert_eq!(
            self.c.b.client.account_db()?.load_actor_state::<String>(&terminal)?,
            Some("legacy-thread".to_owned())
        );
        let committed = self.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter;
        assert!(committed > before);
        assert_eq!(self.c.b.client.gateway_receive_cursor("bob")?, 7);
        assert_eq!(self.c.b.client.account_db()?.due_inbox_retries(i64::MAX)?.len(), 0);
        let observed = OBSERVED.with_borrow(|o| o.imports.clone());
        assert!(self.receive(&entry, true).await?.is_some());
        assert_eq!(
            self.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter,
            committed
        );
        OBSERVED.with_borrow(|o| assert_eq!(o.imports, observed));
        assert_eq!(self.c.b.client.gateway_receive_cursor("bob")?, 7);
        Ok(())
    }
}
#[tokio::test]
async fn e16_legacy_import_receives_only_admitted_subset() -> TestResult {
    let mut f = LegacyCase::new()?;
    f.c.fence()?;
    let rejected = f.c.refs[1].clone();
    f.c.refs = vec![rejected.clone(), f.c.refs[2].clone(), rejected, f.c.refs[0].clone()];
    let entry = f.entry("legacy-ordered-subset", 11)?;
    let before = f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter;
    let delivery = f.receive(&entry, true).await?.ok_or("subset message missing")?;
    assert_eq!(
        delivery.attachments.iter().map(|r| r.object_id.as_str()).collect::<Vec<_>>(),
        ["good-two", "good-one"]
    );
    OBSERVED.with_borrow(|o| {
        assert_eq!(o.registrations, 4);
        assert_eq!(o.refused, 2);
        assert_eq!(o.imports, ["good-two", "good-one"]);
    });
    assert_eq!(
        ramflux_protocol::decode_base64url(&delivery.plaintext_body_base64)?,
        b"preserved legacy text"
    );
    let db = f.c.b.client.account_db()?;
    let terminal = f.c.b.client.legacy_committed_key(&entry)?;
    assert_eq!(db.load_actor_state::<String>(&terminal)?, Some("legacy-thread".to_owned()));
    assert_eq!(db.actor_state_keys("attachment/reference/refused")?.len(), 0);
    assert!(matches!(f.c.b.client.object_content_key("refused"), Err(SdkError::ObjectErased)));
    let raw = super::post_send::raw_connection(&f.c.b)?;
    let key_rows: i64 = raw.query_row(
        "SELECT count(*) FROM object_index WHERE object_id='refused' AND object_content_key IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(key_rows, 0, "refused object key slot must be absent from its row");
    assert!(f.c.b.client.recv_session_checkpoint_at("legacy-thread", "legacy-ordered-subset")?);
    assert_eq!(f.c.b.client.gateway_receive_cursor("bob")?, 11);
    assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
    let committed = f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter;
    assert!(committed > before);
    assert!(f.receive(&entry, true).await?.is_some());
    assert_eq!(f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter, committed);
    assert_eq!(f.c.b.client.gateway_receive_cursor("bob")?, 11);
    OBSERVED.with_borrow(|o| {
        assert_eq!(o.registrations, 4);
        assert_eq!(o.refused, 2);
        assert_eq!(o.imports, ["good-two", "good-one"]);
    });
    Ok(())
}
#[tokio::test]
async fn e16_legacy_item_fenced_between_registration_and_import_is_consumed() -> TestResult {
    LegacyCase::new()?.mixed(true).await
}
#[tokio::test]
async fn e16_legacy_receive_mixed_valid_and_fenced_attachments_auto_fetch() -> TestResult {
    mixed_fenced_is_consumed().await
}
/// Legacy direct receive of a mixed fenced and valid message consumes the refusal and commits.
pub(super) async fn mixed_fenced_is_consumed() -> TestResult {
    LegacyCase::new()?.mixed(false).await
}
#[tokio::test]
async fn e16_fresh_m3_via_direct_reference_caller() -> TestResult {
    let mut f = LegacyCase::new()?;
    // An independently authenticated message owns another selector of the same payload.
    f.c.b.client.send_direct_message("other-thread", "other-owner", "alice", b"surviving owner")?;
    let r = f.c.refs[0].clone();
    f.c.b.client.account_db()?.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: "other-reference",
            wire_id: &r.object_id,
            manifest_hash: &r.manifest_hash,
            selector: "other-selector",
            message_id: "other-owner",
            reference: &serde_json::json!({}),
            metadata: &serde_json::json!({"message_id":"other-owner"}),
        },
    )?;
    f.c.refs = vec![r.clone()];
    let m2 = f.entry("direct-m2", 2)?;
    f.receive(&m2, false).await?;
    f.c.b.client.account_db()?.delete_direct_message(
        "legacy-thread",
        "direct-m2",
        "local",
        "erase",
    )?;
    f.c.b.client.account_db()?.check_object_identity(&r.object_id, &r.manifest_hash)?;
    f.c.b.client.account_db()?.check_object_access("other-selector")?;
    assert!(matches!(
        f.c.b.client.account_db()?.check_object_access(&r.object_id),
        Err(ramflux_storage::StorageError::ObjectErased)
    ));
    assert_eq!(
        f.c.b
            .client
            .account_db()?
            .actor_state_keys(&format!("attachment/reference/{}", r.object_id))?
            .len(),
        0
    );
    let m3 = f.entry("direct-m3", 3)?;
    f.receive(&m3, true).await?;
    f.c.b.client.account_db()?.check_object_access(&r.object_id)?;
    assert!(f.c.b.client.recv_session_checkpoint_at("legacy-thread", "direct-m3")?);
    assert_eq!(f.c.b.client.gateway_receive_cursor("bob")?, 3);
    assert_eq!(f.c.b.client.decrypt_object(&r.object_id)?, b"good-one");
    Ok(())
}
#[tokio::test]
async fn legacy_import_operational_error_keeps_ratchet_and_cursor_uncommitted() -> TestResult {
    let mut f = LegacyCase::new()?;
    f.c.refs[0].total_chunks = 0;
    let entry = f.entry("bad-import", 8)?;
    let before = f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter;
    assert!(matches!(f.receive(&entry, true).await, Err(SdkError::LocalBus(_))));
    assert_eq!(f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter, before);
    assert!(!f.c.b.client.recv_session_checkpoint_at("legacy-thread", "bad-import")?);
    assert_eq!(f.c.b.client.gateway_receive_cursor("bob")?, 0);
    Ok(())
}

#[tokio::test]
async fn legacy_registration_storage_error_keeps_terminal_uncommitted() -> TestResult {
    let mut f = LegacyCase::new()?;
    let entry = f.entry("bad-write", 9)?;
    let sql = super::selector_reopen::connection(&f.c)?;
    sql.execute_batch("CREATE TRIGGER refuse_legacy_reference BEFORE INSERT ON object_retention_reference BEGIN SELECT RAISE(ABORT,'legacy writer failed'); END;")?;
    let before = f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter;
    assert!(matches!(
        f.receive(&entry, true).await,
        Err(SdkError::Storage(ramflux_storage::StorageError::Sqlite(_)))
    ));
    assert_eq!(f.c.b.client.load_dm_session("legacy-thread", "recv")?.receive_counter, before);
    assert_eq!(f.c.b.client.gateway_receive_cursor("bob")?, 0);
    let terminal = f.c.b.client.legacy_committed_key(&entry)?;
    assert!(f.c.b.client.account_db()?.load_actor_state::<String>(&terminal)?.is_none());
    Ok(())
}
