// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real signed pending messages retain content until consent and narrow attachment release.
#![cfg(test)]
use super::selector_reopen::Case;
use super::*;
use crate::dm::{SdkDmAttachmentEnvelope, SdkDmAttachmentRef};
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct PendingCase {
    c: Case,
    root: String,
}
impl PendingCase {
    async fn new() -> Result<Self, SdkError> {
        let mut c = Case::pending()?;
        let root = c.a.client.owned_device_identity()?.root_commitment().to_owned();
        let target = c.b.client.owned_device_identity()?.root_commitment().to_owned();
        let nonce = ramflux_protocol::encode_base64url([77; 32]);
        let now = now_unix_timestamp();
        let request_id = ramflux_protocol::hash_base64url(
            "ramflux.contact_request.id.v1",
            &ramflux_protocol::canonical_json_bytes(&(&root, &nonce))?,
        );
        let body = json!({"schema":"ramflux.contact_request.v1","kind":"request","request_id":request_id,"requester_root":root,"target_root":target,"actor_root":root,"issued_at":now,"expires_at":now+7*24*3600,"nonce":nonce,"note":null,"manifest":crate::client::identity_authority::test_support::manifest(&c.a.client)?});
        let signed = ramflux_protocol::canonical_json_bytes(
            &json!({"domain":"ramflux.contact_request.v1","body":body}),
        )?;
        let seed =
            c.a.client
                .identity_root
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .to_bytes();
        let control = json!({"body":body,"signature":ramflux_crypto::sign_canonical_bytes_with_seed(&signed,seed)});
        let conversation = crate::client::contact_requests::conversation(&root, &target)?;
        let entry = seal_as(
            &c.a,
            &c.b,
            message("pending-request", &conversation),
            &serde_json::to_vec(&control)?,
            Route::control(),
        )?;
        assert!(c.receive(&entry, false).await?.plaintext.is_none());
        assert!(c.b.client.pending_contact_root(&root)?);
        assert!(!c.b.client.friend_link_peer_is_accepted(&root)?);
        Ok(Self { c, root })
    }
    async fn hold(
        &mut self,
        id: &str,
        text: &[u8],
        refs: Vec<SdkDmAttachmentRef>,
    ) -> Result<String, SdkError> {
        let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
            schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
            version: 1,
            body_base64: ramflux_protocol::encode_base64url(text),
            attachments: refs,
        })?;
        let entry = seal_as(
            &self.c.a,
            &self.c.b,
            message(id, "pending-thread"),
            &body,
            Route::attachments(),
        )?;
        let delivery = self.c.receive(&entry, true).await?;
        assert!(delivery.plaintext.is_none(), "pending content must not publish before consent");
        let logical = delivery.routing.ok_or_else(|| invalid("held route missing"))?.message_id;
        assert!(self.c.b.client.direct_message_by_id(&logical)?.is_none());
        Ok(logical)
    }
    fn accept(&self) -> Result<(), SdkError> {
        let request = self
            .c
            .b
            .client
            .account_db()?
            .contact_request(&self.root, "inbound")?
            .ok_or_else(|| invalid("request missing"))?;
        self.c.b.client.decide_inbound_contact(&request, "accepted")
    }
    fn assert_accepted(&self) -> Result<(), SdkError> {
        let db = self.c.b.client.account_db()?;
        assert_eq!(
            db.contact_request(&self.root, "inbound")?.ok_or_else(|| invalid("request"))?.state,
            "accepted"
        );
        assert!(self.c.b.client.friend_link_peer_is_accepted(&self.root)?);
        assert_eq!(db.held_contact_messages(&self.root)?.len(), 0);
        assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
        Ok(())
    }
}
#[tokio::test]
async fn e16_pending_contact_fenced_attachment_held_item_survives_until_release() -> TestResult {
    let mut f = Box::pin(PendingCase::new()).await?;
    let mixed = f.hold("held-mixed", b"held mixed text", f.c.refs.clone()).await?;
    let other = f.hold("held-other", b"other held content", Vec::new()).await?;
    let before = f.c.b.client.account_db()?.held_contact_messages(&f.root)?;
    assert_eq!(before.len(), 2);
    f.c.fence()?;
    assert_eq!(
        f.c.b.client.account_db()?.held_contact_messages(&f.root)?,
        before,
        "a payload fence cannot consume the held item before consent"
    );
    assert!(f.c.b.client.direct_message_by_id(&mixed)?.is_none());
    f.accept()?;
    f.assert_accepted()?;
    assert_eq!(
        f.c.b.client.account_db()?.message_content(&mixed)?,
        Some(b"held mixed text".to_vec())
    );
    assert_eq!(
        f.c.b.client.account_db()?.message_content(&other)?,
        Some(b"other held content".to_vec())
    );
    for id in ["good-one", "good-two"] {
        assert_eq!(f.c.b.client.decrypt_object(id)?, id.as_bytes());
        assert_eq!(
            f.c.b
                .client
                .account_db()?
                .actor_state_keys(&format!("attachment/reference/{id}"))?
                .len(),
            1
        );
    }
    assert_eq!(
        f.c.b.client.account_db()?.actor_state_keys("attachment/reference/refused")?.len(),
        0
    );
    assert!(matches!(
        f.c.b.client.account_db()?.check_object_access("refused"),
        Err(ramflux_storage::StorageError::ObjectErased)
    ));
    f.c.b.client.test_release_contact_messages(&f.root)?;
    assert_eq!(f.c.b.client.direct_messages("pending-thread")?.len(), 2);
    assert_eq!(
        f.c.b.client.account_db()?.actor_state_keys("attachment/reference/good-one")?.len(),
        1
    );
    assert_eq!(
        f.c.b.client.account_db()?.actor_state_keys("attachment/reference/good-two")?.len(),
        1
    );
    assert_eq!(
        f.c.b.client.account_db()?.actor_state_keys("attachment/reference/refused")?.len(),
        0
    );
    Ok(())
}
#[tokio::test]
async fn e16_fresh_m3_via_pending_contact_release() -> TestResult {
    let mut f = Box::pin(PendingCase::new()).await?;
    let r = f.c.refs[0].clone();
    f.c.b.client.send_direct_message("prior-thread", "old-owner", "alice", b"prior attachment")?;
    f.c.b.client.send_direct_message(
        "other-thread",
        "surviving-owner",
        "alice",
        b"other selector",
    )?;
    let db = f.c.b.client.account_db()?;
    db.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: "independent-survivor",
            wire_id: &r.object_id,
            manifest_hash: &r.manifest_hash,
            selector: "other-selector",
            message_id: "surviving-owner",
            reference: &json!({}),
            metadata: &json!({"message_id":"surviving-owner"}),
        },
    )?;
    f.c.b.client.persist_sender_attachment_reference(
        &r,
        "alice",
        crate::client::deferred_attachment::ReferenceContext {
            owner: "alice",
            conversation: "prior-thread",
            message: "old-owner",
        },
        None,
    )?;
    db.delete_direct_message("prior-thread", "old-owner", "local", "erase")?;
    db.check_object_identity(&r.object_id, &r.manifest_hash)?;
    db.check_object_access("other-selector")?;
    assert!(matches!(
        db.check_object_access(&r.object_id),
        Err(ramflux_storage::StorageError::ObjectErased)
    ));
    assert_eq!(db.actor_state_keys(&format!("attachment/reference/{}", r.object_id))?.len(), 0);
    let held = f.hold("fresh-pending-m3", b"fresh pending text", vec![r.clone()]).await?;
    assert_eq!(f.c.b.client.account_db()?.held_contact_messages(&f.root)?.len(), 1);
    f.accept()?;
    f.assert_accepted()?;
    assert_eq!(
        f.c.b.client.account_db()?.message_content(&held)?,
        Some(b"fresh pending text".to_vec())
    );
    f.c.b.client.account_db()?.check_object_access(&r.object_id)?;
    assert_eq!(
        f.c.b
            .client
            .account_db()?
            .actor_state_keys(&format!("attachment/reference/{}", r.object_id))?
            .len(),
        1
    );
    assert_eq!(f.c.b.client.decrypt_object(&r.object_id)?, b"good-one");
    Ok(())
}
#[tokio::test]
async fn pending_release_storage_error_rolls_back_consent_and_keeps_held_content() -> TestResult {
    let mut f = Box::pin(PendingCase::new()).await?;
    let id = f.hold("pending-write-error", b"retained on failure", f.c.refs.clone()).await?;
    f.c.fence()?;
    let before = f.c.b.client.account_db()?.held_contact_messages(&f.root)?;
    let sql = super::selector_reopen::connection(&f.c)?;
    sql.execute_batch("CREATE TRIGGER refuse_pending_reference BEFORE INSERT ON object_retention_reference WHEN NEW.selector='good-two' BEGIN SELECT RAISE(ABORT,'pending writer failed'); END;")?;
    let error = f.accept().err().ok_or("failed storage write accepted")?;
    assert!(matches!(error, SdkError::Storage(ramflux_storage::StorageError::Sqlite(_))));
    assert!(error.to_string().contains("pending writer failed"));
    assert!(f.c.b.client.pending_contact_root(&f.root)?);
    assert!(!f.c.b.client.friend_link_peer_is_accepted(&f.root)?);
    assert_eq!(f.c.b.client.account_db()?.held_contact_messages(&f.root)?, before);
    assert!(f.c.b.client.direct_message_by_id(&id)?.is_none());
    sql.execute_batch("DROP TRIGGER refuse_pending_reference;")?;
    f.accept()?;
    f.assert_accepted()?;
    assert_eq!(
        f.c.b.client.account_db()?.message_content(&id)?,
        Some(b"retained on failure".to_vec())
    );
    Ok(())
}
