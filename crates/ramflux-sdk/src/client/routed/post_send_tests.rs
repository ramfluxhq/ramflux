// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual gateway acknowledgement precedes narrow outgoing-reference finalization.
use super::selector_reopen::Case;
use super::session_record::Wire;
use super::*;
use crate::client::deferred_attachment::ReferenceContext;
use crate::dm::SdkDmAttachmentEnvelope;
use std::sync::{Arc, Mutex};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
struct Fields(String);
impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{}={value:?};", field.name());
    }
}
impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "ramflux_sdk::client::dm::post_send"
            && *metadata.level() == tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        if let Ok(mut bytes) = self.0.lock() {
            bytes.extend(format!("{} {}", event.metadata().level(), fields.0).as_bytes());
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
impl Capture {
    fn text(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(String::from_utf8(self.0.lock().map_err(|_| "capture poisoned")?.clone())?)
    }
}
fn context() -> ReferenceContext<'static> {
    ReferenceContext {
        owner: "alice",
        conversation: "recovery-thread",
        message: "post-send-message",
    }
}
fn stage(c: &Case) -> Result<Vec<ramflux_storage::PreSendObjectHold>, SdkError> {
    let mut holds = Vec::new();
    for r in &c.refs {
        let (object, key) =
            c.b.client
                .account_db()?
                .load_object::<ramflux_sync::EncryptedObject>(&r.object_id)?
                .ok_or_else(|| invalid("object"))?;
        let key = key.ok_or_else(|| invalid("object key"))?;
        holds.push(c.a.client.account_db()?.pre_send_object_hold(&r.object_id, &r.manifest_hash)?);
        c.a.client.account_db()?.upsert_object(&ramflux_storage::ObjectWrite {
            object_id: &object.object_id,
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
    }
    Ok(holds)
}
async fn send(c: &mut Case) -> Result<GatewayInboxEntry, SdkError> {
    super::review::trust(&c.a, &c.b)?;
    super::review::trust(&c.b, &c.a)?;
    c.a.client.establish_friend_link(
        "outgoing",
        c.b.client.owned_device_identity()?.root_commitment(),
        c.a.client.owned_device_identity()?.root_commitment(),
    )?;
    let (mut engine, sent) = Wire::engine(&c.a, &c.b)?;
    let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
        schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
        version: 1,
        body_base64: ramflux_protocol::encode_base64url(b"sent text"),
        attachments: c.refs.clone(),
    })?;
    let mut msg = super::r5::outgoing(&c.a, &c.b, context().message);
    msg.ttl = c.a.client.content_ttl()?;
    let entry = Box::pin(c.a.client.send_plaintext_direct_message_without_franking(
        &mut engine,
        msg,
        &body,
        Route::attachments(),
    ))
    .await?;
    let entries = sent.lock().map_err(|_| invalid("sent mutex"))?;
    assert_eq!(entries.len(), 1, "send must be acknowledged exactly once");
    assert_eq!(serde_json::to_value(&entries[0])?, serde_json::to_value(&entry)?);
    assert_eq!(c.b.client.open_routed(&entry, "bob")?.body.as_slice(), body);
    Ok(entry)
}
fn finish(
    c: &Case,
    result: Result<GatewayInboxEntry, SdkError>,
    holds: Vec<ramflux_storage::PreSendObjectHold>,
    candidate: bool,
) -> (Result<GatewayInboxEntry, SdkError>, Capture) {
    let capture = Capture::default();
    let result = tracing::subscriber::with_default(capture.clone(), || {
        c.a.client.finish_attachment_send(result, &c.refs, context(), holds, candidate)
    });
    (result, capture)
}
fn fence(c: &Case) -> Result<(), SdkError> {
    let r = &c.refs[1];
    let db = c.a.client.account_db()?;
    db.retain_object(
        &r.object_id,
        &r.manifest_hash,
        ramflux_storage::ObjectRetention::OwnDeviceTransport,
    )?;
    db.retire_transport_object(&r.object_id, &r.manifest_hash)?;
    Ok(())
}
fn connection(c: &Case) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    raw_connection(&c.a)
}
/// Opens the account database file directly, bypassing the object access guard.
pub(super) fn raw_connection(
    f: &Fixture,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    use ramflux_storage::{FileVaultSecretSource, VaultSecretSource};
    use std::fmt::Write;
    let vault = FileVaultSecretSource::new(&f.root).vault_secret(&f.id)?;
    let wrapped = f.client.account_index()?.load_wrapped_db_key(&f.id)?.ok_or("wrapped")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(&vault, b"routed-test"),
        &wrapped,
    )?;
    let sql = rusqlite::Connection::open(&f.client.account_db()?.path)?;
    let mut hex = String::new();
    for byte in key.bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    sql.execute_batch(&format!("PRAGMA key=\"x'{hex}'\";"))?;
    Ok(sql)
}
#[tokio::test]
async fn e16_outgoing_post_send_refusal_logged_and_message_stays_sent() -> TestResult {
    let mut c = Case::new()?;
    let holds = stage(&c)?;
    let entry = Box::pin(send(&mut c)).await?;
    let expected = serde_json::to_value(&entry)?;
    let db = c.a.client.account_db()?;
    let checkpoints = db
        .actor_state_keys("dm-pair/session/")?
        .into_iter()
        .map(|key| Ok((key.clone(), db.load_actor_state::<serde_json::Value>(&key)?)))
        .collect::<Result<Vec<_>, ramflux_storage::StorageError>>()?;
    assert_ne!(checkpoints.len(), 0);
    fence(&c)?;
    let (outcome, capture) = finish(&c, Ok(entry), holds, true);
    assert_eq!(serde_json::to_value(outcome?)?, expected);
    assert_eq!(db.message_content(context().message)?, Some(b"sent text".to_vec()));
    assert_eq!(c.a.client.direct_messages(context().conversation)?.len(), 1);
    assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
    for (key, value) in checkpoints {
        assert_eq!(db.load_actor_state::<serde_json::Value>(&key)?, value);
    }
    for id in ["good-one", "good-two"] {
        assert_eq!(db.actor_state_keys(&format!("attachment/reference/{id}"))?.len(), 1);
        assert_eq!(c.a.client.decrypt_object(id)?, id.as_bytes());
    }
    assert_eq!(db.actor_state_keys("attachment/reference/refused")?.len(), 0);
    assert!(matches!(
        db.check_object_access("refused"),
        Err(ramflux_storage::StorageError::ObjectErased)
    ));
    let log = capture.text()?;
    assert!(log.contains("WARN"));
    assert_eq!(
        log.matches("erased outgoing attachment registration skipped after successful send")
            .count(),
        1
    );
    for r in &c.refs {
        for value in [
            &r.object_id,
            &r.manifest_hash,
            &r.plaintext_hash,
            &r.key_slot.conversation_id,
            &r.relay_endpoint,
            &r.owner_principal_id,
        ] {
            assert!(!log.contains(value), "warning leaked an attachment identifier");
        }
    }
    assert!(!log.contains(context().message));
    Ok(())
}
#[tokio::test]
async fn post_send_storage_failure_is_not_consumed_as_erasure() -> TestResult {
    let mut c = Case::new()?;
    let holds = stage(&c)?;
    let entry = Box::pin(send(&mut c)).await?;
    let sql = connection(&c)?;
    sql.execute_batch("CREATE TRIGGER fail_post_send BEFORE INSERT ON object_retention_reference BEGIN SELECT RAISE(ABORT,'post-send writer failed'); END;")?;
    let (result, capture) = finish(&c, Ok(entry), holds, true);
    assert!(matches!(result, Err(SdkError::Storage(ramflux_storage::StorageError::Sqlite(_)))));
    assert_eq!(capture.text()?.len(), 0);
    assert_eq!(
        c.a.client.account_db()?.message_content(context().message)?,
        Some(b"sent text".to_vec())
    );
    assert_eq!(c.a.client.account_db()?.actor_state_keys("attachment/reference/")?.len(), 0);
    Ok(())
}
#[test]
fn post_send_failed_submission_does_not_register_or_mask_io_and_validation_errors() -> TestResult {
    for error in [
        SdkError::Io(std::io::Error::other("submit I/O")),
        SdkError::LocalBus("submit validation".into()),
        SdkError::ObjectErased,
    ] {
        let c = Case::new()?;
        let holds = stage(&c)?;
        let expected = error.to_string();
        let (result, capture) = finish(&c, Err(error), holds, true);
        assert_eq!(result.err().ok_or("failure became success")?.to_string(), expected);
        assert_eq!(capture.text()?.len(), 0);
        assert_eq!(c.a.client.account_db()?.actor_state_keys("attachment/reference/")?.len(), 0);
        for r in &c.refs {
            assert!(matches!(
                c.a.client.account_db()?.check_object_access(&r.object_id),
                Err(ramflux_storage::StorageError::ObjectErased)
            ));
        }
    }
    Ok(())
}

#[tokio::test]
async fn post_send_empty_attachment_list_keeps_gateway_ack() -> TestResult {
    let mut c = Case::new()?;
    let _ = Box::pin(send(&mut c)).await?;
    let (mut engine, sent) = Wire::engine(&c.a, &c.b)?;
    let msg = super::r5::outgoing(&c.a, &c.b, "candidate-empty");
    let entry = Box::pin(c.a.client.send_plaintext_direct_message_with_attachments_via_gateway(
        &mut engine,
        &super::review::pool()?,
        msg,
        b"empty attachment list",
        &[],
    ))
    .await?;
    assert_eq!(sent.lock().map_err(|_| "sent mutex")?.len(), 1);
    assert_eq!(entry.inbox_seq, 2);
    assert_eq!(
        c.a.client.account_db()?.message_content("candidate-empty")?,
        Some(b"empty attachment list".to_vec())
    );
    assert_eq!(c.a.client.account_db()?.actor_state_keys("attachment/reference/")?.len(), 0);
    Ok(())
}
