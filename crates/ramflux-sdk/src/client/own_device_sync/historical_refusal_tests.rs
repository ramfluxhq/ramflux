// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical page registration refusal commits content without granting fresh authority.
use super::tests::{bundle, client_with_account, envelope};
use super::*;
use std::cell::Cell;

type TestResult = Result<(), Box<dyn std::error::Error>>;
thread_local! { static COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) }; }
pub(in crate::client) fn registered(result: &Result<(), SdkError>) {
    COUNTS.with(|counts| {
        let (calls, refusals) = counts.get();
        counts.set((
            calls + 1,
            refusals + usize::from(matches!(result, Err(SdkError::ObjectErased))),
        ));
    });
}
struct Page {
    client: RamfluxClient,

    envelope: SdkOwnDeviceSyncEnvelope,
    bytes: Vec<u8>,
    root: ramflux_test_support::TestPath,
}
impl Page {
    fn new(label: &str, closed: bool) -> Result<Self, SdkError> {
        let (root, client) = client_with_account(label, "principal_sync", "target_device_sync")?;
        let envelope = envelope("source_device_sync", "target_device_sync");
        let mut records = Vec::new();
        for id in ["page-first", "page-second"] {
            records.push(DirectMessageRecord {
                conversation_id: "page-thread".into(),
                message_id: id.into(),
                sender_id: "source_device_sync".into(),
                encrypted_body: b"authenticated history".to_vec(),
                metadata: MessageMetadata::default(),
                deleted: false,
                is_own: false,
                created_at: 1,
                receipts: Vec::new(),
            });
        }
        let mut history = bundle("source_device_sync", "target_device_sync", records, Vec::new());
        history
            .contents
            .insert("page-second".into(), zeroize::Zeroizing::new(b"other page content".to_vec()));
        history.version = 2;
        history.schema = "ramflux.sdk.own_device_history_bundle.v2".into();
        let mut next = envelope.clone();
        next.snapshot_id = "next-snapshot".into();
        next.history_ref.object_id = "next-page".into();
        next.history_ref.manifest_hash = "next-manifest".into();
        history.next_page = Some(Box::new(next));
        let bytes = serde_json::to_vec(&history)?;
        if closed {
            let db = client.account_db()?;
            for (selector, owner) in
                [("object_sync", "old-owner"), ("surviving-alias", "surviving-owner")]
            {
                client.send_direct_message("prior", owner, "peer", b"prior body")?;
                db.register_object_reference(
                    ramflux_storage::ObjectReferenceAdmission::FreshMessage,
                    &ramflux_storage::ObjectReferenceOwner {
                        reference_hash: owner,
                        wire_id: "object_sync",
                        manifest_hash: "manifest_sync",
                        selector,
                        message_id: owner,
                        reference: &serde_json::json!({}),
                        metadata: &serde_json::json!({}),
                    },
                )?;
            }
            db.delete_direct_message("prior", "old-owner", "local", "erase")?;
            db.check_object_identity("object_sync", "manifest_sync")?;
            db.check_object_access("surviving-alias")?;
            assert!(matches!(
                db.check_object_access("object_sync"),
                Err(ramflux_storage::StorageError::ObjectErased)
            ));
        }
        COUNTS.with(|counts| counts.set((0, 0)));
        Ok(Self { client, root, envelope, bytes })
    }
    fn assert_uncommitted(&self) -> Result<(), SdkError> {
        assert!(self.client.direct_message_by_id("page-first")?.is_none());
        assert!(
            self.client
                .account_db()?
                .load_actor_state::<serde_json::Value>(&RamfluxClient::own_sync_receipt_key(
                    &self.envelope
                )?)?
                .is_none()
        );
        Ok(())
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn e16_own_copy_historical_registration_consumed_without_retry() -> TestResult {
    historical_registration_is_consumed()
}
/// An own-copy historical page with a fenced reference consumes the refusal and commits.
pub(in crate::client) fn historical_registration_is_consumed() -> TestResult {
    let p = Page::new("historical-candidate", true)?;
    for _ in 0..2 {
        let (_, next) = p.client.apply_own_history_plaintext(&p.envelope, &p.bytes)?;
        assert!(next.is_some());
        assert!(p.client.direct_message_by_id("page-first")?.is_some_and(|m| !m.deleted));
        let db = p.client.account_db()?;
        assert_eq!(db.message_content("page-second")?, Some(b"other page content".to_vec()));
        assert!(
            db.load_actor_state::<serde_json::Value>(&RamfluxClient::own_sync_receipt_key(
                &p.envelope
            )?)?
            .is_some()
        );
        assert!(
            db.load_actor_state::<SdkOwnDeviceSyncEnvelope>(&format!(
                "{}/next",
                RamfluxClient::own_sync_receipt_key(&p.envelope)?
            ))?
            .is_some()
        );
        assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
        assert!(matches!(
            db.check_object_access("object_sync"),
            Err(ramflux_storage::StorageError::ObjectErased)
        ));
        db.check_object_access("surviving-alias")?;
    }
    COUNTS.with(|c| assert_eq!(c.get(), (4, 4), "real OwnCopy refusal on both owners and replay"));
    Ok(())
}
#[test]
fn historical_page_storage_error_rolls_back_content_and_receipt() -> TestResult {
    use ramflux_storage::{FileVaultSecretSource, VaultSecretSource};
    use std::fmt::Write;
    let p = Page::new("historical-storage", false)?;
    let vault = FileVaultSecretSource::new(&p.root).vault_secret("acct")?;
    let wrapped = p.client.account_index()?.load_wrapped_db_key("acct")?.ok_or("wrapped key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(&vault, b"own-device-sync-test"),
        &wrapped,
    )?;
    let sql = rusqlite::Connection::open(&p.client.account_db()?.path)?;
    let mut hex = String::new();
    for byte in key.bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    sql.execute_batch(&format!("PRAGMA key=\"x'{hex}'\"; PRAGMA cipher_page_size=4096; PRAGMA kdf_iter=256000; PRAGMA cipher_hmac_algorithm=HMAC_SHA512; PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512; PRAGMA foreign_keys=ON;"))?;
    sql.execute_batch("CREATE TRIGGER refuse_history_reference BEFORE INSERT ON object_retention_reference BEGIN SELECT RAISE(ABORT,'history writer failed'); END;")?;
    assert!(matches!(
        p.client.apply_own_history_plaintext(&p.envelope, &p.bytes),
        Err(SdkError::Storage(ramflux_storage::StorageError::Sqlite(_)))
    ));
    p.assert_uncommitted()?;
    sql.execute_batch("DROP TRIGGER refuse_history_reference")?;
    p.client.apply_own_history_plaintext(&p.envelope, &p.bytes)?;
    assert!(p.client.direct_message_by_id("page-second")?.is_some());
    Ok(())
}
