// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private keyed projection read through `AccountDb`; no full installation or courier claim.
use super::super::native_payload::test_support;
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex};
use prost::Message as _;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Account {
    root: tempfile::TempDir,
    index: AccountIndex,
    db: AccountDb,
}
impl Account {
    fn new() -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        let index = AccountIndex::open(root.path())?;
        index.create_account("acct", &ramflux_protocol::encode_base64url([31; 32]))?;
        let key = AccountDbKey::derive("acct", b"direct-install-data-fixture");
        let db = AccountDb::open(&index, "acct", &key)?;
        let inner = test_support::inner(8)?;
        let conversation = &inner.identity.as_ref().ok_or("identity")?.conversation_id;
        db.persist_client_record("conversation", conversation, &serde_json::json!({
            "kind":"direct","group_id":null,"participant_roots":[
                ramflux_protocol::encode_base64url([31;32]),ramflux_protocol::encode_base64url([32;32])
            ]
        }))?;
        Ok(Self { root, index, db })
    }
    fn capture(&self) -> TestResult<OwnAuthoredCapture> {
        let inner = test_support::inner(32)?;
        let original = inner.identity.as_ref().ok_or("identity")?;
        let id = ramflux_protocol::encode_base64url(&original.id);
        let capture = OwnAuthoredCapture {
            target: original.id.clone(),
            current: original.id.clone(),
            original: original.clone(),
            sent: g::OwnSentMessage {
                exact_inner: inner.encode_to_vec(),
                message_id: id.clone(),
                envelope_id: "actual-fixture-original-envelope".into(),
                context: Some(g::OwnContext {
                    conversation_id: original.conversation_id.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        self.db.write_transaction(|| -> TestResult {
            self.db.import_direct_message_projection(crate::DirectMessageWrite {
                conversation_id: &original.conversation_id,
                message_id: &id,
                sender_id: "original-source-device",
                encrypted_body: &[],
                metadata: &MessageMetadata::default(),
                created_at: 17,
            })?;
            self.db.store_message_content(
                &original.conversation_id,
                &id,
                &capture.sent.exact_inner,
            )?;
            self.db.persist_message_actor_state(
                &id,
                &format!("routed/generated-identity/{id}"),
                original,
            )?;
            self.db.persist_message_actor_state(
                &id,
                &format!("own-history/capture/{id}"),
                &capture,
            )?;
            Ok(())
        })?;
        Ok(capture)
    }
    fn private(self) -> TestResult<Private> {
        let path = self.root.path().join("private.db");
        let snapshot = self
            .db
            .pin_full_transfer_cut()?
            .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
        drop(self.db);
        Ok(Private { _root: self.root, index: self.index, key: snapshot.key, path })
    }
}
struct Private {
    _root: tempfile::TempDir,
    index: AccountIndex,
    key: AccountDbKey,
    path: PathBuf,
}
impl Private {
    fn open(&self) -> TestResult<BackupDatabase> {
        Ok(BackupDatabase::open_full_receiver_copy(&self.path, &self.key)?)
    }
    fn reader(&self) -> TestResult<AccountDb> {
        // This fixture exposes the completed private file to the ordinary reader.
        // It deliberately makes no generation-fence or installation acceptance claim.
        self.index.connection.execute(
            "UPDATE local_account SET db_relative_path='private.db' WHERE local_account_id='acct'",
            [],
        )?;
        Ok(AccountDb::open(&self.index, "acct", &self.key)?)
    }
}
#[cfg(test)]
fn project(
    private: &mut BackupDatabase,
    source: &DeviceRef,
    history: &FullDirectHistory,
    row: &DirectMessageRecord,
    capture: Option<&OwnAuthoredCapture>,
) -> Result<bool, StorageError> {
    private.db.execute_batch("SAVEPOINT native_projection_fixture")?;
    let result = private.merge_full_direct_history(source, history, row, capture);
    if result.is_err() {
        private.db.execute_batch("ROLLBACK TO native_projection_fixture")?;
    }
    private.db.execute_batch("RELEASE native_projection_fixture")?;
    result
}
fn source() -> DeviceRef {
    DeviceRef {
        account_anchor: ramflux_protocol::encode_base64url([31; 32]),
        device_id: "source-phone".into(),
        device_epoch: 1,
    }
}

#[test]
fn direct_install_preserves_actual_authored_capture_and_product_identity() -> TestResult {
    let a = Account::new()?;
    let original_capture = a.capture()?;
    let id = ramflux_protocol::encode_base64url(&original_capture.target);
    let history = a.db.read_full_direct_history(&id)?.ok_or("source history")?;
    let row = a.db.direct_message_by_id(&id)?.ok_or("source projection")?;
    let target = Account::new()?.private()?;
    let mut private = target.open()?;
    assert!(
        project(&mut private, &source(), &history, &row, Some(&original_capture))?,
        "native authored history was not installed"
    );
    assert!(
        !project(&mut private, &source(), &history, &row, Some(&original_capture))?,
        "identical native retry gained another version"
    );
    drop(private);
    let db = target.reader()?;
    let actual = db.direct_message_by_id(&id)?.ok_or("installed product row")?;
    assert!(actual.is_own, "new device relabeled the original own-account author as a peer");
    assert_eq!(actual.created_at, 17, "native projection fabricated original capture time");
    assert_eq!(
        db.message_content(&id)?.as_deref(),
        Some(history.exact_inner()),
        "product reader lost exact native bytes"
    );
    let capture = db
        .load_actor_state::<OwnAuthoredCapture>(&format!("own-history/capture/{id}"))?
        .ok_or("installed capture")?;
    assert_eq!(
        serde_json::to_vec(&capture)?,
        serde_json::to_vec(&original_capture)?,
        "native import fabricated or dropped original authored transport metadata"
    );
    let reread = db.read_full_direct_history(&id)?.ok_or("reopened native history")?;
    assert_eq!(
        reread.verify(&source().account_anchor)?.original(),
        &original_capture.original,
        "reopened native reader changed original order or authorship"
    );
    Ok(())
}

#[test]
fn direct_install_missing_capture_and_foreign_account_leave_product_empty() -> TestResult {
    let a = Account::new()?;
    let capture = a.capture()?;
    let id = ramflux_protocol::encode_base64url(&capture.target);
    let history = a.db.read_full_direct_history(&id)?.ok_or("source history")?;
    let row = a.db.direct_message_by_id(&id)?.ok_or("source projection")?;
    let target = Account::new()?.private()?;
    let mut private = target.open()?;
    assert!(
        matches!(
            private.merge_full_direct_history(&source(), &history, &row, Some(&capture)),
            Err(StorageError::PairingField("WrongContext"))
        ),
        "native projection created an independent transaction owner"
    );
    assert!(
        project(&mut private, &source(), &history, &row, None).is_err(),
        "native body import invented missing authored metadata"
    );
    let mut foreign = source();
    foreign.account_anchor = ramflux_protocol::encode_base64url([99; 32]);
    assert!(
        project(&mut private, &foreign, &history, &row, Some(&capture)).is_err(),
        "embedded history account became transfer authority"
    );
    drop(private);
    let db = target.reader()?;
    assert!(db.direct_message_by_id(&id)?.is_none(), "failed native import exposed a partial row");
    assert!(db.message_content(&id)?.is_none(), "failed native import retained partial content");
    Ok(())
}

#[test]
fn direct_install_equal_version_preserves_independent_b_projection_metadata() -> TestResult {
    let a = Account::new()?;
    let capture = a.capture()?;
    let id = ramflux_protocol::encode_base64url(&capture.target);
    let history = a.db.read_full_direct_history(&id)?.ok_or("source history")?;
    let row = a.db.direct_message_by_id(&id)?.ok_or("source projection")?;
    let target = Account::new()?.private()?;
    let mut private = target.open()?;
    project(&mut private, &source(), &history, &row, Some(&capture))?;
    drop(private);
    let db = target.reader()?;
    let independent =
        MessageMetadata { mentions: vec!["independent-B-metadata".into()], ..Default::default() };
    db.replace_generated_message_content(
        &row.conversation_id,
        &id,
        history.exact_inner(),
        &independent,
    )?;
    drop(db);
    let mut private = target.open()?;
    assert!(
        !project(&mut private, &source(), &history, &row, Some(&capture))?,
        "equal imported version replaced independent B history"
    );
    drop(private);
    let db = target.reader()?;
    assert_eq!(
        db.message_metadata(&row.conversation_id, &id)?,
        independent,
        "source defaults erased independent B projection metadata"
    );
    Ok(())
}

#[test]
fn direct_install_joins_outer_rollback_and_erasure_prevents_reimport() -> TestResult {
    let a = Account::new()?;
    let capture = a.capture()?;
    let id = ramflux_protocol::encode_base64url(&capture.target);
    let history = a.db.read_full_direct_history(&id)?.ok_or("source history")?;
    let row = a.db.direct_message_by_id(&id)?.ok_or("source projection")?;
    let target = Account::new()?.private()?;
    let mut private = target.open()?;
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    project(&mut private, &source(), &history, &row, Some(&capture))?;
    private.db.execute_batch("ROLLBACK")?;
    drop(private);
    let db = target.reader()?;
    assert!(
        db.direct_message_by_id(&id)?.is_none(),
        "record savepoint committed the outer generation"
    );
    drop(db);
    let mut private = target.open()?;
    project(&mut private, &source(), &history, &row, Some(&capture))?;
    drop(private);
    let db = target.reader()?;
    db.delete_direct_message(&row.conversation_id, &id, "local", "erase-native-fixture")?;
    assert!(db.message_content(&id)?.is_none(), "ordinary erasure left imported content live");
    assert!(
        !db.actor_state_exists(&format!("own-history/capture/{id}"))?,
        "ordinary erasure did not close the imported capture ownership edge"
    );
    drop(db);
    let mut private = target.open()?;
    assert!(
        !project(&mut private, &source(), &history, &row, Some(&capture))?,
        "independent target erasure lost to source content"
    );
    drop(private);
    let db = target.reader()?;
    assert!(
        db.direct_message_by_id(&id)?.ok_or("erased row")?.deleted,
        "ordinary reader resurrected an erased imported row"
    );
    assert!(db.read_full_direct_history(&id)?.is_none(), "erased content re-entered native export");
    Ok(())
}
