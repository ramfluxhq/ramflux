// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual `SQLCipher` cut/ACK ordering. Native publication is covered in the SDK component.
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use ramflux_protocol::{canonical_json_bytes, encode_base64url};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn pairing_full_j6_ack_and_tail_cut_bind_the_exact_pre_ack_view() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let index = AccountIndex::open(root)?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    db.connection.execute_batch("CREATE TRIGGER runtime_pairing_full_tail_insert AFTER INSERT ON pairing_full_tail BEGIN SELECT NEW.rowid; END;")?;
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    let trigger_count:u64=db.connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'runtime_pairing_full_tail_%'",[],|row|row.get(0))?;
    assert_eq!(trigger_count, 0, "reopen retained runnable tail-bookkeeping triggers");
    let mut head = crate::account_db::pairing::tests::helpers::head()?;
    head.kind = "transfer".into();
    head.state = "submitted".into();
    db.put_pairing_head(&head)?;
    db.connection
        .execute("INSERT INTO projection_checkpoint VALUES('tail-cut',1,'before-j6',NULL,1)", [])?;
    head.state = "acknowledged".into();
    head.ack = Some(canonical_json_bytes(
        &serde_json::json!({"record_hash":head.candidate_hash,"device_set_epoch":7}),
    )?);
    let owner = crate::FullSourcePrimaryOwner {
        reference: encode_base64url([24; 32]),
        public_key: encode_base64url([25; 32]),
    };
    let stage = encode_base64url([21; 32]);
    let snapshot = encode_base64url([22; 32]);
    // If tail reservation fails, neither the head ACK nor a tail marker may commit.
    db.connection.execute_batch("CREATE TRIGGER reject_tail_cut BEFORE INSERT ON pairing_full_tail BEGIN SELECT RAISE(ABORT,'forced tail reservation failure'); END;")?;
    assert!(
        db.commit_full_ack_tail(&head, &stage, &snapshot, false, &owner).is_err(),
        "failed tail reservation accepted ACK"
    );
    assert_eq!(
        db.pairing_head()?.ok_or("submitted head")?.state,
        "submitted",
        "test: failed J6 reservation committed acknowledgement"
    );
    let receipts: u64 =
        db.connection
            .query_row("SELECT count(*) FROM pairing_source_cleanup", [], |row| row.get(0))?;
    assert_eq!(receipts, 0, "test: failed J6 created positive cleanup authority");
    db.connection.execute_batch("DROP TRIGGER reject_tail_cut;")?;
    let cut = db.commit_full_ack_tail(&head, &stage, &snapshot, false, &owner)?;
    assert_eq!(db.pairing_head()?.ok_or("J6 head")?.state, "acknowledged");
    let marker: (String, String, String) = db.connection.query_row(
        "SELECT snapshot_id,tail_status,cut_state FROM pairing_full_tail",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(marker, (snapshot.clone(), "pending".into(), "pinned".into()));
    db.connection.execute("UPDATE projection_checkpoint SET last_event_id='after-j6' WHERE projection_name='tail-cut'",[])?;
    let path = root.join("tail-private.db");
    let copied = cut.write_private_snapshot(
        &path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let private = BackupDatabase::open_full_receiver_copy(&path, &copied.key)?;
    let value: String = private.db.query_row(
        "SELECT last_event_id FROM projection_checkpoint WHERE projection_name='tail-cut'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(value, "before-j6", "post-J6 write entered the immutable tail cut");
    assert!(
        db.commit_full_ack_tail(&head, &stage, &encode_base64url([23; 32]), false, &owner).is_err(),
        "lost tail cut was silently recaptured"
    );
    drop(private);
    drop(db);
    drop(index);
    let db = AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    db.connection.execute_batch(
        "DELETE FROM pairing_full_tail; DELETE FROM pairing_live; DELETE FROM pairing_head;",
    )?;
    let retained = db.full_source_retirement_owner(&head.operation_id, &head.candidate_hash, 1)?;
    assert_eq!(
        retained.reference(),
        owner.reference(),
        "test: old cleanup owner depended on reclaimed journal/tail state"
    );
    assert!(
        db.full_source_retirement_owner(&head.operation_id, &encode_base64url([99; 32]), 1)
            .is_err(),
        "test: cleanup ledger accepted another candidate"
    );
    db.connection.call(|raw| Ok(crate::account_db::pairing::privacy::sanitize_backup(raw)))??;
    assert!(
        db.full_source_retirement_owner(&head.operation_id, &head.candidate_hash, 1).is_err(),
        "test: published backup retained source cleanup ownership"
    );
    Ok(())
}
