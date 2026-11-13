// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual `SQLCipher` cut/ACK ordering. Native publication is covered in the SDK component.
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use ramflux_protocol::{canonical_json_bytes, encode_base64url};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn pairing_full_j6_ack_and_tail_cut_bind_the_exact_pre_ack_view() -> TestResult {
    let (root, db) = crate::tests::test_db("full-j6-tail-cut")?;
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
    let stage = encode_base64url([21; 32]);
    let snapshot = encode_base64url([22; 32]);
    // If tail reservation fails, neither the head ACK nor a tail marker may commit.
    db.connection.execute_batch("CREATE TRIGGER reject_tail_cut BEFORE INSERT ON pairing_full_tail BEGIN SELECT RAISE(ABORT,'forced tail reservation failure'); END;")?;
    assert!(
        db.commit_full_ack_tail(&head, &stage, &snapshot, false).is_err(),
        "failed tail reservation accepted ACK"
    );
    assert_eq!(db.pairing_head()?.ok_or("submitted head")?.state, "submitted");
    db.connection.execute_batch("DROP TRIGGER reject_tail_cut;")?;
    let cut = db.commit_full_ack_tail(&head, &stage, &snapshot, false)?;
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
        db.commit_full_ack_tail(&head, &stage, &encode_base64url([23; 32]), false).is_err(),
        "lost tail cut was silently recaptured"
    );
    drop(private);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
