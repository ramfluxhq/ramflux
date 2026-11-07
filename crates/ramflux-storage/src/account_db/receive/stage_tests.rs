// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! W0 reservations and first-copy authority; actor recovery is tested by P20.
#![allow(clippy::expect_used, clippy::panic)]
use super::*;
use crate::{AccountDb, StorageError};
use rusqlite::params;
use stage::{ReceiveStage, ReceiveStageResult as R};

fn setup(name: &str) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let (root, db) = crate::tests::test_db(name)?;
    db.install_receive_ledger_schema()?;
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    Ok((root, db))
}
fn bytes(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"hash"
    }})).expect("entry fixture")
}
fn input(bytes: &[u8], sequence: u64) -> ReceiveStage<'_> {
    ReceiveStage {
        target: "t",
        incarnation: "e",
        sequence,
        entry_json: bytes,
        admission_key: "authenticated-key",
        retain_until: 100,
        first_seen: 1,
    }
}
fn run(db: &AccountDb, input: ReceiveStage<'_>) -> Result<R, StorageError> {
    db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| tx.stage(input),
    )
}
fn clear(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute_batch("DELETE FROM gateway_receive_work; DELETE FROM gateway_receive_receipt; DELETE FROM gateway_ack_intent;")?;
    Ok(())
}
#[test]
fn capacity_and_range_work() -> Result<(), StorageError> {
    let (root, db) = setup("w0-capacity")?;
    let wire = bytes(u64::MAX);
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::Staged);
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::Existing);
    clear(&db)?;
    let mut maximum = bytes(1);
    maximum.resize(1_048_576, b' ');
    assert_eq!(run(&db, input(&maximum, 1))?, R::Staged, "inclusive entry byte bound");
    clear(&db)?;
    // Inactive E consumes slots; no per-sequence walk, even at u64::MAX.
    db.write_transaction(|| {
        for n in 1u64..=1024 {
            db.connection.execute(
                "INSERT INTO gateway_ack_intent VALUES('t','old',?1,0,0,0,100)",
                params![n.to_be_bytes().as_slice()],
            )?;
        }
        Ok::<(), StorageError>(())
    })?;
    let mut processing = 0;
    if run(&db, input(&wire, u64::MAX))? == R::Staged {
        processing += 1;
    }
    assert_eq!(processing, 0, "processing ran without terminal reservation");
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::PausedIntents);
    db.connection.execute(
        "DELETE FROM gateway_ack_intent WHERE inbox_seq=?1",
        params![1024u64.to_be_bytes().as_slice()],
    )?;
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::Staged, "inclusive 1024-slot bound");
    assert_eq!(
        run(&db, input(&wire, u64::MAX))?,
        R::Existing,
        "duplicates use no slot at capacity"
    );
    clear(&db)?;
    // Fill precisely 64 MiB with 64 maximum-size records, all on an inactive E.
    db.write_transaction(|| {
        for n in 1u64..=64 {
            db.connection.execute("INSERT INTO gateway_receive_receipt VALUES('t','old',?1,'held',100,1)",params![n.to_be_bytes().as_slice()])?;
            db.connection.execute("INSERT INTO gateway_receive_work VALUES('t','old',?1,zeroblob(1048576),'key',1048576)",params![n.to_be_bytes().as_slice()])?;
        }
        Ok::<(), StorageError>(())
    })?;
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::PausedBytes);
    db.connection.execute("UPDATE gateway_receive_work SET entry_json=zeroblob(1048576-?1),byte_len=1048576-?1 WHERE inbox_seq=?2",params![i64::try_from(wire.len()).expect("bounded fixture"),1u64.to_be_bytes().as_slice()])?;
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::Staged, "inclusive 64MiB bound");
    clear(&db)?;
    db.write_transaction(|| {
        for n in 1u64..=1024 {
            db.connection.execute(
                "INSERT INTO gateway_receive_receipt VALUES('t','old',?1,'held',100,1)",
                params![n.to_be_bytes().as_slice()],
            )?;
            db.connection.execute(
                "INSERT INTO gateway_receive_work VALUES('t','old',?1,x'00','key',1)",
                params![n.to_be_bytes().as_slice()],
            )?;
        }
        Ok::<(), StorageError>(())
    })?;
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::PausedWork);
    db.connection.execute(
        "DELETE FROM gateway_receive_work WHERE inbox_seq=?1",
        params![1024u64.to_be_bytes().as_slice()],
    )?;
    db.connection.execute(
        "DELETE FROM gateway_receive_receipt WHERE inbox_seq=?1",
        params![1024u64.to_be_bytes().as_slice()],
    )?;
    assert_eq!(run(&db, input(&wire, u64::MAX))?, R::Staged, "inclusive work bound");
    clear(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn staged_content_conflict() -> Result<(), StorageError> {
    let (root, db) = setup("w0-conflict")?;
    let original = bytes(1);
    assert_eq!(run(&db, input(&original, 1))?, R::Staged);
    let conflicting =
        String::from_utf8(original.clone()).expect("UTF8").replace("cipher", "other").into_bytes();
    assert_eq!(run(&db, input(&conflicting, 1))?, R::Conflict { diagnostic_created: true });
    assert_eq!(run(&db, input(&conflicting, 1))?, R::Conflict { diagnostic_created: false });
    drop(db);
    let db = AccountDb::open(
        &crate::AccountIndex::open(&root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert_eq!(
        run(&db, input(&conflicting, 1))?,
        R::Conflict { diagnostic_created: false },
        "reconnect retains conflict suppression"
    );
    let stored: Vec<u8> =
        db.connection.query_row("SELECT entry_json FROM gateway_receive_work", [], |r| r.get(0))?;
    assert_eq!(stored, original);
    assert_eq!(run(&db, input(&original, 1))?, R::Existing, "original remains redrivable");
    db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| {
            for n in 2..=65 {
                let wire = bytes(n);
                assert_eq!(tx.stage(input(&wire, n))?, R::Staged);
                let conflict =
                    String::from_utf8(wire).expect("UTF8").replace("cipher", "other").into_bytes();
                assert_eq!(
                    tx.stage(input(&conflict, n))?,
                    R::Conflict { diagnostic_created: true }
                );
            }
            Ok::<(), StorageError>(())
        },
    )?;
    let diagnostics:i64=db.connection.query_row("SELECT count(*) FROM projection_checkpoint WHERE projection_name LIKE 'gateway_receive_conflict:%' AND last_event_id='conflict'",[],|r|r.get(0))?;
    assert_eq!(diagnostics, 64, "bounded metadata diagnostics");
    db.connection.execute("UPDATE projection_checkpoint SET projection_version=?1 WHERE projection_name LIKE 'gateway_receive_conflict:%'",params![i64::MAX-1])?;
    let last = bytes(66);
    assert_eq!(run(&db, input(&last, 66))?, R::Staged);
    let last_conflict =
        String::from_utf8(last).expect("UTF8").replace("cipher", "other").into_bytes();
    assert_eq!(
        run(&db, input(&last_conflict, 66))?,
        R::Conflict { diagnostic_created: true },
        "inclusive diagnostic ordinal bound"
    );
    let exhausted = bytes(67);
    assert_eq!(run(&db, input(&exhausted, 67))?, R::Staged);
    let exhausted_conflict =
        String::from_utf8(exhausted).expect("UTF8").replace("cipher", "other").into_bytes();
    assert!(matches!(
        run(&db, input(&exhausted_conflict, 67)),
        Err(StorageError::Integrity("receive diagnostic counter exhausted"))
    ));
    db.connection.execute("UPDATE gateway_receive_receipt SET disposition='erased'", [])?;
    db.connection.execute("DELETE FROM gateway_receive_work", [])?;
    assert_eq!(run(&db, input(&original, 1))?, R::Erased);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn stage_input_and_authority_fences() -> Result<(), StorageError> {
    let (root, db) = setup("w0-fences")?;
    let wire = bytes(1);
    for (candidate, message) in [
        (ReceiveStage { sequence: 0, ..input(&wire, 1) }, "receive sequence must be positive"),
        (ReceiveStage { entry_json: b"", ..input(&wire, 1) }, "receive entry byte bound"),
        (ReceiveStage { entry_json: b"{}", ..input(&wire, 1) }, "receive entry encoding"),
        (ReceiveStage { admission_key: "", ..input(&wire, 1) }, "receive admission key missing"),
        (ReceiveStage { target: "other", ..input(&wire, 1) }, "receive stage authority mismatch"),
        (
            ReceiveStage { incarnation: "other", ..input(&wire, 1) },
            "receive stage authority mismatch",
        ),
        (ReceiveStage { sequence: 2, ..input(&wire, 1) }, "receive entry binding"),
    ] {
        assert!(
            matches!(run(&db,candidate),Err(StorageError::Integrity(actual)) if actual==message),
            "expected {message}"
        );
    }
    let too_large = vec![b' '; 1_048_577];
    assert!(matches!(
        run(&db, input(&too_large, 1)),
        Err(StorageError::Integrity("receive entry byte bound"))
    ));
    let mut wrong_target: serde_json::Value = serde_json::from_slice(&wire)?;
    wrong_target["target_delivery_id"] = serde_json::json!("other");
    let received = serde_json::to_vec(&wrong_target)?;
    assert!(matches!(
        run(&db, input(&received, 1)),
        Err(StorageError::Integrity("receive entry binding"))
    ));
    wrong_target["target_delivery_id"] = serde_json::json!("t");
    wrong_target["envelope"]["target_delivery_id"] = serde_json::json!("other");
    let received = serde_json::to_vec(&wrong_target)?;
    assert!(matches!(
        run(&db, input(&received, 1)),
        Err(StorageError::Integrity("receive entry binding"))
    ));
    let erased = db.privacy_erasure_generation()?;
    let expected = ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor: 0,
        generation: 1,
        erasure_generation: erased - 1,
    };
    assert!(matches!(
        db.receive_transaction(expected, 1, |tx| tx.stage(input(&wire, 1))),
        Err(StorageError::ObjectErased)
    ));
    assert!(matches!(
        db.receive_transaction(
            ReceiveExpectation { erasure_generation: erased, ..expected },
            2,
            |tx| tx.stage(input(&wire, 1))
        ),
        Err(StorageError::AuthorizationRejected)
    ));
    assert!(matches!(
        db.receive_transaction(
            ReceiveExpectation { erasure_generation: erased, ..expected },
            1,
            |tx| {
                assert_eq!(tx.stage(input(&wire, 1))?, R::Staged);
                db.connection
                    .execute("UPDATE account_erasure_generation SET generation=generation+1", [])?;
                Ok::<(), StorageError>(())
            }
        ),
        Err(StorageError::ObjectErased)
    ));
    let rows: i64 =
        db.connection
            .query_row("SELECT count(*) FROM gateway_receive_receipt", [], |r| r.get(0))?;
    assert_eq!(rows, 0, "late erasure fence rolls back staged input");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn stage_failure_rolls_back_reservation_even_if_caught() -> Result<(), StorageError> {
    let (root, db) = setup("w0-rollback")?;
    db.connection.execute_batch("CREATE TEMP TRIGGER fail_w0 BEFORE INSERT ON gateway_receive_work BEGIN SELECT RAISE(ABORT,'w0 work failure'); END;")?;
    let wire = bytes(1);
    db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| {
            match tx.stage(input(&wire, 1)) {
                Err(StorageError::Sqlite(rusqlite::Error::SqliteFailure(code, Some(message)))) => {
                    assert_eq!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER);
                    assert_eq!(message, "w0 work failure");
                }
                other => panic!("expected exact injected work failure, got {other:?}"),
            }
            Ok::<(), StorageError>(())
        },
    )?;
    let count: i64 =
        db.connection
            .query_row("SELECT count(*) FROM gateway_receive_receipt", [], |r| r.get(0))?;
    assert_eq!(count, 0, "failed work insert leaked a receipt reservation");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn entry(sequence: u64, hash: &str, ext: Option<serde_json::Value>) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes(sequence)).expect("entry fixture");
    value["envelope"]["payload_hash"] = serde_json::json!(hash);
    if let Some(ext) = ext {
        value["envelope"]["ext"] = ext;
    }
    serde_json::to_vec(&value).expect("entry encoding")
}
fn footprints(db: &AccountDb) -> Result<Vec<(String, String)>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT message_id,locator FROM message_footprint WHERE kind='receive_work' \
         ORDER BY message_id,locator",
    )?;
    let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}
fn locator(sequence: u64) -> String {
    format!("[\"t\",\"e\",\"{sequence:016X}\"]")
}
fn work_rows(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row("SELECT count(*) FROM gateway_receive_work", [], |r| r.get(0))?)
}

#[test]
fn receive_work_footprint_registered_atomically() -> Result<(), StorageError> {
    let (root, db) = setup("w0-footprint")?;
    for owner in ["bound-owner", "V", "V2"] {
        db.send_direct_message("thread", owner, "peer", b"secret")?;
    }
    // (a) One row with the JSON (T,E,s) locator, owned by the provisional payload alias.
    let first = entry(1, "hash", None);
    assert_eq!(run(&db, input(&first, 1))?, R::Staged);
    assert_eq!(footprints(&db)?, vec![("copy:payload:hash".to_owned(), locator(1))]);
    // (b) A payload already bound to M is owned by M directly.
    db.connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:bound','bound-owner')", [])?;
    let bound = entry(2, "bound", None);
    assert_eq!(run(&db, input(&bound, 2))?, R::Staged);
    assert!(footprints(&db)?.contains(&("bound-owner".to_owned(), locator(2))));
    // Binding the provisional alias later adopts the existing row.
    db.connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:hash','bound-owner')", [])?;
    assert!(footprints(&db)?.contains(&("bound-owner".to_owned(), locator(1))));
    // (c) Extension values never confer ownership.
    let injected = entry(
        3,
        "real",
        Some(serde_json::json!({
            "message_id":"V","payload_hash":"X","object_id":"O","message":{"id":"V2"}
        })),
    );
    assert_eq!(run(&db, input(&injected, 3))?, R::Staged);
    let owners: Vec<String> = footprints(&db)?
        .into_iter()
        .filter(|(_, at)| *at == locator(3))
        .map(|(owner, _)| owner)
        .collect();
    assert_eq!(owners, vec!["copy:payload:real".to_owned()]);
    db.delete_direct_message("thread", "V", "local", "delete-v")?;
    assert_eq!(work_rows(&db)?, 3, "deleting V must not remove unrelated work");
    // (d) A failing closure leaves neither work nor footprint.
    let doomed = entry(4, "doomed", None);
    let failed = db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| {
            tx.stage(input(&doomed, 4))?;
            Err::<(), StorageError>(StorageError::AuthorizationRejected)
        },
    );
    assert!(matches!(failed, Err(StorageError::AuthorizationRejected)));
    assert_eq!(work_rows(&db)?, 3);
    assert!(!footprints(&db)?.iter().any(|(_, at)| *at == locator(4)));
    // (e) Removing the work removes its row.
    db.connection.execute(
        "DELETE FROM gateway_receive_work WHERE inbox_seq=?1",
        params![2u64.to_be_bytes().as_slice()],
    )?;
    assert!(!footprints(&db)?.iter().any(|(_, at)| *at == locator(2)));
    // (f) After reopen new work is still registered.
    drop(db);
    let db = AccountDb::open(
        &crate::AccountIndex::open(&root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    let after = entry(5, "after", None);
    assert_eq!(run(&db, input(&after, 5))?, R::Staged);
    assert!(footprints(&db)?.contains(&("copy:payload:after".to_owned(), locator(5))));
    // (g) The ledger checksum is the unchanged label.
    let checksum: String = db.connection.query_row(
        "SELECT checksum FROM schema_migration WHERE schema_version=15",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(checksum, "2026-11-06-receive-ledger-v1");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn receipt_state(db: &AccountDb, sequence: u64) -> Result<Option<String>, StorageError> {
    use rusqlite::OptionalExtension;
    Ok(db
        .connection
        .query_row(
            "SELECT disposition FROM gateway_receive_receipt WHERE inbox_seq=?1",
            params![sequence.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?)
}
fn work_for(db: &AccountDb, sequence: u64) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE inbox_seq=?1",
        params![sequence.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?)
}

fn assert_erased_pair(db: &AccountDb) -> Result<(), StorageError> {
    // (a) Both receipts of the deleted message are erased and carry no work or row.
    for sequence in [1, 2] {
        assert_eq!(receipt_state(db, sequence)?.as_deref(), Some("erased"), "s{sequence}");
        assert_eq!(work_for(db, sequence)?, 0, "s{sequence} work");
        assert!(!footprints(db)?.iter().any(|(_, at)| *at == locator(sequence)));
    }
    // (b) The same wire id with a distinct payload is untouched.
    assert_eq!(receipt_state(db, 3)?.as_deref(), Some("staged"));
    assert_eq!(work_for(db, 3)?, 1);
    assert!(footprints(db)?.contains(&("copy:payload:other".to_owned(), locator(3))));
    // (c) No non-terminal receipt exists without its work.
    let orphaned: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt r WHERE r.disposition IN ('staged','held') \
         AND NOT EXISTS(SELECT 1 FROM gateway_receive_work w WHERE w.target_delivery_id=r.target_delivery_id \
         AND w.incarnation_id=r.incarnation_id AND w.inbox_seq=r.inbox_seq)",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(orphaned, 0);
    Ok(())
}

#[test]
fn receive_erasure_marks_receipt_before_work() -> Result<(), StorageError> {
    let (root, db) = setup("w0-erasure")?;
    db.connection.disable_background_checkpoints_for_test();
    db.send_direct_message("thread", "M", "peer", b"secret")?;
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:shared','M')", [])?;
    // s1 staged and s2 held, both bound to M; s3 shares the wire id but has a distinct payload.
    for (sequence, hash) in [(1, "shared"), (2, "shared"), (3, "other")] {
        let wire = entry(sequence, hash, None);
        assert_eq!(run(&db, input(&wire, sequence))?, R::Staged);
    }
    db.connection.execute(
        "UPDATE gateway_receive_receipt SET disposition='held' WHERE inbox_seq=?1",
        params![2u64.to_be_bytes().as_slice()],
    )?;
    db.delete_direct_message("thread", "M", "local", "delete-m")?;
    assert_erased_pair(&db)?;
    // (d) Deletion arms the flag; TRUNCATE is clean and leaves an empty WAL.
    let pending: i64 = db.connection.query_row(
        "SELECT erasure_pending FROM runtime_privacy_maintenance WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(pending, 1);
    let (busy, _log, _checkpointed): (i64, i64, i64) =
        db.connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    assert_eq!(busy, 0);
    let mut wal = db.path.clone().into_os_string();
    wal.push("-wal");
    assert_eq!(std::fs::metadata(&wal).map_or(0, |meta| meta.len()), 0);
    let secure: i64 = db.connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    assert_eq!(secure, 1);
    // (e) After reopen (a) to (c) still hold.
    drop(db);
    let db = AccountDb::open(
        &crate::AccountIndex::open(&root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert_erased_pair(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
