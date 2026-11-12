// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual worker/pinned views; this is not the final G2 generation/writer-fence proof.
use crate::{AccountDb, AccountDbKey, AccountIndex, StorageError, database::Connection};
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn seed(db: &AccountDb) -> ResultOf {
    db.connection.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES('target-observation-test',?1)",rusqlite::params![b"before".as_slice()])?;
    Ok(())
}

#[test]
fn pairing_full_target_observation_refuses_ordinary_write_and_retains_pinned_target_bytes()
-> ResultOf {
    let (root, db) = crate::tests::test_db("full-target-observation-write")?;
    seed(&db)?;
    let (cut, observed) = db.pin_full_transfer_target()?;
    observed.require_current(&db)?;
    let privacy = observed.privacy_epoch();
    db.connection.execute(
        "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind='target-observation-test'",
        rusqlite::params![b"after".as_slice()],
    )?;
    assert_eq!(
        db.connection
            .query_row("SELECT generation FROM account_erasure_generation", [], |r| r
                .get::<_, u64>(0))?,
        privacy
    );
    assert!(
        matches!(observed.require_current(&db), Err(StorageError::PairingField("Busy"))),
        "ordinary target change was lost behind an unchanged privacy epoch"
    );
    let path = root.join("pinned-target.db");
    let snapshot = cut.write_private_snapshot(
        &path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let input = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    crate::encryption::apply_key(&input, &snapshot.key)?;
    assert_eq!(input.query_row("SELECT CAST(state_json AS TEXT) FROM runtime_actor_state WHERE state_kind='target-observation-test'",[],|r|r.get::<_,String>(0))?,"before");
    drop(input);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pairing_full_target_observation_refuses_foreign_worker_and_does_not_keep_unlock_alive()
-> ResultOf {
    let (root, db) = crate::tests::test_db("full-target-observation-reopen")?;
    let (cut, observed) = db.pin_full_transfer_target()?;
    drop(cut);
    assert_eq!(observed.local_account_id(), "acct");
    let index = AccountIndex::open(&root)?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let second = AccountDb::open(&index, "acct", &key)?;
    assert!(observed.require_current(&second).is_err(), "observation crossed DB workers");
    drop(second);
    drop(db);
    let reopened = AccountDb::open(&index, "acct", &key)?;
    assert!(
        matches!(observed.require_current(&reopened), Err(StorageError::AuthorizationRejected)),
        "opaque observation restored an old unlock owner"
    );
    let (cut, new_observation) = reopened.pin_full_transfer_target()?;
    new_observation.require_current(&reopened)?;
    drop(cut);
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pairing_full_target_observation_detects_other_connection_commits() -> ResultOf {
    let (root, db) = crate::tests::test_db("full-target-observation-other")?;
    seed(&db)?;
    let (cut, observed) = db.pin_full_transfer_target()?;
    let before: u64 = db.connection.query_row("SELECT total_changes()", [], |r| r.get(0))?;
    // Test-only second SQLite writer isolates PRAGMA data_version from total_changes.
    let writer = Connection::open(&db.path)?;
    crate::encryption::apply_key(&writer, &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    writer.execute(
        "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind='target-observation-test'",
        rusqlite::params![b"another-connection".as_slice()],
    )?;
    assert_eq!(
        db.connection.query_row("SELECT total_changes()", [], |r| r.get::<_, u64>(0))?,
        before
    );
    assert!(
        matches!(observed.require_current(&db), Err(StorageError::PairingField("Busy"))),
        "external target commit bypassed change observation"
    );
    drop(writer);
    drop(cut);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
