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

#[test]
fn pairing_full_generation_fence_retires_queued_and_parallel_old_writers() -> ResultOf {
    use std::sync::{Arc, Barrier};
    let (root, db) = crate::tests::test_db("full-generation-worker-fence")?;
    let index = AccountIndex::open(&root)?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let other = AccountDb::open(&index, "acct", &key)?;
    seed(&db)?;
    let before = db
        .connection
        .query_row("SELECT count(*) FROM runtime_actor_state", [], |r| r.get::<_, u64>(0))?;
    let rendezvous = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let original = db.connection.clone();
    let worker = {
        let rendezvous = rendezvous.clone();
        let released = released.clone();
        std::thread::spawn(move || {
            original.call_generation(move |_| {
                rendezvous.wait();
                released.wait();
                (Ok(()), true)
            })
        })
    };
    rendezvous.wait(); // The real original worker now holds the account-wide exclusive fence.
    let queued = other.connection.clone();
    let waiting = std::thread::spawn(move || {
        queued.execute("INSERT INTO runtime_actor_state VALUES('old-queued-write',x'00')", [])
    });
    released.wait();
    worker.join().map_err(|_| "generation owner panicked")??;
    assert!(
        waiting.join().map_err(|_| "writer panicked")?.is_err(),
        "queued old writer crossed G2"
    );
    assert!(
        db.connection.execute("DELETE FROM runtime_actor_state", []).is_err(),
        "original writer survived G2"
    );
    assert!(
        other.connection.execute("DELETE FROM runtime_actor_state", []).is_err(),
        "parallel writer survived G2"
    );
    // This test retires without changing paths to isolate worker lifetime from index metadata.
    // A fresh writer is usable and observes no queued write; this is not full G1/G2/G3 proof.
    let fresh = AccountDb::open(&index, "acct", &key)?;
    assert_eq!(
        fresh
            .connection
            .query_row("SELECT count(*) FROM runtime_actor_state", [], |r| r.get::<_, u64>(0))?,
        before
    );
    drop(fresh);
    drop(other);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pairing_full_generation_selection_checks_all_writes_and_atomic_prior_selection() -> ResultOf {
    let (root, db) = crate::tests::test_db("full-generation-selection-fence")?;
    let index = AccountIndex::open(&root)?;
    // Index wrapping is mandatory and must remain B's own wrapping at G2.
    let key = crate::WrappedAccountDbKey {
        key_wrapping_provider: "vault".into(),
        key_wrapping_ref: "b-local".into(),
        nonce: [1; 12],
        wrapped_key: vec![2; 48],
    };
    index.store_wrapped_db_key("acct", &key)?;
    seed(&db)?;
    let (cut, stale) = db.pin_full_transfer_target()?;
    drop(cut);
    db.connection.execute("UPDATE runtime_actor_state SET state_json=x'01' WHERE state_kind='target-observation-test'", [])?;
    let install = crate::BackupIndexInstall {
        account_id: "acct",
        principal_commitment: &index.account("acct")?.principal_commitment,
        db_relative_path: "accounts/acct/generation-new/account.db",
        object_relative_path: "accounts/acct/generation-new/objects",
        manifest_json: b"local-test-manifest",
        wrapped_key: &key,
    };
    let prior = index.account("acct")?;
    assert!(stale.commit_prepared_generation(&db, &install).is_err(), "ordinary B write was lost");
    assert_eq!(index.account("acct")?, prior);
    let (cut, current) = db.pin_full_transfer_target()?;
    drop(cut);
    index.connection.execute_batch("CREATE TRIGGER fail_generation BEFORE INSERT ON account_backup_generation BEGIN SELECT RAISE(ABORT,'fail'); END;")?;
    assert!(current.commit_prepared_generation(&db, &install).is_err());
    assert_eq!(index.account("acct")?, prior, "partial G2 selection");
    current.require_current(&db)?; // A known failed commit did not retire the current worker.
    index.connection.execute_batch("DROP TRIGGER fail_generation")?;
    current.commit_prepared_generation(&db, &install)?;
    let selected = index.account_generation_selection("acct")?;
    assert_eq!(selected.account.db_relative_path, install.db_relative_path);
    assert_eq!(selected.account.object_dir_relative_path, install.object_relative_path);
    assert_eq!(selected.manifest_json.as_deref(), Some(install.manifest_json));
    assert_eq!(index.load_wrapped_db_key("acct")?, Some(key));
    assert!(
        db.connection.execute("DELETE FROM runtime_actor_state", []).is_err(),
        "selected old writer stayed writable"
    );
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
