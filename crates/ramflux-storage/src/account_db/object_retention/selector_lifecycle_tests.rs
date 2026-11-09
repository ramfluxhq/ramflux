// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Managed selector death and transport dependency capture.
use super::*;
use serde_json::json;

fn register(db: &AccountDb, selector: &str, message: &str, hash: &str) -> Result<(), StorageError> {
    db.send_direct_message("thread", message, "peer", b"body")?;
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: hash,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector,
            message_id: message,
            reference: &json!({"object_id":"wire","slot":hash}),
            metadata: &json!({"object_id":selector,"message_id":message}),
        },
    )?;
    Ok(())
}

fn placeholder(db: &AccountDb, selector: &str) -> Result<(), StorageError> {
    // Authenticated retained mapping exists; G2 fallback tightening is a later slice.
    db.persist_actor_state(
        &format!("attachment/reference/{selector}"),
        &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
    )?;
    db.set_object_tombstoned(selector)?;
    let key = format!("attachment/reference-by-slot/{selector}");
    db.persist_actor_state(&key, &json!(selector))?;
    let hashes: Vec<String> = db
        .connection
        .prepare("SELECT reference_hash FROM object_retention_reference WHERE selector=?1")?
        .query_map(params![selector], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for hash in hashes {
        db.register_object_reference_actor(&hash, &key)?;
    }
    Ok(())
}

fn assert_retired(db: &AccountDb, selector: &str) -> Result<(), StorageError> {
    assert!(matches!(db.check_object_access(selector), Err(StorageError::ObjectErased)));
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_index WHERE object_id=?1",
        params![selector],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0, "placeholder survived selector retirement");
    for key in [
        format!("attachment/reference/{selector}"),
        format!("directory/object/{selector}"),
        format!("attachment/reference-by-slot/{selector}"),
    ] {
        assert!(!db.actor_state_exists(&key)?, "actor survived: {key}");
        let count: i64 = db.connection.query_row(
            "SELECT count(*) FROM object_payload_actor WHERE state_kind=?1",
            params![key],
            |r| r.get(0),
        )?;
        assert_eq!(count, 0, "payload actor binding survived");
    }
    let bindings: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id=?1",
        params![format!("object:{selector}")],
        |r| r.get(0),
    )?;
    assert_eq!(bindings, 0);
    for table in
        ["object_erasure_work", "object_reference_erasure_work", "object_projection_erasure_work"]
    {
        let count: i64 =
            db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        assert_eq!(count, 0, "work survived: {table}");
    }
    Ok(())
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn verify_snapshot(db: &AccountDb, root: &std::path::Path) -> Result<(), StorageError> {
    db.checkpoint_retired_secrets()?;
    super::tests::assert_erasure_canary_absent(db)?;
    let path = root.join("retired-snapshot.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let sql = rusqlite::Connection::open(&path)?;
    sql.execute_batch(&format!("PRAGMA key=\"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
    super::tests::assert_erasure_canary_absent_sql(&sql)?;
    Ok(())
}

fn alias_deletion(first: &str, second: &str) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-death")?;
    register(&db, "private-canary", "m1", "r1")?;
    register(&db, "private-canary", "m2", "r2")?;
    register(&db, "survivor", "m3", "r3")?;
    placeholder(&db, "private-canary")?;
    db.delete_direct_message("thread", first, "local", "delete-first")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    let lookup: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1",
        params![object_erasure_lookup(db.object_erasure_root(), "private-canary")],
        |r| r.get(0),
    )?;
    assert_eq!(lookup, 0, "a surviving selector must not acquire a new lookup");
    db.delete_direct_message("thread", second, "local", "delete-second")?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    db.check_object_access("survivor")?;
    assert_eq!(db.object_erasure_generation()?, 0, "another selector keeps C alive");
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn alias_order(first: &str, second: &str) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("alias-order")?;
    register(&db, "wire", "m1", "wire-reference")?;
    register(&db, "private-canary", "m2", "alias-reference")?;
    super::tests::payload(&db)?;
    placeholder(&db, "private-canary")?;
    db.delete_direct_message("thread", first, "local", "delete-first")?;
    if first == "m2" {
        assert_retired(&db, "private-canary")?;
        db.check_object_access("wire")?;
        assert!(db.load_object::<Value>("wire")?.is_some());
        assert_eq!(db.object_erasure_generation()?, 0);
    } else {
        assert!(db.object_is_tombstoned("private-canary")?);
        db.check_object_access("private-canary")?;
    }
    db.delete_direct_message("thread", second, "local", "delete-second")?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e1_alias_dies_with_last_reference_m2_then_m1() -> Result<(), StorageError> {
    alias_order("m2", "m1")
}
#[test]
fn e1_alias_dies_with_last_reference_m1_then_m2() -> Result<(), StorageError> {
    alias_order("m1", "m2")
}

#[test]
fn e2_same_selector_distinct_hashes_survive_first_delete() -> Result<(), StorageError> {
    alias_deletion("m1", "m2")
}

#[test]
fn e2_shared_hash_two_owners() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-shared-hash")?;
    register(&db, "private-canary", "m1", "shared")?;
    register(&db, "private-canary", "m2", "shared")?;
    placeholder(&db, "private-canary")?;
    db.delete_direct_message("thread", "m1", "local", "delete-one")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    db.delete_direct_message("thread", "m2", "local", "delete-two")?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn transport(hold_child: bool, two_hops: bool, message_seeded: bool) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-transport")?;
    register(&db, "private-canary", "m1", "parent-ref")?;
    db.retain_object("wire", "manifest", ObjectRetention::OwnDeviceTransport)?;
    placeholder(&db, "private-canary")?;
    let child =
        if hold_child { Some(db.pre_send_object_hold("child", "child-manifest")?) } else { None };
    if hold_child || two_hops || message_seeded {
        if child.is_none() {
            db.retain_object("child", "child-manifest", ObjectRetention::Imported)?;
        }
        if two_hops {
            db.retain_object("middle", "middle-manifest", ObjectRetention::OwnDeviceTransport)?;
            db.retain_transport_dependency("wire", "manifest", "middle", "middle-manifest")?;
            db.retain_transport_dependency("middle", "middle-manifest", "child", "child-manifest")?;
        } else {
            db.retain_transport_dependency("wire", "manifest", "child", "child-manifest")?;
        }
    }
    if let Some(child) = child {
        let (class,owners):(String,i64)=db.connection.query_row("SELECT retention_class,owner_count FROM object_retention_payload WHERE wire_id='child'",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!((class.as_str(), owners), ("pre_send", 0));
        child.release()?;
    } else if message_seeded {
        db.send_direct_message("thread", "child-message", "peer", b"body")?;
        db.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: "child-ref",
                wire_id: "child",
                manifest_hash: "child-manifest",
                selector: "child-alias",
                message_id: "child-message",
                reference: &json!({}),
                metadata: &json!({}),
            },
        )?;
        db.delete_direct_message("thread", "child-message", "local", "child-delete")?;
    } else if two_hops {
        // The public transport retirement API seeds only transports.
        db.retain_object("child", "child-manifest", ObjectRetention::OwnDeviceTransport)?;
        db.retire_transport_object("child", "child-manifest")?;
    } else {
        let generation = db.privacy_erasure_generation()?;
        db.connection.execute_batch("CREATE TEMP TRIGGER fail_transport_capture AFTER INSERT ON main.object_reference_erasure_work BEGIN SELECT RAISE(ABORT,'transport capture cut'); END;")?;
        let Err(error) = db.retire_transport_object("wire", "manifest") else {
            return Err(StorageError::AuthorizationRejected);
        };
        assert!(error.to_string().contains("transport capture cut"));
        drop(db);
        let db = reopen(&root)?;
        assert_managed_original(&db, generation)?;
        // A second fault after cleanup, immediately before the outer COMMIT,
        // must also restore the original reference/placeholder/lookup together.
        let rolled_back: Result<(), StorageError> = db.write_transaction(|| {
            db.retire_transport_object("wire", "manifest")?;
            assert_retired(&db, "private-canary")?;
            Err(StorageError::AuthorizationRejected)
        });
        assert!(matches!(rolled_back, Err(StorageError::AuthorizationRejected)));
        drop(db);
        let db = reopen(&root)?;
        assert_managed_original(&db, generation)?;
        db.retire_transport_object("wire", "manifest")?;
        return finish_transport(db, &root);
    }
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e3_direct_transport_retirement() -> Result<(), StorageError> {
    transport(false, false, false)
}
#[test]
fn e3_hold_child_retires_referenced_transport_parent() -> Result<(), StorageError> {
    transport(true, false, false)
}
#[test]
fn e3_two_hop_ancestor_chain() -> Result<(), StorageError> {
    transport(false, true, false)
}
#[test]
fn e3_message_seeded_chain() -> Result<(), StorageError> {
    transport(false, false, true)
}

#[test]
fn e4_replacement_captures_injected_legacy_ownerless_alias() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-replacement")?;
    register(&db, "private-canary", "m1", "historical-ref")?;
    super::tests::payload(&db)?;
    placeholder(&db, "private-canary")?;
    // Inject historical state that compliant registration/erasure cannot create.
    // Keep the reference and its actors, but remove every active owner so the
    // public replacement eligibility guard remains authoritative.
    db.connection.execute("DELETE FROM object_message_reference", [])?;
    let owners: i64 = db.connection.query_row(
        "SELECT owner_count FROM object_retention_payload WHERE wire_id='wire'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(owners, 0);
    let ciphertext = b"replacement-ciphertext";
    let manifest =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, ciphertext);
    db.replace_object(
        Some("manifest"),
        &crate::ObjectWrite {
            object_id: "wire",
            manifest_hash: &manifest,
            nonce: "nonce",
            ciphertext,
            plaintext_hash: "new-plaintext",
            tombstoned: false,
            backup_excluded: false,
            content_key: Some(&[9; 32]),
            object: &json!({"replacement":true}),
            updated_at: 2,
        },
    )?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    assert!(matches!(
        db.check_object_identity("wire", "manifest"),
        Err(StorageError::ObjectErased)
    ));
    db.check_object_identity("wire", &manifest)?;
    db.check_object_access("wire")?;
    assert_eq!(
        db.load_object::<Value>("wire")?,
        Some((json!({"replacement":true}), Some([9; 32])))
    );
    let receipt: bool = db.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_identity_replacement WHERE commitment=?1)",
        params![object_erasure_commitment(db.object_erasure_root(), "wire", &manifest)],
        |r| r.get(0),
    )?;
    assert!(receipt);
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e4_legacy_maintenance_direct_guard_and_retiring_ancestor() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-maintenance")?;
    register(&db, "private-canary", "m1", "parent-ref")?;
    db.retain_object("wire", "manifest", ObjectRetention::OwnDeviceTransport)?;
    placeholder(&db, "private-canary")?;
    // The direct expired transport stays protected by its reference/veto.
    db.connection.execute("UPDATE object_retention_payload SET hold_expires_at=0", [])?;
    db.maintain_expired_object_holds()?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    assert_eq!(db.object_erasure_generation()?, 0);
    // An eligible unreferenced child reaches that same parent through closure
    // expansion. The direct-candidate guard must not suppress ancestor capture.
    let child = db.pre_send_object_hold("child", "child-manifest")?;
    db.retain_transport_dependency("wire", "manifest", "child", "child-manifest")?;
    db.connection.execute(
        "UPDATE object_retention_payload SET hold_expires_at=0 WHERE wire_id='child'",
        [],
    )?;
    let (class, owners): (String, i64) = db.connection.query_row(
        "SELECT retention_class,owner_count FROM object_retention_payload WHERE wire_id='child'",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!((class.as_str(), owners), ("pre_send", 0));
    db.maintain_expired_object_holds()?;
    drop(child);
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_managed_original(db: &AccountDb, generation: i64) -> Result<(), StorageError> {
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    assert!(!db.message_is_deleted("m1")?);
    assert_eq!(db.privacy_erasure_generation()?, generation);
    for table in ["object_retention_reference", "object_message_reference"] {
        let count: i64 =
            db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        assert_eq!(count, 1, "original graph lost in {table}");
    }
    let lookups: i64 =
        db.connection.query_row("SELECT count(*) FROM object_erasure_lookup", [], |r| r.get(0))?;
    assert_eq!(lookups, 0);
    for table in
        ["object_erasure_work", "object_reference_erasure_work", "object_projection_erasure_work"]
    {
        let count: i64 =
            db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        assert_eq!(count, 0, "uncommitted work survived in {table}");
    }
    Ok(())
}

#[test]
fn e1_message_delete_cut_before_commit_rolls_back() -> Result<(), StorageError> {
    const CHILD_ROOT: &str = "RAMFLUX_TEST_SELECTOR_DELETE_ABORT_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = std::path::PathBuf::from(root);
        let db = reopen(&root)?;
        let marker = root.join("capture-cut-reached");
        db.connection.call(move |raw| {
            raw.update_hook(Some(move |action, _database: &str, table: &str, _row| {
                if action == rusqlite::hooks::Action::SQLITE_INSERT
                    && table == "object_reference_erasure_work"
                {
                    // Exit without unwinding or dropping the writer connection.
                    // The marker distinguishes the intended cut from a child failure.
                    assert!(std::fs::write(&marker, b"captured").is_ok());
                    std::process::abort();
                }
            }))?;
            Ok(())
        })?;
        db.delete_direct_message("thread", "m1", "local", "delete")?;
        return Err(StorageError::AuthorizationRejected);
    }
    let (root, db) = crate::tests::test_db("selector-delete-cut")?;
    register(&db, "private-canary", "m1", "ref")?;
    placeholder(&db, "private-canary")?;
    let generation = db.privacy_erasure_generation()?;
    // SQL fault at the same capture boundary: writer returns Err, then reopen.
    db.connection.execute_batch("CREATE TEMP TRIGGER fail_selector_capture AFTER INSERT ON main.object_reference_erasure_work BEGIN SELECT RAISE(ABORT,'selector capture cut'); END;")?;
    let Err(error) = db.delete_direct_message("thread", "m1", "local", "delete") else {
        return Err(StorageError::AuthorizationRejected);
    };
    assert!(error.to_string().contains("selector capture cut"));
    drop(db);
    let db = reopen(&root)?;
    assert_managed_original(&db, generation)?;
    drop(db);
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "account_db::object_retention::selector_lifecycle_tests::e1_message_delete_cut_before_commit_rolls_back", "--nocapture"])
        .env(CHILD_ROOT, &root).status()?;
    assert!(!status.success(), "child committed despite abort hook");
    assert_eq!(std::fs::read(root.join("capture-cut-reached"))?, b"captured");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(status.signal(), Some(6), "child must terminate via SIGABRT");
    }
    let db = reopen(&root)?;
    assert_managed_original(&db, generation)?;
    db.delete_direct_message("thread", "m1", "local", "delete")?;
    assert_retired(&db, "private-canary")?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn finish_transport(db: AccountDb, root: &std::path::Path) -> Result<(), StorageError> {
    drop(db);
    let db = reopen(root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn selector_projection_outbox_drain_budget() -> Result<(), StorageError> {
    let mut baseline = None;
    for unrelated in [0, 1_000, 10_000] {
        let (root, db) = crate::tests::test_db("selector-outbox-budget")?;
        db.write_transaction(|| -> Result<(), StorageError> {
            db.connection.execute("INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json) WITH RECURSIVE n(i) AS (SELECT 1 WHERE ?1>0 UNION ALL SELECT i+1 FROM n WHERE i<?1) SELECT 'object_index','delete',i,json_object('object_id','unrelated-'||i) FROM n", params![unrelated])?;
            db.connection.execute("INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json) VALUES('object_index','delete',-1,json_object('object_id','private-canary'))", [])?;
            db.connection.execute("INSERT INTO object_projection_erasure_work VALUES('private-canary')", [])?;
            Ok(())
        })?;
        let steps = db.connection.call(|raw| {
            let steps = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let counter = Arc::clone(&steps);
            raw.progress_handler(
                1,
                Some(move || {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    false
                }),
            )?;
            let outcome = raw.execute_batch(super::selector_erasure::DRAIN);
            raw.progress_handler(0, None::<fn() -> bool>)?;
            outcome?;
            Ok(steps.load(std::sync::atomic::Ordering::Relaxed))
        })?;
        let base = *baseline.get_or_insert(steps);
        let ceiling = (base * 105).div_ceil(100) + 64;
        assert!(
            steps <= ceiling,
            "outbox drain scales with unrelated rows: N={unrelated}, steps={steps}, base={base}, ceiling={ceiling}"
        );
        let remaining: i64 = db.connection.query_row(
            "SELECT count(*) FROM runtime_outbox WHERE table_name='object_index'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(remaining, unrelated);
        db.connection.execute("DELETE FROM object_projection_erasure_work", [])?;
        drop(db);
        let db = reopen(&root)?;
        verify_snapshot(&db, &root)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn upgraded_zero_placeholder(survivor: bool) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-v12-zero")?;
    register(&db, "wire", "other-message", "wire-ref")?;
    register(&db, "private-canary", "m1", "r1")?;
    if survivor {
        register(&db, "private-canary", "m2", "r2")?;
    }
    placeholder(&db, "private-canary")?;
    super::selector_upgrade_tests::v12_fixture(&db)?;
    // The payload-free v12 placeholder shape, including both zero manifests.
    db.connection.execute("UPDATE object_index SET manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32) WHERE object_id='private-canary'", [])?;
    drop(db);
    let db = reopen(&root)?;
    let before: Vec<u8> = db.connection.query_row(
        "SELECT manifest_hash FROM object_index WHERE object_id='private-canary'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(before, vec![0; 32], "upgrade must not scrub untouched rows");
    db.delete_direct_message("thread", "m1", "local", "delete-first")?;
    if survivor {
        let (manifest, chunks): (Vec<u8>, Vec<u8>) = db.connection.query_row("SELECT manifest_hash,chunk_manifest_hash FROM object_index WHERE object_id='private-canary'", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!(manifest, b"manifest");
        assert_eq!(chunks, b"manifest");
        db.check_object_access("private-canary")?;
        db.delete_direct_message("thread", "m2", "local", "delete-second")?;
    }
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    db.check_object_access("wire")?;
    assert_eq!(db.object_erasure_generation()?, 0, "wire owner keeps payload alive");
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e1_v12_zero_placeholder_retired_with_last_reference_after_upgrade() -> Result<(), StorageError> {
    upgraded_zero_placeholder(false)
}
#[test]
fn e1_v12_zero_placeholder_survivor_normalized_then_deleted() -> Result<(), StorageError> {
    upgraded_zero_placeholder(true)
}
