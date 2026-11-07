// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Tombstone store: exact tuple, bounded lifetime, bounded sweep, minimal columns, bundle guard.
#![allow(clippy::expect_used, clippy::panic)]
use super::erased_input::ErasedTuple;
use crate::{AccountDb, StorageError};
use rusqlite::params;

fn envelope(device: &str, key: &str, hash: &str) -> ramflux_protocol::Envelope {
    serde_json::from_value(serde_json::json!({
        "schema":"test","version":1,"domain":"test","signing_key_id":key,"signature_alg":"ed25519",
        "signature":"sig","envelope_id":"env","source_principal_id":"source-principal",
        "source_device_id":device,"target_delivery_id":"t","delivery_class":"opaque_event",
        "priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":hash
    }))
    .expect("envelope fixture")
}

fn record(db: &AccountDb, e: &ramflux_protocol::Envelope, created: i64, ttl: u64) {
    db.record_erased_input(&ErasedTuple::from_envelope(e), created, ttl).expect("record");
}

fn count(db: &AccountDb, sql: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(sql, [], |row| row.get(0))?)
}

fn reopen(root: &std::path::Path, db: AccountDb) -> Result<AccountDb, StorageError> {
    drop(db);
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn abort_message(result: Result<usize, rusqlite::Error>) -> Option<String> {
    match result {
        Err(rusqlite::Error::SqliteFailure(_, message)) => message,
        _ => None,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one named test carries all seven cells
fn erased_input_store_bounds_and_retirement() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("erased-input-store")?;
    let now = crate::unix_now();
    let base = envelope("device", "key", "hash");
    // (a) The exact tuple matches; another device, key or payload does not.
    record(&db, &base, now, 60);
    assert!(db.erased_input_matches(&base)?);
    for other in [
        envelope("other-device", "key", "hash"),
        envelope("device", "other-key", "hash"),
        envelope("device", "key", "other-hash"),
    ] {
        assert!(!db.erased_input_matches(&other)?);
    }
    // (b) Lifetime is clamped; an already-expired input writes no row.
    let before = count(&db, "SELECT count(*) FROM receive_erased_input")?;
    let clamped = envelope("device", "key", "clamped");
    record(&db, &clamped, now + 1_000_000, 10_000_000);
    let written = crate::unix_now();
    let longest = count(&db, "SELECT max(expires_at) FROM receive_erased_input")?;
    assert!(longest <= written + 605_220, "expires {longest} beyond the clamp");
    assert!(longest > now + 600_000);
    record(&db, &envelope("device", "key", "stale"), now - 1_000_000, 10);
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, before + 1);
    // (c) 100 expired rows plus one write delete exactly 64 of them.
    db.connection.execute_batch("BEGIN")?;
    for n in 0..100 {
        db.connection.execute(
            "INSERT INTO receive_erased_input VALUES(?1,'old-bundle',1)",
            params![format!("expired-{n:03}")],
        )?;
    }
    db.connection.execute_batch("COMMIT")?;
    record(&db, &envelope("device", "key", "sweeper"), now, 60);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM receive_erased_input WHERE expires_at<=?1"
                .replace("?1", &now.to_string())
                .as_str()
        )?,
        36
    );
    // (d) A duplicate keeps the maximum expiry.
    let window = format!(
        "SELECT max(expires_at) FROM receive_erased_input WHERE expires_at<{}",
        now + 100_000
    );
    let dup = envelope("device", "key", "dup");
    record(&db, &dup, now, 600);
    let first = count(&db, &window)?;
    record(&db, &dup, now, 10);
    assert_eq!(count(&db, &window)?, first);
    record(&db, &dup, now, 6_000);
    assert!(count(&db, &window)? > first);
    // (e) Exact columns, and no plaintext identity strings anywhere in the table.
    let mut columns =
        db.connection.prepare("SELECT name FROM pragma_table_info('receive_erased_input')")?;
    let names: Vec<String> = columns.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    assert_eq!(names, vec!["selector", "bundle_id", "expires_at"]);
    drop(columns);
    for forbidden in ["source-principal", "device", "key", "hash", "cipher"] {
        let hits = count(
            &db,
            &format!(
                "SELECT count(*) FROM receive_erased_input WHERE bundle_id<>'old-bundle' AND (selector LIKE '%{forbidden}%' OR bundle_id LIKE '%{forbidden}%')"
            ),
        )?;
        assert_eq!(hits, 0, "{forbidden}");
    }
    // (f) Retirement: a live row blocks deleting its bundle; once expired, deletion is allowed.
    db.connection.execute("DELETE FROM receive_erased_input WHERE bundle_id='old-bundle'", [])?;
    let bundle: String =
        db.connection.query_row("SELECT bundle_id FROM account_mac_bundle", [], |r| r.get(0))?;
    let blocked = db
        .connection
        .execute("DELETE FROM account_mac_bundle WHERE bundle_id=?1", params![&bundle]);
    assert_eq!(
        abort_message(blocked).as_deref(),
        Some("mac bundle retains erased-input authority")
    );
    db.connection.execute("UPDATE receive_erased_input SET expires_at=1", [])?;
    // A live binding (i) blocks the same way.
    let live_binding = format!("erased-input:{bundle}:selector:{}", crate::unix_now() + 1_000);
    db.connection
        .execute("INSERT INTO message_copy_binding VALUES(?1,'M')", params![&live_binding])?;
    let blocked = db
        .connection
        .execute("DELETE FROM account_mac_bundle WHERE bundle_id=?1", params![&bundle]);
    assert_eq!(
        abort_message(blocked).as_deref(),
        Some("mac bundle retains erased-input authority")
    );
    db.connection.execute(
        "UPDATE message_copy_binding SET copy_id=?1 WHERE copy_id=?2",
        params![format!("erased-input:{bundle}:selector:1"), &live_binding],
    )?;
    // With the row and the binding both expired, retirement is allowed (rolled back here).
    db.connection.execute_batch("BEGIN")?;
    let allowed = db
        .connection
        .execute("DELETE FROM account_mac_bundle WHERE bundle_id=?1", params![&bundle]);
    db.connection.execute_batch("ROLLBACK")?;
    assert_eq!(allowed?, 1);
    // (g) Reopen keeps (a) while the row is live; restore it first.
    db.connection
        .execute("DELETE FROM message_copy_binding WHERE copy_id GLOB 'erased-input:*'", [])?;
    record(&db, &base, now, 60);
    let db = reopen(&root, db)?;
    assert!(db.erased_input_matches(&base)?);
    assert!(!db.erased_input_matches(&envelope("other-device", "key", "hash"))?);
    // Deletion is now allowed only after expiry, on the reopened database too.
    let blocked = db
        .connection
        .execute("DELETE FROM account_mac_bundle WHERE bundle_id=?1", params![&bundle]);
    assert_eq!(
        abort_message(blocked).as_deref(),
        Some("mac bundle retains erased-input authority")
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn tuple_of(e: &ramflux_protocol::Envelope) -> ErasedTuple<'_> {
    ErasedTuple::from_envelope(e)
}

fn only_expiry(db: &AccountDb) -> Result<i64, StorageError> {
    count(db, "SELECT max(expires_at) FROM receive_erased_input")
}

#[test]
fn erased_input_lifetime_boundaries_are_exact() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("erased-input-lifetime")?;
    let now = 1_000_000_i64;
    let e = envelope("device", "key", "hash");
    let write = |created: i64, ttl: u64| -> Result<i64, StorageError> {
        db.connection.execute("DELETE FROM receive_erased_input", [])?;
        db.record_erased_input_at(&tuple_of(&e), created, ttl, now)?;
        only_expiry(&db)
    };
    // Ordinary input: created_at + ttl + 300 slack.
    assert_eq!(write(now - 10, 60)?, now - 10 + 60 + 300);
    // Skew cap, inclusive: created_at = now + 120 is kept, now + 121 is clamped to it.
    assert_eq!(write(now + 120, 60)?, now + 120 + 60 + 300);
    assert_eq!(write(now + 121, 60)?, now + 120 + 60 + 300);
    assert_eq!(write(now + 5_000, 60)?, now + 120 + 60 + 300);
    // TTL cap, inclusive: 604,800 is kept, 604,801 is clamped to it.
    assert_eq!(write(now, 604_800)?, now + 604_800 + 300);
    assert_eq!(write(now, 604_801)?, now + 604_800 + 300);
    // Both caps together stay at the documented worst case.
    assert_eq!(write(now + 9_000, u64::MAX)?, now + 120 + 604_800 + 300);
    // expires_at == now writes nothing; now + 1 is written.
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 1);
    db.connection.execute("DELETE FROM receive_erased_input", [])?;
    db.record_erased_input_at(&tuple_of(&e), now - 300, 0, now)?;
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 0);
    db.record_erased_input_at(&tuple_of(&e), now - 299, 0, now)?;
    assert_eq!(only_expiry(&db)?, now + 1);
    // The stored row expires at now + 1: it matches at now and is expired at now + 1.
    assert!(db.erased_input_matches_at(&e, now)?);
    assert!(!db.erased_input_matches_at(&e, now + 1)?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn add_retired_bundle(db: &AccountDb) -> Result<String, StorageError> {
    use sha2::Digest;
    let keys = [7_u8; 192];
    let mut hash = sha2::Sha256::new();
    hash.update(b"ramflux.account-mac-bundle.v1");
    hash.update(keys);
    let id = ramflux_protocol::encode_base64url(hash.finalize());
    db.connection.execute(
        "INSERT INTO account_mac_bundle(bundle_id,subkeys,is_current) VALUES(?1,?2,0)",
        params![&id, keys.as_slice()],
    )?;
    Ok(id)
}

#[test]
fn erased_input_matcher_authority_is_exact() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("erased-input-matcher")?;
    let now = crate::unix_now();
    let retired = add_retired_bundle(&db)?;
    let base = envelope("device", "key", "hash");
    db.record_erased_input_at(&tuple_of(&base), now, 60, now)?;
    // One row per retained bundle.
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 2);
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM receive_erased_input WHERE bundle_id=?1",
            params![&retired],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    // The principal is part of the authenticated tuple.
    let mut other_principal = base.clone();
    other_principal.source_principal_id = "another-principal".into();
    assert!(db.erased_input_matches_at(&base, now)?);
    assert!(!db.erased_input_matches_at(&other_principal, now)?);
    // An expired stored row never matches.
    db.connection.execute("UPDATE receive_erased_input SET expires_at=?1", params![now - 1])?;
    assert!(!db.erased_input_matches_at(&base, now)?);
    db.connection.execute("UPDATE receive_erased_input SET expires_at=?1", params![now + 100])?;
    assert!(db.erased_input_matches_at(&base, now)?);
    // Authority held only under a non-current retained bundle still matches.
    db.connection
        .execute("DELETE FROM receive_erased_input WHERE bundle_id<>?1", params![&retired])?;
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 1);
    assert!(db.erased_input_matches_at(&base, now)?);
    // ...and the same row for a different tuple does not.
    assert!(!db.erased_input_matches_at(&envelope("device", "key", "other"), now)?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
