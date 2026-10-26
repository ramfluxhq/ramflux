// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing floor encodings, bounded expiry eviction and explicit consent-preserving cleanup.
use super::*;
use crate::{AccountDbKey, AccountIndex, ContactRequestRecord};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn legacy_floor_rows_reopen_unchanged_and_oldest_expired_slots_are_reused() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "floor-expiry-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "root")?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "a", &key)?;
    db.connection.execute_batch("INSERT INTO contact_request_authority_floor VALUES('oldest',7,'oldest-hash',98),('later',8,'later-hash',99),('keep',9,'kept-hash',9999); WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4093) INSERT INTO contact_request_authority_floor SELECT 'live-'||x,1,'hash',9999 FROM n;")?;
    drop(db);
    let db = AccountDb::open(&index, "a", &key)?;
    assert_eq!(db.contact_request_authority_floor("keep", 100)?, Some((9, "kept-hash".into())));
    assert_eq!(db.contact_request_authority_floor_usage(100)?, (4094, 4094));
    assert!(db.retain_contact_request_authority_floor("new", 2, "new-hash", 9999, 100)?);
    let exists = |name: &str| -> Result<bool, StorageError> {
        Ok(db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM contact_request_authority_floor WHERE root=?1)",
            params![name],
            |row| row.get(0),
        )?)
    };
    assert!(!exists("oldest")?);
    assert!(exists("later")?, "only the oldest required expired slot is evicted");
    assert!(db.retain_contact_request_authority_floor("next", 3, "next-hash", 9999, 100)?);
    assert!(!exists("later")?);
    assert!(!db.retain_contact_request_authority_floor("full", 4, "full-hash", 9999, 100)?);
    assert_eq!(db.contact_request_authority_floor("keep", 100)?, Some((9, "kept-hash".into())));
    assert_eq!(db.contact_request_authority_floor_usage(100)?, (4096, 4096));
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn clearing_retired_floors_preserves_pending_authority_and_consent_fences() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "floor-clear-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "root")?;
    let db = AccountDb::open(&index, "a", &AccountDbKey::generate()?)?;
    for (name, direction) in [("pending-in", "inbound"), ("pending-out", "outbound")] {
        db.persist_contact_request(&ContactRequestRecord {
            contact_identity_commitment: name.into(),
            direction: direction.into(),
            request_id: name.into(),
            principal_id: name.into(),
            link_id: name.into(),
            state: "pending".into(),
            request_json: b"{}".to_vec(),
            expires_at: 9999,
            updated_at: 1,
        })?;
    }
    for name in ["pending-in", "pending-out", "blocked", "declined"] {
        assert!(db.retain_contact_request_authority_floor(name, 1, "hash", 9999, 100)?);
    }
    db.fence_contact_request("blocked", "blocked", 0)?;
    db.fence_contact_request("declined", "declined", 9999)?;
    let blocked = db.retained_contact_request_fence("blocked")?;
    let declined = db.retained_contact_request_fence("declined")?;
    assert_eq!(db.contact_request_authority_floor_usage(100)?, (4, 2));
    assert_eq!(db.clear_retired_contact_request_authority_floors(100)?, 2);
    assert_eq!(db.contact_request_authority_floor_usage(100)?, (2, 0));
    assert!(db.contact_request_authority_floor("pending-in", 100)?.is_some());
    assert!(db.contact_request_authority_floor("pending-out", 100)?.is_some());
    assert_eq!(db.retained_contact_request_fence("blocked")?, blocked);
    assert_eq!(db.retained_contact_request_fence("declined")?, declined);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
