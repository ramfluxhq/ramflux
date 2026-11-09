// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Annex F crash cuts for writers that exist on main. Drop+reopen is the process-kill.

use super::super::recovery::{Admission, RecoveredOutcome};
use super::helpers::{
    TestResult, acknowledged_head, adoption, floor, h, head, live_phase, submitted_head, terminal,
};
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError};
use std::path::{Path, PathBuf};

fn reopen(root: &Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn recover_after(
    root: PathBuf,
    db: AccountDb,
) -> Result<(PathBuf, Recovered), Box<dyn std::error::Error>> {
    drop(db);
    let db = reopen(&root)?;
    let recovered = db.recover_pairing()?;
    Ok((root, Recovered { db, recovered }))
}

struct Recovered {
    db: AccountDb,
    recovered: super::super::recovery::RecoveredPairing,
}

fn seed_floor_live(name: &str, phase: &str) -> TestResult<(std::path::PathBuf, AccountDb)> {
    let (root, db) = crate::tests::test_db(name)?;
    db.put_pairing_floor(&floor())?;
    db.put_pairing_live(&live_phase(phase)?)?;
    Ok((root, db))
}

pub(super) fn missing_writers_named() {
    let missing = AccountDb::pairing_missing_crash_writers();
    assert!(missing.iter().any(|row| row.0.contains("J0 AccountIndex")));
    assert!(missing.iter().any(|row| row.0.contains("J1 vault")));
    assert!(missing.iter().any(|row| row.0.contains("J5 node")));
    assert!(missing.iter().any(|row| row.0.contains("J7b authority.json")));
    assert!(missing.iter().any(|row| row.0.contains("J8 vault")));
}

pub(super) fn j1_before_and_after_floor_live() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04j-j1-before")?;
    let (root, recovered) = recover_after(root, db)?;
    assert!(matches!(recovered.recovered.outcome, RecoveredOutcome::Empty));
    assert_eq!(recovered.recovered.admission, Admission::Closed);
    assert!(recovered.recovered.floor.is_none());
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j1-after", "invited")?;
    let (root, recovered) = recover_after(root, db)?;
    match recovered.recovered.outcome {
        RecoveredOutcome::HandshakeCancelled { operation_id } => assert_eq!(operation_id, h(20)),
        other => return Err(format!("j1 after: {other:?}").into()),
    }
    assert_eq!(recovered.recovered.live.len(), 0);
    assert_eq!(recovered.recovered.floor.as_ref().ok_or("floor")?.issued_seq, 3);
    assert_eq!(recovered.recovered.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn j2_live_phase_cancels_without_head() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-j2-before", "invited")?;
    let (root, recovered) = recover_after(root, db)?;
    assert!(matches!(recovered.recovered.outcome, RecoveredOutcome::HandshakeCancelled { .. }));
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j2-after", "proposal_pending")?;
    let (root, recovered) = recover_after(root, db)?;
    match recovered.recovered.outcome {
        RecoveredOutcome::HandshakeCancelled { .. } => {}
        other => return Err(format!("j2 after: {other:?}").into()),
    }
    assert!(recovered.recovered.head.is_none());
    assert_eq!(recovered.recovered.live.len(), 0);
    assert_eq!(recovered.recovered.floor.as_ref().ok_or("floor")?.issued_seq, 3);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn j3_prepared_head_fences_same_hash() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-j3-before", "proposal_pending")?;
    let (root, recovered) = recover_after(root, db)?;
    assert!(matches!(recovered.recovered.outcome, RecoveredOutcome::HandshakeCancelled { .. }));
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j3-after", "prepared")?;
    let prepared = head()?;
    let hash = prepared.candidate_hash.clone();
    db.put_pairing_head(&prepared)?;
    let (root, recovered) = recover_after(root, db)?;
    match &recovered.recovered.outcome {
        RecoveredOutcome::CandidateFenced { candidate_hash, head_state, .. } => {
            assert_eq!(candidate_hash, &hash);
            assert_eq!(head_state, "prepared");
        }
        other => return Err(format!("j3 after: {other:?}").into()),
    }
    assert_eq!(recovered.recovered.head.as_ref().ok_or("head")?.candidate_hash, hash);
    assert_eq!(recovered.recovered.live.len(), 1);
    assert_eq!(recovered.recovered.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn j4_submitted_never_cancelled() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-j4-before", "prepared")?;
    db.put_pairing_head(&head()?)?;
    let (root, recovered) = recover_after(root, db)?;
    match &recovered.recovered.outcome {
        RecoveredOutcome::CandidateFenced { head_state, .. } => assert_eq!(head_state, "prepared"),
        other => return Err(format!("j4 before: {other:?}").into()),
    }
    assert_eq!(recovered.recovered.live.len(), 1);
    assert!(!recovered.recovered.terminals.iter().any(|row| row.outcome == "cancelled"));
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j4-after", "submitted")?;
    let submitted = submitted_head()?;
    let hash = submitted.candidate_hash.clone();
    db.put_pairing_head(&submitted)?;
    let (root, recovered) = recover_after(root, db)?;
    match &recovered.recovered.outcome {
        RecoveredOutcome::CandidateFenced { candidate_hash, head_state, .. } => {
            assert_eq!(candidate_hash, &hash);
            assert_eq!(head_state, "submitted");
        }
        other => return Err(format!("j4 after: {other:?}").into()),
    }
    assert!(!matches!(recovered.recovered.outcome, RecoveredOutcome::HandshakeCancelled { .. }));
    assert_eq!(recovered.recovered.head.as_ref().ok_or("head")?.candidate_hash, hash);
    assert_eq!(recovered.recovered.live.len(), 1);
    assert!(!recovered.recovered.terminals.iter().any(|row| row.outcome == "cancelled"));
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn j6_acknowledged_same_hash() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-j6-before", "submitted")?;
    db.put_pairing_head(&submitted_head()?)?;
    let (root, recovered) = recover_after(root, db)?;
    match &recovered.recovered.outcome {
        RecoveredOutcome::CandidateFenced { head_state, .. } => assert_eq!(head_state, "submitted"),
        other => return Err(format!("j6 before: {other:?}").into()),
    }
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j6-after", "acknowledged")?;
    let acked = acknowledged_head()?;
    let hash = acked.candidate_hash.clone();
    db.put_pairing_head(&acked)?;
    let (root, recovered) = recover_after(root, db)?;
    match &recovered.recovered.outcome {
        RecoveredOutcome::CandidateFenced { candidate_hash, head_state, .. } => {
            assert_eq!(candidate_hash, &hash);
            assert_eq!(head_state, "acknowledged");
        }
        other => return Err(format!("j6 after: {other:?}").into()),
    }
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn j7c_adoption_stays_fenced() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-j7c-before", "acknowledged")?;
    db.put_pairing_head(&acknowledged_head()?)?;
    let (root, recovered) = recover_after(root, db)?;
    assert!(recovered.db.pairing_adoption()?.is_none());
    assert_eq!(recovered.recovered.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j7c-after", "locally_installed")?;
    let acked = acknowledged_head()?;
    let hash = acked.candidate_hash.clone();
    db.put_pairing_head(&acked)?;
    db.put_pairing_adoption(&adoption("secondary", None)?)?;
    let (root, recovered) = recover_after(root, db)?;
    match &recovered.recovered.outcome {
        RecoveredOutcome::CandidateFenced { candidate_hash, .. } => {
            assert_eq!(candidate_hash, &hash);
        }
        other => return Err(format!("j7c after: {other:?}").into()),
    }
    assert!(recovered.db.pairing_adoption()?.is_some());
    assert_eq!(recovered.recovered.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn j8_terminal_cleanup_deletes_head() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-j8-before", "locally_installed")?;
    db.put_pairing_head(&acknowledged_head()?)?;
    db.put_pairing_adoption(&adoption("secondary", None)?)?;
    let (root, recovered) = recover_after(root, db)?;
    assert!(recovered.recovered.head.is_some());
    let _ = std::fs::remove_dir_all(root);

    let (root, db) = seed_floor_live("pair04j-j8-after", "locally_installed")?;
    db.put_pairing_head(&acknowledged_head()?)?;
    db.put_pairing_adoption(&adoption("secondary", None)?)?;
    db.commit_pairing_terminal_cleanup(&terminal())?;
    let (root, recovered) = recover_after(root, db)?;
    assert!(recovered.recovered.head.is_none());
    assert_eq!(recovered.recovered.live.len(), 0);
    assert_eq!(recovered.recovered.terminals[0].outcome, "completed");
    assert_eq!(recovered.recovered.floor.as_ref().ok_or("floor")?.issued_seq, 3);
    let _ = std::fs::remove_dir_all(root);
    let (root, db) = seed_floor_live("pair04j-j8-submitted", "submitted")?;
    db.put_pairing_head(&submitted_head()?)?;
    let error = db.commit_pairing_terminal_cleanup(&terminal());
    assert!(matches!(error, Err(StorageError::PairingField("state"))), "submitted head: {error:?}");
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn backup_mid_ceremony_strips_live_keeps_floor() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-backup", "submitted")?;
    db.put_pairing_head(&submitted_head()?)?;
    db.put_pairing_terminal(&terminal())?;
    db.put_pairing_adoption(&adoption("secondary", None)?)?;
    let archive = root.join("archive.db");
    let snapshot = db.write_backup_snapshot(&archive)?;
    let opened = rusqlite::Connection::open(&archive)?;
    opened.execute_batch(&format!("PRAGMA key = \"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
    for table in ["pairing_live", "pairing_head", "pairing_terminal", "pairing_adoption"] {
        let n: i64 =
            opened.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(n, 0, "{table} restored");
    }
    let issued: i64 = opened.query_row(
        "SELECT issued_seq FROM pairing_floor WHERE account_id='acct'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(issued, 3);
    let (fresh_root, fresh) = crate::tests::test_db("pair04j-backup-fresh")?;
    let mut low = floor();
    low.issued_seq = 1;
    low.next_generation = 1;
    fresh.put_pairing_floor(&low)?;
    let target_path = fresh_root.join("target.db");
    let target_snap = fresh.write_backup_snapshot(&target_path)?;
    let mut restored = BackupDatabase::open(&target_path, &target_snap.key)?;
    restored.merge_backup(&archive, &snapshot.key, || Ok(()))?;
    let live: i64 =
        restored.db.query_row("SELECT count(*) FROM pairing_live", [], |row| row.get(0))?;
    assert_eq!(live, 0);
    let merged: i64 = restored.db.query_row(
        "SELECT issued_seq FROM pairing_floor WHERE account_id='acct'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(merged, 3);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fresh_root);
    Ok(())
}

pub(super) fn recover_does_not_change_candidate() -> TestResult {
    let (root, db) = seed_floor_live("pair04j-hash", "submitted")?;
    let submitted = submitted_head()?;
    let hash = submitted.candidate_hash.clone();
    db.put_pairing_head(&submitted)?;
    let (root, recovered) = recover_after(root, db)?;
    let stored = recovered.db.pairing_head()?.ok_or("head")?;
    assert_eq!(stored.candidate_hash, hash);
    let again = recovered.db.recover_pairing()?;
    assert_eq!(again.head.ok_or("head")?.candidate_hash, hash);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}
