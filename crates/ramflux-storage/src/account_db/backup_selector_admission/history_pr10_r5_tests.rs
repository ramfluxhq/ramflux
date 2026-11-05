// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Veto erasure, typed witness failures, and exact target-backed self-backup admission.
use super::*;

fn count(db: &rusqlite::Connection, sql: &str) -> rusqlite::Result<u64> {
    db.query_row(sql, [], |r| r.get(0))
}

fn legacy_shape(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message("thread", "message", "peer", b"body")?;
    db.persist_actor_state(
        "attachment/reference/private-canary",
        &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
    )?;
    db.persist_client_record(
        "object",
        "private-canary",
        &json!({"owner":"peer","message_id":"message","manifest_hash":"manifest"}),
    )?;
    Ok(())
}

type Shape = (u64, u64, u64, u64);
fn restriction(db: &rusqlite::Connection) -> rusqlite::Result<Shape> {
    Ok((
        count(
            db,
            "SELECT count(*) FROM object_index WHERE object_id='private-canary' AND tombstoned=1",
        )?,
        count(db, "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'")?,
        count(
            db,
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary'",
        )?,
        count(
            db,
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'",
        )?,
    ))
}

#[derive(Debug)]
enum Outcome {
    Kept(Shape),
    Omitted(Shape),
    Refused { unchanged: bool },
}

// Build the revoked side as a file. `rows`: both | footprint | binding. `actor`: keep it?
// `fresh`: run the single-input normalizer (what a restored device holds).
fn revoked_archive(
    db: &AccountDb,
    path: &std::path::Path,
    rows: &str,
    actor: bool,
    fresh: bool,
) -> Result<crate::AccountBackupSnapshot, Box<dyn std::error::Error>> {
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    if !actor {
        db.remove_actor_state("attachment/reference/private-canary")?;
    }
    let saved = db.write_backup_snapshot(path)?;
    let edit =
        BackupDatabase::open_restore_input(path, &saved.key, BackupOpenMode::PreNormalization)?;
    if rows == "footprint" {
        edit.db.execute(
            "DELETE FROM message_copy_binding WHERE copy_id='object:private-canary'",
            [],
        )?;
    }
    if rows == "binding" {
        edit.db.execute("DELETE FROM message_footprint WHERE kind='revocation_selector'", [])?;
    }
    drop(edit);
    if fresh {
        let mut f =
            BackupDatabase::open_restore_input(path, &saved.key, BackupOpenMode::PreNormalization)?;
        f.normalize_backup_candidate()?;
    }
    Ok(saved)
}

fn run_merge(
    target_path: &std::path::Path,
    tkey: &crate::AccountBackupSnapshot,
    input: &std::path::Path,
    ikey: &crate::AccountBackupSnapshot,
    tweak: impl FnOnce(&rusqlite::Connection, &rusqlite::Connection) -> TestResult,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let incoming_fence;
    {
        let t = BackupDatabase::open_restore_input(
            target_path,
            &tkey.key,
            BackupOpenMode::PreNormalization,
        )?;
        let s =
            BackupDatabase::open_restore_input(input, &ikey.key, BackupOpenMode::PreNormalization)?;
        tweak(&t.db, &s.db)?;
        incoming_fence = s.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
            [object_erasure_commitment("principal", "wire", "manifest")],
            |r| r.get(0),
        )?;
    }
    let mut target = BackupDatabase::open_restore_input(
        target_path,
        &tkey.key,
        BackupOpenMode::PreNormalization,
    )?;
    let before = restriction(&target.db)?;
    let input_bytes = std::fs::read(input)?;
    let result = target.merge_backup_candidate(input, &ikey.key, || Ok(()));
    let after = restriction(&target.db)?;
    assert!(std::fs::read(input)? == input_bytes, "merge changed input bytes");
    if result.is_ok() && incoming_fence {
        assert!(
            target.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
                [object_erasure_commitment("principal", "wire", "manifest")],
                |r| r.get::<_, bool>(0)
            )?,
            "incoming fence lost"
        );
    }
    if result.is_ok() && before.0 == 1 && before.1 > 0 && after.0 == 0 {
        assert!(target.db.query_row("SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1) OR EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?2)",params![object_erasure_lookup("principal","private-canary"),object_erasure_commitment("principal","wire","manifest")],|r|r.get::<_,bool>(0))?, "erased selector lost its restriction");
    }
    Ok(match result {
        Ok(_) if after.0 == 1 && after.1 >= 1 => Outcome::Kept(after),
        Ok(_) => Outcome::Omitted(after),
        Err(StorageError::ObjectOwnershipUnverified { .. }) => {
            Outcome::Refused { unchanged: after == before }
        }
        Err(e) => return Err(e.into()),
    })
}

fn cell(
    side: &str,
    rows: &str,
    actor: bool,
    fresh: bool,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db(&format!("p210r4-{side}-{rows}-{actor}-{fresh}"))?;
    legacy_shape(&db)?;
    let old = root.join("old.db");
    let old_key = db.write_backup_snapshot(&old)?;
    let revoked = root.join("revoked.db");
    let rev_key = revoked_archive(&db, &revoked, rows, actor, fresh)?;
    let out = if side == "target" {
        run_merge(&revoked, &rev_key, &old, &old_key, |_, _| Ok(()))?
    } else {
        run_merge(&old, &old_key, &revoked, &rev_key, |_, _| Ok(()))?
    };
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(out)
}

// Check 3: side x rows x actor matrix. Restriction-carrying cells (footprint present)
// must keep or refuse-unchanged; binding-only cells must omit.
#[test]
fn probe_r4_symmetry_matrix() -> TestResult {
    let mut bad = Vec::new();
    for side in ["target", "incoming"] {
        for rows in ["both", "footprint", "binding"] {
            for actor in [true, false] {
                let out = cell(side, rows, actor, false)?;
                eprintln!("MATRIX side={side} rows={rows} actor={actor} -> {out:?}");
                let ok = match (rows, &out) {
                    ("binding", Outcome::Omitted(s)) => s.0 == 0,
                    ("binding", _) => false,
                    (_, Outcome::Kept(_)) => true,
                    (_, Outcome::Refused { unchanged }) => *unchanged,
                    _ => false,
                };
                if !ok {
                    bad.push(format!("{side}/{rows}/{actor}: {out:?}"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "matrix violations: {bad:?}");
    Ok(())
}

// Fresh-restored device merges a later backup of itself: both sides (1,1,1,0).
#[test]
fn probe_r4_fresh_target_merges_own_later_backup() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r4-self")?;
    legacy_shape(&db)?;
    let t = root.join("t.db");
    let tk = revoked_archive(&db, &t, "both", false, true)?;
    for reverse in [false, true] {
        let i = root.join(format!("self-{reverse}.db"));
        BackupDatabase::open(&t, &tk.key)?.copy_to(&i, &tk.key)?;
        let out = if reverse {
            run_merge(&i, &tk, &t, &tk, |_, _| Ok(()))?
        } else {
            run_merge(&t, &tk, &i, &tk, |_, _| Ok(()))?
        };
        assert!(matches!(out, Outcome::Kept((1, 1, 1, 0))), "{out:?}");
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn fresh_target_vs_old(
    name: &str,
    tweak: impl FnOnce(&rusqlite::Connection, &rusqlite::Connection) -> TestResult,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db(name)?;
    legacy_shape(&db)?;
    let old = root.join("old.db");
    let ok = db.write_backup_snapshot(&old)?;
    let t = root.join("t.db");
    let tk = revoked_archive(&db, &t, "both", false, true)?;
    let out = run_merge(&t, &tk, &old, &ok, tweak)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(out)
}

const LOC: &str = "SELECT locator FROM message_footprint WHERE kind='revocation_selector'";

// Check 2a: crafted incoming rows cannot redirect the target witness.
#[test]
fn probe_r4_incoming_forged_footprint_cannot_redirect_target() -> TestResult {
    let out = fresh_target_vs_old("p210r4-forge", |t, s| {
        let loc: String = t.query_row(LOC, [], |r| r.get(0))?;
        let mut v: serde_json::Value = serde_json::from_str(&loc)?;
        v["wire"] = json!("attacker-wire");
        v["commitment"] =
            json!(object_erasure_commitment("principal", "attacker-wire", "manifest"));
        let m: String = t.query_row(
            "SELECT message_id FROM message_footprint WHERE kind='revocation_selector'",
            [],
            |r| r.get(0),
        )?;
        s.execute(
            "INSERT INTO message_footprint VALUES(?1,'revocation_selector',?2)",
            params![m, v.to_string()],
        )?;
        s.execute(
            "INSERT OR IGNORE INTO message_copy_binding VALUES('object:private-canary',?1)",
            [m],
        )?;
        Ok(())
    })?;
    eprintln!("FORGE incoming footprint -> {out:?}");
    assert!(matches!(out, Outcome::Kept(_) | Outcome::Refused { unchanged: true }), "{out:?}");
    Ok(())
}

// Check 2a: an incoming fence on the target commitment is a veto; it must not be
// silently dropped and the target must not lose its restriction.
#[test]
fn probe_r4_incoming_fence_on_target_commitment() -> TestResult {
    let out = fresh_target_vs_old("p210r4-fence", |t, s| {
        let loc: String = t.query_row(LOC, [], |r| r.get(0))?;
        let v: serde_json::Value = serde_json::from_str(&loc)?;
        s.execute(
            "INSERT INTO object_erasure_fence VALUES(?1)",
            [v["commitment"].as_str().ok_or("commitment")?],
        )?;
        Ok(())
    })?;
    eprintln!("FENCE incoming on target commitment -> {out:?}");
    assert!(matches!(out, Outcome::Omitted((0, 0, _, 0))), "{out:?}");
    Ok(())
}

// Check 2b: target footprint locator that fails validation refuses (not omit).
#[test]
fn probe_r4_invalid_target_locator_refuses() -> TestResult {
    for (label, patch) in [
        ("bad-commitment", "json_set(locator,'$.commitment','forged')"),
        ("empty-wire", "json_set(locator,'$.wire','')"),
        ("wrong-manifest", "json_set(locator,'$.manifest','other')"),
        ("int-wire", "json_set(locator,'$.wire',7)"),
        ("no-wire", "json_remove(locator,'$.wire')"),
        ("no-manifest", "json_remove(locator,'$.manifest')"),
        ("int-manifest", "json_set(locator,'$.manifest',7)"),
        ("no-commitment", "json_remove(locator,'$.commitment')"),
        ("int-commitment", "json_set(locator,'$.commitment',7)"),
    ] {
        let sql = format!(
            "UPDATE message_footprint SET locator={patch} WHERE kind='revocation_selector'"
        );
        let out = fresh_target_vs_old(&format!("p210r4-loc-{label}"), move |t, _| {
            t.execute(&sql, [])?;
            Ok(())
        })?;
        eprintln!("LOCATOR {label} -> {out:?}");
        assert!(
            matches!(out, Outcome::Refused { unchanged: true }),
            "{label}: invalid locator must refuse, got {out:?}"
        );
    }
    Ok(())
}

// Check 2b: target footprint whose binding moved to another message (owner mismatch).
#[test]
fn probe_r4_target_binding_owner_mismatch_refuses() -> TestResult {
    let out = fresh_target_vs_old("p210r4-owner", |t, _| {
        t.execute("UPDATE message_copy_binding SET message_id='other' WHERE copy_id='object:private-canary'", [])?;
        Ok(())
    })?;
    eprintln!("OWNER mismatch -> {out:?}");
    assert!(matches!(out, Outcome::Refused { unchanged: true }), "{out:?}");
    Ok(())
}

// Real flow: revoked + then message deleted on the restored device; merge older archive.
#[test]
fn probe_r4_fresh_target_deleted_message_then_merge() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r4-del")?;
    legacy_shape(&db)?;
    let old = root.join("old.db");
    let ok = db.write_backup_snapshot(&old)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    db.remove_actor_state("attachment/reference/private-canary")?;
    db.delete_direct_message("thread", "message", "local", "tomb-1")?;
    let t = root.join("t.db");
    let tk = db.write_backup_snapshot(&t)?;
    {
        let mut f =
            BackupDatabase::open_restore_input(&t, &tk.key, BackupOpenMode::PreNormalization)?;
        f.normalize_backup_candidate()?;
        eprintln!("DELETED target shape after fresh {:?}", restriction(&f.db)?);
    }
    let out = run_merge(&t, &tk, &old, &ok, |_, _| Ok(()))?;
    eprintln!("DELETED target + older archive -> {out:?}");
    assert!(matches!(out, Outcome::Omitted((0, 0, _, 0))), "{out:?}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Real flow: fresh target (1,1,1,0) merges a later archive where the message was deleted.
#[test]
fn probe_r4_fresh_target_merges_later_deletion() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r4-latedel")?;
    legacy_shape(&db)?;
    let t = root.join("t.db");
    let tk = revoked_archive(&db, &t, "both", false, true)?;
    db.delete_direct_message("thread", "message", "local", "tomb-1")?;
    let i = root.join("i.db");
    let ik = db.write_backup_snapshot(&i)?;
    let out = run_merge(&t, &tk, &i, &ik, |_, _| Ok(()))?;
    eprintln!("LATER deletion into fresh target -> {out:?}");
    assert!(matches!(out, Outcome::Omitted((0, 0, _, 0))), "{out:?}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Same veto, actor-present target (legacy_target_identity path).
#[test]
fn probe_r4_actor_target_incoming_fence() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r4-actor-fence")?;
    legacy_shape(&db)?;
    let old = root.join("old.db");
    let ok = db.write_backup_snapshot(&old)?;
    let t = root.join("t.db");
    let tk = revoked_archive(&db, &t, "both", true, false)?;
    let out = run_merge(&t, &tk, &old, &ok, |t, s| {
        let loc: String = t.query_row(LOC, [], |r| r.get(0))?;
        let v: serde_json::Value = serde_json::from_str(&loc)?;
        s.execute(
            "INSERT INTO object_erasure_fence VALUES(?1)",
            [v["commitment"].as_str().ok_or("commitment")?],
        )?;
        Ok(())
    })?;
    eprintln!("ACTOR-FENCE -> {out:?}");
    assert!(matches!(out, Outcome::Omitted((0, 0, _, 0))), "{out:?}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn probe_r5_self_backup_mismatch_refuses() -> TestResult {
    for field in ["identity", "owner"] {
        let (root, db) = crate::tests::test_db(&format!("self-mismatch-{field}"))?;
        legacy_shape(&db)?;
        let target = root.join("target.db");
        let saved = revoked_archive(&db, &target, "both", false, true)?;
        let incoming = root.join("incoming.db");
        BackupDatabase::open(&target, &saved.key)?.copy_to(&incoming, &saved.key)?;
        let result = run_merge(&target, &saved, &incoming, &saved, |_, s| {
            if field == "identity" {
                s.execute("UPDATE message_footprint SET locator=json_set(locator,'$.wire','other','$.commitment',?1) WHERE kind='revocation_selector'",[object_erasure_commitment("principal","other","manifest")])?;
            } else {
                s.execute("UPDATE message_footprint SET message_id='other' WHERE kind='revocation_selector'",[])?;
                s.execute("UPDATE message_copy_binding SET message_id='other' WHERE copy_id='object:private-canary'",[])?;
            }
            Ok(())
        })?;
        assert!(matches!(result, Outcome::Refused { unchanged: true }), "{field}: {result:?}");
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
