// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Target fence retention and surviving-owner parity with live deletion.
use super::*;

#[test]
fn probe_r5r_surviving_second_owner_keeps() -> TestResult {
    let (root, db) = crate::tests::test_db("restore-second-owner")?;
    db.send_direct_message("thread", "message2", "peer", b"body2")?;
    legacy_shape(&db)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    db.remove_actor_state("attachment/reference/private-canary")?;
    db.connection.execute("INSERT INTO message_footprint SELECT 'message2',kind,locator FROM message_footprint WHERE kind='revocation_selector'", [])?;
    db.connection.execute(
        "INSERT INTO message_copy_binding VALUES('object:private-canary','message2')",
        [],
    )?;
    let target = root.join("target.db");
    let target_key = db.write_backup_snapshot(&target)?;
    {
        let mut stage = BackupDatabase::open_restore_input(
            &target,
            &target_key.key,
            BackupOpenMode::PreNormalization,
        )?;
        stage.normalize_backup_candidate()?;
        assert_eq!(restriction(&stage.db)?.0, 1);
    }
    db.delete_direct_message("thread", "message", "local", "tomb-1")?;
    let live_object: u64 = db.connection.query_row(
        "SELECT count(*) FROM object_index WHERE object_id='private-canary' AND tombstoned=1",
        [],
        |r| r.get(0),
    )?;
    let live_footprints: u64 = db.connection.query_row(
        "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(live_object, 1, "live deletion must retain the second owner");
    assert!(live_footprints > 0, "live surviving restriction missing");
    let input = root.join("incoming.db");
    let input_key = db.write_backup_snapshot(&input)?;
    let out = run_merge(&target, &target_key, &input, &input_key, |_, _| Ok(()))?;
    assert_eq!(
        live_object == 1,
        matches!(out, Outcome::Kept(_)),
        "merge disagrees with live oracle: {out:?}"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn probe_r5r_target_fence_retained() -> TestResult {
    let (root, db) = crate::tests::test_db("restore-target-fence")?;
    legacy_shape(&db)?;
    let old = root.join("old.db");
    let old_key = db.write_backup_snapshot(&old)?;
    let target = root.join("target.db");
    let target_key = revoked_archive(&db, &target, "both", false, true)?;
    let commitment = object_erasure_commitment("principal", "wire", "manifest");
    let fence = commitment.clone();
    let out = run_merge(&target, &target_key, &old, &old_key, move |target, _| {
        target.execute("INSERT INTO object_erasure_fence VALUES(?1)", [fence])?;
        Ok(())
    })?;
    assert!(matches!(out, Outcome::Omitted((0, 0, _, 0))), "{out:?}");
    let stage = BackupDatabase::open_restore_input(
        &target,
        &target_key.key,
        BackupOpenMode::PreNormalization,
    )?;
    assert!(
        stage.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
            [commitment],
            |r| r.get::<_, bool>(0),
        )?,
        "target fence lost"
    );
    assert!(
        stage.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1)",
            [object_erasure_lookup("principal", "private-canary")],
            |r| r.get::<_, bool>(0),
        )?,
        "target lookup lost"
    );
    assert_eq!(
        stage.db.query_row(
            "SELECT count(*) FROM object_index WHERE object_id='private-canary'",
            [],
            |r| r.get::<_, u64>(0),
        )?,
        0
    );
    drop(stage);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
