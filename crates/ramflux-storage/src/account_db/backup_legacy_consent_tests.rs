// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy live projections participate in consent ordering even without decision rows.
use super::{AccountDb, BackupDatabase, TestResult, account};

fn stage(db: &AccountDb, state: &str, projection_at: i64) -> TestResult {
    if matches!(state, "declined" | "pending") {
        db.record_pending_friend_link("link", "own", "peer", projection_at)?;
        if state == "declined" {
            db.reject_friend_link("link", projection_at)?;
        }
    } else {
        db.establish_friend_link("link", "own", "peer")?;
        if state == "blocked" {
            db.block_friend_link("link", projection_at)?;
        }
    }
    db.connection.execute(
        "UPDATE friend_link_projection SET updated_at=?1",
        rusqlite::params![projection_at],
    )?;
    if matches!(state, "blocked" | "declined") {
        db.fence_contact_request("peer", state, 0)?;
    }
    let projection = if state == "lifted" { "accepted" } else { state };
    db.connection.execute("INSERT INTO contact_request_projection VALUES('peer','inbound',?1,'peer','link',?2,x'7b7d',999,?3)", rusqlite::params![format!("request-{projection_at}"),projection,projection_at])?;
    if state == "lifted" {
        db.clear_contact_request_fence("peer", None)?;
    }
    db.connection.execute_batch("UPDATE contact_link_decision SET decided_at=7000; UPDATE contact_request_decision SET decided_at=7000;")?;
    Ok(())
}

#[test]
fn legacy_live_consent_ties_keep_the_stricter_decision_and_its_projection() -> TestResult {
    for (local_state, incoming_state, expected) in [
        ("lifted", "blocked", "blocked"),
        ("pending", "blocked", "blocked"),
        ("pending", "declined", "declined"),
        ("lifted", "declined", "declined"),
        ("declined", "blocked", "blocked"),
        ("blocked", "lifted", "blocked"),
        ("declined", "lifted", "declined"),
    ] {
        let (root, index, incoming) = account("legacy-incoming")?;
        let (live_root, live_index, live) = account("legacy-live")?;
        stage(&incoming, incoming_state, 6)?;
        stage(&live, local_state, 7)?;
        let archive = root.join("incoming.db");
        let saved = incoming.write_backup_snapshot(&archive)?;
        let target = live_root.join("merged.db");
        let snapshot = live.write_backup_snapshot(&target)?;
        let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
        // Opening upgrades old snapshots. Remove rows afterwards to exercise the merge's
        // missing-live-decision path itself rather than the open-time migration.
        merged.db.execute_batch(
            "DELETE FROM contact_link_decision; DELETE FROM contact_request_decision;",
        )?;
        let case = format!("legacy {local_state} vs incoming {incoming_state}");
        for _ in 0..2 {
            merged.merge_backup(&archive, &saved.key, || Ok(()))?;
            for table in ["contact_link_decision", "contact_request_decision"] {
                assert_eq!(
                    merged.db.query_row(&format!("SELECT state FROM {table}"), [], |r| r
                        .get::<_, String>(0))?,
                    expected,
                    "{table}: {case}"
                );
            }
            let link_state = if expected == "declined" { "rejected" } else { expected };
            assert_eq!(
                merged.db.query_row(
                    "SELECT state,blocked FROM friend_link_projection",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
                )?,
                (link_state.into(), expected == "blocked"),
                "{case}"
            );
            assert_eq!(
                merged
                    .db
                    .query_row("SELECT state FROM contact_request_projection", [], |r| r
                        .get::<_, String>(0))?,
                expected,
                "{case}"
            );
            if incoming_state == expected && local_state != expected {
                assert_eq!(
                    merged.db.query_row(
                        "SELECT request_id FROM contact_request_projection",
                        [],
                        |r| r.get::<_, String>(0)
                    )?,
                    "request-6",
                    "a tied stricter incoming projection must replace the legacy row: {case}"
                );
                if expected == "blocked" {
                    assert_eq!(
                        merged.db.query_row(
                            "SELECT capability_revoked_at FROM friend_link_projection",
                            [],
                            |r| r.get::<_, i64>(0)
                        )?,
                        6,
                        "{case}"
                    );
                }
            }
        }
        drop(merged);
        drop(incoming);
        drop(live);
        drop(index);
        drop(live_index);
        std::fs::remove_dir_all(root)?;
        std::fs::remove_dir_all(live_root)?;
    }
    Ok(())
}
