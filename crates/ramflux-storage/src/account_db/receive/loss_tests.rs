// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WJ/WP backpressure: 2,048 total ranges and 1 MiB unpublished loss bytes.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCoverKind as Kind, ReceiveCoverResult as Out};
use super::cover_tests::{alternating, cover, gap, snap};
use super::loss::{PENDING_LOSS_BYTES, PROJECTED_RANGE_CAP, TOTAL_RANGE_CAP};
use super::stage_tests::setup;
use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::params;

fn fill_ranges(db: &AccountDb, n: i64) -> Result<u64, StorageError> {
    let mut cursor = 0u64;
    let turns = usize::try_from(n / 64).expect("turns");
    for _ in 0..turns {
        let gaps = alternating(cursor + 1, 64);
        assert_eq!(cover(db, cursor, cursor + 64, Kind::GapOnly, &gaps)?, Out::Covered);
        cursor += 64;
    }
    Ok(cursor)
}

fn seed_unpublished_bytes(db: &AccountDb, bytes: i64) -> Result<(), StorageError> {
    let prefix = r#"{"source_key":"budget","target":"t","pad":""#;
    let suffix = "\"}";
    let pad = usize::try_from(bytes).expect("bytes") - prefix.len() - suffix.len();
    let keys = format!("{prefix}{}{suffix}", "x".repeat(pad));
    assert_eq!(i64::try_from(keys.len()).expect("len"), bytes);
    db.write_transaction(|| {
        db.connection.execute(
            "INSERT INTO runtime_outbox(table_name,change_kind,row_id,published,keys_json)
             VALUES('gateway_inbox_loss','insert',0,0,?1)",
            params![keys],
        )?;
        Ok::<(), StorageError>(())
    })?;
    Ok(())
}

fn loss_count(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id='t'",
        [],
        |row| row.get(0),
    )?)
}

fn unpublished_loss_bytes(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT coalesce(sum(length(keys_json)),0) FROM runtime_outbox
         WHERE published=0 AND table_name='gateway_inbox_loss'
           AND json_extract(keys_json,'$.target')='t'",
        [],
        |row| row.get(0),
    )?)
}

fn journal_gap_count(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='receive.gap'",
        [],
        |row| row.get(0),
    )?)
}

fn pruned_counter(db: &AccountDb) -> Result<u64, StorageError> {
    db.projection_checkpoint("gateway_receive_loss_count:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))
}

#[test]
fn loss_storage_backpressure() -> Result<(), StorageError> {
    range_cap_then_project_and_prune()?;
    byte_cap_then_project()?;
    Ok(())
}

fn range_cap_then_project_and_prune() -> Result<(), StorageError> {
    let (root, db) = setup("wj-wp-range")?;
    let cursor = fill_ranges(&db, TOTAL_RANGE_CAP)?;
    assert_eq!(cursor, 2_048);
    assert_eq!(loss_count(&db)?, TOTAL_RANGE_CAP);
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 2_048);
    let next = [gap(2_049, 2_049)];
    assert_eq!(cover(&db, 2_048, 2_049, Kind::GapOnly, &next)?, Out::Paused);
    assert_eq!(snap(&db)?, pre, "range-cap pause leaves C/work/outbox unchanged");

    let journaled = db.project_loss_outbox(1)?;
    assert_eq!(i64::try_from(journaled.len()).expect("journaled"), TOTAL_RANGE_CAP);
    assert_eq!(journal_gap_count(&db)?, TOTAL_RANGE_CAP);
    assert_eq!(unpublished_loss_bytes(&db)?, 0, "WJ marks loss outbox published");
    let after_wj = journal_gap_count(&db)?;
    db.prune_projected_loss("t")?;
    assert_eq!(loss_count(&db)?, PROJECTED_RANGE_CAP, "WP keeps 1,024 projected ranges");
    assert_eq!(journal_gap_count(&db)?, after_wj, "WP emits no new loss events");
    assert_eq!(pruned_counter(&db)?, 1_024, "counters survive pruning");
    assert_eq!(snap(&db)?.cursor, 2_048, "WP does not move C");

    assert_eq!(cover(&db, 2_048, 2_049, Kind::GapOnly, &next)?, Out::Covered);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 2_049);
    assert_eq!(loss_count(&db)?, PROJECTED_RANGE_CAP + 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn byte_cap_then_project() -> Result<(), StorageError> {
    let (root, db) = setup("wj-wp-bytes")?;
    seed_unpublished_bytes(&db, PENDING_LOSS_BYTES)?;
    assert_eq!(unpublished_loss_bytes(&db)?, PENDING_LOSS_BYTES);
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 0);
    let first = [gap(1, 1)];
    assert_eq!(cover(&db, 0, 1, Kind::GapOnly, &first)?, Out::Paused);
    assert_eq!(snap(&db)?, pre, "byte-cap pause leaves C/work/outbox unchanged");

    db.project_loss_outbox(1)?;
    db.prune_projected_loss("t")?;
    assert_eq!(unpublished_loss_bytes(&db)?, 0);
    assert_eq!(cover(&db, 0, 1, Kind::GapOnly, &first)?, Out::Covered);
    assert_eq!(snap(&db)?.cursor, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
