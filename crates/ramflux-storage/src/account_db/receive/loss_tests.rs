// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WJ/WP backpressure: 2,048 total ranges and 1 MiB unpublished loss bytes.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCoverKind as Kind, ReceiveCoverResult as Out, ReceiveGap};
use super::cover_tests::{alternating, cover, gap, snap};
use super::loss::{
    PENDING_LOSS_BYTES, PROJECTED_RANGE_CAP, TOTAL_RANGE_CAP, gap_keys_json, loss_journal_event,
};
use super::stage_tests::setup;
use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::params;

type LossRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

fn fill_ranges(db: &AccountDb, n: i64) -> Result<u64, StorageError> {
    fill_ranges_from(db, 0, usize::try_from(n / 64).expect("turns"))
}

fn fill_ranges_from(db: &AccountDb, start: u64, turns: usize) -> Result<u64, StorageError> {
    let mut cursor = start;
    for _ in 0..turns {
        let gaps = alternating(cursor + 1, 64);
        assert_eq!(cover(db, cursor, cursor + 64, Kind::GapOnly, &gaps)?, Out::Covered);
        cursor += 64;
    }
    Ok(cursor)
}

fn keys_len(gap: &ReceiveGap<'_>) -> Result<i64, StorageError> {
    Ok(i64::try_from(gap_keys_json("t", "e", gap, 1)?.len()).expect("len"))
}

/// Budget row JSON padded with `pad` to exactly `bytes` UTF-8 bytes.
fn budget_keys(bytes: i64, pad: &str) -> String {
    let prefix = r#"{"source_key":"budget","target":"t","pad":""#;
    let suffix = "\"}";
    let room = usize::try_from(bytes).expect("bytes") - prefix.len() - suffix.len();
    let body = pad.repeat(room / pad.len()) + &"x".repeat(room % pad.len());
    let keys = format!("{prefix}{body}{suffix}");
    assert_eq!(i64::try_from(keys.len()).expect("len"), bytes);
    keys
}

fn insert_loss_outbox(db: &AccountDb, keys: &str) -> Result<(), StorageError> {
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

fn seed_unpublished_bytes(db: &AccountDb, bytes: i64) -> Result<(), StorageError> {
    insert_loss_outbox(db, &budget_keys(bytes, "x"))
}

/// Same as `seed_unpublished_bytes`, but the padding is 2-byte UTF-8 so chars < bytes.
fn seed_utf8_bytes(db: &AccountDb, bytes: i64) -> Result<(), StorageError> {
    insert_loss_outbox(db, &budget_keys(bytes, "\u{e9}"))
}

fn loss_count(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id='t'",
        [],
        |row| row.get(0),
    )?)
}

fn loss_rows(db: &AccountDb) -> Result<Vec<LossRow>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT incarnation_id,from_seq,to_seq,count FROM gateway_inbox_loss
         WHERE target_delivery_id='t' ORDER BY from_seq",
    )?;
    let rows =
        query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
    let out = rows.collect::<Result<Vec<LossRow>, rusqlite::Error>>()?;
    Ok(out)
}

fn unpublished_loss_bytes(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT coalesce(sum(length(CAST(keys_json AS BLOB))),0) FROM runtime_outbox
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

/// WJ for the oldest `n` unpublished loss outbox rows only, through the real `journal_outbox`.
/// `journal_outbox` publishes every outbox row up to its sequence, so WJ publishes a prefix.
fn project_oldest(db: &AccountDb, n: i64) -> Result<usize, StorageError> {
    let rows = {
        let mut query = db.connection.prepare(
            "SELECT sequence,keys_json FROM runtime_outbox
             WHERE published=0 AND table_name='gateway_inbox_loss' ORDER BY sequence LIMIT ?1",
        )?;
        let mapped = query
            .query_map(params![n], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?;
        mapped.collect::<Result<Vec<(i64, String)>, rusqlite::Error>>()?
    };
    for (sequence, keys) in &rows {
        let value: serde_json::Value = serde_json::from_str(keys)?;
        db.journal_outbox(*sequence, &[loss_journal_event(&value)], 1)?;
    }
    Ok(rows.len())
}

#[test]
fn loss_storage_backpressure() -> Result<(), StorageError> {
    range_cap_then_project_and_prune()?;
    prune_before_projection_keeps_unpublished()?;
    partial_publication_prunes_only_projected()?;
    multi_sequence_range_counts_sequences()?;
    byte_cap_then_project()?;
    byte_cap_exact_fit_covers()?;
    byte_cap_counts_utf8_bytes()?;
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

/// (a) WP runs before any WJ: every range is unpublished, so none may be pruned.
fn prune_before_projection_keeps_unpublished() -> Result<(), StorageError> {
    let (root, db) = setup("wj-wp-before")?;
    assert_eq!(fill_ranges(&db, TOTAL_RANGE_CAP)?, 2_048);
    let before = loss_rows(&db)?;
    assert_eq!(before.len(), 2_048);
    db.prune_projected_loss("t")?;
    assert_eq!(loss_rows(&db)?, before, "WP keeps every unpublished range");
    assert_eq!(pruned_counter(&db)?, 0, "nothing pruned, no counter movement");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// (b) Partial publication: WJ projects the oldest 1,000 rows, 1,048 stay unpublished.
/// WP must not prune: 1,000 projected is under the 1,024 keep count, and an overflow of
/// 1,024 from all 2,048 rows would reach the unpublished (oldest-by-recorded_at) ranges.
/// After WJ finishes, WP prunes exactly the 1,024 oldest projected ranges.
fn partial_publication_prunes_only_projected() -> Result<(), StorageError> {
    let (root, db) = setup("wj-wp-partial")?;
    assert_eq!(fill_ranges(&db, TOTAL_RANGE_CAP)?, 2_048);
    let before = loss_rows(&db)?;
    assert_eq!(project_oldest(&db, 1_000)?, 1_000);
    db.prune_projected_loss("t")?;
    assert_eq!(loss_rows(&db)?, before, "unpublished ranges survive a partial-WJ prune");
    assert_eq!(pruned_counter(&db)?, 0);
    assert_eq!(db.project_loss_outbox(1)?.len(), 1_048);
    db.prune_projected_loss("t")?;
    let after = loss_rows(&db)?;
    assert_eq!(after.len(), usize::try_from(PROJECTED_RANGE_CAP).expect("cap"));
    assert_eq!(
        after[..],
        before[1_024..],
        "the 1,024 oldest projected ranges are the ones removed"
    );
    assert_eq!(pruned_counter(&db)?, 1_024);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// L1: the pruned counter adds the sequence count of each pruned range, not one per range.
/// Oldest range is seqs 1..=3 (count 3); 65 overflow pruned = that range + 64 singles.
fn multi_sequence_range_counts_sequences() -> Result<(), StorageError> {
    let (root, db) = setup("wj-wp-multi")?;
    assert_eq!(cover(&db, 0, 3, Kind::GapOnly, &[gap(1, 3)])?, Out::Covered);
    assert_eq!(fill_ranges_from(&db, 3, 17)?, 1_091);
    assert_eq!(loss_count(&db)?, 1_089);
    assert_eq!(db.project_loss_outbox(1)?.len(), 1_089);
    db.prune_projected_loss("t")?;
    assert_eq!(loss_count(&db)?, PROJECTED_RANGE_CAP);
    assert_eq!(pruned_counter(&db)?, 3 + 64, "counter adds sequence count, 67 not 65");
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

/// M2 positive boundary: pending + one gap's encoded size == 1 MiB is still `Covered`.
/// One more byte of pending loss must pause.
fn byte_cap_exact_fit_covers() -> Result<(), StorageError> {
    let first = [gap(1, 1)];
    let fits = PENDING_LOSS_BYTES - keys_len(&first[0])?;

    let (root, db) = setup("wj-wp-bytes-fit")?;
    seed_unpublished_bytes(&db, fits)?;
    assert_eq!(unpublished_loss_bytes(&db)?, fits);
    assert_eq!(cover(&db, 0, 1, Kind::GapOnly, &first)?, Out::Covered);
    assert_eq!(snap(&db)?.cursor, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;

    let (root, db) = setup("wj-wp-bytes-over")?;
    seed_unpublished_bytes(&db, fits + 1)?;
    let pre = snap(&db)?;
    assert_eq!(cover(&db, 0, 1, Kind::GapOnly, &first)?, Out::Paused);
    assert_eq!(snap(&db)?, pre, "one byte over the cap pauses");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// L2: pending loss is counted in UTF-8 bytes, not characters, on both sides of the cap.
fn byte_cap_counts_utf8_bytes() -> Result<(), StorageError> {
    let first = [gap(1, 1)];
    let fits = PENDING_LOSS_BYTES - keys_len(&first[0])?;

    let (root, db) = setup("wj-wp-utf8-fit")?;
    seed_utf8_bytes(&db, fits)?;
    assert_eq!(unpublished_loss_bytes(&db)?, fits, "pending loss is measured in bytes");
    assert_eq!(cover(&db, 0, 1, Kind::GapOnly, &first)?, Out::Covered);
    drop(db);
    std::fs::remove_dir_all(root)?;

    let (root, db) = setup("wj-wp-utf8-over")?;
    seed_utf8_bytes(&db, fits + 1)?;
    assert_eq!(cover(&db, 0, 1, Kind::GapOnly, &first)?, Out::Paused);
    assert_eq!(snap(&db)?.cursor, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
