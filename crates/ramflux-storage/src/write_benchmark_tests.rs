// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Comparative write-cost microbenchmark for privacy-footprint trigger overhead.

use super::*;
use std::time::{Duration, Instant};

const WRITES: i64 = 1_000;

#[derive(Clone, Copy, Debug)]
enum WriteKind {
    ActorState,
    Journal,
    DirectMessage,
}

#[test]
#[ignore = "manual branch-versus-main comparative microbenchmark"]
fn write_cost_microbenchmark() -> Result<(), StorageError> {
    for kind in [WriteKind::ActorState, WriteKind::Journal, WriteKind::DirectMessage] {
        for batched in [true, false] {
            let elapsed = measure(kind, batched)?;
            eprintln!(
                "write-cost kind={kind:?} mode={} writes={WRITES} elapsed_ms={}",
                if batched { "one-transaction" } else { "commit-per-write" },
                elapsed.as_millis()
            );
        }
    }
    Ok(())
}

fn measure(kind: WriteKind, batched: bool) -> Result<Duration, StorageError> {
    let (root, db) = test_db(&format!("write-cost-{kind:?}-{batched}"))?;
    let started = Instant::now();
    if batched {
        db.write_transaction(|| write_rows(&db, kind))?;
    } else {
        write_rows(&db, kind)?;
    }
    let elapsed = started.elapsed();
    assert_eq!(stored_rows(&db, kind)?, WRITES);
    drop(db);
    fs::remove_dir_all(root)?;
    Ok(elapsed)
}

fn write_rows(db: &AccountDb, kind: WriteKind) -> Result<(), StorageError> {
    let metadata = MessageMetadata::default();
    let actor_value = "non-message-state".repeat(8);
    for index in 0..WRITES {
        match kind {
            WriteKind::ActorState => {
                db.persist_actor_state(&format!("probe/state/{index}"), &actor_value)?;
            }
            WriteKind::Journal => {
                db.append_journal(
                    &format!("benchmark:{index}"),
                    "benchmark.event",
                    &serde_json::json!({"sequence":index}),
                    index,
                    None,
                )?;
            }
            WriteKind::DirectMessage => {
                db.import_direct_message_projection(DirectMessageWrite {
                    conversation_id: "benchmark",
                    message_id: &format!("benchmark-message-{index}"),
                    sender_id: "benchmark-sender",
                    encrypted_body: b"benchmark-ciphertext",
                    metadata: &metadata,
                    created_at: index,
                })?;
            }
        }
    }
    Ok(())
}

fn stored_rows(db: &AccountDb, kind: WriteKind) -> Result<i64, StorageError> {
    let sql = match kind {
        WriteKind::ActorState => {
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB 'probe/state/*'"
        }
        WriteKind::Journal => "SELECT count(*) FROM runtime_journal WHERE topic='benchmark.event'",
        WriteKind::DirectMessage => {
            "SELECT count(*) FROM direct_message_projection WHERE conversation_id='benchmark'"
        }
    };
    Ok(db.connection.query_row(sql, [], |row| row.get(0))?)
}
