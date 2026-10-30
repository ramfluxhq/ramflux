// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Comparative write-cost microbenchmark for privacy-footprint trigger overhead.

use super::*;
use std::time::{Duration, Instant};

const WRITES: i64 = 1_000;

#[derive(Clone, Copy, Debug)]
enum WriteKind {
    ActorState,
    MessageActorState,
    Journal,
    DirectMessage,
}

#[test]
#[ignore = "manual branch-versus-main comparative microbenchmark"]
fn write_cost_microbenchmark() -> Result<(), StorageError> {
    for kind in [
        WriteKind::ActorState,
        WriteKind::MessageActorState,
        WriteKind::Journal,
        WriteKind::DirectMessage,
    ] {
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
            WriteKind::MessageActorState => {
                let message = format!("benchmark-message-{index}");
                match index % 4 {
                    0 => db.persist_actor_state(
                        &format!("routed/committed/benchmark-{index}"),
                        &serde_json::json!({
                            "routing":{"message_id":message},
                            "entry":{"envelope":{
                                "envelope_id":format!("benchmark-envelope-{index}"),
                                "payload_hash":format!("benchmark-payload-{index}")
                            }}
                        }),
                    )?,
                    1 => db.persist_actor_state(
                        &format!("routed/message-owner/{message}"),
                        &"benchmark-sender",
                    )?,
                    2 => db.persist_actor_state(
                        &format!("delivery-receipt/pending/benchmark-{index}"),
                        &serde_json::json!({
                            "message":message,
                            "status_id":format!("benchmark-status-{index}")
                        }),
                    )?,
                    _ => db.persist_actor_state(
                        &format!("task/message/benchmark-{index}"),
                        &serde_json::json!({"message_id":message,"state":"pending"}),
                    )?,
                }
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
        WriteKind::MessageActorState => {
            "SELECT count(*) FROM runtime_actor_state WHERE
              state_kind GLOB 'routed/committed/benchmark-*'
              OR state_kind GLOB 'routed/message-owner/benchmark-message-*'
              OR state_kind GLOB 'delivery-receipt/pending/benchmark-*'
              OR state_kind GLOB 'task/message/benchmark-*'"
        }
        WriteKind::Journal => "SELECT count(*) FROM runtime_journal WHERE topic='benchmark.event'",
        WriteKind::DirectMessage => {
            "SELECT count(*) FROM direct_message_projection WHERE conversation_id='benchmark'"
        }
    };
    Ok(db.connection.query_row(sql, [], |row| row.get(0))?)
}
