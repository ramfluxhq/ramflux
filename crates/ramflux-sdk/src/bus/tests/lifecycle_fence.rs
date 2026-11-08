// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::unwrap_used, clippy::panic)]
//! `lifecycle_fence`: a held page/result released after lock under the old generation
//! writes nothing and does not ACK; unlock recovers disk. Negative: drop the actor
//! generation argument at commit and the stale row appears.
use super::super::lifecycle_fence::commit;
use super::fixture::{Case, Fixture};
use crate::bus::connection_manager::ReceiveTurn;
use crate::prelude::*;
use ramflux_storage::{ReceiveStage, ReceiveStageResult, ReceiveTransaction, StorageError};
use serde_json::json;
use std::time::{Duration, Instant};

const SEQ: u64 = 7;

fn turn(db: &AccountDb, generation: u64) -> Result<ReceiveTurn, SdkError> {
    Ok(ReceiveTurn {
        target: "t".into(),
        incarnation: "e".into(),
        cursor: 0,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn wire() -> Vec<u8> {
    serde_json::to_vec(&json!({"inbox_seq":SEQ,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env-7","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"H7"
    }}))
    .unwrap()
}

fn stage_page(tx: &ReceiveTransaction<'_>) -> Result<ReceiveStageResult, StorageError> {
    let entry = wire();
    tx.stage(ReceiveStage {
        target: "t",
        incarnation: "e",
        sequence: SEQ,
        entry_json: &entry,
        admission_key: "authenticated-key",
        retain_until: now_unix_timestamp() + 300,
        first_seen: 1,
    })
}

fn state(account: &LocalBusAccountState) -> Result<(Option<String>, i64), SdkError> {
    Ok(account.client.account_db()?.receive_state_for_test(SEQ)?)
}

fn reopen(account: &mut LocalBusAccountState) -> Case {
    account.client.active_account_db = None;
    account.client.unlock_account("sender", b"actor-test-secret")?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_fence() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(held()))))
        .await
}

async fn held() -> Case {
    let mut fixture = Box::pin(Fixture::new("lifecycle-fence")).await?;
    let account = &mut fixture.source;
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    let old = turn(db, 1)?;
    let held_page = wire();
    let locked = Instant::now();
    account.client.active_account_db = None;
    assert!(locked.elapsed() < Duration::from_secs(1), "account lock must finish in under 1s");
    reopen(account)?;
    assert_eq!(state(account)?, (None, 0), "unlock recovers disk with no held write");
    let db = account.client.account_db()?;
    let stale = commit(db, 2, old.expected(), |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence: SEQ,
            entry_json: &held_page,
            admission_key: "authenticated-key",
            retain_until: now_unix_timestamp() + 300,
            first_seen: 1,
        })
    });
    assert!(
        matches!(stale, Err(StorageError::AuthorizationRejected)),
        "old generation must not commit: {stale:?}"
    );
    assert_eq!(state(account)?, (None, 0), "stale page/result writes nothing and does not ACK");
    let fresh = turn(db, 2)?;
    assert_eq!(commit(db, 2, fresh.expected(), stage_page)?, ReceiveStageResult::Staged);
    assert_eq!(state(account)?, (Some("staged".to_owned()), 1));
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
