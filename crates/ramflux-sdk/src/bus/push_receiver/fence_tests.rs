// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The receive transaction fence under a source effect: staged input is required, a cut
//! before commit rolls the effect back, and a changed generation, incarnation, cursor or
//! erasure generation refuses it.
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_storage::{AccountDb, ReceiveExpectation, ReceiveStage, StorageError};

const TARGET: &str = "qualified-mailbox";
const EPOCH: &str = "source-epoch";
const CUT: &str = "fence test before-commit";

fn expected(db: &AccountDb) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: TARGET,
        incarnation: EPOCH,
        cursor: 0,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn stage(db: &AccountDb) -> TestResult {
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(TARGET, EPOCH)?;
    let entry = serde_json::to_vec(&serde_json::json!({
        "inbox_seq":1,"target_delivery_id":TARGET,"envelope":{
            "schema":"test","version":1,"domain":"test","signing_key_id":"key",
            "signature_alg":"ed25519","signature":"sig","envelope_id":"source-envelope",
            "source_principal_id":"source","source_device_id":"device",
            "target_delivery_id":TARGET,"delivery_class":"opaque_event",
            "priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher",
            "payload_hash":"hash"
        }
    }))?;
    db.receive_transaction(expected(db)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: TARGET,
            incarnation: EPOCH,
            sequence: 1,
            entry_json: &entry,
            admission_key: "source-admission",
            retain_until: i64::MAX,
            first_seen: 1,
        })
    })?;
    Ok(())
}

/// The source effect: requires the staged input, writes one actor-state row, and may be cut
/// before the transaction commits.
fn effect(
    db: &AccountDb,
    expected: ReceiveExpectation<'_>,
    generation: u64,
    cut: bool,
) -> Result<(), StorageError> {
    db.receive_transaction(expected, generation, |tx| {
        tx.require_open_input(1)?;
        tx.account().persist_actor_state("source-hold/effect", &true)?;
        if cut { Err(StorageError::Integrity(CUT)) } else { Ok(()) }
    })
}

#[tokio::test(flavor = "current_thread")]
async fn source_hold_requires_staged_input_and_rolls_back_before_commit_fault() -> TestResult {
    let source = Fixture::new("source-hold-fence").await?;
    let db = source.client.account_db()?;
    assert!(effect(db, expected(db)?, 1, false).is_err(), "no staged input, no effect");
    assert!(!db.actor_state_exists("source-hold/effect")?);
    stage(db)?;
    let result = effect(db, expected(db)?, 1, true);
    assert!(
        matches!(result, Err(StorageError::Integrity(CUT))),
        "a cut before commit surfaces: {result:?}"
    );
    assert!(!db.actor_state_exists("source-hold/effect")?, "the cut rolled the effect back");
    effect(db, expected(db)?, 1, false)?;
    assert_eq!(db.load_actor_state::<bool>("source-hold/effect")?, Some(true));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn source_hold_refuses_changed_generation_incarnation_cursor_and_erasure() -> TestResult {
    let source = Fixture::new("source-hold-fences").await?;
    let db = source.client.account_db()?;
    stage(db)?;
    for boundary in ["generation", "incarnation", "cursor", "erasure"] {
        let mut fence = expected(db)?;
        let mut generation = 1;
        match boundary {
            "generation" => generation = 2,
            "incarnation" => fence.incarnation = "different-epoch",
            "cursor" => fence.cursor = 1,
            _ => fence.erasure_generation += 1,
        }
        assert!(
            effect(db, fence, generation, false).is_err(),
            "{boundary} failed to fence the effect"
        );
        assert!(!db.actor_state_exists("source-hold/effect")?, "{boundary} left an effect");
    }
    effect(db, expected(db)?, 1, false)?;
    assert_eq!(db.load_actor_state::<bool>("source-hold/effect")?, Some(true));
    Ok(())
}
