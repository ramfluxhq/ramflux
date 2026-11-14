// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generic source-hold fences survive activation independently of retired application codecs.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

fn gate(db: &AccountDb) -> Result<LegacyW1<'_>, SdkError> {
    Ok(LegacyW1 {
        expected: ReceiveExpectation {
            target: "qualified-mailbox",
            incarnation: "source-epoch",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    })
}
fn stage(db: &AccountDb, fence: &LegacyW1<'_>) -> Result<(), SdkError> {
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("qualified-mailbox", "source-epoch")?;
    let entry = serde_json::to_vec(&serde_json::json!({
        "inbox_seq":1,"target_delivery_id":"qualified-mailbox","envelope":{
            "schema":"test","version":1,"domain":"test","signing_key_id":"key",
            "signature_alg":"ed25519","signature":"sig","envelope_id":"source-envelope",
            "source_principal_id":"source","source_device_id":"device",
            "target_delivery_id":"qualified-mailbox","delivery_class":"opaque_event",
            "priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher",
            "payload_hash":"hash"
        }
    }))?;
    fence.stage(
        db,
        ReceiveStage {
            target: "qualified-mailbox",
            incarnation: "source-epoch",
            sequence: 1,
            entry_json: &entry,
            admission_key: "source-admission",
            retain_until: i64::MAX,
            first_seen: 1,
        },
    )?;
    Ok(())
}
fn effect(db: &AccountDb) -> Result<(), SdkError> {
    Ok(db.persist_actor_state("source-hold/effect", &true)?)
}

#[tokio::test(flavor = "current_thread")]
async fn source_hold_requires_staged_input_and_rolls_back_before_commit_fault() -> TestResult {
    let source = Fixture::new("source-hold-fence").await?;
    let db = source.client.account_db()?;
    let fence = gate(db)?;
    assert!(fence.effect(db, 1, None, || effect(db)).is_err());
    assert!(!db.actor_state_exists("source-hold/effect")?);
    stage(db, &fence)?;
    let result = run(Fault::BeforeCommit, || fence.effect(db, 1, None, || effect(db)));
    assert!(matches!(
        result,
        Err(SdkError::Storage(StorageError::Integrity("legacy w1 before-commit")))
    ));
    assert!(!db.actor_state_exists("source-hold/effect")?);
    fence.effect(db, 1, None, || effect(db))?;
    assert_eq!(db.load_actor_state::<bool>("source-hold/effect")?, Some(true));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn source_hold_refuses_changed_generation_incarnation_cursor_and_erasure() -> TestResult {
    let source = Fixture::new("source-hold-fences").await?;
    let db = source.client.account_db()?;
    stage(db, &gate(db)?)?;
    for boundary in ["generation", "incarnation", "cursor", "erasure"] {
        let mut fence = gate(db)?;
        match boundary {
            "generation" => fence.generation = 2,
            "incarnation" => fence.expected.incarnation = "different-epoch",
            "cursor" => fence.expected.cursor = 1,
            _ => fence.expected.erasure_generation += 1,
        }
        assert!(
            fence.effect(db, 1, None, || effect(db)).is_err(),
            "{boundary} failed to fence the effect"
        );
        assert!(!db.actor_state_exists("source-hold/effect")?, "{boundary} left an effect");
    }
    gate(db)?.effect(db, 1, None, || effect(db))?;
    assert_eq!(db.load_actor_state::<bool>("source-hold/effect")?, Some(true));
    Ok(())
}
