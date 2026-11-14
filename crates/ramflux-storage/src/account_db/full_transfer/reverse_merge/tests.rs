// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual A commits precede stage progress; restart replay cannot lose vetoes or issue early DV.
use super::super::reverse_validation::tests::staged_with_vetoes;
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn count(db: &crate::AccountDb) -> Result<u64, StorageError> {
    Ok(db
        .connection
        .query_row("SELECT count(*) FROM object_erasure_fence", [], |row| row.get(0))?)
}
fn interrupted(stage: &mut FullTransferStage<'_>, db: &crate::AccountDb, hash: &str) -> TestResult {
    assert!(
        stage.prepare_applied_reverse_receipt(1000).is_err(),
        "test: input validation granted an unapplied reverse DV"
    );
    assert!(
        !stage.apply_restrictive_reverse_batch(hash, 1)?,
        "test: first scalar completed 67-record reverse input"
    );
    assert!(
        !stage.apply_restrictive_reverse_batch(hash, 1)?,
        "test: MAC import completed unapplied veto records"
    );
    stage.connection.execute_batch("CREATE TRIGGER refuse_reverse_progress BEFORE UPDATE ON reverse_merge_progress BEGIN SELECT RAISE(ABORT,'injected progress persistence failure'); END;")?;
    assert!(
        stage.apply_restrictive_reverse_batch(hash, 1).is_err(),
        "test: progress persistence failure was ignored"
    );
    assert_eq!(count(db)?, 2, "test: stage progress preceded the actual A veto commit");
    assert!(
        stage.prepare_applied_reverse_receipt(1000).is_err(),
        "test: partial actual union permitted semantic DV"
    );
    Ok(())
}
#[test]
fn pairing_full_linked_reverse_merge_replays_committed_record_and_signs_only_after_complete()
-> TestResult {
    let (_root, db, reference, hash) = staged_with_vetoes(false, 65)?;
    db.connection
        .execute("UPDATE account_erasure_generation SET generation=12 WHERE singleton=1", [])?;
    db.connection.execute(
        "INSERT INTO object_erasure_fence VALUES(?1)",
        params![ramflux_protocol::encode_base64url([250; 32])],
    )?;
    let work = db
        .open_full_stage_reference(reference.clone(), PairingRole::Initiator, 1000)?
        .into_reverse_validation_work(&hash)?;
    let proof = work.validate()?;
    let mut stage =
        db.open_full_stage_reference(reference.clone(), PairingRole::Initiator, 1000)?;
    stage.accept_validated_reverse_input(&proof)?;
    interrupted(&mut stage, &db, &hash)?;
    drop(stage);
    let mut stage = db.open_full_stage_reference(reference, PairingRole::Initiator, 1000)?;
    stage.connection.execute_batch("DROP TRIGGER refuse_reverse_progress")?;
    db.connection.execute(
        "INSERT INTO object_erasure_fence VALUES(?1)",
        params![ramflux_protocol::encode_base64url([251; 32])],
    )?;
    assert!(
        !stage.apply_restrictive_reverse_batch(&hash, 1)?,
        "test: replay skipped remaining records"
    );
    assert_eq!(
        count(&db)?,
        3,
        "test: replay duplicated a committed veto or lost concurrent A state"
    );
    let mut complete = false;
    for _ in 0..4 {
        if stage.apply_restrictive_reverse_batch(&hash, 32)? {
            complete = true;
            break;
        }
    }
    assert!(complete, "test: bounded reverse batches did not finish");
    assert_eq!(count(&db)?, 67, "test: union lost B vetoes or either independent A write");
    assert_eq!(
        db.connection.query_row(
            "SELECT generation FROM account_erasure_generation",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        12,
        "test: B's older floor lowered A's maximum"
    );
    let proof = stage.prepare_applied_reverse_receipt(1000)?;
    let packet = proof.signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
        &proof.packet().data_verified_signing_bytes()?,
        [7; 32],
    ))?;
    stage.record_reverse_application_receipt(&proof, &packet, 1000)?;
    assert_eq!(
        stage.connection.query_row(
            "SELECT verified FROM manifest WHERE direction=1",
            [],
            |row| row.get::<_, u8>(0)
        )?,
        1,
        "test: complete actual union did not retain original-A semantic DV"
    );
    Ok(())
}
