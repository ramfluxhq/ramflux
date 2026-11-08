// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]
//! `own_copy_ack_binding` (P14 first leg + P21 WA): W1 registers an erased/backup-safe (T,E,s)
//! locator; W2 removes work; a lost ACK retains; `already_settled` WA marks the locator and
//! drops the intent; erasure visits the marked locator. Kill-around-commit for the own-copy
//! transaction and the recovery W1 cut.

use super::fixture::{Case, Fixture};
use super::receive_own_copy::own_copy;
use crate::bus::push_receiver::ack_batch::SourceWa;
use crate::client::own_device_copy::w1::{
    self, Fault, OwnCopyW1, locator_key, run, with_omit_locator,
};
use crate::prelude::*;
use ramflux_storage::{
    ReceiveAckApply, ReceiveAckApplyResult, ReceiveAckOutcome, ReceiveAckResult, ReceiveCover,
    ReceiveCoverKind, ReceiveCoverResult, ReceiveExpectation, ReceiveStage, ReceiveStageResult,
    StorageError,
};
use serde_json::json;

const INTEGRITY: &str = "source effect requires staged receive work";
const BEFORE: &str = "own-copy w1 before-commit";
const TARGET: &str = "sender";
const INCARNATION: &str = "e";
const MESSAGE: &str = "incoming-sibling-envelope";
const SEQUENCE: u64 = 1;
const RECOVERY_SEQ: u64 = 2;

fn gate(db: &AccountDb) -> Result<OwnCopyW1<'static>, SdkError> {
    gate_at(db, 0)
}

fn gate_at(db: &AccountDb, cursor: u64) -> Result<OwnCopyW1<'static>, SdkError> {
    Ok(OwnCopyW1 {
        expected: ReceiveExpectation {
            target: TARGET,
            incarnation: INCARNATION,
            cursor,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    })
}

fn staged(entry: &[u8], sequence: u64) -> ReceiveStage<'_> {
    ReceiveStage {
        target: TARGET,
        incarnation: INCARNATION,
        sequence,
        entry_json: entry,
        admission_key: "authenticated-own-copy",
        retain_until: now_unix_timestamp().saturating_add(300),
        first_seen: 1,
    }
}

fn unique_entry(sequence: u64, payload_hash: &str) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&json!({
        "inbox_seq": sequence,
        "target_delivery_id": TARGET,
        "envelope": {
            "schema": "test",
            "version": 1,
            "domain": "test",
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "sig",
            "envelope_id": format!("env-{sequence}"),
            "source_principal_id": "source",
            "source_device_id": "device",
            "target_delivery_id": TARGET,
            "delivery_class": "opaque_event",
            "priority": "normal",
            "ttl": 60,
            "created_at": 1,
            "encrypted_payload": "cipher",
            "payload_hash": payload_hash
        }
    }))?)
}

fn wire(entry: &GatewayInboxEntry) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&json!({
        "inbox_seq": entry.inbox_seq,
        "target_delivery_id": entry.target_delivery_id,
        "envelope": entry.envelope,
    }))?)
}

fn ledger(account: &LocalBusAccountState, target: &str) -> Case {
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(target, INCARNATION)?;
    Ok(())
}

fn reopen(account: &mut LocalBusAccountState) -> Case {
    account.client.active_account_db = None;
    account.client.unlock_account("sender", b"actor-test-secret")?;
    Ok(())
}

fn locator_present(account: &LocalBusAccountState, message: &str) -> Result<bool, SdkError> {
    Ok(account.client.account_db()?.actor_state_exists(&locator_key(message))?)
}

fn reset_work_present(account: &LocalBusAccountState) -> Result<bool, SdkError> {
    Ok(!account.client.account_db()?.actor_state_keys("dm-pair/reset-work/")?.is_empty())
}

#[tokio::test(flavor = "current_thread")]
async fn own_copy_ack_binding() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}

async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("own-copy-ack-binding")).await?;
    ledger(&fixture.source, TARGET)?;
    let entry = own_copy(&fixture)?;
    let bytes = wire(&entry)?;
    let root = fixture.sibling.client.owned_device_identity()?.root_commitment().to_owned();
    let manifest: crate::SdkDeviceManifestResponse = serde_json::from_value(
        fixture
            .gateway
            .lock()
            .map_err(|_| "gateway")?
            .manifests
            .get(&root)
            .cloned()
            .ok_or("manifest")?,
    )?;
    fixture.source.client.account_db()?.send_direct_message(
        "healthy",
        MESSAGE,
        "peer",
        b"own-copy-locator-owner",
    )?;

    let db = fixture.source.client.account_db()?;
    let refused = gate(db)?.effect(db, SEQUENCE, MESSAGE, || Ok(()));
    assert!(
        matches!(&refused, Err(SdkError::Storage(StorageError::Integrity(text))) if *text == INTEGRITY),
        "{refused:?}"
    );
    assert!(!locator_present(&fixture.source, MESSAGE)?);

    assert_eq!(gate(db)?.stage(db, staged(&bytes, SEQUENCE))?, ReceiveStageResult::Staged);
    let expected = gate(db)?.expected;
    let pre_kill = db.durable_rows_for_test()?;
    let rolled_packet = run(Fault::BeforeCommit, || {
        fixture.source.client.apply_own_copy_w1(&entry, &manifest, expected, SEQUENCE, MESSAGE)
    });
    assert!(
        matches!(&rolled_packet, Err(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "{rolled_packet:?}"
    );
    assert!(!locator_present(&fixture.source, MESSAGE)?);
    assert_eq!(db.durable_rows_for_test()?, pre_kill, "kill-before the real packet writes nothing");
    assert!(
        fixture.source.client.apply_own_copy_w1(&entry, &manifest, expected, SEQUENCE, MESSAGE,)?
    );
    let once_packet = db.durable_rows_for_test()?;
    assert_ne!(once_packet, pre_kill, "the real control/slot/receipt packet must write");
    assert!(locator_present(&fixture.source, MESSAGE)?);
    let locator = fixture
        .source
        .client
        .account_db()?
        .load_actor_state::<w1::SequenceLocator>(&locator_key(MESSAGE))?
        .ok_or("locator")?;
    assert_eq!(locator.target, TARGET);
    assert_eq!(locator.incarnation, INCARNATION);
    assert_eq!(locator.sequence, SEQUENCE);
    assert_eq!(
        fixture.source.client.account_db()?.receive_state_for_test(SEQUENCE)?,
        (Some("staged".to_owned()), 1)
    );

    reopen(&mut fixture.source)?;
    assert!(locator_present(&fixture.source, MESSAGE)?);
    let db = fixture.source.client.account_db()?;
    let expected = gate(db)?.expected;
    assert!(
        fixture.source.client.apply_own_copy_w1(&entry, &manifest, expected, SEQUENCE, MESSAGE,)?
    );
    assert_eq!(
        fixture.source.client.account_db()?.actor_state_keys("own-device/sequence-locator/")?.len(),
        1,
        "re-drive stays a single locator"
    );
    assert_eq!(
        fixture.source.client.account_db()?.durable_rows_for_test()?,
        once_packet,
        "re-drive of the real packet is exactly one effect"
    );

    let db = fixture.source.client.account_db()?;
    assert_eq!(
        db.receive_transaction(gate(db)?.expected, 1, |tx| {
            tx.cover(ReceiveCover {
                sequence: SEQUENCE,
                kind: ReceiveCoverKind::Terminal,
                gaps: &[],
                retain_until: 0,
            })
        })?,
        ReceiveCoverResult::Covered,
        "W2 removes work and writes the ACK intent"
    );
    assert_eq!(db.receive_state_for_test(SEQUENCE)?.0, None, "W2 drops the receipt");
    assert_eq!(db.receive_ledger_snap_for_test(TARGET)?.intents, vec![SEQUENCE]);
    let wa = SourceWa {
        expected: ReceiveExpectation {
            target: TARGET,
            incarnation: INCARNATION,
            cursor: SEQUENCE,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    };
    let lost = [ReceiveAckResult { sequence: SEQUENCE, outcome: ReceiveAckOutcome::Uncertain }];
    assert_eq!(
        wa.apply(
            db,
            ReceiveAckApply {
                incarnation: INCARNATION,
                sequences: &[SEQUENCE],
                results: &lost,
                now: now_unix_timestamp(),
            },
        )?,
        ReceiveAckApplyResult::Applied { settled: 0 }
    );
    let locator =
        db.load_actor_state::<w1::SequenceLocator>(&locator_key(MESSAGE))?.ok_or("locator")?;
    assert!(!locator.acknowledged, "lost ACK reply retains the locator unmarked");
    assert_eq!(db.receive_ledger_snap_for_test(TARGET)?.intents, vec![SEQUENCE]);
    let settled =
        [ReceiveAckResult { sequence: SEQUENCE, outcome: ReceiveAckOutcome::AlreadySettled }];
    assert_eq!(
        wa.apply(
            db,
            ReceiveAckApply {
                incarnation: INCARNATION,
                sequences: &[SEQUENCE],
                results: &settled,
                now: now_unix_timestamp(),
            },
        )?,
        ReceiveAckApplyResult::Applied { settled: 1 }
    );
    let locator =
        db.load_actor_state::<w1::SequenceLocator>(&locator_key(MESSAGE))?.ok_or("locator")?;
    assert!(locator.acknowledged, "already_settled WA marks the locator");
    assert_eq!(db.receive_ledger_snap_for_test(TARGET)?.intents, Vec::<u64>::new());

    db.delete_direct_message("healthy", MESSAGE, "local", "erase-before-wa")?;
    assert!(!locator_present(&fixture.source, MESSAGE)?, "erase before WA must drop the locator");
    assert!(
        db.actor_state_keys("own-device/sequence-locator/")?
            .iter()
            .all(|key| key != &locator_key(MESSAGE)),
        "erased message must not keep its locator"
    );

    let recovery_bytes = unique_entry(RECOVERY_SEQ, "recovery-hash")?;
    let expected = gate_at(db, 1)?.expected;
    assert_eq!(
        gate_at(db, 1)?.stage(db, staged(&recovery_bytes, RECOVERY_SEQ))?,
        ReceiveStageResult::Staged
    );
    let now = now_unix_timestamp();
    let rolled = run(Fault::BeforeCommit, || {
        fixture.source.client.recover_own_copy_w1(&entry, expected, RECOVERY_SEQ, now)
    });
    assert!(
        matches!(&rolled, Err(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "{rolled:?}"
    );
    assert!(!reset_work_present(&fixture.source)?);
    assert!(fixture.source.client.recover_own_copy_w1(&entry, expected, RECOVERY_SEQ, now)?);
    assert!(reset_work_present(&fixture.source)?);
    reopen(&mut fixture.source)?;
    assert!(reset_work_present(&fixture.source)?);

    // L1: a PairRecoveryRequired from the effect rolls back its own reset writes and is returned
    // unchanged. P20 routes that exact error to `recover`; the effect path never leaves reset work.
    let pair_db = fixture.source.client.account_db()?;
    pair_db.send_direct_message("healthy", "pair-recovery", "peer", b"pair")?;
    let pair_bytes = unique_entry(5, "pair-recovery-hash")?;
    let expected = ReceiveExpectation {
        target: TARGET,
        incarnation: INCARNATION,
        cursor: 1,
        generation: 1,
        erasure_generation: pair_db.privacy_erasure_generation()?,
    };
    assert_eq!(
        OwnCopyW1 { expected, generation: 1 }.stage(pair_db, staged(&pair_bytes, 5))?,
        ReceiveStageResult::Staged
    );
    let pair = OwnCopyW1 { expected, generation: 1 }.effect(pair_db, 5, "pair-recovery", || {
        pair_db.persist_actor_state("dm-pair/reset-work/l1", &json!({"pending": true}))?;
        Err::<(), SdkError>(SdkError::PairRecoveryRequired)
    });
    assert!(matches!(&pair, Err(SdkError::PairRecoveryRequired)), "{pair:?}");
    assert!(
        !pair_db.actor_state_exists("dm-pair/reset-work/l1")?,
        "the effect's reset work must not survive a PairRecoveryRequired"
    );
    assert!(!locator_present(&fixture.source, "pair-recovery")?);
    assert_eq!(pair_db.receive_state_for_test(5)?.0.as_deref(), Some("staged"));

    fixture.source.client.account_db()?.send_direct_message(
        "healthy",
        "omit-locator",
        "peer",
        b"omit",
    )?;
    let omit_bytes = unique_entry(4, "omit-hash")?;
    let db = fixture.source.client.account_db()?;
    let expected = ReceiveExpectation {
        target: TARGET,
        incarnation: INCARNATION,
        cursor: 1,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    assert_eq!(
        OwnCopyW1 { expected, generation: 1 }.stage(db, staged(&omit_bytes, 4))?,
        ReceiveStageResult::Staged
    );
    with_omit_locator(|| {
        OwnCopyW1 { expected, generation: 1 }.effect(db, 4, "omit-locator", || {
            crate::client::own_device_copy::receipts::remember(
                db,
                "own-device/committed-packet/omit-locator",
                "omit-fp",
                now_unix_timestamp().saturating_add(900),
                false,
                now_unix_timestamp(),
            )
        })
    })?;
    assert!(db.actor_state_exists(&locator_key("omit-locator"))?);
    db.delete_direct_message("healthy", "omit-locator", "local", "erase-omit")?;
    assert!(
        db.actor_state_exists(&locator_key("omit-locator"))?,
        "omit locator footprint: erase leaves the unbound row (first-leg assertion fails)"
    );

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
