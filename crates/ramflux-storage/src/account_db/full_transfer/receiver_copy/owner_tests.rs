// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared owner witnesses use the existing signed-slot/materialization/DV machinery.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex};
use ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES;
pub(in crate::account_db::full_transfer) type TestResult<T = ()> =
    Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Copy)]
pub(in crate::account_db::full_transfer) struct Case {
    pub name: &'static str,
    pub seed: fn(&AccountDb, &AccountDb) -> TestResult,
    pub before: Option<fn(&BackupDatabase) -> TestResult>,
    pub inspect: fn(&BackupDatabase, &AccountDb) -> TestResult,
    pub conflict: bool,
}
fn open(root: &std::path::Path, anchor: &str, password: &[u8]) -> TestResult<AccountDb> {
    let index = AccountIndex::open(root)?;
    index.create_account("acct", anchor)?;
    Ok(AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", password))?)
}
pub(in crate::account_db::full_transfer) fn run(case: Case) -> TestResult {
    let left = tempfile::Builder::new().prefix(case.name).tempdir()?;
    let right = tempfile::Builder::new().prefix(case.name).tempdir()?;
    let (initial, _, _) = super::super::stage_tests::fixture()?;
    let a = open(left.path(), &initial.grant.source_ref.account_anchor, b"owner-source")?;
    let b = open(right.path(), &initial.grant.destination_ref.account_anchor, b"owner-target")?;
    (case.seed)(&a, &b)?;
    let (record, manifest, bytes) = super::super::receiver_projection::tests::input(&a)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, u64::try_from(index)?, chunk)?;
    }
    let mut copy = stage.pin_receiver_base(&hash)?.copy()?;
    if let Some(before) = case.before {
        let private = BackupDatabase::open_full_receiver_copy(
            &copy.scratch.path.join("private.db"),
            &copy.key,
        )?;
        before(&private)?;
    }
    let result = copy.project(&stage);
    if case.conflict {
        assert!(
            matches!(result, Err(StorageError::PairingField("TransferConflict"))),
            "test: conflicting or non-derived {} generation was accepted: {result:?}",
            case.name
        );
        assert!(
            copy.commit_application(&mut stage, 1000).is_err(),
            "test: failed {} projection minted an application proof",
            case.name
        );
        assert_eq!(
            stage.connection.query_row(
                "SELECT count(*) FROM manifest WHERE verified=1",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            0,
            "test: {} refusal marked the input verified",
            case.name
        );
        return Ok(());
    }
    result?;
    {
        let private = BackupDatabase::open_full_receiver_copy(
            &copy.scratch.path.join("private.db"),
            &copy.key,
        )?;
        (case.inspect)(&private, &b)?;
    }
    let proof = copy.commit_application(&mut stage, 1000)?;
    let signed = proof.signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
        &proof.packet().data_verified_signing_bytes()?,
        [8; 32],
    ))?;
    copy.record_data_verified(&mut stage, &proof, &signed, 1000)?;
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM manifest WHERE verified=1",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1,
        "test: {} normalized bytes did not establish original-branch DV",
        case.name
    );
    Ok(())
}
