// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cold encrypted chunk recovery; native lease admission remains a separate endpoint gate.
use super::{CHUNK_BYTES, PairingRole, TestResult, U64, Zeroizing, fixture, h};
use crate::{AccountDb, AccountDbKey, AccountIndex};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

#[test]
fn primary_transfer_full_crash_resume_exact_chunks() -> TestResult {
    for retained in [1_usize, 2] {
        cold_prefix(retained)?;
    }
    Ok(())
}

fn cold_prefix(retained: usize) -> TestResult {
    let owner = tempfile::tempdir()?;
    let index = AccountIndex::open(owner.path())?;
    let (record, manifest, plaintext) = fixture()?;
    index.create_account("acct", &record.grant.destination_ref.account_anchor)?;
    let key = AccountDbKey::derive("acct", b"original-cold-data-password");
    let db = AccountDb::open(&index, "acct", &key)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).take(retained).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    let reference = stage.reference().clone();
    let path = stage.directory.join("seg-f-0-0.bin");
    let prefix = super::super::stage::read_bounded(&path, 2 * 262_172)?;
    drop(stage);
    drop(db);
    let db = AccountDb::open(&index, "acct", &key)?;
    let mut stage = db.open_full_stage_reference(reference, PairingRole::Responder, 604_801)?;
    assert_eq!(
        stage.revalidate_forward_prefix(&hash)?,
        Some(retained as u64 - 1),
        "test: cold recovery forgot a durable chunk"
    );
    assert!(
        stage.verify_forward_root(&hash).is_err(),
        "test: incomplete cold prefix became complete"
    );
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        assert_eq!(
            stage.retain_forward_chunk(&hash, index as u64, chunk)?,
            index >= retained,
            "test: cold resume rewrote a durable chunk"
        );
    }
    let mut preserved = vec![0; prefix.len()];
    super::super::stage::open_regular(&path, false)?.read_exact(&mut preserved)?;
    assert_eq!(
        preserved.as_slice(),
        prefix.as_slice(),
        "test: cold resume changed previously receipted ciphertext or nonce"
    );
    stage.verify_forward_root(&hash)?;
    let mut output = Zeroizing::new(Vec::new());
    stage.forward_reader(&hash)?.take(plaintext.len() as u64 + 1).read_to_end(&mut output)?;
    assert_eq!(
        output.as_slice(),
        plaintext.as_slice(),
        "test: resumed chunks changed the original signed stream"
    );
    assert!(
        !stage.connection.query_row(
            "SELECT verified FROM manifest WHERE manifest_hash=?1",
            rusqlite::params![hash],
            |row| row.get::<_, bool>(0)
        )?,
        "test: exact ciphertext/root recovery fabricated semantic DV"
    );
    Ok(())
}

#[test]
fn primary_transfer_full_tamper_root_and_resume_binding() -> TestResult {
    let owner = tempfile::tempdir()?;
    let index = AccountIndex::open(owner.path())?;
    let (record, manifest, plaintext) = fixture()?;
    index.create_account("acct", &record.grant.destination_ref.account_anchor)?;
    let key = AccountDbKey::derive("acct", b"tamper-bound-data-password");
    let db = AccountDb::open(&index, "acct", &key)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let mut altered = manifest.clone();
    altered.manifest.chunks_root = h(99);
    altered.source_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&altered.manifest.signing_bytes()?, [7; 32]);
    assert!(
        stage.retain_forward_manifest(&altered, &manifest.manifest.families).is_err(),
        "test: signed replacement root escaped the frozen manifest commitment"
    );
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    stage.verify_forward_root(&hash)?;
    let reference = stage.reference().clone();
    let path = stage.directory.join("seg-f-0-0.bin");
    let mut file = super::super::stage::open_regular(&path, true)?;
    file.seek(SeekFrom::Start(262_172 + 12))?;
    file.write_all(&[0, 1, 2, 3])?;
    file.sync_all()?;
    drop(file);
    drop(stage);
    drop(db);
    let db = AccountDb::open(&index, "acct", &key)?;
    for variant in 0..3 {
        let mut wrong = reference.clone();
        match variant {
            0 => wrong.record_digest = h(98),
            1 => wrong.lease_expires_at = U64(604_901),
            _ => wrong.stage_id = h(97),
        };
        assert!(
            db.open_full_stage_reference(wrong, PairingRole::Responder, 604_801).is_err(),
            "test: foreign resume metadata was accepted: {variant}"
        );
    }
    assert!(
        db.open_full_stage_reference(reference.clone(), PairingRole::Initiator, 604_801).is_err(),
        "test: source role opened B's stage key"
    );
    let stage = db.open_full_stage_reference(reference, PairingRole::Responder, 604_801)?;
    assert_eq!(
        stage.revalidate_forward_prefix(&hash)?,
        Some(0),
        "test: cold resume trusted a receipted corrupt suffix"
    );
    assert!(
        stage.verify_forward_root(&hash).is_err(),
        "test: corrupt ciphertext remained a complete root"
    );
    assert!(
        !stage.connection.query_row(
            "SELECT verified FROM manifest WHERE manifest_hash=?1",
            rusqlite::params![hash],
            |row| row.get::<_, bool>(0)
        )?,
        "test: tampering restored semantic verification"
    );
    Ok(())
}
