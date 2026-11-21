// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original-B actual pinned read cut stays frozen across ordinary writes and data-only retries.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, FullStageReference};
use sha2::Digest as _;
type ResultOf<T> = Result<T, Box<dyn std::error::Error>>;
type Staged = (tempfile::TempDir, AccountDb, FullStageReference, SourceManifest);
fn staged() -> ResultOf<Staged> {
    let (initial, _, _) = super::super::stage_tests::fixture()?;
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", &initial.grant.destination_ref.account_anchor)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"reverse-source-secret"))?;
    db.connection
        .execute("UPDATE account_erasure_generation SET generation=3 WHERE singleton=1", [])?;
    veto(&db, 31)?;
    let (mut record, forward, _) = super::super::receiver_projection::tests::input(&db)?;
    let mut transcript = TranscriptV3::from_wire_bytes(&record.transcript)?;
    transcript.initiator.common.recipient_mode = "existing".into();
    transcript.initiator.common.destination_ref = Some(record.grant.destination_ref.clone());
    transcript.responder.common = transcript.initiator.common.clone();
    record.transcript = Zeroizing::new(transcript.to_wire_bytes()?);
    record.th = sha2::Sha256::digest(
        ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&transcript)?,
    )
    .into();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&forward, &forward.manifest.families)?;
    let reference = stage.reference().clone();
    drop(stage);
    Ok((root, db, reference, forward))
}
fn veto(db: &AccountDb, value: u8) -> ResultOf<()> {
    db.connection.execute(
        "INSERT INTO object_erasure_fence VALUES(?1)",
        params![ramflux_protocol::encode_base64url([value; 32])],
    )?;
    Ok(())
}
#[test]
fn pairing_full_linked_reverse_source_is_own_frozen_cut_and_never_recuts_after_write()
-> ResultOf<()> {
    let (_root, db, reference, forward) = staged()?;
    let work = db
        .open_full_stage_reference(reference.clone(), PairingRole::Responder, 1000)?
        .into_reverse_source_work()?;
    db.connection
        .execute("UPDATE account_erasure_generation SET generation=7 WHERE singleton=1", [])?;
    veto(&db, 42)?;
    let draft = work.encode()?;
    let stage = db.open_full_stage_reference(reference.clone(), PairingRole::Responder, 1000)?;
    let first = stage.accept_reverse_source_draft(&draft)?;
    assert_eq!(
        first.source_erasure_generation,
        U64(3),
        "test: reverse included an ordinary B write after pinning"
    );
    assert_eq!(
        first.census_hash, forward.manifest.census_hash,
        "test: reverse replaced the full census with its restrictive subset"
    );
    assert_eq!(
        first.source_ref, forward.manifest.destination_ref,
        "test: reverse signer orientation changed"
    );
    assert_eq!(
        first.destination_ref, forward.manifest.source_ref,
        "test: reverse destination orientation changed"
    );
    assert!(
        first.families.iter().all(|family| family.restrictive),
        "test: reverse streamed nonrestrictive state"
    );
    assert_eq!(
        first
            .families
            .iter()
            .find(|family| family.id == "sql/object_erasure_fence")
            .ok_or("test: veto family")?
            .source_rows,
        U64(1),
        "test: post-cut B veto silently changed the original reverse cut"
    );
    let work = stage.into_reverse_source_work()?;
    veto(&db, 43)?;
    let repeated = work.encode()?;
    let stage = db.open_full_stage_reference(reference, PairingRole::Responder, 1000)?;
    assert_eq!(
        stage.accept_reverse_source_draft(&repeated)?,
        first,
        "test: data-only retry recut or changed B's original reverse manifest"
    );
    assert_eq!(
        db.connection.query_row(
            "SELECT generation FROM account_erasure_generation",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        7,
        "test: reverse preparation rolled back ordinary B data"
    );
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM manifest WHERE direction=1",
            [],
            |row| row.get::<_, u8>(0)
        )?,
        0,
        "test: unsigned reverse source work granted a retained signature or DV"
    );
    let signed = SourceManifest {
        source_signature: ramflux_crypto::sign_canonical_bytes_with_seed(
            &first.signing_bytes()?,
            [8; 32],
        ),
        manifest: first,
    };
    let hash = ramflux_protocol::encode_base64url(
        ramflux_protocol::custody::pairing::full_transfer::manifest_hash(&signed)?,
    );
    let mut stage = stage;
    stage.retain_reverse_manifest(&signed, &forward.manifest.families)?;
    let mut root = ramflux_protocol::custody::pairing::full_transfer::RootHasher::new(
        signed.manifest.total_bytes.0,
    )?;
    for index in 0..signed.manifest.chunk_count.0 {
        root.push(index, &stage.read_reverse_source_wire_chunk(&hash, index)?)?;
    }
    assert_eq!(
        ramflux_protocol::encode_base64url(root.finish()?),
        signed.manifest.chunks_root,
        "test: signed reverse bytes differ from the actual original-B spool"
    );
    Ok(())
}
#[test]
fn pairing_full_linked_reverse_source_refuses_lost_cut_and_cannot_revive_original_unlock()
-> ResultOf<()> {
    let (root, db, reference, _) = staged()?;
    let work = db
        .open_full_stage_reference(reference.clone(), PairingRole::Responder, 1000)?
        .into_reverse_source_work()?;
    drop(work);
    let stage = db.open_full_stage_reference(reference.clone(), PairingRole::Responder, 1000)?;
    assert!(
        matches!(
            stage.into_reverse_source_work(),
            Err(StorageError::PairingField("SnapshotInvalidated"))
        ),
        "test: lost original B cut was silently replaced"
    );
    drop(db);
    drop(root);
    let (root, db, reference, _) = staged()?;
    let work = db
        .open_full_stage_reference(reference, PairingRole::Responder, 1000)?
        .into_reverse_source_work()?;
    drop(db);
    let index = AccountIndex::open(root.path())?;
    let _reopened =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"reverse-source-secret"))?;
    assert!(work.encode().is_err(), "test: new B unlock revived an old cut/key worker");
    Ok(())
}
