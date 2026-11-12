// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted immutable cuts -> signed delta -> independent private A/B contributions.
use super::*;
use crate::account_db::full_transfer::receiver_projection::tests::{db, input, seed};
use ramflux_crypto::custody::pairing::{FullResumeRecord, PairingRole};
use ramflux_protocol::{custody::pairing::full_transfer::*, encode_base64url};
use rusqlite::params;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(n: u8) -> String {
    encode_base64url([n; 32])
}
fn source_record(record: &FullResumeRecord) -> FullResumeRecord {
    FullResumeRecord {
        role: PairingRole::Initiator,
        transcript: record.transcript.clone(),
        th: record.th,
        grant: record.grant.clone(),
        lease: record.lease.clone(),
        transfer_id: record.transfer_id.clone(),
        base_manifest_hash: record.base_manifest_hash.clone(),
        base_record_hash: record.base_record_hash.clone(),
    }
}
fn capture(
    stage: &FullTransferStage<'_>,
    db: &crate::AccountDb,
    root: &Path,
    cut: u64,
    id: &str,
) -> TestResult {
    let path = root.join(format!("delta-input-{cut}.db"));
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    stage.adopt_source_cut(cut, id, &path, snapshot)?;
    Ok(())
}
fn retain(
    stage: &mut FullTransferStage<'_>,
    manifest: &SourceManifest,
    bytes: &[u8],
) -> TestResult<String> {
    let hash = encode_base64url(manifest_hash(manifest)?);
    stage.retain_forward_manifest(manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    stage.verify_forward_root(&hash)?;
    Ok(hash)
}
fn receipt(
    copy: &mut FullReceiverBaseCopy,
    stage: &mut FullTransferStage<'_>,
) -> TestResult<(super::super::FullAppliedDataReceipt, DataPacket)> {
    let proof = copy.commit_application(stage, 1000)?;
    let signed = proof.signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
        &proof.packet().data_verified_signing_bytes()?,
        [8; 32],
    ))?;
    copy.record_data_verified(stage, &proof, &signed, 1000)?;
    Ok((proof, signed))
}
fn delta(
    source: &mut FullTransferStage<'_>,
    base: &SourceManifest,
    next_id: &str,
) -> TestResult<(SourceManifest, zeroize::Zeroizing<Vec<u8>>)> {
    let (bytes, meta) =
        source.encode_fixed_delta_source(1, &base.manifest.snapshot_id, next_id, Vec::new())?;
    let mut body = base.manifest.clone();
    body.kind = ManifestKind::Delta;
    body.snapshot_cut = U64(1);
    body.previous_cut = Some(U64(0));
    body.parent_manifest_hash = Some(encode_base64url(manifest_hash(base)?));
    body.snapshot_id = next_id.to_owned();
    body.families = meta.schema.families;
    body.total_bytes = U64(meta.total_bytes);
    body.chunk_count = U64(meta.chunk_count);
    body.chunks_root = encode_base64url(meta.chunks_root);
    body.source_erasure_generation = U64(meta.source_erasure_generation);
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(&body.signing_bytes()?, [7; 32]);
    Ok((
        SourceManifest { manifest: body, source_signature: signature },
        zeroize::Zeroizing::new(bytes),
    ))
}
fn assert_union(copy: &FullReceiverBaseCopy, b: &crate::AccountDb) -> TestResult {
    let private =
        BackupDatabase::open_full_receiver_copy(&copy.scratch.path.join("private.db"), &copy.key)?;
    for n in [11, 21, 61] {
        assert_eq!(
            private.db.query_row(
                "SELECT count(*) FROM object_payload_dependency WHERE parent_commitment=?1",
                params![h(n)],
                |r| r.get::<_, u64>(0)
            )?,
            1,
            "lost independent or new contribution {n}"
        );
    }
    assert_eq!(
        private.db.query_row(
            "SELECT count(*) FROM object_payload_dependency WHERE parent_commitment=?1",
            params![h(51)],
            |r| r.get::<_, u64>(0)
        )?,
        0,
        "absent A-only content retained"
    );
    assert_eq!(
        private.db.query_row(
            "SELECT count(*) FROM object_identity_replacement WHERE commitment=?1",
            params![h(41)],
            |r| r.get::<_, u64>(0)
        )?,
        1,
        "absent source veto was lost"
    );
    assert_eq!(
        private.db.query_row("SELECT generation FROM account_erasure_generation", [], |r| r
            .get::<_, u64>(0))?,
        10
    );
    assert_eq!(
        b.connection.query_row("SELECT count(*) FROM object_payload_dependency", [], |r| r
            .get::<_, u64>(0))?,
        2,
        "private delta changed live B"
    );
    Ok(())
}

#[test]
fn pairing_full_private_delta_preserves_independent_b_and_vetoes_and_rejects_old_application()
-> TestResult {
    let (initial, _, _) = crate::account_db::full_transfer::stage_tests::fixture()?;
    let (aroot, a) = db("private-delta-a", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) = db("private-delta-b", &initial.grant.destination_ref.account_anchor)?;
    seed(&a, 11, 8)?;
    seed(&b, 21, 9)?;
    a.connection.execute("INSERT INTO object_identity_replacement VALUES(?1)", params![h(41)])?;
    a.connection
        .execute("INSERT INTO object_payload_dependency VALUES(?1,?2)", params![h(51), h(52)])?;
    b.connection
        .execute("INSERT INTO object_payload_dependency VALUES(?1,?2)", params![h(11), h(12)])?;
    let (record, base, bytes) = input(&a)?;
    let mut source = a.create_full_stage_for_test(source_record(&record), 604_900)?;
    let mut target = b.create_full_stage_for_test(record, 604_900)?;
    capture(&source, &a, &aroot, 0, &base.manifest.snapshot_id)?;
    let hash = retain(&mut target, &base, &bytes)?;
    let mut copy = target.pin_receiver_base(&hash)?.copy()?;
    copy.project(&target)?;
    let (old, old_packet) = receipt(&mut copy, &mut target)?;
    a.connection
        .execute("DELETE FROM object_identity_replacement WHERE commitment=?1", params![h(41)])?;
    a.connection.execute(
        "DELETE FROM object_payload_dependency WHERE parent_commitment IN(?1,?2)",
        params![h(11), h(51)],
    )?;
    a.connection
        .execute("INSERT INTO object_payload_dependency VALUES(?1,?2)", params![h(61), h(62)])?;
    a.connection.execute("UPDATE account_erasure_generation SET generation=10", [])?;
    let next_id = h(71);
    capture(&source, &a, &aroot, 1, &next_id)?;
    let (manifest, bytes) = delta(&mut source, &base, &next_id)?;
    let hash = retain(&mut target, &manifest, &bytes)?;
    copy.project_delta(&target, &hash)?;
    // Advance the actual durable generation first. Otherwise the old SQL row alone
    // rejects this retry and never exercises the current input/root proof boundary.
    let _latest_application = copy.commit_application(&mut target, 1000)?;
    assert!(
        copy.record_data_verified(&mut target, &old, &old_packet, 1000).is_err(),
        "old input proof certified the successor generation"
    );
    let (_, packet) = receipt(&mut copy, &mut target)?;
    let DataPacket::DataVerified { manifest_hash, .. } = packet else {
        return Err("DV".into());
    };
    assert_eq!(manifest_hash, hash);
    assert_union(&copy, &b)?;
    drop(copy);
    drop(source);
    drop(target);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}

#[test]
fn pairing_full_duplex_requires_both_durable_original_receipts_and_final_delta() -> TestResult {
    let (initial, _, _) = crate::account_db::full_transfer::stage_tests::fixture()?;
    let (aroot, a) = db("duplex-a", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) = db("duplex-b", &initial.grant.destination_ref.account_anchor)?;
    seed(&a, 11, 8)?;
    b.connection.execute("INSERT INTO pairing_floor(account_id,account_anchor,issued_seq,next_generation) VALUES('acct',?1,4,7)",params![b.principal_commitment])?;
    let (mut record, base, bytes) = input(&a)?;
    // Well-shaped local envelope for data-only storage tests. Native authenticity
    // is exercised separately by the SDK relay fixture, not by this envelope.
    record.lease = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(
        &ramflux_protocol::custody::Envelope {
            body: ramflux_protocol::custody::pairing::full_transfer::lease::DataLease {
                schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
                version: 1,
                lease_id: h(99),
                grant: record.grant.clone(),
                issued_at: 100,
                expires_at: 604_900,
            },
            signature: encode_base64url([0; 64]),
        },
    )?);

    let mut source = a.create_full_stage_for_test(source_record(&record), 604_900)?;
    let mut target = b.create_full_stage_for_test(record, 604_900)?;
    capture(&source, &a, &aroot, 0, &base.manifest.snapshot_id)?;
    source.retain_source_manifest(&base, super::super::super::full_transfer_catalog())?;
    let hash = retain(&mut target, &base, &bytes)?;
    let mut copy = target.pin_receiver_base(&hash)?.copy()?;
    copy.project(&target)?;
    let (_, packet) = receipt(&mut copy, &mut target)?;
    source.record_source_data_verified(&packet, 1000)?;
    assert!(source.verified_duplex(1000).is_err(), "base-only receipt opened controls");
    let body = target.prepare_empty_reverse_manifest()?;
    let reverse = SourceManifest {
        source_signature: ramflux_crypto::sign_canonical_bytes_with_seed(
            &body.signing_bytes()?,
            [8; 32],
        ),
        manifest: body,
    };
    let catalog = super::super::super::full_transfer_catalog()
        .iter()
        .map(super::super::super::FamilyRule::manifest_family)
        .collect::<Result<Vec<_>, _>>()?;
    target.retain_reverse_manifest(&reverse, &catalog)?;
    source.retain_reverse_manifest(&reverse, &catalog)?;
    let proof = source.apply_empty_reverse(1000)?;
    let reverse_packet = proof.signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
        &proof.packet().data_verified_signing_bytes()?,
        [7; 32],
    ))?;
    source.record_reverse_application_receipt(&proof, &reverse_packet, 1000)?;
    a.connection.execute(
        "DELETE FROM object_payload_dependency WHERE parent_commitment=?1",
        params![h(11)],
    )?;
    let next_id = h(71);
    capture(&source, &a, &aroot, 1, &next_id)?;
    let (manifest, bytes) = delta(&mut source, &base, &next_id)?;
    source.retain_source_manifest(&manifest, super::super::super::full_transfer_catalog())?;
    let hash = retain(&mut target, &manifest, &bytes)?;
    copy.project_delta(&target, &hash)?;
    let (_, packet) = receipt(&mut copy, &mut target)?;
    assert!(
        source.verified_duplex(1000).is_err(),
        "unsigned current forward receipt opened controls"
    );
    source.record_source_data_verified(&packet, 1000)?;
    let own = source.verified_duplex(1000)?;
    assert!(target.verified_duplex(1000).is_err(), "missing reverse receipt opened controls");
    target.record_reverse_source_receipt(&reverse_packet, 1000)?;
    let peer = target.verified_duplex(1000)?;
    assert_eq!(own.manifest_chain_hash(), peer.manifest_chain_hash());
    assert_eq!(own.data_verified_hash(), peer.data_verified_hash());
    assert_eq!(own.target_restrictions_root(), peer.target_restrictions_root());
    let mut rebased = rebase_current_b(copy, &mut target, &b)?;
    retain_rebased_atomically(&mut rebased, &target)?;
    let prepared = prepared_database(rebased, &target, &broot)?;
    target.connection.execute("UPDATE reverse_source_receipt SET bytes=x'7b7d'", [])?;
    assert!(target.verified_duplex(1000).is_err(), "corrupt reverse receipt opened controls");
    source
        .connection
        .execute("UPDATE source_receipt SET bytes=x'7b7d' WHERE manifest_hash=?1", params![hash])?;
    assert!(source.verified_duplex(1000).is_err(), "corrupt forward receipt opened controls");
    let selected = select_prepared(prepared, &target, &reverse_packet)?;
    drop(selected);
    drop(source);
    drop(target);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}

fn retain_rebased_atomically(
    copy: &mut FullReceiverBaseCopy,
    stage: &FullTransferStage<'_>,
) -> TestResult {
    let old: (Vec<u8>, String, Vec<u8>) = stage.connection.query_row(
        "SELECT generation_nonce,workspace,private_key FROM receiver_generation",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let receipt: Vec<u8> = stage.connection.query_row(
        "SELECT bytes FROM receiver_receipt WHERE manifest_hash=?1",
        params![copy.hash],
        |row| row.get(0),
    )?;
    stage.connection.execute_batch("CREATE TRIGGER refuse_receipt_rebind BEFORE UPDATE ON receiver_receipt BEGIN SELECT RAISE(ABORT,'forced receipt rebind failure'); END;")?;
    assert!(
        copy.retain_for_installation(stage, 1000).is_err(),
        "G1 ignored receipt transaction failure"
    );
    let unchanged: bool = stage.connection.query_row(
        "SELECT generation_nonce=?1 AND workspace=?2 AND private_key=?3 FROM receiver_generation",
        params![old.0, old.1, old.2],
        |row| row.get(0),
    )?;
    assert!(unchanged, "failed receipt rebind changed durable generation");
    stage.connection.execute_batch("DROP TRIGGER refuse_receipt_rebind;")?;
    copy.retain_for_installation(stage, 1000)?;
    let retained: bool=stage.connection.query_row("SELECT EXISTS(SELECT 1 FROM receiver_generation g JOIN receiver_receipt r ON g.manifest_hash=r.manifest_hash AND g.generation_nonce=r.generation_nonce WHERE g.generation_nonce=?1 AND g.workspace=?2 AND r.bytes=?3)",params![copy.union_encoding().ok_or("union")?.generation_nonce.as_slice(),copy.scratch.path.file_name().and_then(|name|name.to_str()).ok_or("workspace")?,receipt],|row|row.get(0))?;
    assert!(retained, "G1 lost its qualified generation or changed the original signed input");
    stage.verified_duplex(1000)?;
    Ok(())
}

fn prepared_database(
    copy: FullReceiverBaseCopy,
    stage: &FullTransferStage<'_>,
    root: &Path,
) -> TestResult<crate::FullPreparedReceiverDatabase> {
    let generation = root.join("accounts/acct").join(format!("generation_{}", h(88)));
    std::fs::create_dir(&generation)?;
    let union = copy.union_encoding().ok_or("prepared union")?;
    let adoption = crate::AdoptionRow {
        account_id: "acct".into(),
        operation_id: h(89),
        record_hash: h(90),
        local_ref: ramflux_protocol::canonical_json_bytes(
            &stage.resume_record()?.grant.destination_ref,
        )?,
        local_role: "primary".into(),
        branch_vault_ref: "own-b-branch".into(),
        data_vault_ref: "own-b-data".into(),
        primary_vault_ref: Some("own-b-primary".into()),
        full_generation_nonce: Some(encode_base64url(union.generation_nonce)),
        full_initial_union_root: Some(encode_base64url(union.chunks_root)),
    };
    let before = stage.db.account_index.account("acct")?;
    let work =
        copy.into_generation_database_work(stage, generation.join("account.db"), adoption, 1000)?;
    let prepared = work.prepare()?;
    prepared.verify(stage)?;
    assert_eq!(stage.db.account_index.account("acct")?, before, "G1 selected a live generation");
    let private = BackupDatabase::open_full_receiver_copy(prepared.path(), &stage.db.current_key)?;
    assert_eq!(
        private.db.query_row(
            "SELECT issued_seq,next_generation FROM pairing_floor WHERE account_id='acct'",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
        )?,
        (4, 7),
        "G1 stripped B-local pairing state"
    );
    private
        .db
        .execute("UPDATE object_payload_dependency SET child_commitment=?1", params![h(92)])?;
    drop(private);
    assert!(
        prepared.verify(stage).is_err(),
        "G1 trusted the scratch root without checking copied rows"
    );
    Ok(prepared)
}

fn rebase_current_b(
    old: FullReceiverBaseCopy,
    stage: &mut FullTransferStage<'_>,
    b: &crate::AccountDb,
) -> TestResult<FullReceiverBaseCopy> {
    let before = stage.verified_duplex(1000)?;
    // A removed this dependency in its signed delta. B independently acquired
    // the identical key after that cut, so replaying A's absence must keep B.
    for n in [11, 93] {
        b.connection.execute(
            "INSERT INTO object_payload_dependency VALUES(?1,?2)",
            params![h(n), h(n + 1)],
        )?;
    }
    assert!(old.verify_materialization(stage).is_err(), "changed B reused its old observation");
    let base = stage.resume_record()?.base_manifest_hash;
    let mut copy = stage.pin_receiver_base(&base)?.copy()?;
    copy.project_retained_chain(stage, 1000)?;
    drop(old);
    let private =
        BackupDatabase::open_full_receiver_copy(&copy.scratch.path.join("private.db"), &copy.key)?;
    for n in [11, 93] {
        assert_eq!(private.db.query_row("SELECT count(*) FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2",params![h(n),h(n+1)],|row|row.get::<_,u64>(0))?,1,"rebase lost an independent intervening B write");
    }
    drop(private);
    let (_, packet) = receipt(&mut copy, stage)?;
    assert_eq!(
        encode_base64url(packet.data_verified_hash()?),
        before.data_verified_hash(),
        "B rebase changed the frozen source receipt"
    );
    refuse_selected_repin(stage, b, &base)?;
    Ok(copy)
}
fn refuse_selected_repin(
    stage: &FullTransferStage<'_>,
    b: &crate::AccountDb,
    base: &str,
) -> TestResult {
    // A marker alone is not G2 proof; even this incomplete marker must fail
    // closed instead of allowing the same imported A to be relabeled as B.
    for origin in ["full_transfer", "unknown"] {
        let bytes = ramflux_protocol::canonical_json_bytes(
            &serde_json::json!({"origin":origin,"full_transfer":{"stage_id":stage.reference().stage_id}}),
        )?;
        b.account_index.connection.execute("INSERT INTO account_backup_generation VALUES('acct',?1) ON CONFLICT(local_account_id) DO UPDATE SET manifest_json=excluded.manifest_json",params![bytes])?;
        assert!(
            stage.pin_receiver_base(base).is_err(),
            "selected full generation was repinned as independent B"
        );
    }
    b.account_index
        .connection
        .execute("DELETE FROM account_backup_generation WHERE local_account_id='acct'", [])?;
    Ok(())
}

fn select_prepared(
    prepared: crate::FullPreparedReceiverDatabase,
    stage: &FullTransferStage<'_>,
    reverse: &DataPacket,
) -> TestResult<crate::FullSelectedReceiverGeneration> {
    stage.connection.execute(
        "UPDATE reverse_source_receipt SET bytes=?1",
        params![reverse.encode_secret()?.as_slice()],
    )?;
    let b = stage.db;
    let root = b.account_index.root();
    let private = BackupDatabase::open_full_receiver_copy(prepared.path(), &b.current_key)?;
    for n in [11, 93] {
        private.db.execute(
            "UPDATE object_payload_dependency SET child_commitment=?1 WHERE parent_commitment=?2",
            params![h(n + 1), h(n)],
        )?;
    }
    let (nonce,initial):(String,String)=private.db.query_row("SELECT full_generation_nonce,full_initial_union_root FROM pairing_adoption WHERE account_id='acct'",[],|row|Ok((row.get(0)?,row.get(1)?)))?;
    drop(private);
    prepared.verify(stage)?;
    let object_dir = prepared.path().parent().ok_or("generation parent")?.join("objects");
    std::fs::write(object_dir.join("unaccounted-payload"), b"must never be silently omitted")?;
    assert!(prepared.verify(stage).is_err(), "unaccounted object payload was admitted");
    std::fs::remove_file(object_dir.join("unaccounted-payload"))?;
    let old = b.account_index.account("acct")?;
    let prepared_path = prepared.path().to_owned();
    let path = prepared_path.strip_prefix(root)?.to_str().ok_or("database relative path")?;
    let objects = object_dir.strip_prefix(root)?.to_str().ok_or("object relative path")?;
    let mut marker = serde_json::json!({
        "schema":"ramflux.local.native_data_generation.v1","origin":"full_transfer",
        "local_account_id":"acct","account_anchor":b.principal_commitment,"operation_id":h(89),"record_hash":h(90),
        "full_transfer":{
            "chain_hash":stage.verified_duplex(1000)?.manifest_chain_hash(),"stage_id":stage.reference().stage_id,
            "generation_nonce":nonce,"initial_union_root":initial,"db_relative_path":path,"object_relative_path":objects,
            "expected_prior_generation":{"db_relative_path":old.db_relative_path,"object_relative_path":old.object_dir_relative_path},
            "expected_prior_privacy_epoch":"0"
        }
    });
    let wrapped = b.wrap_current_db_key(&[91; 32])?;
    b.account_index.store_wrapped_db_key("acct", &wrapped)?;
    marker["full_transfer"]["initial_union_root"] = h(92).into();
    let bad = ramflux_protocol::canonical_json_bytes(&marker)?;
    let index_install = crate::BackupIndexInstall {
        account_id: "acct",
        principal_commitment: &b.principal_commitment,
        db_relative_path: path,
        object_relative_path: objects,
        manifest_json: &bad,
        wrapped_key: &wrapped,
    };
    assert!(
        prepared.commit_index_selection(stage, &index_install, 1000).is_err(),
        "foreign G2 root selected G1"
    );
    assert_eq!(b.account_index.account("acct")?, old);
    marker["full_transfer"]["initial_union_root"] = initial.into();
    let good = ramflux_protocol::canonical_json_bytes(&marker)?;
    let data = prepared.select(
        stage,
        &crate::BackupIndexInstall { manifest_json: &good, ..index_install },
        1000,
    )?;
    assert!(
        b.connection.execute("DELETE FROM object_payload_dependency", []).is_err(),
        "old B writer survived G2"
    );
    assert!(root.join(old.db_relative_path).exists(), "G2 reclaimed the old generation before G3");
    let selected = data.open()?;
    assert_eq!(selected.path, prepared_path);
    assert_eq!(
        selected.pairing_adoption()?.ok_or("selected adoption")?.full_generation_nonce.as_deref(),
        Some(nonce.as_str())
    );
    assert_eq!(
        selected.connection.query_row(
            "SELECT count(*) FROM object_payload_dependency",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        2,
        "G2 lost independent B rows"
    );
    data.require_database(&selected)?;
    drop(selected);
    stage.io_cancel_handle().cancel();
    assert!(data.open().is_err(), "G2 handback revived a generation after root lock");
    Ok(data)
}
