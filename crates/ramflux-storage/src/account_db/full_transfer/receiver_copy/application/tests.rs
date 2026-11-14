// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted private application precedes any signed receiver DV or verified bit.
use super::super::super::receiver_projection::tests::{db, input, seed};
use super::*;
use ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_full_receiver_dv_requires_durable_materialized_generation_and_original_branch()
-> TestResult {
    let (initial, _, _) = super::super::super::stage_tests::fixture()?;
    let (aroot, a) = db("receiver-dv-a", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) = db("receiver-dv-b", &initial.grant.destination_ref.account_anchor)?;
    seed(&a, 11, 8)?;
    seed(&b, 21, 9)?;
    let (record, manifest, bytes) = input(&a)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    let mut copy = stage.pin_receiver_base(&hash)?.copy()?;
    assert!(
        copy.commit_application(&mut stage, 1000).is_err(),
        "disk receipt minted an application proof"
    );
    copy.project(&stage)?;
    let application = copy.commit_application(&mut stage, 1000)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &application.packet().data_verified_signing_bytes()?,
        [8; 32],
    );
    assert!(
        application
            .signed_packet(ramflux_crypto::sign_canonical_bytes_with_seed(
                &application.packet().data_verified_signing_bytes()?,
                [7; 32]
            ))
            .is_err(),
        "A signed B's semantic receipt"
    );
    let packet = application.signed_packet(signature)?;
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM manifest WHERE verified=1",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        0
    );
    // An encrypted but wrong durable key cannot stand in for B's actual prepared owner.
    stage.connection.execute("UPDATE receiver_generation SET private_key=zeroblob(32)", [])?;
    assert!(
        copy.record_data_verified(&mut stage, &application, &packet, 1000).is_err(),
        "wrong durable generation key accepted"
    );
    let application = copy.commit_application(&mut stage, 1000)?;
    copy.record_data_verified(&mut stage, &application, &packet, 1000)?;
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM manifest WHERE verified=1",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1
    );
    let bytes: Vec<u8> = stage.connection.query_row(
        "SELECT bytes FROM receiver_receipt WHERE manifest_hash=?1",
        params![hash],
        |row| row.get(0),
    )?;
    assert_eq!(bytes, packet.encode_secret()?.as_slice());
    let path = copy.scratch.path.clone();
    drop(copy);
    assert!(path.exists(), "committed application was removed before DV recovery");
    let fresh = stage.pin_receiver_base(&hash)?;
    assert!(path.exists(), "reclamation removed a generation with a durable key");
    drop(fresh);
    drop(stage);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}
