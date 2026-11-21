// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real erased-input capture and imported-verifier denial, with independent A/B keys.
use super::*;
use crate::BackupDatabase;
use crate::account_db::full_transfer::{full_transfer_catalog, write_full_scalar_sql_row};
use crate::account_db::receive::erased_input::ErasedTuple;
use crate::{AccountDb, AccountDbKey, AccountIndex};
use ramflux_protocol::custody::{DeviceRef, pairing::full_transfer::read_record_header};
use ramflux_protocol::{Envelope, encode_base64url};
use rusqlite::params;
use std::sync::{Arc, atomic::AtomicBool};
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn database(label: &str) -> TestResult<(tempfile::TempDir, AccountDb)> {
    let root = tempfile::Builder::new().prefix(label).tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", &encode_base64url([3; 32]))?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", label.as_bytes()))?;
    Ok((root, db))
}
fn envelope(hash: &str) -> TestResult<Envelope> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519",
        "signature":"sig","envelope_id":"env","source_principal_id":"peer-principal",
        "source_device_id":"peer-device","target_delivery_id":"target","delivery_class":"opaque_event",
        "priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":hash
    }))?)
}
fn encoded(db: &AccountDb) -> TestResult<Zeroizing<Vec<u8>>> {
    let rule = full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == FAMILY)
        .ok_or("test: erased-input owner missing")?;
    Ok(db.connection.call(move |raw| {
        raw.query_row(
            "SELECT selector,bundle_id,expires_at FROM receive_erased_input LIMIT 1",
            [],
            move |row| {
                let mut bytes = Zeroizing::new(Vec::new());
                Ok(write_full_scalar_sql_row(rule, row, &mut *bytes).map(|_| bytes))
            },
        )
    })??)
}
fn project(private: &mut BackupDatabase, source: &DeviceRef, bytes: &[u8]) -> TestResult {
    let mut input = bytes;
    let header = read_record_header(&mut input)?.ok_or("test: input denial header absent")?;
    private.apply_full_fixed_base_record(source, &header, &mut input)?;
    assert!(input.is_empty(), "test: erased-input owner left trailing unchecked cells");
    Ok(())
}

#[test]
fn full_erased_input_round_trip_preserves_max_and_matches_imported_bundle_beyond_sixteen()
-> TestResult {
    let (_aroot, a) = database("input-denial-source")?;
    let (broot, b) = database("input-denial-target")?;
    let event = envelope("exact-hash")?;
    let tuple = ErasedTuple::from_envelope(&event);
    let now = crate::unix_now();
    a.record_erased_input_at(&tuple, now, 60, now)?;
    let early = encoded(&a)?;
    a.record_erased_input_at(&tuple, now, 600, now)?;
    let later = encoded(&a)?;
    let (id, keys): (String, Zeroizing<Vec<u8>>) = a.connection.query_row(
        "SELECT bundle_id,subkeys FROM account_mac_bundle WHERE is_current=1",
        [],
        |row| Ok((row.get(0)?, Zeroizing::new(row.get(1)?))),
    )?;
    let path = broot.path().join("private.db");
    let snapshot =
        b.write_full_transfer_snapshot_cancellable(&path, Arc::new(AtomicBool::new(false)))?;
    let mut private = BackupDatabase::open_full_receiver_copy(&path, &snapshot.key)?;
    let source = DeviceRef {
        account_anchor: encode_base64url([3; 32]),
        device_id: "source".into(),
        device_epoch: 1,
    };
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    for n in 1..=20_u8 {
        let keys = Zeroizing::new([n; 192]);
        let id = crate::account_db::mac_subkeys::bundle_id(keys.as_slice());
        let earlier = DeviceRef { device_id: format!("earlier-{n:02}"), ..source.clone() };
        private.import_full_mac_verifier(&earlier, &id, keys.as_slice())?;
    }
    private.import_full_mac_verifier(&source, &id, &keys)?;
    project(&mut private, &source, &early)?;
    project(&mut private, &source, &later)?;
    project(&mut private, &source, &early)?;
    private.db.execute_batch("COMMIT")?;
    assert_eq!(
        private.db.query_row("SELECT expires_at FROM receive_erased_input", [], |row| row
            .get::<_, i64>(0))?,
        now + 900,
        "test: replay shortened the merged input-erasure denial"
    );
    assert_eq!(
        private.db.query_row(
            "SELECT count(*) FROM account_mac_bundle WHERE is_current=1",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1,
        "test: imported verifier became B's active MAC owner"
    );
    assert!(
        crate::account_db::mac_subkeys::full::imported_erased_input_matches(
            &private.db,
            &tuple.canonical()?,
            now
        )?,
        "test: imported erased-input marker was lost beyond the local bundle limit"
    );
    let different = envelope("different-hash")?;
    assert!(
        !crate::account_db::mac_subkeys::full::imported_erased_input_matches(
            &private.db,
            &ErasedTuple::from_envelope(&different).canonical()?,
            now
        )?,
        "test: transferred denial matched another authenticated tuple"
    );
    assert!(
        !crate::account_db::mac_subkeys::full::imported_erased_input_matches(
            &private.db,
            &tuple.canonical()?,
            now + 900
        )?,
        "test: expired imported denial remained live"
    );
    assert!(
        !b.erased_input_matches_at(&event, now)?,
        "test: private import changed B's live receive gate"
    );
    drop(private);
    let reopened = BackupDatabase::open_full_receiver_copy(&path, &snapshot.key)?;
    assert!(
        crate::account_db::mac_subkeys::full::imported_erased_input_matches(
            &reopened.db,
            &tuple.canonical()?,
            now
        )?,
        "test: encrypted reopen lost imported erasure restriction"
    );
    Ok(())
}

#[test]
fn full_erased_input_refuses_unknown_source_bundle_before_encoding() -> TestResult {
    let (_root, a) = database("input-denial-unknown-bundle")?;
    let event = envelope("source-cut-hash")?;
    let now = crate::unix_now();
    a.record_erased_input_at(&ErasedTuple::from_envelope(&event), now, 60, now)?;
    a.connection.execute(
        "UPDATE receive_erased_input SET bundle_id=?1",
        params![encode_base64url([99; 32])],
    )?;
    let mut preparation = a.prepare_full_transfer_source()?;
    let snapshot = encode_base64url([7; 32]);
    preparation.capture_base_cut(&snapshot)?;
    assert!(
        matches!(
            preparation.encode_fixed_base_source(&snapshot, std::io::sink()),
            Err(StorageError::PairingField("UnsupportedRecord"))
        ),
        "test: source exported a denial without its verifier association"
    );
    Ok(())
}

#[test]
fn full_erased_input_source_cut_uses_the_typed_owner() -> TestResult {
    let (_root, a) = database("input-denial-source-cut")?;
    let event = envelope("source-cut-hash")?;
    let now = crate::unix_now();
    a.record_erased_input_at(&ErasedTuple::from_envelope(&event), now, 60, now)?;
    let mut preparation = a.prepare_full_transfer_source()?;
    let snapshot = encode_base64url([7; 32]);
    preparation.capture_base_cut(&snapshot)?;
    let (_, encoding) = preparation.encode_fixed_base_source(&snapshot, std::io::sink())?;
    let family = encoding
        .schema
        .families
        .iter()
        .find(|family| family.id == FAMILY)
        .ok_or("test: source census omitted erased-input family")?;
    assert_eq!(
        family.portable_records.0, 1,
        "test: source cut omitted the actual erased-input record"
    );
    assert!(family.restrictive, "test: erased input escaped the reverse restrictive catalog");
    Ok(())
}

#[test]
fn full_erased_input_materialized_union_normalizes_independent_target_maximum() -> TestResult {
    use crate::account_db::full_transfer::receiver_projection::tests::{db, input};
    use ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES;
    let (initial, _, _) = crate::account_db::full_transfer::stage_tests::fixture()?;
    let (aroot, a) = db("erased-input-dv-a", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) = db("erased-input-dv-b", &initial.grant.destination_ref.account_anchor)?;
    let event = envelope("materialized-hash")?;
    a.record_erased_input_at(&ErasedTuple::from_envelope(&event), 1000, 60, 1000)?;
    let source = initial.grant.source_ref.clone();
    let (id, keys): (String, Zeroizing<Vec<u8>>) = a.connection.query_row(
        "SELECT bundle_id,subkeys FROM account_mac_bundle WHERE is_current=1",
        [],
        |row| Ok((row.get(0)?, Zeroizing::new(row.get(1)?))),
    )?;
    // B already retained this data-only verifier and a stronger denial from an earlier
    // qualified import. It still has its own independent current MAC bundle.
    b.connection.call(move |raw| {
        Ok(crate::account_db::mac_subkeys::full::import_into_private_generation(
            raw, &source, &id, &keys,
        ))
    })??;
    let selector: String =
        a.connection
            .query_row("SELECT selector FROM receive_erased_input", [], |row| row.get(0))?;
    let bundle: String =
        a.connection
            .query_row("SELECT bundle_id FROM receive_erased_input", [], |row| row.get(0))?;
    b.connection.execute(
        "INSERT INTO receive_erased_input VALUES(?1,?2,1900)",
        params![selector, bundle],
    )?;
    let (record, manifest, bytes) = input(&a)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, u64::try_from(index)?, chunk)?;
    }
    let mut copy = stage.pin_receiver_base(&hash)?.copy()?;
    copy.project(&stage)?;
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
        "test: actual normalized receiver bytes could not establish DataVerified"
    );
    assert_eq!(
        b.connection.query_row("SELECT expires_at FROM receive_erased_input", [], |row| row
            .get::<_, i64>(0))?,
        1900,
        "test: prepared-generation application changed B's original denial"
    );
    drop(copy);
    drop(stage);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}
