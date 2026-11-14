// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data verifier owner only; the cfg(test) index selection is not native/G1-G3 approval.
use super::full::*;
use super::{Bundle, bundle_id};
use crate::{
    AccountDb, AccountDbKey, AccountIndex, BackupDatabase, BackupIndexInstall, WrappedAccountDbKey,
};
use ramflux_protocol::{custody::DeviceRef, encode_base64url};
use zeroize::Zeroizing;
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn source() -> DeviceRef {
    DeviceRef {
        account_anchor: encode_base64url([2; 32]),
        device_id: "original-source".into(),
        device_epoch: 1,
    }
}

fn select_data_fixture(index: &AccountIndex, source: &DeviceRef) -> ResultOf {
    let wrapped = WrappedAccountDbKey {
        key_wrapping_provider: "test".into(),
        key_wrapping_ref: "test".into(),
        nonce: [1; 12],
        wrapped_key: vec![2; 48],
    };
    index.install_backup_generation(&BackupIndexInstall {
        account_id: "acct",
        principal_commitment: &source.account_anchor,
        db_relative_path: "accounts/acct/full-private/account.db",
        object_relative_path: "accounts/acct/full-private",
        manifest_json: b"{}",
        wrapped_key: &wrapped,
    })?;
    Ok(())
}

#[test]
fn pairing_full_imported_mac_verifiers_are_indexed_source_qualified_and_leave_current_unchanged()
-> ResultOf {
    let root = crate::tests::temp_root("full-imported-macs");
    let index = AccountIndex::open(&root)?;
    let source = source();
    index.create_account("acct", &source.account_anchor)?;
    let key = AccountDbKey::derive("acct", b"full-imported-mac-local-test");
    let db = AccountDb::open(&index, "acct", &key)?;
    let current: String = db.connection.query_row(
        "SELECT bundle_id FROM account_mac_bundle WHERE is_current=1",
        [],
        |r| r.get(0),
    )?;
    let generation = root.join("accounts/acct/full-private");
    std::fs::create_dir_all(&generation)?;
    let path = generation.join("account.db");
    let snapshot = db.pin_full_transfer_cut()?.write_private_snapshot(
        &path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut private = BackupDatabase::open(&path, &snapshot.key)?;
    for value in 1..=40_u8 {
        let bundle = Bundle::derive(&[value; 32]);
        private.import_full_mac_verifier(&source, &bundle.id, &bundle.keys)?;
        private.import_full_mac_verifier(&source, &bundle.id, &bundle.keys)?;
    }
    let keys = Zeroizing::new([44; 192]);
    assert!(
        private
            .import_full_mac_verifier(&source, &encode_base64url([0; 32]), keys.as_slice())
            .is_err()
    );
    let mut foreign = source.clone();
    foreign.account_anchor = encode_base64url([99; 32]);
    assert!(
        private
            .import_full_mac_verifier(&foreign, &bundle_id(keys.as_slice()), keys.as_slice())
            .is_err()
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM full_imported_mac_bundle", [], |r| r
            .get::<_, u64>(0))?,
        40
    );
    check_backup_owner(&db, &root, &path, &snapshot.key, &mut private)?;
    drop(private);
    drop(db);
    // Real selected DB reopen for the data owner. This test-only wrapper/manifest is
    // deliberately NOT a network-acceptable install or a real generation-owner proof.
    select_data_fixture(&index, &source)?;
    let db = AccountDb::open(&index, "acct", &snapshot.key)?;
    check_portable_codec(&db)?;
    assert_eq!(
        db.connection.query_row(
            "SELECT bundle_id FROM account_mac_bundle WHERE is_current=1",
            [],
            |r| r.get::<_, String>(0)
        )?,
        current
    );
    let own_count = db
        .connection
        .call(|raw| Ok(super::merge::load_set(raw, "main").map(|set| set.len())))??;
    assert!(own_count <= 16, "imported rows entered the old in-memory current-bundle set");
    for value in 1..=40_u8 {
        let bundle = Bundle::derive(&[value; 32]);
        let expected = bundle.mac(super::LABELS[0], b"retained-marker")?;
        assert!(db.verify_full_imported_mac(
            &source,
            &bundle.id,
            FullImportedMacDomain::Tombstone,
            Zeroizing::new(b"retained-marker".to_vec()),
            &expected
        )?);
        assert!(!db.verify_full_imported_mac(
            &source,
            &bundle.id,
            FullImportedMacDomain::OwnSentIndex,
            Zeroizing::new(b"retained-marker".to_vec()),
            &expected
        )?);
        let mut another = source.clone();
        another.device_id = "another-source".into();
        assert!(
            !db.verify_full_imported_mac(
                &another,
                &bundle.id,
                FullImportedMacDomain::Tombstone,
                Zeroizing::new(b"retained-marker".to_vec()),
                &expected
            )?,
            "source association was ignored"
        );
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn check_backup_owner(
    db: &AccountDb,
    root: &std::path::Path,
    incoming: &std::path::Path,
    incoming_key: &AccountDbKey,
    source_generation: &mut BackupDatabase,
) -> ResultOf {
    let target_path = root.join("namespace-backup-target.db");
    let target_snapshot = db.pin_full_transfer_cut()?.write_private_snapshot(
        &target_path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut target = BackupDatabase::open(&target_path, &target_snapshot.key)?;
    target.merge_backup(incoming, incoming_key, &mut || Ok(()))?;
    assert_eq!(
        target.db.query_row("SELECT count(*) FROM full_imported_mac_bundle", [], |r| r
            .get::<_, u64>(0))?,
        40
    );
    let bundle = Bundle::derive(&[1; 32]);
    source_generation.db.execute(
        "UPDATE full_imported_mac_bundle SET subkeys=?1 WHERE bundle_id=?2",
        rusqlite::params![[77_u8; 192].as_slice(), bundle.id],
    )?;
    assert!(
        target.merge_backup(incoming, incoming_key, &mut || Ok(())).is_err(),
        "backup accepted a mismatched imported verifier ID"
    );
    source_generation.db.execute(
        "UPDATE full_imported_mac_bundle SET subkeys=?1 WHERE bundle_id=?2",
        rusqlite::params![bundle.keys.as_ref(), bundle.id],
    )?;
    assert_eq!(
        target.db.query_row("SELECT count(*) FROM full_imported_mac_bundle", [], |r| r
            .get::<_, u64>(0))?,
        40
    );
    Ok(())
}

#[test]
fn pairing_full_imported_mac_source_export_keeps_every_qualified_bundle() -> ResultOf {
    let root = crate::tests::temp_root("full-imported-mac-source");
    let source = source();
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", &source.account_anchor)?;
    let key = AccountDbKey::derive("acct", b"full-imported-mac-source-test");
    let db = AccountDb::open(&index, "acct", &key)?;
    // Typed data fixture only; no authority or generation selection is inferred.
    db.connection.call(move |raw| {
        let seed = || -> Result<(), crate::StorageError> {
            for value in 1..=40_u8 {
                let bundle = Bundle::derive(&[value; 32]);
                import_into_private_generation(raw, &source, &bundle.id, &bundle.keys)?;
            }
            Ok(())
        };
        Ok(seed())
    })??;
    check_complete_source_export(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn check_complete_source_export(db: &AccountDb) -> ResultOf {
    let mut preparation = db.prepare_full_transfer_source()?;
    let snapshot = encode_base64url(ramflux_crypto::random_32()?);
    let rules = crate::full_transfer_catalog();
    let schema = db.inspect_full_transfer_schema(rules)?;
    let unknown = schema
        .families
        .iter()
        .zip(rules)
        .filter(|(family, rule)| family.source_rows.0 > 0 && rule.require_typed_codec().is_err())
        .map(|(family, _)| family.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(unknown, Vec::<&str>::new(), "source fixture contains undeclared owners");
    preparation.capture_base_cut(&snapshot).map_err(|error| format!("source capture: {error}"))?;
    let (_, encoded) = preparation
        .encode_fixed_base_source(&snapshot, std::io::sink())
        .map_err(|error| format!("source encoding: {error}"))?;
    let imported = encoded
        .schema
        .families
        .iter()
        .find(|family| family.id == "sql/full_imported_mac_bundle")
        .ok_or("imported family")?;
    assert_eq!(imported.source_rows.0, 40);
    assert_eq!(
        imported.portable_records.0, 40,
        "whole-source encoding truncated imported verifiers"
    );
    Ok(())
}

fn check_portable_codec(db: &AccountDb) -> ResultOf {
    use ramflux_protocol::custody::pairing::full_transfer::{
        CellType, encode_stable_key, read_record_header,
    };
    let rule = crate::full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == "sql/full_imported_mac_bundle")
        .ok_or("rule")?;
    let encoded=db.connection.call(move|raw| {
        let encode=||->Result<_,crate::StorageError> {
            let mut query=raw.prepare("SELECT source_ref,bundle_id,subkeys FROM full_imported_mac_bundle ORDER BY source_ref,bundle_id LIMIT 1")?;
            let mut rows=query.query([])?;
            let row=rows.next()?.ok_or(crate::StorageError::PairingField("UnsupportedRecord"))?;
            let mut encoded=Zeroizing::new(Vec::new());
            crate::write_full_scalar_sql_row(rule,row,&mut *encoded)?;
            Ok(encoded)
        };Ok(encode())
    })??;
    let mut cells = encoded.as_slice();
    let mut header = read_record_header(&mut cells)?.ok_or("header")?;
    let body = cells;
    crate::copy_full_scalar_record(rule, &header, &mut cells, &mut std::io::sink())?;
    assert_eq!(cells.len(), 0, "trailing logical cells");
    let mut another = source();
    another.device_id = "substituted-source".into();
    let replacement = source_key(&another)?;
    let id = bundle_id(body.get(body.len() - 192..).ok_or("subkeys")?);
    header.key = encode_stable_key([
        (CellType::Utf8, replacement.as_bytes()),
        (CellType::Utf8, id.as_bytes()),
    ])?
    .to_string();
    assert!(
        crate::copy_full_scalar_record(rule, &header, &mut &body[..], &mut std::io::sink())
            .is_err(),
        "body was rebound to another source-qualified key"
    );
    Ok(())
}

#[test]
fn pairing_full_imported_source_ref_codec_is_closed_canonical_and_bounded() -> ResultOf {
    let source = source();
    let bytes = source_key(&source)?;
    assert_eq!(decode_source_ref(bytes.as_bytes())?, source);
    let mut object = serde_json::to_value(&source)?;
    object["secret"] = "DO_NOT_COPY".into();
    assert!(decode_source_ref(&ramflux_protocol::canonical_json_bytes(&object)?).is_err());
    assert!(decode_source_ref(format!(" {bytes}").as_bytes()).is_err());
    assert!(decode_source_ref(&[b'x'; 513]).is_err());
    let mut invalid = source;
    invalid.device_epoch = 0;
    assert!(source_key(&invalid).is_err());
    Ok(())
}
