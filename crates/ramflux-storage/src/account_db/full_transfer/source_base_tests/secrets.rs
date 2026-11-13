// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real source-cut local secret canaries never enter the portable record stream.
use super::*;
#[test]
fn primary_transfer_full_excludes_device_secrets() -> TestResult {
    let (root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "full-device-secret-canaries",
    )?;
    let canaries = [
        "private-branch-seed-canary-714",
        "private-data-passphrase-canary-932",
        "private-primary-vault-ref-canary-651",
        "private-session-ratchet-canary-478",
    ];
    let private = zeroize::Zeroizing::new(serde_json::to_string(&canaries)?);
    db.connection.execute(
        "INSERT INTO runtime_operation(operation_id,fingerprint,response_json,operation_kind) VALUES('secret-boundary-fixture','local-only',?1,'local-private-owner')",
        rusqlite::params![private.as_str()],
    )?;
    let positive = ramflux_protocol::encode_base64url([77; 32]);
    db.connection.execute(
        "INSERT INTO object_identity_replacement(commitment) VALUES(?1)",
        rusqlite::params![positive],
    )?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let path = root.path().join("secret-canary-source-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &path, snapshot)?;
    let (output, encoded) = stage.encode_fixed_base_source(snapshot_id, Sink::default())?;
    let local = encoded
        .schema
        .families
        .iter()
        .find(|family| family.id == "sql/runtime_operation")
        .ok_or("test: local operation census absent")?;
    assert_eq!(
        local.source_rows.0, 1,
        "test: canary-bearing actual source row was absent from the cut"
    );
    assert_eq!(local.portable_records.0, 0, "test: local operation row entered portable census");
    assert_eq!(local.encoded_bytes.0, 0, "test: local operation secret bytes entered output");
    for canary in canaries {
        assert!(
            !output.0.windows(canary.len()).any(|bytes| bytes == canary.as_bytes()),
            "test: device-local secret canary escaped full source encoding"
        );
    }
    let mut input = output.0.as_slice();
    let mut positive_records = 0;
    while let Some(header) = read_record_header(&mut input)? {
        assert_ne!(
            header.family, "sql/runtime_operation",
            "test: local-only owner emitted a record"
        );
        if header.family == "sql/object_identity_replacement" {
            positive_records += 1;
        }
        let rule = full_transfer_catalog()
            .iter()
            .find(|rule| rule.id == header.family)
            .ok_or("test: unowned output record")?;
        super::super::copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
    }
    assert_eq!(
        positive_records, 1,
        "test: secret exclusion silently omitted required portable data"
    );
    Ok(())
}
