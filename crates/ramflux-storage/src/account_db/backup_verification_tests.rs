// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incoming archives cannot populate private verification-import bookkeeping.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{ContactVerificationUpdate, LEGACY_SAFETY_VERIFICATION_MARKER};
use ramflux_protocol::{PrincipalKind, SignedDeviceSetEntry};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn unstamped_contact(db: &AccountDb) -> Result<String, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("unrelated", [23; 32]);
    let record = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![SignedDeviceSetEntry {
                device_id: "phone".into(),
                device_epoch: 1,
                signing_key_commitment: ramflux_protocol::encode_base64url([24; 32]),
                agreement_key_commitment: ramflux_protocol::encode_base64url([25; 32]),
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), &record)?;
    let commitment = record.principal_commitment.clone();
    db.persist_client_record(
        "identity",
        "unrelated",
        &json!({
            "contact_identity_commitment":commitment, "device_set_hash":"matching-hash"
        }),
    )?;
    db.persist_actor_state(&format!("identity/signed_set/{commitment}"), &record)?;
    db.mark_contact_verified(ContactVerificationUpdate {
        contact_identity_commitment: &commitment,
        safety_number_hash: "safety",
        device_set_hash: "matching-hash",
        lineage_head: "lineage",
        verified_at: 1,
        verified_by_device_id: "phone",
    })?;
    Ok(commitment)
}

#[test]
fn legacy_merge_cannot_import_its_own_verification_scratch_table() -> TestResult {
    let (source_root, source) = crate::tests::test_db("verification-scratch-source")?;
    let (local_root, local) = crate::tests::test_db("verification-scratch-local")?;
    local.migrate_legacy_contact_verifications()?;
    let commitment = unstamped_contact(&local)?;
    // This archive imports no verification rows, only a table named like private scratch state.
    source
        .connection
        .execute_batch("CREATE TABLE backup_imported_verification(root TEXT PRIMARY KEY)")?;
    source.connection.execute(
        "INSERT INTO backup_imported_verification VALUES(?1)",
        rusqlite::params![commitment],
    )?;
    let archive = source_root.join("archive.db");
    let saved = source.write_backup_snapshot(&archive)?;
    let staging = local_root.join("staging.db");
    let copied = local.write_backup_snapshot(&staging)?;
    let mut merged = BackupDatabase::open(&staging, &copied.key)?;
    merged.merge_backup(&archive, &saved.key, || Ok(()))?;
    let stamped: bool = merged.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",
        [format!("identity/safety_verified_set/{commitment}")],
        |r| r.get(0),
    )?;
    assert!(!stamped, "an incoming scratch row must not baseline an unrelated local contact");
    let marker: Vec<u8> = merged.db.query_row(
        "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
        [LEGACY_SAFETY_VERIFICATION_MARKER],
        |r| r.get(0),
    )?;
    assert!(serde_json::from_slice::<bool>(&marker)?);
    assert!(!merged.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='backup_imported_verification')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    drop(merged);
    drop(source);
    drop(local);
    std::fs::remove_dir_all(source_root)?;
    std::fs::remove_dir_all(local_root)?;
    Ok(())
}
