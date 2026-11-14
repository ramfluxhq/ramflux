// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Install, LIMIT, decode, encode, list_pending, pending_path, write_pending};
use crate::SdkError;
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::encode_base64url;

fn h(byte: u8) -> String {
    encode_base64url([byte; 32])
}

fn device() -> DeviceRef {
    DeviceRef { account_anchor: h(2), device_id: "dev-a".into(), device_epoch: 1 }
}

fn base(purpose: &str, state: &str) -> Install {
    Install {
        schema: "ramflux.pairing.Install.v2".into(),
        version: 2,
        account_id: "acct".into(),
        account_anchor: h(2),
        operation_id: h(20),
        recipient_ref: device(),
        recipient_mode: "new".into(),
        install_purpose: purpose.into(),
        record_hash: None,
        prior_record_hash: None,
        branch_vault_ref: "vault-branch".into(),
        data_vault_ref: "vault-data".into(),
        primary_vault_ref: None,
        state: state.into(),
        cleanup_ref: None,
        cleanup_owner_ref: None,
        full_transfer: None,
    }
}

fn field(result: &Result<Vec<u8>, SdkError>, name: &'static str) {
    assert!(
        matches!(result, Err(SdkError::PairingField(got)) if *got == name),
        "{name}: {result:?}"
    );
}

fn field_decode(result: &Result<Install, SdkError>, name: &'static str) {
    assert!(
        matches!(result, Err(SdkError::PairingField(got)) if *got == name),
        "{name}: {result:?}"
    );
}

#[test]
fn reserved_hash_null_and_role_arms() -> Result<(), SdkError> {
    let reserved = base("enroll", "reserved");
    encode(&reserved)?;
    let mut hashed = reserved.clone();
    hashed.record_hash = Some(h(4));
    field(&encode(&hashed), "record_hash");
    let mut vault = base("enroll", "vault_durable");
    encode(&vault)?;
    vault.record_hash = Some(h(4));
    encode(&vault)?;
    let mut prepared = base("enroll", "adopt_prepared");
    field(&encode(&prepared), "record_hash");
    prepared.record_hash = Some(h(4));
    encode(&prepared)?;
    let mut extra = reserved;
    extra.primary_vault_ref = Some("vault-primary".into());
    field(&encode(&extra), "primary_vault_ref");
    Ok(())
}

#[test]
fn authority_refresh_primary_and_secondary() -> Result<(), SdkError> {
    let mut secondary = base("authority_refresh", "installed");
    secondary.record_hash = Some(h(4));
    encode(&secondary)?;
    let mut primary = secondary.clone();
    primary.primary_vault_ref = Some("vault-primary".into());
    encode(&primary)?;
    primary.cleanup_ref = Some("old-mgmt".into());
    field(&encode(&primary), "cleanup_ref");
    let mut dest = base("transfer_destination", "reserved");
    field(&encode(&dest), "primary_vault_ref");
    dest.primary_vault_ref = Some("vault-primary".into());
    encode(&dest)?;
    dest.data_vault_ref = "vault-primary".into();
    field(&encode(&dest), "data_vault_ref");
    dest.data_vault_ref = "vault-data".into();
    dest.branch_vault_ref = "vault-data".into();
    field(&encode(&dest), "data_vault_ref");
    let mut source = base("transfer_source", "reserved");
    source.primary_vault_ref = Some("vault-primary".into());
    field(&encode(&source), "primary_vault_ref");
    Ok(())
}

#[test]
fn cleanup_and_id_ref_size_negatives() -> Result<(), SdkError> {
    let mut pending = base("transfer_source", "cleanup_pending");
    pending.record_hash = Some(h(4));
    field(&encode(&pending), "cleanup_ref");
    pending.cleanup_ref = Some("old-mgmt".into());
    pending.cleanup_owner_ref = Some(device());
    encode(&pending)?;
    pending.cleanup_ref = Some("vault-branch".into());
    field(&encode(&pending), "cleanup_ref");
    pending.cleanup_ref = Some("old-mgmt".into());
    pending.install_purpose = "enroll".into();
    pending.primary_vault_ref = None;
    field(&encode(&pending), "cleanup_pending");
    let mut id = base("enroll", "reserved");
    id.account_id.clear();
    field(&encode(&id), "account_id");
    id = base("enroll", "reserved");
    id.account_id = "x".repeat(129);
    field(&encode(&id), "account_id");
    id = base("enroll", "reserved");
    id.branch_vault_ref = "a/b".into();
    field(&encode(&id), "branch_vault_ref");
    id = base("enroll", "reserved");
    id.recipient_ref.device_id.clear();
    field(&encode(&id), "ref.device_id");
    field_decode(&decode(&vec![b'x'; LIMIT + 1]), "size");
    let mut mode = base("enroll", "reserved");
    mode.recipient_mode = "existing".into();
    field(&encode(&mode), "prior_record_hash");
    mode.prior_record_hash = Some(h(4));
    encode(&mode)?;
    mode.recipient_mode = "new".into();
    field(&encode(&mode), "prior_record_hash");
    let mut anchor = base("enroll", "reserved");
    anchor.recipient_ref.account_anchor = h(9);
    field(&encode(&anchor), "ref.account_anchor");
    let mut pending_anchor = base("transfer_source", "cleanup_pending");
    pending_anchor.record_hash = Some(h(4));
    pending_anchor.cleanup_ref = Some("old-mgmt".into());
    pending_anchor.cleanup_owner_ref =
        Some(DeviceRef { account_anchor: h(9), device_id: "dev-a".into(), device_epoch: 1 });
    field(&encode(&pending_anchor), "ref.account_anchor");
    Ok(())
}

#[test]
fn pending_file_cap_and_mode() -> Result<(), SdkError> {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("pair01-p04-install-{}-{}", std::process::id(), encode_base64url([3; 8])));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    for n in 0..3 {
        let mut row = base("enroll", "reserved");
        row.operation_id = h(30 + n);
        write_pending(&root, &row)?;
    }
    let mut fourth = base("enroll", "reserved");
    fourth.operation_id = h(40);
    assert!(matches!(write_pending(&root, &fourth), Err(SdkError::PairingField("pending_cap"))));
    let path = pending_path(&root, "acct", &h(30));
    assert!(path.is_file(), "pending enrollment file missing");
    #[cfg(unix)]
    assert_eq!(crate::platform::fs::permission_bits(&path)?, 0o600);
    assert_eq!(list_pending(&root, "acct")?.len(), 3);
    let fourth_path = pending_path(&root, "acct", &h(40));
    std::fs::write(&fourth_path, encode(&fourth)?)?;
    assert!(matches!(list_pending(&root, "acct"), Err(SdkError::PairingField("pending_cap"))));
    Ok(())
}

#[test]
fn list_pending_binds_filename_account_and_size() -> Result<(), SdkError> {
    let root =
        ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(
            format!("pair01-p04-install-bind-{}-{}", std::process::id(), encode_base64url([4; 8])),
        );
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    write_pending(&root, &base("enroll", "reserved"))?;
    let src = pending_path(&root, "acct", &h(20));
    let mismatch = pending_path(&root, "acct", &h(50));
    std::fs::copy(&src, &mismatch)?;
    assert!(matches!(list_pending(&root, "acct"), Err(SdkError::PairingField("operation_id"))));
    std::fs::remove_file(&mismatch)?;
    let mut foreign = base("enroll", "reserved");
    foreign.account_id = "other".into();
    foreign.operation_id = h(60);
    std::fs::write(pending_path(&root, "acct", &h(60)), encode(&foreign)?)?;
    assert!(matches!(list_pending(&root, "acct"), Err(SdkError::PairingField("account_id"))));
    std::fs::remove_file(pending_path(&root, "acct", &h(60)))?;
    std::fs::write(pending_path(&root, "acct", &h(70)), vec![b'x'; LIMIT + 1])?;
    assert!(matches!(
        super::read_pending(&root, "acct", &h(70)),
        Err(SdkError::PairingField("size"))
    ));
    Ok(())
}
