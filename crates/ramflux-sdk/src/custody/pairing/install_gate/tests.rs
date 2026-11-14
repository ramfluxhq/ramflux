// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Admission, reopen};
use crate::SdkError;
use crate::custody::pairing::install_store::{
    self, Install, backup_excluded, strip_backup_installs, write_installed, write_pending,
};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::encode_base64url;
use std::path::Path;

fn h(byte: u8) -> String {
    encode_base64url([byte; 32])
}

fn device() -> DeviceRef {
    DeviceRef { account_anchor: h(2), device_id: "dev-a".into(), device_epoch: 1 }
}

fn root(tag: &str) -> ramflux_test_support::TestPath {
    let path =
        ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(
            format!("pair01-p04j-gate-{tag}-{}-{}", std::process::id(), encode_base64url([9; 8])),
        );
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::create_dir_all(&path);
    path
}

fn base(state: &str) -> Install {
    Install {
        schema: "ramflux.pairing.Install.v2".into(),
        version: 2,
        account_id: "acct".into(),
        account_anchor: h(2),
        operation_id: h(20),
        recipient_ref: device(),
        recipient_mode: "new".into(),
        install_purpose: "enroll".into(),
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

fn hashed(state: &str) -> Install {
    let mut row = base(state);
    row.record_hash = Some(h(4));
    row
}

#[test]
fn pairing_journal_crash_fences_and_backup_exclusion() -> Result<(), SdkError> {
    j0_reserved_cuts()?;
    j1_vault_durable_cut()?;
    j3_bind_record_hash()?;
    j7a_adopt_prepared_fenced()?;
    j7c_file_cuts()?;
    backup_excludes_install_files()?;
    Ok(())
}

fn j0_reserved_cuts() -> Result<(), SdkError> {
    let root = root("j0");
    let before = reopen(&root, "acct", None, false)?;
    assert_eq!(before.pending.len(), 0);
    assert_eq!(before.admission, Admission::Closed);
    assert!(!before.admits_ordinary_networking());
    write_pending(&root, &base("reserved"))?;
    let after = reopen(&root, "acct", None, false)?;
    assert_eq!(after.pending.len(), 1);
    assert!(after.pending[0].record_hash.is_none());
    assert_eq!(after.pending[0].state, "reserved");
    assert_eq!(after.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn j1_vault_durable_cut() -> Result<(), SdkError> {
    let root = root("j1");
    write_pending(&root, &base("reserved"))?;
    let before = reopen(&root, "acct", None, false)?;
    assert_eq!(before.pending[0].state, "reserved");
    write_pending(&root, &base("vault_durable"))?;
    let after = reopen(&root, "acct", None, false)?;
    assert_eq!(after.pending[0].state, "vault_durable");
    assert_eq!(after.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn j3_bind_record_hash() -> Result<(), SdkError> {
    let root = root("j3");
    write_pending(&root, &base("vault_durable"))?;
    let before = reopen(&root, "acct", None, false)?;
    assert!(before.pending[0].record_hash.is_none());
    write_pending(&root, &hashed("vault_durable"))?;
    let after = reopen(&root, "acct", Some(&h(4)), false)?;
    assert_eq!(after.pending[0].record_hash.as_deref(), Some(h(4).as_str()));
    assert_eq!(after.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn j7a_adopt_prepared_fenced() -> Result<(), SdkError> {
    let root = root("j7a");
    write_pending(&root, &hashed("vault_durable"))?;
    let before = reopen(&root, "acct", Some(&h(4)), false)?;
    assert!(before.installed.is_none());
    write_pending(&root, &hashed("adopt_prepared"))?;
    let after = reopen(&root, "acct", Some(&h(4)), false)?;
    assert_eq!(after.pending[0].state, "adopt_prepared");
    assert!(after.installed.is_none());
    assert_eq!(after.admission, Admission::Closed);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn j7c_file_cuts() -> Result<(), SdkError> {
    let root = root("j7c");
    write_pending(&root, &hashed("adopt_prepared"))?;
    write_pending(&root, &hashed("authority_durable"))?;
    let durable = reopen(&root, "acct", Some(&h(4)), false)?;
    assert_eq!(durable.pending[0].state, "authority_durable");
    assert_eq!(durable.admission, Admission::Closed);
    write_installed(&root, &hashed("installed"))?;
    let both = reopen(&root, "acct", Some(&h(4)), false)?;
    assert_eq!(both.installed.as_ref().map(|row| row.state.as_str()), Some("installed"));
    assert_eq!(both.pending.len(), 1);
    assert_eq!(both.admission, Admission::Closed);
    install_store::remove_pending(&root, "acct", &h(20))?;
    let agreed = reopen(&root, "acct", Some(&h(4)), false)?;
    assert!(agreed.files_and_db_agree);
    assert_eq!(agreed.pending.len(), 0);
    assert_eq!(agreed.admission, Admission::Closed);
    assert!(!agreed.admits_ordinary_networking());
    let mismatch = reopen(&root, "acct", Some(&h(9)), false)?;
    assert!(!mismatch.files_and_db_agree);
    assert_eq!(mismatch.admission, Admission::Closed);
    let open = reopen(&root, "acct", Some(&h(4)), true)?;
    assert!(open.files_and_db_agree);
    assert_eq!(open.admission, Admission::Open);
    assert!(open.admits_ordinary_networking());
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn backup_excludes_install_files() -> Result<(), SdkError> {
    let root = root("backup");
    write_pending(&root, &hashed("vault_durable"))?;
    write_installed(&root, &hashed("installed"))?;
    let pending = install_store::pending_path(&root, "acct", &h(20));
    assert!(backup_excluded(&pending));
    assert!(backup_excluded(&install_store::installed_path(&root, "acct")));
    assert!(!backup_excluded(Path::new("custody_accounts/acct/authority.json")));
    let backup = root.join("backup-tree");
    copy_tree(&root.join("custody_accounts"), &backup.join("custody_accounts"))?;
    assert_eq!(install_store::list_pending(&backup, "acct")?.len(), 1);
    strip_backup_installs(&backup, "acct")?;
    assert_eq!(install_store::list_pending(&backup, "acct")?.len(), 0);
    assert!(install_store::read_installed(&backup, "acct")?.is_none());
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), SdkError> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}
