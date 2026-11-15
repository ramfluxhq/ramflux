// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual shared owner and recovery scanner; no native/admission acceptance claim.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn pairing_full_generation_lease_survives_creator_and_recovery_keeps_pending_g1() -> TestResult {
    let root = crate::bus::runtime_tests::root("pairing-full-generation-owner");
    let index = AccountIndex::open(&root)?;
    let mut install = crate::custody::pairing::install_store::full_tests::fixture();
    index.create_account("acct", &install.account_anchor)?;
    let owner = FullGenerationDirectory::begin(&root, "acct")?;
    let path = owner.path().to_owned();
    std::fs::write(path.join("account.db"), b"private encrypted G1 placeholder")?;
    // begin's temporary GenerationLocks creator is already dropped. A new
    // backup service/scanner at the same root must still observe this live lease.
    let backup = GenerationLocks::for_root(&root)?;
    assert!(backup.try_acquire("acct")?.is_none(), "lease lost its canonical-root owner");
    super::super::recovery::recover_generations(&root, &index, &backup)?;
    assert!(path.exists(), "recovery removed a live G1 directory");
    let full = install.full_transfer.as_mut().ok_or("full install")?;
    full.db_relative_path = owner.relative(&path.join("account.db"))?;
    full.object_relative_path = owner.relative(&path.join("objects"))?;
    install.state = "adopt_prepared".into();
    crate::custody::pairing::install_store::write_pending(&root, &install)?;
    drop(owner);
    assert!(path.exists(), "unselected required pending G1 was removed on handback");
    assert!(backup.try_acquire("acct")?.is_some(), "released G1 kept its generation lease");
    super::super::recovery::recover_generations(&root, &index, &backup)?;
    assert!(path.exists(), "restart removed required pending G1 before G2");
    crate::custody::pairing::install_store::remove_pending(&root, "acct", &install.operation_id)?;
    super::super::recovery::recover_generations(&root, &index, &backup)?;
    assert!(!path.exists(), "unselected unreferenced abandoned generation was retained");
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
