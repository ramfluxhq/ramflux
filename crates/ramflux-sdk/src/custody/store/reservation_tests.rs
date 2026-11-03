// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native creation must not replace an account reserved after ceremony preparation.
use crate::{
    SdkError,
    custody::{
        CreationCeremony,
        tests::{Root, TestVault, input, words},
    },
};
use ramflux_storage::{AccountIndex, WrappedAccountDbKey};

#[test]
fn custody_reservation_cannot_replace_an_initialized_native_account()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let vault = TestVault::default();
    let mut ceremony = CreationCeremony::begin(&root.0, input("collision"), 100)?;
    let phrase = ceremony.show_once()?;
    let answers = words(&phrase, ceremony.hidden_challenge()?)?;
    let index = AccountIndex::open(&root.0)?;
    let before = index.reserve_account("collision", "existing-native-anchor")?;
    let wrapped = WrappedAccountDbKey {
        key_wrapping_provider: "test".into(),
        key_wrapping_ref: "native-key".into(),
        nonce: [4; 12],
        wrapped_key: vec![5; 48],
    };
    index.store_wrapped_db_key("collision", &wrapped)?;
    assert!(matches!(
        ceremony.confirm(&answers, &vault, 100),
        Err(SdkError::CustodyAccountConflict)
    ));
    assert_eq!(index.account("collision")?, before);
    assert_eq!(index.load_wrapped_db_key("collision")?, Some(wrapped));
    assert_eq!(index.known_account_ids()?, ["collision"]);
    assert!(!root.0.join("custody_accounts/collision").exists());
    assert_eq!(vault.entry_count()?, 0);
    Ok(())
}
