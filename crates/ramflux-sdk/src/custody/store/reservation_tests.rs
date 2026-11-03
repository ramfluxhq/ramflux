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

use super::race_hooks::{self, Stage};
use crate::custody::PrimaryVault;
use ramflux_crypto::custody::SelfSigningKey;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroizing;

#[derive(Default)]
struct CountingVault {
    inner: TestVault,
    stores: AtomicUsize,
}
impl PrimaryVault for CountingVault {
    fn preflight(&self) -> Result<(), SdkError> {
        self.inner.preflight()
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.stores.fetch_add(1, Ordering::SeqCst);
        self.inner.store_new(reference, key)
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        self.inner.load_primary(reference)
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.inner.delete(reference)
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.stores.fetch_add(1, Ordering::SeqCst);
        self.inner.store_branch(reference, seeds)
    }
}

fn displaced_native_reservation(stage: Stage) -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let vault = CountingVault::default();
    let mut ceremony = CreationCeremony::begin(&root.0, input("race"), 100)?;
    let phrase = ceremony.show_once()?;
    let answers = words(&phrase, ceremony.hidden_challenge()?)?;
    let winner = Rc::new(RefCell::new(None));
    let observed = Rc::clone(&winner);
    let _reset = race_hooks::install(move |at, root, id| {
        if at != stage {
            return Ok(());
        }
        // Model an already-admitted native restore completing its replace-capable index write.
        let mut client = crate::RamfluxClient::new();
        client.open_account_index(root)?;
        let row = client.create_account(id, "native-restore-anchor")?;
        client.seal_new_account_data(id, "native-restore-anchor", b"native winner passphrase")?;
        let index = AccountIndex::open(root)?;
        let wrapped = index.load_wrapped_db_key(id)?.ok_or(SdkError::CustodySetupInvalid)?;
        *observed.borrow_mut() = Some((row, wrapped));
        Ok(())
    });
    assert!(matches!(
        ceremony.confirm(&answers, &vault, 100),
        Err(SdkError::CustodyAccountConflict)
    ));
    let (before, wrapped) = winner.borrow_mut().take().ok_or("checkpoint did not run")?;
    let index = AccountIndex::open(&root.0)?;
    assert_eq!(index.account("race")?, before);
    assert_eq!(index.load_wrapped_db_key("race")?, Some(wrapped));
    assert_eq!(index.known_account_ids()?, ["race"]);
    assert!(!root.0.join("custody_accounts/race").exists());
    crate::client::account::verify_stored_data_secret(
        &root.0,
        "race",
        b"native winner passphrase",
    )?;
    assert!(crate::client::account::verify_stored_data_secret(&root.0, "race", b"wrong").is_err());
    assert_eq!(vault.inner.entry_count()?, 0);
    if stage == Stage::AfterReservation {
        assert_eq!(
            vault.stores.load(Ordering::SeqCst),
            0,
            "reservation conflict reached the vault"
        );
    }
    Ok(())
}

#[test]
fn custody_native_writer_after_reservation_preserves_key_without_vault_writes()
-> Result<(), Box<dyn std::error::Error>> {
    displaced_native_reservation(Stage::AfterReservation)
}
#[test]
fn custody_native_writer_after_reservation_check_preserves_key_and_cleans_vault()
-> Result<(), Box<dyn std::error::Error>> {
    displaced_native_reservation(Stage::AfterReservationCheck)
}
#[test]
fn custody_native_writer_before_authority_publication_preserves_key_and_cleans_vault()
-> Result<(), Box<dyn std::error::Error>> {
    displaced_native_reservation(Stage::BeforeAuthorityPublish)
}
