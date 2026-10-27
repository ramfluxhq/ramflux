// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Provider-boundary crashes never leave migration enabled with a flags-0 primary copy.
use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone)]
struct Entry {
    bytes: Zeroizing<Vec<u8>>,
    presence: bool,
}
#[derive(Default)]
struct Store {
    entries: RefCell<BTreeMap<String, Entry>>,
    calls: Cell<usize>,
    fail: Cell<Option<usize>>,
    approved: Cell<bool>,
    prompts: Cell<usize>,
}
impl Store {
    fn step(&self) -> std::result::Result<(), SdkError> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if self.fail.get() == Some(call) {
            return Err(unavailable());
        }
        Ok(())
    }
    fn fixture() -> (Self, SelfSigningKey) {
        let store = Self::default();
        store.approved.set(true);
        let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([7; 32]));
        store.entries.borrow_mut().insert(
            "primary".into(),
            Entry { bytes: Zeroizing::new(primary.vault_seed().to_vec()), presence: false },
        );
        store.entries.borrow_mut().insert(
            "branch:primary".into(),
            Entry { bytes: Zeroizing::new(vec![8; 64]), presence: false },
        );
        (store, primary)
    }
}
impl Items for Store {
    fn exists(&self, reference: &str) -> std::result::Result<bool, SdkError> {
        self.step()?;
        Ok(self.entries.borrow().contains_key(reference))
    }
    fn read(
        &self,
        reference: &str,
        presence: bool,
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
        self.step()?;
        let entries = self.entries.borrow();
        let Some(entry) = entries.get(reference) else { return Ok(None) };
        if entry.presence {
            if !presence {
                return Err(unavailable());
            }
            self.prompts.set(self.prompts.get() + 1);
            if !self.approved.get() {
                return Err(unavailable());
            }
        }
        Ok(Some(entry.bytes.clone()))
    }
    fn insert(
        &self,
        reference: &str,
        bytes: &[u8],
        presence: bool,
    ) -> std::result::Result<bool, SdkError> {
        self.step()?;
        let mut entries = self.entries.borrow_mut();
        if entries.contains_key(reference) {
            return Ok(false);
        }
        entries.insert(reference.into(), Entry { bytes: Zeroizing::new(bytes.to_vec()), presence });
        Ok(true)
    }
    fn journal(&self, reference: &str, bytes: &[u8]) -> std::result::Result<(), SdkError> {
        self.step()?;
        assert!(bytes.len() <= 1024);
        self.entries.borrow_mut().insert(
            reference.into(),
            Entry { bytes: Zeroizing::new(bytes.to_vec()), presence: false },
        );
        Ok(())
    }
    fn delete(&self, reference: &str) -> std::result::Result<(), SdkError> {
        self.step()?;
        self.entries.borrow_mut().remove(reference);
        Ok(())
    }
}
#[test]
fn home_migration_presence_upgrade_recovers_every_io_boundary_without_losing_the_primary() -> Result
{
    let (complete, primary) = Store::fixture();
    approved_primary(&complete, "primary", &primary.public_key())?;
    for boundary in 1..=complete.calls.get() + 1 {
        let (store, primary) = Store::fixture();
        store.fail.set(Some(boundary));
        let attempt = approved_primary(&store, "primary", &primary.public_key());
        if boundary <= complete.calls.get() {
            assert!(attempt.is_err());
        }
        assert!(
            store.entries.borrow().contains_key("primary")
                || store.entries.borrow().contains_key(&protected_reference("primary"))
        );
        store.fail.set(None);
        let loaded = approved_primary(&store, "primary", &primary.public_key())?;
        assert_eq!(loaded.public_key(), primary.public_key());
        assert!(!store.entries.borrow().contains_key("primary"));
        let entries = store.entries.borrow();
        assert!(entries[&protected_reference("primary")].presence);
        assert!(!entries["branch:primary"].presence);
        assert_eq!(&**entries["branch:primary"].bytes, &[8; 64]);
    }
    Ok(())
}
#[test]
fn home_migration_cancelled_presence_keeps_legacy_and_never_turns_ready_metadata_into_approval()
-> Result {
    let (store, primary) = Store::fixture();
    store.approved.set(false);
    assert!(matches!(
        approved_primary(&store, "primary", &primary.public_key()),
        Err(SdkError::HomeMigrationRefused(
            ramflux_protocol::home_migration::Refusal::CustodyUserPresenceUnavailable
        ))
    ));
    assert!(store.entries.borrow().contains_key("primary"));
    store.approved.set(true);
    drop(approved_primary(&store, "primary", &primary.public_key())?);
    let prompts = store.prompts.get();
    store.approved.set(false);
    assert!(approved_primary(&store, "primary", &primary.public_key()).is_err());
    assert_eq!(store.prompts.get(), prompts + 1);
    assert!(!store.entries.borrow().contains_key("primary"));
    Ok(())
}
#[test]
fn home_migration_does_not_replace_an_existing_wrong_protected_primary_or_delete_legacy() -> Result
{
    let (store, primary) = Store::fixture();
    let wrong = SelfSigningKey::from_vault_seed(&Zeroizing::new([9; 32]));
    store.insert(&protected_reference("primary"), &*wrong.vault_seed(), true)?;
    assert!(approved_primary(&store, "primary", &primary.public_key()).is_err());
    assert!(store.entries.borrow().contains_key("primary"));
    assert_eq!(
        key(&store.read(&protected_reference("primary"), true)?.ok_or("protected key")?)?
            .public_key(),
        wrong.public_key()
    );
    Ok(())
}
