// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit local collection only. Never unlock, create a collection, or fall back.
//! Use keyring's explicit SS identity builder, and its underlying synchronous
//! transport directly: keyring's high-level API automatically unlocks/creates
//! collections and updates existing items, which violates this provider's contract.
use super::{cleanup::Secret, init::LinuxVaultInitError as Error};
use dbus_secret_service::{Collection, EncryptionType, SecretService};
use std::collections::HashMap;
use tokio::{sync::watch, time::Instant};
use zeroize::Zeroize;

pub(super) const COLLECTION: &str = "ramflux-local-vault";
const SERVICE: &str = "ramflux.identity.linux_vault.kek.v1";

struct Response(Vec<u8>);
impl Drop for Response {
    fn drop(&mut self) {
        // Initialize spare capacity without reallocating, then wipe and observe
        // the complete owned allocation before Vec releases it.
        self.0.resize(self.0.capacity(), 0);
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        super::cleanup::observer::inspect("p05-response", &self.0);
    }
}
fn read(item: &dbus_secret_service::Item<'_>) -> Result<Secret<32>, Error> {
    // Guard the returned allocation immediately, before validation or copying.
    let response = Response(item.get_secret().map_err(|_| Error::Provider)?);
    if response.0.len() != 32 {
        return Err(Error::Length);
    }
    let mut key = Secret::new("p05-readback");
    key.bytes_mut().copy_from_slice(&response.0);
    Ok(key)
}
fn check(cancel: &watch::Receiver<bool>, deadline: Instant) -> Result<(), Error> {
    if *cancel.borrow() {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    Ok(())
}

// Select by the explicit collection label, matching keyring's target contract.
// Never call its automatic unlock helper.
fn local_collection<'a>(
    service: &'a SecretService,
    cancel: &watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Collection<'a>, Error> {
    let mut selected = None;
    for collection in service.get_all_collections().map_err(|_| Error::Provider)? {
        check(cancel, deadline)?;
        if collection.get_label().map_err(|_| Error::Provider)? == COLLECTION {
            if selected.is_some() {
                return Err(Error::Corrupt);
            }
            selected = Some(collection);
        }
    }
    selected.ok_or(Error::Missing)
}

/// Caller owns the permanent installation lock across missing/set/readback and
/// descriptor publication. All calls run inside its bounded blocking worker.
pub(super) fn ensure(
    id: &str,
    realm: usize,
    create: bool,
    cancel: &watch::Receiver<bool>,
    deadline: Instant,
    cut: &impl Fn(&str),
) -> Result<(), Error> {
    let deadline = deadline.min(Instant::now() + std::time::Duration::from_secs(30));
    check(cancel, deadline)?;
    if realm >= 3 {
        return Err(Error::Realm);
    }
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(Error::Corrupt);
    }
    let user = format!("{}:{id}", super::systemd::NAMES[realm]);
    let credential = keyring::secret_service::default_credential_builder()
        .build(Some(COLLECTION), SERVICE, &user)
        .map_err(|_| Error::Provider)?;
    let identity = credential
        .as_any()
        .downcast_ref::<keyring::secret_service::SsCredential>()
        .ok_or(Error::Provider)?;
    let mut attributes: HashMap<&str, &str> =
        identity.attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    attributes.remove("application");
    // Each underlying D-Bus RPC is bounded to 2 seconds. Never request Unlock;
    // any provider creation prompt has a zero-second wait budget.
    let service = SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0)
        .map_err(|_| Error::Provider)?;
    check(cancel, deadline)?;
    let collection = local_collection(&service, cancel, deadline)?;
    if collection.is_locked().map_err(|_| Error::Provider)? {
        return Err(Error::Provider);
    }
    let matches = service.search_items(attributes.clone()).map_err(|_| Error::Provider)?;
    if matches.unlocked.len() + matches.locked.len() > 1 {
        return Err(Error::Corrupt);
    }
    if !matches.locked.is_empty() {
        return Err(Error::Provider);
    }
    if let Some(item) = matches.unlocked.first() {
        // Refuse same attributes planted in another collection.
        if !collection
            .search_items(attributes)
            .map_err(|_| Error::Provider)?
            .iter()
            .any(|local| local.path == item.path)
        {
            return Err(Error::Corrupt);
        }
        let _key = read(item)?;
        cut("ss-existing-readback");
    } else {
        if !create {
            return Err(Error::Corrupt);
        }
        cut("ss-missing");
        check(cancel, deadline)?;
        let mut key = Secret::<32>::new("p05-generated");
        getrandom::fill(key.bytes_mut()).map_err(|_| Error::Random)?;
        cut("ss-generated");
        check(cancel, deadline)?;
        // Never use set_secret: that API overwrites an existing item. The
        // installation lock serializes all cooperating initialization writers.
        let item = collection
            .create_item(
                "Ramflux local vault KEK",
                attributes,
                key.bytes(),
                false,
                "application/octet-stream",
            )
            .map_err(|_| Error::Provider)?;
        cut("ss-set-reply");
        check(cancel, deadline)?;
        let readback = read(&item)?;
        if readback.bytes() != key.bytes() {
            return Err(Error::Corrupt);
        }
        cut("ss-readback");
    }
    check(cancel, deadline)
}

#[cfg(test)]
mod tests;
