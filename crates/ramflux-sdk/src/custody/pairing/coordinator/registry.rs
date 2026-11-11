// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-scoped frontend ownership. Account names alone cannot select another store's actor.
use super::{PairingActor, PairingNative, SdkError};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

type Key = (PathBuf, String);
fn key(root: &Path, account: &str) -> Result<Key, SdkError> {
    Ok((std::fs::canonicalize(root)?, account.into()))
}
pub(super) struct Entry {
    pub(super) actor: tokio::sync::Mutex<PairingActor>,
    cancelled: AtomicBool,
    native: Option<Arc<dyn PairingNative>>,
}
impl Entry {
    pub(super) fn require_live(&self) -> Result<(), SdkError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(SdkError::PairingCode("Retired"))
        } else {
            Ok(())
        }
    }
}
fn actors() -> &'static Mutex<HashMap<Key, Arc<Entry>>> {
    static ACTORS: OnceLock<Mutex<HashMap<Key, Arc<Entry>>>> = OnceLock::new();
    ACTORS.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Install one owner without replacing a live frontend. Root aliases resolve to the same slot.
/// # Errors
/// Refuses a foreign account/root, an existing owner or an unavailable root.
pub fn install_actor(root: &Path, account_id: String, actor: PairingActor) -> Result<(), SdkError> {
    let key = (std::fs::canonicalize(root)?, account_id);
    if actor.identity.account_id != key.1
        || actor.participant.as_ref().is_some_and(|participant| {
            std::fs::canonicalize(&participant.root).ok().as_ref() != Some(&key.0)
        })
    {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let mut owners = actors().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if owners.contains_key(&key) {
        return Err(SdkError::PairingCode("Busy"));
    }
    let native = actor.native.clone();
    owners.insert(
        key,
        Arc::new(Entry {
            actor: tokio::sync::Mutex::new(actor),
            native,
            cancelled: AtomicBool::new(false),
        }),
    );
    Ok(())
}
/// Fence callbacks and close the proof connection immediately on owner lock/disconnect.
/// An already submitted head remains journaled for reconciliation.
/// # Errors
/// Returns root lookup errors. Missing owners are already removed.
pub fn remove_actor(root: &Path, account_id: &str) -> Result<(), SdkError> {
    let key = match key(root, account_id) {
        Ok(key) => key,
        Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let entry = actors().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&key);
    if let Some(entry) = entry {
        crate::custody::pairing::cancel_credential(&key.0, account_id);
        entry.cancelled.store(true, Ordering::Release);
        if let Some(native) = &entry.native {
            native.close();
        }
    }
    Ok(())
}
pub(super) fn find(root: &Path, account_id: &str) -> Result<Arc<Entry>, SdkError> {
    let key = key(root, account_id)?;
    actors()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned()
        .ok_or(SdkError::PairingCode("NotFound"))
}
