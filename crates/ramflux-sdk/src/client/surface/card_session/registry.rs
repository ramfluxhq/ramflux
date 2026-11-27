// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-global bookkeeping for card sessions. The sessions themselves live on the account
//! actor thread (the VM is not Send); this table must outlive that thread, so it holds only ids.
use super::codes::typed;
use crate::SdkError;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

#[derive(Default)]
struct Registry {
    /// Per account: every session id up to this value that is not live was dropped.
    floors: BTreeMap<String, u64>,
    /// Bus connection to the accounts that hold sessions opened on it.
    live: BTreeMap<u64, BTreeSet<String>>,
    /// Per account: connections that closed and whose sessions are still to be dropped.
    closed: BTreeMap<String, BTreeSet<u64>>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    floors: BTreeMap::new(),
    live: BTreeMap::new(),
    closed: BTreeMap::new(),
});

fn lock() -> Result<MutexGuard<'static, Registry>, SdkError> {
    REGISTRY.lock().map_err(|_| typed("card_session_busy"))
}

/// Raise the expiry floor of `account` to at least `id`.
pub(super) fn raise_floor(account: &str, id: u64) -> Result<(), SdkError> {
    let mut registry = lock()?;
    let floor = registry.floors.entry(account.to_owned()).or_insert(0);
    *floor = (*floor).max(id);
    Ok(())
}

/// True when `id` is at or below the floor of `account`.
pub(super) fn is_expired(account: &str, id: u64) -> Result<bool, SdkError> {
    Ok(lock()?.floors.get(account).is_some_and(|floor| id <= *floor))
}

/// Remember that `account` holds a session opened on `connection`. Connection 0 is internal.
pub(super) fn track(connection: u64, account: &str) -> Result<(), SdkError> {
    if connection == 0 {
        return Ok(());
    }
    lock()?.live.entry(connection).or_default().insert(account.to_owned());
    Ok(())
}

/// A bus connection closed. Returns the accounts that must drop its sessions.
pub(crate) fn connection_closed(connection: u64) -> Vec<String> {
    let Ok(mut registry) = REGISTRY.lock() else {
        return Vec::new();
    };
    let Some(accounts) = registry.live.remove(&connection) else {
        return Vec::new();
    };
    for account in &accounts {
        registry.closed.entry(account.clone()).or_default().insert(connection);
    }
    accounts.into_iter().collect()
}

/// Connections of `account` that closed since the last call.
pub(super) fn take_closed(account: &str) -> Result<BTreeSet<u64>, SdkError> {
    Ok(lock()?.closed.remove(account).unwrap_or_default())
}

/// The account no longer holds sessions: forget its connection links and pending drops.
pub(super) fn forget_account(account: &str) {
    let Ok(mut registry) = REGISTRY.lock() else {
        return;
    };
    registry.closed.remove(account);
    registry.live.retain(|_, accounts| {
        accounts.remove(account);
        !accounts.is_empty()
    });
}
