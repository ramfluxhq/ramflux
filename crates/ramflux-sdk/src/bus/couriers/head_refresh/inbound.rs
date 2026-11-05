// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-local eligibility for durable inbox retries blocked on current authority.
//! The durable row remains the source of truth. A verified refresh grants one attempt
//! before its backoff, without changing TTL, budgets, or ACK retry eligibility.
//! Restart loses only this optimization; the normal durable retry re-discovers demand.
use super::{BTreeSet, LocalBusAccountState, SdkError};
use crate::GatewayInboxEntry;
use crate::client::identity_authority::HeadUse;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Inbound {
    entries: BTreeMap<String, (GatewayInboxEntry, BTreeSet<String>)>,
    ready: BTreeSet<String>,
}

fn stale(account: &LocalBusAccountState, root: &str) -> Result<bool, SdkError> {
    let Some(record) =
        account.client.current_custody_authority(root, crate::custody::network_now()?)?
    else {
        return Ok(false);
    };
    match account.client.require_fresh_custody_head(
        HeadUse::NewAuthorization,
        root,
        record.envelope(),
    ) {
        Ok(()) => Ok(false),
        Err(error) if crate::bus::account_runtime::head_refresh::is_freshness_refusal(&error) => {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn retain(
    account: &mut LocalBusAccountState,
    entry: &GatewayInboxEntry,
    key: &str,
    error: &SdkError,
) -> Result<(), SdkError> {
    account.head_refresh.inbound.entries.remove(key);
    account.head_refresh.inbound.ready.remove(key);
    if account.client.born_v3_account.is_none()
        || crate::client::inbox_failure::deterministic(error).is_some()
        || !account.client.account_db()?.has_inbox_retry(key)?
    {
        return Ok(());
    }
    // This lookup enforces the existing relationship/revocation boundary. Claims alone
    // never authorize a refresh or admission.
    let Ok(peer) = account.client.inbound_device_manifest_request(entry) else {
        return Ok(());
    };
    let mut roots = BTreeSet::new();
    if let Some(peer) = peer {
        roots.insert(peer);
    }
    if stale(account, &account.principal_commitment)? {
        roots.insert(account.principal_commitment.clone());
    }
    if roots.is_empty() || account.head_refresh.inbound.entries.len() >= 128 {
        return Ok(());
    }
    for root in &roots {
        account.head_refresh.enqueue(root.clone());
    }
    account.head_refresh.inbound.entries.insert(key.to_owned(), (entry.clone(), roots));
    Ok(())
}

pub(crate) fn refreshed(account: &mut LocalBusAccountState, root: &str) -> Result<(), SdkError> {
    let mut ready = Vec::new();
    let mut gone = Vec::new();
    for (key, (_, roots)) in &mut account.head_refresh.inbound.entries {
        if !account.client.account_db()?.has_inbox_retry(key)? {
            gone.push(key.clone());
            continue;
        }
        if roots.remove(root)
            && roots.is_empty()
            && !account.head_refresh.inbound.ready.contains(key)
        {
            ready.push(key.clone());
        }
    }
    for key in gone {
        account.head_refresh.inbound.entries.remove(&key);
        account.head_refresh.inbound.ready.remove(&key);
    }
    if !ready.is_empty() {
        account.head_refresh.inbound.ready.extend(ready);
        if let Some(connection) = &account.connection {
            connection.redrive_receive();
        }
    }
    Ok(())
}

pub(crate) fn eligible(account: &LocalBusAccountState, key: &str) -> bool {
    account.head_refresh.inbound.ready.contains(key)
}

pub(crate) fn entries(
    account: &LocalBusAccountState,
) -> impl Iterator<Item = (&String, &GatewayInboxEntry)> {
    account
        .head_refresh
        .inbound
        .entries
        .iter()
        .filter(|(key, _)| eligible(account, key))
        .map(|(key, (entry, _))| (key, entry))
}

pub(crate) fn blocked_roots(account: &LocalBusAccountState) -> Result<BTreeSet<String>, SdkError> {
    let mut roots = BTreeSet::new();
    for (key, (_, dependencies)) in &account.head_refresh.inbound.entries {
        if account.client.account_db()?.has_inbox_retry(key)? && !eligible(account, key) {
            roots.extend(dependencies.iter().cloned());
        }
    }
    Ok(roots)
}

pub(crate) fn consume(account: &mut LocalBusAccountState, key: &str) {
    account.head_refresh.inbound.ready.remove(key);
    account.head_refresh.inbound.entries.remove(key);
}
