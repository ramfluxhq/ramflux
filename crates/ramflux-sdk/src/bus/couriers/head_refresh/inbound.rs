// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-local eligibility for durable inbox retries blocked on current authority.
//! The durable row remains the source of truth. A verified refresh grants one attempt
//! before its backoff, without changing TTL, budgets, or ACK retry eligibility.
//! Restart loses only this optimization; the normal durable retry re-discovers demand.
use super::{BTreeSet, LocalBusAccountState, SdkError};
use crate::GatewayInboxEntry;
use std::collections::BTreeMap;

#[derive(Clone)]
struct HeadWatch {
    roots: BTreeSet<String>,
    local_epoch: u64,
    refresh_done: bool,
}

#[derive(Default)]
pub(super) struct Inbound {
    entries: BTreeMap<String, (GatewayInboxEntry, BTreeSet<String>, Option<String>)>,
    ready: BTreeSet<String>,
    /// Envelopes refused with `HeadChanged`, keyed by the inbox admission key.
    heads: std::sync::Mutex<BTreeMap<String, HeadWatch>>,
}

const HEAD_WATCH_CAP: usize = 128;

/// `true` when a completed refresh left the local epoch at or behind the epoch
/// recorded for this envelope. The caller then finalises with `retry_exhausted`.
pub(crate) fn head_changed_final(
    account: &LocalBusAccountState,
    key: &str,
    entry: &GatewayInboxEntry,
) -> Result<bool, SdkError> {
    if key.is_empty() || key.len() > 512 {
        return Ok(false);
    }
    let local = local_epoch(&account.client);
    let roots = head_roots(account, entry);
    let mut watches = account
        .head_refresh
        .inbound
        .heads
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(watch) = watches.get(key).cloned() {
        if local > watch.local_epoch {
            watches.insert(
                key.to_owned(),
                HeadWatch { roots, local_epoch: local, refresh_done: false },
            );
            return Ok(false);
        }
        if watch.refresh_done {
            watches.remove(key);
            drop(watches);
            account.client.account_db()?.remove_inbox_retry(key)?;
            return Ok(true);
        }
    }
    if watches.len() >= HEAD_WATCH_CAP
        && !watches.contains_key(key)
        && let Some(stale) = watches.keys().next().cloned()
    {
        watches.remove(&stale);
    }
    watches.insert(key.to_owned(), HeadWatch { roots, local_epoch: local, refresh_done: false });
    Ok(false)
}

/// True while this envelope is parked and its refresh has not finished.
/// The receive pass skips another apply; the cursor still moves.
pub(crate) fn head_waiting(account: &LocalBusAccountState, key: &str) -> bool {
    if key.is_empty() || key.len() > 512 {
        return false;
    }
    let local = local_epoch(&account.client);
    let watches = account
        .head_refresh
        .inbound
        .heads
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watches.get(key).is_some_and(|watch| !watch.refresh_done && local <= watch.local_epoch)
}

/// Enqueue the roots recorded for a parked `HeadChanged` envelope.
pub(crate) fn arm(account: &mut LocalBusAccountState, key: &str) {
    let roots = {
        let watches = account
            .head_refresh
            .inbound
            .heads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        watches.get(key).map(|watch| watch.roots.clone()).unwrap_or_default()
    };
    for root in roots {
        let _ = account.head_refresh.enqueue(root);
    }
}

fn mark_refresh_done(account: &LocalBusAccountState, root: &str) {
    let mut watches = account
        .head_refresh
        .inbound
        .heads
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for watch in watches.values_mut() {
        if watch.roots.contains(root) {
            watch.refresh_done = true;
        }
    }
}

fn local_epoch(client: &crate::RamfluxClient) -> u64 {
    client.born_v3_account.as_ref().map_or(0, |born| born.record().body.device_set_epoch)
}

fn head_roots(account: &LocalBusAccountState, entry: &GatewayInboxEntry) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    if !account.principal_commitment.is_empty() {
        roots.insert(account.principal_commitment.clone());
    }
    if !entry.envelope.source_principal_id.is_empty() {
        roots.insert(entry.envelope.source_principal_id.clone());
    }
    roots
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
        || (crate::client::inbox_failure::deterministic(error).is_some()
            && !matches!(error, SdkError::PairingCode("HeadChanged")))
        || !account.client.account_db()?.has_inbox_retry(key)?
    {
        return Ok(());
    }
    // Classify the actual deferral, never ambient head staleness. Directory
    // errors carry the exact attempted root from the failed fetch.
    let roots = match error {
        SdkError::DirectoryAuthorityUnavailable { root, .. } => BTreeSet::from([root.clone()]),
        SdkError::SenderManifestRequired { root } | SdkError::FreshHeadRequired { root } => {
            BTreeSet::from([root.clone()])
        }
        SdkError::PairingCode("HeadChanged") => head_roots(account, entry),
        _ => return Ok(()),
    };
    // Preserve relationship/revocation checks independently of failure provenance.
    if account.client.inbound_device_manifest_request(entry).is_err() {
        return Ok(());
    }
    if roots.is_empty() || account.head_refresh.inbound.entries.len() >= 128 {
        return Ok(());
    }
    for root in &roots {
        account.head_refresh.enqueue(root.clone());
    }
    // Routing is encrypted. An unavailable authority may prevent decoding it;
    // such an opaque retry still refreshes/redrives in the background, but must
    // never hold an RPC for an assumed group or a DM from a shared member.
    let group = account
        .client
        .open_routed(entry, &account.gateway_config.device_id)
        .ok()
        .filter(|opened| {
            matches!(
                opened.routing.kind,
                crate::client::routed::Kind::GroupMessage
                    | crate::client::routed::Kind::GroupControl
            )
        })
        .and_then(|opened| opened.routing.group_id);
    account.head_refresh.inbound.entries.insert(key.to_owned(), (entry.clone(), roots, group));
    Ok(())
}

pub(crate) fn refreshed(account: &mut LocalBusAccountState, root: &str) -> Result<(), SdkError> {
    mark_refresh_done(account, root);
    let mut ready = Vec::new();
    let mut gone = Vec::new();
    for (key, (_, roots, _)) in &mut account.head_refresh.inbound.entries {
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

/// True while a retry is retained and still waiting for its first refresh.
/// A granted attempt (`eligible`) is not blocking: leftover W1 must re-retain
/// if that attempt is cancelled or the head is stale again.
pub(crate) fn blocking(account: &LocalBusAccountState, key: &str) -> bool {
    account.head_refresh.inbound.entries.contains_key(key) && !eligible(account, key)
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
        .map(|(key, (entry, _, _))| (key, entry))
}

pub(crate) fn blocked_roots(
    account: &LocalBusAccountState,
    group_id: &str,
) -> Result<BTreeSet<String>, SdkError> {
    let mut roots = BTreeSet::new();
    for (key, (_, dependencies, group)) in &account.head_refresh.inbound.entries {
        if group.as_deref() != Some(group_id) {
            continue;
        }
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
