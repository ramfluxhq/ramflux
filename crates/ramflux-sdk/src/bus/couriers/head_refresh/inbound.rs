// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-local eligibility for durable inbox retries blocked on current authority.
//! The durable row remains the source of truth. A verified refresh grants one attempt
//! before its backoff, without changing TTL, budgets, or ACK retry eligibility.
//! Restart loses only this optimization; the normal durable retry re-discovers demand.
use super::{BTreeSet, LocalBusAccountState, SdkError};
use crate::GatewayInboxEntry;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Inbound {
    entries: BTreeMap<String, (GatewayInboxEntry, BTreeSet<String>, Option<String>)>,
    ready: BTreeSet<String>,
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
    // Classify the actual deferral, never ambient head staleness. Directory
    // errors carry the exact attempted root from the failed fetch.
    let roots = match error {
        SdkError::DirectoryAuthorityUnavailable { root, .. } => BTreeSet::from([root.clone()]),
        SdkError::SenderManifestRequired { root } | SdkError::FreshHeadRequired { root } => {
            BTreeSet::from([root.clone()])
        }
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
