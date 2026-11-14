// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-directory lookup is prepared locally and fetched before the account receives its result.

use crate::bus::{
    connection_manager::ReceiveEntry, contact_backpressure::Backpressure, couriers::writer::Writer,
};
use crate::client::routed::PreparedInbound;
pub(crate) mod failure;
mod group;

pub(crate) mod hold;
mod native;
pub(crate) mod reset;
pub(crate) mod w0;
pub(crate) mod ws;
use crate::prelude::*;

pub(crate) type PreparedSource = Option<Box<Result<PreparedInbound, SdkError>>>;

enum Request {
    Original,
    Prepared(Result<Lookup, SdkError>),
}

enum Lookup {
    Sender(Option<String>),
    Contact(String),
}

pub(crate) async fn prepare(
    writer: &Writer,
    entry: ReceiveEntry,
    mut backpressure: Box<Backpressure>,
) -> Result<(ReceiveEntry, Box<Backpressure>, PreparedSource), SdkError> {
    #[cfg(feature = "itest-rfd-fault")]
    let entry = {
        let mut entry = entry;
        if let Some(changed) = crate::itest_rfd_fault::tamper_received_binding(&entry.entry)? {
            entry.entry = *changed;
        }
        entry
    };
    #[cfg(test)]
    let source_writer = writer.source_reads();
    #[cfg(test)]
    let writer = &source_writer;
    let (request, entry, backpressure, config) = writer
        .apply(move |account| {
            let saturated = entry.replay
                && backpressure.saturated(&account.client, &entry.entry, now_unix_timestamp())?;
            let request =
                if saturated { Request::Original } else { request(account, &entry, &backpressure) };
            let config = account.gateway_config.clone();
            #[cfg(test)]
            let config = {
                let mut config = config;
                config.timeout = account.timeouts.frame;
                config.quic_fallback_timeout = account.timeouts.transport_open;
                config
            };
            Ok((request, entry, backpressure, config))
        })
        .await?;
    let prepared = match request {
        Request::Original => None,
        Request::Prepared(request) => {
            let result = match request {
                Err(error) => Err(error),
                Ok(Lookup::Contact(root)) => match fetch_inbound_manifest(&config, &root).await {
                    Ok(manifest) => native::contact(writer, &config, &entry.entry, manifest).await,
                    Err(error) => Err(error),
                },
                Ok(Lookup::Sender(root)) => {
                    let manifest = match root {
                        Some(root) => fetch_inbound_manifest(&config, &root).await.map(Some),
                        None => Ok(None),
                    };
                    match manifest {
                        Ok(manifest) => {
                            native::prepare(writer, &config, &entry.entry, manifest).await
                        }
                        Err(error) => Err(error),
                    }
                }
            };
            Some(Box::new(result))
        }
    };
    Ok((entry, backpressure, prepared))
}

fn request(
    account: &LocalBusAccountState,
    prepared: &ReceiveEntry,
    backpressure: &Backpressure,
) -> Request {
    let entry = &prepared.entry;
    let request = (|| {
        if account.client.routed_seen_marker(entry)?.is_some() || backpressure.duplicate(entry) {
            return Ok(None);
        }
        let mut keys = BTreeMap::new();
        if let Some(key) = &prepared.retry_key {
            keys.insert(super::pending_entry_id(entry), key.clone());
        }
        let (key, committed) = super::retry_context(&account.client, entry, &keys)?;
        if !matches!(committed, Ok(false))
            || (!crate::bus::couriers::head_refresh::inbound::eligible(account, &key)
                && !account.client.account_db()?.inbox_retry_ready(&key, now_unix_timestamp())?)
            || (now_unix_timestamp()
                >= entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl))
                && account.client.account_db()?.has_inbox_retry(&key)?)
        {
            return Ok(None);
        }
        if crate::client::routed::decode(&entry.envelope).is_err() {
            return Ok(None);
        }
        if account.client.contact_bootstrap_required(entry)? {
            return Ok(Some(
                account.client.contact_candidate_manifest_request(entry).map(Lookup::Contact),
            ));
        }
        Ok(Some(account.client.inbound_device_manifest_request(entry).map(Lookup::Sender)))
    })();
    match request {
        Ok(None) => Request::Original,
        Ok(Some(request)) => Request::Prepared(request),
        Err(error) => Request::Prepared(Err(error)),
    }
}

async fn fetch_inbound_manifest(
    config: &GatewaySessionConfig,
    root: &str,
) -> Result<crate::SdkDeviceManifestResponse, SdkError> {
    crate::client::contact::fetch_verified_device_manifest(config, root).await.map_err(|source| {
        SdkError::DirectoryAuthorityUnavailable { root: root.to_owned(), source: Box::new(source) }
    })
}
