// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive-side own history runs one relay page in the shared transfer pool at a time.

use crate::bus::{couriers::writer::Writer, transfer_slots::JobHandle};
use crate::client::{
    own_device_sync::receive_job::{HistoryCompletion, HistoryFetch, HistoryPreparation},
    routed::Routing,
};
use crate::own_device_sync::SdkOwnDeviceSyncEnvelope;
use crate::{GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, SdkError};
use std::{collections::BTreeSet, sync::Arc};

type Next = Option<Box<SdkOwnDeviceSyncEnvelope>>;
enum Page {
    Complete(Next),
    Running(JobHandle<Next>),
}
pub(super) async fn prepare(
    writer: &Writer,
    config: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    route: &Routing,
    body: &[u8],
) -> Result<Option<HistoryCompletion>, SdkError> {
    let Some(envelope) =
        RamfluxClient::routed_own_history_envelope(entry, route, body, &config.device_id)?
    else {
        return Ok(None);
    };
    let owned_entry = entry.clone();
    let owned_route = route.clone();
    let owned_body = zeroize::Zeroizing::new(body.to_vec());
    writer
        .apply(move |account| {
            account.client.contact_route_gate(&owned_entry, &owned_route, &owned_body)?;
            account.client.confirm_routed_context(&owned_route, &owned_entry)
        })
        .await?;
    let mut current = envelope.clone();
    let mut seen = BTreeSet::new();
    loop {
        if current.source_device_id != envelope.source_device_id
            || current.target_device_id != envelope.target_device_id
            || !seen.insert(current.snapshot_id.clone())
        {
            return Err(SdkError::InboundRejected(
                "own history continuation binding or cycle".into(),
            ));
        }
        let checked = current.clone();
        writer
            .apply(move |account| {
                account
                    .client
                    .validate_own_sync_header(&account.client.own_account_anchor()?, &checked)
            })
            .await?;
        let manifest = super::fetch_inbound_manifest(config, &current.principal_commitment).await?;
        let owned_writer = writer.clone();
        let page = writer
            .apply(move |account| {
                match account.client.prepare_own_history_receive(
                    current,
                    manifest,
                    #[cfg(feature = "itest-local-mint")]
                    account.timeouts.relay_http,
                )? {
                    HistoryPreparation::Complete(next) => Ok(Page::Complete(next)),
                    HistoryPreparation::Fetch(fetch) => {
                        let permit = account
                            .transfer_slots
                            .as_ref()
                            .ok_or(SdkError::NetworkingPending)?
                            .reserve()?;
                        let engine = account.live_session_client()?;
                        let generation = engine.generation();
                        let pool = account.relay_quic_pool()?;
                        Ok(Page::Running(
                            permit
                                .submit(generation, fetch_page(owned_writer, engine, pool, fetch)),
                        ))
                    }
                }
            })
            .await?;
        let next = match page {
            Page::Complete(next) => next,
            Page::Running(mut job) => job.wait().await?,
        };
        let Some(next) = next else {
            return writer
                .apply(move |account| account.client.own_history_completion(&envelope).map(Some))
                .await;
        };
        current = *next;
    }
}
async fn fetch_page(
    writer: Writer,
    mut engine: crate::bus::connection_manager::SessionClient,
    pool: Arc<ramflux_transport::RelayQuicPool>,
    fetch: Arc<HistoryFetch>,
) -> Result<Next, SdkError> {
    let cipher =
        crate::client::object::fetch_job::download(&mut engine, &pool, &fetch.input, |chunk| {
            let writer = writer.clone();
            let fetch = Arc::clone(&fetch);
            async move {
                writer
                    .apply(move |account| {
                        account.client.check_own_history_fetch(&fetch)?;
                        account.client.persist_fetch_chunk(&fetch.input, &chunk)
                    })
                    .await
            }
        })
        .await?;
    let imported = Arc::clone(&fetch);
    writer
        .apply(move |account| account.client.import_own_history_cipher(&imported, &cipher))
        .await?;
    let authorize = Arc::clone(&fetch);
    let ack = writer
        .apply(move |account| {
            account.client.check_own_history_fetch(&authorize)?;
            account.client.authorize_fetch_ack(&authorize.input)
        })
        .await?;
    if ack {
        for index in 0..fetch.input.manifest.total_chunks {
            if fetch.input.confirmed.contains(&index) {
                continue;
            }
            let checked = Arc::clone(&fetch);
            writer.apply(move |account| account.client.check_own_history_fetch(&checked)).await?;
            crate::client::object::fetch_job::acknowledge(&mut engine, &pool, &fetch.input, index)
                .await?;
            let confirmed = Arc::clone(&fetch);
            writer
                .apply(move |account| {
                    account.client.check_own_history_fetch(&confirmed)?;
                    account
                        .client
                        .persist_received_attachment_ack(&confirmed.input.reference, index)
                })
                .await?;
        }
    }
    writer
        .apply(move |account| {
            account.client.commit_own_history_slot(&fetch)?;
            account.client.finish_own_history_receive(&fetch)
        })
        .await
}
