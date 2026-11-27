// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh-authority contracts for DM send authorizations.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn new_dm_send_authorization_needs_a_fetch_made_after_the_command_began() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let peer = Fixture::new("fresh-peer").await?;
        let holder = Fixture::new("fresh-holder").await?;
        holder.client.persist_observed_identity_directory_now(&peer.manifest)?;
        let account = LocalBusAccountState::disconnected(
            holder.client,
            holder.config,
            holder.manifest.principal_commitment.clone(),
        );
        let request = crate::LocalBusFrame::request(
            "dm-send",
            Some("sender".into()),
            "message",
            "message.submit",
            json!({"recipient_principal_commitment": peer.manifest.principal_commitment}),
        );
        // An observation from before the command (still inside the 300 s window) is not enough.
        let began = std::time::Instant::now();
        let stale = stale_roots_since(&account, &request, Some(began))?;
        assert!(
            stale.contains(&peer.manifest.principal_commitment),
            "a new DM authorization must not reuse an earlier observation: {stale:?}"
        );
        // A fetch that completes after the command began satisfies it.
        account.client.persist_observed_identity_directory_now(&peer.manifest)?;
        assert!(
            stale_roots_since(&account, &request, Some(began))?.is_empty(),
            "a fetch made after the command began must authorize it"
        );
        // Methods that are not sends keep the process-wide window semantics.
        let read = crate::LocalBusFrame::request(
            "dm-read",
            Some("sender".into()),
            "message",
            "message.read",
            json!({}),
        );
        assert!(stale_roots_since(&account, &read, Some(began))?.is_empty(), "reads are not sends");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "test: deadline exceeded")?
}

#[tokio::test]
async fn a_queued_fetch_result_keeps_the_instant_its_fetch_began() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let peer = Fixture::new("queued-peer").await?;
        let holder = Fixture::new("queued-holder").await?;
        let account = LocalBusAccountState::disconnected(
            holder.client,
            holder.config,
            holder.manifest.principal_commitment.clone(),
        );
        let request = crate::LocalBusFrame::request(
            "dm-send",
            Some("sender".into()),
            "message",
            "message.submit",
            json!({"recipient_principal_commitment": peer.manifest.principal_commitment}),
        );
        let root = peer.manifest.principal_commitment.clone();
        let admitted = std::time::Instant::now();
        // A fetch that began before the command was admitted, applied only now (a queued result).
        let mut early = peer.manifest.clone();
        early.fetched_after = crate::prekey::FetchStamp(
            admitted.checked_sub(Duration::from_secs(5)),
        );
        account.client.persist_fetched_identity_directory(&early)?;
        let stale = stale_roots_since(&account, &request, Some(admitted))?;
        assert!(
            stale.contains(&root),
            "a result whose fetch predates admission must not authorize it, even applied later: {stale:?}"
        );
        // A fetch that began after admission does.
        let mut late = peer.manifest.clone();
        late.fetched_after = crate::prekey::FetchStamp(Some(std::time::Instant::now()));
        account.client.persist_fetched_identity_directory(&late)?;
        assert!(
            stale_roots_since(&account, &request, Some(admitted))?.is_empty(),
            "a fetch that began after admission must authorize it"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "test: deadline exceeded")?
}

#[tokio::test]
async fn a_native_projection_keeps_the_fetch_start_through_ready_manifest() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let peer = Fixture::new("projected-peer").await?;
        let holder = Fixture::new("projected-holder").await?;
        let account = LocalBusAccountState::disconnected(
            holder.client,
            holder.config,
            holder.manifest.principal_commitment.clone(),
        );
        let request = crate::LocalBusFrame::request(
            "dm-send",
            Some("sender".into()),
            "message",
            "message.submit",
            json!({"recipient_principal_commitment": peer.manifest.principal_commitment}),
        );
        let root = peer.manifest.principal_commitment.clone();
        let admitted = std::time::Instant::now();
        let project = |began: Option<std::time::Instant>| {
            let mut fetched = peer.manifest.clone();
            fetched.fetched_after = crate::prekey::FetchStamp(began);
            let ready = crate::client::identity_authority::ready_manifest(
                fetched,
                crate::prelude::now_unix_timestamp(),
            );
            (ready.custody.is_some(), ready.fetched_after.0 == began, ready)
        };
        // A fetch that began before admission, projected and applied only now, is refused.
        let (native, kept, early) = project(admitted.checked_sub(Duration::from_secs(5)));
        assert!(native && kept, "native projection must keep the fetch start (native={native})");
        account.client.persist_fetched_identity_directory(&early)?;
        let stale = stale_roots_since(&account, &request, Some(admitted))?;
        assert!(
            stale.contains(&root),
            "a projected pre-admission fetch must not authorize: {stale:?}"
        );
        // Missing provenance never becomes a new observation at Apply.
        let (_, _, unstamped) = project(None);
        account.client.persist_fetched_identity_directory(&unstamped)?;
        let stale = stale_roots_since(&account, &request, Some(admitted))?;
        assert!(stale.contains(&root), "an unstamped result must fail closed: {stale:?}");
        // A fetch that began after admission is accepted.
        let (native, kept, late) = project(Some(std::time::Instant::now()));
        assert!(native && kept, "native projection must keep a post-admission start");
        account.client.persist_fetched_identity_directory(&late)?;
        assert!(
            stale_roots_since(&account, &request, Some(admitted))?.is_empty(),
            "a projected post-admission fetch must authorize"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "test: deadline exceeded")?
}

/// Real directory and pair-material producers run before a command is admitted; their older,
/// queued results are applied while the command's own fresh fetch is still held. The command
/// must stay blocked until a fetch that began after admission is applied.
#[tokio::test]
async fn queued_directory_and_pair_material_results_cannot_renew_a_later_command() -> TestResult {
    use crate::bus::connection_manager::CallClass;
    use crate::client::routed::SendMaterialRequest;
    tokio::task::LocalSet::new()
        .run_until(crate::client::native_test_support::watchdog::within(async {
            let peer = Fixture::new("producer-peer").await?;
            let holder = Fixture::new("producer-holder").await?;
            let root = peer.manifest.principal_commitment.clone();
            let (address, server) = crate::bus::dispatch::surface_transport::fixture::directory(
                &holder.root.0,
                [(root.clone(), serde_json::to_value(&peer.manifest)?)].into_iter().collect(),
            )
            .await?;
            let mut config = holder.config;
            config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
            config.gateway_addr = address;
            config.tcp_gateway_addr = Some(address);
            config.server_name = "test-gateway".into();
            config.ca_cert = holder.root.0.join("ca.pem");
            let account = LocalBusAccountState::disconnected(
                holder.client,
                config.clone(),
                holder.manifest.principal_commitment.clone(),
            );
            let (handle, _io) = crate::bus::connection_manager::tests::fixture().await?;
            let context = handle.test_context();
            let request = crate::LocalBusFrame::request(
                "dm-send",
                Some("sender".into()),
                "message",
                "message.submit",
                json!({"recipient_principal_commitment": root}),
            );
            // Older results, produced by the real couriers' fetch functions.
            let directory = crate::bus::couriers::directory::fetch(&config, &root).await?;
            let material = crate::bus::couriers::pair_material::fetch(
                &context,
                &config,
                SendMaterialRequest { root: Some(root.clone()), prekey: None },
                CallClass::Bulk,
            )
            .await?;
            let (_, pair) = material.manifest.ok_or("pair-material manifest")?;
            assert!(
                directory.fetched_after.0.is_some() && pair.fetched_after.0.is_some(),
                "real producers must stamp their fetch start"
            );
            let admitted = std::time::Instant::now();
            // The command's own fresh fetch is held and never completes.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let mut held_config = config.clone();
            held_config.gateway_addr = listener.local_addr()?;
            held_config.tcp_gateway_addr = Some(listener.local_addr()?);
            let held_root = root.clone();
            let held = tokio::task::spawn_local(async move {
                let _hold = listener.accept().await;
                crate::bus::couriers::directory::fetch(&held_config, &held_root).await
            });
            // Apply the older results as the queued writer paths do.
            account.client.accept_fetched_device_manifest(
                directory,
                &root,
                "own-contact-backfill",
            )?;
            let stale = stale_roots_since(&account, &request, Some(admitted))?;
            assert!(stale.contains(&root), "older directory result must not authorize: {stale:?}");
            account.client.accept_fetched_device_manifest(pair, &root, "background-outbox")?;
            let stale = stale_roots_since(&account, &request, Some(admitted))?;
            assert!(
                stale.contains(&root),
                "older pair-material result must not authorize: {stale:?}"
            );
            assert!(!held.is_finished(), "the command's fresh fetch is still held");
            // A fetch that begins after admission releases the command.
            let fresh = crate::bus::couriers::directory::fetch(&config, &root).await?;
            account.client.accept_fetched_device_manifest(fresh, &root, "own-contact-backfill")?;
            assert!(
                stale_roots_since(&account, &request, Some(admitted))?.is_empty(),
                "a post-admission fetch must authorize"
            );
            held.abort();
            handle.stop().await;
            server.abort();
            Ok::<(), Box<dyn std::error::Error>>(())
        }))
        .await
        .map_err(|_| "test: deadline exceeded")?
}
