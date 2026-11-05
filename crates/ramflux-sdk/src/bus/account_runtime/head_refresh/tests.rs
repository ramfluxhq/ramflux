// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live demand, timeout and independent offline-gate contracts.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc;

fn command() -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    AccountCommand {
        admission: None,
        private: None,
        request: crate::LocalBusFrame::request(
            "demand",
            Some("sender".into()),
            "group",
            "group.send",
            json!({"group_id":"group", "conversation_id":"thread", "message_id":"msg", "sender_id":"device", "encrypted_body_base64":"aGk"}),
        ),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    }
}

async fn add_peer(
    native: &Fixture,
    primary: &ramflux_crypto::custody::SelfSigningKey,
    mode: &str,
) -> TestResult<Option<Fixture>> {
    Ok(if mode == "peer404" {
        let peer = Fixture::new("demand-peer").await?;
        native.client.persist_fetched_identity_directory(&peer.manifest)?;
        native.client.shared_group_change_with_primary(
            "group",
            &native.config.target_delivery_id,
            ramflux_protocol::group_state::GroupStateChange::Add {
                member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(primary),
        )?;
        Some(peer)
    } else {
        None
    })
}

type HeldFetch = Option<(std::net::SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>)>;
async fn held_fetch(mode: &str) -> TestResult<HeldFetch> {
    Ok(if mode == "held" {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await?;
            std::future::pending::<std::io::Result<()>>().await
        });
        Some((address, task))
    } else {
        None
    })
}

async fn case(mode: &str) -> TestResult {
    let native = Fixture::with_device("demand", "device").await?;
    let primary = native
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(native.vault.as_ref())?;
    native.client.shared_group_create_with_primary(
        "group",
        "thread",
        None,
        &native.config.target_delivery_id,
        Some(&primary),
    )?;
    let peer = add_peer(&native, &primary, mode).await?;
    *native.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    if peer.is_some() {
        native.client.persist_fetched_identity_directory(&native.manifest)?;
    }
    let manifests = if mode == "success" {
        BTreeSet::from([native.manifest.principal_commitment.clone()])
    } else {
        BTreeSet::new()
    };
    let (address, server) = crate::bus::dispatch::surface_transport::fixture::directory(
        &native.root.0,
        manifests
            .into_iter()
            .map(|root| Ok((root, serde_json::to_value(&native.manifest)?)))
            .collect::<Result<_, serde_json::Error>>()?,
    )
    .await?;
    let held = held_fetch(mode).await?;
    let address = held.as_ref().map_or(address, |(address, _)| *address);
    let mut config = native.config;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = native.root.0.join("ca.pem");
    let mut account = LocalBusAccountState::disconnected(
        native.client,
        config,
        native.manifest.principal_commitment,
    );
    let (handle, _io) = crate::bus::connection_manager::tests::fixture().await?;
    if mode != "offline" {
        account.connection = Some(handle.clone());
    }
    let (mut runtime, _commands, _stop, _observed) =
        super::super::tests::runtime(account, &native.root.0);
    let child = tokio::spawn(crate::bus::couriers::head_refresh::run(
        handle.test_context(),
        runtime.connection_sender.clone(),
    ));
    let mut command = command();
    let admitted = Instant::now() - Duration::from_secs(3);
    command.admission = Some(std::sync::Arc::new(
        crate::bus::command_admission::CommandAdmission::new(admitted, &runtime.timeouts),
    ));
    let outcome = runtime.prepare_command_network(&command).await;
    if mode == "success" {
        outcome?;
        assert!(
            stale_roots(runtime.state.accounts.get("sender").ok_or("account")?, &command.request)?
                .is_empty()
        );
        crate::bus::dispatch::group::dispatch_group_send_request(
            &command.request,
            runtime.state.accounts.get_mut("sender").ok_or("account")?,
        )
        .await?;
    } else {
        let error = outcome.err().ok_or("must remain pending")?;
        let body = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(body.code, "NetworkingPending");
        if mode != "offline" {
            assert!(body.retry_after_ms.is_some());
            assert!(body.details.as_ref().ok_or("details")?.get("networking").is_some());
            assert!(Instant::now() <= admitted + Duration::from_millis(5_500));
        }
        assert!(!serde_json::to_string(&body)?.contains("freshness expired"));
    }
    child.abort();
    handle.stop().await;
    server.abort();
    if let Some((_, task)) = held {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn new_authorization_stale_head_waits_then_proceeds() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(case("success"))).await
}
#[tokio::test]
async fn stale_head_with_live_session_and_held_fetch_returns_networking_pending() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            Box::pin(case("404")).await?;
            Box::pin(case("peer404")).await?;
            Box::pin(case("held")).await?;
            // Exercise every serialized freshness escape, independently of the offline gate.
            let error = SdkError::FreshHeadRequired { root: "test-root".into() };
            let body = crate::bus::io::local_bus_error_body(&error);
            assert_eq!(body.code, "NetworkingPending");
            assert!(body.retry_after_ms.is_some());
            assert!(body.details.ok_or("details")?.get("networking").is_some());
            assert!(!body.message.contains("freshness expired"));
            Ok(())
        })
        .await
}
#[tokio::test]
async fn no_session_returns_networking_pending_from_the_gate() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(case("offline"))).await
}
