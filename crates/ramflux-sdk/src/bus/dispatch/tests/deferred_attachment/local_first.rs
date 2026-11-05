// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `LocalFirst` GETs resolve local availability and erasure before the shared relay boundary.

use super::{make_state, test_root};
use crate::prelude::*;
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct RelayBoundary {
    writes: Arc<AtomicUsize>,
    pending: bool,
}
impl GatewaySessionFrameSink for RelayBoundary {
    fn send_frame<'a>(&'a mut self, _bytes: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            self.writes.fetch_add(1, Ordering::AcqRel);
            self.pending = true;
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for RelayBoundary {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            if !self.pending {
                return std::future::pending().await;
            }
            self.pending = false;
            Ok(serde_json::to_vec(&GatewayServerFrame::Nack {
                reason: "relay boundary reached".into(),
            })?)
        })
    }
}

#[tokio::test]
async fn local_first_gets_keep_cached_and_erased_outcomes_offline_and_gate_uncached_relay()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(case())).await?
}

async fn case() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root();
    let writes = Arc::new(AtomicUsize::new(0));
    let mut state = configured_state(&root, &writes)?;
    let requests = ["object.get", "object.get.begin"].map(|method| LocalBusFrame::request(
        method, Some("account".into()), "object", method,
        serde_json::json!({"object_id":"object","operation_id":format!("local-first-{method}"),"protocol_version":1}),
    ));
    for request in &requests {
        let result = Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(
            request, &mut state,
        ))
        .await?;
        if request.method == "object.get" {
            assert_eq!(
                result.response_body["plaintext_base64"],
                ramflux_protocol::encode_base64url(b"local bytes")
            );
        } else {
            assert_eq!(result.response_body["total_len"], 11);
        }
    }
    assert_eq!(
        writes.load(Ordering::Acquire),
        0,
        "cached GETs must stay offline with a relay default"
    );
    state
        .accounts
        .get("account")
        .ok_or(SdkError::AccountDbNotUnlocked)?
        .client
        .account_db()?
        .remove_actor_state("attachment/fetch/object")?;
    for request in &requests {
        let started = std::time::Instant::now();
        let outcome = Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(
            request, &mut state,
        ))
        .await;
        assert!(
            matches!(
                outcome,
                Err(SdkError::NetworkingPending | SdkError::NetworkingPendingContext { .. })
            ),
            "uncached {} must fail at its relay boundary",
            request.method
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            writes.load(Ordering::Acquire),
            0,
            "offline refusal must precede every transport write"
        );
    }
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    account.start_connection()?;
    let connection = account.connection.clone().ok_or("manager not started")?;
    connection.require_live(Duration::from_secs(600)).await?;
    for (index, request) in requests.iter().enumerate() {
        let outcome = Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(
            request, &mut state,
        ))
        .await;
        assert!(
            matches!(outcome, Err(SdkError::GatewaySessionRejected(ref reason)) if reason == "relay boundary reached"),
            "Live {} must reach the fake transport",
            request.method
        );
        assert_eq!(writes.load(Ordering::Acquire), index + 1);
    }
    connection.stop().await;
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    account.connection = None;
    account.client.tombstone_object("object")?;
    for request in &requests {
        let outcome = Box::pin(crate::bus::dispatch::object::dispatch_object_bus_request(
            request, &mut state,
        ))
        .await;
        assert!(
            matches!(outcome, Err(SdkError::ObjectErased)),
            "erasure precedes the network gate for {}",
            request.method
        );
    }
    assert_eq!(writes.load(Ordering::Acquire), 2);
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn configured_state(
    root: &Path,
    writes: &Arc<AtomicUsize>,
) -> Result<LocalBusDaemonState, SdkError> {
    let mut state = make_state(root)?;
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    account.gateway_config =
        account.gateway_config.clone().with_account_identity(&account.client)?;
    account.install_test_session(GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(RelayBoundary { writes: Arc::clone(writes), pending: false }),
    ));
    let mut options =
        parse_relay_transfer_options(Some("https://relay.invalid".into()), None, None)?
            .ok_or(SdkError::GatewaySessionNotEstablished)?;
    options.relay_owner_home_node_id = Some("home-node".into());
    options.relay_owner_principal_id = Some("recipient".into());
    options.relay_audience_node_id = Some("relay-node".into());
    account.client.node_relay_options = Some(options);
    account.client.put_encrypted_object("object", b"local bytes")?;
    account.client.account_db()?.persist_actor_state("attachment/fetch/object", &serde_json::json!({
        "object_id":"object","operation_id":"fetch-op","transfer_state":"available","last_error":null,"attempts":1,
    }))?;
    Ok(state)
}

fn keyed_read(method: &str) -> crate::bus::actor::AccountCommand {
    let mut request = LocalBusFrame::request(
        method,
        Some("account".into()),
        "test",
        method,
        serde_json::json!({"object_id":"object","operation_id":format!("keyed-{method}"),"protocol_version":1}),
    );
    request.operation_id = Some(format!("receipt-{method}"));
    let (outbound, _) = tokio::sync::mpsc::channel(1);
    crate::bus::actor::AccountCommand {
        admission: None,
        private: None,
        request,
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: false,
        nodes: None,
        outbound,
        reply: None,
    }
}
#[tokio::test]
async fn local_first_keyed_refusal_precedes_reservation_and_started_failure_stays_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(keyed_case())).await?
}
async fn keyed_case() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root();
    let writes = Arc::new(AtomicUsize::new(0));
    let mut state = configured_state(&root, &writes)?;
    let reader = state
        .accounts
        .get("account")
        .ok_or(SdkError::AccountDbNotUnlocked)?
        .client
        .account_db()?
        .open_reader()?;
    state
        .accounts
        .get("account")
        .ok_or(SdkError::AccountDbNotUnlocked)?
        .client
        .account_db()?
        .remove_actor_state("attachment/fetch/object")?;
    for method in ["object.get", "object.get.begin"] {
        let command = keyed_read(method);
        let outcome = crate::bus::mutations::execute(&mut state, "account", &command).await;
        assert!(matches!(
            outcome,
            Err(SdkError::NetworkingPending | SdkError::NetworkingPendingContext { .. })
        ));
        assert!(
            crate::bus::mutation_intent::MutationIntent::new(&command.request)?
                .lookup(&reader)?
                .is_none(),
            "a LocalFirst relay refusal must leave the key absent for {method}"
        );
        assert_eq!(writes.load(Ordering::Acquire), 0);
        assert!(
            !state
                .accounts
                .get("account")
                .ok_or(SdkError::AccountDbNotUnlocked)?
                .object_get_spools
                .contains_key(&format!("keyed-{method}"))
        );
    }
    let account = state.accounts.get_mut("account").ok_or(SdkError::AccountDbNotUnlocked)?;
    account.start_connection()?;
    let connection = account.connection.clone().ok_or("manager not started")?;
    connection.require_live(Duration::from_secs(600)).await?;
    for (index, method) in ["object.get", "object.get.begin"].into_iter().enumerate() {
        let command = keyed_read(method);
        let outcome = crate::bus::mutations::execute(&mut state, "account", &command).await;
        assert!(
            matches!(outcome, Err(SdkError::GatewaySessionRejected(ref reason)) if reason == "relay boundary reached")
        );
        assert_eq!(writes.load(Ordering::Acquire), index + 1);
        let lookup =
            crate::bus::mutation_intent::MutationIntent::new(&command.request)?.lookup(&reader);
        assert!(matches!(
            lookup,
            Err(SdkError::Storage(
                ramflux_storage::StorageError::OperationReconciliationRequired { .. }
            ))
        ));
        assert!(crate::bus::mutations::execute(&mut state, "account", &command).await.is_err());
        assert_eq!(
            writes.load(Ordering::Acquire),
            index + 1,
            "a started failure cannot repeat its network effect"
        );
    }
    connection.stop().await;
    drop(reader);
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
