// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bus-level routing of the three agent creation methods (`agent.create`,
//! `agent.creation.decide`, `agent.operation.get`) through the real connection dispatcher.
//!
//! Each request travels a real local-bus socket to `connection::handle`, is answered by the
//! owning account's actor (the desktop for `agent.create`, the primary phone for
//! `agent.creation.decide`), and returns that actor's answer. The accounts are the native
//! fixtures of `custody::agent_creation::test_support` (`pair`), reopened on their own actor
//! threads exactly as `native_actor.rs` reopens its accounts. The packets between the two
//! roots are carried by the real `RouterCore` (`OwnRouter`). Every request is bounded by the
//! hang guard `HANG`; a request that does not return fails with the name of the method.
use super::{HANG, client, request};
use crate::bus::actor::AccountInitializer;
use crate::bus::dispatch::surface_transport::fixture::RecordingGateway;
use crate::bus::state::LocalBusAccountState;
use crate::bus::supervisor::Supervisor;
use crate::client::native_test_support::bus::Material;
use crate::custody::agent_creation::test_support::{
    OwnRouter, Pair, TestResult, create_body, decide_body, now, pair, root_of, store_of, vault_of,
};
use crate::custody::PrimaryVault;
use crate::{GatewaySessionEngine, LocalBusClient, LocalBusConfig, LocalBusFrame, RamfluxClient};
use ramflux_protocol::message as g;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use tokio::task::LocalSet;

/// The data passphrase of the native phone fixture (`native_test_support.rs:51`).
const PHONE_PASSPHRASE: &[u8] = b"native fixture data passphrase";
/// The data passphrase of the native sibling fixture (`native_test_support/sibling.rs:66`).
const SIBLING_PASSPHRASE: &[u8] = b"native sibling data passphrase";

/// The initializer of one native account, built as `native_actor.rs` `Side::initializer` builds
/// its accounts: reopened from disk on the actor thread, observed directory persisted, gateway
/// configured with the account identity. The gateway is a recording double, since agent methods
/// never open a session.
fn reopened(
    account: &LocalBusAccountState,
    passphrase: &'static [u8],
) -> TestResult<AccountInitializer> {
    let material: &Material = account.client.native_bus_fixture.as_ref().ok_or("native fixture")?;
    let root = material.root.0.to_path_buf();
    let vault = Arc::clone(&material.vault);
    let manifest = material.manifest.clone();
    let id = account.client.account_db()?.local_account_id.clone();
    let device = account.gateway_config.device_id.clone();
    let config = account.gateway_config.clone();
    Ok(Box::new(move |index| {
        let mut client = RamfluxClient::new();
        client.account_index = Some(index);
        client.open_account_index(&root)?;
        client.unlock_account(&id, passphrase)?;
        client.initialize_born_v3_branch_for_fixture(&device, vault.as_ref())?;
        client.persist_observed_identity_directory_now(&manifest)?;
        let branch = client.device_branch.clone().ok_or(crate::SdkError::CustodySetupInvalid)?;
        let mut config = config.with_account_identity(&client)?;
        config.device_branch = Some(Arc::new(branch));
        config.source_identity = Some(client.owned_device_identity()?);
        let anchor = client.own_account_anchor()?;
        let gateway = RecordingGateway::new(Arc::default());
        let engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
        let mut account = LocalBusAccountState::new(client, engine, anchor);
        let mut setup = LocalBusConfig::new(root.join("fixture.sock"), root.clone());
        setup.custody_vault = Some(vault);
        account.native_setup = Some(setup);
        Ok(account)
    }))
}

/// Serves one native account through its own supervisor. The supervisor's custody vault is the
/// account's fixture vault: the bus reads the vault from its config (`custody_setup.rs:152-158`),
/// so a config without it would reach the platform vault.
fn serve_one(
    dir: &Path,
    account: &LocalBusAccountState,
    passphrase: &'static [u8],
) -> TestResult<Rc<Supervisor>> {
    let initializer = reopened(account, passphrase)?;
    let id = account.client.account_db()?.local_account_id.clone();
    let vault = Arc::clone(&account.client.native_bus_fixture.as_ref().ok_or("native fixture")?.vault);
    let mut config = LocalBusConfig::new(dir.join("bus.sock"), dir);
    config.custody_vault = Some(vault as Arc<dyn PrimaryVault>);
    Ok(Supervisor::from_initializers(&config, vec![(id, initializer)], None)?)
}

/// Sends one request through the socket and waits for its response, bounded by `HANG`.
async fn call(bus: &LocalBusClient, method: &str, frame: LocalBusFrame) -> TestResult<LocalBusFrame> {
    tokio::time::timeout(HANG, bus.request_frame_response(frame))
        .await
        .map_err(|_| format!("test: {method} did not return within the hang guard"))?
        .map_err(Into::into)
}

/// The custody status a successful agent method returns in its body.
fn custody_status(response: &LocalBusFrame) -> TestResult<g::AgentCustodyStatus> {
    let result: g::AgentConfigResult = serde_json::from_value(response.body.clone())?;
    match result.value {
        Some(g::agent_config_result::Value::Custody(status)) => Ok(status),
        _ => Err("test: the bus did not return a custody status".into()),
    }
}

/// The stable refusal code of an error response.
fn refusal_code(response: &LocalBusFrame) -> Option<&str> {
    response.error.as_ref().map(|error| error.code.as_str())
}

/// Runs one scenario on a current-thread runtime inside a `LocalSet`, as the bus connection needs.
fn run(case: impl std::future::Future<Output = TestResult>) -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(LocalSet::new().run_until(case))
}

#[test]
fn agent_create_routes_to_the_desktop_actor_and_refuses_on_the_phone() -> TestResult {
    let Pair { phone, laptop } = pair("bus-create")?;
    run(create_case(phone, laptop))
}

/// Proves: `agent.create` reaches the desktop actor (a response carrying the new operation in
/// `authorization_pending`), and the same call on the phone is refused by the
/// phone's actor with `desktop_required`.
async fn create_case(phone: LocalBusAccountState, laptop: LocalBusAccountState) -> TestResult {
    let desk_id = laptop.client.account_db()?.local_account_id.clone();
    let phone_id = phone.client.account_db()?.local_account_id.clone();
    let desk_dir = super::root("agent-create-desk");
    let phone_dir = super::root("agent-create-phone");
    let desk_sup = serve_one(&desk_dir, &laptop, SIBLING_PASSPHRASE)?;
    let phone_sup = serve_one(&phone_dir, &phone, PHONE_PASSPHRASE)?;
    let (bus, server) = client(Rc::clone(&desk_sup), 1).await?;
    let (phone_bus, phone_server) = client(Rc::clone(&phone_sup), 2).await?;
    let body = serde_json::to_value(create_body(Some(true)))?;
    let created = call(
        &bus,
        "agent.create",
        request("create-desk", &desk_id, "agent.create", body.clone()),
    )
    .await?;
    assert!(created.error.is_none(), "the desktop accepts the creation: {:?}", created.error);
    let status = custody_status(&created)?;
    assert_eq!(status.state, "authorization_pending");
    assert!(!status.request_id.is_empty(), "the operation names its request");
    let refused = call(
        &phone_bus,
        "agent.create",
        request("create-phone", &phone_id, "agent.create", body),
    )
    .await?;
    assert_eq!(refused.kind, crate::LocalBusFrameKind::Error);
    assert_eq!(refusal_code(&refused), Some("desktop_required"), "the phone cannot start a creation");
    drop(bus);
    drop(phone_bus);
    server.await??;
    phone_server.await??;
    Ok(())
}

#[test]
fn agent_operation_get_routes_to_the_desktop_actor_and_refuses_unknown_requests() -> TestResult {
    let mut pair = pair("bus-get")?;
    run(get_case(&mut pair))
}

/// Proves: `agent.operation.get` reaches the desktop actor, which answers with the frozen plan of
/// the operation it created; an unknown operation id is refused with `creation_request_unknown`
/// by that actor; the phone answers for the plan it received through the router.
async fn get_case(pair: &mut Pair) -> TestResult {
    let desk_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let vault = vault_of(&pair.laptop.client)?;
    let created = pair.laptop.client.agent_create(vault.as_ref(), &create_body(Some(true)), now()?)?;
    OwnRouter::new()?.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let desk_sup = serve_one(&super::root("agent-get-desk"), &pair.laptop, SIBLING_PASSPHRASE)?;
    let phone_sup = serve_one(&super::root("agent-get-phone"), &pair.phone, PHONE_PASSPHRASE)?;
    let (bus, server) = client(Rc::clone(&desk_sup), 1).await?;
    let (phone_bus, phone_server) = client(Rc::clone(&phone_sup), 2).await?;
    let get = |id: &str| serde_json::to_value(g::AgentOperationGet { operation_id: id.into() });
    let read = call(
        &bus,
        "agent.operation.get",
        request("get-desk", &desk_id, "agent.operation.get", get(&created.request_id)?),
    )
    .await?;
    assert!(read.error.is_none(), "the desktop answers the read: {:?}", read.error);
    let status = custody_status(&read)?;
    assert_eq!(status.state, "authorization_pending");
    assert!(status.request_json.is_some(), "the operation carries the frozen plan");
    let unknown = call(
        &bus,
        "agent.operation.get",
        request("get-unknown", &desk_id, "agent.operation.get", get("no-such-operation")?),
    )
    .await?;
    assert_eq!(refusal_code(&unknown), Some("creation_request_unknown"));
    let on_phone = call(
        &phone_bus,
        "agent.operation.get",
        request("get-phone", &phone_id, "agent.operation.get", get(&created.request_id)?),
    )
    .await?;
    assert!(on_phone.error.is_none(), "the phone holds the plan and answers for it");
    drop(bus);
    drop(phone_bus);
    server.await??;
    phone_server.await??;
    Ok(())
}

#[test]
fn agent_creation_decide_routes_to_the_primary_actor_and_refuses_on_the_desktop() -> TestResult {
    let mut pair = pair("bus-decide")?;
    run(decide_case(&mut pair))
}

/// Proves: `agent.creation.decide` reaches the phone's actor and approves the plan
/// (`authorized`); the same decision sent to the desktop is refused with
/// `creation_not_primary` by the desktop's actor.
async fn decide_case(pair: &mut Pair) -> TestResult {
    let desk_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let vault = vault_of(&pair.laptop.client)?;
    let created = pair.laptop.client.agent_create(vault.as_ref(), &create_body(Some(true)), now()?)?;
    OwnRouter::new()?.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let hash = store_of(&root_of(&pair.laptop)?, &desk_id)?
        .load(&created.request_id)?
        .ok_or("the desktop record")?
        .request_hash;
    pair.phone
        .client
        .native_bus_fixture
        .as_ref()
        .ok_or("the phone fixture vault")?
        .vault
        .arm_agent_decision(&hash)?;
    let desk_sup = serve_one(&super::root("agent-decide-desk"), &pair.laptop, SIBLING_PASSPHRASE)?;
    let phone_sup = serve_one(&super::root("agent-decide-phone"), &pair.phone, PHONE_PASSPHRASE)?;
    let (desk_bus, desk_server) = client(Rc::clone(&desk_sup), 1).await?;
    let (phone_bus, phone_server) = client(Rc::clone(&phone_sup), 2).await?;
    let decide = serde_json::to_value(decide_body(&created.request_id, &hash, Some(true)))?;
    let decided = call(
        &phone_bus,
        "agent.creation.decide",
        request("decide-phone", &phone_id, "agent.creation.decide", decide.clone()),
    )
    .await?;
    assert!(decided.error.is_none(), "the phone answers the decision: {:?}", decided.error);
    assert_eq!(custody_status(&decided)?.state, "authorized");
    let refused = call(
        &desk_bus,
        "agent.creation.decide",
        request("decide-desk", &desk_id, "agent.creation.decide", decide),
    )
    .await?;
    assert_eq!(refusal_code(&refused), Some("creation_not_primary"), "the desktop never approves");
    drop(phone_bus);
    drop(desk_bus);
    phone_server.await??;
    desk_server.await??;
    Ok(())
}
