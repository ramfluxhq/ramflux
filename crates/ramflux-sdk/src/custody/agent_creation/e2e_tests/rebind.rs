// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D end-to-end tests of the rebind after a human primary transfer (contract 7.5 and 7.6).
//! Shared fixture and what is real or fixture: `../test_support.rs` (`transfer_fixture`,
//! `transfer_primary`). The three devices are native fixtures, the transfer is the real
//! `cooperative_transfer_preserving_devices`, and the rebind request travels through the real
//! `RouterCore` (`OwnRouter`).
use super::super::rebind::{RebindBinding, RebindEntry};
use super::super::rebind_observe::observe_primary;
use super::super::test_support::{
    DesktopSteps, OwnRouter, TestNode, TestResult, Transfer, capable, decide_body, desk_create,
    now, phone_decides, root_of, store_of, transfer_fixture, transfer_primary, vault_of,
};
use super::super::{AgentCreationState, advance_one, commit_approved};
use crate::SdkError;
use ramflux_protocol::custody::decode_register_plan;

fn runtime() -> TestResult<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

/// A committed agent of the old primary, marked complete. Publication is covered by
/// `primary_phone.rs`; a complete record is all a rebind request needs. Returns the agent id.
async fn bound_agent(t: &mut Transfer, router: &OwnRouter, at: u64) -> TestResult<String> {
    let laptop_root = root_of(&t.pair.laptop)?;
    let laptop_id = t.pair.laptop.client.account_db()?.local_account_id.clone();
    let desk_vault = vault_of(&t.pair.laptop.client)?;
    let created = desk_create(&t.pair, desk_vault.as_ref(), at)?;
    phone_decides(&mut t.pair, router, &created, true, at).await?;
    let store = store_of(&laptop_root, &laptop_id)?;
    commit_approved(&store, desk_vault.as_ref(), &laptop_id, &created.request_id, &capable(), at)?;
    let mut record = store.load(&created.request_id)?.ok_or("test: the committed agent")?;
    let agent_id = record.account_id.clone().ok_or("test: the agent account")?;
    record.state = AgentCreationState::Complete;
    record.master_range = 1;
    store.save(&record)?;
    Ok(agent_id)
}

/// The inventory entry of one agent after an observation of the transferred primary.
fn observed_entry(
    t: &Transfer,
    agent_id: &str,
    primary: &ramflux_protocol::custody::DeviceRef,
) -> TestResult<RebindEntry> {
    let store =
        store_of(&root_of(&t.pair.laptop)?, &t.pair.laptop.client.account_db()?.local_account_id)?;
    let entries = observe_primary(&store, primary)?;
    entries
        .into_iter()
        .find(|entry| entry.agent_account_id == agent_id)
        .ok_or_else(|| "test: the agent is observed".into())
}

#[test]
fn agent_rebind_request_reaches_only_the_new_primary() -> TestResult {
    let mut t = transfer_fixture("rebind-sent")?;
    runtime()?.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(
        sent_to_new_primary(&mut t),
    )))
}

async fn sent_to_new_primary(t: &mut Transfer) -> TestResult {
    let router = OwnRouter::new()?;
    let at = now()?;
    let agent_id = bound_agent(t, &router, at).await?;
    let transferred = transfer_primary(t, at + 10)?;
    let primary = transferred.body.master_certificate.body.primary_device_ref.clone();
    let entry = observed_entry(t, &agent_id, &primary)?;
    assert_eq!(entry.binding, RebindBinding::RebindPending, "the transfer pauses the agent");
    assert!(entry.request_id.is_none(), "nothing is sent before the request is frozen");

    // The packet is flushed on the real clock, so it is staged at the real instant.
    t.pair.laptop.client.agent_rebind_send(&agent_id, now()?)?;
    let laptop_root = root_of(&t.pair.laptop)?;
    let laptop_id = t.pair.laptop.client.account_db()?.local_account_id.clone();
    let desk_store = store_of(&laptop_root, &laptop_id)?;
    let request_id = desk_store
        .load_rebind(&agent_id)?
        .and_then(|entry| entry.request_id)
        .ok_or("test: the rebind request is recorded")?;
    router.route(&mut t.pair.laptop, &mut t.new_primary, 3).await?;

    let desk_record = desk_store.load(&request_id)?.ok_or("test: the desktop request")?;
    assert_eq!(desk_record.state, AgentCreationState::AuthorizationPending);
    let new_root = root_of(&t.new_primary)?;
    let new_id = t.new_primary.client.account_db()?.local_account_id.clone();
    let received = store_of(&new_root, &new_id)?
        .load(&request_id)?
        .ok_or("test: the new primary holds the plan")?;
    assert_eq!(
        received.request_hash, desk_record.request_hash,
        "the same plan reached the new primary"
    );
    assert_eq!(received.state, AgentCreationState::AuthorizationPending);
    let phone_root = root_of(&t.pair.phone)?;
    let phone_id = t.pair.phone.client.account_db()?.local_account_id.clone();
    assert!(
        store_of(&phone_root, &phone_id)?.load(&request_id)?.is_none(),
        "the old primary receives no rebind request"
    );
    Ok(())
}

#[test]
fn agent_rebind_request_is_not_sent_when_the_desktop_left_the_human() -> TestResult {
    let mut t = transfer_fixture("rebind-unpaired")?;
    runtime()?.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(
        desktop_left_the_human(&mut t),
    )))
}

async fn desktop_left_the_human(t: &mut Transfer) -> TestResult {
    let router = OwnRouter::new()?;
    let at = now()?;
    let agent_id = bound_agent(t, &router, at).await?;
    let transferred = transfer_primary(t, at + 10)?;
    let primary = transferred.body.master_certificate.body.primary_device_ref.clone();
    observed_entry(t, &agent_id, &primary)?;

    // A clock after the desktop branch lease: the desktop is no longer an enrolled sibling.
    let lapsed = at + 10 * 365 * 24 * 3600;
    let refused = t.pair.laptop.client.agent_rebind_send(&agent_id, lapsed);
    assert!(
        matches!(refused, Err(SdkError::AgentCreationRefused("creation_pairing_required"))),
        "a desktop that left the human refuses: {refused:?}"
    );
    let laptop_root = root_of(&t.pair.laptop)?;
    let laptop_id = t.pair.laptop.client.account_db()?.local_account_id.clone();
    let entry = store_of(&laptop_root, &laptop_id)?
        .load_rebind(&agent_id)?
        .ok_or("test: the inventory entry")?;
    assert_eq!(entry.binding, RebindBinding::RebindPending, "the agent stays paused");
    assert!(entry.request_id.is_none(), "no request is recorded");
    assert_eq!(
        entry.failure,
        Some(super::super::AgentFailure::CreationPairingRequired),
        "the typed reason is kept beside the state"
    );
    let new_root = root_of(&t.new_primary)?;
    let new_id = t.new_primary.client.account_db()?.local_account_id.clone();
    assert!(
        store_of(&new_root, &new_id)?.records()?.is_empty(),
        "the new primary receives nothing"
    );
    Ok(())
}

/// Stage D R3, the happy path on the real node. A committed agent is admitted and connected under
/// the old primary (P0). The human's transferred authority is published to the node. The desktop
/// pauses the agent and sends the rebind plan to the new primary (P1), which approves it. The
/// desktop commits the next range, publishes the rebind through a proof-only connection (no session),
/// and then connects the agent again. Fixture: the transfer, the directory adoption and the
/// authority refresh are `test_support::transfer_fixture` and `transfer_primary`; the node, the
/// router, the TLS and the publication are the real components.
#[test]
fn agent_custodian_primary_transfer_rebind() -> TestResult {
    let mut t = transfer_fixture("rebind-happy")?;
    runtime()?.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(
        rebind_on_the_real_node(&mut t),
    )))
}

async fn rebind_on_the_real_node(t: &mut Transfer) -> TestResult {
    let router = OwnRouter::new()?;
    let phone_root = root_of(&t.pair.phone)?;
    let phone_id = t.pair.phone.client.account_db()?.local_account_id.clone();
    let phone_device = t.pair.phone.client.owned_device_identity()?.device_id().to_owned();
    let phone_vault = vault_of(&t.pair.phone.client)?;
    let desk_root = root_of(&t.pair.laptop)?;
    let desk_id = t.pair.laptop.client.account_db()?.local_account_id.clone();
    let desk_vault = vault_of(&t.pair.laptop.client)?;

    // Five client connections: the human publication before and after the transfer, the agent's
    // activation, the rebind's proof-only publication and the agent's activation after state B.
    let node = TestNode::start(5, None).await?;
    node.publish_current(&phone_root, &phone_id, &phone_device, phone_vault.clone()).await?;

    let at = now()?;
    let created = desk_create(&t.pair, desk_vault.as_ref(), at)?;
    phone_decides(&mut t.pair, &router, &created, true, at).await?;
    let desk_store = store_of(&desk_root, &desk_id)?;
    let mut steps = DesktopSteps {
        node: &node,
        root: &desk_root,
        human: &desk_id,
        vault: desk_vault.clone(),
        connections: Vec::new(),
    };
    let state = advance_one(&mut steps, &desk_store, &created.request_id, at).await?;
    assert_eq!(state, AgentCreationState::Complete, "the agent is bound under the old primary");
    let agent_id = desk_store
        .load(&created.request_id)?
        .and_then(|record| record.account_id)
        .ok_or("test: the agent account")?;

    // The transfer P0 -> P1 is published to the node by the old primary's connection.
    let transferred = transfer_primary(t, at + 10)?;
    node.publish_current(&phone_root, &phone_id, &phone_device, phone_vault.clone()).await?;
    let primary = transferred.body.master_certificate.body.primary_device_ref.clone();
    let observed = super::super::observe_primary(&desk_store, &primary)?;
    let entry = observed
        .iter()
        .find(|entry| entry.agent_account_id == agent_id)
        .ok_or("test: the agent is observed")?;
    assert_eq!(entry.binding, super::super::RebindBinding::RebindPending, "the agent is paused");
    // The paused agent's session closes with the observation (contract 7.5 pause).
    steps.connections.clear();

    // The desktop freezes the rebind plan and sends it to the new primary, which approves it.
    t.pair.laptop.client.agent_rebind_send(&agent_id, now()?)?;
    let request_id = desk_store
        .load_rebind(&agent_id)?
        .and_then(|entry| entry.request_id)
        .ok_or("test: the rebind request is recorded")?;
    router.route(&mut t.pair.laptop, &mut t.new_primary, 3).await?;
    let hash = desk_store.load(&request_id)?.ok_or("test: desktop request")?.request_hash;
    let new_vault = vault_of(&t.new_primary.client)?;
    t.new_primary
        .client
        .native_bus_fixture
        .as_ref()
        .ok_or("test: the new primary fixture")?
        .vault
        .arm_agent_decision(&hash)?;
    t.new_primary.client.agent_creation_decide(
        new_vault.as_ref(),
        &decide_body(&request_id, &hash, Some(true)),
        now()?,
    )?;
    router.route(&mut t.new_primary, &mut t.pair.laptop, 4).await?;
    assert_eq!(
        desk_store.load(&request_id)?.ok_or("test: desktop request")?.state,
        AgentCreationState::Authorized,
        "the new primary's approval authorizes the rebind on the desktop"
    );

    // Commit the next range, publish the rebind (proof only), then connect the agent again.
    let state = advance_one(&mut steps, &desk_store, &request_id, now()?).await?;
    assert_eq!(state, AgentCreationState::Complete, "the rebind reaches state B");
    let proof = steps.connections.first().ok_or("test: the rebind publication connection")?;
    assert!(proof.session().is_none(), "the rebind publication opens no session");
    let reconnected = steps.connections.last().ok_or("test: the agent connection")?;
    assert!(reconnected.session().is_some(), "the agent connects again under state B");
    let entry = desk_store.load_rebind(&agent_id)?.ok_or("test: the inventory")?;
    assert_eq!(entry.binding, super::super::RebindBinding::Bound);
    assert_eq!(entry.bound_primary, primary);

    // The rebound profile names the new primary with a higher epoch; the anchor and the keys are the
    // original ones (nothing is widened or replaced).
    let original_record =
        desk_store.load(&created.request_id)?.ok_or("test: the creation record")?;
    let original = decode_register_plan(&original_record.plan_bytes()?)?;
    let bound = desk_store.load(&request_id)?.ok_or("test: the rebind record")?;
    let rebound = decode_register_plan(&bound.plan_bytes()?)?;
    let profile = super::super::stored_profile(&bound)?;
    assert_eq!(profile.body.custodian_primary, primary, "the profile names the new primary");
    assert!(profile.body.profile_epoch > 1, "the profile epoch is raised");
    assert_eq!(rebound.agent_anchor, original.agent_anchor, "the anchor is unchanged");
    assert_eq!(
        rebound.master_public_key, original.master_public_key,
        "the master key is unchanged"
    );
    assert_eq!(rebound.self_signing_public_key, original.self_signing_public_key);
    assert_eq!(rebound.branch_signing_public_key, original.branch_signing_public_key);
    let agent = crate::custody::load_account(&desk_root, &agent_id, now()?)?;
    assert_eq!(
        agent.record().body.master_certificate.body.primary_device_ref,
        primary,
        "the agent's authority names the new primary"
    );
    drop(steps);
    node.finish().await
}
