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
    OwnRouter, Transfer, TestResult, capable, desk_create, now, phone_decides, root_of,
    store_of, transfer_fixture, transfer_primary, vault_of,
};
use super::super::{AgentCreationState, commit_approved};
use crate::SdkError;

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
fn observed_entry(t: &Transfer, agent_id: &str, primary: &ramflux_protocol::custody::DeviceRef) -> TestResult<RebindEntry> {
    let store = store_of(&root_of(&t.pair.laptop)?, &t.pair.laptop.client.account_db()?.local_account_id)?;
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
    let received = store_of(&new_root, &new_id)?.load(&request_id)?.ok_or("test: the new primary holds the plan")?;
    assert_eq!(received.request_hash, desk_record.request_hash, "the same plan reached the new primary");
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
