// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D tests of the rebind inventory and the primary observation. Real creation store on a
//! temporary data root; the primary transfer is produced by the real cooperative transfer in
//! `ramflux-crypto` (see `observation` tests). Nothing here sleeps: every instant is explicit.
use super::rebind::{RebindBinding, RebindEntry};
use super::rebind_observe::observe_primary;
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore};
use super::tests::{HUMAN as HUMAN_ACCOUNT, begin_for_human, human_fixture};
use crate::custody::memory_vault::MemoryPrimaryVault;
use ramflux_crypto::custody::{
    CooperativeTransferInput, MasterKey, SelfSigningKey, cooperative_transfer_preserving_devices,
    verify_record,
};
use ramflux_protocol::custody::{DeviceRef, decode_register_plan};
use ramflux_protocol::encode_base64url;
use tempfile::TempDir;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HUMAN: &str = "human";

fn primary_ref(device_id: &str) -> DeviceRef {
    DeviceRef {
        account_anchor: "anchor-human".into(),
        device_id: device_id.into(),
        device_epoch: 1,
    }
}

fn entry(agent: &str, binding: RebindBinding, primary: &str) -> RebindEntry {
    RebindEntry {
        agent_account_id: agent.into(),
        binding,
        bound_primary: primary_ref(primary),
        master_range: 1,
        request_id: None,
        failure: None,
    }
}

#[test]
fn rebind_inventory_round_trips_and_lists_sorted() -> TestResult {
    let dir = TempDir::new()?;
    let store = AgentCreationStore::open(dir.path(), HUMAN)?;
    store.save_rebind(&entry("agent-b", RebindBinding::Live, "primary"))?;
    store.save_rebind(&entry("agent-a", RebindBinding::RebindPending, "primary"))?;
    assert_eq!(
        store.load_rebind("agent-a")?,
        Some(entry("agent-a", RebindBinding::RebindPending, "primary")),
        "test: a saved inventory entry must load unchanged"
    );
    assert!(store.load_rebind("agent-missing")?.is_none(), "test: an absent entry is None");
    let listed: Vec<String> =
        store.rebind_entries()?.into_iter().map(|entry| entry.agent_account_id).collect();
    assert_eq!(listed, ["agent-a", "agent-b"], "test: the inventory lists every agent sorted");
    Ok(())
}

#[test]
fn rebind_inventory_refuses_corrupt_renamed_and_empty_entries() -> TestResult {
    let dir = TempDir::new()?;
    let store = AgentCreationStore::open(dir.path(), HUMAN)?;
    let rebind_dir =
        dir.path().join("custody_accounts").join(HUMAN).join("agent_creation").join("rebind");
    assert!(store.rebind_entries()?.is_empty(), "test: no inventory directory is an empty list");
    store.save_rebind(&entry("agent-c", RebindBinding::Live, "primary"))?;
    std::fs::write(rebind_dir.join("agent-c.json"), b"{not json")?;
    assert!(store.load_rebind("agent-c").is_err(), "test: a corrupt entry refuses");
    store.save_rebind(&entry("agent-d", RebindBinding::Live, "primary"))?;
    std::fs::rename(rebind_dir.join("agent-d.json"), rebind_dir.join("agent-e.json"))?;
    assert!(
        store.load_rebind("agent-e").is_err(),
        "test: an entry whose file name is not its agent id refuses"
    );
    let mut empty_range = entry("agent-f", RebindBinding::Live, "primary");
    empty_range.master_range = 0;
    assert!(store.save_rebind(&empty_range).is_err(), "test: a zero master range refuses to save");
    Ok(())
}

#[test]
fn rebind_binding_tokens_are_closed_and_only_settled_states_are_compared() {
    assert_eq!(RebindBinding::RebindPending.as_str(), "rebind_pending");
    assert_eq!(RebindBinding::Committed.as_str(), "committed");
    assert!(RebindBinding::Live.is_settled() && RebindBinding::Bound.is_settled());
    assert!(!RebindBinding::RebindPending.is_settled() && !RebindBinding::Committed.is_settled());
    let refused: Result<RebindBinding, _> = serde_json::from_str("\"paused\"");
    assert!(refused.is_err(), "test: an unknown binding token refuses on read");
}

/// The human's primary after a real cooperative transfer: the desktop device becomes the primary in
/// the next master range, signed by the human master key and a new primary key. Nothing is faked:
/// the envelope is what `ramflux-crypto` issues for a management transfer.
fn transferred_primary(
    fixture: &super::tests::HumanFixture,
) -> Result<DeviceRef, Box<dyn std::error::Error>> {
    let now = fixture.now;
    let account = crate::custody::store::load_account(&fixture.root.0, HUMAN_ACCOUNT, now)?;
    let current = verify_record(account.record(), now, None, None)?;
    let master = MasterKey::from_vault_seed(&Zeroizing::new([21_u8; 32]));
    let new_primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([31_u8; 32]));
    let destination = DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id: "desktop-device".into(),
        device_epoch: 1,
    };
    let candidate = cooperative_transfer_preserving_devices(
        &master,
        &new_primary,
        &current,
        CooperativeTransferInput {
            destination,
            fresh_destination: None,
            highest_observed_range: 0,
            issued_at: now + 1,
            master_cert_id: encode_base64url([34_u8; 32]),
        },
    )?;
    Ok(candidate.body.master_certificate.body.primary_device_ref.clone())
}

/// An agent whose creation reached `complete` on this root. Fixture: the plan is the real plan of
/// `begin` against the human fixture; the state is then set by hand. No account is committed.
fn complete_agent(
    fixture: &super::tests::HumanFixture,
    store: &AgentCreationStore,
    request_id: &str,
    agent: &str,
) -> Result<AgentCreationRecord, Box<dyn std::error::Error>> {
    let desk = MemoryPrimaryVault::default();
    begin_for_human(fixture, store, &desk, request_id, None)?;
    let mut record = store.load(request_id)?.ok_or("test: begun record missing")?;
    record.state = AgentCreationState::Complete;
    record.account_id = Some(agent.into());
    record.master_range = 1;
    store.save(&record)?;
    Ok(record)
}

fn plan_primary(record: &AgentCreationRecord) -> Result<DeviceRef, Box<dyn std::error::Error>> {
    Ok(decode_register_plan(&record.plan_bytes()?)?.human_primary)
}

#[test]
fn observation_keeps_a_live_agent_live_while_its_primary_is_current() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN_ACCOUNT)?;
    let record = complete_agent(&fixture, &store, "req-live", "agent-live")?;
    let entries = observe_primary(&store, &plan_primary(&record)?)?;
    assert_eq!(entries.len(), 1, "test: one complete agent gives one entry");
    assert_eq!(entries[0].binding, RebindBinding::Live, "test: the approved primary is current");
    assert_eq!(entries[0].master_range, 1, "test: the entry carries the record's master range");
    assert_eq!(
        store.load_rebind("agent-live")?,
        Some(entries[0].clone()),
        "test: the observation is written before it is reported"
    );
    Ok(())
}

#[test]
fn a_primary_change_pauses_each_agent_and_an_old_primary_never_clears_the_pause() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN_ACCOUNT)?;
    let record = complete_agent(&fixture, &store, "req-moved", "agent-moved")?;
    let original = plan_primary(&record)?;
    let moved = transferred_primary(&fixture)?;
    assert_ne!(moved, original, "test: the transfer must change the primary");
    let paused = observe_primary(&store, &moved)?;
    assert_eq!(paused[0].binding, RebindBinding::RebindPending, "test: a change pauses the agent");
    assert_eq!(paused[0].bound_primary, original, "test: the entry keeps its approved primary");
    let back = observe_primary(&store, &original)?;
    assert_eq!(
        back[0].binding,
        RebindBinding::RebindPending,
        "test: the old primary never clears the pause"
    );
    let again = observe_primary(&store, &moved)?;
    assert_eq!(again[0].binding, RebindBinding::RebindPending, "test: the pause is stable");
    assert_eq!(
        store.load_rebind("agent-moved")?.map(|entry| entry.binding),
        Some(RebindBinding::RebindPending),
        "test: the pause is durable"
    );
    Ok(())
}

#[test]
fn a_bound_agent_is_compared_with_the_primary_it_was_rebound_to() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN_ACCOUNT)?;
    let record = complete_agent(&fixture, &store, "req-bound", "agent-bound")?;
    let original = plan_primary(&record)?;
    let moved = transferred_primary(&fixture)?;
    store.save_rebind(&RebindEntry {
        agent_account_id: "agent-bound".into(),
        binding: RebindBinding::Bound,
        bound_primary: moved.clone(),
        master_range: 2,
        request_id: None,
        failure: None,
    })?;
    let kept = observe_primary(&store, &moved)?;
    assert_eq!(
        kept[0].binding,
        RebindBinding::Bound,
        "test: a bound agent under its primary stays"
    );
    let paused = observe_primary(&store, &original)?;
    assert_eq!(
        paused[0].binding,
        RebindBinding::RebindPending,
        "test: a bound agent is paused by the next change"
    );
    Ok(())
}

#[test]
fn observation_ignores_records_that_are_not_complete() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN_ACCOUNT)?;
    let desk = MemoryPrimaryVault::default();
    begin_for_human(&fixture, &store, &desk, "req-waiting", None)?;
    let moved = transferred_primary(&fixture)?;
    assert!(
        observe_primary(&store, &moved)?.is_empty(),
        "test: a request that is not complete has no inventory entry"
    );
    assert!(store.rebind_entries()?.is_empty(), "test: nothing is written for it");
    Ok(())
}
