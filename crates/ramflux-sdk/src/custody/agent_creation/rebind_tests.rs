// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D tests of the rebind inventory and the primary observation. Real creation store on a
//! temporary data root; the primary transfer is produced by the real cooperative transfer in
//! `ramflux-crypto` (see `observation` tests). Nothing here sleeps: every instant is explicit.
use super::rebind::{RebindBinding, RebindEntry};
use super::store::AgentCreationStore;
use ramflux_protocol::custody::DeviceRef;
use tempfile::TempDir;

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
