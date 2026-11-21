// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unit tests of the agent record store and its creation (AGENT-IDENTITY-01 E2). The plan comes from
//! the real `begin` of the creation store (`custody/agent_creation/tests.rs` fixture); nothing is
//! stored by hand except the intent and the refused variants.
use super::edit::{create_from_plan, edit_record, retire};
use super::store::parse_cursor;
use super::{AgentIntent, AgentRecordStore};
use crate::SdkError;
use crate::agent_record::seed_for_test;
use crate::custody::agent_creation::AgentCreationStore;
use crate::custody::agent_creation::tests::{
    HUMAN, HumanFixture, begin_for_human, human_fixture_with,
};
use crate::custody::memory_vault::MemoryPrimaryVault;
use ramflux_protocol::custody::decode_register_plan;
use ramflux_protocol::message::{AgentAccessPolicy, AgentPersona};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn persona() -> AgentPersona {
    AgentPersona {
        name: "Support".into(),
        avatar: String::new(),
        responsibility: "answers questions".into(),
    }
}

fn owner_access() -> AgentAccessPolicy {
    AgentAccessPolicy {
        dm: "owner".into(),
        group_inviters: "owner".into(),
        allowed_humans: Vec::new(),
    }
}

/// A real plan of the human fixture, the agent record store beside its creation store, and the
/// fixture that owns the temporary root: the caller keeps it alive, or the store would recreate
/// directories inside a root that was already removed.
type Planned = (ramflux_protocol::custody::RegisterPlan, AgentRecordStore, HumanFixture);
fn planned() -> Result<Planned, Box<dyn std::error::Error>> {
    let fixture = human_fixture_with(Some(b"human data secret"))?;
    let root = fixture.root.0.to_path_buf();
    let store = AgentCreationStore::open(root, HUMAN)?;
    let desk = Arc::new(MemoryPrimaryVault::default());
    let outcome = begin_for_human(&fixture, &store, &desk, "req-record", None)?;
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    Ok((plan, AgentRecordStore::at(store.agent_record_dir()), fixture))
}

#[test]
fn creation_writes_one_record_in_state_u_and_replays_the_first_identity() -> TestResult {
    let (plan, records, _fixture) = planned()?;
    let intent = AgentIntent { persona: persona(), access: owner_access() };
    let first = create_from_plan(&records, &plan, &intent)?;
    assert_eq!(first.lifecycle, "U", "the new agent is in state U");
    assert_eq!(
        first.custodian_anchor, plan.human_primary.account_anchor,
        "the custodian is the owner"
    );
    assert_eq!(first.role, "named");
    assert_eq!(first.persona, persona());
    assert_eq!(
        first.identity.author.as_ref().map(|author| author.device_id.as_str()),
        Some(plan.desktop.device_id.as_str()),
        "the desktop authored the record"
    );
    let replayed = create_from_plan(&records, &plan, &intent)?;
    assert_eq!(replayed.identity, first.identity, "a replay returns the stored identity");
    let loaded = records.load(&plan.agent_anchor)?.ok_or("the record is stored")?;
    assert_eq!(loaded, first, "the stored record reads back unchanged");
    Ok(())
}

#[test]
fn an_invalid_access_policy_or_persona_refuses_and_writes_nothing() -> TestResult {
    let (plan, records, _fixture) = planned()?;
    let mut bad_dm = owner_access();
    bad_dm.dm = "everyone".into();
    let refused =
        create_from_plan(&records, &plan, &AgentIntent { persona: persona(), access: bad_dm });
    assert!(matches!(refused, Err(SdkError::AgentCreationRefused("access_policy_invalid"))));

    let mut no_name = persona();
    no_name.name = "  ".into();
    let refused = create_from_plan(
        &records,
        &plan,
        &AgentIntent { persona: no_name, access: owner_access() },
    );
    assert!(matches!(refused, Err(SdkError::AgentCreationRefused("persona_invalid"))));
    assert!(records.load(&plan.agent_anchor)?.is_none(), "no record after a refusal");
    Ok(())
}

#[test]
fn allowed_humans_need_allowlist_and_must_be_unique() -> TestResult {
    let mut access = owner_access();
    access.allowed_humans = vec!["human-one".into()];
    assert!(
        matches!(
            crate::agent_record::check_access(&access),
            Err(SdkError::AgentCreationRefused("access_policy_invalid"))
        ),
        "allowed humans without allowlist refuse"
    );
    access.dm = "allowlist".into();
    crate::agent_record::check_access(&access)?;
    access.allowed_humans = vec!["human-one".into(), "human-one".into()];
    assert!(
        matches!(
            crate::agent_record::check_access(&access),
            Err(SdkError::AgentCreationRefused("access_policy_invalid"))
        ),
        "a duplicate allowed human refuses"
    );
    Ok(())
}

#[test]
fn a_record_file_that_names_another_agent_is_refused() -> TestResult {
    let (plan, records, _fixture) = planned()?;
    create_from_plan(&records, &plan, &AgentIntent { persona: persona(), access: owner_access() })?;
    let source = records.load(&plan.agent_anchor)?.ok_or("the record")?;
    // The record of one agent planted under another agent's file name.
    let other = "other-agent-anchor-0000000000000000000000";
    let path = records.dir_for_test().join(format!("{other}.json"));
    std::fs::write(&path, serde_json::to_vec(&source)?)?;
    assert!(
        matches!(records.load(other), Err(SdkError::CustodySetupInvalid)),
        "a file under another anchor's name refuses"
    );
    Ok(())
}

#[test]
fn watch_reads_changes_after_a_cursor_across_a_tombstone_and_refuses_bad_cursors() -> TestResult {
    let (plan, records, _fixture) = planned()?;
    let intent = AgentIntent { persona: persona(), access: owner_access() };
    let empty = records.changes(parse_cursor("")?)?;
    assert!(empty.records.is_empty() && empty.cursor == 0 && !empty.more, "no record, cursor zero");

    // Change 1: the created agent. Change 2: a second agent. Change 3: an edit of the first.
    let created = create_from_plan(&records, &plan, &intent)?;
    let from_start = records.changes(0)?;
    assert_eq!(from_start.records.len(), 1, "watch from empty sees the created agent");
    assert_eq!(from_start.cursor, 1, "the cursor is the head");
    assert_eq!(records.changes(from_start.cursor)?.records.len(), 0, "nothing after the head");
    seed_for_test(&records, &ramflux_protocol::encode_base64url([7_u8; 32]), &plan.desktop, 1)?;
    let edited =
        edit_record(&records, &plan.agent_anchor, &created.identity, &plan.desktop, 2, |r| {
            r.persona.name = "edited".into();
        })?;
    let after_edit = records.changes(from_start.cursor)?;
    assert_eq!(
        after_edit.records.len(),
        2,
        "the second agent and the edited first one are both changed"
    );
    assert_eq!(after_edit.cursor, 3, "the new cursor is the head");
    assert_eq!(edited.change_seq, 3, "the edit took the next sequence");

    // Change 4: the tombstone of the first agent is delivered as a change too.
    retire(&records, &plan.agent_anchor, &edited.identity, &plan.desktop, 3)?;
    let tombstone = records.changes(after_edit.cursor)?;
    assert_eq!(tombstone.records.len(), 1, "the tombstone is a change");
    assert_eq!(tombstone.records[0].lifecycle, "X", "and it names the retired state");
    assert_eq!(tombstone.cursor, 4);
    assert_eq!(records.changes(tombstone.cursor)?.records.len(), 0, "nothing after the tombstone");

    // A cursor above the head was never issued here: refused, the caller lists again.
    let future = records.changes(5);
    assert!(matches!(future, Err(SdkError::AgentCreationRefused("journal_cursor_invalid"))));

    // Only the canonical decimal form is a cursor.
    assert_eq!(parse_cursor("")?, 0);
    assert_eq!(parse_cursor("17")?, 17);
    for bad in ["007", "+7", "-1", "x1", "18446744073709551616", " 1"] {
        assert!(
            matches!(
                parse_cursor(bad),
                Err(SdkError::AgentCreationRefused("journal_cursor_invalid"))
            ),
            "{bad:?} is not a cursor"
        );
    }
    Ok(())
}

#[test]
fn a_retired_anchor_is_never_created_again_on_this_device() -> TestResult {
    let (plan, records, _fixture) = planned()?;
    let intent = AgentIntent { persona: persona(), access: owner_access() };
    let first = create_from_plan(&records, &plan, &intent)?;
    retire(&records, &plan.agent_anchor, &first.identity, &plan.desktop, 2)?;
    let again = create_from_plan(&records, &plan, &intent);
    assert!(
        matches!(again, Err(SdkError::AgentCreationRefused("agent_retired"))),
        "a replayed creation of a retired anchor refuses"
    );
    assert_eq!(records.load(&plan.agent_anchor)?.ok_or("the tombstone stays")?.lifecycle, "X");
    Ok(())
}
