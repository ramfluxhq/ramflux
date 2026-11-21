// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `agent_delete_in_u_removes_the_vault_items_and_retires_on_both_roots` (AGENT-IDENTITY-01 E6,
//! decision r22 item 2). Real: the agent is created and completed through the real creation flow on
//! the test node (`primary_phone::complete_agent`), the replicas travel through the real router, and
//! the vault items are the ones the creation stored. Checked: every item the creation names (the
//! self-signing key, the branch seeds, the provisioning secret, the `agent-master:` seed and every
//! `agent-master-cert:` item up to the highest range) is gone afterwards; the local agent account
//! directory is gone; both roots hold the retirement; an older packet cannot resurrect the agent;
//! the delete refuses without `confirmed` and in a state other than `U`.
use super::super::test_support::{
    DesktopSteps, Pair, TestNode, TestResult, assert_no_account, item_present, now, pair, root_of,
    store_of, vault_of,
};
use super::primary_phone::complete_agent;
use crate::SdkError;
use crate::agent_record::metadata_of;
use crate::custody::PrimaryVault;
use crate::custody::tests::TestVault;
use crate::custody::vault::agent_master_item::certificate_reference;
use ramflux_protocol::custody::{RegisterPlan, decode_register_plan};
use ramflux_protocol::message::AgentPersona;
use std::sync::Arc;

fn runtime() -> TestResult<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

#[test]
fn agent_delete_in_u_removes_the_vault_items_and_retires_on_both_roots() -> TestResult {
    let mut pair = pair("delete-in-u")?;
    runtime()?.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(delete_case(
        &mut pair,
    ))))
}

/// Whether one item the creation named is still held. The agent master seed and its certificates
/// live in the test vault's agent store; the other items through the provider's own presence check.
fn held(
    fixture: &TestVault,
    desk: &dyn PrimaryVault,
    plan: &RegisterPlan,
    reference: &str,
) -> TestResult<bool> {
    if reference.starts_with("agent-master:") || reference.starts_with("agent-master-cert:") {
        return Ok(fixture.agent_item_present(reference)?);
    }
    Ok(item_present(desk, plan, reference))
}

async fn delete_case(pair: &mut Pair) -> TestResult {
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let desk_vault: Arc<dyn PrimaryVault> = vault_of(&pair.laptop.client)?;
    let fixture: Arc<TestVault> = pair
        .laptop
        .client
        .native_bus_fixture
        .as_ref()
        .ok_or("test: the desktop vault fixture")?
        .vault
        .clone();
    // The node takes exactly the connections this test makes: the publication and the activation.
    // `finish` waits for every one of them to close.
    let node = TestNode::start(2, None).await?;
    let mut steps = DesktopSteps {
        node: &node,
        root: &laptop_root,
        human: &laptop_id,
        vault: desk_vault.clone(),
        connections: Vec::new(),
    };
    let (agent_id, complete, router) = complete_agent(pair, &node, &mut steps).await?;
    let plan = decode_register_plan(&complete.plan_bytes()?)?;
    let agent = plan.agent_anchor.clone();
    let at = now()?;

    // The creation holds every item of the agent: the seed, the certificates and the pending items.
    let refs = complete.vault_refs.clone();
    let master = refs
        .iter()
        .find(|reference| reference.starts_with("agent-master:"))
        .ok_or("the completed creation names the agent master")?
        .clone();
    assert!(complete.master_range >= 1, "a genesis certificate was issued");
    let certificates: Vec<String> = (1..=complete.master_range)
        .map(|range| certificate_reference(&master, range))
        .collect::<Result<_, _>>()?;
    for reference in refs.iter().chain(certificates.iter()) {
        assert!(held(&fixture, desk_vault.as_ref(), &plan, reference)?, "{reference} is held");
    }

    // The replica of the phone is made by a change: the persona edit is broadcast as a whole record.
    let base = pair.laptop.client.agent_record_get(&agent)?.identity;
    let persona = AgentPersona {
        name: "before delete".into(),
        avatar: String::new(),
        responsibility: "answers".into(),
    };
    let edited = pair.laptop.client.agent_persona_edit(&agent, &base, persona, Some(true), at)?;
    router.route(&mut pair.laptop, &mut pair.phone, 3).await?;
    let older = metadata_of(&edited);
    assert_eq!(pair.phone.client.agent_record_get(&agent)?.lifecycle, "U");

    // Without the owner's confirmation nothing is removed.
    let unconfirmed = pair.laptop.client.agent_delete(desk_vault.as_ref(), &agent, None, at);
    assert!(
        matches!(unconfirmed, Err(SdkError::AgentCreationRefused("confirmation_required"))),
        "delete without confirmed refuses"
    );
    for reference in refs.iter().chain(certificates.iter()) {
        assert!(held(&fixture, desk_vault.as_ref(), &plan, reference)?, "{reference} stays");
    }

    // Confirmed: every item goes, the local account goes, the record becomes X.
    let retired = pair.laptop.client.agent_delete(desk_vault.as_ref(), &agent, Some(true), at)?;
    assert_eq!(retired.lifecycle, "X", "the desktop retires the identity");
    for reference in refs.iter().chain(certificates.iter()) {
        assert!(!held(&fixture, desk_vault.as_ref(), &plan, reference)?, "{reference} is deleted");
    }
    assert_no_account(&laptop_root, &agent_id, at);
    let stored = store_of(&laptop_root, &laptop_id)?.load(&complete.request_id)?;
    assert!(stored.ok_or("the creation record")?.vault_refs.is_empty(), "no item is named");

    // Both roots hold the retirement; an older packet cannot resurrect the agent.
    router.route(&mut pair.laptop, &mut pair.phone, 4).await?;
    assert_eq!(pair.phone.client.agent_record_get(&agent)?.lifecycle, "X", "the phone retires");
    assert!(!pair.phone.client.receive_agent_metadata(&older)?, "the older packet is ignored");
    assert_eq!(pair.phone.client.agent_record_get(&agent)?.lifecycle, "X", "still retired");

    // A second delete is not a state U delete.
    let again = pair.laptop.client.agent_delete(desk_vault.as_ref(), &agent, Some(true), at);
    assert!(matches!(again, Err(SdkError::AgentCreationRefused("unsupported"))), "state X refuses");
    drop(steps);
    node.finish().await
}
