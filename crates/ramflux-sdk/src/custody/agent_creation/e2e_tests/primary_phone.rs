// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `agent_creation_primary_phone_round_trip`: the desktop creates an agent, the exact plan reaches
//! the primary phone through the real router, one approval signs it, the decision returns through
//! the router, and the committed agent account is admitted by the real test node with a receipt.
use super::super::test_support::{
    DesktopSteps, OwnRouter, Pair, TestNode, TestResult, create_body, decide_body, now, pair,
    root_of, store_of, vault_of,
};
use crate::custody::agent_creation::{AgentCreationState, advance_one};
use crate::custody::{CreationState, PrimaryVault};
use std::sync::Arc;

fn runtime() -> TestResult<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

#[test]
fn agent_creation_primary_phone_round_trip() -> TestResult {
    let mut pair = pair("primary-phone")?;
    runtime()?.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(round_trip(
        &mut pair,
    ))))
}

async fn round_trip(pair: &mut Pair) -> TestResult {
    let phone_root = root_of(&pair.phone)?;
    let laptop_root = root_of(&pair.laptop)?;
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let phone_device = pair.phone.client.owned_device_identity()?.device_id().to_owned();
    let phone_vault: Arc<dyn PrimaryVault> = vault_of(&pair.phone.client)?;
    let desk_vault: Arc<dyn PrimaryVault> = vault_of(&pair.laptop.client)?;

    // The human account reaches the test node first: the phone publishes its current record.
    let node = TestNode::start(2, None).await?;
    node.publish_current(&phone_root, &phone_id, &phone_device, phone_vault.clone()).await?;

    // The desktop starts the creation. Nothing is listed before the receipt.
    let created =
        pair.laptop.client.agent_create(desk_vault.as_ref(), &create_body(Some(true)), now()?)?;
    assert_eq!(created.state, "authorization_pending");
    let desk_store = store_of(&laptop_root, &laptop_id)?;
    let desk_record = desk_store.load(&created.request_id)?.ok_or("desktop record")?;
    let agent_id = desk_record.account_id.clone().ok_or("the request reserves its account")?;
    assert!(
        !laptop_root.join("custody_accounts").join(&agent_id).exists(),
        "no agent account exists on the desktop before the receipt"
    );

    // The exact plan reaches the phone through the real router; the phone holds no account.
    let router = OwnRouter::new()?;
    router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let phone_store = store_of(&phone_root, &phone_id)?;
    let plan_record = phone_store.load(&created.request_id)?.ok_or("the phone stores the plan")?;
    assert_eq!(plan_record.state, AgentCreationState::AuthorizationPending);
    assert_eq!(plan_record.request_hash, desk_record.request_hash, "the phone holds the same plan");
    assert!(plan_record.account_id.is_none(), "the phone holds no agent account");
    assert!(!phone_root.join("custody_accounts").join(&agent_id).exists());

    // One approval from the primary phone signs the plan and returns through the router.
    let hash = plan_record.request_hash.clone();
    pair.phone
        .client
        .native_bus_fixture
        .as_ref()
        .ok_or("the phone fixture vault")?
        .vault
        .arm_agent_decision(&hash)?;
    let decided = pair.phone.client.agent_creation_decide(
        phone_vault.as_ref(),
        &decide_body(&created.request_id, &hash, Some(true)),
        now()?,
    )?;
    assert_eq!(decided.state, "authorized");
    router.route(&mut pair.phone, &mut pair.laptop, 2).await?;
    let authorized = desk_store.load(&created.request_id)?.ok_or("desktop record")?;
    assert_eq!(authorized.state, AgentCreationState::Authorized);

    // The desktop commits the agent and the real node admits its AgentPublish.
    let mut steps = DesktopSteps {
        node: &node,
        root: &laptop_root,
        human: &laptop_id,
        vault: desk_vault.clone(),
        connections: Vec::new(),
    };
    let state = advance_one(&mut steps, &desk_store, &created.request_id, now()?).await?;
    assert_eq!(state, AgentCreationState::Complete);
    let agent = crate::custody::load_account(&laptop_root, &agent_id, now()?)?;
    assert_eq!(agent.state(), CreationState::Live, "the agent account is live after the receipt");
    assert_eq!(agent.custodian_account_id(), Some(laptop_id.as_str()));
    let complete = desk_store.load(&created.request_id)?.ok_or("desktop record")?;
    assert_eq!(complete.state, AgentCreationState::Complete);
    assert!(complete.receipt_b64.is_some(), "the verified receipt is saved");
    assert!(
        phone_store.load(&created.request_id)?.ok_or("phone record")?.account_id.is_none(),
        "the phone never receives an agent account"
    );
    drop(steps);
    node.finish().await
}
