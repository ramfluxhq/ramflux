// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `agent_creation_primary_phone_round_trip`: the desktop creates an agent, the exact plan reaches
//! the primary phone through the real router, one approval signs it, the decision returns through
//! the router, and the committed agent account is admitted by the real test node with a receipt.
//! The node is then asked, through the real admission only, for the identical publication (the
//! saved receipt comes back), for a different decision under the same request (refused), and for
//! the agent's directory record (the record the receipt names).
use super::super::test_support::{
    DesktopSteps, OwnRouter, Pair, TestNode, TestResult, create_body, decide_body,
    later_primary_decision, now, pair, root_of, saved_receipt, store_of, vault_of,
};
use crate::custody::agent_creation::{AgentCreationState, advance_one, load_publishing};
use crate::custody::{CreationState, CustodyConnection, PrimaryVault};
use ramflux_protocol::custody::{
    CustodyProofAction, CustodyRefusal, CustodyServerFrame, decode_register_decision,
    decode_register_plan, object_hash,
};
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
    // The node takes four client connections: this publication, the agent's activation, one
    // proof connection and one directory lookup.
    let node = TestNode::start(4, None).await?;
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
    Box::pin(node_view(&node, pair, (&phone_root, &laptop_root), &agent_id, &complete, desk_vault.clone())).await?;

    drop(steps);
    node.finish().await
}

/// What the real node holds for the completed agent: the identical publication answered with the
/// saved receipt, a different decision refused, and the directory record of the agent.
async fn node_view(
    node: &TestNode,
    pair: &Pair,
    roots: (&std::path::Path, &std::path::Path),
    agent_id: &str,
    complete: &crate::custody::agent_creation::AgentCreationRecord,
    desk_vault: Arc<dyn PrimaryVault>,
) -> TestResult {
    let (phone_root, laptop_root) = roots;
    let receipt = saved_receipt(complete)?;
    let plan = decode_register_plan(&complete.plan_bytes()?)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let laptop_device = pair.laptop.client.owned_device_identity()?.device_id().to_owned();

    // (i) The identical AgentPublish again, through the real admission: the saved receipt returns.
    let mut proof = CustodyConnection::connect_for_proof(
        node.config(laptop_root, agent_id, &plan.agent_device.device_id),
        desk_vault.clone(),
    )
    .await?;
    let publication = proof.account().publication();
    let saved = load_publishing(laptop_root, proof.account())?.ok_or("the saved approval")?;
    let replay = proof.prove(saved.publish_action(&publication)).await?;
    assert_eq!(replay, CustodyServerFrame::AgentPublished { receipt: Box::new(receipt.clone()) });

    // (ii) A different decision for the same request id: the node refuses as an idempotency
    // conflict, and the stored receipt still returns for the identical publication afterwards.
    let later = later_primary_decision(&pair.phone, phone_root, &complete.plan_bytes()?, now()? + 1)?;
    let CustodyProofAction::AgentPublish { publication: pub_box, agent_profile, plan: plan_box, .. } =
        saved.publish_action(&publication)
    else {
        return Err("test: the saved approval builds an AgentPublish".into());
    };
    let other = CustodyProofAction::AgentPublish {
        publication: pub_box,
        agent_profile,
        plan: plan_box,
        authorization: Box::new(decode_register_decision(&later)?),
    };
    let conflict = proof.prove(other).await;
    assert!(
        matches!(conflict, Err(crate::SdkError::CustodyNetwork(CustodyRefusal::IdempotencyConflict))),
        "the node refuses a second decision for the same request: {conflict:?}"
    );
    let again = proof.prove(saved.publish_action(&publication)).await?;
    assert_eq!(again, CustodyServerFrame::AgentPublished { receipt: Box::new(receipt.clone()) });
    drop(proof);

    // (iii) The directory record of the agent, read by a peer through the production lookup of an
    // established session: the record the receipt names is the one the node serves.
    let mut peer = CustodyConnection::connect(
        node.config(laptop_root, &laptop_id, &laptop_device),
        desk_vault.clone(),
    )
    .await?;
    let entry = peer.lookup(&plan.agent_device).await?;
    assert_eq!(object_hash(&entry.publication.record)?, receipt.record_hash);
    drop(peer);
    Ok(())
}
