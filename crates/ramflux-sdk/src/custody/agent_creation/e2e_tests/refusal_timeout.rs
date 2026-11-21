// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refusal, deadline and atomicity cells of contract 7.4 and 7.6, each test named by its behaviour
//! (`agent_creation_refusal_timeout_atomicity`). Real: the desktop and phone native fixtures with
//! their real stores and vaults, the real client creation, decision and receive code, the real
//! `RouterCore` between the roots, and the real test node (`network_tests`) for the lost reply.
//! Time is always an explicit `now`: nothing sleeps for the 300-second deadline. The deadline is
//! the stored `expires_at` of the record (`issued_at + REGISTER_TTL_SECONDS`), read back and passed.
//! Probes: a pending item is probed by its kind (primary, branch, provisioning). Agent master items
//! have no read method on the vault; their removal is checked through the record's `vault_refs`,
//! which is emptied only when every delete, master included, succeeded.
use super::super::test_support::{
    DesktopSteps, OwnRouter, Pair, TestNode, TestResult, assert_items_gone, assert_items_present,
    assert_no_account, assert_retry_creates_no_second_anchor, begin_again, capable, decide_body,
    desk_create, desk_record, now, pair, phone_decides, root_of, saved_receipt, store_of, vault_of,
};
use crate::SdkError;
use crate::custody::CustodyConnection;
use crate::custody::agent_creation::{
    AgentCreationState, AgentFailure, advance_one, commit_approved, load_publishing, resume_request,
};
use crate::custody::network_tests::ReplyFault;
use ramflux_protocol::custody::{CustodyServerFrame, REGISTER_TTL_SECONDS, decode_register_plan};

fn scenario(case: impl std::future::Future<Output = TestResult>) -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(case)))
}

#[test]
fn phone_that_never_receives_keeps_the_request_authorization_pending() -> TestResult {
    let mut pair = pair("refusal-offline")?;
    offline_case(&mut pair)
}

/// Phone offline (7.6 row "Phone offline / request redelivery"): nothing reaches the phone, the
/// request stays `authorization_pending` with its deadline, the phone holds nothing, and no agent
/// account exists on the desktop.
fn offline_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    assert_eq!(record.state, AgentCreationState::AuthorizationPending);
    let laptop_root = root_of(&pair.laptop)?;
    let store = store_of(&laptop_root, &pair.laptop.client.account_db()?.local_account_id)?;
    let later = resume_request(&store, vault.as_ref(), &record.request_id, at + 60)?;
    assert_eq!(later.state, AgentCreationState::AuthorizationPending);
    assert_eq!(later.expires_at, record.expires_at, "the deadline does not move");
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    assert!(
        store_of(&root_of(&pair.phone)?, &phone_id)?.load(&record.request_id)?.is_none(),
        "the phone holds nothing for an undelivered request"
    );
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&laptop_root, &agent_id, at);
    Ok(())
}

#[test]
fn phone_deny_refuses_and_leaves_no_account_or_pending_item() -> TestResult {
    let mut pair = pair("refusal-deny")?;
    scenario(deny_case(&mut pair))
}

/// Signed deny (7.6 row "Phone deny / local cancel"): the desktop request is `refused` with its
/// authorization failure, every pending item is deleted, no account exists, and a retry of the
/// same operation id makes no second anchor.
async fn deny_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let before = record.vault_refs.clone();
    assert_items_present(vault.as_ref(), &plan, &before);
    let router = OwnRouter::new()?;
    phone_decides(pair, &router, &record, false, now()?).await?;
    let laptop_root = root_of(&pair.laptop)?;
    let store = store_of(&laptop_root, &pair.laptop.client.account_db()?.local_account_id)?;
    let refused = store.load(&record.request_id)?.ok_or("test: the desktop record")?;
    assert_eq!(refused.state, AgentCreationState::Refused, "a signed deny refuses the request");
    assert_eq!(refused.failure, Some(AgentFailure::AuthorizationRefused));
    assert_items_gone(vault.as_ref(), &plan, &before, &refused);
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&laptop_root, &agent_id, at + 2);
    assert_retry_creates_no_second_anchor(&store, vault.as_ref(), &refused, at + 3)
}

#[test]
fn original_deadline_expires_at_its_instant_and_cleans_up() -> TestResult {
    let mut pair = pair("refusal-expiry")?;
    expiry_case(&mut pair)
}

/// One second before the stored `expires_at` keeps the request; at `expires_at` it expires. The
/// deadline is the original 300 seconds of the plan, read from the record and never extended.
fn expiry_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    assert_eq!(record.expires_at, plan.issued_at + REGISTER_TTL_SECONDS, "the original lifetime");
    let laptop_root = root_of(&pair.laptop)?;
    let store = store_of(&laptop_root, &pair.laptop.client.account_db()?.local_account_id)?;
    let before = record.vault_refs.clone();
    assert_items_present(vault.as_ref(), &plan, &before);
    let kept = resume_request(&store, vault.as_ref(), &record.request_id, record.expires_at - 1)?;
    assert_eq!(kept.state, AgentCreationState::AuthorizationPending, "one second early keeps it");
    let expired = resume_request(&store, vault.as_ref(), &record.request_id, record.expires_at)?;
    assert_eq!(expired.state, AgentCreationState::Expired, "at the deadline it expires");
    assert_items_gone(vault.as_ref(), &plan, &before, &expired);
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&laptop_root, &agent_id, record.expires_at);
    assert_retry_creates_no_second_anchor(&store, vault.as_ref(), &expired, record.expires_at + 1)
}

#[test]
fn restart_while_pending_keeps_the_original_deadline() -> TestResult {
    let mut pending = pair("refusal-restart-pending")?;
    restart_pending_case(&mut pending)
}

#[test]
fn restart_while_authorized_keeps_the_original_deadline() -> TestResult {
    let mut approved = pair("refusal-restart-authorized")?;
    scenario(restart_authorized_case(&mut approved))
}

/// Restart while `authorization_pending`: the reopened store keeps the stored deadline.
fn restart_pending_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let before = record.vault_refs.clone();
    drop(store_of(&laptop_root, &laptop_id)?);
    let reopened = store_of(&laptop_root, &laptop_id)?;
    let again = resume_request(&reopened, vault.as_ref(), &record.request_id, at + 100)?;
    assert_eq!(again.state, AgentCreationState::AuthorizationPending);
    assert_eq!(again.expires_at, record.expires_at, "a restart does not restart the deadline");
    let expired = resume_request(&reopened, vault.as_ref(), &record.request_id, record.expires_at)?;
    assert_eq!(expired.state, AgentCreationState::Expired);
    assert_items_gone(vault.as_ref(), &plan, &before, &expired);
    Ok(())
}

/// Restart while `authorized` (approved, not yet committed): the stored deadline still expires it.
async fn restart_authorized_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let before = record.vault_refs.clone();
    phone_decides(pair, &OwnRouter::new()?, &record, true, now()?).await?;
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let authorized = desk_record(pair, &record.request_id)?;
    assert_eq!(authorized.state, AgentCreationState::Authorized);
    assert_eq!(authorized.expires_at, record.expires_at);
    drop(store_of(&laptop_root, &laptop_id)?);
    let reopened = store_of(&laptop_root, &laptop_id)?;
    let again = resume_request(&reopened, vault.as_ref(), &record.request_id, at + 100)?;
    assert_eq!(again.state, AgentCreationState::Authorized, "approval survives the restart");
    assert_eq!(again.expires_at, record.expires_at, "a restart does not restart the deadline");
    let expired = resume_request(&reopened, vault.as_ref(), &record.request_id, record.expires_at)?;
    assert_eq!(expired.state, AgentCreationState::Expired, "the stored deadline expires it");
    assert_items_gone(vault.as_ref(), &plan, &before, &expired);
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&laptop_root, &agent_id, record.expires_at);
    Ok(())
}

#[test]
fn clock_behind_the_issue_time_expires_the_request() -> TestResult {
    let mut pair = pair("refusal-clock")?;
    clock_case(&mut pair)
}

/// A clock that moved behind the stored issue time expires the request and cleans it up.
fn clock_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let laptop_root = root_of(&pair.laptop)?;
    let store = store_of(&laptop_root, &pair.laptop.client.account_db()?.local_account_id)?;
    let before = record.vault_refs.clone();
    assert_items_present(vault.as_ref(), &plan, &before);
    let behind = resume_request(&store, vault.as_ref(), &record.request_id, record.issued_at - 1)?;
    assert_eq!(
        behind.state,
        AgentCreationState::Expired,
        "a clock behind the issue time expires it"
    );
    assert_items_gone(vault.as_ref(), &plan, &before, &behind);
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&laptop_root, &agent_id, at);
    Ok(())
}

#[cfg(unix)]
#[test]
fn failed_vault_delete_leaves_cleanup_pending_until_a_later_run_succeeds() -> TestResult {
    let mut pair = pair("refusal-cleanup")?;
    cleanup_case(&mut pair)
}

/// A failed pending-item delete (the real vault directory refuses writes) is `cleanup_pending`,
/// never success; the next run finishes the deletion and every item is gone.
#[cfg(unix)]
fn cleanup_case(pair: &mut Pair) -> TestResult {
    use crate::custody::memory_vault::MemoryPrimaryVault;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::TempDir::new()?;
    let vault_dir = dir.path().join("vault");
    std::fs::create_dir_all(&vault_dir)?;
    let desk = MemoryPrimaryVault::persist_at(vault_dir.join("items.json"))?;
    let at = now()?;
    let record = desk_create(pair, &desk, at)?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let laptop_root = root_of(&pair.laptop)?;
    let store = store_of(&laptop_root, &pair.laptop.client.account_db()?.local_account_id)?;
    let before = record.vault_refs.clone();
    assert_items_present(&desk, &plan, &before);
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o500))?;
    let failed = resume_request(&store, &desk, &record.request_id, record.expires_at);
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o700))?;
    let failed = failed?;
    assert_eq!(failed.state, AgentCreationState::CleanupPending, "a failed delete is not success");
    assert_eq!(failed.intended, Some(AgentCreationState::Expired));
    assert_eq!(failed.vault_refs.len(), before.len(), "every undeleted reference is kept");
    let done = resume_request(&store, &desk, &record.request_id, record.expires_at + 1)?;
    assert_eq!(done.state, AgentCreationState::Expired, "a later run finishes the cleanup");
    assert_items_gone(&desk, &plan, &before, &done);
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&laptop_root, &agent_id, record.expires_at);
    Ok(())
}

#[test]
fn lost_agent_publish_reply_is_publication_unknown_then_reconciles_to_the_saved_receipt()
-> TestResult {
    let mut pair = pair("refusal-lost-reply")?;
    scenario(lost_reply_case(&mut pair))
}

/// The node admits the `AgentPublish` and its reply is lost once (`ReplyFault::DropAgentPublished`).
/// The request is `publication_unknown`, the account and its keys are kept, and the identical
/// publication returns the node's saved receipt; the request then completes with that receipt.
async fn lost_reply_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let phone_vault = vault_of(&pair.phone.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    phone_decides(pair, &OwnRouter::new()?, &record, true, now()?).await?;
    let phone_root = root_of(&pair.phone)?;
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let phone_device = pair.phone.client.owned_device_identity()?.device_id().to_owned();
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let store = store_of(&laptop_root, &laptop_id)?;
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    let node = TestNode::start(4, Some(ReplyFault::DropAgentPublished)).await?;
    node.publish_current(&phone_root, &phone_id, &phone_device, phone_vault).await?;
    let mut steps = DesktopSteps {
        node: &node,
        root: &laptop_root,
        human: &laptop_id,
        vault: vault.clone(),
        connections: Vec::new(),
    };
    let lost = advance_one(&mut steps, &store, &record.request_id, now()?).await;
    assert!(lost.is_err(), "the lost reply is an error, never a success");
    let unknown = store.load(&record.request_id)?.ok_or("test: the desktop record")?;
    assert_eq!(unknown.state, AgentCreationState::PublicationUnknown, "not 'not created'");
    assert!(laptop_root.join("custody_accounts").join(&agent_id).exists(), "the account is kept");
    let state = advance_one(&mut steps, &store, &record.request_id, now()?).await?;
    assert_eq!(state, AgentCreationState::Complete, "the same request reconciles");
    let complete = store.load(&record.request_id)?.ok_or("test: the desktop record")?;
    let receipt = saved_receipt(&complete)?;
    let plan = decode_register_plan(&complete.plan_bytes()?)?;
    let mut proof = CustodyConnection::connect_for_proof(
        node.config(&laptop_root, &agent_id, &plan.agent_device.device_id),
        vault.clone(),
    )
    .await?;
    let publication = proof.account().publication();
    let saved = load_publishing(&laptop_root, proof.account())?.ok_or("the saved approval")?;
    let answer = proof.prove(saved.publish_action(&publication)).await?;
    assert_eq!(answer, CustodyServerFrame::AgentPublished { receipt: Box::new(receipt) });
    drop(proof);
    drop(steps);
    node.finish().await
}

#[test]
fn same_operation_replay_keeps_the_saved_request_in_pending_authorized_and_committed() -> TestResult
{
    let mut pair = pair("refusal-replay")?;
    scenario(replay_case(&mut pair))
}

/// Same-operation replay (7.6 row "Desktop starts / same-operation replay", states P, A and C). The
/// retry with the request's own id returns the saved plan, account and hash in every state, and
/// creates no second anchor. In C the replay reports the committed state (`publication_pending`).
async fn replay_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let store = store_of(&laptop_root, &laptop_id)?;

    // P: the request waits for the phone.
    let pending = desk_create(pair, vault.as_ref(), at)?;
    assert_retry_creates_no_second_anchor(&store, vault.as_ref(), &pending, at + 1)?;
    let still = store.load(&pending.request_id)?.ok_or("test: the desktop record")?;
    assert_eq!(still.state, AgentCreationState::AuthorizationPending, "the replay keeps P");

    // A: the phone approved; the desktop holds the decision and has not committed.
    phone_decides(pair, &OwnRouter::new()?, &pending, true, now()?).await?;
    let authorized = desk_record(pair, &pending.request_id)?;
    assert_eq!(authorized.state, AgentCreationState::Authorized);
    assert_retry_creates_no_second_anchor(&store, vault.as_ref(), &authorized, at + 2)?;

    // C: the commit point is passed (the local bundle is written); publication is still pending.
    let committed = commit_approved(
        &store,
        vault.as_ref(),
        &laptop_id,
        &pending.request_id,
        &capable(),
        at + 3,
    )?;
    assert_eq!(committed.state, AgentCreationState::PublicationPending, "C is committed");
    assert_retry_creates_no_second_anchor(&store, vault.as_ref(), &committed, at + 4)?;
    let replayed = begin_again(&store, vault.as_ref(), &committed, at + 5)?;
    assert_eq!(replayed.state, AgentCreationState::PublicationPending, "the replay reports C");
    Ok(())
}

#[test]
fn a_decision_at_the_original_deadline_is_refused_and_the_phone_stays_pending() -> TestResult {
    let mut pair = pair("refusal-late-decide")?;
    scenario(late_decide_case(&mut pair))
}

/// A decision after the stored deadline (7.6 row "Original deadline expires"): the primary refuses
/// with `CustodyExpired` before any presence check, nothing is saved on the phone, and the desktop
/// keeps its request pending until its own clock expires it.
async fn late_decide_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let router = OwnRouter::new()?;
    router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let phone_vault = vault_of(&pair.phone.client)?;
    let hash = record.request_hash.clone();
    let fixture = pair.phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?;
    fixture.vault.arm_agent_decision(&hash)?;
    let late = pair.phone.client.agent_creation_decide(
        phone_vault.as_ref(),
        &decide_body(&record.request_id, &hash, Some(true)),
        record.expires_at,
    );
    assert!(matches!(late, Err(SdkError::CustodyExpired)), "a decision at the deadline is refused");
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let held = store_of(&root_of(&pair.phone)?, &phone_id)?
        .load(&record.request_id)?
        .ok_or("test: the phone stores the plan")?;
    assert_eq!(held.state, AgentCreationState::AuthorizationPending, "the phone stays pending");
    assert!(held.decision_b64.is_none(), "no decision is saved for a late answer");
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let desk = store_of(&laptop_root, &laptop_id)?.load(&record.request_id)?;
    assert_eq!(
        desk.ok_or("test: the desktop record")?.state,
        AgentCreationState::AuthorizationPending
    );
    Ok(())
}

#[test]
fn local_expiry_on_the_phone_reaches_x_and_a_replay_of_it_stays_x() -> TestResult {
    let mut pair = pair("refusal-phone-expiry")?;
    scenario(phone_expiry_case(&mut pair))
}

/// The phone's own copy of a request expires by its own clock at the stored deadline (X), and a
/// second look at that deadline keeps X. The phone never held an account or a pending item.
async fn phone_expiry_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let router = OwnRouter::new()?;
    router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let phone_root = root_of(&pair.phone)?;
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let phone_store = store_of(&phone_root, &phone_id)?;
    let phone_vault = vault_of(&pair.phone.client)?;
    let before = phone_store.load(&record.request_id)?.ok_or("test: the phone stores the plan")?;
    assert_eq!(before.state, AgentCreationState::AuthorizationPending);
    let expired =
        resume_request(&phone_store, phone_vault.as_ref(), &record.request_id, record.expires_at)?;
    assert_eq!(expired.state, AgentCreationState::Expired, "the phone's copy reaches X");
    let again = resume_request(
        &phone_store,
        phone_vault.as_ref(),
        &record.request_id,
        record.expires_at + 5,
    )?;
    assert_eq!(again.state, AgentCreationState::Expired, "a replay of the expiry stays X");
    if let Some(account_id) = &record.account_id {
        assert!(!phone_root.join("custody_accounts").join(account_id).exists(), "no phone account");
    }
    Ok(())
}
