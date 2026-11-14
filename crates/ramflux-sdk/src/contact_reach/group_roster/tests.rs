// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adopted native heads exercise automatic staging, continuous-root floors and repair.
use super::super::group_test_support::install_grant;
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::{contact_reach::Applied, group_state::GroupStateChange};

async fn group_fixture() -> TestResult<(Fixture, Fixture, VerifiedGroupState)> {
    let owner = Fixture::new("reach-roster-owner").await?;
    let peer = Fixture::new("reach-roster-peer").await?;
    owner.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&owner.manifest)?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("owner account")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "roster-group",
        "roster-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let member = peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity;
    let joined = owner.client.shared_group_change_with_primary(
        "roster-group",
        &owner.config.target_delivery_id,
        GroupStateChange::Add { member, role: ramflux_protocol::SharedGroupRole::Member },
        Some(&primary),
    )?;
    peer.client.accept_shared_group_state(&joined, &peer.config.target_delivery_id)?;
    install_grant(&peer, &joined)?;
    Ok((owner, peer, joined))
}
fn advance(owner: &Fixture, change: GroupStateChange) -> TestResult<VerifiedGroupState> {
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("owner account")?
        .group_primary(owner.vault.as_ref())?;
    Ok(owner.client.shared_group_change_with_primary(
        "roster-group",
        &owner.config.target_delivery_id,
        change,
        Some(&primary),
    )?)
}
fn roster(operation: &Operation) -> TestResult<&GroupRoster> {
    if let Operation::GroupRoster { roster, .. } = operation {
        Ok(roster)
    } else {
        Err("derived roster operation".into())
    }
}

#[tokio::test]
async fn cr_group_roster_preserves_inflight_retry_and_repairs_without_allow() -> TestResult {
    let (owner, peer, joined) = group_fixture().await?;
    let third = advance(&owner, GroupStateChange::SetName { name: "third".into() })?;
    peer.client.accept_shared_group_state(&third, &peer.config.target_delivery_id)?;
    let now = crate::custody::network_now()?;
    let first = peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
    let fourth = advance(&owner, GroupStateChange::SetName { name: "fourth".into() })?;
    peer.client.accept_shared_group_state(&fourth, &peer.config.target_delivery_id)?;
    assert_eq!(
        peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?,
        first,
        "a newer adopted head cannot replace the signed operation while its outcome is uncertain"
    );
    let result = OperationResult::Admission { revision: 2, outcome: Applied::Applied };
    peer.client.apply_reach_group_roster_result("roster-group", &first, &result)?;
    let second =
        peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
    assert_eq!(
        roster(&second)?.header.body.group_epoch,
        fourth.view().epoch,
        "the successor staged with adoption is promoted after the older result"
    );
    assert_eq!(
        roster(&second)?.members.first().ok_or("owner root")?.since_epoch,
        joined.view().epoch,
        "continuous membership remains clamped to the recipient's JOIN epoch"
    );
    peer.client.apply_reach_group_roster_result("roster-group", &second, &result)?;
    peer.client.account_db()?.remove_actor_state(&key("roster-group"))?;
    assert!(
        !peer.client.stage_reach_group_repairs()?,
        "the bounded state-read repair page recovers this missing roster without an allow"
    );
    let repaired =
        peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
    assert_eq!(
        roster(&repaired)?.members,
        roster(&second)?.members,
        "repair rederives the same floors from adopted history and creates only bookkeeping"
    );
    let before = peer.client.group_reach_mirror()?.ok_or("mirror")?;
    let grant = grant(&before.records, &fourth)?;
    ramflux_crypto::contact_reach::verify_group_roster(
        roster(&repaired)?,
        grant,
        peer.client.born_v3_account.as_ref().ok_or("peer account")?.verified(),
        now,
    )?;
    assert_eq!(before.records.len(), 1, "roster maintenance never adds or replaces the live grant");
    Ok(())
}

#[tokio::test]
async fn cr_group_roster_readded_root_gets_new_continuous_floor() -> TestResult {
    let (owner, peer, _) = group_fixture().await?;
    let visitor = Fixture::new("reach-roster-visitor").await?;
    owner.client.persist_fetched_identity_directory(&visitor.manifest)?;
    peer.client.persist_fetched_identity_directory(&visitor.manifest)?;
    let member = visitor.client.owned_group_actor(&visitor.config.target_delivery_id)?.identity;
    let added = advance(
        &owner,
        GroupStateChange::Add {
            member: member.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.client.accept_shared_group_state(&added, &peer.config.target_delivery_id)?;
    let removed = advance(
        &owner,
        GroupStateChange::Remove {
            root_commitment: member.root_commitment.clone(),
            device_id: member.device_id.clone(),
        },
    )?;
    peer.client.accept_shared_group_state(&removed, &peer.config.target_delivery_id)?;
    let readded = advance(
        &owner,
        GroupStateChange::Add {
            member: member.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.client.accept_shared_group_state(&readded, &peer.config.target_delivery_id)?;
    let operation = peer.client.prepare_reach_group_roster(
        peer.vault.as_ref(),
        "roster-group",
        crate::custody::network_now()?,
    )?;
    let bookkeeping = roster(&operation)?;
    assert_eq!(
        bookkeeping.header.body.group_epoch,
        readded.view().epoch,
        "unsigned superseded intents coalesce at the newest adopted head before any RPC"
    );
    let root = bookkeeping
        .members
        .iter()
        .find(|entry| entry.root == member.root_commitment)
        .ok_or("readded visitor")?;
    assert_eq!(
        root.since_epoch,
        readded.view().epoch,
        "a removed then re-added root cannot retain its earlier admission floor"
    );
    assert!(root.since_epoch > added.view().epoch, "the old interval ended at removal");
    let result = OperationResult::Admission { revision: 2, outcome: Applied::Applied };
    peer.client.apply_reach_group_roster_result("roster-group", &operation, &result)?;
    let db = peer.client.account_db()?;
    let mut queue: Queue = db.load_actor_state(&key("roster-group"))?.ok_or("settled roster")?;
    let checkpoint = queue.checkpoint.as_mut().ok_or("signed checkpoint")?;
    checkpoint
        .members
        .iter_mut()
        .find(|entry| entry.root == member.root_commitment)
        .ok_or("checkpoint visitor")?
        .since_epoch = added.view().epoch;
    checkpoint.header.body.members_hash =
        custody::framed_hash(GROUP_ROSTER_MEMBERS_DOMAIN, &checkpoint.members)?;
    db.persist_actor_state(&key("roster-group"), &queue)?;
    let next = advance(&owner, GroupStateChange::SetName { name: "after checkpoint".into() })?;
    peer.client.accept_shared_group_state(&next, &peer.config.target_delivery_id)?;
    assert!(
        matches!(
            peer.client.prepare_reach_group_roster(
                peer.vault.as_ref(),
                "roster-group",
                crate::custody::network_now()?
            ),
            Err(SdkError::Crypto(_))
        ),
        "repair must authenticate the original signed checkpoint before re-signing any membership floor"
    );
    Ok(())
}

#[tokio::test]
async fn cr_group_roster_keeps_root_floor_when_its_oldest_device_leaves() -> TestResult {
    let (owner, peer, _) = group_fixture().await?;
    let mut visitor = Fixture::new("reach-roster-device-owner").await?;
    let sibling = visitor.enroll_sibling("reach-roster-device-sibling", "second").await?;
    owner.client.persist_fetched_identity_directory(&visitor.manifest)?;
    peer.client.persist_fetched_identity_directory(&visitor.manifest)?;
    let first = visitor.client.owned_group_actor(&visitor.config.target_delivery_id)?.identity;
    let second = sibling.client.owned_group_actor(&sibling.config.target_delivery_id)?.identity;
    let root_joined = advance(
        &owner,
        GroupStateChange::Add {
            member: first.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.client.accept_shared_group_state(&root_joined, &peer.config.target_delivery_id)?;
    let sibling_joined = advance(
        &owner,
        GroupStateChange::Add { member: second, role: ramflux_protocol::SharedGroupRole::Member },
    )?;
    peer.client.accept_shared_group_state(&sibling_joined, &peer.config.target_delivery_id)?;
    let oldest_left = advance(
        &owner,
        GroupStateChange::Remove {
            root_commitment: first.root_commitment.clone(),
            device_id: first.device_id,
        },
    )?;
    peer.client.accept_shared_group_state(&oldest_left, &peer.config.target_delivery_id)?;
    let operation = peer.client.prepare_reach_group_roster(
        peer.vault.as_ref(),
        "roster-group",
        crate::custody::network_now()?,
    )?;
    let entry = roster(&operation)?
        .members
        .iter()
        .find(|entry| entry.root == first.root_commitment)
        .ok_or("continuously present root")?;
    assert_eq!(
        entry.since_epoch,
        root_joined.view().epoch,
        "root membership remained continuous while the newer device overlapped the older one"
    );
    assert!(
        entry.since_epoch < sibling_joined.view().epoch,
        "the earliest remaining device's joined_epoch is not the root's admission floor"
    );
    Ok(())
}

#[tokio::test]
async fn cr_group_roster_missing_history_stays_unsigned_and_fork_pauses_repair() -> TestResult {
    let (owner, peer, _) = group_fixture().await?;
    let next = advance(&owner, GroupStateChange::SetName { name: "history gap".into() })?;
    peer.client.accept_shared_group_state(&next, &peer.config.target_delivery_id)?;
    let db = peer.client.account_db()?;
    db.remove_actor_state(&format!(
        "group-state/known-heads/{}",
        ramflux_protocol::encode_base64url("roster-group")
    ))?;
    let result = peer.client.prepare_reach_group_roster(
        peer.vault.as_ref(),
        "roster-group",
        crate::custody::network_now()?,
    );
    assert!(
        matches!(result, Err(SdkError::InboundPending(_))),
        "an incomplete restore cannot invent the root's continuous membership interval"
    );
    let queue: Queue = db.load_actor_state(&key("roster-group"))?.ok_or("pending roster")?;
    assert!(
        queue.active.as_ref().is_some_and(|intent| intent.operation.is_none()),
        "missing proof leaves the committed retry id unsigned and sends no operation"
    );
    peer.client.pause_reach_group_roster("roster-group")?;
    peer.client.stage_reach_group_roster_repair("roster-group")?;
    assert!(
        peer.client.require_reach_group_roster_unforked("roster-group").is_err(),
        "ordinary repair cannot clear a retained group fork warning"
    );
    assert!(
        peer.client
            .prepare_reach_group_roster(
                peer.vault.as_ref(),
                "roster-group",
                crate::custody::network_now()?
            )
            .is_err(),
        "a fork pauses automatic signatures as well as bookkeeping repair"
    );
    Ok(())
}
