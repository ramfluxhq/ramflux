// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adopted native heads exercise automatic staging, continuous-root floors and repair.
use super::super::group_test_support::{roster_fixture as group_fixture, verified_records};
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::{contact_reach::Applied, group_state::GroupStateChange};

#[test]
fn cr_roster_queue_requires_explicit_current_context_fields() -> TestResult {
    let current = serde_json::to_value(Queue::default())?;
    for field in ["checkpoint", "active", "next", "success", "refusal"] {
        let mut missing = current.clone();
        missing.as_object_mut().ok_or("queue object")?.remove(field);
        assert!(
            serde_json::from_value::<Queue>(missing).is_err(),
            "missing {field} cannot silently select an older roster-queue shape"
        );
    }
    assert!(
        serde_json::from_value::<Queue>(current).is_ok(),
        "a current unsigned queue has explicit null context rather than omitted fields"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_roster_refusal_cannot_roll_back_an_observed_command_expiry() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let (_, peer, _) = group_fixture().await?;
        let now = crate::custody::network_now()?;
        peer.client.stage_reach_group_roster_repair("roster-group")?;
        let operation =
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
        peer.client.pause_reach_group_roster("roster-group")?;
        let db = peer.client.account_db()?;
        let before: Queue = db.load_actor_state(&key("roster-group"))?.ok_or("forked intent")?;
        let observed = now.checked_add(301).ok_or("command expiry")?;
        assert!(
            matches!(
                peer.client.prepare_reach_group_roster(
                    peer.vault.as_ref(),
                    "roster-group",
                    observed
                ),
                Err(SdkError::InboundPending(_))
            ),
            "the fork must refuse expiry replacement inside its operation transaction"
        );
        assert!(
            db.reach_fenced_now(now)? >= observed,
            "the standalone UTC observation survives that operation's rollback"
        );
        assert!(
            matches!(
                peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now),
                Err(SdkError::InboundPending(_))
            ),
            "rolling wall time back cannot return an expired signed roster for retry"
        );
        let after: Queue = db.load_actor_state(&key("roster-group"))?.ok_or("preserved intent")?;
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(&after)?,
            ramflux_protocol::canonical_json_bytes(&before)?,
            "a refused repair preserves the exact signed intent and fork warning"
        );
        assert!(
            after.active.as_ref().and_then(|intent| intent.operation.as_ref()) == Some(&operation),
            "the failed repair neither replaces nor acknowledges the original signed operation"
        );
        Ok(())
    })
    .await?
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
    tokio::time::timeout(std::time::Duration::from_secs(60), roster_retry_and_repair()).await?
}

async fn roster_retry_and_repair() -> TestResult {
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
    let mirror = peer.client.group_reach_mirror()?.ok_or("mirror before collection")?;
    peer.client.install_reach_state(verified_records(
        &peer,
        &mirror.home_head_hash,
        mirror.records.clone(),
        now,
    )?)?;
    let original_hash = custody::framed_hash(OPERATION_HASH_DOMAIN, &roster(&first)?.header)?;
    assert!(
        peer.client
            .account_db()?
            .reach_provenance_reference(
                ramflux_protocol::contact_reach::ObjectKind::GroupRoster,
                &original_hash,
            )?
            .is_some(),
        "equal-content snapshot collection must retain the uncertain signed roster's original"
    );
    let result = OperationResult::GroupRoster {
        group_epoch: roster(&first)?.header.body.group_epoch,
        outcome: Applied::Applied,
    };
    peer.client.apply_reach_group_roster_result("roster-group", &first, &result)?;
    let second =
        peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
    let mirror = peer.client.group_reach_mirror()?.ok_or("mirror with checkpoint")?;
    peer.client.install_reach_state(verified_records(
        &peer,
        &mirror.home_head_hash,
        mirror.records.clone(),
        now,
    )?)?;
    assert!(
        peer.client
            .account_db()?
            .reach_provenance_reference(
                ramflux_protocol::contact_reach::ObjectKind::GroupRoster,
                &original_hash,
            )?
            .is_some(),
        "the last applied checkpoint remains pinned alongside the successor intent"
    );
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
    let second_result = OperationResult::GroupRoster {
        group_epoch: roster(&second)?.header.body.group_epoch,
        outcome: Applied::Applied,
    };
    peer.client.apply_reach_group_roster_result("roster-group", &second, &second_result)?;
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
    assert_eq!(
        before.records.iter().filter(|record| matches!(record, StateRecord::Grant { .. })).count(),
        1,
        "roster maintenance never adds or replaces the live grant"
    );
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
    let result = OperationResult::GroupRoster {
        group_epoch: bookkeeping.header.body.group_epoch,
        outcome: Applied::Applied,
    };
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

#[tokio::test]
async fn cr_reach_read_rechecks_current_authority_and_refreshes_same_content_binding() -> TestResult
{
    let (_, mut peer, _) = group_fixture().await?;
    let before = peer.client.group_reach_mirror()?.ok_or("verified mirror")?;
    let home = ramflux_protocol::encode_base64url([30; 32]);
    let now = crate::custody::network_now()?;
    let fresh = verified_records(&peer, &home, before.records.clone(), now)?;
    assert_eq!(
        fresh.state_hash(),
        before.state_hash,
        "fresh transport/home binding does not change the canonical content identity"
    );
    peer.client.install_reach_state(fresh)?;
    let refreshed = peer.client.group_reach_mirror()?.ok_or("refreshed mirror")?;
    assert_eq!(
        refreshed.home_head_hash, home,
        "an equal-revision equal-content read must refresh its independently verified home binding"
    );
    let stale = verified_records(&peer, &home, before.records.clone(), now)?;
    let _sibling = peer.enroll_sibling("reach-state-new-sibling", "second").await?;
    assert!(
        matches!(peer.client.install_reach_state(stale), Err(SdkError::InboundPending(_))),
        "authority advancing between page verification and writer commit invalidates that read"
    );
    assert!(
        peer.client.group_reach_mirror().is_err(),
        "a stale saved authority cannot supply positive group bookkeeping after the custody head changes"
    );
    let current =
        verified_records(&peer, &home, before.records.clone(), crate::custody::network_now()?)?;
    peer.client.install_reach_state(current)?;
    let updated = peer.client.group_reach_mirror()?.ok_or("current mirror")?;
    assert_ne!(
        updated.authority_head_hash, before.authority_head_hash,
        "the renewed authority binding is saved even when admission/content revisions stay equal"
    );
    assert_eq!(
        updated.state_hash, before.state_hash,
        "transport and current authority refresh never manufacture a new signed admission"
    );
    Ok(())
}

#[tokio::test]
async fn cr_group_roster_recovery_rebinds_home_and_replaces_expired_intent() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let (_, peer, _) = group_fixture().await?;
        let now = crate::custody::network_now()?;
        peer.client.stage_reach_group_roster_repair("roster-group")?;
        let first =
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
        let first_epoch = roster(&first)?.header.body.group_epoch;
        let before = peer.client.group_reach_mirror()?.ok_or("mirror before repair")?;
        peer.client.apply_reach_group_roster_result(
            "roster-group",
            &first,
            &OperationResult::GroupRoster { group_epoch: first_epoch, outcome: Applied::Applied },
        )?;
        peer.client.stage_reach_group_roster_repair("roster-group")?;
        let db = peer.client.account_db()?;
        let settled: Queue = db.load_actor_state(&key("roster-group"))?.ok_or("settled queue")?;
        assert!(settled.active.is_none(), "valid local success suppresses redundant repair");
        let home = ramflux_protocol::encode_base64url([31; 32]);
        peer.client.install_reach_state(verified_records(
            &peer,
            &home,
            before.records.clone(),
            now,
        )?)?;
        let second =
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
        assert_ne!(second, first, "a verified home change invalidates the saved success");
        assert_eq!(
            roster(&second)?.header.body.grant_hash,
            roster(&first)?.header.body.grant_hash,
            "home repair must never replace or resign the live allow"
        );
        let expired = peer.client.prepare_reach_group_roster(
            peer.vault.as_ref(),
            "roster-group",
            now + 300,
        )?;
        let Operation::GroupRoster { operation_id: old_id, .. } = &second else {
            return Err("old roster".into());
        };
        let Operation::GroupRoster { operation_id: new_id, roster: renewed } = &expired else {
            return Err("new roster".into());
        };
        assert_ne!(
            new_id, old_id,
            "an expired uncertain command needs a fresh durable operation id"
        );
        assert_eq!(
            renewed.header.body.issued_at,
            now + 300,
            "the replacement is signed with fresh time"
        );
        assert_eq!(
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?,
            expired,
            "clock rollback cannot resurrect the discarded signed command"
        );
        let after = peer.client.group_reach_mirror()?.ok_or("mirror after repair")?;
        assert_eq!(after.records, before.records, "repair cannot alter grants or retained floors");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn cr_group_roster_remote_errors_preserve_uncertainty_and_stop_definite_refusals()
-> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let (_, peer, _) = group_fixture().await?;
        let now = crate::custody::network_now()?;
        peer.client.stage_reach_group_roster_repair("roster-group")?;
        let first =
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
        let remote = |reason| {
            super::super::remote_result(OperationResult::Error {
                reason,
                retry_after_ms: None,
                current_revision: None,
            })
            .expect_err("test: native connection must lift the pinned Error arm")
        };
        peer.client.settle_reach_group_roster_remote_error(
            "roster-group",
            &first,
            &remote(Reason::ForeignStorageUnavailable),
        )?;
        assert_eq!(
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?,
            first,
            "uncertain storage must retain exact signed operation bytes for dedup retry"
        );
        peer.client.settle_reach_group_roster_remote_error(
            "roster-group",
            &first,
            &remote(Reason::ReachCommandExpired),
        )?;
        let fresh =
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
        assert_ne!(fresh, first, "remote expiry must stage a fresh committed operation identity");
        peer.client.settle_reach_group_roster_remote_error(
            "roster-group",
            &fresh,
            &remote(Reason::GroupEpochStale),
        )?;
        peer.client.stage_reach_group_roster_repair("roster-group")?;
        let db = peer.client.account_db()?;
        let queue: Queue = db.load_actor_state(&key("roster-group"))?.ok_or("stale note")?;
        assert!(
            queue.active.is_none() && queue.success.is_none(),
            "a stale answer stops same-head repair without fabricating an applied success"
        );
        let mut queue = queue;
        queue.refusal = None;
        db.persist_actor_state(&key("roster-group"), &queue)?;
        peer.client.stage_reach_group_roster_repair("roster-group")?;
        let retry =
            peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now)?;
        peer.client.settle_reach_group_roster_remote_error(
            "roster-group",
            &retry,
            &remote(Reason::CustodyRefused),
        )?;
        assert!(
            matches!(
                peer.client.prepare_reach_group_roster(peer.vault.as_ref(), "roster-group", now),
                Err(SdkError::InboundPending(_))
            ),
            "a definite custody refusal stays pending without automatic retries"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
