// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native primary and encrypted account writer; no transport or full SDK/rf acceptance claim.
use super::super::group_test_support::UnavailableVault;
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::contact_reach::Applied;

fn stage_fixture(owner: &Fixture) -> TestResult<JoinIntent> {
    let account = owner.client.born_v3_account.as_ref().ok_or("native account")?;
    let primary = account.group_primary(owner.vault.as_ref())?;
    let state = owner.client.shared_group_create_with_primary(
        "reach-group",
        "reach-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let notice = owner.client.reach_group_join_notice("reach-group")?;
    let acknowledged = custody::framed_hash(GROUP_JOIN_NOTICE_DOMAIN, &notice)?;
    assert!(
        owner.client.stage_reach_group_join("reach-group", &acknowledged).is_err(),
        "a notice acknowledgment cannot replace the existing same-genesis account Consent"
    );
    owner.client.publish_own_group_decision(&state, true, &owner.config.target_delivery_id)?;
    assert!(
        owner.client.stage_reach_group_join("reach-group", "changed-notice").is_err(),
        "JOIN requires acknowledgment of the exact recomputed Notice"
    );
    let db = owner.client.account_db()?;
    let rolled_back: Result<(), SdkError> = db.write_transaction(|| {
        owner.client.stage_reach_group_join("reach-group", &acknowledged)?;
        Err(invalid())
    });
    assert!(rolled_back.is_err(), "the outer account transaction must abort");
    assert!(
        !db.actor_state_exists(&key("reach-group"))?,
        "an outer rollback must leave neither JOIN intent"
    );
    owner.client.stage_reach_group_join("reach-group", &acknowledged)?;
    let staged: JoinIntent = db.load_actor_state(&key("reach-group"))?.ok_or("staged JOIN")?;
    assert_ne!(
        staged.grant_id, staged.roster_id,
        "independent CSPRNG identities order the two operations"
    );
    assert!(
        staged.grant.is_none() && staged.roster.is_none(),
        "staging succeeds without accessing the unavailable signing vault"
    );
    Ok(staged)
}

#[tokio::test]
async fn cr_group_join_persists_retry_ids_before_signing_and_orders_roster() -> TestResult {
    let owner = Fixture::new("reach-join-owner").await?;
    let staged = stage_fixture(&owner)?;
    let account = owner.client.born_v3_account.as_ref().ok_or("native account")?;
    let actor = account.record().body.master_certificate.body.primary_device_ref.clone();
    let home = ramflux_protocol::encode_base64url([23; 32]);
    let context = ReachCommandContext {
        actor: &actor,
        home_head_hash: &home,
        expected_revision: 1,
        now: crate::custody::network_now()?,
    };
    assert!(
        owner
            .client
            .prepare_reach_group_join_operation(&UnavailableVault, context, "reach-group")
            .is_err(),
        "an unavailable vault cannot sign"
    );
    let grant = owner.client.prepare_reach_group_join_operation(
        owner.vault.as_ref(),
        context,
        "reach-group",
    )?;
    let Operation::Admission { update, .. } = &grant else {
        return Err("grant first".into());
    };
    assert_eq!(
        update.body.operation_id, staged.grant_id,
        "signing keeps the committed retry identity"
    );
    assert_eq!(
        update.body.permissions,
        Some(Permissions::UNACCEPTED),
        "group grants carry no optional signals"
    );
    ramflux_crypto::contact_reach::verify_retained_admission(
        update,
        account.verified(),
        context.now,
    )?;
    let retry = owner.client.prepare_reach_group_join_operation(
        owner.vault.as_ref(),
        context,
        "reach-group",
    )?;
    assert_eq!(
        retry, grant,
        "uncertain grant outcomes return exact saved signed bytes, never a roster"
    );
    let applied = OperationResult::Admission { revision: 2, outcome: Applied::Applied };
    owner.client.apply_reach_group_join_result("reach-group", &grant, &applied)?;
    owner.client.apply_reach_group_join_result("reach-group", &grant, &applied)?;
    let roster = owner.client.prepare_reach_group_join_operation(
        owner.vault.as_ref(),
        context,
        "reach-group",
    )?;
    let Operation::GroupRoster { operation_id, roster: bookkeeping } = &roster else {
        return Err("roster second".into());
    };
    assert_eq!(
        operation_id, &staged.roster_id,
        "the roster also preserves its initial committed identity"
    );
    ramflux_crypto::contact_reach::verify_group_roster(
        bookkeeping,
        update,
        account.verified(),
        context.now,
    )?;
    assert!(bookkeeping.members.is_empty(), "the initial roster excludes self");
    assert_eq!(
        owner.client.prepare_reach_group_join_operation(
            owner.vault.as_ref(),
            context,
            "reach-group"
        )?,
        roster,
        "uncertain roster outcomes reuse the saved signed header and operation id"
    );
    let roster_applied = OperationResult::GroupRoster {
        group_epoch: bookkeeping.header.body.group_epoch,
        outcome: Applied::Applied,
    };
    owner.client.apply_reach_group_join_result("reach-group", &roster, &roster_applied)?;
    assert!(
        owner
            .client
            .prepare_reach_group_join_operation(owner.vault.as_ref(), context, "reach-group")
            .is_err(),
        "a completed JOIN cannot implicitly issue another allow"
    );
    Ok(())
}
