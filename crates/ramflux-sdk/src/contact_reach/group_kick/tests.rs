// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native adopted-head/writer test; transport submission remains a separate boundary.
use super::super::group_test_support::{UnavailableVault, install_grant};
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::group_state::GroupStateChange;

async fn kick_fixture() -> TestResult<(Fixture, VerifiedGroupState, VerifiedGroupState)> {
    let owner = Fixture::new("reach-kick-owner").await?;
    let peer = Fixture::new("reach-kick-peer").await?;
    owner.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&owner.manifest)?;
    let account = owner.client.born_v3_account.as_ref().ok_or("owner native account")?;
    let primary = account.group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "kick-group",
        "kick-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let member = peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity;
    let joined = owner.client.shared_group_change_with_primary(
        "kick-group",
        &owner.config.target_delivery_id,
        GroupStateChange::Add {
            member: member.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    peer.client.accept_shared_group_state(&joined, &peer.config.target_delivery_id)?;
    install_grant(&peer, &joined)?;
    let kicked = owner.client.shared_group_change_with_primary(
        "kick-group",
        &owner.config.target_delivery_id,
        GroupStateChange::Remove {
            root_commitment: member.root_commitment,
            device_id: member.device_id,
        },
        Some(&primary),
    )?;
    Ok((peer, joined, kicked))
}

#[tokio::test]
async fn cr_group_own_kick_stages_with_head_and_signs_after_commit() -> TestResult {
    let (peer, joined, kicked) = kick_fixture().await?;
    let db = peer.client.account_db()?;
    let rollback: Result<(), SdkError> = db.write_transaction(|| {
        peer.client.accept_shared_group_state(&kicked, &peer.config.target_delivery_id)?;
        Err(pending())
    });
    assert!(rollback.is_err(), "the outer writer is intentionally aborted");
    assert_eq!(
        db.shared_group_state("kick-group")?.ok_or("retained joined head")?.snapshot().state_hash,
        joined.snapshot().state_hash,
        "rollback preserves the prior adopted head"
    );
    assert!(
        !db.actor_state_exists(&key("kick-group"))?,
        "rollback also removes the dependent revoke intent"
    );
    peer.client.accept_shared_group_state(&kicked, &peer.config.target_delivery_id)?;
    let intent: KickIntent =
        db.load_actor_state(&key("kick-group"))?.ok_or("committed kick intent")?;
    assert!(intent.operation.is_none(), "head adoption cannot sign or access the primary vault");
    let mirror = peer.client.group_reach_mirror()?.ok_or("verified reach mirror")?;
    let peer_account = peer.client.born_v3_account.as_ref().ok_or("native peer account")?;
    let context = ReachCommandContext {
        actor: &peer_account.record().body.master_certificate.body.primary_device_ref,
        home_head_hash: &mirror.home_head_hash,
        expected_revision: mirror.admission_revision,
        now: crate::custody::network_now()?,
    };
    assert!(
        peer.client.prepare_reach_group_kick(&UnavailableVault, context, "kick-group").is_err(),
        "signing requires the primary vault after the writer has committed"
    );
    let operation =
        peer.client.prepare_reach_group_kick(peer.vault.as_ref(), context, "kick-group")?;
    let Operation::Admission { update, .. } = &operation else {
        return Err("kick revoke operation".into());
    };
    assert_eq!(
        update.body.decision,
        Decision::Revoke,
        "automatic removal creates only a restrictive operation"
    );
    assert_eq!(
        update.body.operation_id, intent.operation_id,
        "signing keeps the id persisted with adoption"
    );
    ramflux_crypto::contact_reach::verify_retained_admission(
        update,
        peer_account.verified(),
        context.now,
    )?;
    assert_eq!(
        peer.client.prepare_reach_group_kick(peer.vault.as_ref(), context, "kick-group")?,
        operation,
        "uncertain outcomes preserve the exact signed negative command"
    );
    let applied = OperationResult::Admission {
        revision: mirror.admission_revision + 1,
        outcome: ramflux_protocol::contact_reach::Applied::Applied,
    };
    peer.client.apply_reach_group_kick_result("kick-group", &operation, &applied)?;
    peer.client.apply_reach_group_kick_result("kick-group", &operation, &applied)?;
    peer.client.stage_reach_group_kick_repair("kick-group")?;
    assert!(
        peer.client.prepare_reach_group_kick(peer.vault.as_ref(), context, "kick-group").is_err(),
        "settlement and restart repair cannot resubmit or replace a completed revoke"
    );
    Ok(())
}
