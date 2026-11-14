// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An actual sealed invitation remains pending even when an older native head was adopted.
use super::*;
use crate::client::{
    native_test_support::{Fixture, TestResult},
    shared_group::{GroupDirectoryEvidence, PreparedSharedGroup},
};

#[tokio::test(flavor = "current_thread")]
async fn cr_group_invitation_cannot_reuse_previous_join_consent() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), Box::pin(previous_consent())).await?
}

async fn previous_consent() -> TestResult {
    let source = Fixture::new("invite-current-source").await?;
    let target = Fixture::new("invite-current-target").await?;
    let material = source.material_for(&target)?;
    target.client.persist_fetched_identity_directory(&source.manifest)?;
    let (joined, candidate) = joined_and_new_candidate(&source, &target)?;
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let exact = zeroize::Zeroizing::new(
        source
            .client
            .reach_group_invitation_inner(&candidate, &target.client.owned_device_identity()?)?,
    );
    let inner = g::Inner::decode(exact.as_slice())?;
    let message = GatewayDirectMessage {
        conversation_id: candidate.view().conversation_id.clone(),
        message_id: ramflux_protocol::encode_base64url(&inner.identity.ok_or("identity")?.id),
        envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    let submission = source.client.prepare_reach_submission(
        &source.config,
        &message,
        &exact,
        material.bundle,
        ReachSendIntent::GroupInvitation,
    )?;
    let entry = crate::GatewayInboxEntry {
        inbox_seq: 1,
        forwarded: false,
        target_delivery_id: target.config.target_delivery_id.clone(),
        envelope: submission.envelope,
        reach: Some(Box::new(wire::DeliveryReach {
            node_report_receipt: None,
            route: submission.route,
            cost: submission.cost,
        })),
    };
    let opened = target.client.open_routed(&entry, &target.config.device_id)?;
    let key_checkpoint = crate::group::group_key_checkpoint(
        &candidate.view().group_id,
        &source.client.owned_device_identity()?,
        candidate.view().epoch,
        "recv",
        Some(&candidate.snapshot().state_hash),
    )?;
    assert!(
        target.client.projection_checkpoint(&key_checkpoint)?.is_none(),
        "the receiving fixture starts without the candidate sender key"
    );
    let directory = GroupDirectoryEvidence { actor: source.manifest.clone(), addition: None };
    let engine = crate::gateway::access::CountingGateway::new(target.config.clone());
    let prepared = target
        .client
        .prepare_shared_group_receive_with_directory(
            &engine,
            &opened,
            &entry,
            &opened.body,
            Some(&directory),
        )
        .await?
        .ok_or("prepared invitation")?;
    assert!(
        matches!(&prepared, PreparedSharedGroup::Invitation { .. }),
        "explicit invitation admission cannot borrow consent from an older adopted head"
    );
    target.client.apply_prepared_shared_group(&prepared, &target.config.target_delivery_id)?;
    assert!(
        target.client.projection_checkpoint(&key_checkpoint)?.is_none(),
        "holding an invitation must not install the candidate sender key"
    );
    assert_eq!(
        target
            .client
            .account_db()?
            .shared_group_state("invite-current-group")?
            .ok_or("retained joined head")?
            .snapshot()
            .state_hash,
        joined.snapshot().state_hash,
        "holding the invitation must not adopt its newer head or install sender keys"
    );
    assert_eq!(engine.acks, 0, "local invitation preparation performs no transport ACK");
    Ok(())
}

fn joined_and_new_candidate(
    source: &Fixture,
    target: &Fixture,
) -> TestResult<(ramflux_crypto::VerifiedGroupState, ramflux_crypto::VerifiedGroupState)> {
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("owner")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "invite-current-group",
        "invite-current-thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let joined = source.client.shared_group_change_with_primary(
        "invite-current-group",
        &source.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: target.client.owned_group_actor(&target.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    target.client.accept_shared_group_state(&joined, &target.config.target_delivery_id)?;
    let candidate = source.client.shared_group_change_with_primary(
        "invite-current-group",
        &source.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::SetName { name: "new candidate".into() },
        Some(&primary),
    )?;
    Ok((joined, candidate))
}
