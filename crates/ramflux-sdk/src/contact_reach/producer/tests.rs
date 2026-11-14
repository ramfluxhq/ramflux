// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real adopted native snapshot, checked transport sealing and distinct group/conversation IDs.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test(flavor = "current_thread")]
async fn cr_group_producer_binds_distinct_ids_and_requires_explicit_invitation() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), group_producer()).await?
}

async fn group_producer() -> TestResult {
    let source = Fixture::new("reach-producer-owner").await?;
    let target = Fixture::new("reach-producer-invitee").await?;
    let material = source.material_for(&target)?;
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native owner")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "producer-group",
        "producer-signed-thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let state =
        source.client.account_db()?.shared_group_state("producer-group")?.ok_or("adopted head")?;
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let inner = source
        .client
        .shared_group_packet_for_recipient(&state, &target.client.owned_device_identity()?)?;
    let identity = g::Inner::decode(inner.as_slice())?.identity.ok_or("snapshot identity")?;
    let message = GatewayDirectMessage {
        conversation_id: state.view().conversation_id.clone(),
        message_id: ramflux_protocol::encode_base64url(identity.id),
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
    let invitation = source.client.prepare_reach_submission(
        &source.config,
        &message,
        &inner,
        material.bundle.clone(),
        ReachSendIntent::GroupInvitation,
    )?;
    assert_eq!(
        invitation.route.body.traffic,
        Traffic::GroupInvite,
        "explicit verified snapshot intent selects the invitation placement"
    );
    assert!(
        invitation.route.body.group.is_none(),
        "r4f requires group:null for invitation traffic"
    );
    assert_eq!(
        invitation.route.body.conversation_id, "producer-signed-thread",
        "the adopted conversation is distinct from group ID"
    );
    let mut ordinary_message = message.clone();
    ordinary_message.envelope_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let ordinary = source.client.prepare_reach_submission(
        &source.config,
        &ordinary_message,
        &inner,
        material.bundle.clone(),
        ReachSendIntent::Ordinary,
    )?;
    assert_eq!(
        ordinary.route.body.traffic,
        Traffic::Group,
        "a snapshot alone must not silently become an invitation"
    );
    let group = ordinary.route.body.group.ok_or("signed group route")?;
    assert_eq!(group.group_id, "producer-group", "W retains the adopted group identifier");
    assert_eq!(group.group_epoch, state.view().epoch, "W uses the exact adopted epoch");
    assert_eq!(
        group.membership_hash,
        state.snapshot().state_hash,
        "W binds the original signed state hash"
    );
    reject_namespace(&source, message, &inner, material.bundle)?;
    Ok(())
}

fn reject_namespace(
    source: &Fixture,
    message: GatewayDirectMessage,
    inner: &[u8],
    prekey: Option<ramflux_crypto::PrekeyBundle>,
) -> TestResult {
    let before = crate::contact_reach::group_test_support::sealing_state(&source.client)?;
    let mut confused = message;
    confused.conversation_id = "producer-group".into();
    assert!(
        source
            .client
            .prepare_reach_submission(
                &source.config,
                &confused,
                inner,
                prekey,
                ReachSendIntent::Ordinary,
            )
            .is_err(),
        "using the group ID as conversation ID must refuse before sealing commits"
    );
    assert_eq!(
        crate::contact_reach::group_test_support::sealing_state(&source.client)?,
        before,
        "refused namespace substitution cannot advance the pair"
    );
    Ok(())
}
