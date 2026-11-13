// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Explicit native recovery sends use the real session encoder and ordinary receive writer.
use super::*;
use crate::gateway::{GatewayClientFrame, GatewayServerFrame};
use crate::{GatewayDirectMessage, GatewayInboxEntry, GatewaySessionEngine};
use std::{collections::VecDeque, future::Future, pin::Pin};
type WireResult<T> = Result<T, ramflux_transport::TransportError>;
struct Wire {
    bundle: ramflux_crypto::PrekeyBundle,
    replies: VecDeque<Vec<u8>>,
    nack: bool,
}
impl ramflux_transport::GatewaySessionFrameSink for Wire {
    fn finish(&mut self) -> WireResult<()> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = WireResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let reply = match serde_json::from_slice::<GatewayClientFrame>(bytes)? {
                GatewayClientFrame::PrekeyFetch { device_id } => GatewayServerFrame::Prekey {
                    response: crate::prekey::SdkPrekeyResponse {
                        device_id: device_id.clone(),
                        bundle: Some(self.bundle.clone()),
                        principal_commitment: device_id.clone(),
                        target_delivery_id: Some(device_id),
                    },
                },
                GatewayClientFrame::Submit { submit } => {
                    if self.nack {
                        GatewayServerFrame::Nack { reason: "fixture refusal".into() }
                    } else {
                        GatewayServerFrame::Deliver {
                            entry: GatewayInboxEntry {
                                forwarded: false,
                                inbox_seq: 1,
                                target_delivery_id: submit.envelope.target_delivery_id.clone(),
                                envelope: submit.envelope,
                            },
                        }
                    }
                }
                _ => {
                    return Err(ramflux_transport::TransportError::Quic(
                        "unexpected native-control frame".into(),
                    ));
                }
            };
            self.replies.push_back(serde_json::to_vec(&reply)?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for Wire {
    fn recv_frame(&mut self) -> Pin<Box<dyn Future<Output = WireResult<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            self.replies
                .pop_front()
                .ok_or_else(|| ramflux_transport::TransportError::Quic("no reply".into()))
        })
    }
}
fn engine(source: &Fixture, target: &Fixture, nack: bool) -> TestResult<GatewaySessionEngine> {
    let bundle =
        target.client.load_x3dh_private_state(&target.client.owned_device_identity()?)?.bundle;
    Ok(GatewaySessionEngine::with_test_transport(
        source.config.clone(),
        Box::new(Wire { bundle, replies: VecDeque::new(), nack }),
    ))
}
fn message(source: &Fixture, target: &Fixture) -> TestResult<GatewayDirectMessage> {
    Ok(GatewayDirectMessage {
        conversation_id: ramflux_protocol::message::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?,
        message_id: "filled-from-exact-control".into(),
        envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        source_principal_id: source.manifest.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 300,
    })
}
fn invite(
    owner: &Fixture,
    guardian: &Fixture,
) -> TestResult<crate::client::recovery::SdkGuardianInviteMessage> {
    let share = ramflux_crypto::RecoveryShare {
        share_id: 2,
        threshold: 2,
        total: 2,
        member_kind: Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare),
        value: [0x51; 32],
    };
    Ok(owner.client.invite_guardian(
        "native-invite",
        "native-quorum",
        &guardian.manifest.principal_id,
        &share,
        crate::time::now_unix_timestamp() + 300,
    )?)
}
#[tokio::test(flavor = "current_thread")]
async fn native_guardian_send_retries_capture_and_requires_explicit_local_acceptance() -> TestResult
{
    let mut owner = Fixture::new("native-recovery-owner").await?;
    let mut guardian = Fixture::new("native-recovery-guardian").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for (local, remote) in [(&owner, &guardian), (&guardian, &owner)] {
        local.client.persist_fetched_identity_directory(&remote.manifest)?;
        local.client.establish_friend_link(
            "recovery-link",
            &owner.client.own_account_anchor()?,
            &guardian.client.own_account_anchor()?,
        )?;
    }
    let invite = invite(&owner, &guardian)?;
    let db = owner.client.account_db()?;
    let mut wrong_role = invite.clone();
    wrong_role.guardian_principal_id = owner.manifest.principal_id.clone();
    let mut role_check = engine(&owner, &guardian, false)?;
    assert!(
        owner
            .client
            .send_guardian_invite_via_gateway(
                &mut role_check,
                message(&owner, &guardian)?,
                &wrong_role
            )
            .await
            .is_err()
    );
    assert_eq!(
        db.actor_state_keys("routed/native-control-outbound/")?.len(),
        0,
        "a wrong recipient must not capture or transmit the share"
    );
    let mut refused = engine(&owner, &guardian, true)?;
    assert!(
        owner
            .client
            .send_guardian_invite_via_gateway(&mut refused, message(&owner, &guardian)?, &invite)
            .await
            .is_err()
    );
    assert_eq!(
        db.actor_state_keys("routed/native-control-outbound/")?.len(),
        1,
        "failed submission preserves exact retry bytes"
    );
    let mut outgoing = engine(&owner, &guardian, false)?;
    let delivered = owner
        .client
        .send_guardian_invite_via_gateway(&mut outgoing, message(&owner, &guardian)?, &invite)
        .await?;
    assert_eq!(
        delivered.envelope.schema,
        ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA
    );
    assert_eq!(
        db.actor_state_keys("routed/native-control-outbound/")?.len(),
        0,
        "accepted capture retires secret share"
    );
    guardian.receive(delivered.envelope, 1).await?;
    let pending = guardian.client.pending_guardian_invites()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(
        guardian.client.guardian_recovery_shares_for_owner(&owner.manifest.principal_id)?.len(),
        0
    );
    let accepted = guardian
        .client
        .decide_pending_guardian_invite(&pending[0].handle, true)?
        .ok_or("accept response")?;
    let mut response = engine(&guardian, &owner, false)?;
    let delivered = guardian
        .client
        .send_guardian_accept_via_gateway(&mut response, message(&guardian, &owner)?, &accepted)
        .await?;
    owner.receive(delivered.envelope, 1).await?;
    assert_eq!(
        guardian.client.guardian_recovery_shares_for_owner(&owner.manifest.principal_id)?.len(),
        1
    );
    assert_eq!(guardian.client.pending_guardian_invites()?.len(), 0);
    assert!(
        owner
            .client
            .account_db()?
            .actor_state_exists("recovery/guardian-accept/bmF0aXZlLWludml0ZQ")?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_object_revoke_sender_preserves_original_owner_and_uses_generated_outer()
-> TestResult {
    let owner = Fixture::new("native-revoke-owner").await?;
    let mut recipient = Fixture::new("native-revoke-recipient").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (original, _, conversation) =
        Box::pin(super::history::receive_first_hand(&mut recipient, &owner)).await?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    let db = recipient.client.account_db()?;
    let reference =
        serde_json::json!({"reference":{"object_id":"native-object","manifest_hash":"manifest"}});
    let metadata = serde_json::json!({"owner":owner.manifest.principal_id,"message_id":id,"conversation_id":conversation});
    db.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: "native-received-reference",
            wire_id: "native-object",
            manifest_hash: "manifest",
            selector: "native-object",
            message_id: &id,
            reference: &reference,
            metadata: &metadata,
        },
    )?;
    db.persist_client_record("object", "native-object", &metadata)?;
    let revoke = ramflux_protocol::message::ObjectRevokeAccess {
        object_id: "native-object".into(),
        recipient_principal_id: recipient.client.own_account_anchor()?,
        link_id: "native-object-link".into(),
        reason: "owner withdrew access".into(),
        effective_at: crate::time::now_unix_timestamp(),
    };
    let mut outgoing = engine(&owner, &recipient, false)?;
    let entry = owner
        .client
        .send_object_revoke_via_gateway(&mut outgoing, message(&owner, &recipient)?, revoke)
        .await?;
    assert_eq!(entry.envelope.schema, ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA);
    recipient.receive(entry.envelope, 2).await?;
    assert!(recipient.client.account_db()?.object_is_tombstoned("native-object")?);
    assert_eq!(
        recipient.client.account_db()?.actor_state_keys("routed/native-control-applied/")?.len(),
        1
    );
    assert_eq!(
        owner.client.account_db()?.actor_state_keys("routed/native-control-outbound/")?.len(),
        0
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_guardian_accept_capture_keeps_colliding_owner_invite_ids_independent() -> TestResult
{
    let first = Fixture::new("native-first-owner").await?;
    let second = Fixture::new("native-second-owner").await?;
    let guardian = Fixture::new("native-common-guardian").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let first_reply = guardian.client.accept_guardian_invite(&invite(&first, &guardian)?)?;
    let second_reply = guardian.client.accept_guardian_invite(&invite(&second, &guardian)?)?;
    assert_eq!(first_reply.invite_id, second_reply.invite_id);
    let first_root = first.client.own_account_anchor()?;
    let second_root = second.client.own_account_anchor()?;
    let first_bytes = guardian.client.generated_guardian_accept_inner(&first_reply, &first_root)?;
    let second_bytes =
        guardian.client.generated_guardian_accept_inner(&second_reply, &second_root)?;
    assert_ne!(*first_bytes, *second_bytes);
    assert_eq!(
        guardian.client.generated_guardian_accept_inner(&first_reply, &first_root)?,
        first_bytes
    );
    assert_eq!(
        guardian.client.account_db()?.actor_state_keys("routed/native-control-outbound/")?.len(),
        2
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn pending_guardian_invites_refuses_generation_zero_without_expiry_writes() -> TestResult {
    super::watchdog::within(pending_guardian_invites_expiry_body()).await?
}

async fn pending_guardian_invites_expiry_body() -> TestResult {
    let owner = Fixture::new("pending-invite-owner").await?;
    let mut guardian = Fixture::new("pending-invite-guardian").await?;
    let expires_at;
    {
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        for (local, remote) in [(&owner, &guardian), (&guardian, &owner)] {
            local.client.persist_fetched_identity_directory(&remote.manifest)?;
            local.client.establish_friend_link(
                "pending-invite-link",
                &owner.client.own_account_anchor()?,
                &guardian.client.own_account_anchor()?,
            )?;
        }
        let invitation = invite(&owner, &guardian)?;
        expires_at = invitation.expires_at;
        let mut outgoing = engine(&owner, &guardian, false)?;
        let delivered = Box::pin(owner.client.send_guardian_invite_via_gateway(
            &mut outgoing,
            message(&owner, &guardian)?,
            &invitation,
        ))
        .await?;
        guardian.receive(delivered.envelope, 1).await?;
        assert_eq!(
            guardian.client.pending_guardian_invites()?.len(),
            1,
            "a genuine authenticated invitation must be pending before expiry"
        );
    }
    let _clock = crate::time::FixedClock::set(expires_at.checked_add(1).ok_or("expiry overflow")?);
    let before = super::generation_zero_tests::actors(&guardian.client)?;
    super::generation_zero_tests::dormant(guardian.client.pending_guardian_invites());
    assert!(
        super::generation_zero_tests::actors(&guardian.client)? == before,
        "generation-zero expiry lookup must preserve pending shares and all actor bytes"
    );
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    assert!(
        guardian.client.pending_guardian_invites()?.is_empty(),
        "active-profile lookup must still erase expired invitations"
    );
    let retained: Vec<_> = before
        .into_iter()
        .filter(|(key, _)| !key.starts_with("recovery/guardian-invite/"))
        .collect();
    assert!(
        super::generation_zero_tests::actors(&guardian.client)? == retained,
        "active expiry cleanup must remove only the expired pending invitation"
    );
    assert!(
        guardian
            .client
            .guardian_recovery_shares_for_owner(&owner.manifest.principal_id)?
            .is_empty(),
        "expiry cleanup must not accept the pending share"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_conversation_mutations_use_generated_carrier_and_update_source_and_receiver()
-> TestResult {
    use crate::client::routed::ConversationEvent;
    use ramflux_protocol::message as g;
    let source = Fixture::new("conversation-event-source").await?;
    let mut peer = Fixture::new("conversation-event-peer").await?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&source.manifest)?;
    let source_root = source.client.own_account_anchor()?;
    let peer_root = peer.client.own_account_anchor()?;
    source.client.establish_friend_link("conversation-peer-link", &source_root, &peer_root)?;
    peer.client.establish_friend_link("conversation-source-link", &source_root, &peer_root)?;
    let conversation = g::dm_scope::derive(&source_root, &peer_root)?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let identity = source.client.allocate_generated_identity(&conversation, 1000, false)?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "original".into(),
                ..Default::default()
            })),
        },
    )?;
    let recipients = vec![peer.client.owned_device_identity()?.storage_key().to_owned()];
    let mut transport = engine(&source, &peer, false)?;
    let accepted = source
        .client
        .submit_conversation_event(
            &mut transport,
            ConversationEvent {
                message: message(&source, &peer)?,
                exact: &exact,
                wire: &exact,
                recipients: &recipients,
            },
        )
        .await?;
    assert_eq!(accepted.envelope.schema, g::outer::CANDIDATE_ENVELOPE_SCHEMA);
    assert_eq!(accepted.envelope.version, 2);
    peer.receive(accepted.envelope, 1).await?;
    for (sequence, method, fields) in [
        (2, "conversation.edit", serde_json::json!({"text":"replacement"})),
        (3, "conversation.react", serde_json::json!({"token":"👍"})),
        (4, "conversation.delete", serde_json::json!({"scope":"everyone"})),
    ] {
        let mut body = serde_json::json!({"conversation_id":conversation,"message_id":id});
        body.as_object_mut().ok_or("body")?.extend(fields.as_object().ok_or("fields")?.clone());
        let mut request = crate::LocalBusFrame::request(
            method,
            Some("source".into()),
            "conversation",
            method,
            body,
        );
        request.operation_id = Some(method.into());
        let prepared =
            crate::bus::dispatch::conversation_mutation::prepare(&source.client, &request)?;
        let accepted = source
            .client
            .submit_conversation_event(
                &mut transport,
                ConversationEvent {
                    message: message(&source, &peer)?,
                    exact: &prepared.exact,
                    wire: &prepared.wire,
                    recipients: &recipients,
                },
            )
            .await?;
        peer.receive(accepted.envelope, sequence).await?;
        assert_eq!(
            source.client.direct_messages(&conversation)?.len(),
            1,
            "mutations must not add synthetic message rows"
        );
        assert_eq!(peer.client.direct_messages(&conversation)?.len(), 1);
        if method == "conversation.edit" {
            let source_bytes =
                source.client.account_db()?.message_content(&id)?.ok_or("source content")?;
            let peer_bytes =
                peer.client.account_db()?.message_content(&id)?.ok_or("peer content")?;
            assert_eq!(source_bytes, peer_bytes, "accepted edit must update both projections");
            assert!(
                source
                    .client
                    .account_db()?
                    .actor_state_exists(&format!("own-history/capture/{id}"))?,
                "edit retirement must precede capturing the accepted revision"
            );
        }
    }
    assert!(source.client.account_db()?.message_is_deleted(&id)?);
    assert!(peer.client.account_db()?.message_is_deleted(&id)?);
    assert!(source.client.account_db()?.message_content(&id)?.is_none());
    assert!(peer.client.account_db()?.message_content(&id)?.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_conversation_group_reply_keeps_reference_inside_sender_key_wrapper() -> TestResult {
    use crate::client::routed::ConversationEvent;
    use ramflux_protocol::message as g;
    let source = Fixture::new("conversation-group-source").await?;
    let mut peer = Fixture::with_device("conversation-group-peer", "peer").await?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&source.manifest)?;
    prepare_conversation_group(&source, &peer)?;
    let state =
        source.client.account_db()?.shared_group_state("conversation-group")?.ok_or("group")?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let distribution = ramflux_protocol::parse_i_json(
        &source
            .client
            .export_group_sender_key_distribution("conversation-group", &source.config.device_id)?,
    )?;
    let key = source.client.generated_group_key_inner(
        "thread",
        state.view().epoch,
        &distribution,
        &peer.client.owned_device_identity()?,
    )?;
    peer.receive(source.seal_inner_to(&peer, &key)?, 1)
        .await
        .map_err(|error| format!("key receive: {error}"))?;
    let mut identity = source.client.allocate_generated_identity("thread", 1000, false)?;
    identity.group_id = Some("conversation-group".into());
    identity.group_epoch = Some(state.view().epoch);
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "group original".into(),
                ..Default::default()
            })),
        },
    )?;
    let wire = source.client.wrap_conversation_group_reply(&identity, &exact)?;
    let recipients = vec![peer.client.owned_device_identity()?.storage_key().to_owned()];
    let mut transport = engine(&source, &peer, false)?;
    let mut outbound = message(&source, &peer)?;
    outbound.conversation_id = "thread".into();
    let accepted = source
        .client
        .submit_conversation_event(
            &mut transport,
            ConversationEvent {
                message: outbound,
                exact: &exact,
                wire: &wire,
                recipients: &recipients,
            },
        )
        .await?;
    peer.receive(accepted.envelope, 2)
        .await
        .map_err(|error| format!("original group receive: {error}"))?;
    let mut request = crate::LocalBusFrame::request(
        "group-reply",
        Some("source".into()),
        "conversation",
        "conversation.reply",
        serde_json::json!({"conversation_id":"thread","message_id":id,"text":"group reply"}),
    );
    request.operation_id = Some("group-reply".into());
    let prepared = crate::bus::dispatch::conversation_mutation::prepare(&source.client, &request)?;
    let retry = crate::bus::dispatch::conversation_mutation::prepare(&source.client, &request)?;
    assert_eq!(
        prepared.wire, retry.wire,
        "retry cannot advance a sender-key counter or rewrap content"
    );
    let mut outbound = message(&source, &peer)?;
    outbound.conversation_id = "thread".into();
    let accepted = source
        .client
        .submit_conversation_event(
            &mut transport,
            ConversationEvent {
                message: outbound,
                exact: &prepared.exact,
                wire: &prepared.wire,
                recipients: &recipients,
            },
        )
        .await?;
    peer.receive(accepted.envelope, 3)
        .await
        .map_err(|error| format!("group reply receive: {error}"))?;
    let reply_id = ramflux_protocol::encode_base64url(&prepared.identity.id);
    let projection = peer
        .client
        .account_db()?
        .load_actor_state::<g::Message>(&format!("routed/group-projection/{reply_id}"))?
        .ok_or("group projection")?;
    assert_eq!(projection.text, "group reply");
    assert_eq!(projection.reply_to.ok_or("reply reference")?.id, identity.id);
    Ok(())
}

fn prepare_conversation_group(source: &Fixture, peer: &Fixture) -> TestResult {
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("account")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "conversation-group",
        "thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let actor = peer.client.owned_group_actor(&peer.config.target_delivery_id)?;
    let state = source.client.shared_group_change_with_primary(
        "conversation-group",
        &source.config.target_delivery_id,
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: actor.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    peer.client.accept_shared_group_state(&state, &peer.config.target_delivery_id)?;
    Ok(())
}
