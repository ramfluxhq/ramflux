// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit native recovery sends use the real session encoder and ordinary receive writer.
use super::*;
use crate::{GatewayDirectMessage, GatewayInboxEntry, GatewaySessionEngine};
use crate::gateway::{GatewayClientFrame, GatewayServerFrame};
use std::{collections::VecDeque, future::Future, pin::Pin};
type WireResult<T> = Result<T, ramflux_transport::TransportError>;
struct Wire { bundle: ramflux_crypto::PrekeyBundle, replies: VecDeque<Vec<u8>>, nack: bool }
impl ramflux_transport::GatewaySessionFrameSink for Wire {
    fn finish(&mut self) -> WireResult<()> { Ok(()) }
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> Pin<Box<dyn Future<Output = WireResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let reply = match serde_json::from_slice::<GatewayClientFrame>(bytes)? {
                GatewayClientFrame::PrekeyFetch { device_id } => GatewayServerFrame::Prekey {
                    response: crate::prekey::SdkPrekeyResponse { device_id: device_id.clone(),
                        bundle: Some(self.bundle.clone()), principal_commitment: device_id.clone(),
                        target_delivery_id: Some(device_id) },
                },
                GatewayClientFrame::Submit { submit } => {
                    if self.nack { GatewayServerFrame::Nack { reason: "fixture refusal".into() } }
                    else { GatewayServerFrame::Deliver { entry: GatewayInboxEntry {
                        forwarded: false, inbox_seq: 1,
                        target_delivery_id: submit.envelope.target_delivery_id.clone(), envelope: submit.envelope,
                    } } }
                }
                _ => return Err(ramflux_transport::TransportError::Quic("unexpected native-control frame".into())),
            };
            self.replies.push_back(serde_json::to_vec(&reply)?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for Wire {
    fn recv_frame(&mut self) -> Pin<Box<dyn Future<Output = WireResult<Vec<u8>>> + Send + '_>> {
        Box::pin(async move { self.replies.pop_front().ok_or_else(|| ramflux_transport::TransportError::Quic("no reply".into())) })
    }
}
fn engine(source: &Fixture, target: &Fixture, nack: bool) -> TestResult<GatewaySessionEngine> {
    let bundle = target.client.load_x3dh_private_state(&target.client.owned_device_identity()?)?.bundle;
    Ok(GatewaySessionEngine::with_test_transport(source.config.clone(), Box::new(Wire { bundle, replies: VecDeque::new(), nack })))
}
fn message(source: &Fixture, target: &Fixture) -> TestResult<GatewayDirectMessage> {
    Ok(GatewayDirectMessage {
        conversation_id: ramflux_protocol::message::dm_scope::derive(&source.client.own_account_anchor()?, &target.client.own_account_anchor()?)?,
        message_id: "filled-from-exact-control".into(),
        envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        source_principal_id: source.manifest.principal_id.clone(), sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()), recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(), encrypted_body: Vec::new(), created_at: crate::time::now_unix_timestamp(), ttl: 300,
    })
}
fn invite(owner: &Fixture, guardian: &Fixture) -> TestResult<crate::client::recovery::SdkGuardianInviteMessage> {
    let share = ramflux_crypto::RecoveryShare { share_id: 2, threshold: 2, total: 2,
        member_kind: Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare), value: [0x51; 32] };
    Ok(owner.client.invite_guardian("native-invite", "native-quorum", &guardian.manifest.principal_id, &share, crate::time::now_unix_timestamp() + 300)?)
}
#[tokio::test(flavor = "current_thread")]
async fn native_guardian_send_retries_capture_and_requires_explicit_local_acceptance() -> TestResult {
    let mut owner = Fixture::new("native-recovery-owner").await?;
    let mut guardian = Fixture::new("native-recovery-guardian").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for (local, remote) in [(&owner, &guardian), (&guardian, &owner)] {
        local.client.persist_fetched_identity_directory(&remote.manifest)?;
        local.client.establish_friend_link("recovery-link", &owner.client.own_account_anchor()?, &guardian.client.own_account_anchor()?)?;
    }
    let invite = invite(&owner, &guardian)?;
    let db = owner.client.account_db()?;
    let mut wrong_role = invite.clone();
    wrong_role.guardian_principal_id = owner.manifest.principal_id.clone();
    let mut role_check = engine(&owner, &guardian, false)?;
    assert!(owner.client.send_guardian_invite_via_gateway(&mut role_check, message(&owner, &guardian)?, &wrong_role).await.is_err());
    assert_eq!(db.actor_state_keys("routed/native-control-outbound/")?.len(), 0, "a wrong recipient must not capture or transmit the share");
    let mut refused = engine(&owner, &guardian, true)?;
    assert!(owner.client.send_guardian_invite_via_gateway(&mut refused, message(&owner, &guardian)?, &invite).await.is_err());
    assert_eq!(db.actor_state_keys("routed/native-control-outbound/")?.len(), 1, "failed submission preserves exact retry bytes");
    let mut outgoing = engine(&owner, &guardian, false)?;
    let delivered = owner.client.send_guardian_invite_via_gateway(&mut outgoing, message(&owner, &guardian)?, &invite).await?;
    assert_eq!(delivered.envelope.schema, ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA);
    assert_eq!(db.actor_state_keys("routed/native-control-outbound/")?.len(), 0, "accepted capture retires secret share");
    guardian.receive(delivered.envelope, 1).await?;
    let pending = guardian.client.pending_guardian_invites()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(guardian.client.guardian_recovery_shares_for_owner(&owner.manifest.principal_id)?.len(), 0);
    let accepted = guardian.client.decide_pending_guardian_invite(&pending[0].handle, true)?.ok_or("accept response")?;
    let mut response = engine(&guardian, &owner, false)?;
    let delivered = guardian.client.send_guardian_accept_via_gateway(&mut response, message(&guardian, &owner)?, &accepted).await?;
    owner.receive(delivered.envelope, 1).await?;
    assert_eq!(guardian.client.guardian_recovery_shares_for_owner(&owner.manifest.principal_id)?.len(), 1);
    assert_eq!(guardian.client.pending_guardian_invites()?.len(), 0);
    assert!(owner.client.account_db()?.actor_state_exists("recovery/guardian-accept/bmF0aXZlLWludml0ZQ")?);
    Ok(())
}
