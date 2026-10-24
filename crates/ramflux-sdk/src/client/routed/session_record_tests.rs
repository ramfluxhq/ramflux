// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Overlapping, delayed, evicted and offline device-pair session regressions.
use super::r5::{fresh, outgoing, settle};
use super::review::{pool, trust};
use super::*;
use std::sync::{Arc, Mutex};
pub(super) type Sent = Arc<Mutex<Vec<GatewayInboxEntry>>>;
pub(super) struct Wire {
    bundle: ramflux_crypto::PrekeyBundle,
    responses: VecDeque<Vec<u8>>,
    sent: Sent,
}
impl Wire {
    pub(super) fn engine(
        local: &Fixture,
        remote: &Fixture,
    ) -> Result<(GatewaySessionEngine, Sent), SdkError> {
        let sent = Arc::new(Mutex::new(Vec::new()));
        Ok((
            GatewaySessionEngine::with_test_transport(
                local.config()?,
                Box::new(Self {
                    bundle: remote.client.load_x3dh_private_state(&remote.id)?.bundle,
                    responses: VecDeque::new(),
                    sent: sent.clone(),
                }),
            ),
            sent,
        ))
    }
}
impl ramflux_transport::GatewaySessionFrameSink for Wire {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let frame: GatewayClientFrame = serde_json::from_slice(body)?;
            let response = match frame {
                GatewayClientFrame::PrekeyFetch { device_id } => GatewayServerFrame::Prekey {
                    response: crate::prekey::SdkPrekeyResponse {
                        device_id: device_id.clone(),
                        bundle: Some(self.bundle.clone()),
                        principal_commitment: device_id.clone(),
                        target_delivery_id: Some(device_id),
                    },
                },
                GatewayClientFrame::Submit { submit } => {
                    let entry = GatewayInboxEntry {
                        inbox_seq: 2,
                        target_delivery_id: submit.envelope.target_delivery_id.clone(),
                        envelope: submit.envelope,
                    };
                    self.sent
                        .lock()
                        .map_err(|_| ramflux_transport::TransportError::Quic("mutex".to_owned()))?
                        .push(entry.clone());
                    GatewayServerFrame::Deliver { entry }
                }
                GatewayClientFrame::Heartbeat { now } => GatewayServerFrame::Heartbeat { now },
                GatewayClientFrame::Resume { .. } => {
                    GatewayServerFrame::Resume { entries: Vec::new() }
                }
                _ => {
                    return Err(ramflux_transport::TransportError::Quic(
                        "unexpected session-record test frame".to_owned(),
                    ));
                }
            };
            self.responses.push_back(serde_json::to_vec(&response)?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for Wire {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            self.responses
                .pop_front()
                .ok_or_else(|| ramflux_transport::TransportError::Quic("no response".to_owned()))
        })
    }
}
pub(super) fn active(f: &Fixture, remote: &str) -> Result<String, SdkError> {
    Ok(f.client.active_pair(&f.id, remote)?.ok_or_else(|| invalid("current pair"))?.0.session_id)
}
pub(super) fn archive(f: &Fixture, remote: &str) -> Result<Vec<String>, SdkError> {
    Ok(f.client
        .account_db()?
        .load_actor_state::<Vec<String>>(&format!(
            "{}/archive",
            super::super::session::pair_key(&f.id, remote)?
        ))?
        .unwrap_or_default())
}
pub(super) fn gap(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    let (mut session, bundle) =
        sender.client.active_pair(&sender.id, &receiver.id)?.ok_or_else(|| invalid("pair"))?;
    for _ in 0..1001 {
        session.encrypt(b"lost", b"discarded")?;
    }
    sender.client.persist_pair(&sender.id, &receiver.id, &bundle, &session)?;
    seal(sender, receiver, outgoing(sender, receiver, id), b"past gap")
}
pub(super) fn last(sent: &Sent) -> Result<GatewayInboxEntry, SdkError> {
    sent.lock()
        .map_err(|_| invalid("mutex"))?
        .last()
        .cloned()
        .ok_or_else(|| invalid("no control submitted"))
}
fn group_bootstrap(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
    group: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    trust(sender, receiver)?;
    trust(receiver, sender)?;
    sender.client.create_group(group, &sender.id)?;
    sender.client.add_group_member(group, &receiver.id, "member")?;
    let body = sender.client.encrypt_group_message(group, &sender.id, b"delayed group packet")?;
    let mut message = outgoing(sender, receiver, id);
    message.conversation_id = format!("thread-{group}");
    let bundle = receiver.client.load_x3dh_private_state(&receiver.id)?.bundle;
    let (mut session, header, bundle) =
        sender.client.new_send_pair(&sender.id, &message, bundle)?;
    let wrapper = sender.client.seal_routed_with_route(
        &message,
        &body,
        Route::group_message(group),
        SealPair { local: &sender.id, remote: &receiver.id, session: &mut session, header, bundle },
    )?;
    message.encrypted_body = serde_json::to_vec(&wrapper)?;
    Ok(GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: receiver.id.clone(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &message, None)?,
    })
}
fn membership(receiver: &Fixture, sender: &Fixture, group: &str) -> Result<(), SdkError> {
    receiver.client.create_group(group, &receiver.id)?;
    receiver.client.add_group_member(group, &sender.id, "member")?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution(group, &sender.id)?,
    )?;
    Ok(())
}
#[tokio::test]
async fn delayed_loser_bootstrap_behind_membership_keeps_both_directions_decryptable()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let bob = Fixture::new("bob", 61)?;
    alice.client.establish_friend_link("friend", "alice", "bob")?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let a = group_bootstrap(&alice, &bob, "initial-a", "group-a")?;
    let b = group_bootstrap(&bob, &alice, "initial-b", "group-b")?;
    let (mut loser, mut winner, delayed, first, delayed_group, first_group) = if decode(
        &a.envelope,
    )?
    .ciphertext
    .session_id
        > decode(&b.envelope)?.ciphertext.session_id
    {
        (alice, bob, a, b, "group-a", "group-b")
    } else {
        (bob, alice, b, a, "group-b", "group-a")
    };
    let low = decode(&first.envelope)?.ciphertext.session_id;
    let high = decode(&delayed.envelope)?.ciphertext.session_id;
    let mut le = GatewaySessionEngine::with_test_transport(loser.config()?, Box::new(NoNetwork));
    let mut we = GatewaySessionEngine::with_test_transport(winner.config()?, Box::new(NoNetwork));
    assert!(matches!(
        winner.client.apply_routed_entry(&mut we, &pool()?, &delayed, false).await,
        Err(SdkError::InboundPending(_))
    ));
    membership(&loser, &winner, first_group)?;
    loser.client.apply_routed_entry(&mut le, &pool()?, &first, false).await?;
    let confirm = seal(&loser, &winner, outgoing(&loser, &winner, "confirm-winner"), b"confirm")?;
    winner.client.apply_routed_entry(&mut we, &pool()?, &confirm, false).await?;
    assert_eq!(active(&winner, &loser.id)?, low);
    membership(&winner, &loser, delayed_group)?;
    winner.client.apply_routed_entry(&mut we, &pool()?, &delayed, false).await?;
    let old_direction =
        seal(&loser, &winner, outgoing(&loser, &winner, "old-state-still-live"), b"old direction")?;
    winner.client.apply_routed_entry(&mut we, &pool()?, &old_direction, false).await?;
    assert_eq!(active(&winner, &loser.id)?, high);
    let new_direction =
        seal(&winner, &loser, outgoing(&winner, &loser, "new-state-reply"), b"new direction")?;
    loser.client.apply_routed_entry(&mut le, &pool()?, &new_direction, false).await?;
    assert_eq!(active(&loser, &winner.id)?, low);
    assert!(archive(&winner, &loser.id)?.contains(&low));
    assert!(archive(&loser, &winner.id)?.contains(&high));
    Ok(())
}
#[tokio::test]
async fn simultaneous_resets_converge_without_rejecting_either_valid_state() -> Result<(), SdkError>
{
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let a = gap(&alice, &bob, "alice-gap")?;
    let b = gap(&bob, &alice, "bob-gap")?;
    let (mut ae, asent) = Wire::engine(&alice, &bob)?;
    let (mut be, bsent) = Wire::engine(&bob, &alice)?;
    assert!(alice.client.apply_routed_entry(&mut ae, &pool()?, &b, false).await.is_err());
    let ra = last(&asent)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &a, false).await.is_err());
    let rb = last(&bsent)?;
    let sa = decode(&ra.envelope)?.ciphertext.session_id;
    let sb = decode(&rb.envelope)?.ciphertext.session_id;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &rb, false).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &ra, false).await?;
    assert_eq!(active(&alice, "bob")?, active(&bob, "alice")?);
    assert_eq!(active(&alice, "bob")?, sa.min(sb));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &last(&bsent)?, false).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&asent)?, false).await?;
    let a = seal(&alice, &bob, outgoing(&alice, &bob, "after-reset-a"), b"A survives")?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &a, false).await?;
    let b = seal(&bob, &alice, outgoing(&bob, &alice, "after-reset-b"), b"B survives")?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &b, false).await?;
    Ok(())
}
#[tokio::test]
async fn a_lost_reset_is_retried_without_inbound_traffic_until_peer_confirmation()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let packet = gap(&alice, &bob, "gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &packet, false).await.is_err());
    let lost = last(&sent)?;
    let key = format!("dm-pair/reset-work/{}", super::super::session::pair_key("bob", "alice")?);
    let mut work = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&key)?
        .ok_or_else(|| invalid("accepted transport lost its durable reset"))?;
    work["next_at"] = serde_json::json!(0);
    bob.client.account_db()?.persist_actor_state(
        &format!("{}/reset-at", super::super::session::pair_key("bob", "alice")?),
        &(now_unix_timestamp() - 60),
    )?;
    bob.client.account_db()?.persist_actor_state(&key, &work)?;
    let (engine, resent) = Wire::engine(&bob, &alice)?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    bob.client = std::mem::take(&mut account.client);
    let retry = last(&resent)?;
    assert_ne!(retry.envelope.envelope_id, lost.envelope.envelope_id);
    assert_eq!(
        decode(&retry.envelope)?.ciphertext.session_id,
        decode(&lost.envelope)?.ciphertext.session_id
    );
    let (mut ae, acks) = Wire::engine(&alice, &bob)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &retry, false).await?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&acks)?, false).await?;
    assert!(bob.client.account_db()?.load_actor_state::<serde_json::Value>(&key)?.is_none());
    let next = seal(&alice, &bob, outgoing(&alice, &bob, "after-offline"), b"online again")?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &next, false).await?;
    Ok(())
}
#[tokio::test]
async fn archive_eviction_erases_the_old_state_and_requests_authenticated_reset()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let old = active(&bob, "alice")?;
    let late = seal(&alice, &bob, outgoing(&alice, &bob, "late-old-state"), b"late")?;
    for n in 0..10 {
        let _packet = fresh(&bob, &alice, &format!("replace-{n}"))?;
    }
    let previous = archive(&bob, "alice")?;
    assert_eq!(previous.len(), 8);
    assert!(!previous.contains(&old));
    assert!(
        bob.client
            .account_db()?
            .load_actor_state::<serde_json::Value>(&format!("dm-pair/session/{old}"))?
            .is_none()
    );
    assert!(matches!(bob.client.open_routed(&late, "bob"), Err(SdkError::PairRecoveryRequired)));
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &late, false).await.is_err());
    assert_eq!(sent.lock().map_err(|_| invalid("mutex"))?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_reset_rotates_before_its_own_retry_gap_can_wedge_it()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let packet = gap(&alice, &bob, "initial-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &packet, false).await.is_err());
    let first = last(&sent)?;
    let (mut session, bundle) =
        bob.client.active_pair("bob", "alice")?.ok_or_else(|| invalid("pair"))?;
    for _ in 0..1001 {
        session.encrypt(b"unacknowledged", b"discarded")?;
    }
    bob.client.persist_pair("bob", "alice", &bundle, &session)?;
    let key = format!("dm-pair/reset-work/{}", super::super::session::pair_key("bob", "alice")?);
    let mut work = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&key)?
        .ok_or_else(|| invalid("no durable reset"))?;
    work["next_at"] = serde_json::json!(0);
    bob.client.account_db()?.persist_actor_state(
        &format!("{}/reset-at", super::super::session::pair_key("bob", "alice")?),
        &(now_unix_timestamp() - 60),
    )?;
    bob.client.account_db()?.persist_actor_state(&key, &work)?;
    let (engine, retries) = Wire::engine(&bob, &alice)?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    bob.client = std::mem::take(&mut account.client);
    let retry = last(&retries)?;
    assert_ne!(
        decode(&retry.envelope)?.ciphertext.session_id,
        decode(&first.envelope)?.ciphertext.session_id
    );
    let (mut ae, ack) = Wire::engine(&alice, &bob)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &retry, false).await?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&ack)?, false).await?;
    assert_eq!(active(&alice, "bob")?, active(&bob, "alice")?);
    Ok(())
}

#[tokio::test]
async fn reset_requests_use_the_verified_identity_directory_delivery_alias() -> Result<(), SdkError>
{
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let mut manifest = crate::client::identity_authority::test_support::manifest(&alice.client)?;
    manifest.devices[0].target_delivery_id = "alice-delivery".into();
    bob.client.persist_identity_directory(&manifest)?;
    let packet = gap(&alice, &bob, "alias-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &packet, false).await.is_err());
    assert_eq!(last(&sent)?.envelope.target_delivery_id, "alice-delivery");
    Ok(())
}
