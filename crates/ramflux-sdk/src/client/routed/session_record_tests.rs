// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Overlapping, delayed, evicted and offline device-pair session regressions.
use super::r5::{fresh, native_outgoing as outgoing, seal, settle};
use super::review::{pool, trust};
use super::*;
use std::sync::{Arc, Mutex};
pub(super) type Sent = Arc<Mutex<Vec<GatewayInboxEntry>>>;
/// Runs inside the gateway Submit handler, after acceptance and before the ACK is returned.
pub(super) type AcceptanceHook = Box<dyn Fn() -> Result<(), String> + Send>;
pub(super) struct Wire {
    bundle: ramflux_crypto::PrekeyBundle,
    responses: VecDeque<Vec<u8>>,
    sent: Sent,
    on_accept: Option<AcceptanceHook>,
    /// Answers every submit with a `nack` of exactly this reason (the submit is still recorded).
    nack: Option<String>,
    /// Holds every submit (after recording it) until the test releases it.
    hold: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}
impl Wire {
    pub(super) fn engine(
        local: &Fixture,
        remote: &Fixture,
    ) -> Result<(GatewaySessionEngine, Sent), SdkError> {
        Self::engine_with_hook(local, remote, None)
    }
    pub(super) fn engine_with_hook(
        local: &Fixture,
        remote: &Fixture,
        on_accept: Option<AcceptanceHook>,
    ) -> Result<(GatewaySessionEngine, Sent), SdkError> {
        Self::scripted_held(local, remote, on_accept, None, None)
    }
    pub(super) fn engine_nacking(
        local: &Fixture,
        remote: &Fixture,
        reason: &str,
    ) -> Result<(GatewaySessionEngine, Sent), SdkError> {
        Self::scripted_held(local, remote, None, Some(reason.to_owned()), None)
    }
    /// A nacking engine whose submit signals `entered` and waits for `release` before replying.
    pub(super) fn engine_held(
        local: &Fixture,
        remote: &Fixture,
        reason: &str,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    ) -> Result<(GatewaySessionEngine, Sent), SdkError> {
        Self::scripted_held(local, remote, None, Some(reason.to_owned()), Some((entered, release)))
    }
    fn scripted_held(
        local: &Fixture,
        remote: &Fixture,
        on_accept: Option<AcceptanceHook>,
        nack: Option<String>,
        hold: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    ) -> Result<(GatewaySessionEngine, Sent), SdkError> {
        let sent = Arc::new(Mutex::new(Vec::new()));
        Ok((
            GatewaySessionEngine::with_test_transport(
                local.config()?,
                Box::new(Self {
                    bundle: remote
                        .client
                        .load_x3dh_private_state(&remote.client.local_device_identity(&remote.id)?)?
                        .bundle,
                    responses: VecDeque::new(),
                    sent: sent.clone(),
                    on_accept,
                    nack,
                    hold,
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
                        forwarded: false,
                        inbox_seq: 2,
                        target_delivery_id: submit.envelope.target_delivery_id.clone(),
                        envelope: submit.envelope,
                    };
                    self.sent
                        .lock()
                        .map_err(|_| ramflux_transport::TransportError::Quic("mutex".to_owned()))?
                        .push(entry.clone());
                    if let Some(hook) = &self.on_accept {
                        hook().map_err(ramflux_transport::TransportError::Quic)?;
                    }
                    if let Some((entered, release)) = &self.hold {
                        entered.notify_one();
                        release.notified().await;
                    }
                    match &self.nack {
                        Some(reason) => GatewayServerFrame::Nack { reason: reason.clone() },
                        None => GatewayServerFrame::Deliver { entry },
                    }
                }
                GatewayClientFrame::RelayTokenV3Issue { request } => {
                    GatewayServerFrame::RelayTokenV3Issued {
                        response: Box::new(crate::gateway::GatewayRelayTokenV3IssueResponse {
                            relay_token: echo_token(&request.body),
                        }),
                    }
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
    fn recv_idle_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        // This scripted transport queues solicited replies only and has no idle server pushes.
        Box::pin(std::future::pending())
    }
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
/// Answers a token issuance by echoing the request fields; the in-process relay checks the binding.
fn echo_token(body: &crate::gateway::SdkRelayTokenV3IssueBody) -> ramflux_protocol::RelayTokenV3 {
    ramflux_protocol::RelayTokenV3 {
        token_version: ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION,
        token_id: format!("token-{}", body.nonce),
        requester_device_id: body.requester_device_id.clone(),
        requester_device_hash: body.requester_device_hash.clone(),
        requester_public_key: body.requester_public_key.clone(),
        requester_device_epoch: body.requester_device_epoch,
        owner_signing_key_id: body.owner_signing_key_id.clone(),
        owner_public_key: body.owner_public_key.clone(),
        owner_home_node_id: body.owner_home_node_id.clone(),
        owner_principal_id: body.owner_principal_id.clone(),
        owner_device_epoch: body.owner_device_epoch,
        issuer_node_id: body.issuer_node_id.clone(),
        gateway_instance_id: body.gateway_instance_id.clone(),
        issuer_certificate_id: body.issuer_certificate.cert_id.clone(),
        attestation_key_id: body.issuer_certificate.attestation_key_id.clone(),
        issuer_certificate: body.issuer_certificate.clone(),
        audience_service: ramflux_protocol::RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
        audience_node_id: body.audience_node_id.clone(),
        relay_instance_id: body.relay_instance_id.clone(),
        object_id: body.object_id.clone(),
        manifest_hash: body.manifest_hash.clone(),
        chunk_id: body.chunk_id.clone(),
        capabilities: body.capabilities.clone(),
        authorization_kind: body.authorization_kind,
        authorization_binding_hash: body.authorization_binding_hash.clone(),
        delete_after_ack: body.delete_after_ack,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        nonce: body.nonce.clone(),
        issuer_signature: String::new(),
    }
}
pub(super) fn active(f: &Fixture, remote: &str) -> Result<String, SdkError> {
    Ok(f.client
        .active_pair(
            &f.client.local_device_identity(&f.id)?,
            &f.client.device_identity(&fixture_peer_reference(&f.client, remote)?)?,
        )?
        .ok_or_else(|| invalid("current pair"))?
        .0
        .session_id)
}
pub(super) fn archive(f: &Fixture, remote: &str) -> Result<Vec<String>, SdkError> {
    Ok(f.client
        .account_db()?
        .load_actor_state::<Vec<String>>(&format!(
            "{}/archive",
            RamfluxClient::pair_key(
                &f.client.local_device_identity(&f.id)?,
                &f.client.device_identity(&fixture_peer_reference(&f.client, remote)?)?
            )?
        ))?
        .unwrap_or_default())
}
pub(super) fn gap(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    let (mut session, bundle) = sender
        .client
        .active_pair(
            &sender.client.local_device_identity(&sender.id)?,
            &sender.client.device_identity(&receiver.reference()?)?,
        )?
        .ok_or_else(|| invalid("pair"))?;
    for _ in 0..1001 {
        session.encrypt(b"lost", b"discarded")?;
    }
    sender.client.persist_pair(
        &sender.client.local_device_identity(&sender.id)?,
        &sender.client.device_identity(&receiver.reference()?)?,
        &bundle,
        &session,
    )?;
    seal(sender, receiver, outgoing(sender, receiver, id)?, b"past gap")
}
pub(super) fn last(sent: &Sent) -> Result<GatewayInboxEntry, SdkError> {
    sent.lock()
        .map_err(|_| invalid("mutex"))?
        .last()
        .cloned()
        .ok_or_else(|| invalid("no control submitted"))
}
fn last_pair_control(sent: &Sent) -> Result<GatewayInboxEntry, SdkError> {
    // The sync pass also flushes receipt work; replay the reset, not the later receipt.
    sent.lock()
        .map_err(|_| invalid("mutex"))?
        .iter()
        .rev()
        .find(|entry| entry.envelope.envelope_id.starts_with("pair-control-"))
        .cloned()
        .ok_or_else(|| invalid("no pair control submitted"))
}

fn group_bootstrap(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
    group: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    trust(sender, receiver)?;
    trust(receiver, sender)?;
    let conversation = format!("thread-{group}");
    sender.create_shared_group(group, &conversation)?;
    let native = sender.native.as_ref().ok_or_else(|| invalid("test: native group source"))?;
    let primary = sender
        .client
        .born_v3_account
        .as_ref()
        .ok_or(SdkError::CustodySetupInvalid)?
        .group_primary(native.vault.as_ref())?;
    sender.client.shared_group_change_with_primary(
        group,
        &sender.config()?.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: receiver
                .client
                .owned_group_actor(&receiver.config()?.target_delivery_id)?
                .identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    let mut message = outgoing(sender, receiver, id)?;
    message.conversation_id = conversation;
    let identity = sender.client.allocate_generated_identity(
        &message.conversation_id,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    message.message_id = ramflux_protocol::encode_base64url(&identity.id);
    let body = sender.client.encrypt_generated_group_inner(
        group,
        &sender.id,
        identity,
        &ramflux_protocol::message::Message {
            text: "delayed group packet".into(),
            ..Default::default()
        },
    )?;
    let bundle =
        receiver.client.load_x3dh_private_state(&receiver.client.owned_device_identity()?)?.bundle;
    let (mut session, header, bundle) =
        sender.client.new_send_pair(&sender.client.owned_device_identity()?, &message, bundle)?;
    let sealed = sender.client.seal_routed_with_route(
        &message,
        &body,
        Route::group_message(group),
        SealPair {
            local: &sender.id,
            remote: &receiver.reference()?,
            session: &mut session,
            header,
            bundle,
        },
    )?;
    let envelope =
        crate::dm::gateway_generated_envelope_from_sealed(&sender.config()?, &mut message, sealed)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.config()?.target_delivery_id,
        envelope,
    })
}
fn membership(receiver: &Fixture, sender: &Fixture, group: &str) -> Result<(), SdkError> {
    let state = sender
        .client
        .account_db()?
        .shared_group_state(group)?
        .ok_or_else(|| invalid("test: verified source group missing"))?;
    receiver.client.accept_shared_group_state(&state, &receiver.config()?.target_delivery_id)?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution(group, &sender.id)?,
    )?;
    Ok(())
}
#[tokio::test]
async fn delayed_loser_bootstrap_behind_membership_keeps_both_directions_decryptable()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        delayed_loser_bootstrap_behind_membership_keeps_both_directions_decryptable_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn delayed_loser_bootstrap_behind_membership_keeps_both_directions_decryptable_body()
-> Result<(), SdkError> {
    let alice = Fixture::native("alice", 41).await?;
    let bob = Fixture::native("bob", 61).await?;
    for client in [&alice.client, &bob.client] {
        client.establish_friend_link(
            "friend",
            &alice.client.own_account_anchor()?,
            &bob.client.own_account_anchor()?,
        )?;
    }
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
        winner.client.apply_routed_entry(&mut we, &pool()?, &delayed).await,
        Err(SdkError::InboundPending(_)
            | SdkError::SenderManifestRequired { .. }
            | SdkError::FreshHeadRequired { .. })
    ));
    membership(&loser, &winner, first_group)?;
    loser.client.apply_routed_entry(&mut le, &pool()?, &first).await?;
    let confirm = seal(&loser, &winner, outgoing(&loser, &winner, "confirm-winner")?, b"confirm")?;
    winner.client.apply_routed_entry(&mut we, &pool()?, &confirm).await?;
    assert_eq!(active(&winner, &loser.id)?, low);
    membership(&winner, &loser, delayed_group)?;
    winner.client.apply_routed_entry(&mut we, &pool()?, &delayed).await?;
    let old_direction = seal(
        &loser,
        &winner,
        outgoing(&loser, &winner, "old-state-still-live")?,
        b"old direction",
    )?;
    winner.client.apply_routed_entry(&mut we, &pool()?, &old_direction).await?;
    assert_eq!(active(&winner, &loser.id)?, high);
    let new_direction =
        seal(&winner, &loser, outgoing(&winner, &loser, "new-state-reply")?, b"new direction")?;
    loser.client.apply_routed_entry(&mut le, &pool()?, &new_direction).await?;
    assert_eq!(active(&loser, &winner.id)?, low);
    assert!(archive(&winner, &loser.id)?.contains(&low));
    assert!(archive(&loser, &winner.id)?.contains(&high));
    Ok(())
}
#[tokio::test]
async fn simultaneous_resets_converge_without_rejecting_either_valid_state() -> Result<(), SdkError>
{
    crate::client::native_test_support::watchdog::within(
        simultaneous_resets_converge_without_rejecting_either_valid_state_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn simultaneous_resets_converge_without_rejecting_either_valid_state_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let a = gap(&alice, &bob, "alice-gap")?;
    let b = gap(&bob, &alice, "bob-gap")?;
    let (mut ae, asent) = Wire::engine(&alice, &bob)?;
    let (mut be, bsent) = Wire::engine(&bob, &alice)?;
    assert!(alice.client.apply_routed_entry(&mut ae, &pool()?, &b).await.is_err());
    let ra = last(&asent)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &a).await.is_err());
    let rb = last(&bsent)?;
    let sa = decode(&ra.envelope)?.ciphertext.session_id;
    let sb = decode(&rb.envelope)?.ciphertext.session_id;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &rb).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &ra).await?;
    assert_eq!(active(&alice, "bob")?, active(&bob, "alice")?);
    assert_eq!(active(&alice, "bob")?, sa.min(sb));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &last(&bsent)?).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&asent)?).await?;
    let a = seal(&alice, &bob, outgoing(&alice, &bob, "after-reset-a")?, b"A survives")?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &a).await?;
    let b = seal(&bob, &alice, outgoing(&bob, &alice, "after-reset-b")?, b"B survives")?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &b).await?;
    Ok(())
}
#[tokio::test]
async fn a_lost_reset_is_retried_without_inbound_traffic_until_peer_confirmation()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        a_lost_reset_is_retried_without_inbound_traffic_until_peer_confirmation_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn a_lost_reset_is_retried_without_inbound_traffic_until_peer_confirmation_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let packet = gap(&alice, &bob, "gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &packet).await.is_err());
    let lost = last(&sent)?;
    let key = format!(
        "dm-pair/reset-work/{}",
        RamfluxClient::pair_key(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
        )?
    );
    let mut work = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&key)?
        .ok_or_else(|| invalid("accepted transport lost its durable reset"))?;
    work["next_at"] = serde_json::json!(0);
    bob.client.account_db()?.persist_actor_state(
        &format!(
            "{}/reset-at",
            RamfluxClient::pair_key(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
        ),
        &(now_unix_timestamp() - 60),
    )?;
    bob.client.account_db()?.persist_actor_state(&key, &work)?;
    let (engine, resent) = Wire::engine(&bob, &alice)?;
    let root = bob.client.own_account_anchor()?;
    let mut account =
        crate::bus::state::LocalBusAccountState::new(std::mem::take(&mut bob.client), engine, root);
    crate::bus::sync_driver::run(&mut account).await?;
    bob.client = std::mem::take(&mut account.client);
    let retry = last_pair_control(&resent)?;
    assert_ne!(retry.envelope.envelope_id, lost.envelope.envelope_id);
    assert_eq!(
        decode(&retry.envelope)?.ciphertext.session_id,
        decode(&lost.envelope)?.ciphertext.session_id
    );
    let (mut ae, acks) = Wire::engine(&alice, &bob)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &retry).await?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&acks)?).await?;
    assert!(bob.client.account_db()?.load_actor_state::<serde_json::Value>(&key)?.is_none());
    let next = seal(&alice, &bob, outgoing(&alice, &bob, "after-offline")?, b"online again")?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &next).await?;
    Ok(())
}
#[tokio::test]
async fn archive_eviction_erases_the_old_state_and_requests_authenticated_reset()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        archive_eviction_erases_the_old_state_and_requests_authenticated_reset_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn archive_eviction_erases_the_old_state_and_requests_authenticated_reset_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let old = active(&bob, "alice")?;
    let late = seal(&alice, &bob, outgoing(&alice, &bob, "late-old-state")?, b"late")?;
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
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &late).await.is_err());
    assert_eq!(sent.lock().map_err(|_| invalid("mutex"))?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_reset_rotates_before_its_own_retry_gap_can_wedge_it()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        an_unacknowledged_reset_rotates_before_its_own_retry_gap_can_wedge_it_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn an_unacknowledged_reset_rotates_before_its_own_retry_gap_can_wedge_it_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let packet = gap(&alice, &bob, "initial-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &packet).await.is_err());
    let first = last(&sent)?;
    let (mut session, bundle) = bob
        .client
        .active_pair(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?;
    for _ in 0..1001 {
        session.encrypt(b"unacknowledged", b"discarded")?;
    }
    bob.client.persist_pair(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        &bundle,
        &session,
    )?;
    let key = format!(
        "dm-pair/reset-work/{}",
        RamfluxClient::pair_key(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
        )?
    );
    let mut work = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&key)?
        .ok_or_else(|| invalid("no durable reset"))?;
    work["next_at"] = serde_json::json!(0);
    bob.client.account_db()?.persist_actor_state(
        &format!(
            "{}/reset-at",
            RamfluxClient::pair_key(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
        ),
        &(now_unix_timestamp() - 60),
    )?;
    bob.client.account_db()?.persist_actor_state(&key, &work)?;
    let (engine, retries) = Wire::engine(&bob, &alice)?;
    let root = bob.client.own_account_anchor()?;
    let mut account =
        crate::bus::state::LocalBusAccountState::new(std::mem::take(&mut bob.client), engine, root);
    crate::bus::sync_driver::run(&mut account).await?;
    bob.client = std::mem::take(&mut account.client);
    let retry = last_pair_control(&retries)?;
    assert_ne!(
        decode(&retry.envelope)?.ciphertext.session_id,
        decode(&first.envelope)?.ciphertext.session_id
    );
    let (mut ae, ack) = Wire::engine(&alice, &bob)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &retry).await?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&ack)?).await?;
    assert_eq!(active(&alice, "bob")?, active(&bob, "alice")?);
    Ok(())
}

#[tokio::test]
async fn reset_requests_use_the_verified_identity_directory_delivery_alias() -> Result<(), SdkError>
{
    crate::client::native_test_support::watchdog::within(
        reset_requests_use_the_verified_identity_directory_delivery_alias_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn reset_requests_use_the_verified_identity_directory_delivery_alias_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let manifest = alice.manifest()?;
    bob.client.persist_fetched_identity_directory(&manifest)?;
    let packet = gap(&alice, &bob, "alias-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &packet).await.is_err());
    assert_eq!(last(&sent)?.envelope.target_delivery_id, alice.config()?.target_delivery_id);
    assert_ne!(
        last(&sent)?.envelope.target_delivery_id,
        alice.id,
        "native directory delivery must keep the certified root-qualified alias",
    );
    Ok(())
}
