// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair recovery and failed object-slot isolation regressions.
use super::review::{pool, trust};
use super::*;
pub(super) fn outgoing(sender: &Fixture, receiver: &Fixture, id: &str) -> GatewayDirectMessage {
    let mut msg = message(id, "recovery-thread");
    msg.source_principal_id = sender
        .client
        .device_branch
        .as_ref()
        .map_or_else(|| sender.id.clone(), |b| b.principal_id.clone());
    msg.sender_id.clone_from(&sender.id);
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.recipient_principal_commitment =
        receiver.client.identity_root.as_ref().map(|root| {
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())
        });
    msg.target_delivery_id.clone_from(&receiver.id);
    msg
}
pub(super) fn fresh(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    trust(sender, receiver)?;
    trust(receiver, sender)?;
    let mut msg = native_outgoing(sender, receiver, id)?;
    let bundle = receiver
        .client
        .load_x3dh_private_state(&receiver.client.local_device_identity(&receiver.id)?)?
        .bundle;
    let (mut session, header, bundle) = sender.client.new_send_pair(
        &sender.client.local_device_identity(&sender.id)?,
        &msg,
        bundle,
    )?;
    let exact = candidate_report::text_inner(sender, &msg.conversation_id, b"fresh")?;
    msg.message_id =
        ramflux_protocol::encode_base64url(RamfluxClient::decode_generated_inner(&exact)?.0.id);
    let encrypted = sender.client.seal_routed_with_route(
        &msg,
        &exact,
        Route::direct(),
        SealPair {
            local: &sender.id,
            remote: &receiver.reference()?,
            session: &mut session,
            header,
            bundle,
        },
    )?;
    let envelope =
        crate::dm::gateway_generated_envelope_from_sealed(&sender.config()?, &mut msg, encrypted)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.config()?.target_delivery_id,
        envelope,
    })
}
pub(super) async fn settle(alice: &mut Fixture, bob: &mut Fixture) -> Result<(), SdkError> {
    for local in [&alice.client, &bob.client] {
        local.establish_friend_link(
            "friend",
            &alice.client.own_account_anchor()?,
            &bob.client.own_account_anchor()?,
        )?;
    }
    let entry = fresh(alice, bob, "initial")?;
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    Box::pin(bob.client.apply_routed_entry(&mut be, &pool()?, &entry, false)).await?;
    let reply = seal(bob, alice, native_outgoing(bob, alice, "reply")?, b"reply")?;
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    Box::pin(alice.client.apply_routed_entry(&mut ae, &pool()?, &reply, false)).await?;
    Ok(())
}
#[tokio::test]
async fn verified_peer_state_loss_bootstrap_supersedes_a_settled_pair() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        verified_peer_state_loss_bootstrap_supersedes_a_settled_pair_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn verified_peer_state_loss_bootstrap_supersedes_a_settled_pair_body() -> Result<(), SdkError>
{
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let old = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    bob.client.account_db()?.remove_actor_state(&RamfluxClient::pair_key(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
    )?)?;
    bob.client.account_db()?.remove_actor_state(&format!("dm-pair/session/{old}"))?;
    let entry = fresh(&bob, &alice, "after-state-loss")?;
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &entry, false).await?;
    let active = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    assert_ne!(active, old);
    assert_eq!(active, decode(&entry.envelope)?.ciphertext.session_id);
    let reply = seal(&alice, &bob, native_outgoing(&alice, &bob, "after-recovery")?, b"recovered")?;
    let opened = bob.client.open_routed(&reply, "bob")?;
    let (_, content) = RamfluxClient::decode_generated_inner(&opened.body)?;
    let Some(ramflux_protocol::message::content::Value::Message(message)) = content.value else {
        return Err(invalid("test: recovered Message missing"));
    };
    assert_eq!(message.text, "recovered");
    Ok(())
}
#[tokio::test]
async fn unverified_fresh_bootstrap_cannot_displace_a_settled_pair() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        unverified_fresh_bootstrap_cannot_displace_a_settled_pair_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn unverified_fresh_bootstrap_cannot_displace_a_settled_pair_body() -> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let old = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    let mut entry = fresh(&bob, &alice, "forged")?;
    entry.envelope.signed.signature = "invalid".to_owned();
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    assert!(alice.client.apply_routed_entry(&mut ae, &pool()?, &entry, false).await.is_err());
    assert_eq!(
        alice
            .client
            .active_pair(
                &alice.client.local_device_identity("alice")?,
                &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?
            )?
            .ok_or_else(|| invalid("pair"))?
            .0
            .session_id,
        old
    );
    Ok(())
}
struct ResetWire {
    bundle: ramflux_crypto::PrekeyBundle,
    responses: VecDeque<Vec<u8>>,
    sent: std::sync::Arc<std::sync::Mutex<Vec<GatewayInboxEntry>>>,
}
impl ramflux_transport::GatewaySessionFrameSink for ResetWire {
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
                        device_id,
                        bundle: Some(self.bundle.clone()),
                        principal_commitment: "alice".to_owned(),
                        target_delivery_id: Some("alice".to_owned()),
                    },
                },
                GatewayClientFrame::Submit { submit } => {
                    let entry = GatewayInboxEntry {
                        forwarded: false,
                        inbox_seq: 2,
                        target_delivery_id: "alice".to_owned(),
                        envelope: submit.envelope,
                    };
                    self.sent
                        .lock()
                        .map_err(|_| ramflux_transport::TransportError::Quic("mutex".to_owned()))?
                        .push(entry.clone());
                    GatewayServerFrame::Deliver { entry }
                }
                _ => {
                    return Err(ramflux_transport::TransportError::Quic(
                        "unexpected recovery frame".to_owned(),
                    ));
                }
            };
            self.responses.push_back(serde_json::to_vec(&response)?);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for ResetWire {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            self.responses
                .pop_front()
                .ok_or_else(|| ramflux_transport::TransportError::Quic("empty".to_owned()))
        })
    }
}
#[tokio::test]
async fn a_gap_beyond_one_thousand_packets_sends_an_encrypted_reset_and_recovers()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        a_gap_beyond_one_thousand_packets_sends_an_encrypted_reset_and_recovers_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn a_gap_beyond_one_thousand_packets_sends_an_encrypted_reset_and_recovers_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let (mut session, bundle) = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?;
    for _ in 0..1001 {
        session.encrypt(b"lost", b"discarded")?;
    }
    alice.client.persist_pair(
        &alice.client.local_device_identity("alice")?,
        &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        &bundle,
        &session,
    )?;
    let gap = seal(&alice, &bob, native_outgoing(&alice, &bob, "gap")?, b"past-gap")?;
    assert!(matches!(
        bob.client.open_routed(&gap, "bob"),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::MaxSkipExceeded))
    ));
    let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let wire = ResetWire {
        bundle: alice
            .client
            .load_x3dh_private_state(&alice.client.local_device_identity("alice")?)?
            .bundle,
        responses: VecDeque::new(),
        sent: sent.clone(),
    };
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(wire));
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &gap, false).await.is_err());
    let reset = sent
        .lock()
        .map_err(|_| invalid("mutex"))?
        .first()
        .cloned()
        .ok_or_else(|| invalid("authenticated reset was not sent"))?;
    let outer = serde_json::to_value(&reset.envelope)?;
    assert!(outer.get("conversation_id").is_none());
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &reset, false).await?;
    let next = seal(&alice, &bob, native_outgoing(&alice, &bob, "recovered")?, b"works-after-gap")?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &next, false).await?;
    assert!(
        alice
            .client
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|event| event.topic == "session.reset")
    );
    assert!(
        bob.client
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|event| event.topic == "session.reset")
    );
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn a_failed_attachment_slot_leaves_the_live_ratchet_unchanged() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        a_failed_attachment_slot_leaves_the_live_ratchet_unchanged_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn a_failed_attachment_slot_leaves_the_live_ratchet_unchanged_body() -> Result<(), SdkError> {
    let alice = Fixture::native("alice", 41).await?;
    let bob = Fixture::native("bob", 61).await?;
    let entry = fresh(&alice, &bob, "slot-bootstrap")?;
    let mut opened = bob.client.open_routed(&entry, "bob")?;
    let before = opened.session.clone();
    let (mut send, bundle) = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?;
    for _ in 0..3 {
        send.encrypt(b"lost", b"discarded")?;
    }
    let ciphertext = send.encrypt(&[9; 32], b"wrong-aad")?;
    let slot = crate::SdkObjectKeySlot {
        schema: "ramflux.sdk.object_key_slot.dm.v2".to_owned(),
        version: 2,
        object_id: "object".to_owned(),
        conversation_id: "recovery-thread".to_owned(),
        recipient_device_id: "bob".to_owned(),
        source_principal_commitment: None,
        x3dh: decode(&entry.envelope)?.x3dh,
        ciphertext,
    };
    bob.client.persist_pair(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        &bundle,
        &opened.session,
    )?;
    assert!(bob.client.decrypt_pair_object_slot(&slot, Some(&mut opened.session)).is_err());
    assert_eq!(opened.session, before);
    Ok(())
}

#[tokio::test]
async fn verified_rebootstrap_also_replaces_a_passively_confirmed_pair() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        verified_rebootstrap_also_replaces_a_passively_confirmed_pair_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn verified_rebootstrap_also_replaces_a_passively_confirmed_pair_body() -> Result<(), SdkError>
{
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let old = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    alice.client.account_db()?.remove_actor_state(&RamfluxClient::pair_key(
        &alice.client.local_device_identity("alice")?,
        &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
    )?)?;
    alice.client.account_db()?.remove_actor_state(&format!("dm-pair/session/{old}"))?;
    let entry = fresh(&alice, &bob, "alice-state-loss")?;
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    Box::pin(bob.client.apply_routed_entry(&mut be, &pool()?, &entry, false)).await?;
    assert_eq!(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .ok_or_else(|| invalid("pair"))?
            .0
            .session_id,
        decode(&entry.envelope)?.ciphertext.session_id
    );
    assert!(
        bob.client
            .archived_pairs(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .contains(&old)
    );
    assert!(
        bob.client
            .account_db()?
            .load_actor_state::<serde_json::Value>(&format!("dm-pair/session/{old}"))?
            .is_some()
    );
    Ok(())
}
#[tokio::test]
async fn an_authenticated_reset_keeps_both_candidates_and_chooses_the_lower_id()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        an_authenticated_reset_keeps_both_candidates_and_chooses_the_lower_id_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn an_authenticated_reset_keeps_both_candidates_and_chooses_the_lower_id_body()
-> Result<(), SdkError> {
    let alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    trust(&alice, &bob)?;
    trust(&bob, &alice)?;
    let pending = fresh(&bob, &alice, "unconfirmed-bob")?;
    let old = decode(&pending.envelope)?.ciphertext.session_id;
    let (mut message, sealed) = seal_native_fixture(
        &alice,
        &bob,
        native_outgoing(&alice, &bob, "reset")?,
        &candidate_report::reset_inner(&alice, &bob)?,
        Route::control(),
    )?;
    let reset = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: bob.config()?.target_delivery_id,
        envelope: crate::dm::gateway_generated_envelope_from_sealed(
            &alice.config()?,
            &mut message,
            sealed,
        )?,
    };
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut be, &pool()?, &reset, false).await?;
    let incoming = decode(&reset.envelope)?.ciphertext.session_id;
    assert_eq!(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .ok_or_else(|| invalid("pair"))?
            .0
            .session_id,
        old.clone().min(incoming.clone())
    );
    assert!(
        bob.client
            .archived_pairs(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .contains(&old.clone().max(incoming))
    );
    assert!(
        bob.client
            .account_db()?
            .load_actor_state::<serde_json::Value>(&format!("dm-pair/session/{old}"))?
            .is_some()
    );
    Ok(())
}

#[test]
fn an_address_shaped_device_name_is_rejected_at_live_enrollment() -> Result<(), SdkError> {
    let literal = ramflux_protocol::qualified_device_id("unrelated-root", "phone")?;
    assert!(matches!(Fixture::new(&literal, 41), Err(SdkError::Crypto(_))));
    // The address codec still preserves historical literal names without aliasing.
    let historical = ramflux_protocol::qualified_device_id("actual-root", &literal)?;
    assert_eq!(
        ramflux_protocol::parse_qualified_device_id(&historical)?,
        Some(("actual-root".into(), literal))
    );
    Ok(())
}

pub(super) fn native_outgoing(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
) -> Result<GatewayDirectMessage, SdkError> {
    let mut message = outgoing(sender, receiver, id);
    message.conversation_id = ramflux_protocol::message::dm_scope::derive(
        &sender.client.own_account_anchor()?,
        &receiver.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    message.source_principal_id = sender.config()?.principal_id;
    message.recipient_principal_commitment = Some(receiver.client.own_account_anchor()?);
    message.target_delivery_id = receiver.config()?.target_delivery_id;
    Ok(message)
}

pub(super) fn seal(
    sender: &Fixture,
    receiver: &Fixture,
    message: GatewayDirectMessage,
    text: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    let exact = candidate_report::text_inner(sender, &message.conversation_id, text)?;
    let mut message = message;
    message.message_id =
        ramflux_protocol::encode_base64url(RamfluxClient::decode_generated_inner(&exact)?.0.id);
    let (mut message, sealed) =
        seal_native_fixture(sender, receiver, message, &exact, Route::direct())?;
    let envelope =
        crate::dm::gateway_generated_envelope_from_sealed(&sender.config()?, &mut message, sealed)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.config()?.target_delivery_id,
        envelope,
    })
}
