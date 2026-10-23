// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair recovery and failed object-slot isolation regressions.
use super::review::{pool, trust};
use super::*;
fn outgoing(sender: &Fixture, receiver: &Fixture, id: &str) -> GatewayDirectMessage {
    let mut msg = message(id, "recovery-thread");
    msg.source_principal_id.clone_from(&sender.id);
    msg.sender_id.clone_from(&sender.id);
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.target_delivery_id.clone_from(&receiver.id);
    msg
}
fn fresh(sender: &Fixture, receiver: &Fixture, id: &str) -> Result<GatewayInboxEntry, SdkError> {
    trust(sender, receiver)?;
    trust(receiver, sender)?;
    let mut msg = outgoing(sender, receiver, id);
    let bundle = receiver.client.load_x3dh_private_state(&receiver.id)?.bundle;
    let (mut session, header, bundle) = sender.client.new_send_pair(&sender.id, &msg, bundle)?;
    let encrypted = sender.client.seal_routed_with_route(
        &msg,
        b"fresh",
        Route::direct(),
        SealPair { local: &sender.id, remote: &receiver.id, session: &mut session, header, bundle },
    )?;
    msg.encrypted_body = serde_json::to_vec(&encrypted)?;
    Ok(GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: receiver.id.clone(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}
async fn settle(alice: &mut Fixture, bob: &mut Fixture) -> Result<(), SdkError> {
    alice.client.establish_friend_link("friend", "alice", "bob")?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let entry = fresh(alice, bob, "initial")?;
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut be, &pool()?, &entry, false).await?;
    let reply = seal(bob, alice, outgoing(bob, alice, "reply"), b"reply")?;
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &reply, false).await?;
    Ok(())
}
#[tokio::test]
async fn verified_peer_state_loss_bootstrap_supersedes_a_settled_pair() -> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let old =
        alice.client.active_pair("alice", "bob")?.ok_or_else(|| invalid("pair"))?.0.session_id;
    bob.client
        .account_db()?
        .remove_actor_state(&super::super::session::pair_key("bob", "alice")?)?;
    bob.client.account_db()?.remove_actor_state(&format!("dm-pair/session/{old}"))?;
    let entry = fresh(&bob, &alice, "after-state-loss")?;
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &entry, false).await?;
    let active =
        alice.client.active_pair("alice", "bob")?.ok_or_else(|| invalid("pair"))?.0.session_id;
    assert_ne!(active, old);
    assert_eq!(active, decode(&entry.envelope)?.ciphertext.session_id);
    let reply = seal(&alice, &bob, outgoing(&alice, &bob, "after-recovery"), b"recovered")?;
    assert_eq!(bob.client.open_routed(&reply, "bob")?.body.as_slice(), b"recovered");
    Ok(())
}
#[tokio::test]
async fn unverified_fresh_bootstrap_cannot_displace_a_settled_pair() -> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let old =
        alice.client.active_pair("alice", "bob")?.ok_or_else(|| invalid("pair"))?.0.session_id;
    let mut entry = fresh(&bob, &alice, "forged")?;
    entry.envelope.signed.signature = "invalid".to_owned();
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    assert!(alice.client.apply_routed_entry(&mut ae, &pool()?, &entry, false).await.is_err());
    assert_eq!(
        alice.client.active_pair("alice", "bob")?.ok_or_else(|| invalid("pair"))?.0.session_id,
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
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let (mut session, bundle) =
        alice.client.active_pair("alice", "bob")?.ok_or_else(|| invalid("pair"))?;
    for _ in 0..1001 {
        session.encrypt(b"lost", b"discarded")?;
    }
    alice.client.persist_pair("alice", "bob", &bundle, &session)?;
    let gap = seal(&alice, &bob, outgoing(&alice, &bob, "gap"), b"past-gap")?;
    assert!(matches!(
        bob.client.open_routed(&gap, "bob"),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::MaxSkipExceeded))
    ));
    let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let wire = ResetWire {
        bundle: alice.client.load_x3dh_private_state("alice")?.bundle,
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
    let next = seal(&alice, &bob, outgoing(&alice, &bob, "recovered"), b"works-after-gap")?;
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
#[test]
fn a_failed_attachment_slot_leaves_the_live_ratchet_unchanged() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let bob = Fixture::new("bob", 61)?;
    let entry = fresh(&alice, &bob, "slot-bootstrap")?;
    let mut opened = bob.client.open_routed(&entry, "bob")?;
    let before = opened.session.clone();
    let (mut send, bundle) =
        alice.client.active_pair("alice", "bob")?.ok_or_else(|| invalid("pair"))?;
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
        x3dh: decode(&entry.envelope)?.x3dh,
        ciphertext,
    };
    bob.client.persist_pair("bob", "alice", &bundle, &opened.session)?;
    assert!(bob.client.decrypt_pair_object_slot(&slot, Some(&mut opened.session)).is_err());
    assert_eq!(opened.session, before);
    Ok(())
}
