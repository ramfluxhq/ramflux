// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed call controls pass through the actual pair AEAD and durable routing projection.
use super::*;
use crate::client::call::{self, state::LiveCall};
use ramflux_protocol::{CallAction, CallControl, VoiceAllocation};
use serde_json::json;
fn contacts(a: &Fixture, b: &Fixture) -> Result<(), SdkError> {
    for (local, peer) in [(a, b), (b, a)] {
        review::trust(local, peer)?;
        let own = r9::manifest(local)?;
        let remote = r9::manifest(peer)?;
        local
            .client
            .account_db()?
            .persist_actor_state(&format!("identity/manifest/{}", peer.id), &remote)?;
        local.client.establish_friend_link(
            "call-contact",
            &own.principal_commitment,
            &remote.principal_commitment,
        )?;
    }
    Ok(())
}
fn control(a: &Fixture, b: &Fixture, id: u8, thread: &str) -> Result<LiveCall, SdkError> {
    let mut call = LiveCall::outgoing(
        ramflux_protocol::encode_base64url([id; 16]),
        thread.into(),
        a.client.call_local_endpoint()?,
        vec![b.client.call_local_endpoint()?],
        now_unix_timestamp(),
    )?;
    call.pin_peer(
        b.client.call_local_endpoint()?,
        r9::manifest(b)?.devices[0].branch_public_key.clone(),
    )?;
    Ok(call)
}
fn signed(sender: &Fixture, mut c: CallControl) -> Result<CallControl, SdkError> {
    c.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &call::signing_bytes(&c)?,
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
    );
    Ok(c)
}
fn entry(
    sender: &Fixture,
    receiver: &Fixture,
    c: &CallControl,
    id: &str,
    thread: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    seal_as(
        sender,
        receiver,
        GatewayDirectMessage {
            conversation_id: thread.into(),
            message_id: id.into(),
            envelope_id: id.into(),
            source_principal_id: sender.id.clone(),
            sender_id: sender.id.clone(),
            recipient_device_id: Some(receiver.id.clone()),
            target_delivery_id: receiver.id.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 300,
        },
        &call::bytes(c)?,
        Route::control(),
    )
}
async fn apply(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let mut engine =
        GatewaySessionEngine::with_test_transport(receiver.config()?, Box::new(NoNetwork));
    receiver.client.apply_routed_entry(&mut engine, &review::pool()?, entry, false).await?;
    Ok(())
}
#[tokio::test]
async fn first_call_invite_creates_a_bound_direct_thread_and_committed_retries_do_not_rering()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 21)?;
    let mut bob = Fixture::new("bob", 31)?;
    contacts(&alice, &bob)?;
    let origin = control(&alice, &bob, 1, "private-first-call-thread")?;
    let invite = signed(&alice, origin.pending[0].clone())?;
    let entry = entry(&alice, &bob, &invite, "call-invite", "private-first-call-thread")?;
    let outer = serde_json::to_string(&entry)?;
    assert!(!outer.contains("private-first-call-thread"));
    assert!(!outer.contains(&invite.call_id));
    apply(&mut bob, &entry).await?;
    let call = &bob.client.voice_calls[&invite.call_id];
    assert_eq!(call.row.state, "incoming_ringing");
    assert_eq!(call.pending.len(), 1);
    let head = bob.client.account_db()?.journal_bounds()?.head_seq;
    apply(&mut bob, &entry).await?;
    assert_eq!(bob.client.account_db()?.journal_bounds()?.head_seq, head);
    assert_eq!(bob.client.voice_calls[&invite.call_id].pending.len(), 1);
    let redrive =
        self::entry(&alice, &bob, &invite, "call-invite-redrive", "private-first-call-thread")?;
    apply(&mut bob, &redrive).await?;
    assert_eq!(bob.client.account_db()?.journal_bounds()?.head_seq, head);
    assert_eq!(bob.client.voice_calls[&invite.call_id].pending.len(), 1);
    let mut changed = invite.clone();
    changed.created_at += 1;
    let changed = signed(&alice, changed)?;
    let equivocation =
        self::entry(&alice, &bob, &changed, "call-equivocation", "private-first-call-thread")?;
    assert!(apply(&mut bob, &equivocation).await.is_err());
    let thread = bob
        .client
        .account_db()?
        .client_record("conversation", "private-first-call-thread")?
        .ok_or_else(|| invalid("thread missing"))?;
    assert_eq!(thread["kind"], "direct");
    assert_eq!(thread["participants"], json!(["alice", "bob"]));
    Ok(())
}
#[tokio::test]
async fn forged_call_signatures_and_cross_conversation_controls_publish_no_call()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 51)?;
    contacts(&alice, &bob)?;
    let origin = control(&alice, &bob, 2, "thread")?;
    let mut forged = signed(&alice, origin.pending[0].clone())?;
    forged.created_at += 1;
    let forged_entry = entry(&alice, &bob, &forged, "forged-call", "thread")?;
    assert!(apply(&mut bob, &forged_entry).await.is_err());
    assert_eq!(bob.client.account_db()?.voice_call_rows(false)?.len(), 0);
    bob.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"direct","participants":["bob","carol"]}),
    )?;
    let genuine = signed(&alice, origin.pending[0].clone())?;
    let cross = entry(&alice, &bob, &genuine, "cross-thread-call", "thread")?;
    assert!(apply(&mut bob, &cross).await.is_err());
    assert_eq!(bob.client.account_db()?.voice_call_rows(false)?.len(), 0);
    assert_eq!(bob.client.voice_calls.len(), 0);
    Ok(())
}
#[tokio::test]
async fn signed_answer_ack_and_hangup_transition_both_peers_and_wipe_ended_media()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 61)?;
    let mut bob = Fixture::new("bob", 71)?;
    contacts(&alice, &bob)?;
    let origin = control(&alice, &bob, 3, "voice-thread")?;
    let id = origin.row.call_id.clone();
    let invite = signed(&alice, origin.pending[0].clone())?;
    alice.client.persist_call_row(&origin.row)?;
    alice.client.voice_calls.insert(id.clone(), origin);
    let invite = entry(&alice, &bob, &invite, "invite", "voice-thread")?;
    apply(&mut bob, &invite).await?;
    let recipient =
        bob.client.voice_calls.get_mut(&id).ok_or_else(|| invalid("recipient missing"))?;
    recipient.answer(now_unix_timestamp())?;
    let answer = recipient
        .pending
        .iter()
        .find(|c| matches!(c.body, CallAction::Answer { .. }))
        .cloned()
        .ok_or_else(|| invalid("answer missing"))?;
    let answer = signed(&bob, answer)?;
    let answer = entry(&bob, &alice, &answer, "answer", "voice-thread")?;
    apply(&mut alice, &answer).await?;
    assert_eq!(alice.client.voice_calls[&id].row.state, "connecting");
    let origin = alice.client.voice_calls.get_mut(&id).ok_or_else(|| invalid("origin missing"))?;
    origin.activate(
        VoiceAllocation {
            endpoint: "relay.example:9000".into(),
            caller_token: ramflux_protocol::encode_base64url([9; 32]),
            callee_token: ramflux_protocol::encode_base64url([10; 32]),
            expires_at: now_unix_timestamp().unsigned_abs().saturating_add(60),
        },
        now_unix_timestamp(),
    )?;
    let ack = origin
        .pending
        .iter()
        .find(|c| matches!(c.body, CallAction::Ack { .. }))
        .cloned()
        .ok_or_else(|| invalid("ack missing"))?;
    let ack = signed(&alice, ack)?;
    let ack = entry(&alice, &bob, &ack, "ack", "voice-thread")?;
    apply(&mut bob, &ack).await?;
    assert_eq!(bob.client.voice_calls[&id].row.state, "active");
    alice
        .client
        .voice_calls
        .get_mut(&id)
        .ok_or_else(|| invalid("origin missing"))?
        .end(false, now_unix_timestamp())?;
    let hangup = alice.client.voice_calls[&id].pending[0].clone();
    let hangup = signed(&alice, hangup)?;
    let hangup = entry(&alice, &bob, &hangup, "hangup", "voice-thread")?;
    apply(&mut bob, &hangup).await?;
    let ended = &bob.client.voice_calls[&id];
    assert_eq!(ended.row.state, "ended");
    assert_eq!(ended.row.end_reason.as_deref(), Some("completed"));
    assert!(ended.receive_key.is_none());
    assert_eq!(ended.send_key.as_ref(), &[0; 32]);
    apply(&mut bob, &hangup).await?;
    assert_eq!(bob.client.voice_calls[&id].row.end_reason.as_deref(), Some("completed"));
    Ok(())
}
