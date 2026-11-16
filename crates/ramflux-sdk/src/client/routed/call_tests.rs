// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed call controls pass through the actual pair AEAD and durable routing projection.
use super::*;
use crate::client::call::{self, state::LiveCall};
use crate::client::identity_authority::HeadUse;
use ramflux_protocol::{CallAction, CallControl};
use serde_json::json;
fn contacts(a: &Fixture, b: &Fixture) -> Result<(), SdkError> {
    for (local, peer) in [(a, b), (b, a)] {
        review::trust(local, peer)?;
        let own = r9::manifest(local)?;
        local.client.persist_fetched_identity_directory(&own)?;
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
        r9::manifest(b)?
            .devices
            .first()
            .ok_or_else(|| invalid("test: peer device missing"))?
            .branch_public_key
            .clone(),
    )?;
    Ok(call)
}
fn signed(sender: &Fixture, mut c: CallControl) -> Result<CallControl, SdkError> {
    if matches!(c.body, CallAction::Invite { .. }) {
        let branch = sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let peer = sender.client.call_device_identity(&c.callee)?;
        let peer_record = sender.client.trusted_device(HeadUse::NewAuthorization, &peer)?;
        let created_at = u64::try_from(c.created_at).map_err(|_| invalid("test: call clock"))?;
        let entropy = ramflux_crypto::random_32()?;
        let reference = entropy.get(..16).ok_or_else(|| invalid("test: call reference entropy"))?;
        let body = ramflux_protocol::CallIntentV1 {
            version: 1,
            signing_key_id: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
            audience: ramflux_protocol::GATEWAY_CALL_INTENT_AUDIENCE.into(),
            sender_device: sender.client.call_device_identity(&c.caller)?.storage_key().into(),
            sender_epoch: branch.device_epoch,
            target_device: peer.storage_key().into(),
            target_epoch: peer_record
                .get("device_epoch")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| invalid("test: peer epoch"))?,
            target_delivery_id: peer_record
                .get("target_delivery_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("test: peer delivery route"))?
                .into(),
            call_ref: ramflux_protocol::encode_base64url(reference),
            source_event_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            kind: ramflux_protocol::CallIntentKind::OneToOne,
            action: ramflux_protocol::CallIntentAction::Start,
            seq: 0,
            created_at,
            issued_at: created_at,
            expires_at: created_at + 30,
            start_digest: None,
        };
        let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::call_intent_signing_bytes(&body)?,
            branch,
        );
        c.call_ref = Some(body.call_ref.clone());
        c.call_start = Some(ramflux_protocol::SignedCallIntentV1 { body, signature });
    }
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
    use ramflux_protocol::message as g;
    let id = c.call_start.as_ref().map_or(id, |start| start.body.source_event_id.as_str());
    let identity = sender.client.account_db()?.write_transaction(|| {
        sender.client.allocate_generated_identity(
            thread,
            crate::client::generated_identity::now_ms(),
            false,
        )
    })?;
    let exact = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content {
            value: Some(g::content::Value::Call(
                crate::client::generated_call::native::from_native(c)?,
            )),
        },
    )?;
    let message = GatewayDirectMessage {
        conversation_id: thread.into(),
        message_id: ramflux_protocol::encode_base64url(identity.id),
        envelope_id: id.into(),
        source_principal_id: sender.config()?.principal_id,
        sender_id: sender.id.clone(),
        recipient_device_id: Some(receiver.id.clone()),
        recipient_principal_commitment: Some(receiver.client.own_account_anchor()?),
        target_delivery_id: receiver.config()?.target_delivery_id,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 300,
    };
    let (mut message, sealed) =
        seal_native_fixture(sender, receiver, message, &exact, Route::control())?;
    let envelope =
        crate::dm::gateway_generated_envelope_from_sealed(&sender.config()?, &mut message, sealed)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.config()?.target_delivery_id,
        envelope,
    })
}
async fn apply(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let mut engine =
        GatewaySessionEngine::with_test_transport(receiver.config()?, Box::new(NoNetwork));
    receiver.client.apply_routed_entry(&mut engine, &review::pool()?, entry).await?;
    Ok(())
}
#[tokio::test]
async fn first_call_invite_creates_a_bound_direct_thread_and_committed_retries_do_not_rering()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        first_call_invite_creates_a_bound_direct_thread_and_committed_retries_do_not_rering_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn first_call_invite_creates_a_bound_direct_thread_and_committed_retries_do_not_rering_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 21).await?;
    let mut bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let origin = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        origin.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let entry = entry(&alice, &bob, &invite, "call-invite", &conversation)?;
    let outer = serde_json::to_string(&entry)?;
    assert!(!outer.contains(&conversation));
    assert!(!outer.contains(&invite.call_id));
    apply(&mut bob, &entry).await?;
    let call = &bob
        .client
        .voice_calls
        .get(&invite.call_id)
        .ok_or_else(|| invalid("test: call missing"))?;
    assert_eq!(call.row.state, "incoming_ringing");
    assert_eq!(call.pending.len(), 1);
    let head = bob.client.account_db()?.journal_bounds()?.head_seq;
    apply(&mut bob, &entry).await?;
    assert_eq!(bob.client.account_db()?.journal_bounds()?.head_seq, head);
    assert_eq!(
        bob.client
            .voice_calls
            .get(&invite.call_id)
            .ok_or_else(|| invalid("test: call missing"))?
            .pending
            .len(),
        1
    );
    let redrive = entry.clone();
    apply(&mut bob, &redrive).await?;
    assert_eq!(bob.client.account_db()?.journal_bounds()?.head_seq, head);
    assert_eq!(
        bob.client
            .voice_calls
            .get(&invite.call_id)
            .ok_or_else(|| invalid("test: call missing"))?
            .pending
            .len(),
        1
    );
    let mut changed = invite.clone();
    changed.created_at += 1;
    let changed = signed(&alice, changed)?;
    let equivocation = self::entry(&alice, &bob, &changed, "call-equivocation", &conversation)?;
    assert!(apply(&mut bob, &equivocation).await.is_err());
    let thread = bob
        .client
        .account_db()?
        .client_record("conversation", &conversation)?
        .ok_or_else(|| invalid("thread missing"))?;
    assert_eq!(thread["kind"], "direct");
    assert_eq!(thread["participants"], json!(["alice", "bob"]));
    Ok(())
}
#[tokio::test]
async fn forged_call_signatures_and_cross_conversation_controls_publish_no_call()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        forged_call_signatures_and_cross_conversation_controls_publish_no_call_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn forged_call_signatures_and_cross_conversation_controls_publish_no_call_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 41).await?;
    let mut bob = Fixture::native_named("bob", 51).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let origin = control(&alice, &bob, 2, &conversation)?;
    let mut forged = signed(
        &alice,
        origin.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    forged.created_at += 1;
    let forged_entry = entry(&alice, &bob, &forged, "forged-call", &conversation)?;
    assert!(apply(&mut bob, &forged_entry).await.is_err());
    assert_eq!(bob.client.account_db()?.voice_call_rows(false)?.len(), 0);
    bob.client.account_db()?.persist_client_record(
        "conversation",
        &conversation,
        &json!({"kind":"direct","participants":["bob","carol"]}),
    )?;
    let genuine = signed(
        &alice,
        origin.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let cross = entry(&alice, &bob, &genuine, "cross-thread-call", &conversation)?;
    assert!(apply(&mut bob, &cross).await.is_err());
    assert_eq!(bob.client.account_db()?.voice_call_rows(false)?.len(), 0);
    assert_eq!(bob.client.voice_calls.len(), 0);
    Ok(())
}
#[tokio::test]
async fn a_signed_invite_stays_held_without_a_correlated_gateway_decision() -> Result<(), SdkError>
{
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Box::pin(async {
            let alice = Fixture::native_named("alice", 61).await?;
            let mut bob = Fixture::native_named("bob", 71).await?;
            contacts(&alice, &bob)?;
            let conversation = ramflux_protocol::message::dm_scope::derive(
                &alice.client.own_account_anchor()?,
                &bob.client.own_account_anchor()?,
            )
            .map_err(|e| invalid(&e.to_string()))?;
            let origin = control(&alice, &bob, 3, &conversation)?;
            let id = origin.row.call_id.clone();
            let invite = signed(
                &alice,
                origin
                    .pending
                    .first()
                    .ok_or_else(|| invalid("test: pending call missing"))?
                    .clone(),
            )?;
            let packet = entry(&alice, &bob, &invite, "invite", &conversation)?;
            apply(&mut bob, &packet).await?;
            let recipient = bob
                .client
                .voice_calls
                .get_mut(&id)
                .ok_or_else(|| invalid("test: recipient missing"))?;
            assert!(recipient.media_held, "signed provenance alone granted media");
            assert!(
                recipient.answer(now_unix_timestamp()).is_err(),
                "answer bypassed correlated Ringing authority"
            );
            assert_eq!(
                recipient.row.state, "incoming_ringing",
                "refusal mutated the incoming state"
            );
            assert!(recipient.allocation.is_none(), "held call acquired relay credentials");
            assert!(
                !recipient.pending.iter().any(|c| matches!(c.body, CallAction::Answer { .. })),
                "refused answer queued a control"
            );
            Ok(())
        }),
    )
    .await
    .map_err(|_| invalid("test: routed call admission timed out"))?
}

#[tokio::test]
async fn an_established_pair_cannot_create_an_unrelated_call_conversation() -> Result<(), SdkError>
{
    crate::client::native_test_support::watchdog::within(
        an_established_pair_cannot_create_an_unrelated_call_conversation_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn an_established_pair_cannot_create_an_unrelated_call_conversation_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 21).await?;
    let mut bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let first = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        first.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let packet = entry(&alice, &bob, &invite, "first-call", &conversation)?;
    apply(&mut bob, &packet).await?;
    let injected = control(&alice, &bob, 2, "unrelated-thread")?;
    let invite = signed(
        &alice,
        injected.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let packet = entry(&alice, &bob, &invite, "injected-call", "unrelated-thread")?;
    assert!(apply(&mut bob, &packet).await.is_err());
    assert!(bob.client.account_db()?.client_record("conversation", "unrelated-thread")?.is_none());
    assert!(!bob.client.voice_calls.contains_key(&invite.call_id));
    Ok(())
}
#[tokio::test]
async fn retiring_a_call_removes_control_receipts_without_reviving_keys_on_redelivery()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        retiring_a_call_removes_control_receipts_without_reviving_keys_on_redelivery_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn retiring_a_call_removes_control_receipts_without_reviving_keys_on_redelivery_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 21).await?;
    let mut bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let first = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        first.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let packet = entry(&alice, &bob, &invite, "first-call", &conversation)?;
    apply(&mut bob, &packet).await?;
    let prefix = format!("voice/control/{}/", invite.call_id);
    assert_eq!(bob.client.account_db()?.actor_state_usage(&prefix)?.0, 1);
    bob.client.retire_call_without_keys(&invite.call_id)?;
    bob.client.voice_calls.clear();
    assert_eq!(bob.client.account_db()?.actor_state_usage(&prefix)?.0, 0);
    let retry = packet.clone();
    apply(&mut bob, &retry).await?;
    assert!(bob.client.voice_calls.is_empty());
    assert_eq!(bob.client.account_db()?.actor_state_usage(&prefix)?.0, 0);
    Ok(())
}
#[tokio::test]
async fn committed_call_controls_retain_neither_ciphertext_nor_consumed_pair_message_keys()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        committed_call_controls_retain_neither_ciphertext_nor_consumed_pair_message_keys_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn committed_call_controls_retain_neither_ciphertext_nor_consumed_pair_message_keys_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 21).await?;
    let mut bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let first = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        first.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let packet = entry(&alice, &bob, &invite, "first-call", &conversation)?;
    apply(&mut bob, &packet).await?;
    let envelope = decode(&packet.envelope)?;
    let pair = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&format!(
            "dm-pair/session/{}",
            envelope.ciphertext.session_id
        ))?
        .ok_or_else(|| invalid("pair"))?;
    let bundle: [u8; 32] = serde_json::from_value(pair["bundle"].clone())?;
    let mut restored = ramflux_crypto::DmSession::from_snapshot(serde_json::from_value(
        pair["snapshot"].clone(),
    )?)?;
    let aad = associated_data_from_outer(&packet.envelope, "alice", "bob", &bundle)?;
    assert!(restored.decrypt_with_franking_keys(&envelope.ciphertext, &aad).is_err());
    // Consumed ratchet keys are gone, but retained static X3DH private prekeys can reconstruct
    // a bootstrap packet. This is why even encrypted call controls must not remain in receipts.
    let header = envelope.x3dh.as_ref().ok_or_else(|| invalid("bootstrap"))?;
    let bootstrap_aad = associated_data(
        header.bootstrap_envelope_id.as_deref().unwrap_or(&packet.envelope.envelope_id),
        "alice",
        "bob",
        &bundle,
    )?;
    let mut reconstructed = bob.client.create_recv_dm_session_with_aad(header, &bootstrap_aad)?;
    let recovered = reconstructed.decrypt_with_franking_keys(&envelope.ciphertext, &aad)?;
    assert_ne!(recovered.plaintext.len(), 0);

    let receipt = bob
        .client
        .account_db()?
        .load_actor_state::<super::committed::Committed>(
            &bob.client.authenticated_committed_key(HeadUse::NewAuthorization, &packet)?,
        )?
        .ok_or_else(|| invalid("receipt"))?;
    assert_eq!(receipt.entry.envelope.encrypted_payload.len(), 0);
    let stored =
        bob.client.event_body(&packet.envelope.envelope_id)?.ok_or_else(|| invalid("event"))?;
    assert!(!String::from_utf8_lossy(&stored).contains(&packet.envelope.encrypted_payload));
    bob.client.retire_call_without_keys(&invite.call_id)?;
    bob.client.voice_calls.clear();
    apply(&mut bob, &packet).await?;
    assert!(bob.client.voice_calls.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_call_refuses_control_receipts_beyond_its_bounded_capacity() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        a_call_refuses_control_receipts_beyond_its_bounded_capacity_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn a_call_refuses_control_receipts_beyond_its_bounded_capacity_body() -> Result<(), SdkError>
{
    let alice = Fixture::native_named("alice", 21).await?;
    let mut bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let first = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        first.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let prefix = format!("voice/control/{}/", invite.call_id);
    for index in 0..128 {
        bob.client.account_db()?.persist_actor_state(&format!("{prefix}{index:03}"), &"receipt")?;
    }
    let packet = entry(&alice, &bob, &invite, "over-cap-call", &conversation)?;
    let Err(error) = apply(&mut bob, &packet).await else {
        return Err(invalid("receipt cap accepted control"));
    };
    assert!(matches!(error, SdkError::CallControlReceiptCapacity { limit: 128 }));
    assert_eq!(crate::bus::io::local_bus_error_code(&error), "CallControlReceiptCapacity");
    assert_eq!(bob.client.account_db()?.actor_state_usage(&prefix)?.0, 128);
    assert!(!bob.client.voice_calls.contains_key(&invite.call_id));
    Ok(())
}

#[tokio::test]
async fn new_call_failure_rows_drop_ciphertext_while_existing_rows_still_decode()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        new_call_failure_rows_drop_ciphertext_while_existing_rows_still_decode_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn new_call_failure_rows_drop_ciphertext_while_existing_rows_still_decode_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 21).await?;
    let bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let first = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        first.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let packet = entry(&alice, &bob, &invite, "retained-call", &conversation)?;
    assert!(bob.client.is_call_control_entry(&packet, "bob")?);

    let old_bytes = serde_json::to_vec(&packet)?;
    let now = now_unix_timestamp();
    assert_ne!(bob.client.account_db()?.defer_inbox_entry("old-call-row", &old_bytes, now)?, 0);
    let old: GatewayInboxEntry = serde_json::from_slice(
        bob.client
            .account_db()?
            .due_inbox_retries(now.saturating_add(2))?
            .first()
            .ok_or_else(|| invalid("existing retry row missing"))?,
    )?;
    assert_eq!(old, packet, "pre-upgrade stored rows retain their original representation");

    let retained = crate::bus::sync_driver::retained_inbox_entry(&packet, true);
    assert_eq!(retained.envelope.encrypted_payload, "");
    assert_eq!(retained.envelope.payload_hash, packet.envelope.payload_hash);
    assert_eq!(retained.envelope.envelope_id, packet.envelope.envelope_id);
    let decoded: GatewayInboxEntry = serde_json::from_slice(&serde_json::to_vec(&retained)?)?;
    assert_eq!(decoded, retained);
    assert_ne!(
        bob.client.account_db()?.defer_inbox_entry(
            "new-call-row",
            &serde_json::to_vec(&retained)?,
            now
        )?,
        0
    );
    let rows = bob.client.account_db()?.due_inbox_retries(now.saturating_add(2))?;
    let stored = rows
        .iter()
        .map(|row| serde_json::from_slice::<GatewayInboxEntry>(row))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|row| row.envelope.encrypted_payload.is_empty())
        .ok_or_else(|| invalid("new retry row missing"))?;
    assert_eq!(stored.envelope.encrypted_payload, "");
    Ok(())
}

#[tokio::test]
async fn stripped_call_ack_retry_uses_committed_receipt_before_payload_decode()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        stripped_call_ack_retry_uses_committed_receipt_before_payload_decode_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn stripped_call_ack_retry_uses_committed_receipt_before_payload_decode_body()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 21).await?;
    let mut bob = Fixture::native_named("bob", 31).await?;
    contacts(&alice, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let first = control(&alice, &bob, 1, &conversation)?;
    let invite = signed(
        &alice,
        first.pending.first().ok_or_else(|| invalid("test: pending call missing"))?.clone(),
    )?;
    let packet = entry(&alice, &bob, &invite, "call-ack-retry", &conversation)?;
    apply(&mut bob, &packet).await?;
    let envelope_id = packet.envelope.envelope_id.as_str();

    let key = bob.client.inbox_admission_key(&packet)?;
    let retained = crate::bus::sync_driver::retained_inbox_entry(&packet, true);
    assert_eq!(
        bob.client.retained_committed_receipt_key(&retained)?.as_deref(),
        Some(key.as_str())
    );
    assert_eq!(
        bob.client.committed_direct_context(&retained)?,
        None,
        "attachment prefetch must skip a stripped committed control without rechecking erased ciphertext"
    );
    let mut mismatched = retained.clone();
    mismatched.envelope.payload_hash.push('x');
    assert!(matches!(
        bob.client.retained_committed_receipt_key(&mismatched),
        Err(SdkError::InboundRejected(_))
    ));
    let mut node_metadata = retained.clone();
    node_metadata
        .envelope
        .ext
        .ext
        .insert("home_node_migration_forward_count".into(), serde_json::json!(1));
    bob.client.validate_routed_receipt_or_ciphertext(&node_metadata)?;
    let mut changed_header = retained.clone();
    changed_header.envelope.ttl = changed_header.envelope.ttl.saturating_add(1);
    assert!(bob.client.validate_routed_receipt_or_ciphertext(&changed_header).is_err());
    let mut changed_payload = packet.clone();
    changed_payload.envelope.encrypted_payload = ramflux_protocol::encode_base64url(b"changed");
    assert!(bob.client.validate_routed_receipt_or_ciphertext(&changed_payload).is_err());
    let now = now_unix_timestamp();
    assert_ne!(
        bob.client.account_db()?.defer_inbox_entry(
            &key,
            &serde_json::to_vec(&retained)?,
            now.saturating_sub(2),
        )?,
        0
    );
    let (engine, writes) =
        review::Inbox::engine_with_acknowledgements(bob.config()?, Vec::new(), 1)?;
    let root = bob.client.own_account_anchor()?;
    let mut account =
        crate::bus::state::LocalBusAccountState::new(std::mem::take(&mut bob.client), engine, root);
    crate::bus::sync_driver::run(&mut account).await?;

    assert!(
        writes
            .lock()
            .map_err(|_| invalid("mutex"))?
            .iter()
            .any(|v| v["frame_type"] == "ack"
                && v["ack"]["envelope_id"].as_str() == Some(envelope_id))
    );
    assert!(!account.client.account_db()?.has_inbox_retry(&key)?);
    let events = account.client.account_db()?.journal_after(0, 128)?;
    assert!(
        !events.iter().any(|event| {
            event.topic == "message.undeliverable"
                && event.body["envelope_id"].as_str() == Some(envelope_id)
        }),
        "{}",
        serde_json::to_string(&events)?
    );
    Ok(())
}
