// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native master provenance through the ordinary signed call-control state machine.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
fn signed_control(
    sender: &Fixture,
    control: &CallControl,
) -> TestResult<(GatewayInboxEntry, zeroize::Zeroizing<Vec<u8>>)> {
    let mut control = control.clone();
    let callee_root = crate::identity_root_public_key_commitment(&control.callee.root_public_key)?;
    let target = ramflux_protocol::qualified_device_id(&callee_root, &control.callee.device_id)?;
    if matches!(control.body, ramflux_protocol::CallAction::Invite { .. }) {
        let branch = sender.client.device_branch.as_ref().ok_or("test: sender branch missing")?;
        let created_at = u64::try_from(control.created_at)?;
        let body = ramflux_protocol::CallIntentV1 {
            version: 1,
            signing_key_id: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
            audience: ramflux_protocol::GATEWAY_CALL_INTENT_AUDIENCE.into(),
            sender_device: ramflux_protocol::qualified_device_id(
                &sender.manifest.principal_commitment,
                &control.caller.device_id,
            )?,
            sender_epoch: 1,
            target_device: target.clone(),
            target_epoch: 1,
            target_delivery_id: target.clone(),
            call_ref: ramflux_protocol::encode_base64url([43; 16]),
            source_event_id: "native-call-control".into(),
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
        control.call_ref = Some(body.call_ref.clone());
        control.call_start = Some(ramflux_protocol::SignedCallIntentV1 { body, signature });
    }
    control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &signing_bytes(&control)?,
        sender.client.device_branch.as_ref().ok_or("branch")?,
    );
    let body = bytes(&control)?;
    let message = crate::GatewayDirectMessage {
        conversation_id: control.conversation_id,
        message_id: "native-call-control".into(),
        envelope_id: "native-call-control".into(),
        source_principal_id: control.sender.principal_id,
        sender_id: control.sender.device_id,
        recipient_device_id: Some("primary".into()),
        recipient_principal_commitment: Some(callee_root),
        target_delivery_id: target,
        encrypted_body: body.to_vec(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 600,
    };
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: message.target_delivery_id.clone(),
            envelope: crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?,
        },
        body,
    ))
}
#[tokio::test]
async fn native_call_invite_and_replay_hold_media_with_real_master_and_anchor() -> TestResult {
    let mut alice = Fixture::new("native-call-alice").await?;
    let mut bob = Fixture::new("native-call-bob").await?;
    alice.client.persist_fetched_identity_directory(&bob.manifest)?;
    bob.client.persist_fetched_identity_directory(&alice.manifest)?;
    for fixture in [&alice, &bob] {
        fixture.client.establish_friend_link(
            "native-call-friend",
            &alice.manifest.principal_commitment,
            &bob.manifest.principal_commitment,
        )?;
        fixture.client.account_db()?.persist_client_record(
            "conversation",
            "native-call-thread",
            &json!({
                "kind":"direct", "group_id":null,
                "participants":[alice.manifest.principal_id,bob.manifest.principal_id],
            }),
        )?;
    }
    let local = alice.client.call_local_endpoint()?;
    let peer = bob.client.call_local_endpoint()?;
    assert_eq!(local.root_public_key, alice.client.own_master_public_key()?);
    assert_eq!(
        bob.client.call_device_identity(&local)?.root_commitment(),
        alice.manifest.principal_commitment
    );
    assert_eq!(
        crate::identity_root_public_key_commitment(&local.root_public_key)?,
        alice.manifest.principal_commitment
    );
    let id = ramflux_protocol::encode_base64url([38; 16]);
    let mut outgoing = LiveCall::outgoing(
        id.clone(),
        "native-call-thread".into(),
        local.clone(),
        vec![peer.clone()],
        crate::time::now_unix_timestamp(),
    )?;
    outgoing.pin_peer(peer.clone(), bob.manifest.devices[0].branch_public_key.clone())?;
    let invite = outgoing.pending[0].clone();
    alice.client.voice_calls.insert(id.clone(), outgoing);
    let (entry, body) = signed_control(&alice, &invite)?;
    assert!(bob.client.project_call_control(&entry, "native-call-thread", None, &body)?);
    assert!(bob.client.refresh_call_control(&body)?);
    let before = bob.client.voice_calls[&id].row.clone();
    assert!(bob.client.project_call_control(&entry, "native-call-thread", None, &body)?);
    assert!(bob.client.refresh_call_control(&body)?);
    assert_eq!(bob.client.voice_calls[&id].row, before);
    let call = bob.client.voice_calls.get_mut(&id).ok_or("incoming")?;
    call.pending.clear();
    assert!(
        call.answer(crate::time::now_unix_timestamp()).is_err(),
        "answer requires a correlated Ringing resolution"
    );
    assert!(call.media_held, "native provenance alone released media");
    assert_eq!(alice.client.voice_calls[&id].callee, peer);
    let mut forged = invite;
    forged.sender.root_public_key = peer.root_public_key;
    let (entry, body) = signed_control(&alice, &forged)?;
    assert!(bob.client.project_call_control(&entry, "native-call-thread", None, &body).is_err());
    assert!(alice.client.identity_root.is_none());
    assert!(bob.client.identity_root.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_call_cache_uses_exact_inner_transition_after_native_commit() -> TestResult {
    let alice = Fixture::new("generated-cache-alice").await?;
    let mut bob = Fixture::new("generated-cache-bob").await?;
    alice.client.persist_fetched_identity_directory(&bob.manifest)?;
    bob.client.persist_fetched_identity_directory(&alice.manifest)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    for fixture in [&alice, &bob] {
        fixture.client.establish_friend_link(
            "native-cache-friend",
            &alice.client.own_account_anchor()?,
            &bob.client.own_account_anchor()?,
        )?;
        fixture.client.account_db()?.persist_client_record(
            "conversation",
            &conversation,
            &json!({
                "kind": "direct", "group_id": null,
                "participants": [alice.manifest.principal_id, bob.manifest.principal_id],
            }),
        )?;
    }
    let local = alice.client.call_local_endpoint()?;
    let peer = bob.client.call_local_endpoint()?;
    let id = ramflux_protocol::encode_base64url([39; 16]);
    let mut outgoing = LiveCall::outgoing(
        id.clone(),
        conversation.clone(),
        local,
        vec![peer.clone()],
        crate::time::now_unix_timestamp(),
    )?;
    outgoing.pin_peer(peer, bob.manifest.devices[0].branch_public_key.clone())?;
    let (entry, native_body) = signed_control(&alice, &outgoing.pending[0])?;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let signed = decode(&native_body)?.ok_or("signed call")?;
    let identity = alice.client.account_db()?.write_transaction(|| {
        alice.client.allocate_generated_identity(
            &conversation,
            crate::client::generated_identity::now_ms(),
            false,
        )
    })?;
    let raw = RamfluxClient::encode_generated_inner(
        identity,
        &ramflux_protocol::message::Content {
            value: Some(ramflux_protocol::message::content::Value::Call(
                crate::client::generated_call::native::from_native(&signed)?,
            )),
        },
    )?;
    let converted = decode(&raw)?.ok_or("test: generated call missing")?;
    assert!(converted == signed, "generated carrier must retain signed Start authority");
    bob.client.account_db()?.write_transaction(|| {
        bob.client.project_native_call_control(&entry, &conversation, None, &converted, &raw)
    })?;
    assert!(bob.client.refresh_generated_control_cache(&raw)?);
    assert!(
        bob.client.voice_calls.contains_key(&id),
        "generated cache lost the committed native call transition"
    );
    Ok(())
}
