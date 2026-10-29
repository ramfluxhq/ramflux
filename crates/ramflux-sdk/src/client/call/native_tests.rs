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
        recipient_principal_commitment: None,
        target_delivery_id: "native-call-target".into(),
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
async fn native_call_invite_answer_and_replay_use_real_master_and_anchor() -> TestResult {
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
    call.answer(crate::time::now_unix_timestamp())?;
    let answer = call.pending[0].clone();
    let (entry, body) = signed_control(&bob, &answer)?;
    assert!(alice.client.project_call_control(&entry, "native-call-thread", None, &body)?);
    assert!(alice.client.refresh_call_control(&body)?);
    assert_eq!(alice.client.voice_calls[&id].callee, peer);
    let mut forged = invite;
    forged.sender.root_public_key = peer.root_public_key;
    let (entry, body) = signed_control(&alice, &forged)?;
    assert!(bob.client.project_call_control(&entry, "native-call-thread", None, &body).is_err());
    assert!(alice.client.identity_root.is_none());
    assert!(bob.client.identity_root.is_none());
    Ok(())
}
