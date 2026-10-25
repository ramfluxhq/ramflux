// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! State, replay and device-selection regressions independent of transport timing.
use super::state::LiveCall;
use super::*;
use ramflux_protocol::{CallAction, VoiceAllocation};
fn endpoint(principal: &str, device: &str) -> CallEndpoint {
    CallEndpoint {
        principal_id: principal.into(),
        device_id: device.into(),
        root_public_key: format!("root-{principal}"),
    }
}
fn outgoing() -> Result<LiveCall, SdkError> {
    LiveCall::outgoing(
        ramflux_protocol::encode_base64url([7; 16]),
        "thread".into(),
        endpoint("alice", "a1"),
        vec![endpoint("bob", "b1"), endpoint("bob", "b2")],
        100,
    )
}
fn allocation() -> VoiceAllocation {
    VoiceAllocation {
        endpoint: "relay.example:17449".into(),
        caller_token: ramflux_protocol::encode_base64url([9; 32]),
        callee_token: ramflux_protocol::encode_base64url([10; 32]),
        expires_at: 200,
    }
}
#[test]
fn first_answer_wins_and_other_devices_do_not_share_the_winners_media_key() -> Result<(), SdkError>
{
    let mut origin = outgoing()?;
    let mut first = LiveCall::incoming(&origin.pending[0], endpoint("bob", "b1"), 100)?;
    let mut second = LiveCall::incoming(&origin.pending[1], endpoint("bob", "b2"), 100)?;
    assert_ne!(first.receive_key, second.receive_key);
    origin.pending.clear();
    first.pending.clear();
    second.pending.clear();
    first.answer(101)?;
    second.answer(101)?;
    let answer = first.pending.pop().ok_or_else(|| invalid("test answer missing"))?;
    assert!(origin.apply(&answer, 102)?);
    let alternative = second.pending.pop().ok_or_else(|| invalid("test answer missing"))?;
    assert!(!origin.apply(&alternative, 102)?);
    assert_eq!(origin.callee.device_id, "b1");
    assert_eq!(
        origin.send_key,
        first.receive_key.clone().ok_or_else(|| invalid("test key missing"))?
    );
    assert_eq!(origin.receive_key, Some(first.send_key.clone()));
    let loser = origin
        .pending
        .iter()
        .find(|c| c.callee.device_id == "b2")
        .ok_or_else(|| invalid("test loser missing"))?;
    second.apply(loser, 102)?;
    assert_eq!(second.row.end_reason.as_deref(), Some("answered_elsewhere"));
    origin.activate(allocation(), 103)?;
    assert_eq!(origin.row.state, "active");
    let ack = origin
        .pending
        .iter()
        .find(|c| matches!(c.body, CallAction::Ack { .. }))
        .ok_or_else(|| invalid("test ack missing"))?;
    first.apply(ack, 103)?;
    assert_eq!(first.row.state, "active");
    Ok(())
}
#[test]
fn replay_cross_call_and_uninvited_endpoint_cannot_mutate_call() -> Result<(), SdkError> {
    let mut origin = outgoing()?;
    let mut peer = LiveCall::incoming(&origin.pending[0], endpoint("bob", "b1"), 100)?;
    let ringing = peer.pending.pop().ok_or_else(|| invalid("test ringing missing"))?;
    origin.apply(&ringing, 100)?;
    assert!(origin.clone().apply(&ringing, 100).is_err());
    let before = origin.row.clone();
    for mode in 0..4 {
        let mut forged = ringing.clone();
        forged.seq += 1;
        match mode {
            0 => forged.call_id.push('x'),
            1 => forged.conversation_id.push('x'),
            2 => forged.sender.root_public_key.push('x'),
            _ => forged.callee.device_id.push('x'),
        }
        assert!(origin.clone().apply(&forged, 101).is_err());
    }
    assert_eq!(origin.row, before);
    Ok(())
}
#[test]
fn unanswered_call_expires_at_forty_five_seconds_and_wipes_media_keys() -> Result<(), SdkError> {
    let mut call = outgoing()?;
    assert!(!call.expire(144)?);
    assert!(call.expire(145)?);
    assert_eq!(call.row.end_reason.as_deref(), Some("timeout"));
    assert_eq!(call.send_key.as_ref(), &[0; 32]);
    assert!(call.receive_key.is_none());
    assert!(!call.expire(146)?);
    assert!(LiveCall::incoming(&outgoing()?.pending[0], endpoint("bob", "b1"), 146).is_err());
    Ok(())
}
#[test]
fn a_siblings_rejection_does_not_cancel_another_ringing_device() -> Result<(), SdkError> {
    let mut call = outgoing()?;
    let mut first = LiveCall::incoming(&call.pending[0], endpoint("bob", "b1"), 100)?;
    first.pending.clear();
    first.end(true, 101)?;
    call.apply(&first.pending[0], 101)?;
    assert_eq!(call.row.state, "outgoing_ringing");
    assert_eq!(call.invited.len(), 1);
    Ok(())
}

#[test]
fn a_future_dated_invite_cannot_extend_the_local_ring_timer() -> Result<(), SdkError> {
    let origin = outgoing()?;
    let mut invite = origin.pending[0].clone();
    invite.created_at = 130;
    let mut recipient = LiveCall::incoming(&invite, endpoint("bob", "b1"), 100)?;
    assert!(!recipient.expire(144)?);
    assert!(recipient.expire(145)?);
    assert_eq!(recipient.row.end_reason.as_deref(), Some("missed"));
    invite.created_at = 161;
    assert!(LiveCall::incoming(&invite, endpoint("bob", "b1"), 100).is_err());
    Ok(())
}
#[test]
fn a_late_answer_times_out_instead_of_selecting_a_key_or_claiming_another_winner()
-> Result<(), SdkError> {
    let mut origin = outgoing()?;
    let mut recipient = LiveCall::incoming(&origin.pending[0], endpoint("bob", "b1"), 100)?;
    recipient.pending.clear();
    recipient.answer(144)?;
    assert!(!origin.apply(&recipient.pending[0], 145)?);
    assert_eq!(origin.row.end_reason.as_deref(), Some("timeout"));
    assert!(origin.receive_key.is_none());
    assert!(!origin.pending.iter().any(|c| matches!(c.body, CallAction::AnsweredElsewhere)));
    Ok(())
}
#[test]
fn a_selected_device_cannot_replace_an_active_key_with_a_second_answer() -> Result<(), SdkError> {
    let mut origin = outgoing()?;
    let mut recipient = LiveCall::incoming(&origin.pending[0], endpoint("bob", "b1"), 100)?;
    recipient.pending.clear();
    recipient.answer(101)?;
    let mut answer = recipient.pending[0].clone();
    origin.apply(&answer, 101)?;
    origin.activate(allocation(), 102)?;
    answer.seq += 1;
    assert!(origin.apply(&answer, 103).is_err());
    assert_eq!(origin.row.state, "active");
    Ok(())
}
#[test]
fn a_busy_callee_sends_a_terminal_control_and_never_keeps_media_keys() -> Result<(), SdkError> {
    let origin = outgoing()?;
    let mut recipient = LiveCall::incoming(&origin.pending[0], endpoint("bob", "b1"), 100)?;
    recipient.busy(101)?;
    assert_eq!(recipient.row.end_reason.as_deref(), Some("busy"));
    assert_eq!(recipient.pending.len(), 1);
    assert!(matches!(recipient.pending[0].body, CallAction::Busy));
    assert!(recipient.receive_key.is_none());
    assert_eq!(recipient.send_key.as_ref(), &[0; 32]);
    Ok(())
}

#[test]
fn authenticated_lease_updates_preserve_active_state_until_the_new_expiry() -> Result<(), SdkError>
{
    let mut origin = outgoing()?;
    let mut recipient = LiveCall::incoming(&origin.pending[0], endpoint("bob", "b1"), 100)?;
    recipient.pending.clear();
    recipient.answer(101)?;
    origin.apply(&recipient.pending[0], 102)?;
    origin.activate(allocation(), 103)?;
    let ack = origin
        .pending
        .iter()
        .find(|c| matches!(c.body, CallAction::Ack { .. }))
        .cloned()
        .ok_or_else(|| invalid("ack missing"))?;
    recipient.apply(&ack, 103)?;
    let version = recipient.row.seq;
    let mut renewed = allocation();
    renewed.expires_at = 220;
    let renewal =
        origin.control(CallAction::Ack { allocation: Box::new(renewed.for_callee()) }, 110)?;
    recipient.apply(&renewal, 110)?;
    assert_eq!(recipient.row.seq, version);
    assert_eq!(recipient.row.state, "active");
    assert!(!recipient.expire_media(200)?);
    assert!(recipient.expire_media(220)?);
    assert_eq!(recipient.row.end_reason.as_deref(), Some("failed"));
    assert!(recipient.receive_key.is_none());
    Ok(())
}
#[test]
fn a_device_key_change_requires_a_new_call_with_fresh_media_secrets() -> Result<(), SdkError> {
    let mut origin = outgoing()?;
    let device = endpoint("bob", "b1");
    let first = ramflux_crypto::public_key_base64url_from_seed([3; 32]);
    let replacement = ramflux_crypto::public_key_base64url_from_seed([4; 32]);
    origin.pin_peer(device.clone(), first.clone())?;
    assert!(origin.pin_peer(device.clone(), replacement.clone()).is_err());
    assert!(origin.peer_key_matches(&device, &first));
    assert!(!origin.peer_key_matches(&device, &replacement));
    let mut fresh = outgoing()?;
    fresh.pin_peer(device, replacement)?;
    if fresh.send_key == origin.send_key {
        return Err(invalid("fresh call reused a media secret"));
    }
    Ok(())
}
#[test]
fn terminal_calls_discard_unsent_invites_and_their_media_secrets() -> Result<(), SdkError> {
    let mut origin = outgoing()?;
    assert_eq!(origin.pending.len(), 2);
    origin.finish("failed", 101)?;
    assert_eq!(origin.pending.len(), 0);
    assert_eq!(origin.send_key.as_ref(), &[0; 32]);
    assert!(origin.receive_key.is_none());
    Ok(())
}

#[test]
fn a_callee_ack_contains_only_the_callees_own_relay_credential() -> Result<(), SdkError> {
    let mut origin = outgoing()?;
    let invite = origin.pending[0].clone();
    let mut receiver = LiveCall::incoming(&invite, origin.callee.clone(), 100)?;
    receiver.pending.clear();
    receiver.answer(101)?;
    origin.apply(&receiver.pending[0], 101)?;
    let lease = allocation();
    origin.activate(lease.clone(), 102)?;
    let ack = origin.pending.last().ok_or_else(|| invalid("ack"))?;
    let encoded = serde_json::to_value(ack)?;
    assert!(encoded["body"]["allocation"].get("caller_token").is_none());
    assert!(!serde_json::to_string(ack)?.contains(&lease.caller_token));
    receiver.apply(ack, 102)?;
    let media_lease = receiver.allocation.as_ref().ok_or_else(|| invalid("allocation"))?;
    assert_eq!(media_lease.callee_token, lease.callee_token);
    assert_eq!(media_lease.caller_token.len(), 0);
    Ok(())
}
