// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::message::{
    Call, CallAction, CallActionAck, CallActionAnswer, CallActionAnsweredElsewhere, CallActionBusy,
    CallActionFailed, CallActionHangup, CallActionInvite, CallActionReady, CallActionReject,
    CallActionRekey, CallActionRekeyAck, CallActionRinging, CallActionTimeout, CallControl,
    CallEndpoint, QualifiedDevice, VoiceAllocationRequest, VoiceLeaseConsent, VoicePeerAllocation,
    call_action, content,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn author() -> QualifiedDevice {
    QualifiedDevice { account_anchor: "anchor".into(), device_id: "device".into(), device_epoch: 1 }
}

fn stream() -> GeneratedEventStream {
    GeneratedEventStream::new("c1", author())
}

fn endpoint(id: &str) -> CallEndpoint {
    CallEndpoint {
        principal_id: id.into(),
        root_public_key: format!("{id}-key"),
        device_id: format!("{id}-dev"),
    }
}

fn lease() -> VoiceLeaseConsent {
    VoiceLeaseConsent {
        scope: Some(VoiceAllocationRequest {
            call_id: "call-1".into(),
            caller: Some(endpoint("alice")),
            callee: Some(endpoint("bob")),
        }),
        lease_id: "lease-1".into(),
        expires_at: 9,
        signature: "lease-sig".into(),
    }
}

fn control(action: call_action::Value) -> CallControl {
    CallControl {
        schema: "call.v1".into(),
        call_id: "call-1".into(),
        conversation_id: "c1".into(),
        caller: Some(endpoint("alice")),
        callee: Some(endpoint("bob")),
        sender: Some(endpoint("alice")),
        seq: 1,
        created_at: 1,
        body: Some(CallAction { value: Some(action) }),
        signature: "sig-alice".into(),
        call_ref: None,
        call_start: None,
    }
}

fn call(action: call_action::Value) -> Call {
    Call { control: Some(control(action)) }
}

fn round_trip(action: call_action::Value, event_id: &[u8]) -> TestResult {
    let call = call(action);
    RamfluxClient::validate_generated_call(&call)?;
    let native = super::native::to_native(call.clone())?;
    assert_eq!(super::native::from_native(&native)?, call);
    let encoded =
        RamfluxClient::encode_generated_call(&mut stream(), event_id.to_vec(), call.clone())?;
    let (_, decoded) = RamfluxClient::decode_generated_inner(&encoded)?;
    assert!(matches!(decoded.value, Some(content::Value::Call(_))));
    Ok(())
}

#[test]
fn all_thirteen_call_actions_and_native_lease_fields_round_trip() -> TestResult {
    let actions = vec![
        call_action::Value::Invite(CallActionInvite { base_key: "k0".into() }),
        call_action::Value::Ringing(CallActionRinging {}),
        call_action::Value::Answer(CallActionAnswer { base_key: "k1".into() }),
        call_action::Value::Ack(CallActionAck {
            allocation: Some(VoicePeerAllocation {
                lease_id: "lease-1".into(),
                endpoint: "ep".into(),
                expires_at: 9,
                hard_expires_at: 10,
            }),
        }),
        call_action::Value::Ready(CallActionReady { consent: Some(lease()) }),
        call_action::Value::Reject(CallActionReject {}),
        call_action::Value::Busy(CallActionBusy {}),
        call_action::Value::Hangup(CallActionHangup {}),
        call_action::Value::Timeout(CallActionTimeout {}),
        call_action::Value::Failed(CallActionFailed {}),
        call_action::Value::AnsweredElsewhere(CallActionAnsweredElsewhere {}),
        call_action::Value::Rekey(CallActionRekey { generation: 2, base_key: "k2".into() }),
        call_action::Value::RekeyAck(CallActionRekeyAck { generation: 2, base_key: "k2".into() }),
    ];
    assert_eq!(actions.len(), 13);
    for (index, action) in actions.into_iter().enumerate() {
        round_trip(action, format!("call-{index}").as_bytes())?;
    }
    RamfluxClient::validate_generated_voice_lease(&lease(), "call-1")?;
    assert!(RamfluxClient::validate_generated_voice_lease(&lease(), "other").is_err());

    let signed = control(call_action::Value::Invite(CallActionInvite { base_key: "k0".into() }));
    RamfluxClient::authorize_generated_call_action_signer("alice", &signed)?;
    let mut forged = signed.clone();
    forged.signature.clear();
    assert!(RamfluxClient::authorize_generated_call_action_signer("alice", &forged).is_err());
    assert!(RamfluxClient::validate_generated_call(&Call { control: Some(forged) }).is_err());
    assert!(RamfluxClient::authorize_generated_call_action_signer("mallory", &signed).is_err());
    Ok(())
}
