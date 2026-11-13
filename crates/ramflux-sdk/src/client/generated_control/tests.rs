// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::message::registry::CONTROLS;
use ramflux_protocol::message::{
    A2iControlEvent, ContactControl, Control, ControlDomain, ControlDomainA2ui,
    ControlDomainConversation, ControlDomainMcpTool, ControlDomainMessage, ControlOperation,
    FriendControl, FriendLinkRecord, GroupControlBody, GroupControlBodyDeviceSet,
    GroupControlBodyRequest, GroupControlBodyResult, GroupControlBodyTransfer, GroupKeyControl,
    GroupKeyDistribution, GroupStateControl, GuardianInvite, HistoryItem, HistoryPage,
    HomeMigrationControl, LivePresence, LocalBusFederationRoute, NativeContactConsent,
    NativeDeviceManifest, NativeGroupActor, NativeGroupChangeRequest, NativeGroupChangeResult,
    NativeGroupSnapshot, NativeHomeAuthorization, ObjectRevokeAccess, OwnContactSync,
    OwnContactTombstone, OwnGroupConsent, OwnMessageCopy, OwnSentMessage, PairReset, PairResetAck,
    QualifiedDevice, RecoveryControl, TransferBody, TransferBodyHead, TransferBodyProbe,
    TransferControl, TransferHead, TransferProbe, content, control, control_domain,
    group_control_body, own_message_copy, recovery_control, transfer_body,
};
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn author() -> QualifiedDevice {
    QualifiedDevice { account_anchor: "anchor".into(), device_id: "device".into(), device_epoch: 1 }
}

fn sibling() -> QualifiedDevice {
    QualifiedDevice {
        account_anchor: "anchor".into(),
        device_id: "sibling".into(),
        device_epoch: 1,
    }
}

fn stream() -> GeneratedEventStream {
    GeneratedEventStream::new("c1", author())
}

fn canonical(label: &str) -> Vec<u8> {
    label.as_bytes().to_vec()
}

fn route() -> LocalBusFederationRoute {
    LocalBusFederationRoute {
        federation_url: "https://fed.example".into(),
        source_node_id: "n1".into(),
        target_node_id: "n2".into(),
        required_capability: "group".into(),
        ..Default::default()
    }
}

fn a2i(domain: control_domain::Value) -> A2iControlEvent {
    A2iControlEvent {
        control_domain: Some(ControlDomain { value: Some(domain) }),
        ..Default::default()
    }
}

fn object_revoke() -> ObjectRevokeAccess {
    ObjectRevokeAccess {
        object_id: "obj".into(),
        recipient_principal_id: "peer".into(),
        link_id: "link".into(),
        reason: "revoke".into(),
        effective_at: 9,
    }
}

fn group_state(value: group_control_body::Value) -> Result<Control, SdkError> {
    control_from_payload(control::Payload::GroupState(GroupStateControl {
        schema: "group.state.v1".into(),
        body: Some(GroupControlBody { value: Some(value) }),
    }))
}

fn transfer(body: transfer_body::Value) -> Result<Control, SdkError> {
    group_state(group_control_body::Value::Transfer(GroupControlBodyTransfer {
        control: Some(TransferControl {
            body: Some(TransferBody { value: Some(body) }),
            signature: "sig".into(),
        }),
    }))
}

fn pair_reset() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::Reset(PairReset { rejected_bootstrap_floor: 3 }))
}

fn pair_reset_ack() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::ResetAck(PairResetAck { rejected_bootstrap_floor: 0 }))
}

fn contact() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::ContactControl(ContactControl {
        consent: Some(NativeContactConsent { canonical: canonical("consent") }),
    }))
}

fn group_request() -> Result<Control, SdkError> {
    group_state(group_control_body::Value::Request(GroupControlBodyRequest {
        request: Some(NativeGroupChangeRequest { canonical: canonical("req") }),
        federation: Some(route()),
    }))
}

fn own_history() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::OwnHistory(HistoryPage {
        transfer_id: canonical("xfer"),
        page: 1,
        ..Default::default()
    }))
}

fn home_migration() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::HomeMigration(HomeMigrationControl {
        proposal: Some(NativeHomeAuthorization { canonical: canonical("home") }),
    }))
}

fn live_presence() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::LivePresence(LivePresence {
        epoch: 4,
        subjects: vec![author()],
    }))
}

fn a2i_message() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::A2i(a2i(control_domain::Value::Message(
        ControlDomainMessage {},
    ))))
}

fn samples() -> Result<Vec<Control>, SdkError> {
    Ok(vec![
        pair_reset()?,
        pair_reset_ack()?,
        contact()?,
        group_request()?,
        group_key()?,
        own_contact_sync()?,
        own_history()?,
        home_migration()?,
        recovery_invite()?,
        live_presence()?,
        a2i_message()?,
        control_from_payload(control::Payload::ObjectRevoke(object_revoke()))?,
        own_contact_tombstone()?,
        own_group_consent()?,
        own_message_copy_sent()?,
        friend()?,
    ])
}

fn group_key() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::GroupKeyControl(GroupKeyControl {
        schema: "group.key.v4".into(),
        version: 4,
        distribution: Some(GroupKeyDistribution {
            schema: "group.key.v4".into(),
            version: 4,
            group_id: "g1".into(),
            sender_id: "s1".into(),
            group_key_epoch: 9,
            sender_key_seed: canonical("seed"),
            ..Default::default()
        }),
        ..Default::default()
    }))
}

fn own_contact_sync() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::OwnContactSync(OwnContactSync {
        manifest: Some(NativeDeviceManifest {
            principal_id: "principal".into(),
            ..Default::default()
        }),
        link: Some(FriendLinkRecord {
            link_id: "link".into(),
            requester_id: "a".into(),
            target_id: "b".into(),
            state: "accepted".into(),
            ..Default::default()
        }),
    }))
}

fn recovery_invite() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::RecoveryControl(RecoveryControl {
        payload: Some(recovery_control::Payload::Invite(GuardianInvite {
            invite_id: "inv".into(),
            inviter_principal_id: "owner".into(),
            guardian_principal_id: "guard".into(),
            issued_at: 1,
            expires_at: 2,
            ..Default::default()
        })),
    }))
}

fn own_contact_tombstone() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::OwnContactTombstone(OwnContactTombstone {
        link: Some(FriendLinkRecord { link_id: "link".into(), ..Default::default() }),
        decided_at: Some(11),
    }))
}

fn own_group_consent() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::OwnGroupConsent(OwnGroupConsent {
        actor: Some(NativeGroupActor { canonical: canonical("actor") }),
        snapshot: Some(NativeGroupSnapshot { canonical: canonical("snap") }),
        accepted: true,
        issued_at: 1,
        expires_at: 2,
        signature: "sig".into(),
        ..Default::default()
    }))
}

fn own_message_copy_sent() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::OwnMessageCopy(OwnMessageCopy {
        source: Some(author()),
        target: Some(sibling()),
        created_at: 1,
        expires_at: 2,
        payload: Some(own_message_copy::Payload::Sent(OwnSentMessage {
            envelope_id: "env".into(),
            message_id: "msg".into(),
            sender_id: "sender".into(),
            original_recipients: vec!["peer".into()],
            ciphertext_digest: Some(vec![1; 32]),
            authored_at: Some(1),
            exact_inner: canonical("inner"),
            ..Default::default()
        })),
    }))
}

fn friend() -> Result<Control, SdkError> {
    control_from_payload(control::Payload::Friend(FriendControl {
        action: 1,
        link_id: "link".into(),
        requester: "a".into(),
        target: "b".into(),
        ..Default::default()
    }))
}

fn round_trip_all_operations() -> TestResult {
    assert_eq!(CONTROLS.len(), 16);
    let operations: BTreeSet<u32> = CONTROLS.iter().map(|binding| binding.operation).collect();
    let tags: BTreeSet<u32> = CONTROLS.iter().map(|binding| binding.tag).collect();
    assert_eq!(operations, (1..=16).collect());
    assert_eq!(tags, (16..=31).collect());
    let mut events = stream();
    let mut seen = BTreeSet::new();
    for (index, control) in samples()?.into_iter().enumerate() {
        let operation = u32::try_from(control.operation)?;
        assert!(seen.insert(operation), "duplicate operation {operation}");
        let expected = CONTROLS
            .iter()
            .find(|binding| binding.operation == operation)
            .ok_or("unmapped control")?;
        let payload = control.payload.as_ref().ok_or("missing payload")?;
        let (mapped_operation, mapped_tag) = payload_operation_and_tag(payload);
        assert_eq!(mapped_operation, expected.operation);
        assert_eq!(mapped_tag, expected.tag);
        RamfluxClient::validate_generated_control(&control)?;
        let event_id = format!("ctl-{index}").into_bytes();
        let encoded = RamfluxClient::encode_generated_control(
            &mut events,
            event_id.clone(),
            control.clone(),
        )?;
        let (identity, decoded) = RamfluxClient::decode_generated_inner(&encoded)?;
        g::identity::verify(&identity)?;
        assert_eq!(identity.id.len(), 32);
        assert_eq!(identity.device_sequence, u64::try_from(index)? + 1);
        assert_ne!(identity.id, event_id);
        let content::Value::Control(decoded_control) =
            decoded.value.ok_or("missing decoded control")?
        else {
            return Err("decoded kind is not Control".into());
        };
        assert_eq!(decoded_control.operation, control.operation);
        assert_eq!(
            payload_operation_and_tag(decoded_control.payload.as_ref().ok_or("decoded payload")?),
            (mapped_operation, mapped_tag)
        );
        RamfluxClient::validate_generated_control(&decoded_control)?;
    }
    assert_eq!(seen.len(), 16);
    Ok(())
}

fn wrong_typed_arm_fails() -> TestResult {
    let mut mismatched =
        control_from_payload(control::Payload::Reset(PairReset { rejected_bootstrap_floor: 1 }))?;
    mismatched.operation = ControlOperation::ControlPairResetAck as i32;
    let mut mismatch_stream = stream();
    let mismatch = RamfluxClient::encode_generated_control(
        &mut mismatch_stream,
        b"bad-arm".to_vec(),
        mismatched.clone(),
    );
    match mismatch {
        Err(error) => {
            assert!(
                error.to_string().contains("control operation/payload mismatch"),
                "wrong typed arm must fail the operation/payload assertion"
            );
        }
        Ok(_) => return Err("wrong typed arm must fail".into()),
    }
    assert!(RamfluxClient::validate_generated_control(&mismatched).is_err());
    Ok(())
}

fn a2i_domains_and_group_native() -> TestResult {
    for domain in [
        control_domain::Value::Message(ControlDomainMessage {}),
        control_domain::Value::Conversation(ControlDomainConversation {}),
        control_domain::Value::A2ui(ControlDomainA2ui {}),
        control_domain::Value::McpTool(ControlDomainMcpTool {}),
    ] {
        RamfluxClient::validate_generated_control(&control_from_payload(control::Payload::A2i(
            a2i(domain),
        ))?)?;
    }
    let missing_domain = control_from_payload(control::Payload::A2i(A2iControlEvent::default()))?;
    assert!(RamfluxClient::validate_generated_control(&missing_domain).is_err());

    RamfluxClient::validate_generated_control(&group_state(group_control_body::Value::Request(
        GroupControlBodyRequest {
            request: Some(NativeGroupChangeRequest { canonical: canonical("req") }),
            federation: Some(route()),
        },
    ))?)?;
    let no_route = group_state(group_control_body::Value::Request(GroupControlBodyRequest {
        request: Some(NativeGroupChangeRequest { canonical: canonical("req") }),
        federation: None,
    }))?;
    RamfluxClient::validate_generated_control(&no_route)?;
    let incomplete_route =
        group_state(group_control_body::Value::Request(GroupControlBodyRequest {
            request: Some(NativeGroupChangeRequest { canonical: canonical("req") }),
            federation: Some(LocalBusFederationRoute { federation_url: String::new(), ..route() }),
        }))?;
    assert!(RamfluxClient::validate_generated_control(&incomplete_route).is_err());
    RamfluxClient::validate_generated_control(&group_state(group_control_body::Value::Result(
        GroupControlBodyResult {
            result: Some(NativeGroupChangeResult { canonical: canonical("res") }),
        },
    ))?)?;
    RamfluxClient::validate_generated_control(&group_state(
        group_control_body::Value::DeviceSet(GroupControlBodyDeviceSet {
            group_id: "g1".into(),
            actor: Some(NativeGroupActor { canonical: canonical("actor") }),
            device_set_epoch: 7,
        }),
    )?)?;
    let no_epoch = group_state(group_control_body::Value::DeviceSet(GroupControlBodyDeviceSet {
        group_id: "g1".into(),
        device_set_epoch: 0,
        ..Default::default()
    }))?;
    assert!(RamfluxClient::validate_generated_control(&no_epoch).is_err());
    Ok(())
}

fn transfer_and_object_revoke_native() -> TestResult {
    RamfluxClient::validate_generated_control(&transfer(transfer_body::Value::Probe(
        TransferBodyProbe {
            probe: Some(TransferProbe {
                id: "probe-1".into(),
                issued_at: 1,
                expires_at: 2,
                ..Default::default()
            }),
        },
    ))?)?;
    RamfluxClient::validate_generated_control(&transfer(transfer_body::Value::Head(
        TransferBodyHead {
            reply: Some(TransferHead {
                proposal: "prop".into(),
                issued_at: 1,
                expires_at: 2,
                ..Default::default()
            }),
        },
    ))?)?;
    let no_transfer_body =
        group_state(group_control_body::Value::Transfer(GroupControlBodyTransfer {
            control: Some(TransferControl { body: None, signature: "sig".into() }),
        }))?;
    assert!(RamfluxClient::validate_generated_control(&no_transfer_body).is_err());

    let revoke = object_revoke();
    RamfluxClient::authorize_generated_object_revoke("owner", "owner", &revoke)?;
    assert!(RamfluxClient::authorize_generated_object_revoke("peer", "owner", &revoke).is_err());
    let mut empty_revoke = revoke.clone();
    empty_revoke.object_id.clear();
    assert!(
        RamfluxClient::authorize_generated_object_revoke("owner", "owner", &empty_revoke).is_err()
    );

    let copy_item = control_from_payload(control::Payload::OwnMessageCopy(OwnMessageCopy {
        source: Some(author()),
        target: Some(sibling()),
        created_at: 1,
        expires_at: 2,
        payload: Some(own_message_copy::Payload::Item(HistoryItem {
            exact_inner: canonical("nested"),
            ..Default::default()
        })),
    }))?;
    RamfluxClient::validate_generated_control(&copy_item)?;
    Ok(())
}

#[test]
fn every_control_operation_has_exactly_one_typed_payload() -> TestResult {
    round_trip_all_operations()?;
    wrong_typed_arm_fails()?;
    a2i_domains_and_group_native()?;
    transfer_and_object_revoke_native()?;
    Ok(())
}
