// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    tests::{TestResult, body_variants, event},
    *,
};

fn client() -> RamfluxClient {
    let mut client = RamfluxClient::new();
    client.create_identity_root("human", [22; 32]);
    client.create_device_branch("human", "device", 1, [23; 32]);
    client
}

pub(super) fn fixture(
    client: &RamfluxClient,
) -> Result<g::TaskHistoryExport, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    for (index, body) in body_variants().into_iter().enumerate() {
        let bytes = client.encode_generated_task_carrier(event(body)?, format!("event-{index}"))?;
        let carrier = client.decode_generated_task_carrier(&bytes)?;
        let decision_certificate = if index == 6 {
            let (_, mut certificate) = super::certificate_tests::fixture(client, true)?;
            certificate.carrier_hash = Some(super::carrier::carrier_hash(&carrier));
            Some(g::TaskCertificate::decode(
                client.encode_generated_task_certificate(&certificate)?.as_slice(),
            )?)
        } else {
            None
        };
        events.push(g::TaskAcceptedEvent {
            carrier: Some(carrier),
            public_key: client.task_signer_key("human", "device")?,
            actor_kind_verified: index % 2 == 0,
            received_at: -17,
            decision_certificate,
            membership: Some(g::TaskMembership {
                conversation: "thread".into(),
                group: None,
                epoch: None,
                at: -17,
                members: vec!["human".into(), "agent".into()],
            }),
        });
    }
    Ok(g::TaskHistoryExport {
        packets: vec![g::TaskOwnPacket {
            context: Some(g::OwnContext {
                conversation_id: "thread".into(),
                participants: vec!["human".into(), "agent".into()],
                group: None,
                friend: Some(g::FriendLinkRecord {
                    link_id: "link".into(),
                    requester_id: "human".into(),
                    target_id: "agent".into(),
                    state: "accepted".into(),
                    remove_scope: Some(String::new()),
                    blocked: false,
                    capability_revoked_at: Some(-2),
                }),
            }),
            history: Some(g::TaskHistory { events, created_at: -29, updated_at: 83 }),
            manifests: vec![],
            pins: vec![],
            base: 0,
            prefix_hash: super::history::prefix_hash(&[])?,
        }],
        metadata: Some(g::TaskExportMetadata {
            truncated: true,
            skipped_items: 3,
            next_cursor: Some("task/history/cursor".into()),
        }),
    })
}

fn group_fixture(
    client: &RamfluxClient,
) -> Result<g::TaskHistoryExport, Box<dyn std::error::Error>> {
    let mut group_history = fixture(client)?;
    let root = client.identity_root.as_ref().ok_or("root")?;
    let branch = client.device_branch.as_ref().ok_or("device")?;
    let actor = ramflux_crypto::certify_group_state_actor(root, branch, "delivery")?;
    let snapshot = ramflux_crypto::create_group_state(
        root,
        branch,
        &actor,
        ramflux_crypto::GroupStateCreateInput {
            group_id: "group",
            conversation_id: "thread",
            max_members: 40,
            new_member_history: "all_history",
            name: Some("group".into()),
            now: 19,
        },
    )?;
    let packet = group_history.packets.first_mut().ok_or("packet")?;
    packet.context.as_mut().ok_or("context")?.group = Some(g::SdkOwnDeviceGroupSnapshot {
        group_id: "group".into(),
        group_epoch: 1,
        max_members: 40,
        new_member_history: "all_history".into(),
        local_role: "member".into(),
        local_joined_epoch: 1,
        members: vec![g::SdkOwnDeviceGroupMemberSnapshot {
            member_id: "human".into(),
            role: "member".into(),
            joined_epoch: 1,
        }],
        routes: vec![g::LocalBusGroupMemberRoute {
            member_id: "device".into(),
            member_principal_commitment: Some("root".into()),
            device_signing_public_key: Some(client.task_signer_key("human", "device")?),
            target_delivery_id: Some("delivery".into()),
            federation: None,
        }],
        shared_state: Some(g::NativeGroupSnapshot {
            canonical: ramflux_protocol::canonical_json_bytes(snapshot.snapshot())?,
        }),
    });
    packet.pins = vec![g::SdkOwnDeviceGroupMemberPin {
        group_id: "group".into(),
        device_id: "device".into(),
        signing_public_key: client.task_signer_key("human", "device")?,
        principal_id: Some("human".into()),
        principal_commitment: None,
    }];
    for event in &mut packet.history.as_mut().ok_or("history")?.events {
        let witness = event.membership.as_mut().ok_or("witness")?;
        witness.group = Some("group".into());
        witness.epoch = Some(1);
    }
    Ok(group_history)
}

fn wire(history: g::TaskHistoryExport) -> Vec<u8> {
    g::Task { payload: Some(g::task::Payload::OwnHistory(history)) }.encode_to_vec()
}

fn native_fields(history: &g::TaskHistoryExport) -> TestResult {
    let metadata = history.metadata.as_ref().ok_or("metadata")?;
    let native = super::super::own_history::TaskExportMetadata::from(metadata);
    assert_eq!(g::TaskExportMetadata::from(&native), *metadata);
    for packet in &history.packets {
        let context = packet.context.as_ref().ok_or("context")?;
        let native = crate::client::surface::OwnContext::try_from(context)?;
        assert_eq!(g::OwnContext::try_from(&native)?, *context);
        for pin in &packet.pins {
            let native = crate::own_device_sync::SdkOwnDeviceGroupMemberPin::from(pin);
            assert_eq!(g::SdkOwnDeviceGroupMemberPin::from(&native), *pin);
        }
        for event in &packet.history.as_ref().ok_or("history")?.events {
            if let Some(witness) = &event.membership {
                let native = super::super::historical::Membership::try_from(witness)?;
                assert_eq!(g::TaskMembership::try_from(&native)?, *witness);
            }
        }
    }
    Ok(())
}
fn exact(result: Result<g::TaskHistoryExport, SdkError>, expected: &str) {
    let error = result.err();
    assert!(
        matches!(&error, Some(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, message }) if message == expected),
        "{error:?}"
    );
}

#[test]
fn every_task_event_approval_control_and_history_round_trips() -> TestResult {
    // The leaf scenarios own all native event/grant/control/signing fields;
    // this completes T17 with witnessed history, paging and export metadata.
    super::tests::all_seven_generated_task_events_preserve_native_signing_bytes()?;
    super::control_tests::generated_approval_round_trip_requires_the_native_grant_signature()?;
    super::control_tests::generated_intent_and_ack_round_trip_all_fields_and_bind_typed_signatures(
    )?;
    super::control_tests::generated_ack_native_manifest_fields_and_documents_preserve_verified_authority()?;
    super::manifest_tests::generated_task_native_custody_manifest_round_trips_without_installing_keys()?;
    let client = client();
    let original = fixture(&client)?;
    native_fields(&original)?;
    let bytes = client.encode_generated_task_history_export(&original)?;
    let decoded = client.decode_generated_task_history_export(&bytes)?;
    assert_eq!(decoded, original);
    assert_eq!(client.encode_generated_task_history_export(&decoded)?, bytes);
    let packet = original.packets.first().ok_or("packet")?;
    client.check_generated_task_history_page(
        packet,
        packet.context.as_ref().ok_or("context")?,
        &[],
    )?;
    let first = packet
        .history
        .as_ref()
        .ok_or("history")?
        .events
        .first()
        .ok_or("event")?
        .carrier
        .clone()
        .ok_or("carrier")?;
    let mut page = packet.clone();
    page.base = 1;
    page.prefix_hash = super::history::prefix_hash(std::slice::from_ref(&first))?;
    page.history.as_mut().ok_or("history")?.events.remove(0);
    client.check_generated_task_history_page(
        &page,
        page.context.as_ref().ok_or("context")?,
        &[first],
    )?;
    assert!(matches!(
        client.check_generated_task_history_page(
            &page,
            page.context.as_ref().ok_or("context")?,
            &[]
        ),
        Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. })
    ));
    let group_history = group_fixture(&client)?;
    native_fields(&group_history)?;
    assert_eq!(
        client.decode_generated_task_history_export(
            &client.encode_generated_task_history_export(&group_history)?
        )?,
        group_history
    );
    Ok(())
}

#[test]
fn generated_history_received_fields_and_cross_bindings_reject_exactly() -> TestResult {
    let client = client();
    let original = fixture(&client)?;
    for field in 0..18 {
        let mut changed = original.clone();
        let packet = changed.packets.first_mut().ok_or("packet")?;
        let expected = match field {
            0 => {
                packet.context = None;
                "task history context missing"
            }
            1 => {
                packet.history = None;
                "task history events missing"
            }
            2 => {
                packet.base = 290;
                "task history context or count mismatch"
            }
            3 => {
                packet.prefix_hash = "wrong".into();
                "task history empty prefix mismatch"
            }
            4 => {
                packet.manifests = vec![g::NativeDeviceManifest::default(); 65];
                "task history context or count mismatch"
            }
            5 => {
                packet.history.as_mut().ok_or("history")?.events.clear();
                "task history context or count mismatch"
            }
            6 => {
                packet.history.as_mut().ok_or("history")?.events =
                    vec![g::TaskAcceptedEvent::default(); 290];
                "task history context or count mismatch"
            }
            7 => {
                packet.history.as_mut().ok_or("history")?.events[0].carrier = None;
                "task history carrier missing"
            }
            8 => {
                packet.history.as_mut().ok_or("history")?.events[0].public_key = "wrong".into();
                "task history signer or context mismatch"
            }
            9 => {
                packet.context.as_mut().ok_or("context")?.conversation_id = "other".into();
                "task history signer or context mismatch"
            }
            10..=14 => {
                let witness = packet.history.as_mut().ok_or("history")?.events[0]
                    .membership
                    .as_mut()
                    .ok_or("witness")?;
                match field {
                    10 => witness.at += 1,
                    11 => witness.conversation = "other".into(),
                    12 => witness.epoch = Some(1),
                    13 => witness.group = Some("other".into()),
                    _ => witness.members.clear(),
                }
                "task history membership witness mismatch"
            }
            15 => {
                packet.history.as_mut().ok_or("history")?.events[6].decision_certificate = None;
                "task history resolution certificate missing"
            }
            16 => {
                packet.context.as_mut().ok_or("context")?.participants.clear();
                "task history direct participant mismatch"
            }
            _ => {
                packet.pins = vec![g::SdkOwnDeviceGroupMemberPin::default()];
                "task history pin group mismatch"
            }
        };
        exact(client.decode_generated_task_history_export(&wire(changed)), expected);
    }
    Ok(())
}

#[test]
fn generated_history_export_metadata_and_canonical_bounds_reject_exactly() -> TestResult {
    let client = client();
    let original = fixture(&client)?;
    for field in 0..4 {
        let mut changed = original.clone();
        let expected = match field {
            0 => {
                changed.metadata = None;
                "task history export metadata missing"
            }
            1 => {
                changed.metadata.as_mut().ok_or("metadata")?.truncated = false;
                "task history export truncation metadata mismatch"
            }
            2 => {
                changed.packets = vec![g::TaskOwnPacket::default(); 101];
                "task history export packet count exceeded"
            }
            _ => {
                changed.metadata.as_mut().ok_or("metadata")?.next_cursor = Some(String::new());
                "invalid task history identifier"
            }
        };
        exact(client.decode_generated_task_history_export(&wire(changed)), expected);
    }
    let bytes = wire(original);
    let mut duplicate = bytes.clone();
    duplicate.extend(&bytes);
    exact(
        client.decode_generated_task_history_export(&duplicate),
        "noncanonical generated task history",
    );
    exact(
        client.decode_generated_task_history_export(&vec![0; 4 * 1024 * 1024 + 1]),
        "task history export byte budget exceeded",
    );
    Ok(())
}

#[test]
fn generated_history_bounds_signatures_and_committed_page_bindings_are_exact() -> TestResult {
    let client = client();
    let original = fixture(&client)?;
    for field in 0..4 {
        for value in [String::new(), "x".repeat(257), "bad\nvalue".into()] {
            let scan_rejects = field == 1 && !value.is_empty();
            let mut changed = original.clone();
            let packet = changed.packets.first_mut().ok_or("packet")?;
            match field {
                0 => packet.prefix_hash = value,
                1 => packet.context.as_mut().ok_or("context")?.conversation_id = value,
                2 => packet.context.as_mut().ok_or("context")?.participants[0] = value,
                _ => {
                    packet.history.as_mut().ok_or("history")?.events[0]
                        .membership
                        .as_mut()
                        .ok_or("witness")?
                        .members[1] = value;
                }
            }
            exact(
                client.decode_generated_task_history_export(&wire(changed)),
                if scan_rejects {
                    "noncanonical generated task history"
                } else {
                    "invalid task history identifier"
                },
            );
        }
    }
    let mut changed = original.clone();
    changed.packets[0].base = 289;
    exact(
        client.decode_generated_task_history_export(&wire(changed)),
        "task history context or count mismatch",
    );
    for field in 0..2 {
        let mut changed = original.clone();
        let certificate = changed.packets[0].history.as_mut().ok_or("history")?.events[6]
            .decision_certificate
            .as_mut()
            .ok_or("certificate")?;
        if field == 0 {
            certificate.carrier_hash = Some("other".into());
        } else {
            certificate.phase = Some(g::TaskCertificatePhase {
                value: Some(g::task_certificate_phase::Value::Reserved(
                    g::TaskCertificatePhaseReserved {},
                )),
            });
            certificate.carrier_hash = None;
            certificate.committed_version = None;
        }
        *certificate = g::TaskCertificate::decode(
            client.encode_generated_task_certificate(certificate)?.as_slice(),
        )?;
        exact(
            client.decode_generated_task_history_export(&wire(changed)),
            "task history committed certificate mismatch",
        );
    }
    let mut changed = original.clone();
    changed.packets[0].history.as_mut().ok_or("history")?.events[0]
        .carrier
        .as_mut()
        .ok_or("carrier")?
        .signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(matches!(
        client.decode_generated_task_history_export(&wire(changed)),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))
    ));
    let packet = original.packets.first().ok_or("packet")?;
    let mut context = packet.context.clone().ok_or("context")?;
    context.participants.push("other".into());
    assert!(
        matches!(client.check_generated_task_history_page(packet, &context, &[]), Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, message }) if message == "task history page context or prefix mismatch")
    );
    let mut changed = original;
    changed.packets[0]
        .context
        .as_mut()
        .ok_or("context")?
        .participants
        .push("x".repeat(super::super::MAX_DELIVERY_BYTES));
    assert!(
        matches!(client.decode_generated_task_history_export(&wire(changed)), Err(SdkError::TaskDeliveryTooLarge { limit, .. }) if limit == super::super::MAX_DELIVERY_BYTES)
    );
    Ok(())
}

#[test]
fn generated_group_history_witness_epoch_and_pin_bindings_reject_exactly() -> TestResult {
    let client = client();
    let original = group_fixture(&client)?;
    for field in 0..7 {
        let mut changed = original.clone();
        let packet = changed.packets.first_mut().ok_or("packet")?;
        let expected = match field {
            0 => {
                packet.pins[0].group_id = "other".into();
                "task history pin group mismatch"
            }
            1 => {
                packet.pins[0].signing_public_key = "other".into();
                "task history pin key mismatch"
            }
            2 => {
                packet.pins[0].device_id.clear();
                "invalid task history identifier"
            }
            3 => {
                packet.history.as_mut().ok_or("history")?.events[0].membership = None;
                "task history group witness missing"
            }
            _ => {
                let witness = packet.history.as_mut().ok_or("history")?.events[0]
                    .membership
                    .as_mut()
                    .ok_or("witness")?;
                match field {
                    4 => witness.epoch = None,
                    5 => witness.epoch = Some(13),
                    _ => witness.group = Some("other".into()),
                }
                "task history membership witness mismatch"
            }
        };
        exact(client.decode_generated_task_history_export(&wire(changed)), expected);
    }
    Ok(())
}

#[test]
fn generated_history_native_group_documents_keep_canonical_signatures_and_bounds() -> TestResult {
    let client = client();
    let original = group_fixture(&client)?;
    for field in 0..3 {
        let mut changed = original.clone();
        let context = changed.packets[0].context.as_mut().ok_or("context")?;
        match field {
            0 => context.group.as_mut().ok_or("group")?.group_id = "other".into(),
            1 => context.group.as_mut().ok_or("group")?.group_epoch += 1,
            _ => context.conversation_id = "other".into(),
        }
        exact(
            client.decode_generated_task_history_export(&wire(changed)),
            "task history native group binding mismatch",
        );
    }
    let mut changed = original.clone();
    let document = changed.packets[0]
        .context
        .as_mut()
        .ok_or("context")?
        .group
        .as_mut()
        .ok_or("group")?
        .shared_state
        .as_mut()
        .ok_or("document")?;
    document.canonical.push(b' ');
    exact(
        client.decode_generated_task_history_export(&wire(changed)),
        "noncanonical task group snapshot",
    );
    let mut changed = original.clone();
    let document = changed.packets[0]
        .context
        .as_mut()
        .ok_or("context")?
        .group
        .as_mut()
        .ok_or("group")?
        .shared_state
        .as_mut()
        .ok_or("document")?;
    let mut snapshot =
        ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(&document.canonical)?;
    snapshot.signature = ramflux_protocol::encode_base64url([0; 64]);
    document.canonical = ramflux_protocol::canonical_json_bytes(&snapshot)?;
    assert!(matches!(
        client.decode_generated_task_history_export(&wire(changed)),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))
    ));
    let mut context = original.packets[0].context.clone().ok_or("context")?;
    context.group.as_mut().ok_or("group")?.shared_state.as_mut().ok_or("document")?.canonical =
        vec![0; ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES + 1];
    assert!(matches!(
        crate::client::surface::OwnContext::try_from(&context),
        Err(SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
            ramflux_protocol::group_state::GroupStateLimit::Bytes
        )))
    ));
    Ok(())
}

#[test]
fn generated_history_foreign_signed_task_and_cursor_constraints_reject_exactly() -> TestResult {
    let client = client();
    let original = fixture(&client)?;
    let mut changed = original.clone();
    let event = event(ramflux_protocol::TaskEventBody::Cancel(ramflux_protocol::TaskCancel {
        task_id: "other-task".into(),
        base_revision: 3,
    }))?;
    let bytes = client.encode_generated_task_carrier(event, "foreign".into())?;
    changed.packets[0].history.as_mut().ok_or("history")?.events[1].carrier =
        Some(client.decode_generated_task_carrier(&bytes)?);
    exact(
        client.decode_generated_task_history_export(&wire(changed)),
        "task history task binding mismatch",
    );
    for cursor in [String::new(), "x".repeat(257), "bad\nvalue".into()] {
        let mut changed = original.clone();
        changed.metadata.as_mut().ok_or("metadata")?.next_cursor = Some(cursor);
        exact(
            client.decode_generated_task_history_export(&wire(changed)),
            "invalid task history identifier",
        );
    }
    for field in 0..2 {
        let mut changed = original.clone();
        let metadata = changed.metadata.as_mut().ok_or("metadata")?;
        metadata.truncated = false;
        if field == 0 {
            metadata.skipped_items = 0;
        } else {
            metadata.next_cursor = None;
        }
        exact(
            client.decode_generated_task_history_export(&wire(changed)),
            "task history export truncation metadata mismatch",
        );
    }
    exact(
        client.decode_generated_task_history_export(&g::Task::default().encode_to_vec()),
        "noncanonical generated task history",
    );
    Ok(())
}
