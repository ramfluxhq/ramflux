// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::pairing::full_transfer::{DataPacket, SecretBase64};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn h(value: u8) -> String {
    crate::encode_base64url([value; 32])
}
fn destination() -> DeviceRef {
    DeviceRef { account_anchor: h(2), device_id: "destination".into(), device_epoch: 1 }
}
fn ready() -> FullControlPayload {
    FullControlPayload::TransferReadyFull {
        transfer_id: h(3),
        record_hash: h(4),
        compacted_ids_hash: None,
        preservation: Box::new(Envelope {
            body: PreservationFull {
                schema: "ramflux.identity.transfer.preserve.full.v1".into(),
                version: 1,
                transfer_id: h(3),
                transcript_hash: h(5),
                old_record_hash: h(6),
                new_record_hash: h(4),
                destination_ref: destination(),
                recipient_mode: "new".into(),
                policy: "preserve_all_existing".into(),
                expires_at: 1000,
                manifest_chain_hash: h(7),
                data_verified_hash: h(8),
                target_restrictions_root: h(9),
            },
            signature: crate::encode_base64url([10; 64]),
        }),
    }
}
#[test]
fn full_control_and_idle_are_closed_canonical_and_role_checked() -> TestResult {
    let packets = [
        DataPacket::Idle { last_verified: h(1) },
        DataPacket::Control {
            payload: FullControlPayload::CandidateReady {
                transfer_id: h(3),
                record_hash: h(4),
                compacted_ids_hash: None,
            },
        },
        DataPacket::Control { payload: ready() },
        DataPacket::Control {
            payload: FullControlPayload::Published {
                operation_id: h(11),
                record_hash: h(4),
                device_set_epoch: 4_294_967_297,
                recipient_ref: destination(),
            },
        },
        DataPacket::Control {
            payload: FullControlPayload::Installed {
                operation_id: h(11),
                record_hash: h(4),
                recipient_ref: destination(),
            },
        },
        DataPacket::Control {
            payload: FullControlPayload::Completed {
                operation_id: h(11),
                record_hash: h(4),
                cleanup: "pending".into(),
            },
        },
        DataPacket::Control { payload: FullControlPayload::Abort { reason: "HeadChanged".into() } },
    ];
    for packet in packets {
        let bytes = packet.encode_secret()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(bytes.as_slice(), crate::canonical_json_bytes(&value)?.as_slice());
        let decoded = DataPacket::from_wire_bytes(&bytes)?;
        assert_eq!(decoded.encode_secret()?.as_slice(), bytes.as_slice());
    }
    let candidate = FullControlPayload::CandidateReady {
        transfer_id: h(3),
        record_hash: h(4),
        compacted_ids_hash: None,
    };
    candidate.require_sender("responder")?;
    assert!(candidate.require_sender("initiator").is_err());
    ready().require_sender("initiator")?;
    assert!(ready().require_sender("responder").is_err());
    for bytes in [
        br#"{"kind":"idle","last_verified":null}"#.as_slice(),
        br#"{"kind":"control","payload":{"kind":"enrollment","proposal":{}}}"#.as_slice(),
        br#"{"kind":"control","payload":{"kind":"transfer_ready","transfer_id":"x"}}"#.as_slice(),
    ] {
        assert!(DataPacket::from_wire_bytes(bytes).is_err());
    }
    Ok(())
}
#[test]
fn full_control_candidate_keeps_annex_d_part_bound_without_growing_relay_controls() -> TestResult {
    let packet = DataPacket::Control {
        payload: FullControlPayload::ArtifactChunk {
            object_kind: "candidate".into(),
            object_id: h(12),
            index: 63,
            count: 64,
            total_bytes: 524_288,
            bytes: SecretBase64::from_bytes(&[17; 8192]),
        },
    };
    let bytes = packet.encode_secret()?;
    assert!(bytes.len() > 8192);
    assert!(bytes.len() <= CONTROL_PACKET_BYTES);
    let decoded = DataPacket::from_wire_bytes(&bytes)?;
    assert_eq!(decoded.encode_secret()?.as_slice(), bytes.as_slice());
    let DataPacket::Control { mut payload } = decoded else { return Err("control".into()) };
    if let FullControlPayload::ArtifactChunk { object_kind, .. } = &mut payload {
        *object_kind = "hpke".into();
    }
    assert!(
        payload.validate().is_err(),
        "full channel admitted obsolete transfer payload artifacts"
    );
    let mut oversized = bytes.to_vec();
    oversized.resize(CONTROL_PACKET_BYTES + 1, b' ');
    assert!(DataPacket::from_wire_bytes(&oversized).is_err());
    assert_eq!(
        <crate::custody::pairing::full_transfer::relay::HpkeConfirmFull as PairingWire>::LIMIT,
        8192
    );
    Ok(())
}

#[test]
fn full_control_rejects_foreign_native_context_and_phase() -> TestResult {
    let transfer = h(3);
    let candidate = h(4);
    let th = h(5);
    let base = h(6);
    let chain = h(7);
    let verified = h(8);
    let restrictions = h(9);
    let operation = h(11);
    let destination = destination();
    let mut context = FullControlContext {
        sender: "initiator",
        phase: "prepared",
        transfer_id: &transfer,
        operation_id: &operation,
        transcript_hash: &th,
        base_record_hash: &base,
        manifest_chain_hash: &chain,
        data_verified_hash: &verified,
        target_restrictions_root: &restrictions,
        recipient_mode: "new",
        destination_ref: &destination,
        candidate_hash: Some(&candidate),
        candidate_object_id: Some(&candidate),
        compacted_ids_hash: None,
        record_epoch: Some(7),
        lease_expires_at: 1000,
        now: 999,
    };
    ready().validate_context(&context)?;
    context.phase = "mutually_confirmed";
    assert!(ready().validate_context(&context).is_err());
    context.phase = "prepared";
    context.now = 1000;
    assert!(ready().validate_context(&context).is_err());
    context.now = 999;
    let foreign = h(77);
    context.transcript_hash = &foreign;
    assert!(ready().validate_context(&context).is_err());
    context.transcript_hash = &th;
    context.base_record_hash = &foreign;
    assert!(ready().validate_context(&context).is_err());
    context.base_record_hash = &base;
    context.manifest_chain_hash = &foreign;
    assert!(ready().validate_context(&context).is_err());
    context.manifest_chain_hash = &chain;
    context.data_verified_hash = &foreign;
    assert!(ready().validate_context(&context).is_err());
    context.data_verified_hash = &verified;
    context.target_restrictions_root = &foreign;
    assert!(ready().validate_context(&context).is_err());
    context.target_restrictions_root = &restrictions;
    context.recipient_mode = "existing";
    assert!(ready().validate_context(&context).is_err());
    context.recipient_mode = "new";
    context.candidate_hash = Some(&foreign);
    assert!(ready().validate_context(&context).is_err());
    context.candidate_hash = Some(&candidate);
    let published = FullControlPayload::Published {
        operation_id: operation.clone(),
        record_hash: candidate.clone(),
        device_set_epoch: 7,
        recipient_ref: destination.clone(),
    };
    context.phase = "acknowledged";
    published.validate_context(&context)?;
    context.record_epoch = Some(8);
    assert!(published.validate_context(&context).is_err());
    context.record_epoch = Some(7);
    context.operation_id = &foreign;
    assert!(published.validate_context(&context).is_err());
    Ok(())
}
