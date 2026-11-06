// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    certificate_tests::fixture,
    tests::{TestResult, body_variants, event},
    *,
};

fn client() -> RamfluxClient {
    let mut client = RamfluxClient::new();
    client.create_identity_root("human", [22; 32]);
    client.create_device_branch("human", "device", 1, [23; 32]);
    client
}
fn resolution_carrier(
    client: &RamfluxClient,
) -> Result<g::TaskCarrier, Box<dyn std::error::Error>> {
    let event = event(body_variants().pop().ok_or("resolve")?)?;
    let bytes = client.encode_generated_task_carrier(event, "intent".into())?;
    Ok(client.decode_generated_task_carrier(&bytes)?)
}
fn ack(client: &RamfluxClient) -> Result<g::TaskAck, Box<dyn std::error::Error>> {
    let carrier = resolution_carrier(client)?;
    let (_, mut certificate) = fixture(client, true)?;
    certificate.carrier_hash = Some(super::carrier::carrier_hash(&carrier));
    let certificate = g::TaskCertificate::decode(
        client.encode_generated_task_certificate(&certificate)?.as_slice(),
    )?;
    Ok(g::TaskAck {
        carrier: Some(carrier),
        certificate: Some(certificate),
        manifests: vec![],
        signer_principal: "human".into(),
        signer_device: "device".into(),
        signature: String::new(),
    })
}
fn control(ack: g::TaskAck) -> g::TaskControl {
    g::TaskControl {
        value: Some(g::task_control::Value::Ack(g::TaskControlAck { value: Some(ack) })),
    }
}
fn invalid<T: std::fmt::Debug>(result: &Result<T, SdkError>) {
    assert!(
        matches!(
            result,
            Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. })
        ),
        "{result:?}"
    );
}
fn decode(client: &RamfluxClient, value: &g::TaskControl) -> Result<g::TaskControl, SdkError> {
    client.decode_generated_task_control(&value.encode_to_vec(), "thread", "human", "device")
}

#[test]
pub(super) fn generated_intent_and_ack_round_trip_all_fields_and_bind_typed_signatures()
-> TestResult {
    let client = client();
    let carrier = resolution_carrier(&client)?;
    let intent = g::TaskControl {
        value: Some(g::task_control::Value::Intent(g::TaskControlIntent {
            carrier: Some(carrier.clone()),
        })),
    };
    let bytes = client.encode_generated_task_control(intent.clone())?;
    assert_eq!(decode(&client, &intent)?, intent);
    assert_eq!(client.decode_generated_task_control(&bytes, "thread", "human", "device")?, intent);
    let bytes = client.encode_generated_task_control(control(ack(&client)?))?;
    let decoded = client.decode_generated_task_control(&bytes, "thread", "human", "device")?;
    let Some(g::task_control::Value::Ack(value)) = decoded.value.as_ref() else {
        return Err("ack".into());
    };
    let signed = value.value.as_ref().ok_or("ack")?;
    assert_eq!(signed.carrier.as_ref(), Some(&carrier));
    assert_eq!(
        signed.certificate.as_ref().ok_or("certificate")?.carrier_hash,
        Some(ramflux_protocol::hash_base64url(
            "ramflux.message.typed.TaskCarrier.v1",
            &carrier.encode_to_vec()
        ))
    );
    assert_eq!(client.encode_generated_task_control(decoded.clone())?, bytes);
    let mut unsigned = signed.clone();
    unsigned.signature.clear();
    let domain = b"ramflux.message.typed.TaskAck.v1";
    let body = unsigned.encode_to_vec();
    let mut transcript = u32::try_from(domain.len())?.to_be_bytes().to_vec();
    transcript.extend(domain);
    transcript.extend(u32::try_from(body.len())?.to_be_bytes());
    transcript.extend(body);
    ramflux_crypto::verify_canonical_signature(
        &transcript,
        &signed.signature,
        &client.task_signer_key("human", "device")?,
    )?;
    Ok(())
}

#[test]
fn generated_control_source_certificate_and_required_fields_have_exact_errors() -> TestResult {
    let client = client();
    let original = ack(&client)?;
    for field in 0..11 {
        let mut changed = original.clone();
        match field {
            0 => changed.carrier = None,
            1 => changed.certificate = None,
            2 => changed.signer_principal = "other".into(),
            3 => changed.signer_device = "other".into(),
            4 => changed.carrier.as_mut().ok_or("carrier")?.conversation_id = "other".into(),
            5 => changed.certificate.as_mut().ok_or("certificate")?.assignee = "other".into(),
            6 => changed.certificate.as_mut().ok_or("certificate")?.issuer_device = "other".into(),
            7 => {
                changed.certificate.as_mut().ok_or("certificate")?.carrier_hash =
                    Some("other".into());
            }
            8 => {
                changed.certificate.as_mut().ok_or("certificate")?.phase =
                    Some(serde_json::from_value(json!({"reserved":{}}))?);
            }
            9 => changed
                .certificate
                .as_mut()
                .ok_or("certificate")?
                .resolution
                .as_mut()
                .ok_or("resolution")?
                .decision_id
                .push('x'),
            _ => changed.manifests = vec![g::NativeDeviceManifest::default(); 2],
        }
        invalid(&decode(&client, &control(changed)));
    }
    for value in [
        g::TaskControl::default(),
        g::TaskControl { value: Some(g::task_control::Value::Ack(g::TaskControlAck::default())) },
        g::TaskControl {
            value: Some(g::task_control::Value::Intent(g::TaskControlIntent::default())),
        },
    ] {
        invalid(&decode(&client, &value));
    }
    let bytes = client.encode_generated_task_control(control(original.clone()))?;
    for (conversation, principal, device) in
        [("other", "human", "device"), ("thread", "other", "device"), ("thread", "human", "other")]
    {
        invalid(&client.decode_generated_task_control(&bytes, conversation, principal, device));
    }
    for field in 0..2 {
        let mut changed = original.clone();
        if field == 0 {
            changed.signer_principal = "other".into();
        } else {
            changed.signer_device = "other".into();
        }
        invalid(&client.encode_generated_task_control(control(changed)));
    }
    let carrier = resolution_carrier(&client)?;
    let intent = g::TaskControl {
        value: Some(g::task_control::Value::Intent(g::TaskControlIntent {
            carrier: Some(carrier),
        })),
    };
    for (conversation, principal, device) in
        [("other", "human", "device"), ("thread", "other", "device"), ("thread", "human", "other")]
    {
        invalid(&client.decode_generated_task_control(
            &intent.encode_to_vec(),
            conversation,
            principal,
            device,
        ));
    }
    let bytes =
        client.encode_generated_task_carrier(event(body_variants().remove(0))?, "start".into())?;
    let carrier = client.decode_generated_task_carrier(&bytes)?;
    invalid(&decode(
        &client,
        &g::TaskControl {
            value: Some(g::task_control::Value::Intent(g::TaskControlIntent {
                carrier: Some(carrier),
            })),
        },
    ));
    Ok(())
}

#[test]
fn generated_control_canonical_caps_and_each_nested_signature_reject_exactly() -> TestResult {
    let client = client();
    let bytes = client.encode_generated_task_control(control(ack(&client)?))?;
    let original = g::TaskControl::decode(bytes.as_slice())?;
    for field in 0..3 {
        let mut changed = original.clone();
        let Some(g::task_control::Value::Ack(value)) = changed.value.as_mut() else {
            return Err("ack".into());
        };
        let ack = value.value.as_mut().ok_or("ack")?;
        match field {
            0 => ack.signature = ramflux_protocol::encode_base64url([0; 64]),
            1 => {
                ack.certificate.as_mut().ok_or("certificate")?.signature =
                    ramflux_protocol::encode_base64url([0; 64]);
            }
            _ => {
                ack.carrier.as_mut().ok_or("carrier")?.signature =
                    ramflux_protocol::encode_base64url([0; 64]);
                let hash = super::carrier::carrier_hash(ack.carrier.as_ref().ok_or("carrier")?);
                let certificate = ack.certificate.as_mut().ok_or("certificate")?;
                certificate.carrier_hash = Some(hash);
                *certificate = g::TaskCertificate::decode(
                    client.encode_generated_task_certificate(certificate)?.as_slice(),
                )?;
            }
        }
        let result = decode(&client, &changed);
        assert!(
            matches!(result, Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))),
            "{result:?}"
        );
    }
    let mut duplicate = bytes.clone();
    duplicate.extend(&bytes);
    invalid(&client.decode_generated_task_control(&duplicate, "thread", "human", "device"));
    let mut nonminimal = bytes.clone();
    // Rewrite the first length varint without changing the nested bytes.
    let end = nonminimal
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, byte)| **byte < 128)
        .map(|(index, _)| index)
        .ok_or("length")?;
    nonminimal[end] |= 128;
    nonminimal.insert(end + 1, 0);
    invalid(&client.decode_generated_task_control(&nonminimal, "thread", "human", "device"));
    let over = vec![0xff; super::super::MAX_DELIVERY_BYTES + 1];
    assert!(
        matches!(client.decode_generated_task_control(&over, "thread", "human", "device"), Err(SdkError::TaskDeliveryTooLarge { bytes, limit }) if bytes == over.len() && limit == super::super::MAX_DELIVERY_BYTES)
    );
    Ok(())
}

#[test]
fn generated_carrier_identifier_bounds_and_certificate_bindings_have_exact_errors() -> TestResult {
    let client = client();
    let resolution = event(body_variants().pop().ok_or("resolve")?)?;
    let (_, certificate) = fixture(&client, false)?;
    let bytes = client.encode_generated_task_carrier_with_certificate(
        resolution.clone(),
        "intent".into(),
        Some(certificate.clone()),
    )?;
    let original = client.decode_generated_task_carrier(&bytes)?;
    assert_eq!(original.decision_proof, Some(certificate.clone()));
    for field in 0..3 {
        for invalid_value in [String::new(), "x".repeat(257), "bad\nidentifier".into()] {
            let mut changed = original.clone();
            match field {
                0 => changed.message_id = invalid_value,
                1 => changed.principal_id = invalid_value,
                _ => changed.device_id = invalid_value,
            }
            let bytes =
                g::Task { payload: Some(g::task::Payload::Carrier(changed)) }.encode_to_vec();
            invalid(&client.decode_generated_task_carrier(&bytes));
        }
    }
    client.encode_generated_task_carrier_with_certificate(
        resolution.clone(),
        "x".repeat(256),
        Some(certificate.clone()),
    )?;
    let mut mismatched = certificate.clone();
    mismatched.resolution.as_mut().ok_or("resolution")?.decision_id.push('x');
    let mismatched = g::TaskCertificate::decode(
        client.encode_generated_task_certificate(&mismatched)?.as_slice(),
    )?;
    invalid(&client.encode_generated_task_carrier_with_certificate(
        resolution.clone(),
        "intent".into(),
        Some(mismatched),
    ));
    invalid(&client.encode_generated_task_carrier_with_certificate(
        event(body_variants().remove(0))?,
        "start".into(),
        Some(certificate.clone()),
    ));
    let mut changed = original;
    let proof = changed.decision_proof.as_mut().ok_or("proof")?;
    proof.evidence_hash.push('x');
    *proof =
        g::TaskCertificate::decode(client.encode_generated_task_certificate(proof)?.as_slice())?;
    let changed_bytes =
        g::Task { payload: Some(g::task::Payload::Carrier(changed)) }.encode_to_vec();
    assert!(matches!(
        client.decode_generated_task_carrier(&changed_bytes),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))
    ));
    let mut corrupt = certificate;
    corrupt.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(matches!(
        client.encode_generated_task_carrier_with_certificate(
            resolution,
            "intent".into(),
            Some(corrupt)
        ),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))
    ));
    Ok(())
}

#[test]
pub(super) fn generated_ack_native_manifest_fields_and_documents_preserve_verified_authority()
-> TestResult {
    let directory = tempfile::tempdir()?;
    let mut client = client();
    client.open_account_index(directory.path())?;
    client.create_account("human", "human")?;
    client.unlock_account("human", b"generated-control-test")?;
    let native = crate::client::identity_authority::test_support::public_manifest(&client)?;
    let bytes = client.encode_generated_task_manifest(&native)?;
    assert_eq!(client.decode_generated_task_manifest(&bytes, "human")?, native);
    let generated = g::NativeDeviceManifest::decode(bytes.as_slice())?;
    let mut history = super::history_tests::fixture(&client)?;
    history.packets[0].manifests = vec![generated.clone()];
    assert_eq!(
        client.decode_generated_task_history_export(
            &client.encode_generated_task_history_export(&history)?
        )?,
        history
    );
    let mut original = ack(&client)?;
    original.manifests = vec![generated.clone()];
    let bytes = client.encode_generated_task_control(control(original))?;
    let decoded = client.decode_generated_task_control(&bytes, "thread", "human", "device")?;
    let Some(g::task_control::Value::Ack(value)) = decoded.value else { return Err("ack".into()) };
    let mut signed_ack = value.value.ok_or("ack")?;
    assert_eq!(signed_ack.manifests, vec![generated.clone()]);
    signed_ack.manifests.clear();
    assert!(matches!(
        decode(&client, &control(signed_ack)),
        Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))
    ));
    invalid(&client.decode_generated_task_manifest(&generated.encode_to_vec(), "other"));
    let mut wrong_root = generated.clone();
    wrong_root.principal_commitment = "other".into();
    assert!(matches!(client.decode_generated_task_manifest(&wrong_root.encode_to_vec(), "human"),
        Err(SdkError::InboundRejected(message)) if message == "identity authority: root commitment mismatch"));
    let mut foreign = ack(&client)?;
    let mut other = generated.clone();
    other.principal_id = "other".into();
    foreign.manifests = vec![other];
    invalid(&client.encode_generated_task_control(control(foreign)));
    let mut noncanonical = generated.clone();
    noncanonical.signed_device_set.as_mut().ok_or("set")?.canonical.push(b' ');
    invalid(&client.decode_generated_task_manifest(&noncanonical.encode_to_vec(), "human"));
    let mut missing = generated.clone();
    missing.devices.first_mut().ok_or("device")?.prekey_bundle = None;
    invalid(&client.decode_generated_task_manifest(&missing.encode_to_vec(), "human"));
    let mut tampered = native.clone();
    tampered.signed_device_set.as_mut().ok_or("set")?.signature =
        ramflux_protocol::encode_base64url([0; 64]);
    let mut changed = generated.clone();
    changed.signed_device_set.as_mut().ok_or("set")?.canonical =
        ramflux_protocol::canonical_json_bytes(tampered.signed_device_set.as_ref().ok_or("set")?)?;
    let result = client.decode_generated_task_manifest(&changed.encode_to_vec(), "human");
    assert!(
        matches!(result, Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))),
        "{result:?}"
    );
    let over = vec![0xff; super::super::MAX_DELIVERY_BYTES + 1];
    assert!(
        matches!(client.decode_generated_task_manifest(&over, "human"), Err(SdkError::TaskDeliveryTooLarge { bytes, limit }) if bytes == over.len() && limit == super::super::MAX_DELIVERY_BYTES)
    );
    Ok(())
}

#[test]
pub(super) fn generated_approval_round_trip_requires_the_native_grant_signature() -> TestResult {
    let client = client();
    let (packet, native) = super::tests::approval_packet()?;
    let bytes = client.encode_generated_task_approval(packet.clone())?;
    let decoded = client.decode_generated_task_approval(&bytes)?;
    let Some(g::task_approval_payload::Value::Decision(value)) =
        decoded.payload.as_ref().and_then(|value| value.value.as_ref())
    else {
        return Err("decision".into());
    };
    ramflux_crypto::verify_device_branch_signature(
        &client.task_signer_key("human", "device")?,
        &native,
        value.grant_signature.as_deref().ok_or("grant signature")?,
    )?;
    let mut missing = packet;
    let Some(g::task_approval_payload::Value::Decision(value)) =
        missing.payload.as_mut().and_then(|value| value.value.as_mut())
    else {
        return Err("decision".into());
    };
    value.grant_signature = None;
    invalid(&client.encode_generated_task_approval(missing.clone()));
    // A valid new wrapper cannot authorize an approved decision lacking native proof.
    missing.signature.clear();
    let transcript = typed_transcript("TaskApprovalPacket", &missing.encode_to_vec())?;
    missing.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &transcript,
        client.device_branch.as_ref().ok_or("device")?,
    );
    let bytes = g::Task { payload: Some(g::task::Payload::Approval(missing)) }.encode_to_vec();
    invalid(&client.decode_generated_task_approval(&bytes));
    Ok(())
}
