// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::certificate::{Certificate, Phase};
use super::{certificate::native_certificate, tests::TestResult, *};

fn fixture(
    client: &RamfluxClient,
    committed: bool,
) -> Result<(Certificate, g::TaskCertificate), Box<dyn std::error::Error>> {
    let ramflux_protocol::TaskEventBody::Resolve(resolution) =
        super::tests::body_variants().pop().ok_or("resolve fixture")?
    else {
        return Err("resolve fixture".into());
    };
    let native = client.sign_task_certificate(Certificate {
        conversation_id: "thread".into(),
        resolution,
        assignee: "human".into(),
        issuer_device: "device".into(),
        issued_at: 4_000_000_000,
        phase: if committed { Phase::Committed } else { Phase::Reserved },
        committed_version: committed.then_some(4),
        carrier_hash: committed.then(|| "carrier-hash".into()),
        decision_key: "decision-key".into(),
        evidence_hash: "evidence-hash".into(),
        signature: String::new(),
    })?;
    let mut resolution = serde_json::to_value(&native.resolution)?;
    payload_shape(&mut resolution, true)?;
    let generated = g::TaskCertificate {
        conversation_id: native.conversation_id.clone(),
        resolution: Some(serde_json::from_value(resolution)?),
        assignee: native.assignee.clone(),
        issuer_device: native.issuer_device.clone(),
        issued_at: native.issued_at,
        phase: Some(serde_json::from_value(if committed {
            json!({"committed":{}})
        } else {
            json!({"reserved":{}})
        })?),
        committed_version: native.committed_version,
        carrier_hash: native.carrier_hash.clone(),
        decision_key: native.decision_key.clone(),
        evidence_hash: native.evidence_hash.clone(),
        signature: native.signature.clone(),
    };
    let generated = g::TaskCertificate::decode(
        client.encode_generated_task_certificate(&generated)?.as_slice(),
    )?;
    Ok((native, generated))
}
fn client() -> RamfluxClient {
    let mut client = RamfluxClient::new();
    client.create_device_branch("human", "device", 1, [23; 32]);
    client
}
fn invalid_request(result: &Result<g::TaskCertificate, SdkError>) {
    assert!(
        matches!(
            result,
            Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::InvalidRequest, .. })
        ),
        "{result:?}"
    );
}

#[test]
fn generated_certificates_preserve_fields_and_use_typed_executor_signature() -> TestResult {
    let client = client();
    for committed in [false, true] {
        let (native, generated) = fixture(&client, committed)?;
        let bytes = client.encode_generated_task_certificate(&generated)?;
        let decoded = client.decode_generated_task_certificate(&bytes)?;
        assert_eq!(generated, decoded);
        let mut unsigned = decoded.clone();
        unsigned.signature.clear();
        let domain = b"ramflux.message.typed.TaskCertificate.v1";
        let body = unsigned.encode_to_vec();
        let mut transcript = u32::try_from(domain.len())?.to_be_bytes().to_vec();
        transcript.extend(domain);
        transcript.extend(u32::try_from(body.len())?.to_be_bytes());
        transcript.extend(body);
        let public = client.task_signer_key("human", "device")?;
        ramflux_crypto::verify_canonical_signature(&transcript, &decoded.signature, &public)?;
        let mut round_trip = native_certificate(&decoded)?;
        assert_ne!(native.signature, decoded.signature);
        round_trip.signature.clone_from(&native.signature);
        assert_eq!(serde_json::to_value(&native)?, serde_json::to_value(&round_trip)?);
        assert_eq!(native.signing_bytes()?, round_trip.signing_bytes()?);
        assert_eq!(client.encode_generated_task_certificate(&decoded)?, bytes);
        for field in 0..11 {
            let mut changed = generated.clone();
            match field {
                0 => changed.conversation_id.push('x'),
                1 => changed.resolution.as_mut().ok_or("resolution")?.decision_id.push('x'),
                2 => changed.assignee = "other".into(),
                3 => changed.issuer_device = "other".into(),
                4 => changed.issued_at += 1,
                5 => {
                    changed.phase = Some(serde_json::from_value(json!({"reserved":{}}))?);
                    changed.committed_version = None;
                    changed.carrier_hash = None;
                    if !committed {
                        continue;
                    }
                }
                6 => {
                    if !committed {
                        continue;
                    }
                    changed.committed_version = Some(5);
                }
                7 => {
                    if !committed {
                        continue;
                    }
                    changed.carrier_hash = Some("other".into());
                }
                8 => changed.decision_key.push('x'),
                9 => changed.evidence_hash.push('x'),
                _ => changed.signature = ramflux_protocol::encode_base64url([0; 64]),
            }
            if matches!(field, 2 | 3) {
                assert!(matches!(
                    client.encode_generated_task_certificate(&changed),
                    Err(SdkError::TaskRefused {
                        reason: crate::TaskRefusalCode::InvalidRequest,
                        ..
                    })
                ));
            }
            let result = client.decode_generated_task_certificate(&changed.encode_to_vec());
            if field == 2 {
                assert!(matches!(result, Err(SdkError::AccountDbNotUnlocked)), "{result:?}");
            } else if field == 3 {
                assert!(matches!(result, Err(SdkError::IdentityRootMissing)), "{result:?}");
            } else {
                assert!(
                    matches!(
                        result,
                        Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))
                    ),
                    "field {field}: {result:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn generated_certificate_phase_and_identifier_bounds_have_exact_errors() -> TestResult {
    let client = client();
    let (_, committed) = fixture(&client, true)?;
    let (_, reserved) = fixture(&client, false)?;
    for index in 0..9 {
        let mut changed = if index < 6 { committed.clone() } else { reserved.clone() };
        match index {
            0 => changed.phase = None,
            1 => changed.committed_version = None,
            2 => changed.carrier_hash = None,
            3 => changed.committed_version = Some(3),
            4 => changed.committed_version = Some(ramflux_protocol::MAX_TASK_VERSION + 1),
            5 => changed.carrier_hash = Some(String::new()),
            6 => changed.committed_version = Some(4),
            7 => changed.carrier_hash = Some("hash".into()),
            _ => changed.phase = Some(g::TaskCertificatePhase::default()),
        }
        invalid_request(&client.decode_generated_task_certificate(&changed.encode_to_vec()));
    }
    for field in 0..5 {
        for invalid in [String::new(), "x".repeat(257), "unsafe\nidentifier".into(), " ".into()] {
            let mut changed = committed.clone();
            match field {
                0 => changed.assignee = invalid,
                1 => changed.issuer_device = invalid,
                2 => changed.decision_key = invalid,
                3 => changed.evidence_hash = invalid,
                _ => changed.carrier_hash = Some(invalid),
            }
            invalid_request(&client.decode_generated_task_certificate(&changed.encode_to_vec()));
        }
        let mut boundary = committed.clone();
        match field {
            0 => boundary.assignee = "x".repeat(256),
            1 => boundary.issuer_device = "x".repeat(256),
            2 => boundary.decision_key = "x".repeat(256),
            3 => boundary.evidence_hash = "x".repeat(256),
            _ => boundary.carrier_hash = Some("x".repeat(256)),
        }
        native_certificate(&boundary)?;
    }
    for field in 0..4 {
        for invalid in [String::new(), "x".repeat(257), "unsafe\nidentifier".into()] {
            let expected = if invalid.is_empty() {
                crate::TaskRefusalCode::InvalidEvent
            } else {
                crate::TaskRefusalCode::InvalidRequest
            };
            let mut changed = committed.clone();
            let resolution = changed.resolution.as_mut().ok_or("resolution")?;
            match field {
                0 => changed.conversation_id = invalid,
                1 => resolution.task_id = invalid,
                2 => resolution.step_id = invalid,
                _ => resolution.decision_id = invalid,
            }
            let result = client.decode_generated_task_certificate(&changed.encode_to_vec());
            assert!(
                matches!(
                    result,
                    Err(SdkError::TaskRefused { reason, .. }) if reason == expected
                ),
                "{result:?}"
            );
        }
    }
    for revision in [0, ramflux_protocol::MAX_TASK_VERSION + 1] {
        let mut changed = committed.clone();
        changed.resolution.as_mut().ok_or("resolution")?.base_revision = revision;
        let result = client.decode_generated_task_certificate(&changed.encode_to_vec());
        assert!(
            matches!(
                result,
                Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::StaleRevision, .. })
            ),
            "{result:?}"
        );
    }
    for missing in 0..3 {
        let mut changed = committed.clone();
        match missing {
            0 => changed.resolution = None,
            1 => changed.resolution.as_mut().ok_or("resolution")?.target = None,
            _ => changed.resolution.as_mut().ok_or("resolution")?.decision = None,
        }
        invalid_request(&client.decode_generated_task_certificate(&changed.encode_to_vec()));
    }
    Ok(())
}

#[test]
fn generated_certificate_canonical_bytes_and_delivery_budget_reject_before_signature() -> TestResult
{
    let client = client();
    let (_, certificate) = fixture(&client, true)?;
    let mut reordered = vec![0x28, 1];
    reordered.extend(certificate.encode_to_vec());
    invalid_request(&client.decode_generated_task_certificate(&reordered));
    let mut overlong = certificate.encode_to_vec();
    // First tag is a length-delimited conversation identifier with length six.
    overlong.splice(1..2, [0x86, 0]);
    invalid_request(&client.decode_generated_task_certificate(&overlong));
    let bytes = vec![0xff; super::super::MAX_DELIVERY_BYTES + 1];
    assert!(
        matches!(client.decode_generated_task_certificate(&bytes), Err(SdkError::TaskDeliveryTooLarge {bytes: actual, limit}) if actual == bytes.len() && limit == super::super::MAX_DELIVERY_BYTES)
    );
    Ok(())
}

#[test]
fn generated_certificate_resolution_targets_and_revision_boundaries_are_native() -> TestResult {
    let client = client();
    let (_, original) = fixture(&client, true)?;
    for target in ["approval", "choice", "input"] {
        for length in [0, 256, 257] {
            let key = if target == "approval" { "grant_id" } else { "surface_id" };
            let mut changed = original.clone();
            let resolution = changed.resolution.as_mut().ok_or("resolution")?;
            resolution.target =
                Some(serde_json::from_value(json!({target:{key:"x".repeat(length)}}))?);
            let result = native_certificate(&changed);
            if length == 256 {
                result?;
            } else {
                assert!(
                    matches!(
                        result,
                        Err(SdkError::TaskRefused {
                            reason: crate::TaskRefusalCode::InvalidEvent,
                            ..
                        })
                    ),
                    "{target}/{length}"
                );
            }
        }
    }
    let mut boundary = original.clone();
    boundary.committed_version = Some(ramflux_protocol::MAX_TASK_VERSION);
    boundary.resolution.as_mut().ok_or("resolution")?.base_revision =
        ramflux_protocol::MAX_TASK_VERSION - 1;
    native_certificate(&boundary)?;
    boundary.resolution.as_mut().ok_or("resolution")?.base_revision =
        ramflux_protocol::MAX_TASK_VERSION;
    invalid_request(&client.decode_generated_task_certificate(&boundary.encode_to_vec()));
    Ok(())
}

#[test]
fn generated_certificate_signature_covers_all_resolution_fields() -> TestResult {
    let client = client();
    let (_, original) = fixture(&client, true)?;
    for field in 0..6 {
        let mut changed = original.clone();
        let resolution = changed.resolution.as_mut().ok_or("resolution")?;
        match field {
            0 => resolution.task_id.push('x'),
            1 => resolution.base_revision = 2,
            2 => resolution.step_id.push('x'),
            3 => {
                resolution.target =
                    Some(serde_json::from_value(json!({"approval":{"grantId":"grant"}}))?);
            }
            4 => resolution.decision_id.push('x'),
            _ => resolution.decision = Some(serde_json::from_value(json!({"deny":{}}))?),
        }
        let result = client.decode_generated_task_certificate(&changed.encode_to_vec());
        assert!(
            matches!(result, Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))),
            "field {field}: {result:?}"
        );
    }
    Ok(())
}
