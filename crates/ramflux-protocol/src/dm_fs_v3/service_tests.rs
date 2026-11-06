// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::{RetryHint, RetryScope};
use serde_json::Value;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn vectors() -> Result<Value> {
    Ok(serde_json::from_str(include_str!("../../fixtures/dm_fs_v3/wire_vectors.json"))?)
}
fn hex(s: &str) -> Result<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn raw(name: &str) -> Result<Vec<u8>> {
    let w = vectors()?;
    let v = w["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("vector")?;
    hex(v["bytes"].as_str().ok_or("bytes")?)
}
fn replace(bytes: &[u8], id: u16, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = bytes[..8].to_vec();
    let mut pos = 8;
    while pos < bytes.len() {
        let field = u16::from_be_bytes(bytes[pos..pos + 2].try_into()?);
        let len = usize::try_from(u32::from_be_bytes(bytes[pos + 2..pos + 6].try_into()?))?;
        let body = if field == id { value } else { &bytes[pos + 6..pos + 6 + len] };
        out.extend_from_slice(&field.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        out.extend_from_slice(body);
        pos += 6 + len;
    }
    Ok(out)
}
fn field(bytes: &[u8], kind: WireType, id: u16) -> Result<Vec<u8>> {
    Ok(scan(kind, bytes)?.field(id).ok_or("field")?.to_vec())
}
fn list(count: u16, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = count.to_be_bytes().to_vec();
    for _ in 0..count {
        out.extend_from_slice(&u32::try_from(value.len())?.to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}
#[test]
fn dm_fs_v3_native_request_vector() -> Result {
    let bytes = raw("NativePrekeyRequest")?;
    let r = NativePrekeyRequest::from_bytes(&bytes)?;
    assert_eq!(r.to_bytes()?, bytes);
    assert_eq!(r.action, NativePrekeyAction::Lease);
    let body = r.signing_body()?;
    assert_eq!(body.len() + 70, bytes.len());
    for bad in ["", "other", "lease\n"] {
        assert_eq!(
            NativePrekeyRequest::from_bytes(&replace(&bytes, 2, bad.as_bytes())?),
            Err(DecodeError::Value)
        );
    }
    assert_eq!(
        NativePrekeyRequest::from_bytes(&replace(&bytes, 13, &(r.issued_at + 301).to_be_bytes())?),
        Err(DecodeError::Value)
    );
    assert_eq!(
        NativePrekeyRequest::from_bytes(&replace(&bytes, 13, &(r.issued_at - 1).to_be_bytes())?),
        Err(DecodeError::Value)
    );
    Ok(())
}
#[test]
fn dm_fs_v3_frames_vector() -> Result {
    let w = vectors()?;
    let mut count = 0;
    for v in w["positive"].as_array().ok_or("positive")? {
        if let Some(carrier) = v.get("json_carrier") {
            let input = serde_json::to_vec(carrier)?;
            let f = NativePrekeyFrame::from_json(&input)?;
            assert_eq!(serde_json::from_slice::<Value>(&f.to_json()?)?, *carrier);
            count += 1;
            let mut bad = carrier.clone();
            bad["payload"] =
                Value::String(format!("{}=", carrier["payload"].as_str().ok_or("payload")?));
            assert!(NativePrekeyFrame::from_json(&serde_json::to_vec(&bad)?).is_err());
            for label in ["", "native_prekey_other"] {
                bad = carrier.clone();
                bad["frame_type"] = label.into();
                assert!(NativePrekeyFrame::from_json(&serde_json::to_vec(&bad)?).is_err());
            }
            bad = carrier.clone();
            bad["extra"] = true.into();
            assert!(NativePrekeyFrame::from_json(&serde_json::to_vec(&bad)?).is_err());
        }
    }
    assert_eq!(count, 7);
    assert!(NativePrekeyFrame::from_json(br#"{"frame_type":"native_prekey_status","frame_type":"native_prekey_lease","payload":""}"#).is_err());
    let bytes = raw("NativePrekeyLease")?;
    let request = field(&bytes, WireType::NativePrekeyLease, 2)?;
    let bad = replace(&bytes, 2, &replace(&request, 2, b"status")?)?;
    assert_eq!(NativePrekeyLease::from_bytes(&bad), Err(DecodeError::Value));
    let bytes = raw("result_busy")?;
    for (id, bad) in [(3, b"".as_slice()), (3, b"other"), (6, b""), (6, b"other"), (7, b"other")] {
        assert_eq!(
            NativePrekeyResult::from_bytes(&replace(&bytes, id, bad)?),
            Err(DecodeError::Value)
        );
    }
    for name in ["result_opk", "result_status"] {
        let b = raw(name)?;
        assert_eq!(
            NativePrekeyResult::from_bytes(&replace(&b, 6, b"busy")?),
            Err(DecodeError::Value)
        );
        assert_eq!(
            NativePrekeyResult::from_bytes(&replace(&b, 3, b"publish")?),
            Err(DecodeError::Value)
        );
    }
    assert_eq!(NativePrekeyResult::from_bytes(&replace(&bytes, 7, b"")?), Err(DecodeError::Value));
    let no_retry = replace(&replace(&bytes, 7, b"")?, 8, &0u32.to_be_bytes())?;
    assert!(NativePrekeyResult::from_bytes(&no_retry).is_ok());
    let publish = replace(&replace(&no_retry, 3, b"publish")?, 6, b"")?;
    assert!(NativePrekeyResult::from_bytes(&publish).is_ok());
    Ok(())
}
fn header(name: &str) -> Result {
    let bytes = raw(name)?;
    let h = BootstrapHeader::from_bytes(&bytes)?;
    assert_eq!(h.to_bytes()?, bytes);
    assert_eq!(h.opk_id.is_some(), name == "header_opk");
    for id in [10, 11] {
        let bad_tag: &[u8] = if h.opk_id.is_some() { &[0] } else { &[1; 33] };
        assert_eq!(
            BootstrapHeader::from_bytes(&replace(&bytes, id, bad_tag)?),
            Err(DecodeError::Value)
        );
    }
    Ok(())
}
#[test]
fn dm_fs_v3_header_opk_vector() -> Result {
    header("header_opk")
}
#[test]
fn dm_fs_v3_header_spk_only_vector() -> Result {
    header("header_spk_only")
}
#[test]
fn dm_fs_v3_domains_distinct() -> Result {
    let s: Value = serde_json::from_str(include_str!("../../fixtures/dm_fs_v3/wire_schema.json"))?;
    let domains = s["domains"].as_array().ok_or("domains")?;
    assert_eq!(domains.len(), 23);
    for domain in domains {
        assert!(crate::domain::ALL.contains(&domain.as_str().ok_or("domain")?));
    }
    assert_eq!(
        crate::domain::ALL.len(),
        crate::domain::ALL.into_iter().collect::<std::collections::BTreeSet<_>>().len()
    );
    Ok(())
}
#[test]
fn dm_fs_v3_refusal_codes_stable_and_distinct() -> Result {
    let codes = [
        "native_publication_requires_custody",
        "native_account_required",
        "prekey_profile_inactive",
        "prekey_cross_home_unavailable",
        "prekey_clock_untrusted",
        "prekey_capacity",
        "prekey_repair_required",
        "prekey_refresh_required",
        "prekey_lease_unavailable",
        "bootstrap_key_unavailable",
        "update_required",
        "replay",
        "busy",
        "persistence_unavailable",
        "capacity",
    ];
    let mut seen = std::collections::BTreeSet::new();
    for code in codes {
        let r = DmFsV3Refusal::try_from(code)?;
        assert_eq!(r.as_str(), code);
        assert!(seen.insert(r.as_str()));
        let bytes = replace(&replace(&raw("result_busy")?, 7, b"")?, 8, &0u32.to_be_bytes())?;
        assert_eq!(
            NativePrekeyResult::from_bytes(&replace(&bytes, 6, code.as_bytes())?)?.refusal,
            Some(r)
        );
    }
    for bad in ["", "unsupported_schema", "update-required"] {
        assert!(DmFsV3Refusal::try_from(bad).is_err());
    }
    Ok(())
}
#[test]
fn dm_fs_v3_retry_hint_is_shared_clamped_and_bound() -> Result {
    let b = raw("result_busy")?;
    let request = NativePrekeyRequest::from_bytes(&raw("NativePrekeyRequest")?)?;
    for (n, expected) in
        [(0, 1000), (999, 1000), (1000, 1000), (3_600_000, 3_600_000), (u32::MAX, 3_600_000)]
    {
        let r = NativePrekeyResult::from_bytes(&replace(&b, 8, &n.to_be_bytes())?)?;
        assert_eq!(
            r.validate_for(&r.correlation_id, &r.request_hash, &request)?,
            Some(RetryHint::new(RetryScope::NodeCapacity, expected))
        );
        for wrong in [0, 1] {
            let mut q = request.clone();
            if wrong == 0 {
                q.node_id.push('x');
            } else {
                q.session_id.push('x');
            }
            assert!(r.validate_for(&r.correlation_id, &r.request_hash, &q).is_err());
        }
        assert!(r.validate_for(&[0; 32], &r.request_hash, &request).is_err());
        assert!(r.validate_for(&r.correlation_id, &[0; 32], &request).is_err());
    }
    let r = NativePrekeyResult::from_bytes(&replace(&b, 7, b"pre_auth_source")?)?;
    assert_eq!(r.retry.ok_or("hint")?.scope, RetryScope::PreAuthSource);
    assert_eq!(
        NativePrekeyResult::from_bytes(&replace(&b, 6, b"capacity")?),
        Err(DecodeError::Value)
    );
    Ok(())
}
#[test]
fn dm_fs_v3_service_decoder_limits() -> Result {
    let publish = raw("NativePrekeyPublish")?;
    let update = field(&publish, WireType::NativePrekeyPublish, 3)?;
    for (id, count, name) in [(4, 65, "SignedNativeOpk"), (5, 401, "RetirementRef")] {
        let bad = replace(&update, id, &list(count, &raw(name)?)?)?;
        assert_eq!(
            NativePrekeyPublish::from_bytes(&replace(&publish, 3, &bad)?),
            Err(DecodeError::Count)
        );
    }
    let status = raw("NativePrekeyStatus")?;
    let query = field(&status, WireType::NativePrekeyStatus, 3)?;
    let bad = replace(&query, 3, &list(201, &raw("RetirementRef")?)?)?;
    assert_eq!(
        NativePrekeyStatus::from_bytes(&replace(&status, 3, &bad)?),
        Err(DecodeError::Count)
    );
    let result = raw("result_status")?;
    let status = OwnerPrekeyStatus::from_bytes(&raw("OwnerPrekeyStatus")?)?;
    let entry = status.entries.first().ok_or("entry")?.to_bytes()?;
    let mut body = vec![1];
    body.extend_from_slice(&replace(&status.to_bytes()?, 9, &list(201, &entry)?)?);
    assert_eq!(
        NativePrekeyResult::from_bytes(&replace(&result, 5, &body)?),
        Err(DecodeError::Count)
    );
    assert_eq!(
        BootstrapHeader::from_bytes(&replace(&raw("header_opk")?, 22, &vec![0; 4097])?),
        Err(DecodeError::FieldCeiling)
    );
    Ok(())
}

fn round_trip(kind: &str, bytes: &[u8]) -> std::result::Result<Vec<u8>, DecodeError> {
    match kind {
        "NativePrekeyRequest" => NativePrekeyRequest::from_bytes(bytes)?.to_bytes(),
        "NativePrekeyLease" => NativePrekeyLease::from_bytes(bytes)?.to_bytes(),
        "NativePrekeyPublish" => NativePrekeyPublish::from_bytes(bytes)?.to_bytes(),
        "NativePrekeyStatus" => NativePrekeyStatus::from_bytes(bytes)?.to_bytes(),
        "NativePrekeyResult" => NativePrekeyResult::from_bytes(bytes)?.to_bytes(),
        "BootstrapHeader" => BootstrapHeader::from_bytes(bytes)?.to_bytes(),
        "BootstrapTranscript" => BootstrapTranscript::from_bytes(bytes)?.to_bytes(),
        _ => Err(DecodeError::Header),
    }
}
#[test]
fn dm_fs_v3_service_maxima_and_malformed_frames() -> Result {
    let w = vectors()?;
    let schema: Value =
        serde_json::from_str(include_str!("../../fixtures/dm_fs_v3/wire_schema.json"))?;
    let mut count = 0;
    for v in w["service_maximum"].as_array().ok_or("maxima")? {
        let kind = v["type"].as_str().ok_or("type")?;
        let bytes = hex(v["bytes"].as_str().ok_or("bytes")?)?;
        assert_eq!(round_trip(kind, &bytes)?, bytes, "{kind}");
        assert_eq!(bytes.len(), usize::try_from(v["byte_length"].as_u64().ok_or("length")?)?);
        let ceiling = usize::try_from(schema["types"][kind]["ceiling"].as_u64().ok_or("ceiling")?)?;
        assert_eq!(round_trip(kind, &vec![0; ceiling + 1]), Err(DecodeError::TypeCeiling));
        count += 1;
        if let Ok(frame) = match kind {
            "NativePrekeyLease" => {
                Ok(NativePrekeyFrame::Lease(Box::new(NativePrekeyLease::from_bytes(&bytes)?)))
            }
            "NativePrekeyPublish" => {
                Ok(NativePrekeyFrame::Publish(Box::new(NativePrekeyPublish::from_bytes(&bytes)?)))
            }
            "NativePrekeyStatus" => {
                Ok(NativePrekeyFrame::Status(Box::new(NativePrekeyStatus::from_bytes(&bytes)?)))
            }
            "NativePrekeyResult" => {
                Ok(NativePrekeyFrame::Result(Box::new(NativePrekeyResult::from_bytes(&bytes)?)))
            }
            _ => Err(DecodeError::Header),
        } {
            let json = frame.to_json()?;
            assert_eq!(NativePrekeyFrame::from_json(&json)?, frame);
            let carrier: Value = serde_json::from_slice(&json)?;
            let label = carrier["frame_type"].as_str().ok_or("frame_type")?;
            let cap = usize::try_from(
                schema["json_size_policy"]["table"][label]["ceiling"].as_u64().ok_or("ceiling")?,
            )?;
            let mut padded = json.clone();
            padded.resize(cap, b' ');
            assert!(NativePrekeyFrame::from_json(&padded).is_ok());
            padded.push(b' ');
            assert_eq!(NativePrekeyFrame::from_json(&padded), Err(DecodeError::TypeCeiling));
        }
    }
    assert_eq!(count, 7);
    let mut positive = 0;
    for v in w["positive"].as_array().ok_or("positive")? {
        let kind = v["type"].as_str().ok_or("type")?;
        if schema["types"][kind]["code"].as_u64().ok_or("code")? >= 13 {
            let b = hex(v["bytes"].as_str().ok_or("bytes")?)?;
            assert_eq!(round_trip(kind, &b)?, b);
            positive += 1;
        }
    }
    assert_eq!(positive, 12);
    let mut negative = 0;
    for v in w["negative"].as_array().ok_or("negative")? {
        let kind = v["type"].as_str().ok_or("type")?;
        if schema["types"][kind]["code"].as_u64().ok_or("code")? >= 13 {
            assert!(round_trip(kind, &hex(v["bytes"].as_str().ok_or("bytes")?)?).is_err());
            negative += 1;
        }
    }
    assert!(negative >= 7);
    Ok(())
}

#[test]
fn dm_fs_v3_service_code_combinations() -> Result {
    for (name, kind, action) in [
        ("NativePrekeyPublish", WireType::NativePrekeyPublish, b"lease".as_slice()),
        ("NativePrekeyStatus", WireType::NativePrekeyStatus, b"publish".as_slice()),
    ] {
        let bytes = raw(name)?;
        let request = field(&bytes, kind, 2)?;
        assert_eq!(
            round_trip(name, &replace(&bytes, 2, &replace(&request, 2, action)?)?),
            Err(DecodeError::Value)
        );
    }
    let lease = raw("result_opk")?;
    let status = raw("result_status")?;
    let refusal = raw("result_busy")?;
    for (bytes, id, body) in [
        (&lease, 4, vec![0]),
        (&status, 5, vec![0]),
        (&lease, 5, field(&status, WireType::NativePrekeyResult, 5)?),
        (&status, 4, field(&lease, WireType::NativePrekeyResult, 4)?),
        (&refusal, 4, field(&lease, WireType::NativePrekeyResult, 4)?),
        (&lease, 7, b"node_capacity".to_vec()),
    ] {
        assert_eq!(
            NativePrekeyResult::from_bytes(&replace(bytes, id, &body)?),
            Err(DecodeError::Value)
        );
    }
    let schema: Value =
        serde_json::from_str(include_str!("../../fixtures/dm_fs_v3/wire_schema.json"))?;
    for (key, codes) in [
        (
            "action",
            vec![
                NativePrekeyAction::Lease.as_str(),
                NativePrekeyAction::Publish.as_str(),
                NativePrekeyAction::Status.as_str(),
            ],
        ),
        (
            "result_kind",
            vec![
                NativePrekeyResultKind::Lease.as_str(),
                NativePrekeyResultKind::Publish.as_str(),
                NativePrekeyResultKind::Status.as_str(),
                NativePrekeyResultKind::Refusal.as_str(),
            ],
        ),
    ] {
        assert_eq!(schema["service_value_sets"][key], serde_json::to_value(codes)?);
    }
    for value in schema["service_value_sets"]["refusal"].as_array().ok_or("refusal")? {
        let code = value.as_str().ok_or("code")?;
        assert_eq!(DmFsV3Refusal::try_from(code)?.as_str(), code);
    }
    let request = NativePrekeyRequest::from_bytes(&raw("NativePrekeyRequest")?)?;
    let result = NativePrekeyResult::from_bytes(&status)?;
    assert!(result.validate_for(&result.correlation_id, &result.request_hash, &request).is_err());
    Ok(())
}

#[test]
fn dm_fs_v3_largest_lease_status_fixtures_decode() -> Result {
    let w = vectors()?;
    let maxima = w["filled_maximum"].as_array().ok_or("maxima")?;
    for (name, size) in
        [("PrekeyLeaseResult", 3017), ("OwnerStatusEntry", 116), ("OwnerPrekeyStatus", 24992)]
    {
        let v = maxima.iter().find(|v| v["type"] == name).ok_or("maximum")?;
        let bytes = hex(v["bytes"].as_str().ok_or("bytes")?)?;
        assert_eq!(bytes.len(), size);
        let encoded = match name {
            "PrekeyLeaseResult" => PrekeyLeaseResult::from_bytes(&bytes)?.to_bytes()?,
            "OwnerStatusEntry" => OwnerStatusEntry::from_bytes(&bytes)?.to_bytes()?,
            "OwnerPrekeyStatus" => OwnerPrekeyStatus::from_bytes(&bytes)?.to_bytes()?,
            _ => return Err("fixture type".into()),
        };
        assert_eq!(encoded, bytes);
    }
    let status =
        maxima.iter().find(|v| v["type"] == "OwnerPrekeyStatus").ok_or("status maximum")?;
    let bytes = hex(status["bytes"].as_str().ok_or("bytes")?)?;
    let decoded = OwnerPrekeyStatus::from_bytes(&bytes)?;
    let entry = decoded.entries.first().ok_or("entry")?.to_bytes()?;
    let bad = replace(&bytes, 9, &list(201, &entry)?)?;
    assert_eq!(OwnerPrekeyStatus::from_bytes(&bad), Err(DecodeError::Count));
    let mut optional = vec![1];
    optional.extend_from_slice(&bad);
    assert_eq!(
        NativePrekeyResult::from_bytes(&replace(&raw("result_status")?, 5, &optional)?),
        Err(DecodeError::Count)
    );
    Ok(())
}
#[test]
fn dm_fs_v3_unleased_state_requires_zero_times() -> Result {
    let mut entry = OwnerStatusEntry {
        key_id: [1; 32],
        generation: 1,
        serial: 1,
        leased_at: 0,
        deadline: 0,
        state: OwnerPrekeyState::Unleased,
    };
    let original = entry.to_bytes()?;
    assert_eq!(OwnerStatusEntry::from_bytes(&original)?, entry);
    for (leased_at, deadline) in [(1u64, 0u64), (0, 1), (1, 1)] {
        entry.leased_at = leased_at;
        entry.deadline = deadline;
        assert_eq!(entry.to_bytes(), Err(DecodeError::Value));
        let bad =
            replace(&replace(&original, 4, &leased_at.to_be_bytes())?, 5, &deadline.to_be_bytes())?;
        assert_eq!(OwnerStatusEntry::from_bytes(&bad), Err(DecodeError::Value));
        let status = replace(&raw("OwnerPrekeyStatus")?, 9, &list(1, &bad)?)?;
        assert_eq!(OwnerPrekeyStatus::from_bytes(&status), Err(DecodeError::Value));
    }
    Ok(())
}
