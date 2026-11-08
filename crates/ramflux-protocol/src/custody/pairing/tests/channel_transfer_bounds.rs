// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exhaustive transfer/channel limits and frozen-context separation.
use super::*;
use crate::custody::pairing::channel::*;

const MAX_CHUNK: usize = 8192;
const MAX_HPKE: u64 = 819_200;
const MAX_CANDIDATE: u64 = 524_288;

fn hash() -> String {
    encode_base64url([1; 32])
}

#[allow(clippy::needless_pass_by_value)] // JSON builders deliberately take owned fixture values.
fn signed(value: Value) -> Value {
    json!({"body":value,"signature":encode_base64url([7;64])})
}

fn obj(name: &str, mut value: Value) -> Value {
    value["schema"] = json!(format!("ramflux.pairing.{name}.v2"));
    value["version"] = json!(2);
    value
}

fn maxima() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../fixtures/pairing_v2/channel_local/maxima.json"
    ))?)
}

fn independent<T: PairingWire>(all: &Value, key: &str) -> TestResult<Value> {
    let wire = all[key]["wire"].as_str().ok_or("missing independent bytes")?.as_bytes();
    assert_eq!(wire.len() as u64, all[key]["size"].as_u64().ok_or("missing size")?);
    let value = T::from_wire_bytes(wire)?;
    assert_eq!(value.to_wire_bytes()?, wire, "{key}");
    Ok(serde_json::from_slice(wire)?)
}

fn transfer_transcript(source: &Value) -> TestResult<(Value, Transcript)> {
    let mut value = source.clone();
    let common = transfer(&source["initiator"]["common"]);
    value["initiator"]["common"] = common.clone();
    value["responder"]["common"] = common;
    value["initiator"]["hpke_key"] = json!(encode_base64url([100; 32]));
    value["responder"]["hpke_key"] = json!(encode_base64url([101; 32]));
    let typed = decode_value::<Transcript>(&value)?;
    Ok((value, typed))
}

fn transfer_payload(common: &Value, digest: &str) -> Value {
    json!({
        "schema":"ramflux.identity.transfer.payload.v1",
        "version":1,
        "transfer_id":common["transfer_id"],
        "transcript_hash":digest,
        "current_record_hash":common["record_hash"],
        "device_set_epoch":common["device_set_epoch"],
        "pending_invitations":[],
        "journal":[],
        "delegation_state":[],
        "group_restriction_summary":[],
        "pending_erasure":[],
        "optional_data_keys":[]
    })
}

#[allow(clippy::needless_pass_by_value)] // JSON builders deliberately take owned fixture values.
fn channel(common: &Value, digest: &str, payload: Value) -> Value {
    obj(
        "Channel",
        json!({
            "invitation_id":common["invitation_id"],
            "transcript_hash":digest,
            "payload":payload
        }),
    )
}

fn context<'a>(
    transcript: &'a Transcript,
    digest: &'a str,
    sender: &'a str,
    phase: &'a str,
    record_hash: Option<&'a str>,
    compacted_ids_hash: Option<&'a str>,
) -> ChannelContext<'a> {
    ChannelContext {
        transcript,
        transcript_hash: digest,
        sender,
        phase,
        operation_id: digest,
        proposal_hash: Some(digest),
        record_hash,
        record_epoch: Some(MAX_SAFE_JSON_INTEGER),
        compacted_ids_hash,
    }
}

#[test]
fn pairing_channel_transfer_bounds_and_contexts() -> TestResult {
    let all = maxima()?;
    transfer_payload_bounds(&all).map_err(|e| format!("transfer payload bounds: {e}"))?;
    transfer_contexts(&all).map_err(|e| format!("transfer contexts: {e}"))?;
    channel_chunk_bounds(&all).map_err(|e| format!("channel chunk bounds: {e}"))?;
    channel_contexts(&all).map_err(|e| format!("channel contexts: {e}"))?;
    preservation_contexts(&all).map_err(|e| format!("preservation contexts: {e}"))?;
    binding_and_hpke_contexts(&all).map_err(|e| format!("binding and HPKE contexts: {e}"))?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep collection maxima and isolated over-bound rows together.
fn transfer_payload_bounds(all: &Value) -> TestResult {
    let full = independent::<TransferPayload>(all, "TransferPayload")?;
    let typed = decode_value::<TransferPayload>(&full)?;
    assert_eq!(typed.pending_invitations.len(), 3);
    assert_eq!(typed.journal.len(), 64);
    assert_eq!(typed.group_restriction_summary.len(), 64);
    assert_eq!(typed.pending_erasure.len(), 256);
    assert_eq!(typed.optional_data_keys.len(), 32);
    assert!(typed.group_restriction_summary.iter().all(|v| v.restriction_hashes.len() == 8));
    assert!(typed.group_restriction_summary.iter().all(|v| v.revocation_hashes.len() == 8));
    for (path, limit) in [
        ("/pending_invitations/0", 512),
        ("/journal/0", 512),
        ("/group_restriction_summary/0", 2048),
        ("/pending_erasure/0", 1024),
        ("/optional_data_keys/0", 1024),
    ] {
        assert!(bytes(full.pointer(path).ok_or("element")?)?.len() < limit, "{path}");
    }

    for (path, value, error) in [
        (
            "/pending_invitations",
            {
                let mut v = full["pending_invitations"].as_array().ok_or("pending")?.clone();
                v.push(v[0].clone());
                json!(v)
            },
            "pending_invitations",
        ),
        (
            "/journal",
            {
                let mut v = full["journal"].as_array().ok_or("journal")?.clone();
                v.push(v[0].clone());
                json!(v)
            },
            "journal",
        ),
        (
            "/group_restriction_summary",
            {
                let mut v = full["group_restriction_summary"].as_array().ok_or("groups")?.clone();
                v.push(v[0].clone());
                json!(v)
            },
            "group_restriction_summary",
        ),
        (
            "/pending_erasure",
            {
                let mut v = full["pending_erasure"].as_array().ok_or("erasure")?.clone();
                v.push(v[0].clone());
                json!(v)
            },
            "pending_erasure",
        ),
        (
            "/optional_data_keys",
            {
                let mut v = full["optional_data_keys"].as_array().ok_or("keys")?.clone();
                v.push(v[0].clone());
                json!(v)
            },
            "optional_data_keys",
        ),
    ] {
        field::<TransferPayload>(&full, path, value, error)?;
    }

    // Independent maxima reach the declared 256-byte payload identifiers,
    // 128-byte DeviceRef ids and all hash-count limits. The element byte
    // ceilings (512/1024/2048) are deliberately conservative and unreachable:
    // the closed field grammar and the above maxima are smaller than each cap.
    field::<TransferPayload>(
        &full,
        "/group_restriction_summary/63/group_id",
        json!(format!(
            "{}x",
            full["group_restriction_summary"][63]["group_id"].as_str().ok_or("group id")?
        )),
        "group_id",
    )?;
    field::<TransferPayload>(
        &full,
        "/optional_data_keys/31/key_id",
        json!(format!("{}x", full["optional_data_keys"][31]["key_id"].as_str().ok_or("key id")?)),
        "key_id",
    )?;
    field::<TransferPayload>(
        &full,
        "/optional_data_keys/0/purpose",
        json!("metadata"),
        "key.purpose",
    )?;
    field::<TransferPayload>(
        &full,
        "/pending_erasure/255/device_id",
        json!(format!(
            "{}x",
            full["pending_erasure"][255]["device_id"].as_str().ok_or("device id")?
        )),
        "ref.device_id",
    )?;
    invalid::<TransferPayload>(
        &full,
        "/pending_erasure/255/device_epoch",
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;
    let mut hashes = full["group_restriction_summary"][0]["restriction_hashes"]
        .as_array()
        .ok_or("restriction hashes")?
        .clone();
    hashes.push(json!(encode_base64url([250; 32])));
    hashes.sort_by_key(Value::to_string);
    field::<TransferPayload>(
        &full,
        "/group_restriction_summary/0/restriction_hashes",
        json!(hashes),
        "hashes",
    )?;
    let mut revocations = full["group_restriction_summary"][0]["revocation_hashes"]
        .as_array()
        .ok_or("revocation hashes")?
        .clone();
    revocations.push(json!(encode_base64url([250; 32])));
    revocations.sort_by_key(Value::to_string);
    field::<TransferPayload>(
        &full,
        "/group_restriction_summary/0/revocation_hashes",
        json!(revocations),
        "hashes",
    )?;
    assert!(bytes(&full)?.len() < TransferPayload::LIMIT);
    Ok(())
}

fn transfer_contexts(all: &Value) -> TestResult {
    let fixture_values = fixture()?;
    let source = &fixture_values["transcript"];
    let (transcript_value, transcript) = transfer_transcript(source)?;
    let common = &transcript_value["initiator"]["common"];
    let digest = hash();
    let payload = transfer_payload(common, &digest);
    let typed = decode_value::<TransferPayload>(&payload)?;
    typed.validate_context(&transcript, &digest)?;

    for (path, value) in [
        ("/transfer_id", json!(encode_base64url([2; 32]))),
        ("/transcript_hash", json!(encode_base64url([2; 32]))),
        ("/current_record_hash", json!(encode_base64url([2; 32]))),
        ("/device_set_epoch", json!(MAX_SAFE_JSON_INTEGER - 1)),
    ] {
        let mut wrong = payload.clone();
        *wrong.pointer_mut(path).ok_or("payload context field")? = value;
        assert_eq!(
            decode_value::<TransferPayload>(&wrong)?.validate_context(&transcript, &digest),
            Err(WireError::Field("transfer_context")),
            "{path} must be independently bound"
        );
    }
    assert_eq!(
        decode_value::<TransferPayload>(&payload)?
            .validate_context(&transcript, &encode_base64url([2; 32])),
        Err(WireError::Field("transfer_context"))
    );

    let mut selected_value = transcript_value.clone();
    selected_value["initiator"]["common"]["data_selection"] = json!([
        {"key_id":"history-a","purpose":"history"},
        {"key_id":"history-b","purpose":"attachment"}
    ]);
    selected_value["responder"]["common"] = selected_value["initiator"]["common"].clone();
    let selected = decode_value::<Transcript>(&selected_value)?;
    let mut consent = payload.clone();
    consent["optional_data_keys"] = json!([
        {"key_id":"history-a","purpose":"history","key":hash()},
        {"key_id":"history-b","purpose":"attachment","key":hash()}
    ]);
    decode_value::<TransferPayload>(&consent)?.validate_context(&selected, &digest)?;
    for (path, value) in [
        ("/optional_data_keys/0/key_id", json!("history-a0")),
        ("/optional_data_keys/0/purpose", json!("attachment")),
    ] {
        let mut wrong = consent.clone();
        *wrong.pointer_mut(path).ok_or("consent field")? = value;
        assert_eq!(
            decode_value::<TransferPayload>(&wrong)?.validate_context(&selected, &digest),
            Err(WireError::Field("data_consent")),
            "{path} must be independently bound"
        );
    }
    let mut missing = consent;
    missing["optional_data_keys"].as_array_mut().ok_or("keys")?.pop();
    assert_eq!(
        decode_value::<TransferPayload>(&missing)?.validate_context(&selected, &digest),
        Err(WireError::Field("data_consent"))
    );
    let _ = all;
    Ok(())
}

fn channel_chunk_bounds(all: &Value) -> TestResult {
    let digest = hash();
    let fixture_values = fixture()?;
    for (key, object_kind, total, count) in [
        ("Channel_hpke", "hpke", MAX_HPKE, 100_u64),
        ("Channel_candidate", "candidate", MAX_CANDIDATE, 64_u64),
    ] {
        let value = independent::<Channel>(all, key)?;
        let typed = decode_value::<Channel>(&value)?;
        let Payload::ArtifactChunk {
            object_kind: actual,
            index,
            count: actual_count,
            total_bytes,
            bytes: encoded,
            ..
        } = typed.payload
        else {
            return Err("fixture is not an artifact chunk".into());
        };
        assert_eq!(actual, object_kind);
        assert_eq!(index, count - 1);
        assert_eq!(actual_count, count);
        assert_eq!(total_bytes, total);
        assert_eq!(decode_base64url(&encoded)?.len(), MAX_CHUNK);

        let common = &fixture_values["transcript"]["initiator"]["common"];
        let maximum = channel(
            common,
            &digest,
            json!({"kind":"artifact_chunk","object_kind":object_kind,"object_id":digest,"index":count-1,"count":count,"total_bytes":total,"bytes":encode_base64url(vec![1;MAX_CHUNK])}),
        );
        decode_value::<Channel>(&maximum)?;
        field::<Channel>(&maximum, "/payload/total_bytes", json!(total + 1), "total_bytes")?;
        field::<Channel>(&maximum, "/payload/count", json!(count + 1), "count")?;
        field::<Channel>(&maximum, "/payload/index", json!(count), "index")?;
        field::<Channel>(
            &maximum,
            "/payload/bytes",
            json!(encode_base64url(vec![1; MAX_CHUNK + 1])),
            "bytes",
        )?;
        let mut short = maximum.clone();
        short["payload"]["index"] = json!(0);
        field::<Channel>(
            &short,
            "/payload/bytes",
            json!(encode_base64url(vec![1; MAX_CHUNK - 1])),
            "chunk_length",
        )?;
    }
    // The channel byte cap is conservative: the largest valid chunk encoding
    // is smaller than 11,700 because a chunk is capped at 8,192 raw bytes and
    // every other field is fixed-width. The independent max fixture proves the
    // largest reachable encoding; cap+1 is covered by from_wire_bytes below.
    let hpke = all["Channel_hpke"]["wire"].as_str().ok_or("hpke wire")?;
    assert!(hpke.len() < Channel::LIMIT);
    let mut over = hpke.as_bytes().to_vec();
    over.resize(Channel::LIMIT + 1, b' ');
    assert_eq!(Channel::from_wire_bytes(&over).err(), Some(WireError::Size));
    over.truncate(Channel::LIMIT);
    assert_eq!(Channel::from_wire_bytes(&over).err(), Some(WireError::NonCanonical));
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the per-arm context-binding regression matrix together.
fn channel_contexts(all: &Value) -> TestResult {
    let fixture_values = fixture()?;
    let source = &fixture_values["transcript"];
    let (transcript_value, transcript) = transfer_transcript(source)?;
    let common = &transcript_value["initiator"]["common"];
    let digest = hash();

    let enrollment_context = decode_value::<Transcript>(source)?;
    let enrollment_common = &source["initiator"]["common"];
    let enrollment_proposal = signed(json!({
        "schema":"ramflux.identity.pairing.enrollment.v1",
        "version":1,
        "invitation_id":enrollment_common["invitation_id"],
        "transcript_hash":digest,
        "base_record_hash":enrollment_common["record_hash"],
        "base_epoch":enrollment_common["device_set_epoch"],
        "recipient_ref":source["responder"]["device_ref"],
        "branch_signing_key":source["responder"]["branch_key"],
        "agreement_key":source["responder"]["agreement_key"],
        "requested_role":"secondary",
        "capabilities":enrollment_common["capabilities"],
        "lease_expires_at":enrollment_common["lease_expires_at"],
        "display_name":source["responder"]["display_name"]
    }));
    let enrollment = channel(
        enrollment_common,
        &digest,
        json!({"kind":"enrollment","proposal":enrollment_proposal}),
    );
    let mut enroll_context =
        context(&enrollment_context, &digest, "responder", "mutually_confirmed", None, None);
    decode_value::<Channel>(&enrollment)?.validate_context(&enroll_context)?;
    for (path, value, error) in [
        (
            "/payload/proposal/body/base_record_hash",
            json!(encode_base64url([2; 32])),
            "proposal_head",
        ),
        ("/payload/proposal/body/base_epoch", json!(1), "proposal_head"),
        (
            "/payload/proposal/body/recipient_ref/device_id",
            json!("other-device"),
            "proposal_context",
        ),
        (
            "/payload/proposal/body/branch_signing_key",
            json!(encode_base64url([2; 32])),
            "proposal_context",
        ),
        (
            "/payload/proposal/body/agreement_key",
            json!(encode_base64url([2; 32])),
            "proposal_context",
        ),
        ("/payload/proposal/body/capabilities", json!(["call"]), "proposal_context"),
        (
            "/payload/proposal/body/lease_expires_at",
            json!(enrollment_common["lease_expires_at"].as_u64().ok_or("lease")? - 1),
            "proposal_context",
        ),
        (
            "/payload/proposal/body/display_name",
            json!("different safe display name"),
            "proposal_context",
        ),
    ] {
        let mut wrong = enrollment.clone();
        *wrong.pointer_mut(path).ok_or("enrollment field")? = value;
        assert_eq!(
            decode_value::<Channel>(&wrong)?.validate_context(&enroll_context),
            Err(WireError::Field(error)),
            "{path}"
        );
    }
    enroll_context.sender = "initiator";
    assert_eq!(
        decode_value::<Channel>(&enrollment)?.validate_context(&enroll_context),
        Err(WireError::Field("channel_role"))
    );
    enroll_context.sender = "responder";
    enroll_context.phase = "proposal_pending";
    assert_eq!(
        decode_value::<Channel>(&enrollment)?.validate_context(&enroll_context),
        Err(WireError::Field("channel_phase"))
    );
    let wrong_purpose = channel(common, &digest, enrollment["payload"].clone());
    let transfer_proposal = wrong_purpose.clone();
    assert_eq!(
        decode_value::<Channel>(&transfer_proposal)?.validate_context(&context(
            &transcript,
            &digest,
            "responder",
            "mutually_confirmed",
            None,
            None,
        )),
        Err(WireError::Field("channel_purpose"))
    );

    let hpke_chunk = channel(
        common,
        &digest,
        json!({"kind":"artifact_chunk","object_kind":"hpke","object_id":common["transfer_id"],"index":0,"count":1,"total_bytes":1,"bytes":encode_base64url([1])}),
    );
    let mut c = context(&transcript, &digest, "initiator", "mutually_confirmed", None, None);
    decode_value::<Channel>(&hpke_chunk)?.validate_context(&c)?;
    let mut wrong = hpke_chunk.clone();
    wrong["payload"]["object_id"] = json!(encode_base64url([2; 32]));
    assert_eq!(
        decode_value::<Channel>(&wrong)?.validate_context(&c),
        Err(WireError::Field("artifact_context"))
    );
    c.sender = "responder";
    assert_eq!(
        decode_value::<Channel>(&hpke_chunk)?.validate_context(&c),
        Err(WireError::Field("artifact_context"))
    );
    c.sender = "initiator";
    c.phase = "acknowledged";
    assert_eq!(
        decode_value::<Channel>(&hpke_chunk)?.validate_context(&c),
        Err(WireError::Field("channel_phase"))
    );
    let candidate_chunk = channel(
        common,
        &digest,
        json!({"kind":"artifact_chunk","object_kind":"candidate","object_id":common["invitation_id"],"index":0,"count":1,"total_bytes":1,"bytes":encode_base64url([1])}),
    );
    c.sender = "responder";
    c.phase = "prepared";
    c.record_hash = Some(&digest);
    decode_value::<Channel>(&candidate_chunk)?.validate_context(&c)?;
    let mut wrong = candidate_chunk.clone();
    wrong["payload"]["object_id"] = json!(encode_base64url([2; 32]));
    assert_eq!(
        decode_value::<Channel>(&wrong)?.validate_context(&c),
        Err(WireError::Field("artifact_context"))
    );

    let approval = channel(
        common,
        &digest,
        json!({"kind":"approval","proposal_hash":digest,"base_record_hash":common["record_hash"],"base_epoch":common["device_set_epoch"],"approved":true}),
    );
    let mut c = context(&transcript, &digest, "initiator", "proposal_pending", None, None);
    decode_value::<Channel>(&approval)?.validate_context(&c)?;
    for (path, value, error) in [
        ("/payload/proposal_hash", json!(encode_base64url([2; 32])), "proposal_hash"),
        ("/payload/base_record_hash", json!(encode_base64url([2; 32])), "approval_head"),
        ("/payload/base_epoch", json!(1), "approval_head"),
    ] {
        let mut wrong = approval.clone();
        *wrong.pointer_mut(path).ok_or("approval field")? = value;
        assert_eq!(
            decode_value::<Channel>(&wrong)?.validate_context(&c),
            Err(WireError::Field(error))
        );
    }
    c.sender = "responder";
    assert_eq!(
        decode_value::<Channel>(&approval)?.validate_context(&c),
        Err(WireError::Field("channel_role"))
    );
    c.sender = "initiator";
    c.phase = "prepared";
    assert_eq!(
        decode_value::<Channel>(&approval)?.validate_context(&c),
        Err(WireError::Field("channel_phase"))
    );
    c.phase = "proposal_pending";
    c.proposal_hash = None;
    assert_eq!(
        decode_value::<Channel>(&approval)?.validate_context(&c),
        Err(WireError::Field("proposal_hash"))
    );

    let candidate = channel(
        common,
        &digest,
        json!({"kind":"candidate_ready","transfer_id":common["transfer_id"],"record_hash":digest,"compacted_ids_hash":null}),
    );
    let mut c = context(&transcript, &digest, "responder", "prepared", Some(&digest), None);
    decode_value::<Channel>(&candidate)?.validate_context(&c)?;
    for (path, value, error) in [
        ("/payload/transfer_id", json!(encode_base64url([2; 32])), "transfer_id"),
        ("/payload/record_hash", json!(encode_base64url([2; 32])), "record_hash"),
    ] {
        let mut wrong = candidate.clone();
        *wrong.pointer_mut(path).ok_or("candidate field")? = value;
        assert_eq!(
            decode_value::<Channel>(&wrong)?.validate_context(&c),
            Err(WireError::Field(error))
        );
    }
    c.compacted_ids_hash = Some(&digest);
    assert_eq!(
        decode_value::<Channel>(&candidate)?.validate_context(&c),
        Err(WireError::Field("compacted_ids_hash"))
    );

    let published = channel(
        common,
        &digest,
        json!({"kind":"published","operation_id":digest,"record_hash":digest,"device_set_epoch":MAX_SAFE_JSON_INTEGER,"recipient_ref":transcript_value["responder"]["device_ref"]}),
    );
    let mut c = context(&transcript, &digest, "initiator", "acknowledged", Some(&digest), None);
    decode_value::<Channel>(&published)?.validate_context(&c)?;
    for (path, value, error) in [
        ("/payload/operation_id", json!(encode_base64url([2; 32])), "operation_binding"),
        ("/payload/record_hash", json!(encode_base64url([2; 32])), "record_hash"),
        ("/payload/recipient_ref/device_epoch", json!(2), "recipient_ref"),
        ("/payload/device_set_epoch", json!(MAX_SAFE_JSON_INTEGER - 1), "published_epoch"),
    ] {
        let mut wrong = published.clone();
        *wrong.pointer_mut(path).ok_or("published field")? = value;
        assert_eq!(
            decode_value::<Channel>(&wrong)?.validate_context(&c),
            Err(WireError::Field(error))
        );
    }
    c.phase = "prepared";
    assert_eq!(
        decode_value::<Channel>(&published)?.validate_context(&c),
        Err(WireError::Field("channel_phase"))
    );

    let completed = channel(
        common,
        &digest,
        json!({"kind":"completed","operation_id":digest,"record_hash":digest,"cleanup":"done"}),
    );
    let mut c = context(&transcript, &digest, "initiator", "completed", Some(&digest), None);
    decode_value::<Channel>(&completed)?.validate_context(&c)?;
    for path in ["/payload/operation_id", "/payload/record_hash"] {
        let mut wrong = completed.clone();
        *wrong.pointer_mut(path).ok_or("completed field")? = json!(encode_base64url([2; 32]));
        assert_eq!(
            decode_value::<Channel>(&wrong)?.validate_context(&c),
            Err(WireError::Field(if path.ends_with("operation_id") {
                "operation_binding"
            } else {
                "record_hash"
            }))
        );
    }

    let installed = channel(
        common,
        &digest,
        json!({"kind":"installed","operation_id":digest,"record_hash":digest,"recipient_ref":transcript_value["responder"]["device_ref"]}),
    );
    c = context(&transcript, &digest, "responder", "locally_installed", Some(&digest), None);
    decode_value::<Channel>(&installed)?.validate_context(&c)?;
    let mut wrong = installed;
    wrong["payload"]["recipient_ref"]["device_id"] = json!("other");
    assert_eq!(
        decode_value::<Channel>(&wrong)?.validate_context(&c),
        Err(WireError::Field("recipient_ref"))
    );

    // Invitation/transcript are checked before payload-specific contexts.
    let mut wrong = approval.clone();
    wrong["invitation_id"] = json!(encode_base64url([2; 32]));
    assert_eq!(
        decode_value::<Channel>(&wrong)?.validate_context(&c),
        Err(WireError::Field("channel_invitation"))
    );
    let mut wrong = approval;
    wrong["transcript_hash"] = json!(encode_base64url([2; 32]));
    assert_eq!(
        decode_value::<Channel>(&wrong)?.validate_context(&c),
        Err(WireError::Field("channel_transcript"))
    );
    let _ = all;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keeps codec-level and frozen-context preservation rows adjacent.
fn preservation_contexts(all: &Value) -> TestResult {
    let fixture_values = fixture()?;
    let source = &fixture_values["transcript"];
    let (transcript_value, transcript) = transfer_transcript(source)?;
    let common = &transcript_value["initiator"]["common"];
    let digest = hash();
    let preservation = json!({
        "schema":"ramflux.identity.transfer.preserve.v1",
        "version":1,
        "transfer_id":common["transfer_id"],
        "transcript_hash":digest,
        "old_record_hash":common["record_hash"],
        "new_record_hash":digest,
        "destination_ref":transcript_value["responder"]["device_ref"],
        "recipient_mode":common["recipient_mode"],
        "policy":"preserve_all_existing",
        "expires_at":common["expires_at"]
    });
    let ready = channel(
        common,
        &digest,
        json!({"kind":"transfer_ready","transfer_id":common["transfer_id"],"record_hash":digest,"compacted_ids_hash":null,"preservation":signed(preservation)}),
    );
    let mut c = context(&transcript, &digest, "initiator", "prepared", Some(&digest), None);
    decode_value::<Channel>(&ready)?.validate_context(&c)?;

    for (path, value, error) in [
        (
            "/payload/preservation/body/transfer_id",
            json!(encode_base64url([2; 32])),
            "preservation_binding",
        ),
        (
            "/payload/preservation/body/new_record_hash",
            json!(encode_base64url([2; 32])),
            "preservation_binding",
        ),
        (
            "/payload/preservation/body/transcript_hash",
            json!(encode_base64url([2; 32])),
            "preservation_transcript",
        ),
        (
            "/payload/preservation/body/old_record_hash",
            json!(encode_base64url([2; 32])),
            "preservation_context",
        ),
        (
            "/payload/preservation/body/destination_ref/device_id",
            json!("foreign"),
            "preservation_context",
        ),
        ("/payload/preservation/body/recipient_mode", json!("existing"), "preservation_context"),
        (
            "/payload/preservation/body/expires_at",
            json!(common["expires_at"].as_u64().ok_or("expiry")? + 1),
            "preservation_context",
        ),
    ] {
        let mut wrong = ready.clone();
        *wrong.pointer_mut(path).ok_or("preservation field")? = value;
        if matches!(error, "preservation_binding" | "preservation_transcript") {
            assert_eq!(
                decode_value::<Channel>(&wrong).err(),
                Some(WireError::Field(error)),
                "{path}"
            );
        } else {
            assert_eq!(
                decode_value::<Channel>(&wrong)?.validate_context(&c),
                Err(WireError::Field(error)),
                "{path}"
            );
        }
    }
    c.phase = "proposal_pending";
    assert_eq!(
        decode_value::<Channel>(&ready)?.validate_context(&c),
        Err(WireError::Field("channel_phase"))
    );

    // PreservationBody's byte ceiling is conservative and unreachable under
    // its closed fixed-field grammar; exercise its full integer range and each
    // enum/hash/ref cap directly instead of manufacturing padded pseudo-input.
    let body = ready["payload"]["preservation"]["body"].clone();
    decode_value::<PreservationBody>(&body)?;
    let mut maximum = body.clone();
    maximum["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    maximum["destination_ref"]["device_id"] = json!("x".repeat(128));
    maximum["destination_ref"]["device_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    decode_value::<PreservationBody>(&maximum)?;
    field::<PreservationBody>(
        &maximum,
        "/destination_ref/device_id",
        json!("x".repeat(129)),
        "ref.device_id",
    )?;
    invalid::<PreservationBody>(
        &maximum,
        "/destination_ref/device_epoch",
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;
    for key in ["transfer_id", "transcript_hash", "old_record_hash", "new_record_hash"] {
        field::<PreservationBody>(&body, &format!("/{key}"), json!("bad"), key)?;
    }
    field::<PreservationBody>(&body, "/recipient_mode", json!("fresh"), "recipient_mode")?;
    field::<PreservationBody>(&body, "/policy", json!("discard"), "policy")?;
    invalid::<PreservationBody>(
        &body,
        "/expires_at",
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;
    let _ = all;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep independent envelope-bound and context cases together.
fn binding_and_hpke_contexts(all: &Value) -> TestResult {
    let maximum = independent::<HpkeEnvelope>(all, "HpkeEnvelopeMax")?;
    assert_eq!(bytes(&maximum)?.len(), HpkeEnvelope::LIMIT);
    let maximum_binding = maximum["sender_binding"]["body"].clone();
    let maximum_binding_typed = decode_value::<TransferBinding>(&maximum_binding)?;
    assert_eq!(maximum_binding_typed.sender_device_ref.device_id.len(), 128);
    assert_eq!(maximum_binding_typed.sender_device_ref.device_epoch, MAX_SAFE_JSON_INTEGER);
    for (path, error) in [
        ("/transfer_id", "transfer_id"),
        ("/transcript_hash", "transcript_hash"),
        ("/current_record_hash", "current_record_hash"),
        ("/sender_hpke_key", "sender_hpke_key"),
        ("/recipient_hpke_key", "recipient_hpke_key"),
    ] {
        field::<TransferBinding>(&maximum_binding, path, json!("bad"), error)?;
    }
    field::<TransferBinding>(
        &maximum_binding,
        "/sender_device_ref/device_id",
        json!("x".repeat(129)),
        "ref.device_id",
    )?;
    field::<TransferBinding>(
        &maximum_binding,
        "/sender_device_ref/device_epoch",
        json!(0),
        "ref.device_epoch",
    )?;
    let mut one_over = bytes(&maximum)?;
    one_over.push(b' ');
    assert_eq!(HpkeEnvelope::from_wire_bytes(&one_over).err(), Some(WireError::Size));

    let fixture_values = fixture()?;
    let mut source = fixture_values["transcript"].clone();
    source["initiator"]["common"]["expires_at"] = json!(MAX_SAFE_JSON_INTEGER - 1);
    source["initiator"]["common"]["device_set_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    source["responder"]["common"] = source["initiator"]["common"].clone();
    let (transcript_value, transcript) = transfer_transcript(&source)?;
    let common = &transcript_value["initiator"]["common"];
    let digest = hash();
    let binding = json!({
        "schema":"ramflux.identity.transfer_binding.v1",
        "version":1,
        "transfer_id":common["transfer_id"],
        "transcript_hash":digest,
        "current_record_hash":common["record_hash"],
        "device_set_epoch":MAX_SAFE_JSON_INTEGER,
        "sender_device_ref":transcript_value["initiator"]["device_ref"],
        "sender_hpke_key":transcript_value["initiator"]["hpke_key"],
        "recipient_hpke_key":transcript_value["responder"]["hpke_key"],
        "issued_at":MAX_SAFE_JSON_INTEGER - 301,
        "expires_at":MAX_SAFE_JSON_INTEGER - 1
    });
    let envelope = json!({
        "schema":"ramflux.identity.transfer.hpke.v1",
        "version":1,
        "transfer_id":common["transfer_id"],
        "transcript_hash":digest,
        "current_record_hash":common["record_hash"],
        "device_set_epoch":MAX_SAFE_JSON_INTEGER,
        "sender_binding":signed(binding),
        "enc":hash(),
        "ciphertext":encode_base64url([0;16])
    });
    decode_value::<TransferBinding>(&envelope["sender_binding"]["body"])?;
    decode_value::<HpkeEnvelope>(&envelope)?.validate_context(&transcript, &digest)?;

    let mut late = envelope.clone();
    late["sender_binding"]["body"]["issued_at"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    late["sender_binding"]["body"]["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    decode_value::<TransferBinding>(&late["sender_binding"]["body"])?;
    field::<TransferBinding>(
        &late["sender_binding"]["body"],
        "/issued_at",
        json!(MAX_SAFE_JSON_INTEGER - 301),
        "binding_lifetime",
    )?;
    invalid::<TransferBinding>(
        &late["sender_binding"]["body"],
        "/expires_at",
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;

    for (path, binding_path, value) in [
        ("/transfer_id", "/sender_binding/body/transfer_id", json!(encode_base64url([2; 32]))),
        (
            "/transcript_hash",
            "/sender_binding/body/transcript_hash",
            json!(encode_base64url([2; 32])),
        ),
        (
            "/current_record_hash",
            "/sender_binding/body/current_record_hash",
            json!(encode_base64url([2; 32])),
        ),
        (
            "/device_set_epoch",
            "/sender_binding/body/device_set_epoch",
            json!(MAX_SAFE_JSON_INTEGER - 1),
        ),
    ] {
        let mut wrong = envelope.clone();
        *wrong.pointer_mut(path).ok_or("envelope context")? = value.clone();
        *wrong.pointer_mut(binding_path).ok_or("binding context")? = value;
        assert_eq!(
            decode_value::<HpkeEnvelope>(&wrong)?.validate_context(&transcript, &digest),
            Err(WireError::Field("hpke_context")),
            "{path}"
        );
    }
    for (path, value, error) in [
        ("/sender_binding/body/transfer_id", json!(encode_base64url([2; 32])), "hpke_binding"),
        ("/sender_binding/body/transcript_hash", json!(encode_base64url([2; 32])), "hpke_binding"),
        (
            "/sender_binding/body/current_record_hash",
            json!(encode_base64url([2; 32])),
            "hpke_binding",
        ),
        ("/sender_binding/body/device_set_epoch", json!(MAX_SAFE_JSON_INTEGER - 1), "hpke_binding"),
        ("/sender_binding/body/sender_device_ref/device_id", json!("foreign"), "hpke_keys"),
        ("/sender_binding/body/sender_hpke_key", json!(encode_base64url([9; 32])), "hpke_keys"),
        ("/sender_binding/body/recipient_hpke_key", json!(encode_base64url([9; 32])), "hpke_keys"),
    ] {
        let mut wrong = envelope.clone();
        *wrong.pointer_mut(path).ok_or("binding context")? = value;
        if error == "hpke_binding" {
            assert_eq!(
                decode_value::<HpkeEnvelope>(&wrong).err(),
                Some(WireError::Field(error)),
                "{path}"
            );
        } else {
            assert_eq!(
                decode_value::<HpkeEnvelope>(&wrong)?.validate_context(&transcript, &digest),
                Err(WireError::Field(error)),
                "{path}"
            );
        }
    }
    let mut beyond = envelope.clone();
    beyond["sender_binding"]["body"]["issued_at"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    beyond["sender_binding"]["body"]["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    assert_eq!(
        decode_value::<HpkeEnvelope>(&beyond)?.validate_context(&transcript, &digest),
        Err(WireError::Field("hpke_expiry"))
    );
    field::<HpkeEnvelope>(
        &envelope,
        "/ciphertext",
        json!(encode_base64url([0; 15])),
        "ciphertext",
    )?;

    // The ciphertext field's 1,048,592-byte raw ceiling is not independently
    // reachable: the closed envelope's 819,200-byte encoded-object cap is
    // tighter. The independent object fixture pins the whole-object maximum.
    let _ = all;
    Ok(())
}
