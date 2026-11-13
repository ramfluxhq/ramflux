// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Received-byte local boundary vectors and independently serialized size witnesses.
use super::*;
use crate::custody::pairing::{channel::*, local_dto::*};

fn maxima() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../fixtures/pairing_v2/channel_local/maxima.json"
    ))?)
}
fn independent_bytes<T: PairingWire>(all: &Value, key: &str) -> TestResult<Value> {
    let wire = all[key]["wire"].as_str().ok_or("missing independent bytes")?.as_bytes();
    assert_eq!(wire.len() as u64, all[key]["size"].as_u64().ok_or("missing size")?);
    assert_eq!(T::from_wire_bytes(wire)?.to_wire_bytes()?, wire, "{key}");
    let typed = T::from_wire_bytes(wire)?;
    let cap = typed.received_limit();
    let mut padded = wire.to_vec();
    padded.resize(cap, b' ');
    assert_eq!(
        T::from_wire_bytes(&padded).err(),
        Some(WireError::NonCanonical),
        "{key} at input cap"
    );
    padded.push(b' ');
    assert_eq!(T::from_wire_bytes(&padded).err(), Some(WireError::Size), "{key} over input cap");
    let value: Value = serde_json::from_slice(wire)?;
    for secret in ["passphrase", "confirmation", "provider_handle"] {
        let mut wrong = value.clone();
        wrong[secret] = json!("synthetic");
        assert_eq!(decode_value::<T>(&wrong).err(), Some(WireError::Shape), "{key}/{secret}");
    }
    Ok(value)
}
fn witness<T: PairingWire>(all: &Value, key: &str) -> TestResult<Value> {
    let value = independent_bytes::<T>(all, key)?;
    nested_shapes::<T>(&value)?;
    Ok(value)
}
fn b32_vectors<T: PairingWire>(value: &Value, path: &str, error: &'static str) -> TestResult {
    for bad in [
        json!("A".repeat(42)),
        json!("A".repeat(44)),
        json!(format!("{}B", "A".repeat(42))),
        json!("+".repeat(43)),
    ] {
        field::<T>(value, path, bad, error)?;
    }
    Ok(())
}
fn local_base_vectors<T: PairingWire>(v: &Value) -> TestResult {
    b32_vectors::<T>(v, "/operation_id", "operation_id")?;
    field::<T>(v, "/generation", json!(0), "generation")?;
    invalid::<T>(v, "/generation", json!(MAX_SAFE_JSON_INTEGER + 1), WireError::Json)?;
    let mut low = v.clone();
    low["generation"] = json!(1);
    decode_value::<T>(&low)?;
    Ok(())
}
fn rights_vectors<T: PairingWire>(v: &Value) -> TestResult {
    for caps in [
        json!([]),
        json!(["call", "call"]),
        json!(["sync", "call"]),
        json!(["unknown"]),
        json!(["call", "group", "message", "register", "sync", "sync"]),
    ] {
        field::<T>(v, "/capabilities", caps, "capabilities")?;
    }
    for key in ["lease_not_before", "lease_expires_at"] {
        invalid::<T>(v, &format!("/{key}"), json!(MAX_SAFE_JSON_INTEGER + 1), WireError::Json)?;
    }
    let mut low = v.clone();
    low["lease_not_before"] = json!(0);
    low["lease_expires_at"] = json!(1);
    low["capabilities"] = json!(["call"]);
    decode_value::<T>(&low)?;
    low["lease_expires_at"] = json!(MAX_BRANCH_LEASE_SECONDS);
    decode_value::<T>(&low)?;
    field::<T>(&low, "/lease_expires_at", json!(MAX_BRANCH_LEASE_SECONDS + 1), "lease")?;
    field::<T>(v, "/lease_expires_at", v["lease_not_before"].clone(), "lease")?;
    for end in [0, MAX_SAFE_JSON_INTEGER - 301] {
        field::<T>(v, "/lease_expires_at", json!(end), "lease")?;
    }
    Ok(())
}
fn name_vectors<T: PairingWire>(v: &Value, path: &str) -> TestResult {
    for text in [String::new(), "x".repeat(128), "é".repeat(64)] {
        let mut valid = v.clone();
        *valid.pointer_mut(path).ok_or("name path")? = json!(text);
        decode_value::<T>(&valid)?;
    }
    for text in ["x".repeat(129), "é".repeat(64) + "x", "\u{202e}".into()] {
        field::<T>(v, path, json!(text), "display_name")?;
    }
    Ok(())
}
#[test]
fn pairing_local_bounds_and_independent_maxima() -> TestResult {
    let all = maxima()?;
    local_begin_vectors(&all)?;
    local_request_vectors(&all)?;
    local_result_vectors(&all)?;
    witness::<LocalEvent>(&all, "LocalEvent")?;
    credential_request_vectors(&witness::<CredentialRequest>(&all, "CredentialRequest")?)?;
    // Keep the independent collection-size witness separate from per-field
    // shape/context vectors, avoiding repeated shape mutations at256 identical
    // reference layouts.
    independent_bytes::<TransferPayload>(&all, "TransferPayload")?;
    witness::<Channel>(&all, "Channel_hpke")?;
    witness::<Channel>(&all, "Channel_candidate")?;
    witness::<Update>(&all, "Update_installed")?;
    witness::<Update>(&all, "Update_terminal")?;
    update_vectors(&witness::<Update>(&all, "Update")?)?;
    Ok(())
}
fn local_begin_vectors(all: &Value) -> TestResult {
    let begin = witness::<Begin>(all, "Begin")?;
    rights_vectors::<Begin>(&begin)?;
    name_vectors::<Begin>(&begin, "/display_name")?;
    let transfer = witness::<TransferBegin>(all, "TransferBegin")?;
    rights_vectors::<TransferBegin>(&transfer)?;
    name_vectors::<TransferBegin>(&transfer, "/display_name")?;
    field::<TransferBegin>(&transfer, "/recipient_mode", json!("other"), "recipient_mode")?;
    field::<TransferBegin>(&transfer, "/destination_ref", Value::Null, "destination_ref")?;
    reference_vectors::<TransferBegin>(&transfer, "/destination_ref")?;
    let mut new = transfer.clone();
    new["recipient_mode"] = json!("new");
    new["destination_ref"] = Value::Null;
    new["data_selection"] = json!([]);
    decode_value::<TransferBegin>(&new)?;
    field::<TransferBegin>(
        &new,
        "/destination_ref",
        transfer["destination_ref"].clone(),
        "destination_ref",
    )?;
    for path in ["/destination_ref/account_anchor", "/destination_ref/device_id"] {
        field::<TransferBegin>(
            &transfer,
            path,
            json!(""),
            if path.ends_with("account_anchor") { "ref.account_anchor" } else { "ref.device_id" },
        )?;
    }
    field::<TransferBegin>(
        &transfer,
        "/destination_ref/device_id",
        json!("x".repeat(129)),
        "ref.device_id",
    )?;
    field::<TransferBegin>(
        &transfer,
        "/destination_ref/device_epoch",
        json!(0),
        "ref.device_epoch",
    )?;
    invalid::<TransferBegin>(
        &transfer,
        "/destination_ref/device_epoch",
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;
    let mut single = transfer.clone();
    single["data_selection"] = json!([transfer["data_selection"][0]]);
    for (path, value, error) in [
        ("/data_selection/0/key_id", json!(""), "selection.key_id"),
        ("/data_selection/0/key_id", json!("x".repeat(129)), "selection.key_id"),
        ("/data_selection/0/key_id", json!("\n"), "selection.key_id"),
        ("/data_selection/0/purpose", json!("other"), "selection.purpose"),
    ] {
        field::<TransferBegin>(&single, path, value, error)?;
    }
    let mut selection = transfer["data_selection"].as_array().ok_or("selection")?.clone();
    selection.swap(0, 1);
    field::<TransferBegin>(&transfer, "/data_selection", json!(selection), "data_selection")?;
    selection.swap(0, 1);
    selection[1] = selection[0].clone();
    field::<TransferBegin>(&transfer, "/data_selection", json!(selection), "data_selection")?;
    let join = witness::<Join>(all, "Join")?;
    name_vectors::<Join>(&join, "/display_name")?;
    Ok(())
}
fn local_request_vectors(all: &Value) -> TestResult {
    macro_rules! request {
        ($ty:ty,$key:literal,$($hash:literal),*) => {{
            let v = witness::<$ty>(all,$key)?;
            local_base_vectors::<$ty>(&v)?;
            $(b32_vectors::<$ty>(&v,$hash, &$hash[1..])?;)*
        }};
    }
    request!(Confirm, "Confirm", "/transcript_hash");
    request!(Approve, "Approve", "/transcript_hash", "/proposal_hash");
    request!(Prepare, "Prepare", "/transcript_hash");
    request!(Cancel, "Cancel",);
    request!(StatusRequest, "StatusRequest",);
    let br = witness::<BeginResult>(all, "BeginResult")?;
    local_base_vectors::<BeginResult>(&br)?;
    field::<BeginResult>(
        &br,
        "/operation_id",
        json!(encode_base64url([9; 32])),
        "operation_binding",
    )?;
    field::<BeginResult>(&br, "/expires_at", json!(0), "expiry_binding")?;
    invalid::<BeginResult>(&br, "/expires_at", json!(MAX_SAFE_JSON_INTEGER + 1), WireError::Json)?;
    Ok(())
}
fn local_result_vectors(all: &Value) -> TestResult {
    for tag in ["begin", "update", "error"] {
        let value = witness::<LocalResult>(all, &format!("LocalResult_{tag}"))?;
        invalid::<LocalResult>(&value, "/outcome/tag", json!("other"), WireError::Shape)?;
        let result = decode_value::<LocalResult>(&value)?;
        for method in [
            "pair.begin",
            "transfer.begin",
            "pair.join",
            "transfer.join",
            "pair.confirm",
            "pair.approve",
            "pair.cancel",
            "pair.status",
            "transfer.prepare",
            "transfer.confirm",
            "transfer.cancel",
            "transfer.status",
        ] {
            let expected = if tag == "error"
                || (tag == "begin") == matches!(method, "pair.begin" | "transfer.begin")
            {
                Ok(())
            } else {
                Err(WireError::Field("result_method"))
            };
            assert_eq!(result.validate_method(method), expected, "{tag}/{method}");
        }
        assert_eq!(result.validate_method("other"), Err(WireError::Field("method")));
        let cap = match tag {
            "begin" => 18_432,
            "update" => 4608,
            _ => 1024,
        };
        let mut wire = bytes(&value)?;
        wire.resize(cap, b' ');
        assert_eq!(LocalResult::from_wire_bytes(&wire).err(), Some(WireError::NonCanonical));
        wire.push(b' ');
        assert_eq!(LocalResult::from_wire_bytes(&wire).err(), Some(WireError::Size));
    }
    Ok(())
}

fn update_vectors(v: &Value) -> TestResult {
    local_base_vectors::<Update>(v)?;
    rights_vectors::<Update>(v)?;
    name_vectors::<Update>(v, "/peer_name")?;
    invalid::<Update>(v, "/expires_at", json!(MAX_SAFE_JSON_INTEGER + 1), WireError::Json)?;
    for key in ["transcript_hash", "proposal_hash", "record_hash"] {
        b32_vectors::<Update>(v, &format!("/{key}"), key)?;
    }
    field::<Update>(v, "/phase", json!("other"), "phase")?;
    field::<Update>(v, "/cleanup", json!("other"), "cleanup")?;
    field::<Update>(v, "/result", json!("other"), "code")?;
    field::<Update>(v, "/peer_name", Value::Null, "peer_fields")?;
    field::<Update>(v, "/peer_ref", Value::Null, "peer_fields")?;
    reference_vectors::<Update>(v, "/peer_ref")?;

    for indices in [json!([]), json!(vec![0; 6]), json!(vec![0; 8]), json!([64, 0, 0, 0, 0, 0, 0])]
    {
        field::<Update>(v, "/emoji_indices", indices, "emoji_indices")?;
    }
    update_phase_vectors(v)
}
fn update_phase_vectors(v: &Value) -> TestResult {
    for (i, phase) in PHASES.iter().enumerate() {
        let mut current = v.clone();
        current["phase"] = json!(phase);
        current["emoji_indices"] = Value::Null;
        if i < 2 {
            current["transcript_hash"] = Value::Null;
            current["peer_ref"] = Value::Null;
            current["peer_name"] = Value::Null;
        }
        current["proposal_hash"] =
            if i >= 5 { json!(encode_base64url([1; 32])) } else { Value::Null };
        current["record_hash"] =
            if i >= 6 { json!(encode_base64url([1; 32])) } else { Value::Null };
        current["result"] = if i >= 11 { json!("Expired") } else { Value::Null };
        if i >= 10 {
            let mut cleared = current.clone();
            for key in ["transcript_hash", "peer_ref", "peer_name", "proposal_hash", "record_hash"]
            {
                cleared[key] = Value::Null;
            }
            decode_value::<Update>(&cleared)?;
        }
        let mut pending = current.clone();
        pending["result"] = json!("PublicationPending");
        decode_value::<Update>(&pending)?;
        for cleanup in ["none", "pending", "done"] {
            current["cleanup"] = json!(cleanup);
            decode_value::<Update>(&current)?;
        }
        if i < 10 {
            field::<Update>(
                &current,
                "/transcript_hash",
                if i < 2 { json!(encode_base64url([1; 32])) } else { Value::Null },
                "phase_transcript",
            )?;
            let mut peer = current.clone();
            peer["peer_ref"] = if i < 2 { v["peer_ref"].clone() } else { Value::Null };
            peer["peer_name"] = if i < 2 { v["peer_name"].clone() } else { Value::Null };
            assert_eq!(decode_value::<Update>(&peer).err(), Some(WireError::Field("phase_peer")));
        }
        if i < 5 {
            field::<Update>(
                &current,
                "/proposal_hash",
                json!(encode_base64url([1; 32])),
                "phase_proposal",
            )?;
        }
        if i < 6 {
            field::<Update>(
                &current,
                "/record_hash",
                json!(encode_base64url([1; 32])),
                "phase_record",
            )?;
        }
        if i < 11 {
            field::<Update>(&current, "/result", json!("Expired"), "phase_result")?;
        } else {
            field::<Update>(&current, "/result", Value::Null, "terminal_result")?;
        }
        if matches!(*phase, "sas_pending" | "mutually_confirmed") {
            for indices in [vec![0; 7], vec![63; 7]] {
                current["emoji_indices"] = json!(indices);
                decode_value::<Update>(&current)?;
            }
        } else {
            field::<Update>(
                &current,
                "/emoji_indices",
                json!([0, 0, 0, 0, 0, 0, 0]),
                "phase_emoji",
            )?;
        }
    }
    Ok(())
}

fn reference_vectors<T: PairingWire>(value: &Value, prefix: &str) -> TestResult {
    b32_vectors::<T>(value, &format!("{prefix}/account_anchor"), "ref.account_anchor")?;
    let mut minimum = value.clone();
    minimum.pointer_mut(prefix).ok_or("reference path")?["device_epoch"] = json!(1);
    decode_value::<T>(&minimum)?;
    for (name, bad, error) in [
        ("account_anchor", json!("bad"), "ref.account_anchor"),
        ("device_id", json!(""), "ref.device_id"),
        ("device_id", json!("x".repeat(129)), "ref.device_id"),
        ("device_id", json!("\n"), "ref.device_id"),
        ("device_epoch", json!(0), "ref.device_epoch"),
    ] {
        field::<T>(value, &format!("{prefix}/{name}"), bad, error)?;
    }
    invalid::<T>(
        value,
        &format!("{prefix}/device_epoch"),
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;
    for (name, text) in [("device_id", "x".into()), ("device_id", "é".repeat(64))] {
        let mut valid = value.clone();
        *valid.pointer_mut(&format!("{prefix}/{name}")).ok_or("reference path")? = json!(text);
        decode_value::<T>(&valid)?;
    }
    Ok(())
}
fn credential_request_vectors(value: &Value) -> TestResult {
    b32_vectors::<CredentialRequest>(value, "/reservation_id", "reservation_id")?;
    invalid::<CredentialRequest>(
        value,
        "/frontend_generation",
        json!(MAX_SAFE_JSON_INTEGER + 1),
        WireError::Json,
    )?;
    for account in ["x".to_owned(), "é".repeat(64)] {
        let mut valid = value.clone();
        valid["local_account_id"] = json!(account);
        decode_value::<CredentialRequest>(&valid)?;
    }
    let request = decode_value::<CredentialRequest>(value)?;
    for (confirmation, error) in [
        (b"".as_slice(), "credential_length"),
        (&[255], "credential_utf8"),
        (&vec![b'x'; 1025], "credential_length"),
    ] {
        assert_eq!(
            request.validate_input(
                &request,
                CredentialInput { passphrase: b"x", confirmation: Some(confirmation) }
            ),
            Err(WireError::Field(error))
        );
    }
    let mut unlock = value.clone();
    unlock["action"] = json!("unlock");
    let request = decode_value::<CredentialRequest>(&unlock)?;
    for n in [1, 1024] {
        request.validate_input(
            &request,
            CredentialInput { passphrase: &vec![b'x'; n], confirmation: None },
        )?;
    }
    Ok(())
}
