// SPDX-License-Identifier: BSD-3-Clause
// Copyright (common_value) 2026 Span Brain

use super::*;
use crate::custody::pairing::{channel::*, local_dto::*};
fn obj(name: &str, mut v: Value) -> Value {
    v["schema"] = json!(format!("ramflux.pairing.{name}.v2"));
    v["version"] = json!(2);
    v
}
fn hash() -> String {
    encode_base64url([1; 32])
}
fn signed(v: Value) -> Value {
    let mut value = json!({"signature":encode_base64url([7;64])});
    value["body"] = v;
    value
}
fn exact<T: PairingWire>(v: &Value) -> TestResult {
    closed::<T>(v)?;
    nested_shapes::<T>(v)?;
    for key in ["passphrase", "confirmation", "provider_handle"] {
        let mut bad = v.clone();
        bad[key] = json!("synthetic");
        assert_eq!(decode_value::<T>(&bad).err(), Some(WireError::Shape));
    }
    Ok(())
}
#[test]
fn pairing_channel_local_schemas_bind_each_field() -> TestResult {
    let fixture_values = fixture()?;
    let transcript_value = &fixture_values["transcript"];
    begin_cases(transcript_value)?;
    request_cases()?;
    result_cases(&fixture_values, transcript_value)?;
    channel_cases(transcript_value, &transcript_value["initiator"]["common"])?;
    credential_cases()?;
    local_bounds()?;
    transfer_cases(transcript_value)?;
    transfer_envelopes(transcript_value)?;
    transfer_contexts(transcript_value)?;
    Ok(())
}
fn begin_cases(transcript_value: &Value) -> TestResult {
    let begin = obj(
        "Begin",
        json!({"capabilities":["message"],"lease_not_before":0,"lease_expires_at":1,"display_name":""}),
    );
    exact::<Begin>(&begin)?;
    let mut transfer = begin.clone();
    transfer["schema"] = json!("ramflux.pairing.TransferBegin.v2");
    transfer["recipient_mode"] = json!("new");
    transfer["destination_ref"] = Value::Null;
    transfer["data_selection"] = json!([]);
    exact::<TransferBegin>(&transfer)?;
    for name in ["Begin", "TransferBegin"] {
        let mut v = if name == "Begin" { begin.clone() } else { transfer.clone() };
        v["display_name"] = json!("é".repeat(64));
        v["lease_not_before"] = json!(MAX_SAFE_JSON_INTEGER - 1);
        v["lease_expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
        if name == "Begin" {
            exact::<Begin>(&v)?;
            field::<Begin>(&v, "/display_name", json!("é".repeat(65)), "display_name")?;
        } else {
            exact::<TransferBegin>(&v)?;
        }
    }
    field::<Begin>(&begin, "/capabilities", json!([]), "capabilities")?;
    field::<Begin>(&begin, "/lease_expires_at", json!(0), "lease")?;
    field::<TransferBegin>(&transfer, "/recipient_mode", json!("other"), "recipient_mode")?;
    field::<TransferBegin>(
        &transfer,
        "/destination_ref",
        transcript_value["responder"]["device_ref"].clone(),
        "destination_ref",
    )?;
    let mut witness = transfer.clone();
    witness["display_name"] = json!("x".repeat(97));
    witness["data_selection"] = json!(
        (0..32)
            .map(|i| json!({"key_id":format!("{i:02}"),"purpose":"history"}))
            .collect::<Vec<_>>()
    );
    for index in 0..32 {
        while bytes(&witness)?.len() < 5490
            && witness["data_selection"][index]["key_id"].as_str().ok_or("id")?.len() < 128
        {
            let id =
                witness["data_selection"][index]["key_id"].as_str().ok_or("id")?.to_owned() + "x";
            witness["data_selection"][index]["key_id"] = json!(id);
        }
    }
    assert_eq!(bytes(&witness)?.len(), 5490);
    exact::<TransferBegin>(&witness)?;
    for escaped in [false, true] {
        let mut v = transfer.clone();
        v["recipient_mode"] = json!("existing");
        v["destination_ref"] = transcript_value["responder"]["device_ref"].clone();
        v["display_name"] = json!(r#"\""#.repeat(64));
        v["data_selection"]=json!((0..32).map(|i|json!({"key_id":format!("{i:02}{}",if escaped {r#"\""#.repeat(63)}else{"x".repeat(126)}),"purpose":"history"})).collect::<Vec<_>>());
        let wire = bytes(&v)?;
        assert!(wire.len() > 4096 && wire.len() < TransferBegin::LIMIT);
        exact::<TransferBegin>(&v)?;
        let mut bad = v.clone();
        bad["data_selection"]
            .as_array_mut()
            .ok_or("selection")?
            .push(json!({"key_id":"zz","purpose":"history"}));
        field::<TransferBegin>(
            &v,
            "/data_selection",
            bad["data_selection"].clone(),
            "data_selection",
        )?;
    }
    Ok(())
}
fn request_cases() -> TestResult {
    let digest_value = hash();
    let base = json!({"operation_id":digest_value,"generation":1});
    let mut requests = Vec::new();
    for name in ["Confirm", "Approve", "Prepare", "Cancel", "StatusRequest"] {
        let mut v = base.clone();
        if matches!(name, "Confirm" | "Approve" | "Prepare") {
            v["transcript_hash"] = json!(digest_value);
        }
        if name == "Confirm" {
            v["match"] = json!(true);
        }
        if name == "Approve" {
            v["proposal_hash"] = json!(digest_value);
            v["approved"] = json!(true);
        }
        let v = obj(name, v);
        requests.push(v.clone());
        macro_rules! case {
            ($ty:ty) => {{
                exact::<$ty>(&v)?;
                field::<$ty>(&v, "/generation", json!(0), "generation")?;
                let mut max = v.clone();
                max["generation"] = json!(MAX_SAFE_JSON_INTEGER);
                exact::<$ty>(&max)?;
            }};
        }
        match name {
            "Confirm" => case!(Confirm),
            "Approve" => case!(Approve),
            "Prepare" => case!(Prepare),
            "Cancel" => case!(Cancel),
            _ => case!(StatusRequest),
        }
    }
    Ok(())
}
fn result_cases(fixture_values: &Value, transcript_value: &Value) -> TestResult {
    let digest_value = hash();
    let update = obj(
        "Update",
        json!({"operation_id":digest_value,"generation":1,"phase":"invited","expires_at":0,"transcript_hash":null,"emoji_indices":null,"peer_ref":null,"peer_name":null,"capabilities":["message"],"lease_not_before":0,"lease_expires_at":1,"proposal_hash":null,"record_hash":null,"result":null,"cleanup":"none"}),
    );
    exact::<Update>(&update)?;
    for (tag, cap) in [("update", 4608), ("error", 1024)] {
        let outcome = if tag == "update" {
            json!({"tag":tag,"value":update})
        } else {
            json!({"tag":tag,"error":obj("Failure",json!({"code":"InvalidInput","retry_after_ms":null}))})
        };
        let value = obj("LocalResult", json!({"outcome":outcome}));
        let mut over = bytes(&value)?;
        over.resize(cap + 1, b' ');
        assert_eq!(LocalResult::from_wire_bytes(&over).err(), Some(WireError::Size));
    }
    let mut sas = update.clone();
    sas["phase"] = json!("sas_pending");
    sas["transcript_hash"] = json!(digest_value);
    sas["peer_ref"] = transcript_value["responder"]["device_ref"].clone();
    sas["peer_name"] = json!("Peer");
    sas["emoji_indices"] = json!([0, 63, 0, 63, 0, 63, 0]);
    exact::<Update>(&sas)?;
    field::<Update>(&sas, "/emoji_indices", json!([0, 0, 0, 0, 0, 0, 64]), "emoji_indices")?;
    field::<Update>(&sas, "/emoji_indices", json!([0, 0, 0, 0, 0, 0]), "emoji_indices")?;
    field::<Update>(&update, "/record_hash", json!(digest_value), "phase_record")?;
    field::<Update>(&update, "/proposal_hash", json!(digest_value), "phase_proposal")?;
    let invite = fixture_values["native_relay"]["invite_token"].clone();
    // Fixtures use the exact P01W token shape; construct from the signed invitation if absent.
    let invite = if invite.is_null() {
        obj(
            "InviteToken",
            json!({"invitation":signed(fixture_values["native_relay"]["invitation"].clone()),"recipient_token":encode_base64url([4;32])}),
        )
    } else {
        invite
    };
    let mut invite = invite;
    let invitation = &mut invite["invitation"]["body"];
    invitation["purpose"] = json!("primary_transfer");
    invitation["transfer_id"] = json!(hash());
    invitation["recipient_mode"] = json!("existing");
    invitation["destination_ref"] = transcript_value["responder"]["device_ref"].clone();
    invitation["destination_ref"]["device_id"] = json!(format!("r{}", r#"\""#.repeat(63)));
    invitation["primary_ref"]["device_id"] = json!(format!("i{}", r#"\""#.repeat(63)));
    invitation["data_selection"] = json!(
        (0..32)
            .map(
                |i| json!({"key_id":format!("{i:02}{}",r#"\""#.repeat(63)),"purpose":"attachment"})
            )
            .collect::<Vec<_>>()
    );
    invitation["capabilities"] = json!(["call", "group", "message", "register", "sync"]);
    invitation["base_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    invitation["issuer_seq"] = json!(MAX_SAFE_JSON_INTEGER);
    invitation["lease_not_before"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    invitation["lease_expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    invitation["created_at"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    invitation["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    let join = obj("Join", json!({"token":invite,"display_name":"Peer"}));
    exact::<Join>(&join)?;
    let br = obj(
        "BeginResult",
        json!({"operation_id":invite["invitation"]["body"]["request_id"],"generation":1,"expires_at":invite["invitation"]["body"]["expires_at"],"invite_token":invite}),
    );
    exact::<BeginResult>(&br)?;
    let result = obj("LocalResult", json!({"outcome":{"tag":"begin","value":br}}));
    exact::<LocalResult>(&result)?;
    decode_value::<LocalResult>(&result)?.validate_method("transfer.begin")?;
    assert_eq!(
        decode_value::<LocalResult>(&result)?.validate_method("pair.status"),
        Err(WireError::Field("result_method"))
    );
    exact::<LocalResult>(&obj("LocalResult", json!({"outcome":{"tag":"update","value":update}})))?;
    exact::<LocalResult>(&obj(
        "LocalResult",
        json!({"outcome":{"tag":"error","error":obj("Failure",json!({"code":"InvalidInput","retry_after_ms":null}))}}),
    ))?;
    exact::<LocalEvent>(&obj("LocalEvent", json!({"update":sas})))?;
    Ok(())
}
fn channel_cases(transcript_value: &Value, common_value: &Value) -> TestResult {
    let digest_value = hash();
    let transcript = decode_value::<Transcript>(transcript_value)?;
    let proposal = signed(
        json!({"schema":"ramflux.identity.pairing.enrollment.v1","version":1,"invitation_id":common_value["invitation_id"],"transcript_hash":digest_value,"base_record_hash":common_value["record_hash"],"base_epoch":common_value["device_set_epoch"],"recipient_ref":transcript_value["responder"]["device_ref"],"branch_signing_key":transcript_value["responder"]["branch_key"],"agreement_key":transcript_value["responder"]["agreement_key"],"requested_role":"secondary","capabilities":common_value["capabilities"],"lease_expires_at":common_value["lease_expires_at"],"display_name":transcript_value["responder"]["display_name"]}),
    );
    let make = |p| {
        obj(
            "Channel",
            json!({"invitation_id":common_value["invitation_id"],"transcript_hash":digest_value,"payload":p}),
        )
    };
    let mut ctx = ChannelContext {
        transcript: &transcript,
        transcript_hash: &digest_value,
        sender: "responder",
        phase: "mutually_confirmed",
        operation_id: &digest_value,
        proposal_hash: Some(&digest_value),
        record_hash: Some(&digest_value),
        record_epoch: Some(0),
        compacted_ids_hash: None,
    };
    let enrollment = make(json!({"kind":"enrollment","proposal":proposal}));
    exact::<Channel>(&enrollment)?;
    decode_value::<Channel>(&enrollment)?.validate_context(&ctx)?;
    ctx.sender = "initiator";
    assert_eq!(
        decode_value::<Channel>(&enrollment)?.validate_context(&ctx),
        Err(WireError::Field("channel_role"))
    );
    ctx.sender = "responder";
    ctx.phase = "submitted";
    assert_eq!(
        decode_value::<Channel>(&enrollment)?.validate_context(&ctx),
        Err(WireError::Field("channel_phase"))
    );
    for p in [
        json!({"kind":"approval","proposal_hash":digest_value,"base_record_hash":digest_value,"base_epoch":0,"approved":false}),
        json!({"kind":"candidate_ready","transfer_id":digest_value,"record_hash":digest_value,"compacted_ids_hash":null}),
        json!({"kind":"published","operation_id":digest_value,"record_hash":digest_value,"device_set_epoch":0,"recipient_ref":transcript_value["responder"]["device_ref"]}),
        json!({"kind":"installed","operation_id":digest_value,"record_hash":digest_value,"recipient_ref":transcript_value["responder"]["device_ref"]}),
        json!({"kind":"completed","operation_id":digest_value,"record_hash":digest_value,"cleanup":"pending"}),
        json!({"kind":"abort","reason":"InvalidInput"}),
    ] {
        exact::<Channel>(&make(p))?;
    }
    for (kind, total, count) in [("hpke", 819_200, 100), ("candidate", 524_288, 64)] {
        for index in [0, count - 1] {
            let v = make(
                json!({"kind":"artifact_chunk","object_kind":kind,"object_id":digest_value,"index":index,"count":count,"total_bytes":total,"bytes":encode_base64url(vec![1;8192])}),
            );
            exact::<Channel>(&v)?;
            field::<Channel>(&v, "/payload/total_bytes", json!(total + 1), "total_bytes")?;
            field::<Channel>(&v, "/payload/count", json!(count + 1), "count")?;
            field::<Channel>(&v, "/payload/index", json!(count), "index")?;
            field::<Channel>(
                &v,
                "/payload/bytes",
                json!(encode_base64url(vec![1; 8191])),
                "chunk_length",
            )?;
        }
    }
    Ok(())
}
fn credential_cases() -> TestResult {
    let req = obj(
        "CredentialRequest",
        json!({"local_account_id":"local","reservation_id":hash(),"frontend_generation":1,"action":"setup"}),
    );
    let mut req = req;
    req.as_object_mut().ok_or("request")?.remove("schema");
    req.as_object_mut().ok_or("request")?.remove("version");
    let canonical = bytes(&req)?;
    assert_eq!(decode_value::<CredentialRequest>(&req)?.to_wire_bytes()?, canonical);
    assert_eq!(CredentialRequest::from_wire_bytes(&vec![b' '; 1025]).err(), Some(WireError::Size));
    let r = decode_value::<CredentialRequest>(&req)?;
    r.validate_recipient_mode("new")?;
    assert_eq!(r.validate_recipient_mode("existing"), Err(WireError::Field("credential_mode")));
    assert_eq!(r.validate_recipient_mode("other"), Err(WireError::Field("recipient_mode")));
    for n in [1, 1024] {
        let b = vec![b'x'; n];
        r.validate_input(&r, CredentialInput { passphrase: &b, confirmation: Some(&b) })?;
    }
    let check = |p: &[u8], common_value: Option<&[u8]>, e| {
        assert_eq!(
            r.validate_input(&r, CredentialInput { passphrase: p, confirmation: common_value }),
            Err(WireError::Field(e))
        );
    };
    check(b"", Some(b""), "credential_length");
    check(&vec![b'x'; 1025], None, "credential_length");
    check(&[255], Some(&[255]), "credential_utf8");
    check(b"x", Some(b"y"), "credential_confirmation");
    check(b"x", None, "credential_confirmation");
    check(&vec![1; 1025], Some(&vec![1; 1024]), "credential_total");
    for (key, value, error) in [
        ("local_account_id", json!("other"), "credential_account"),
        ("reservation_id", json!(encode_base64url([2; 32])), "credential_reservation"),
        ("frontend_generation", json!(2), "credential_generation"),
        ("action", json!("unlock"), "credential_action"),
    ] {
        let mut v = req.clone();
        v[key] = value;
        let wrong = decode_value::<CredentialRequest>(&v)?;
        assert_eq!(
            wrong.validate_input(&r, CredentialInput { passphrase: b"x", confirmation: None }),
            Err(WireError::Field(error))
        );
    }
    let mut unlock = req.clone();
    unlock["action"] = json!("unlock");
    let u = decode_value::<CredentialRequest>(&unlock)?;
    u.validate_recipient_mode("existing")?;
    u.validate_input(&u, CredentialInput { passphrase: b"x", confirmation: None })?;
    assert_eq!(
        u.validate_input(&u, CredentialInput { passphrase: b"x", confirmation: Some(b"x") }),
        Err(WireError::Field("credential_confirmation"))
    );
    Ok(())
}
fn transfer_cases(transcript_value: &Value) -> TestResult {
    let digest_value = hash();
    let empty = json!({"schema":"ramflux.identity.transfer.payload.v1","version":1,"transfer_id":digest_value,"transcript_hash":digest_value,"current_record_hash":digest_value,"device_set_epoch":0,"pending_invitations":[],"journal":[],"delegation_state":[],"group_restriction_summary":[],"pending_erasure":[],"optional_data_keys":[]});
    // Legacy schemas retain version1: check closure without the v2 header helper.
    let check = |v: &Value| -> TestResult {
        let b = bytes(v)?;
        assert_eq!(decode_value::<TransferPayload>(v)?.to_wire_bytes()?, b);
        for key in ["passphrase", "confirmation", "provider_handle"] {
            let mut bad = v.clone();
            bad[key] = json!("synthetic");
            assert_eq!(decode_value::<TransferPayload>(&bad).err(), Some(WireError::Shape));
        }
        Ok(())
    };
    check(&empty)?;
    let mut full = empty.clone();
    full["pending_invitations"]=json!((0..3).map(|_|json!({"invitation_id":digest_value,"expires_at":MAX_SAFE_JSON_INTEGER,"proposal_hash":digest_value})).collect::<Vec<_>>());
    full["journal"]=json!((0..64).map(|_|json!({"operation_id":digest_value,"intent_hash":digest_value,"state":"acknowledged","acknowledgement_hash":digest_value})).collect::<Vec<_>>());
    full["group_restriction_summary"]=json!((0..64).map(|i|json!({"group_id":format!("{i:03}{}","x".repeat(253)),"group_genesis_hash":digest_value,"control_head_hash":digest_value,"restriction_hashes":(0..8).map(|i|encode_base64url([i;32])).collect::<Vec<_>>(),"revocation_hashes":[]})).collect::<Vec<_>>());
    // base64url lexical ordering is explicitly part of the received profile.
    for v in full["group_restriction_summary"].as_array_mut().ok_or("groups")? {
        v["restriction_hashes"].as_array_mut().ok_or("hashes")?.sort_by_key(Value::to_string);
        v["revocation_hashes"] = v["restriction_hashes"].clone();
    }
    full["pending_erasure"] = json!(
        (0..256)
            .map(|i| {
                let mut r = transcript_value["responder"]["device_ref"].clone();
                r["device_id"] = json!(format!("{i:03}{}", "x".repeat(125)));
                r
            })
            .collect::<Vec<_>>()
    );
    full["optional_data_keys"]=json!((0..32).map(|i|json!({"key_id":format!("{i:02}{}","x".repeat(254)),"purpose":"history","key":digest_value})).collect::<Vec<_>>());
    check(&full)?;
    for (key, error) in [
        ("pending_invitations", "pending_invitations"),
        ("journal", "journal"),
        ("group_restriction_summary", "group_restriction_summary"),
        ("pending_erasure", "pending_erasure"),
        ("optional_data_keys", "optional_data_keys"),
    ] {
        let mut bad = full.clone();
        let a = bad[key].as_array_mut().ok_or("array")?;
        a.push(a[0].clone());
        field::<TransferPayload>(&full, &format!("/{key}"), bad[key].clone(), error)?;
    }
    field::<TransferPayload>(
        &full,
        "/journal/0/acknowledgement_hash",
        Value::Null,
        "acknowledgement_hash",
    )?;
    field::<TransferPayload>(&full, "/delegation_state", json!([{}]), "UpdateRequired")?;
    field::<TransferPayload>(
        &full,
        "/optional_data_keys/0/key_id",
        json!(format!("00{}", "x".repeat(255))),
        "key_id",
    )?;
    field::<TransferPayload>(
        &full,
        "/group_restriction_summary/0/group_id",
        json!(format!("000{}", "x".repeat(254))),
        "group_id",
    )?;
    field::<TransferPayload>(
        &full,
        "/pending_erasure/0/device_id",
        json!(format!("000{}", "x".repeat(126))),
        "ref.device_id",
    )?;
    let mut hashes = (0..9).map(|i| encode_base64url([i; 32])).collect::<Vec<_>>();
    hashes.sort();
    field::<TransferPayload>(
        &full,
        "/group_restriction_summary/0/restriction_hashes",
        json!(hashes),
        "hashes",
    )?;

    Ok(())
}

fn legacy_exact<T: PairingWire>(v: &Value) -> TestResult {
    let b = bytes(v)?;
    assert_eq!(decode_value::<T>(v)?.to_wire_bytes()?, b);
    nested_shapes::<T>(v)?;
    assert_eq!(T::from_wire_bytes(&vec![b' '; T::LIMIT + 1]).err(), Some(WireError::Size));
    for key in ["passphrase", "confirmation", "provider_handle"] {
        let mut bad = v.clone();
        bad[key] = json!("synthetic");
        assert_eq!(decode_value::<T>(&bad).err(), Some(WireError::Shape));
    }
    Ok(())
}
fn transfer_envelopes(transcript_value: &Value) -> TestResult {
    let digest_value = hash();
    let preservation = json!({"schema":"ramflux.identity.transfer.preserve.v1","version":1,"transfer_id":digest_value,"transcript_hash":digest_value,"old_record_hash":digest_value,"new_record_hash":digest_value,"destination_ref":transcript_value["responder"]["device_ref"],"recipient_mode":"new","policy":"preserve_all_existing","expires_at":MAX_SAFE_JSON_INTEGER});
    legacy_exact::<PreservationBody>(&preservation)?;
    field::<PreservationBody>(&preservation, "/policy", json!("discard"), "policy")?;
    let ready = obj(
        "Channel",
        json!({"invitation_id":digest_value,"transcript_hash":digest_value,"payload":{"kind":"transfer_ready","transfer_id":digest_value,"record_hash":digest_value,"compacted_ids_hash":digest_value,"preservation":signed(preservation)}}),
    );
    exact::<Channel>(&ready)?;
    field::<Channel>(
        &ready,
        "/payload/preservation/body/transfer_id",
        json!(encode_base64url([2; 32])),
        "preservation_binding",
    )?;
    let binding = json!({"schema":"ramflux.identity.transfer_binding.v1","version":1,"transfer_id":digest_value,"transcript_hash":digest_value,"current_record_hash":digest_value,"device_set_epoch":MAX_SAFE_JSON_INTEGER,"sender_device_ref":transcript_value["initiator"]["device_ref"],"sender_hpke_key":digest_value,"recipient_hpke_key":encode_base64url([2;32]),"issued_at":MAX_SAFE_JSON_INTEGER-300,"expires_at":MAX_SAFE_JSON_INTEGER});
    legacy_exact::<TransferBinding>(&binding)?;
    field::<TransferBinding>(
        &binding,
        "/issued_at",
        json!(MAX_SAFE_JSON_INTEGER - 301),
        "binding_lifetime",
    )?;
    let hpke = json!({"schema":"ramflux.identity.transfer.hpke.v1","version":1,"transfer_id":digest_value,"transcript_hash":digest_value,"current_record_hash":digest_value,"device_set_epoch":MAX_SAFE_JSON_INTEGER,"sender_binding":signed(binding),"enc":digest_value,"ciphertext":encode_base64url([0;16])});
    legacy_exact::<HpkeEnvelope>(&hpke)?;
    field::<HpkeEnvelope>(&hpke, "/ciphertext", json!(encode_base64url([0; 15])), "ciphertext")?;
    field::<HpkeEnvelope>(
        &hpke,
        "/sender_binding/body/transfer_id",
        json!(encode_base64url([2; 32])),
        "hpke_binding",
    )?;
    for key in ["transfer_id", "transcript_hash", "current_record_hash", "enc"] {
        let mut bad = hpke.clone();
        bad[key] = json!("bad");
        assert_eq!(
            decode_value::<HpkeEnvelope>(&bad).err(),
            Some(WireError::Field(match key {
                "transfer_id" => "transfer_id",
                "transcript_hash" => "transcript_hash",
                "current_record_hash" => "current_record_hash",
                _ => "enc",
            }))
        );
    }
    Ok(())
}

fn local_bounds() -> TestResult {
    let mut begin = obj(
        "Begin",
        json!({"capabilities":["call","group","message","register","sync"],"lease_not_before":0,"lease_expires_at":MAX_BRANCH_LEASE_SECONDS,"display_name":"x".repeat(128)}),
    );
    exact::<Begin>(&begin)?;
    field::<Begin>(&begin, "/lease_expires_at", json!(MAX_BRANCH_LEASE_SECONDS + 1), "lease")?;
    field::<Begin>(
        &begin,
        "/capabilities",
        json!(["call", "group", "message", "register", "sync", "sync"]),
        "capabilities",
    )?;
    field::<Begin>(&begin, "/display_name", json!("x".repeat(129)), "display_name")?;
    field::<Begin>(&begin, "/display_name", json!("\u{202e}"), "display_name")?;
    begin["lease_expires_at"] = json!(1);
    begin["capabilities"] = json!(["message"]);
    begin["display_name"] = json!("");
    exact::<Begin>(&begin)?;
    let request = json!({"local_account_id":"x".repeat(128),"reservation_id":hash(),"frontend_generation":MAX_SAFE_JSON_INTEGER,"action":"setup"});
    let canonical = bytes(&request)?;
    assert_eq!(decode_value::<CredentialRequest>(&request)?.to_wire_bytes()?, canonical);
    for (path, value, error) in [
        ("/local_account_id", json!(""), "local_account_id"),
        ("/local_account_id", json!("x".repeat(129)), "local_account_id"),
        ("/local_account_id", json!("\n"), "local_account_id"),
        ("/reservation_id", json!("bad"), "reservation_id"),
        ("/frontend_generation", json!(0), "frontend_generation"),
        ("/action", json!("remote"), "action"),
    ] {
        field::<CredentialRequest>(&request, path, value, error)?;
    }
    let r = decode_value::<CredentialRequest>(&request)?;
    let utf8 = "é".repeat(512);
    r.validate_input(
        &r,
        CredentialInput { passphrase: utf8.as_bytes(), confirmation: Some(utf8.as_bytes()) },
    )?;
    assert_eq!(
        r.validate_input(&r, CredentialInput { passphrase: b" x ", confirmation: Some(b"x") }),
        Err(WireError::Field("credential_confirmation"))
    );
    Ok(())
}

fn transfer_contexts(source: &Value) -> TestResult {
    let mut transcript = source.clone();
    let common = transfer(&source["initiator"]["common"]);
    transcript["initiator"]["common"] = common.clone();
    transcript["responder"]["common"] = common.clone();
    transcript["initiator"]["hpke_key"] = json!(encode_base64url([100; 32]));
    transcript["responder"]["hpke_key"] = json!(encode_base64url([101; 32]));
    let frozen = decode_value::<Transcript>(&transcript)?;
    let digest = hash();
    let payload = json!({"schema":"ramflux.identity.transfer.payload.v1","version":1,"transfer_id":common["transfer_id"],"transcript_hash":digest,"current_record_hash":common["record_hash"],"device_set_epoch":common["device_set_epoch"],"pending_invitations":[],"journal":[],"delegation_state":[],"group_restriction_summary":[],"pending_erasure":[],"optional_data_keys":[]});
    decode_value::<TransferPayload>(&payload)?.validate_context(&frozen, &digest)?;
    let mut wrong = payload.clone();
    wrong["transfer_id"] = json!(encode_base64url([9; 32]));
    assert_eq!(
        decode_value::<TransferPayload>(&wrong)?.validate_context(&frozen, &digest),
        Err(WireError::Field("transfer_context"))
    );
    wrong = payload.clone();
    wrong["optional_data_keys"] = json!([{"key_id":"key","purpose":"history","key":hash()}]);
    assert_eq!(
        decode_value::<TransferPayload>(&wrong)?.validate_context(&frozen, &digest),
        Err(WireError::Field("data_consent"))
    );
    let binding = json!({"schema":"ramflux.identity.transfer_binding.v1","version":1,"transfer_id":common["transfer_id"],"transcript_hash":digest,"current_record_hash":common["record_hash"],"device_set_epoch":common["device_set_epoch"],"sender_device_ref":transcript["initiator"]["device_ref"],"sender_hpke_key":transcript["initiator"]["hpke_key"],"recipient_hpke_key":transcript["responder"]["hpke_key"],"issued_at":0,"expires_at":0});
    let envelope = json!({"schema":"ramflux.identity.transfer.hpke.v1","version":1,"transfer_id":common["transfer_id"],"transcript_hash":digest,"current_record_hash":common["record_hash"],"device_set_epoch":common["device_set_epoch"],"sender_binding":signed(binding),"enc":hash(),"ciphertext":encode_base64url([0;16])});
    decode_value::<HpkeEnvelope>(&envelope)?.validate_context(&frozen, &digest)?;
    let mut wrong = envelope.clone();
    wrong["sender_binding"]["body"]["sender_hpke_key"] = json!(encode_base64url([9; 32]));
    assert_eq!(
        decode_value::<HpkeEnvelope>(&wrong)?.validate_context(&frozen, &digest),
        Err(WireError::Field("hpke_keys"))
    );
    assert_eq!(
        decode_value::<HpkeEnvelope>(&envelope)?
            .validate_context(&frozen, &encode_base64url([9; 32])),
        Err(WireError::Field("hpke_context"))
    );
    Ok(())
}
