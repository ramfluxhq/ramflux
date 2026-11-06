// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::custody::pairing::{native::*, relay::*};
use crate::custody::{CustodyProofAction, Envelope};

fn object(name: &str, fields: Value) -> Value {
    let mut value = fields;
    value["schema"] = json!(format!("ramflux.pairing.{name}.v2"));
    value["version"] = json!(2);
    value
}
fn signed_value(body: &Value) -> Value {
    json!({"body":body,"signature":encode_base64url([7;64])})
}
fn spec_fixture() -> TestResult<Value> {
    let f = fixture()?;
    let c = &f["transcript"]["initiator"]["common"];
    Ok(object(
        "CreateSpec",
        json!({"account_anchor":c["account_anchor"],"primary_ref":f["transcript"]["initiator"]["device_ref"],"base_record_hash":c["record_hash"],"base_epoch":c["device_set_epoch"],"purpose":"enroll","recipient_mode":"new","destination_ref":null,"capabilities":c["capabilities"],"lease_not_before":c["lease_not_before"],"lease_expires_at":c["lease_expires_at"],"data_selection":[],"ttl_seconds":300}),
    ))
}
fn invitation_fixture(spec: &Value) -> Value {
    let mut i = spec.clone();
    i.as_object_mut().and_then(|m| m.remove("ttl_seconds"));
    i["schema"] = json!("ramflux.pairing.Invitation.v2");
    for (k, v) in [
        ("invitation_id", json!(encode_base64url([1; 32]))),
        ("issuer_seq", json!(1)),
        ("request_id", json!(encode_base64url([2; 32]))),
        ("node_key", json!(encode_base64url([3; 32]))),
        ("public_origin", json!("https://relay.example:443")),
        ("transfer_id", Value::Null),
        ("created_at", json!(100)),
        ("expires_at", json!(400)),
    ] {
        i[k] = v;
    }
    i
}
fn id() -> String {
    encode_base64url([1; 32])
}
fn token() -> String {
    encode_base64url([4; 32])
}
fn common_fields() -> Value {
    json!({"invitation_id":id(),"issuer_seq":1,"role":"initiator","token":token()})
}
fn field_rule<T: PairingWire>(
    v: &Value,
    path: &str,
    bad: Value,
    error: &'static str,
) -> TestResult {
    field::<T>(v, path, bad, error)
}
fn b32_cases<T: PairingWire>(v: &Value, path: &str, error: &'static str) -> TestResult {
    for bad in [
        json!(""),
        json!("A".repeat(42)),
        json!("A".repeat(44)),
        json!(format!("{}B", "A".repeat(42))),
        json!("+".repeat(43)),
    ] {
        field_rule::<T>(v, path, bad, error)?;
    }
    Ok(())
}
fn integer_case<T: PairingWire>(v: &Value, path: &str, error: &'static str) -> TestResult {
    invalid::<T>(v, path, json!(MAX_SAFE_JSON_INTEGER + 1), WireError::Json)?;
    let mut changed = v.clone();
    *changed.pointer_mut(path).ok_or("missing integer")? = json!(MAX_SAFE_JSON_INTEGER + 1);
    let typed: T = serde_json::from_value(changed)?;
    assert_eq!(typed.validate(), Err(WireError::Field(error)));
    for bad in [json!(-1), json!(1.5), json!("1"), Value::Null] {
        invalid::<T>(v, path, bad, WireError::Shape)?;
    }
    Ok(())
}
fn round<T: PairingWire>(v: &Value) -> TestResult {
    closed::<T>(v)?;
    nested_shapes::<T>(v)?;
    Ok(())
}

#[test]
fn pairing_native_relay_schemas_are_closed() -> TestResult {
    let independent = fixture()?["native_relay"].clone();
    assert_eq!(bytes(&spec_fixture()?)?, bytes(&independent["spec"])?);
    assert_eq!(
        decode_value::<CreateSpec>(&independent["spec"])?.spec_hash()?,
        independent["spec_hash"]
    );
    assert_eq!(
        hex(&ticket_signing_bytes(&decode_value::<CreateTicket>(&independent["ticket"])?)?),
        independent["preimages_hex"]["ticket"]
    );
    assert_eq!(
        hex(&invitation_signing_bytes(&decode_value::<Invitation>(&independent["invitation"])?)?),
        independent["preimages_hex"]["invitation"]
    );
    assert_eq!(
        decode_value::<Send>(&independent["send"])?.frame_digest()?,
        independent["send_digest"]
    );
    let spec = spec_fixture()?;
    round::<CreateSpec>(&spec)?;
    let issue = object("Issue", json!({"spec":spec}));
    round::<Issue>(&issue)?;
    let spec_t = decode_value::<CreateSpec>(&spec)?;
    let ticket = object(
        "CreateTicket",
        json!({"node_key":encode_base64url([3;32]),"boot_id":encode_base64url([5;32]),"create_id":encode_base64url([2;32]),"issuer_seq":1,"account_anchor":spec["account_anchor"],"primary_ref":spec["primary_ref"],"spec_hash":spec_t.spec_hash()?,"issued_at":100,"expires_at":400}),
    );
    round::<CreateTicket>(&ticket)?;
    let create = object("Create", json!({"ticket":signed_value(&ticket),"spec":spec}));
    round::<Create>(&create)?;
    let issued = object("Issued", json!({"ticket":signed_value(&ticket)}));
    round::<Issued>(&issued)?;
    let invitation = invitation_fixture(&spec);
    round::<Invitation>(&invitation)?;
    let created = object(
        "Created",
        json!({"request_id":encode_base64url([2;32]),"invitation":signed_value(&invitation),"primary_token":token(),"recipient_token":encode_base64url([6;32])}),
    );
    round::<Created>(&created)?;
    let invite = object(
        "InviteToken",
        json!({"invitation":signed_value(&invitation),"recipient_token":encode_base64url([6;32])}),
    );
    round::<InviteToken>(&invite)?;
    for reply in
        [&issued, &created, &object("Failure", json!({"code":"Retired","retry_after_ms":null}))]
    {
        round::<PairingReply>(&object("PairingReply", json!({"reply":reply})))?;
    }
    native_cases(&spec, &ticket, &create, &invitation, &created, &invite)?;
    native_controls(&issue, &create, &ticket, &invitation, &created)?;
    relay_cases()?;
    failure_cases()?;
    Ok(())
}
fn native_cases(
    spec: &Value,
    ticket: &Value,
    create: &Value,
    invitation: &Value,
    created: &Value,
    invite: &Value,
) -> TestResult {
    for (k, e) in [("account_anchor", "account_anchor"), ("base_record_hash", "record_hash")] {
        b32_cases::<CreateSpec>(spec, &format!("/{k}"), e)?;
    }
    integer_case::<CreateSpec>(spec, "/base_epoch", "device_set_epoch")?;
    field::<CreateSpec>(spec, "/ttl_seconds", json!(299), "ttl_seconds")?;
    field::<CreateSpec>(spec, "/ttl_seconds", json!(301), "ttl_seconds")?;
    for (path, error) in [("/purpose", "purpose"), ("/recipient_mode", "recipient_mode")] {
        field::<CreateSpec>(spec, path, json!("other"), error)?;
    }
    field::<CreateSpec>(spec, "/primary_ref/account_anchor", json!(id()), "primary_anchor")?;
    for key in ["node_key", "boot_id", "create_id", "account_anchor", "spec_hash"] {
        b32_cases::<CreateTicket>(
            ticket,
            &format!("/{key}"),
            match key {
                "node_key" => "node_key",
                "boot_id" => "boot_id",
                "create_id" => "create_id",
                "account_anchor" => "account_anchor",
                _ => "spec_hash",
            },
        )?;
    }
    field::<CreateTicket>(ticket, "/issuer_seq", json!(0), "issuer_seq")?;
    integer_case::<CreateTicket>(ticket, "/issuer_seq", "issuer_seq")?;
    for end in [399, 401] {
        field::<CreateTicket>(ticket, "/expires_at", json!(end), "invitation_lifetime")?;
    }
    field::<Create>(create, "/ticket/body/spec_hash", json!(id()), "spec_hash")?;
    field::<Create>(
        create,
        "/ticket/body/primary_ref/device_id",
        json!("another"),
        "ticket_context",
    )?;
    for sig in ["", &"A".repeat(85), &"A".repeat(87)] {
        field::<Create>(create, "/ticket/signature", json!(sig), "signature")?;
    }
    descriptor_cases(invitation, created, invite)?;
    native_max_cases(spec, ticket, create, invitation, created)?;
    Ok(())
}
fn descriptor_cases(invitation: &Value, created: &Value, invite: &Value) -> TestResult {
    for key in ["invitation_id", "request_id", "node_key"] {
        b32_cases::<Invitation>(
            invitation,
            &format!("/{key}"),
            match key {
                "invitation_id" => "invitation_id",
                "request_id" => "request_id",
                _ => "node_key",
            },
        )?;
    }
    for bad in [
        "http://relay.example",
        "https://",
        "https://a/path",
        "https://u@a",
        "https://a?b",
        "https://é.test",
        "https://:",
        "https://a:abc",
        "https://a:65536",
        "https://[bad]",
    ] {
        field::<Invitation>(invitation, "/public_origin", json!(bad), "public_origin")?;
    }
    let mut longest = invitation.clone();
    longest["public_origin"] = json!(format!("https://{}", "a".repeat(248)));
    assert_eq!(longest["public_origin"].as_str().ok_or("origin")?.len(), 256);
    decode_value::<Invitation>(&longest)?;
    field::<Invitation>(
        &longest,
        "/public_origin",
        json!(format!("https://{}", "a".repeat(249))),
        "public_origin",
    )?;
    for end in [399, 401] {
        field::<Invitation>(invitation, "/expires_at", json!(end), "invitation_lifetime")?;
    }
    field::<Created>(
        created,
        "/primary_token",
        created["recipient_token"].clone(),
        "distinct_tokens",
    )?;
    field::<Created>(created, "/request_id", json!(id()), "request_binding")?;
    b32_cases::<Created>(created, "/primary_token", "primary_token")?;
    b32_cases::<Created>(created, "/recipient_token", "recipient_token")?;
    b32_cases::<InviteToken>(invite, "/recipient_token", "recipient_token")?;
    Ok(())
}
fn native_max_cases(
    spec: &Value,
    ticket: &Value,
    create: &Value,
    invitation: &Value,
    created: &Value,
) -> TestResult {
    for (start, end) in [(0, 300), (MAX_SAFE_JSON_INTEGER - 300, MAX_SAFE_JSON_INTEGER)] {
        let mut value = ticket.clone();
        value["issued_at"] = json!(start);
        value["expires_at"] = json!(end);
        round::<CreateTicket>(&value)?;
        let mut value = invitation.clone();
        value["created_at"] = json!(start);
        value["expires_at"] = json!(end);
        round::<Invitation>(&value)?;
    }
    let mut maximal_ticket = ticket.clone();
    maximal_ticket["issuer_seq"] = json!(MAX_SAFE_JSON_INTEGER);
    maximal_ticket["issued_at"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    maximal_ticket["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    maximal_ticket["primary_ref"]["device_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    maximal_ticket["primary_ref"]["device_id"] = json!("\\".repeat(128));
    round::<CreateTicket>(&maximal_ticket)?;
    for envelope in [signed_value(ticket), signed_value(&maximal_ticket)] {
        let canonical = bytes(&envelope)?;
        assert_eq!(
            Envelope::<CreateTicket>::from_wire_bytes(&canonical)?.to_wire_bytes()?,
            canonical
        );
        nested_shapes::<Envelope<CreateTicket>>(&envelope)?;
    }
    let canonical = bytes(&signed_value(invitation))?;
    assert_eq!(Envelope::<Invitation>::from_wire_bytes(&canonical)?.to_wire_bytes()?, canonical);
    let mut wrong_frame = object("Send", common_fields());
    wrong_frame["seq"] = json!(0);
    wrong_frame["frame"] = json!({"kind":"commit","value":object("Commit",json!({"invitation_id":encode_base64url([9;32]),"role":"initiator","commitment":id()}))});
    assert_eq!(
        decode_value::<Send>(&wrong_frame).err(),
        Some(WireError::Field("frame_invitation"))
    );
    // Full simultaneous maxima: escaped ids and selection, all capabilities, existing transfer.
    let mut full = spec.clone();
    full["purpose"] = json!("primary_transfer");
    full["recipient_mode"] = json!("existing");
    full["base_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    full["primary_ref"]["device_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    full["lease_not_before"] = json!(MAX_SAFE_JSON_INTEGER - MAX_BRANCH_LEASE_SECONDS);
    full["lease_expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    full["destination_ref"] = full["primary_ref"].clone();
    full["destination_ref"]["device_id"] = json!("\"".repeat(128));
    full["primary_ref"]["device_id"] = json!("\\".repeat(128));
    full["capabilities"] = json!(["call", "group", "message", "register", "sync"]);
    full["data_selection"] = json!(
        (0..32)
            .map(|i| json!({"key_id":format!("{i:02}{}","\\".repeat(126)),"purpose":"attachment"}))
            .collect::<Vec<_>>()
    );
    round::<CreateSpec>(&full)?;
    let mut full_i = invitation_fixture(&full);
    full_i["transfer_id"] = json!(id());
    full_i["issuer_seq"] = json!(MAX_SAFE_JSON_INTEGER);
    full_i["created_at"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    full_i["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    round::<Invitation>(&full_i)?;
    let mut full_create = create.clone();
    full_create["spec"] = full.clone();
    full_create["ticket"]["body"]["issuer_seq"] = json!(MAX_SAFE_JSON_INTEGER);
    full_create["ticket"]["body"]["issued_at"] = json!(MAX_SAFE_JSON_INTEGER - 300);
    full_create["ticket"]["body"]["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    full_create["ticket"]["body"]["primary_ref"] = full["primary_ref"].clone();
    full_create["ticket"]["body"]["spec_hash"] =
        json!(decode_value::<CreateSpec>(&full)?.spec_hash()?);
    round::<Create>(&full_create)?;
    let mut full_created = created.clone();
    full_created["invitation"] = signed_value(&full_i);
    round::<Created>(&full_created)?;
    decode_value::<Created>(&full_created)?
        .validate_create(&decode_value::<Create>(&full_create)?)?;
    field::<CreateSpec>(
        &full,
        "/data_selection",
        json!(
            (0..33)
                .map(|i| json!({"key_id":format!("{i:02}"),"purpose":"history"}))
                .collect::<Vec<_>>()
        ),
        "data_selection",
    )?;
    field::<CreateSpec>(&full, "/destination_ref", Value::Null, "destination_ref")?;
    field::<CreateSpec>(
        &full,
        "/destination_ref/device_id",
        full["primary_ref"]["device_id"].clone(),
        "destination_is_primary",
    )?;
    Ok(())
}
fn native_controls(
    issue: &Value,
    create: &Value,
    ticket: &Value,
    invitation: &Value,
    created: &Value,
) -> TestResult {
    let saved_create = decode_value::<Create>(create)?;
    let out = decode_value::<Created>(created)?;
    out.validate_create(&saved_create)?;
    let boot = saved_create.ticket.body.boot_id.clone();
    for slot in [CreateSlot::Issued, CreateSlot::Live] {
        saved_create.validate_admission(&boot, slot, 399, true)?;
    }
    for (create_action, slot, now, live, e) in [
        (boot.as_str(), CreateSlot::Missing, 100, true, "retired"),
        ("another-boot", CreateSlot::Issued, 100, true, "retired"),
        (boot.as_str(), CreateSlot::Issued, 400, true, "expired"),
        (boot.as_str(), CreateSlot::Issued, 99, false, "expired"),
    ] {
        assert_eq!(
            saved_create.validate_admission(create_action, slot, now, live),
            Err(WireError::Field(e))
        );
    }
    let mut changed = out.clone();
    changed.invitation.body.invitation_id = encode_base64url([9; 32]);
    changed.validate_create(&saved_create)?; // server-generated invitation is independent of create_id
    changed.invitation.body.node_key = id();
    assert_eq!(changed.validate_create(&saved_create), Err(WireError::Field("created_binding")));
    let ticket_body = decode_value::<CreateTicket>(ticket)?;
    let descriptor = decode_value::<Invitation>(invitation)?;
    assert_eq!(
        ticket_signing_bytes(&ticket_body)?,
        bytes(&json!({"body":ticket,"domain":"ramflux.identity.pairing.create_ticket.v2"}))?
    );
    assert_eq!(
        invitation_signing_bytes(&descriptor)?,
        bytes(&json!({"body":invitation,"domain":"ramflux.identity.pairing.invitation.v2"}))?
    );
    assert_ne!(
        ticket_signing_bytes(&ticket_body)?,
        crate::custody::signing_bytes("ramflux.identity.pairing.create_ticket.v1", &ticket_body)?
    );
    let issue_action =
        CustodyProofAction::PairingIssue { request: Box::new(decode_value::<Issue>(issue)?) };
    let create_action = CustodyProofAction::PairingCreate { request: Box::new(saved_create) };
    assert_eq!(issue_action.capability(), "register");
    assert_eq!(create_action.capability(), "register");
    assert_eq!(serde_json::from_slice::<CustodyProofAction>(&bytes(&issue_action)?)?, issue_action);
    assert_eq!(
        serde_json::from_slice::<CustodyProofAction>(&bytes(&create_action)?)?,
        create_action
    );
    assert_eq!(bytes(&CustodyProofAction::OpenSession)?, br#"{"operation":"open_session"}"#);
    assert_eq!(
        bytes(&CustodyProofAction::Register { prekey_bundle: json!({"x":1}) })?,
        br#"{"operation":"register","prekey_bundle":{"x":1}}"#
    );
    let env: Envelope<CreateTicket> = serde_json::from_value(signed_value(ticket))?;
    assert_eq!(env.body, ticket_body);
    Ok(())
}
fn relay_cases() -> TestResult {
    let claim = object(
        "Claim",
        json!({"invitation_id":id(),"issuer_seq":1,"recipient_token":token(),"claim_nonce":encode_base64url([8;32])}),
    );
    round::<Claim>(&claim)?;
    let claimed = object(
        "Claimed",
        json!({"invitation_id":id(),"issuer_seq":1,"claim_nonce":encode_base64url([8;32]),"role":"responder","expires_at":400}),
    );
    round::<Claimed>(&claimed)?;
    let commit =
        object("Commit", json!({"invitation_id":id(),"role":"initiator","commitment":id()}));
    let mut s = common_fields();
    s["seq"] = json!(0);
    s["frame"] = json!({"kind":"commit","value":commit});
    let send = object("Send", s);
    round::<Send>(&send)?;
    let receipt = object("Sent", json!({"invitation_id":id(),"role":"initiator","seq":0}));
    round::<Sent>(&receipt)?;
    let mut p = common_fields();
    p["after_seq"] = Value::Null;
    let poll = object("Poll", p);
    round::<Poll>(&poll)?;
    let polled = object("Polled", json!({"invitation_id":id(),"frames":[],"closed":false}));
    round::<Polled>(&polled)?;
    let mut x = common_fields();
    x["reason"] = json!("cancel");
    let close = object("Close", x);
    round::<Close>(&close)?;
    let closed = object("Closed", json!({"invitation_id":id(),"reason":"cancel"}));
    round::<Closed>(&closed)?;
    for reason in ["cancel", "mismatch", "expired", "done", "protocol"] {
        let mut v = close.clone();
        v["reason"] = json!(reason);
        decode_value::<Close>(&v)?;
        let mut v = closed.clone();
        v["reason"] = json!(reason);
        decode_value::<Closed>(&v)?;
    }
    field::<Close>(&close, "/reason", json!("recovery"), "reason")?;
    field::<Closed>(&closed, "/reason", json!("recovery"), "reason")?;
    field::<Claimed>(&claimed, "/role", json!("initiator"), "role")?;
    b32_cases::<Claim>(&claim, "/claim_nonce", "claim_nonce")?;
    b32_cases::<Claim>(&claim, "/recipient_token", "recipient_token")?;
    b32_cases::<Send>(&send, "/token", "token")?;
    field::<Send>(&send, "/role", json!("other"), "role")?;
    field::<Send>(&send, "/frame/value/role", json!("responder"), "frame_role")?;
    invalid::<Send>(&send, "/frame/kind", json!("publication"), WireError::Shape)?;
    integer_case::<Send>(&send, "/seq", "seq")?;
    invalid::<Poll>(&poll, "/after_seq", json!(MAX_SAFE_JSON_INTEGER + 1), WireError::Json)?;
    let mut after = poll.clone();
    after["after_seq"] = json!(MAX_SAFE_JSON_INTEGER);
    decode_value::<Poll>(&after)?;
    integer_case::<Claimed>(&claimed, "/expires_at", "expires_at")?;
    integer_case::<Sent>(&receipt, "/seq", "seq")?;
    for r in ["initiator", "responder"] {
        let mut v = send.clone();
        v["role"] = json!(r);
        v["frame"] = json!({"kind":"confirm","role":r,"transcript_hash":id(),"mac":id()});
        round::<Send>(&v)?;
        b32_cases::<Send>(&v, "/frame/mac", "mac")?;
        b32_cases::<Send>(&v, "/frame/transcript_hash", "transcript_hash")?;
    }
    frame_cases(&send, &polled)?;
    token_cases(&send, &poll, &close, &claim)?;
    Ok(())
}
fn frame_cases(send: &Value, polled: &Value) -> TestResult {
    let mut channel = send.clone();
    channel["frame"] = json!({"kind":"channel","counter":MAX_SAFE_JSON_INTEGER,"ciphertext":encode_base64url([1;11716])});
    round::<Send>(&channel)?;
    field::<Send>(
        &channel,
        "/frame/ciphertext",
        json!(encode_base64url([1; 11717])),
        "ciphertext",
    )?;
    field::<Send>(&channel, "/frame/ciphertext", json!(encode_base64url([1; 15])), "ciphertext")?;
    let mut min = channel.clone();
    min["frame"]["counter"] = json!(0);
    min["frame"]["ciphertext"] = json!(encode_base64url([1; 16]));
    round::<Send>(&min)?;
    integer_case::<Send>(&channel, "/frame/counter", "counter")?;
    // Per-chunk exact geometry, both inclusive assembly maxima and all indices.
    for (kind, max) in [("offer_chunk", 16384), ("reveal_chunk", 24576)] {
        for total in [1_u64, 8192, 8193, max] {
            let count = total.div_ceil(8192);
            for index in 0..count {
                let length = if index + 1 == count { total - index * 8192 } else { 8192 };
                let mut v = send.clone();
                v["frame"] = json!({"kind":kind,"object_id":id(),"index":index,"count":count,"total_bytes":total,"bytes":encode_base64url(vec![0;usize::try_from(length)?])});
                round::<Send>(&v)?;
                field::<Send>(&v, "/frame/count", json!(count + 1), "count")?;
                field::<Send>(&v, "/frame/index", json!(count), "index")?;
                field::<Send>(&v, "/frame/total_bytes", json!(max + 1), "total_bytes")?;
                field::<Send>(&v, "/frame/total_bytes", json!(0), "total_bytes")?;
                field::<Send>(&v, "/frame/bytes", json!(encode_base64url([0; 8193])), "bytes")?;
                b32_cases::<Send>(&v, "/frame/object_id", "object_id")?;
            }
        }
    }
    let mut short = send.clone();
    short["frame"] = json!({"kind":"reveal_chunk","object_id":id(),"index":0,"count":1,"total_bytes":2,"bytes":encode_base64url([0])});
    assert_eq!(decode_value::<Send>(&short).err(), Some(WireError::Field("chunk_length")));
    let mut one = polled.clone();
    one["frames"] = json!([{"seq":0,"frame":min["frame"]}]);
    round::<Polled>(&one)?;
    let mut two = polled.clone();
    two["frames"] = json!([{"seq":0,"frame":min["frame"]},{"seq":1,"frame":min["frame"]}]);
    round::<Polled>(&two)?;
    let mut three = two.clone();
    three["frames"].as_array_mut().ok_or("frames")?.push(json!({"seq":2,"frame":min["frame"]}));
    assert_eq!(decode_value::<Polled>(&three).err(), Some(WireError::Field("frames")));
    field::<Polled>(&two, "/frames/1/seq", json!(2), "frame_sequence")?;
    let mut too_large = two.clone();
    too_large["frames"][0]["frame"] = channel["frame"].clone();
    too_large["frames"][1]["frame"] = channel["frame"].clone();
    assert_eq!(decode_value::<Polled>(&too_large).err(), Some(WireError::Size));
    Ok(())
}
fn token_cases(send: &Value, poll: &Value, close: &Value, claim: &Value) -> TestResult {
    let send = decode_value::<Send>(send)?;
    let token_value = token();
    let id_value = id();
    let binding = TokenBinding {
        invitation_id: &id_value,
        issuer_seq: 1,
        role: "initiator",
        token: &token_value,
        expires_at: 400,
    };
    send.validate_token(&binding, 399)?;
    assert_eq!(send.validate_token(&binding, 400), Err(WireError::Field("expired")));
    let wrong_role = TokenBinding { role: "responder", ..binding };
    // Owned BtF: removing only token-role binding must admit this otherwise valid request.
    assert_eq!(send.validate_token(&wrong_role, 100), Err(WireError::Field("token_role")));
    assert_eq!(
        send.frame_digest()?,
        crate::custody::framed_hash(domain::CUSTODY_OBJECT_HASH, &send)?
    );
    decode_value::<Poll>(poll)?.validate_token(&binding, 100)?;
    decode_value::<Close>(close)?.validate_token(&binding, 100)?;
    decode_value::<Claim>(claim)?.validate_token(&wrong_role, 100)?;
    assert_eq!(
        decode_value::<Claim>(claim)?.validate_token(&binding, 100),
        Err(WireError::Field("token_role"))
    );
    Ok(())
}
fn failure_cases() -> TestResult {
    for code in [
        "Busy",
        "InvalidInput",
        "Expired",
        "Retired",
        "WrongRole",
        "WrongContext",
        "Replay",
        "HeadChanged",
        "PrimaryRequired",
        "SasMismatch",
        "PublicationPending",
        "TransferCapacity",
        "UpdateRequired",
        "VaultUnavailable",
        "NotFound",
    ] {
        let f = object(
            "Failure",
            json!({"code":code,"retry_after_ms":if code=="Busy" {json!(1000)} else {Value::Null}}),
        );
        round::<Failure>(&f)?;
        field::<Failure>(&f, "/code", json!("diagnostic"), "code")?;
        if code == "Busy" {
            for bad in [Value::Null, json!(999), json!(30001)] {
                field::<Failure>(&f, "/retry_after_ms", bad, "retry_after_ms")?;
            }
            let mut v = f.clone();
            v["retry_after_ms"] = json!(30000);
            round::<Failure>(&v)?;
        } else {
            field::<Failure>(&f, "/retry_after_ms", json!(1000), "retry_after_ms")?;
        }
    }
    Ok(())
}
