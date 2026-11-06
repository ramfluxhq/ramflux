// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!("../../../fixtures/pairing_v2/vectors.json"))?)
}
fn decode_value<T: PairingWire>(v: &Value) -> Result<T> {
    T::from_wire_bytes(&bytes(v)?)
}
fn invalid<T: PairingWire>(base: &Value, path: &str, value: Value, error: WireError) -> TestResult {
    let mut changed = base.clone();
    *changed.pointer_mut(path).ok_or("missing test field")? = value;
    assert_eq!(decode_value::<T>(&changed).err(), Some(error), "{path}: {changed}");
    Ok(())
}
fn field<T: PairingWire>(base: &Value, path: &str, value: Value, name: &'static str) -> TestResult {
    invalid::<T>(base, path, value, WireError::Field(name))?;
    Ok(())
}
fn transfer(common: &Value) -> Value {
    let mut v = common.clone();
    v["purpose"] = json!("primary_transfer");
    v["requested_role"] = json!("primary");
    v["transfer_id"] = v["invitation_id"].clone();
    v["hpke_suite"] = json!(domain::CUSTODY_TRANSFER_HPKE_SUITE);
    v
}
fn closed<T: PairingWire>(value: &Value) -> TestResult {
    let canonical = canonical_json_bytes(value)?;
    assert_eq!(T::from_wire_bytes(&canonical)?.to_wire_bytes()?, canonical);
    for key in value.as_object().ok_or("expected test object")?.keys() {
        let mut v = value.clone();
        v.as_object_mut().ok_or("expected test object")?.remove(key);
        assert_eq!(decode_value::<T>(&v).err(), Some(WireError::Shape), "missing {key}");
    }
    let mut v = value.clone();
    v["extra"] = json!(true);
    assert_eq!(decode_value::<T>(&v).err(), Some(WireError::Shape));
    invalid::<T>(value, "/schema", json!("old.v1"), WireError::Field("schema"))?;
    invalid::<T>(value, "/version", json!(1), WireError::Field("version"))?;
    let mut padded = canonical.clone();
    padded.push(b' ');
    assert_eq!(T::from_wire_bytes(&padded).err(), Some(WireError::NonCanonical));
    let duplicate = canonical
        .iter()
        .copied()
        .take(canonical.len() - 1)
        .chain(b",\"version\":2}".iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(T::from_wire_bytes(&duplicate).err(), Some(WireError::Json));
    assert_eq!(T::from_wire_bytes(&vec![b' '; T::LIMIT + 1]).err(), Some(WireError::Size));
    Ok(())
}

#[test]
fn pairing_wire_domains_canonical_caps_and_old_controls() -> TestResult {
    let fixture = fixture()?;
    let transcript = &fixture["transcript"];
    let common = &transcript["initiator"]["common"];
    let role = &transcript["initiator"];
    closed::<Common>(common)?;
    closed::<RoleContext>(role)?;
    closed::<Transcript>(transcript)?;
    nested_shapes::<Transcript>(transcript)?;
    maximal_objects(transcript)?;
    scalar_cases(common, role)?;
    let existing = transfer_selection_cases(common, role, transcript)?;
    bounds_role_cases(common, role, &existing)?;
    transcript_controls(&fixture, transcript, common, role)?;
    Ok(())
}
fn scalar_cases(common: &Value, role: &Value) -> TestResult {
    for name in ["invitation_id", "account_anchor", "master_public_key", "record_hash"] {
        for bad in [
            json!(""),
            json!("A".repeat(42)),
            json!("A".repeat(44)),
            json!(format!("{}B", "A".repeat(42))),
            json!("+".repeat(43)),
        ] {
            field::<Common>(
                common,
                &format!("/{name}"),
                bad,
                match name {
                    "invitation_id" => "invitation_id",
                    "account_anchor" => "account_anchor",
                    "master_public_key" => "master_public_key",
                    _ => "record_hash",
                },
            )?;
        }
    }
    for (name, exact) in [
        ("issuer_seq", "issuer_seq"),
        ("device_set_epoch", "device_set_epoch"),
        ("lease_not_before", "lease_not_before"),
        ("lease_expires_at", "lease_expires_at"),
        ("expires_at", "expires_at"),
    ] {
        invalid::<Common>(
            common,
            &format!("/{name}"),
            json!(MAX_SAFE_JSON_INTEGER + 1),
            WireError::Json,
        )?;
        let mut typed: Common = decode_value(common)?;
        match exact {
            "issuer_seq" => typed.issuer_seq = MAX_SAFE_JSON_INTEGER + 1,
            "device_set_epoch" => typed.device_set_epoch = MAX_SAFE_JSON_INTEGER + 1,
            "lease_not_before" => typed.lease_not_before = MAX_SAFE_JSON_INTEGER + 1,
            "lease_expires_at" => typed.lease_expires_at = MAX_SAFE_JSON_INTEGER + 1,
            _ => typed.expires_at = MAX_SAFE_JSON_INTEGER + 1,
        }
        assert_eq!(typed.validate(), Err(WireError::Field(exact)));
        invalid::<Common>(common, &format!("/{name}"), json!(-1), WireError::Shape)?;
        invalid::<Common>(common, &format!("/{name}"), json!(1.5), WireError::Shape)?;
    }
    field::<Common>(common, "/issuer_seq", json!(0), "issuer_seq")?;
    for (name, bad) in [
        ("principal_kind", "service"),
        ("sas_suite", "v1"),
        ("purpose", "unknown"),
        ("requested_role", "owner"),
        ("recipient_mode", "other"),
    ] {
        field::<Common>(
            common,
            &format!("/{name}"),
            json!(bad),
            match name {
                "principal_kind" => "principal_kind",
                "sas_suite" => "sas_suite",
                "purpose" => "purpose",
                "requested_role" => "requested_role",
                _ => "recipient_mode",
            },
        )?;
    }
    for bad in [
        json!([]),
        json!(["message", "call"]),
        json!(["call", "call"]),
        json!(["unknown"]),
        json!(["call", "group", "message", "register", "sync", "sync"]),
    ] {
        field::<Common>(common, "/capabilities", bad, "capabilities")?;
    }
    field::<Common>(common, "/lease_expires_at", common["lease_not_before"].clone(), "lease")?;
    field::<Common>(common, "/lease_expires_at", json!(1_702_592_001_u64), "lease")?;
    field::<Common>(common, "/requested_role", json!("primary"), "enroll_context")?;
    field::<Common>(
        common,
        "/hpke_suite",
        json!(domain::CUSTODY_TRANSFER_HPKE_SUITE),
        "enroll_context",
    )?;
    field::<Common>(common, "/transfer_id", common["invitation_id"].clone(), "enroll_context")?;
    field::<Common>(common, "/transfer_id", json!("bad"), "transfer_id")?;
    field::<Common>(common, "/recipient_mode", json!("existing"), "destination_ref")?;
    field::<Common>(common, "/destination_ref", role["device_ref"].clone(), "destination_ref")?;
    Ok(())
}
fn transfer_selection_cases(common: &Value, role: &Value, transcript: &Value) -> TestResult<Value> {
    let tr = transfer(common);
    closed::<Common>(&tr)?;
    for (path, bad) in [
        ("/requested_role", json!("secondary")),
        ("/transfer_id", Value::Null),
        ("/hpke_suite", Value::Null),
        ("/hpke_suite", json!("wrong")),
    ] {
        field::<Common>(&tr, path, bad, "transfer_context")?;
    }
    let mut existing = tr.clone();
    existing["recipient_mode"] = json!("existing");
    existing["destination_ref"] = transcript["responder"]["device_ref"].clone();
    closed::<Common>(&existing)?;
    field::<Common>(
        &existing,
        "/destination_ref/account_anchor",
        role["branch_key"].clone(),
        "destination_anchor",
    )?;
    for (name, bad, error) in [
        ("account_anchor", json!("bad"), "ref.account_anchor"),
        ("device_id", json!(""), "ref.device_id"),
        ("device_id", json!("\n"), "ref.device_id"),
        ("device_id", json!("x".repeat(129)), "ref.device_id"),
        ("device_epoch", json!(0), "ref.device_epoch"),
        ("device_epoch", json!(MAX_SAFE_JSON_INTEGER + 1), "ref.device_epoch"),
    ] {
        let expected = if bad == json!(MAX_SAFE_JSON_INTEGER + 1) {
            WireError::Json
        } else {
            WireError::Field(error)
        };
        invalid::<Common>(
            &existing,
            &format!("/destination_ref/{name}"),
            bad.clone(),
            expected.clone(),
        )?;
        invalid::<RoleContext>(role, &format!("/device_ref/{name}"), bad, expected)?;
    }
    let selection = json!([{"key_id":"a","purpose":"history"}]);
    field::<Common>(common, "/data_selection", selection.clone(), "enroll_context")?;
    let mut selected = tr.clone();
    selected["data_selection"] = selection;
    closed::<Common>(&selected)?;
    for bad in [json!([]), json!([{"key_id":"a","purpose":"history"}])] {
        let mut v = tr.clone();
        v["data_selection"] = bad;
        assert!(decode_value::<Common>(&v).is_ok());
    }
    for (bad, error) in [("", "selection.key_id"), ("\n", "selection.key_id")] {
        field::<Common>(&selected, "/data_selection/0/key_id", json!(bad), error)?;
    }
    field::<Common>(
        &selected,
        "/data_selection/0/key_id",
        json!("x".repeat(129)),
        "selection.key_id",
    )?;
    field::<Common>(&selected, "/data_selection/0/purpose", json!("secret"), "selection.purpose")?;
    for bad in [
        json!([{"key_id":"a","purpose":"history"},{"key_id":"a","purpose":"history"}]),
        json!([{"key_id":"b","purpose":"history"},{"key_id":"a","purpose":"history"}]),
        json!(
            (0..33)
                .map(|n| json!({"key_id":format!("key{n:02}"),"purpose":"history"}))
                .collect::<Vec<_>>()
        ),
    ] {
        field::<Common>(&tr, "/data_selection", bad, "data_selection")?;
    }
    let mut max = tr.clone();
    max["data_selection"] = json!(
        (0..32)
            .map(|n| json!({"key_id":format!("{n:02}{}","\"".repeat(126)),"purpose":"attachment"}))
            .collect::<Vec<_>>()
    );
    closed::<Common>(&max)?;
    let max_common: Common = decode_value(&max)?;
    for v in &max_common.data_selection {
        assert!(bytes(v)?.len() <= 384);
    }
    let mut unsorted: Common = decode_value(&max)?;
    unsorted.capabilities.reverse();
    unsorted.data_selection.reverse();
    assert_eq!(Common::from_wire_bytes(&unsorted.to_wire_bytes()?)?, max_common);
    Ok(existing)
}
fn bounds_role_cases(common: &Value, role: &Value, existing: &Value) -> TestResult {
    let typed: Common = decode_value(common)?;
    assert_eq!(
        typed.validate_bounds(1_699_999_999, 1_700_000_000, 1_702_592_000),
        Err(WireError::Field("invitation_lifetime"))
    );
    assert_eq!(
        typed.validate_bounds(1_700_000_301, 1_700_000_000, 1_702_592_000),
        Err(WireError::Field("invitation_lifetime"))
    );
    assert_eq!(
        typed.validate_bounds(1_700_000_000, 1_700_000_001, 1_702_592_000),
        Err(WireError::Field("authority_lease"))
    );
    assert_eq!(
        typed.validate_bounds(1_700_000_000, 1_700_000_000, 1_702_591_999),
        Err(WireError::Field("authority_lease"))
    );
    assert_eq!(
        typed.validate_bounds(MAX_SAFE_JSON_INTEGER + 1, 0, MAX_SAFE_JSON_INTEGER),
        Err(WireError::Field("created_at"))
    );
    typed.validate_bounds(1_700_000_000, 1_700_000_000, 1_702_592_000)?;
    field::<RoleContext>(role, "/role", json!("other"), "role")?;
    field::<RoleContext>(
        role,
        "/device_ref/account_anchor",
        role["branch_key"].clone(),
        "device_anchor",
    )?;
    for name in ["branch_key", "agreement_key", "sas_key"] {
        field::<RoleContext>(
            role,
            &format!("/{name}"),
            json!("bad"),
            match name {
                "branch_key" => "branch_key",
                "agreement_key" => "agreement_key",
                _ => "sas_key",
            },
        )?;
    }
    field::<RoleContext>(role, "/hpke_key", role["sas_key"].clone(), "hpke_key")?;
    for bad in ["x".repeat(129), "\u{202e}".into()] {
        field::<RoleContext>(role, "/display_name", json!(bad), "display_name")?;
    }
    let mut transfer_role = role.clone();
    transfer_role["common"] = existing.clone();
    transfer_role["hpke_key"] = role["sas_key"].clone();
    closed::<RoleContext>(&transfer_role)?;
    field::<RoleContext>(&transfer_role, "/hpke_key", Value::Null, "hpke_key")?;
    field::<RoleContext>(&transfer_role, "/hpke_key", json!("bad"), "hpke_key")?;
    field::<RoleContext>(
        &transfer_role,
        "/common/destination_ref",
        role["device_ref"].clone(),
        "destination_is_primary",
    )?;
    transfer_role["role"] = json!("responder");
    field::<RoleContext>(&transfer_role, "/display_name", json!("OK"), "destination_device")?;
    transfer_role["device_ref"] = existing["destination_ref"].clone();
    closed::<RoleContext>(&transfer_role)?;
    Ok(())
}
fn transcript_controls(
    fixture: &Value,
    transcript: &Value,
    common: &Value,
    role: &Value,
) -> TestResult {
    field::<Transcript>(transcript, "/initiator/role", json!("responder"), "role_slots")?;
    field::<Transcript>(transcript, "/responder/common/issuer_seq", json!(2), "common_binding")?;
    field::<Transcript>(
        transcript,
        "/responder/device_ref",
        role["device_ref"].clone(),
        "distinct_devices",
    )?;
    let mut reused_id = role["device_ref"].clone();
    reused_id["device_epoch"] = json!(2);
    field::<Transcript>(transcript, "/responder/device_ref", reused_id, "distinct_devices")?;
    let offer = json!({"schema":"ramflux.pairing.ContextOffer.v2","version":2,"common":common});
    closed::<ContextOffer>(&offer)?;
    let commit = json!({"schema":"ramflux.pairing.Commit.v2","version":2,"invitation_id":common["invitation_id"],"role":"initiator","commitment":common["record_hash"]});
    closed::<Commit>(&commit)?;
    field::<Commit>(&commit, "/invitation_id", json!("bad"), "invitation_id")?;
    field::<Commit>(&commit, "/role", json!("other"), "role")?;
    field::<Commit>(&commit, "/commitment", json!("bad"), "commitment")?;
    let reveal = json!({"schema":"ramflux.pairing.Reveal.v2","version":2,"invitation_id":common["invitation_id"],"role":"initiator","salt":common["record_hash"],"context":role});
    closed::<Reveal>(&reveal)?;
    field::<Reveal>(&reveal, "/invitation_id", json!("bad"), "invitation_id")?;
    field::<Reveal>(&reveal, "/salt", json!("bad"), "salt")?;
    field::<Reveal>(&reveal, "/role", json!("responder"), "reveal_role")?;
    field::<Reveal>(
        &reveal,
        "/invitation_id",
        common["account_anchor"].clone(),
        "reveal_invitation",
    )?;
    let typed: Transcript = decode_value(transcript)?;
    assert_eq!(hex(&transcript_preimage(&typed)?), fixture["preimages_hex"]["transcript"]);
    for (ctx, salt, name) in
        [(&typed.initiator, 11, "initiator"), (&typed.responder, 12, "responder")]
    {
        assert_eq!(
            hex(&context_commitment_preimage(ctx, &[salt; 32])?),
            fixture["preimages_hex"][name]
        );
    }
    for control in fixture["old_controls"].as_object().ok_or("expected test object")?.values() {
        assert_eq!(
            super::super::framed_hash(
                control["domain"].as_str().ok_or("expected test string")?,
                &control["value"]
            )?,
            control["blake3"]
        );
    }
    let control = &fixture["old_controls"]["object"];
    let envelope: super::super::Envelope<Value> = serde_json::from_value(control["value"].clone())?;
    assert_eq!(super::super::object_hash(&envelope)?, control["blake3"]);
    assert_eq!(
        super::super::signing_bytes("control.v1", &envelope.body)?,
        canonical_json_bytes(&json!({"domain":"control.v1","body":envelope.body}))?
    );
    assert_eq!(domain::CUSTODY_PAIRING_TRANSCRIPT, "ramflux.identity.pairing_transcript.v1");
    assert_eq!(domain::CUSTODY_PAIRING_COMMITMENT, "ramflux.identity.pairing.commitment.v1");
    Ok(())
}
fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    value
        .iter()
        .flat_map(|v| [char::from(HEX[usize::from(v >> 4)]), char::from(HEX[usize::from(v & 15)])])
        .collect()
}

fn nested_shapes<T: PairingWire>(value: &Value) -> TestResult {
    fn walk<T: PairingWire>(root: &Value, current: &Value, path: &str) -> TestResult {
        match current {
            Value::Object(fields) => {
                for (key, child) in fields {
                    let mut missing = root.clone();
                    missing
                        .pointer_mut(path)
                        .ok_or("missing test object")?
                        .as_object_mut()
                        .ok_or("expected test object")?
                        .remove(key);
                    assert_eq!(
                        decode_value::<T>(&missing).err(),
                        Some(WireError::Shape),
                        "{path}/{key}"
                    );
                    walk::<T>(root, child, &format!("{path}/{key}"))?;
                }
                let mut extra = root.clone();
                extra.pointer_mut(path).ok_or("missing test object")?["unexpected"] = json!(true);
                assert_eq!(decode_value::<T>(&extra).err(), Some(WireError::Shape));
            }
            Value::Array(items) => {
                for (n, child) in items.iter().enumerate() {
                    walk::<T>(root, child, &format!("{path}/{n}"))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk::<T>(value, value, "")
}

fn maximal_objects(original: &Value) -> TestResult {
    let mut value = original.clone();
    let mut common = transfer(&original["initiator"]["common"]);
    common["issuer_seq"] = json!(MAX_SAFE_JSON_INTEGER);
    common["device_set_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
    common["expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    common["lease_not_before"] = json!(MAX_SAFE_JSON_INTEGER - MAX_BRANCH_LEASE_SECONDS);
    common["lease_expires_at"] = json!(MAX_SAFE_JSON_INTEGER);
    common["data_selection"] = json!(
        (0..32)
            .map(|n| json!({"key_id":format!("{n:02}{}","\"".repeat(126)),"purpose":"attachment"}))
            .collect::<Vec<_>>()
    );
    for name in ["initiator", "responder"] {
        value[name]["common"] = common.clone();
        value[name]["device_ref"]["device_id"] =
            json!(format!("{name}{}", "\"".repeat(128 - name.len())));
        value[name]["device_ref"]["device_epoch"] = json!(MAX_SAFE_JSON_INTEGER);
        value[name]["display_name"] = json!("\"".repeat(128));
        value[name]["hpke_key"] = original[name]["sas_key"].clone();
        closed::<RoleContext>(&value[name])?;
    }
    closed::<Transcript>(&value)?;
    let offer = json!({"schema":"ramflux.pairing.ContextOffer.v2","version":2,"common":common});
    closed::<ContextOffer>(&offer)?;
    let reveal = json!({"schema":"ramflux.pairing.Reveal.v2","version":2,"invitation_id":common["invitation_id"],"role":"responder","salt":common["record_hash"],"context":value["responder"]});
    closed::<Reveal>(&reveal)?;
    nested_shapes::<Reveal>(&reveal)?;
    let typed: Common = decode_value(&common)?;
    typed.validate_bounds(MAX_SAFE_JSON_INTEGER - 300, 0, MAX_SAFE_JSON_INTEGER)?;
    Ok(())
}

mod native_relay;
