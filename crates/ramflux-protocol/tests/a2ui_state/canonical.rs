// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! RFC 8785 Appendix B and section 3.2.3 vectors; trusted binary64 serialization is
//! distinct from strict original-byte ingress for exact integer tokens (RFC 7493).
use super::support::*;
use ramflux_protocol::*;
use serde_json::{Value, json};
#[test]
fn rfc8785_appendix_b_binary64_vectors() {
    for (bits, expected) in [
        (0x0000_0000_0000_0000, "0"),
        (0x8000_0000_0000_0000, "0"),
        (0x0000_0000_0000_0001, "5e-324"),
        (0x8000_0000_0000_0001, "-5e-324"),
        (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
        (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
        (0x4340_0000_0000_0000, "9007199254740992"),
        (0xc340_0000_0000_0000, "-9007199254740992"),
        (0x4430_0000_0000_0000, "295147905179352830000"),
        (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
        (0x44b5_2d02_c7e1_4af6, "1e+23"),
        (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
        (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
        (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
        (0x444b_1ae4_d6e2_ef50, "1e+21"),
        (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
        (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
        (0x41b3_de43_5555_5553, "333333333.3333332"),
        (0x41b3_de43_5555_5554, "333333333.33333325"),
        (0x41b3_de43_5555_5555, "333333333.3333333"),
        (0x41b3_de43_5555_5556, "333333333.3333334"),
        (0x41b3_de43_5555_5557, "333333333.33333343"),
        (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
        (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
    ] {
        assert_eq!(canonical_json_string(&f64::from_bits(bits)).unwrap(), expected, "{bits:016x}");
    }
    // JSON cannot represent these; reject before serde's generic float-to-null serialization.
    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(serde_json::Number::from_f64(number).is_none());
    }
}
#[test]
fn rfc8785_utf16_key_order_minimal_escaping_and_no_normalization() {
    let value = json!({"\u{20ac}":1,"\r":2,"\u{fb33}":3,"1":4,"\u{1f600}":5,"\u{80}":6,"\u{f6}":7});
    assert_eq!(
        canonical_json_string(&value).unwrap(),
        "{\"\\r\":2,\"1\":4,\"\u{80}\":6,\"ö\":7,\"€\":1,\"😀\":5,\"\u{fb33}\":3}"
    );
    assert_eq!(
        canonical_json_string(&json!({"\u{e000}":0,"\u{10000}":1})).unwrap(),
        "{\"𐀀\":1,\"\u{e000}\":0}"
    );
    assert_eq!(
        canonical_json_string(&json!("\u{c}\n\r\t\u{8}\u{0}/\\\"é")).unwrap(),
        "\"\\f\\n\\r\\t\\b\\u0000/\\\\\\\"é\""
    );
    assert_ne!(
        surface_hash(&json!({"text":"é"})).unwrap(),
        surface_hash(&json!({"text":"e\u{301}"})).unwrap()
    );
}
#[test]
fn typed_snapshot_hash_matches_the_existing_a2ui_hash_fieldset() {
    let mut snapshot = snapshot();
    snapshot.components.push(
        json!({"id":"progress","kind":"progress","value":1.0,"data":{"\u{e000}":0,"\u{10000}":1}}),
    );
    let value = serde_json::to_value(&snapshot).unwrap();
    let hash = surface_hash(&value).unwrap();
    assert_eq!(surface_snapshot_hash(&snapshot).unwrap(), hash);
    let mut with_hash = value.clone();
    with_hash["surfaceHash"] = json!("ignored");
    with_hash["surface_hash"] = json!("ignored");
    assert_eq!(surface_hash(&with_hash).unwrap(), hash);
    for key in [
        "surfaceId",
        "surfaceType",
        "catalog",
        "catalogVersion",
        "fallbackText",
        "fallbackMarkdown",
        "components",
        "dataModel",
        "allowedActions",
    ] {
        let mut changed = value.clone();
        changed[key] = json!("changed");
        assert_ne!(surface_hash(&changed).unwrap(), hash, "{key}");
    }
    assert!(!hash.contains(':'));
    assert_eq!(hash.len(), 43);
    let bytes = canonical_json_bytes(&value).unwrap();
    assert_eq!(hash, hash_base64url(domain::A2UI_SURFACE_HASH, &bytes));
    assert!(String::from_utf8(bytes).unwrap().contains("\"value\":1"));
    let _: Value = parse_i_json(&serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn frozen_existing_hash_goldens_cover_both_desktop_divergences() {
    let vectors: Value = serde_json::from_str(include_str!("goldens.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let snapshot: CreateSurfaceCommand =
            serde_json::from_value(vector["snapshot"].clone()).unwrap();
        assert_eq!(
            canonical_json_string(&snapshot).unwrap(),
            vector["canonical"].as_str().unwrap()
        );
        assert_eq!(surface_snapshot_hash(&snapshot).unwrap(), vector["hash"].as_str().unwrap());
        assert_eq!(surface_hash(&vector["snapshot"]).unwrap(), vector["hash"].as_str().unwrap());
    }
}

#[test]
fn original_signed_a2ui_v1_fixture_retains_canonical_bytes_and_hash() {
    let bytes = include_bytes!("../../fixtures/protocol/v1/a2ui_surface/fixture.json");
    let event: A2uiSurfaceEvent = parse_i_json(bytes).unwrap();
    let canonical = signed_bytes(&event).unwrap();
    assert_eq!(
        canonical,
        include_bytes!("../../fixtures/protocol/v1/a2ui_surface/fixture.canonical")
    );
    assert_eq!(
        hash_hex(&event.domain, &canonical),
        include_str!("../../fixtures/protocol/v1/a2ui_surface/fixture.hash")
    );
}
