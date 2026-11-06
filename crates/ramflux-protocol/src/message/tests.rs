// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use prost::Message as _;

#[test]
fn protojson_integer_presence_unicode_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let update =
        MessageUpdate { journal_sequence: u64::MAX, account_id: "a".into(), ..Default::default() };
    let json = serde_json::to_string(&update)?;
    assert!(json.contains("\"journalSequence\":\"18446744073709551615\""));
    assert_eq!(from_protojson::<MessageUpdate>(&json)?, update);
    assert_eq!(
        from_protojson::<MessageUpdate>(r#"{"journalSequence":9007199254740993}"#)?
            .journal_sequence,
        9_007_199_254_740_993
    );
    for value in [i64::MIN, i64::MAX] {
        let original = ObjectRevokeAccess { effective_at: value, ..Default::default() };
        assert_eq!(
            from_protojson::<ObjectRevokeAccess>(&serde_json::to_string(&original)?)?,
            original
        );
    }
    let original =
        Message { text: "é e\u{301} 👩🏽‍💻 中文".into(), ..Default::default() };
    assert_eq!(from_protojson::<Message>(&serde_json::to_string(&original)?)?, original);
    assert_eq!(Message::decode(original.encode_to_vec().as_slice())?, original);
    let absent = EventIdentity::default();
    let present =
        EventIdentity { group_id: Some(String::new()), group_epoch: Some(0), ..Default::default() };
    assert_eq!(serde_json::to_string(&absent)?, "{}");
    assert_eq!(serde_json::to_string(&present)?, r#"{"groupId":"","groupEpoch":"0"}"#);
    assert_eq!(from_protojson::<EventIdentity>(&serde_json::to_string(&present)?)?, present);
    let inner = Inner { body: vec![0, 255, 254], ..Default::default() };
    assert_eq!(serde_json::to_string(&inner)?, r#"{"body":"AP/+"}"#);
    assert_eq!(from_protojson::<Inner>(r#"{"body":"AP_-"}"#)?, inner);
    assert_eq!(from_protojson::<EventIdentity>(r#"{"groupEpoch":null}"#)?, absent);
    assert_eq!(
        from_protojson::<Entity>(r#"{"kind":"ENTITY_BOLD"}"#)?.kind,
        EntityKind::EntityBold as i32
    );
    let map = SurfaceExportMetadata {
        skipped: [("a_b".into(), 1), ("ab".into(), 2)].into(),
        ..Default::default()
    };
    assert_eq!(from_protojson::<SurfaceExportMetadata>(&serde_json::to_string(&map)?)?, map);
    duplicate_map_keys_are_rejected()?;
    let unknown = Entity { kind: 9876, ..Default::default() };
    assert_eq!(serde_json::to_string(&unknown)?, r#"{"kind":9876}"#);
    assert_eq!(from_protojson::<Entity>(r#"{"kind":9876}"#)?, unknown);
    assert_eq!(from_protojson::<EventIdentity>(r#"{"group_epoch":"7"}"#)?.group_epoch, Some(7));
    for bad in [
        r#"{"groupEpoch":"1","group_epoch":"2"}"#,
        r#"{"groupEpoch":null,"group_epoch":"2"}"#,
        r#"{"groupEpoch":null,"groupEpoch":null}"#,
        r#"{"unknown":1}"#,
        r#"{"groupEpoch":"18446744073709551616"}"#,
    ] {
        assert!(from_protojson::<EventIdentity>(bad).is_err(), "accepted {bad}");
    }
    assert!(from_protojson::<MessageRequest>(r#"{"send":{},"edit":{}}"#).is_err());
    Ok(())
}

fn duplicate_map_keys_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for invalid in [
        r#"{"skipped":{"a":1,"a":2}}"#,
        r#"{"skipped":{"a":1,"a":1}}"#,
        r#"{"skipped":{"a":0,"a":2}}"#,
        r#"{"skipped":{"":1,"":2}}"#,
        r#"{"skipped":{"a":1,"\u0061":2}}"#,
        r#"{"skipped":{"😀":1,"\ud83d\ude00":2}}"#,
    ] {
        assert!(
            from_protojson::<SurfaceExportMetadata>(invalid).is_err(),
            "accepted duplicate map key: {invalid}"
        );
        assert!(serde_json::from_str::<SurfaceExportMetadata>(invalid).is_err());
    }
    assert!(
        from_protojson::<SurfaceHistoryExport>(r#"{"metadata":{"skipped":{"a":1,"a":2}}}"#)
            .is_err()
    );
    let valid = from_protojson::<SurfaceExportMetadata>(
        r#"{"skipped":{"a_b":0,"ab":1,"é":2,"e\u0301":3}}"#,
    )?;
    assert_eq!(valid.skipped.len(), 4);
    assert_eq!(from_protojson::<SurfaceExportMetadata>(&serde_json::to_string(&valid)?)?, valid);
    Ok(())
}

#[test]
fn canonical_protobuf_binary_vectors_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    fn identity<T: prost::Message + Default>(bytes: &[u8]) -> Result<(), prost::DecodeError> {
        assert_eq!(T::decode(bytes)?.encode_to_vec(), bytes);
        Ok(())
    }
    identity::<Inner>(&[0x08, 1, 0x10, 1, 0x22, 3, 0x0a, 1, b'x'])?;
    identity::<EventIdentity>(&[0x32, 0, 0x38, 0])?; // explicit optional empty/zero
    identity::<Message>(&[0x0a, 7, b'A', 0xf0, 0x9f, 0x98, 0x80, 0xc3, 0xa9])?;
    identity::<SurfaceExportMetadata>(&[
        0x1a, 5, 0x0a, 1, b'a', 0x10, 1, 0x1a, 5, 0x0a, 1, b'b', 0x10, 2,
    ])?;
    let mut maximum = vec![0x0a, 1, b'a', 0x12, 1, b'b', 0x18];
    maximum.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
    identity::<QualifiedDevice>(&maximum)?;
    Ok(())
}

#[test]
fn prost_decoding_does_not_establish_canonicality() -> Result<(), prost::DecodeError> {
    // P03's pre-decode scanner must reject both; prost itself normalizes them.
    for input in [&[0x08, 0x81, 0][..], &[0x10, 1, 0x08, 1][..]] {
        assert_ne!(Inner::decode(input)?.encode_to_vec(), input);
    }
    Ok(())
}
