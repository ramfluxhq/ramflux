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
