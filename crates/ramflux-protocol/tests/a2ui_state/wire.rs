// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::support::*;
use ramflux_protocol::*;
use serde_json::{Value, json};
#[test]
fn strict_ingress_rejects_duplicate_decoded_names_at_every_depth() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"nested":{"x":0,"x":1}}"#,
        r#"[{"x":0,"x":1}]"#,
    ] {
        assert!(parse_i_json::<Value>(input.as_bytes()).is_err(), "{input}");
    }
    let encoded = serde_json::to_string(&event(1, A2uiCommand::CreateSurface(snapshot()))).unwrap();
    let duplicate = encoded.replace(r#""kind":"text""#, r#""kind":"text","kind":"button""#);
    assert_ne!(encoded, duplicate);
    assert!(serde_json::from_str::<A2uiConversationEvent>(&duplicate).is_err());
    let encoded = serde_json::to_string(&action(&created())).unwrap();
    let duplicate = encoded.replace(r#""approved":true"#, r#""approved":true,"approved":false"#);
    assert!(serde_json::from_str::<A2uiSurfaceAction>(&duplicate).is_err());
}
#[test]
fn strict_ingress_rejects_invalid_unicode_and_unsafe_numeric_tokens() {
    for input in [
        r#""\ud800""#,
        r#""\udfff""#,
        r#""\ufdd0""#,
        r#""\uffff""#,
        r#""\udbff\udfff""#,
        "NaN",
        "Infinity",
        "1e400",
        "1e-400",
        "-1e400",
        "9007199254740992",
        "-9007199254740992",
        "18446744073709551616",
        "{} {}",
    ] {
        assert!(parse_i_json::<Value>(input.as_bytes()).is_err(), "{input}");
    }
    assert!(parse_i_json::<Value>(&[b'"', 0xff, b'"']).is_err());
    for input in [
        "9007199254740991",
        "-9007199254740991",
        "1.7976931348623157e308",
        "-0",
        "1.0",
        r#""9007199254740992""#,
        r#""\ud800\udc00""#,
    ] {
        assert!(parse_i_json::<Value>(input.as_bytes()).is_ok(), "{input}");
    }
}
#[test]
fn versioned_wire_round_trips_and_rejects_unknown_fields_and_schemas() {
    let event = event(1, A2uiCommand::CreateSurface(snapshot()));
    assert_eq!(
        parse_i_json::<A2uiConversationEvent>(&serde_json::to_vec(&event).unwrap()).unwrap(),
        event
    );
    assert_eq!(
        serde_json::from_value::<A2uiConversationEvent>(serde_json::to_value(&event).unwrap())
            .unwrap(),
        event
    );
    let a = action(&created());
    assert_eq!(
        serde_json::from_slice::<A2uiSurfaceAction>(&serde_json::to_vec(&a).unwrap()).unwrap(),
        a
    );
    for mutate in 0..3 {
        let mut value = serde_json::to_value(&event).unwrap();
        match mutate {
            0 => value["schema"] = json!("ramflux.a2ui.conversation.v3"),
            1 => {
                value["unexpected"] = json!(true);
            }
            _ => value["command"]["unexpected"] = json!(true),
        }
        assert!(serde_json::from_value::<A2uiConversationEvent>(value).is_err());
    }
    let text = serde_json::to_string(&event)
        .unwrap()
        .replace("\"text\":\"\"", "\"text\":9007199254740992");
    assert!(serde_json::from_str::<A2uiConversationEvent>(&text).is_err());
}
