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
    let encoded =
        serde_json::to_string(&event(1, A2uiConversationCommand::CreateSurface(snapshot())))
            .unwrap();
    let duplicate = encoded.replace(r#""kind":"text""#, r#""kind":"text","kind":"button""#);
    assert_ne!(encoded, duplicate);
    assert!(A2uiConversationEvent::from_wire_bytes(duplicate.as_bytes()).is_err());
    let encoded = serde_json::to_string(&action(&created())).unwrap();
    let duplicate = encoded.replace(r#""approved":true"#, r#""approved":true,"approved":false"#);
    assert!(A2uiSurfaceAction::from_wire_bytes(duplicate.as_bytes()).is_err());
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
    let event = event(1, A2uiConversationCommand::CreateSurface(snapshot()));
    assert_eq!(
        A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&event).unwrap()).unwrap(),
        event
    );
    let action = action(&created());
    assert_eq!(
        A2uiSurfaceAction::from_wire_bytes(&serde_json::to_vec(&action).unwrap()).unwrap(),
        action
    );
    for mutate in 0..3 {
        let mut value = serde_json::to_value(&event).unwrap();
        match mutate {
            0 => value["schema"] = json!("ramflux.a2ui.conversation.v3"),
            1 => value["unexpected"] = json!(true),
            _ => value["command"]["unexpected"] = json!(true),
        }
        assert!(
            A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&value).unwrap()).is_err()
        );
    }
    let text = serde_json::to_string(&event)
        .unwrap()
        .replace("\"text\":\"\"", "\"text\":9007199254740992");
    assert!(matches!(
        A2uiConversationEvent::from_wire_bytes(text.as_bytes()),
        Err(ProtocolError::IJson(_))
    ));
}
#[test]
fn legacy_v1_decoder_rejects_both_v2_only_commands() {
    for command in [
        json!({"command":"streamAppend","surfaceId":"s","componentId":"text","textDelta":"x","final":true}),
        json!({"command":"patchSurface","surfaceId":"s","baseSurfaceHash":"a","ops":[],"newSurfaceHash":"b"}),
    ] {
        assert!(serde_json::from_value::<A2uiCommand>(command.clone()).is_err());
        let wire = json!({"schema":A2UI_CONVERSATION_SCHEMA,"conversationId":"c","version":2,"command":command});
        assert!(
            A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&wire).unwrap()).is_ok()
        );
    }
    for command in [
        A2uiCommand::CreateSurface(snapshot()),
        A2uiCommand::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }),
    ] {
        let wire = serde_json::to_vec(&command).unwrap();
        assert_eq!(serde_json::from_slice::<A2uiCommand>(&wire).unwrap(), command);
    }
}
#[test]
fn duplicate_ingress_is_a_distinct_error_before_last_wins_conversion() {
    let wire = serde_json::to_string(&event(1, A2uiConversationCommand::CreateSurface(snapshot())))
        .unwrap();
    let duplicate = wire.replace(r#""text":"""#, r#""text":"first","text":"last""#);
    assert_ne!(wire, duplicate);
    let dropped: Value = serde_json::from_str(&duplicate).unwrap();
    assert_eq!(dropped["command"]["components"][0]["text"], "last");
    let error = A2uiConversationEvent::from_wire_bytes(duplicate.as_bytes()).unwrap_err();
    assert!(matches!(error, ProtocolError::IJson(_)));
    assert!(error.to_string().starts_with("I-JSON ingress rejected:"));
    // Compile-fail API tests prove this dropped-duplicate Value cannot be converted to a
    // validated event or passed to apply. No public Deserialize implementation exists.
}
