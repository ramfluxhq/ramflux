// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{registry::*, validation::*, *};
use prost::Message as _;
use prost_reflect::{DynamicMessage, Kind, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn kind_registry_is_exhaustive_and_reserved() -> TestResult {
    let pool = descriptors()?;
    let enumeration = pool.get_enum_by_name("ramflux.message.v1.KindId").ok_or("KindId absent")?;
    assert_eq!(KINDS.len(), 12);
    for binding in KINDS {
        assert!(enumeration.get_value(i32::try_from(binding.kind)?).is_some());
        assert_eq!(descriptor(binding.body)?.name(), binding.body);
        let field = descriptor("Content")?.get_field(binding.kind).ok_or("Content arm missing")?;
        assert!(matches!(field.kind(), Kind::Message(message) if message.name()==binding.body));
    }
    assert!(kind_binding(0).is_none());
    for reserved in RESERVED_KINDS {
        assert!(kind_binding(reserved).is_none());
        assert!(enumeration.get_value(i32::try_from(reserved)?).is_none());
    }
    let proto = enumeration.enum_descriptor_proto();
    assert!(
        proto.reserved_range.iter().any(|range| range.start == Some(13) && range.end == Some(15))
    );
    assert!(proto.reserved_name.iter().any(|name| name == "KIND_LEGACY_OPAQUE"));
    for binding in CONTROLS {
        assert_eq!(binding.tag, binding.operation + 15, "approved section 3.2 binding");
        let field = descriptor("Control")?.get_field(binding.tag).ok_or("Control arm missing")?;
        assert!(matches!(field.kind(), Kind::Message(message) if message.name()==binding.body));
    }
    for message in pool.all_messages() {
        for field in message.fields() {
            assert!(
                field_layer(message.name(), field.number()).is_some(),
                "missing layer for {}.{}",
                message.name(),
                field.name()
            );
        }
    }
    let mut frozen = std::collections::BTreeSet::new();
    for row in FIELD_LAYERS.lines().filter(|row| !row.starts_with('#')) {
        let mut cells = row.split('\t');
        let message = cells.next().ok_or("missing layer message")?;
        let name = cells.next().ok_or("missing layer field")?;
        let tag: u32 = cells.next().ok_or("missing layer tag")?.parse()?;
        let layer: u32 = cells.next().ok_or("missing layer number")?.parse()?;
        assert!((1..=4).contains(&layer));
        assert!(frozen.insert((message, tag)), "duplicate field introduction");
        let field = pool
            .all_messages()
            .find(|owner| owner.name() == message)
            .ok_or("missing field owner")?
            .get_field_by_name(name)
            .ok_or("stale field introduction")?;
        assert_eq!(field.number(), tag);
    }
    assert_eq!(
        frozen.len(),
        pool.all_messages().map(|message| message.fields().len()).sum::<usize>()
    );
    verify_approved_fields()?;
    Ok(())
}

fn verify_approved_fields() -> TestResult {
    let mut count = 0;
    for row in FIELD_MAPPINGS.lines().filter(|row| !row.starts_with('#')) {
        let mut cells = row.split('\t');
        let message = cells.next().ok_or("missing message")?;
        let name = cells.next().ok_or("missing field")?;
        let tag: u32 = cells.next().ok_or("missing tag")?.parse()?;
        let _native = cells.next().ok_or("missing native field")?;
        let ty = cells.next().ok_or("missing type")?;
        let field = descriptor(message)?.get_field_by_name(name).ok_or("mapped field missing")?;
        assert_eq!(field.number(), tag, "{message}.{name}");
        let mut tokens = ty.split_whitespace();
        let first = tokens.next().ok_or("empty type")?;
        let expected = if matches!(first, "optional" | "repeated") {
            tokens.next().ok_or("empty qualified type")?
        } else {
            first
        };
        if first == "optional" {
            assert!(field.supports_presence(), "{message}.{name}");
        }
        if first == "repeated" {
            assert!(field.is_list(), "{message}.{name}");
        }
        if field.is_map() {
            assert!(ty.starts_with("map<"));
            count += 1;
            continue;
        }
        let actual = match field.kind() {
            Kind::Message(message) => message.name().to_string(),
            Kind::Enum(enumeration) => enumeration.name().to_string(),
            kind => format!("{kind:?}").to_lowercase(),
        };
        assert_eq!(actual, expected, "{message}.{name}");
        count += 1;
    }
    assert_eq!(count, 513, "approved section 3.1 mapping coverage");
    Ok(())
}

// Descriptor-created choices exercise every generated sub-operation, rather than
// hand-writing a parallel set of enum variants in the fixture.
fn populated(descriptor: &prost_reflect::MessageDescriptor, depth: usize) -> DynamicMessage {
    let mut message = DynamicMessage::new(descriptor.clone());
    if depth > 16 {
        return message;
    }
    for oneof in descriptor.oneofs().filter(|oneof| !oneof.is_synthetic()) {
        if let Some(field) = oneof.fields().next()
            && let Kind::Message(child) = field.kind()
        {
            message.set_field(&field, Value::Message(populated(&child, depth + 1)));
        }
    }
    if descriptor.name() == "Control" {
        message.set_field_by_name("operation", Value::EnumNumber(1));
    }
    message
}

#[test]
fn all_kind_binding_round_trip() -> TestResult {
    let reference =
        MessageRef { id: vec![1], conversation_id: "c".into(), author_anchor: "a".into() };
    let mut values = vec![
        content::Value::Message(Message { text: "hello 😀".into(), ..Default::default() }),
        content::Value::Service(Service { action: 1, ..Default::default() }),
        content::Value::Edit(Edit {
            target: Some(reference.clone()),
            revision: 1,
            replacement: Some(Message { text: "edit".into(), ..Default::default() }),
            ..Default::default()
        }),
        content::Value::Delete(Delete {
            targets: vec![reference.clone()],
            scope: 1,
            ..Default::default()
        }),
        content::Value::Reaction(Reaction {
            target: Some(reference),
            token: "👩🏽‍💻".into(),
            ..Default::default()
        }),
        content::Value::Receipt(Receipt { state: 1, ..Default::default() }),
        content::Value::Typing(Typing { active: true, expires_at: 1 }),
        content::Value::Control(Control {
            operation: 1,
            payload: Some(control::Payload::Reset(PairReset { rejected_bootstrap_floor: 1 })),
        }),
        content::Value::Surface(Surface {
            payload: Some(surface::Payload::OwnHistory(SurfaceHistoryExport::default())),
        }),
        content::Value::Task(Task {
            payload: Some(task::Payload::OwnHistory(TaskHistoryExport::default())),
        }),
        content::Value::Call(Call {
            control: Some(CallControl {
                body: Some(CallAction {
                    value: Some(call_action::Value::Ringing(CallActionRinging {})),
                }),
                ..Default::default()
            }),
        }),
        content::Value::SelfSync(SelfSync { revision: 1, ..Default::default() }),
    ];
    for value in values.drain(..) {
        let content = Content { value: Some(value) };
        let (kind, bytes) = encode_body(&content)?;
        assert_eq!(decode_body(kind, &bytes, 2)?, content);
        let inner =
            Inner { layer: 2, kind, body: bytes.clone(), ..Default::default() }.encode_to_vec();
        let scanned = scan_inner(&inner)?;
        assert_eq!(scanned.outcome, ScanOutcome::Supported);
        assert_eq!(scanned.body, bytes);
        assert_eq!(scanned.exact_inner, inner);
        let (_, encoded) = encode_body(&decode_body(kind, &bytes, 2)?)?;
        assert_eq!(encoded, bytes, "canonical decode/encode identity");
    }
    verify_every_operation()?;
    Ok(())
}

fn verify_every_operation() -> TestResult {
    for message in descriptors()?.all_messages() {
        for choice in message.oneofs().filter(|choice| !choice.is_synthetic()) {
            for field in choice.fields() {
                let Kind::Message(child) = field.kind() else {
                    continue;
                };
                let mut body = DynamicMessage::new(message.clone());
                body.set_field(&field, Value::Message(populated(&child, 0)));
                if message.name() == "Control" {
                    let operation = CONTROLS
                        .iter()
                        .find(|binding| binding.tag == field.number())
                        .ok_or("unmapped control")?;
                    body.set_field_by_name(
                        "operation",
                        Value::EnumNumber(i32::try_from(operation.operation)?),
                    );
                }
                let bytes = body.encode_to_vec();
                // JsonValue.number/string/bool are primitive arms, covered by conformance;
                // all message-valued operation arms, including unit markers, are exercised.
                assert_eq!(
                    scan_message(message.name(), &bytes, 4)?,
                    ScanOutcome::Supported,
                    "{}.{}",
                    message.name(),
                    field.name()
                );
                assert_eq!(
                    DynamicMessage::decode(message.clone(), bytes.as_slice())?.encode_to_vec(),
                    bytes
                );
            }
        }
    }
    let bad =
        Control { operation: 2, payload: Some(control::Payload::Reset(PairReset::default())) }
            .encode_to_vec();
    assert_eq!(scan_message("Control", &bad, 2), Err(ValidationError::Operation));
    Ok(())
}

#[test]
fn entity_unknown_is_projection_only_and_reaction_token_is_bounded() -> TestResult {
    let mut message = Message {
        text: "A😀é".into(),
        entities: vec![Entity { offset: 1, length: 2, kind: 1, value: None }],
        ..Default::default()
    };
    validate_message(&message)?;
    message.entities.first_mut().ok_or("entity missing")?.kind = 999;
    let raw = message.encode_to_vec();
    assert_eq!(scan_message("Message", &raw, 2)?, ScanOutcome::Unsupported);
    let mut removed = Entity { offset: 1, length: 1, kind: 1, value: None }.encode_to_vec();
    removed.extend_from_slice(&[0x2a, 0x01, b'x']);
    assert_eq!(scan_message("Entity", &removed, 2)?, ScanOutcome::Unsupported);
    for token in ["👍", "👩🏽‍💻", "e\u{301}"] {
        validate_reaction_token(token)?;
    }
    // One combining grapheme, exactly 64 UTF-8 bytes, then 65 bytes. The test
    // isolates the byte ceiling, independently of the one-grapheme predicate.
    let at_cap = format!("a{}\u{20dd}", "\u{301}".repeat(30));
    assert_eq!(at_cap.len(), 64);
    validate_reaction_token(&at_cap)?;
    let over_cap = format!("a{}", "\u{301}".repeat(32));
    assert_eq!(over_cap.len(), 65);
    for remove in [false, true] {
        let reaction = Reaction { token: over_cap.clone(), remove, ..Default::default() };
        let bytes = reaction.encode_to_vec();
        assert!(scan_message("Reaction", &bytes, 2).is_err());
        assert!(
            validate_content(&Content { value: Some(content::Value::Reaction(reaction)) }).is_err()
        );
    }
    for invalid in ["", " ", "\n", "👍👍"] {
        assert!(validate_reaction_token(invalid).is_err());
    }
    message.entities.first_mut().ok_or("entity missing")?.kind = 1;
    message.entities.first_mut().ok_or("entity missing")?.length = 3;
    assert_eq!(validate_message(&message), Err(ValidationError::Content));
    Ok(())
}

#[test]
fn scanner_preserves_unknown_and_rejects_noncanonical_bounds() -> TestResult {
    for bytes in [&[0x08, 0x81, 0][..], &[0x10, 1, 0x08, 1][..]] {
        assert_eq!(scan_message("Inner", bytes, 2), Err(ValidationError::NonCanonical));
    }
    assert_eq!(
        scan_message("Message", &[0x0a, 0x81, 0x00, b'x'], 2),
        Err(ValidationError::NonCanonical)
    );
    assert_eq!(scan_message("Typing", &[0x08, 0x02], 2), Err(ValidationError::Malformed));
    assert_eq!(
        scan_message("Typing", &[0x08, 0x01, 0x08, 0x01], 2),
        Err(ValidationError::NonCanonical)
    );
    assert_eq!(scan_message("Message", &[0x0a, 0x02, b'x'], 2), Err(ValidationError::Malformed));
    let duplicate = CallAction { value: Some(call_action::Value::Ringing(CallActionRinging {})) }
        .encode_to_vec();
    let mut two = duplicate;
    two.extend_from_slice(&[0x32, 0]);
    assert_eq!(scan_message("CallAction", &two, 2), Err(ValidationError::MissingChoice));
    let unknown = Inner { layer: 99, kind: 1234, body: vec![0xff, 0x00], ..Default::default() }
        .encode_to_vec();
    let scanned = scan_inner(&unknown)?;
    assert_eq!(scanned.outcome, ScanOutcome::Unsupported);
    assert_eq!(scanned.exact_inner, unknown);
    let map = SurfaceExportMetadata {
        skipped: [(String::new(), 0), ("a".into(), 1), ("b".into(), 2)].into(),
        ..Default::default()
    };
    assert_eq!(
        scan_message("SurfaceExportMetadata", &map.encode_to_vec(), 2)?,
        ScanOutcome::Supported
    );
    let repeated = [0x1a, 5, 0x0a, 1, b'a', 0x10, 1, 0x1a, 5, 0x0a, 1, b'a', 0x10, 2];
    assert_eq!(
        scan_message("SurfaceExportMetadata", &repeated, 2),
        Err(ValidationError::NonCanonical)
    );
    let reordered = [0x1a, 5, 0x0a, 1, b'b', 0x10, 1, 0x1a, 5, 0x0a, 1, b'a', 0x10, 2];
    assert_eq!(
        scan_message("SurfaceExportMetadata", &reordered, 2),
        Err(ValidationError::NonCanonical)
    );
    let max_entities = Message {
        text: "a".into(),
        entities: vec![Entity { offset: 0, length: 1, kind: 1, value: None }; MAX_ENTITIES],
        ..Default::default()
    };
    assert_eq!(scan_message("Message", &max_entities.encode_to_vec(), 2)?, ScanOutcome::Supported);
    let mut excessive = max_entities;
    excessive.entities.push(Entity { length: 1, kind: 1, ..Default::default() });
    assert_eq!(scan_message("Message", &excessive.encode_to_vec(), 2), Err(ValidationError::Limit));
    let media = Message { media: vec![MediaRef::default(); MAX_MEDIA + 1], ..Default::default() };
    assert_eq!(scan_message("Message", &media.encode_to_vec(), 2), Err(ValidationError::Limit));
    let mut nested = JsonValue { value: Some(json_value::Value::Null(JsonNull {})) };
    for _ in 0..MAX_DEPTH {
        nested =
            JsonValue { value: Some(json_value::Value::Array(JsonArray { values: vec![nested] })) };
    }
    assert_eq!(scan_message("JsonValue", &nested.encode_to_vec(), 2), Err(ValidationError::Limit));
    let text = Message { text: "a".repeat(MAX_TEXT_BYTES + 1), ..Default::default() };
    assert_eq!(scan_message("Message", &text.encode_to_vec(), 2), Err(ValidationError::Limit));
    Ok(())
}
