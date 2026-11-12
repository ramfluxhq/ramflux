// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{registry::*, validation::*, *};
use prost::Message as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 128 {
        bytes.push((value.to_le_bytes()[0] & 127) | 128);
        value >>= 7;
    }
    bytes.push(value.to_le_bytes()[0]);
    bytes
}
fn blob(tag: u32, bytes: &[u8]) -> Vec<u8> {
    let mut result = varint(u64::from(tag) * 8 + 2);
    result.extend(varint(bytes.len() as u64));
    result.extend(bytes);
    result
}
fn scalar(tag: u32, value: u64) -> Vec<u8> {
    let mut result = varint(u64::from(tag) * 8);
    result.extend(varint(value));
    result
}

#[test]
fn every_interleaved_oneof_has_a_field_order_encoder() -> TestResult {
    let pool = descriptors()?;
    assert_eq!(pool.all_messages().filter(|message| !message.is_map_entry()).count(), 255);
    assert_eq!(pool.all_messages().count(), 256);
    let mut interleaved = Vec::new();
    for message in pool.all_messages() {
        for choice in message.oneofs().filter(|choice| !choice.is_synthetic()) {
            let low = choice.fields().map(|f| f.number()).min().ok_or("empty choice")?;
            let high = choice.fields().map(|f| f.number()).max().ok_or("empty choice")?;
            if message.fields().any(|f| {
                f.containing_oneof().as_ref() != Some(&choice)
                    && f.number() > low
                    && f.number() < high
            }) {
                interleaved.push((message.name().to_owned(), choice.name().to_owned()));
            }
        }
    }
    assert_eq!(interleaved, [("OwnMessageCopy".into(), "payload".into())]);
    Ok(())
}

#[test]
fn byte_limits_accept_the_cap_and_reject_one_more() -> TestResult {
    let mut caps = vec![
        ("Thumbnail".to_owned(), "encoded_image", 16 * 1024),
        ("Service".to_owned(), "native_authority_proof", 8 * 1024),
        ("GroupSealedContent".to_owned(), "native_authority_proof", 8 * 1024),
    ];
    let pool = descriptors()?;
    for message in pool.all_messages().filter(|m| m.name().starts_with("Native")) {
        if message.get_field_by_name("canonical").is_some() {
            caps.push((message.name().to_owned(), "canonical", 8 * 1024));
        }
    }
    for (name, field, cap) in caps {
        let tag = descriptor(&name)?.get_field_by_name(field).ok_or("field missing")?.number();
        assert_eq!(
            scan_message(&name, &blob(tag, &vec![1; cap]), 2),
            Ok(ScanOutcome::Supported),
            "{name}.{field}"
        );
        assert_eq!(
            scan_message(&name, &blob(tag, &vec![1; cap + 1]), 2),
            Err(ValidationError::Limit),
            "{name}.{field}"
        );
    }
    for size in [16 * 1024, 16 * 1024 + 1] {
        let message = Message {
            media: vec![MediaRef {
                inline_thumbnail: Some(Thumbnail {
                    encoded_image: vec![1; size],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            validate_message(&message),
            if size == 16 * 1024 { Ok(()) } else { Err(ValidationError::Limit) }
        );
    }
    // Known fields reach the complete delivery caps without hitting a nested cap.
    for name in ["Task", "Surface"] {
        for size in [30_720, 30_721] {
            let bytes = if name == "Task" {
                blob(16, &blob(7, &vec![b'x'; size - 9]))
            } else {
                blob(18, &blob(2, &blob(4, &vec![b'x'; size - 13])))
            };
            assert_eq!(bytes.len(), size);
            assert_eq!(
                scan_message(name, &bytes, 2),
                if size == 30_720 {
                    Ok(ScanOutcome::Supported)
                } else {
                    Err(ValidationError::Limit)
                },
                "{name}"
            );
        }
    }
    for size in [MAX_INNER_BYTES, MAX_INNER_BYTES + 1] {
        let bytes = blob(4, &vec![1; size - 4]);
        assert_eq!(bytes.len(), size);
        assert_eq!(
            scan_message("Inner", &bytes, 2),
            if size == MAX_INNER_BYTES {
                Ok(ScanOutcome::Supported)
            } else {
                Err(ValidationError::Limit)
            }
        );
    }
    for size in [MAX_TEXT_BYTES, MAX_TEXT_BYTES + 1] {
        let message = Message { text: "a".repeat(size), ..Default::default() };
        assert_eq!(
            validate_message(&message),
            if size == MAX_TEXT_BYTES { Ok(()) } else { Err(ValidationError::Limit) }
        );
        assert_eq!(
            scan_message("Message", &message.encode_to_vec(), 2),
            if size == MAX_TEXT_BYTES {
                Ok(ScanOutcome::Supported)
            } else {
                Err(ValidationError::Limit)
            }
        );
    }
    Ok(())
}

#[test]
fn identifiers_and_scalar_encodings_have_exact_errors() -> TestResult {
    for (value, expected) in [
        ("a".repeat(256), Ok(ScanOutcome::Supported)),
        ("a".repeat(257), Err(ValidationError::Limit)),
        ("é".repeat(128), Ok(ScanOutcome::Supported)),
        (format!("{}a", "é".repeat(128)), Err(ValidationError::Limit)),
    ] {
        assert_eq!(scan_message("QualifiedDevice", &blob(2, value.as_bytes()), 2), expected);
    }
    for control in ['\0', '\n', '\r', '\t', '\u{7f}', '\u{85}'] {
        assert_eq!(
            scan_message("QualifiedDevice", &blob(2, format!("a{control}b").as_bytes()), 2),
            Err(ValidationError::Content)
        );
    }
    assert_eq!(
        scan_message("QualifiedDevice", &blob(2, &[0xff]), 2),
        Err(ValidationError::Malformed)
    );
    assert_eq!(
        scan_message("Inner", &scalar(1, u64::from(u32::MAX)), 2),
        Ok(ScanOutcome::Supported)
    );
    assert_eq!(
        scan_message("Inner", &scalar(1, u64::from(u32::MAX) + 1), 2),
        Err(ValidationError::Malformed)
    );
    // The application descriptor currently has no int32/sint32 fields. A synthetic
    // descriptor exercises their scanner rules without changing the public schema.
    for (ty, valid, invalid) in [
        ("int32", i32::MAX as u64, i32::MAX as u64 + 1),
        ("sint32", u64::from(u32::MAX), u64::from(u32::MAX) + 1),
    ] {
        scalar_descriptor_boundary(ty, valid, invalid)?;
    }
    for (name, bytes, error) in [
        ("Typing", blob(1, &[1]), ValidationError::Malformed),
        ("Typing", scalar(1, 0), ValidationError::NonCanonical),
        ("Message", blob(1, &[]), ValidationError::NonCanonical),
        ("Task", vec![], ValidationError::MissingChoice),
        ("Content", vec![], ValidationError::MissingChoice),
    ] {
        assert_eq!(scan_message(name, &bytes, 2), Err(error));
    }
    Ok(())
}

fn scalar_descriptor_boundary(ty: &str, valid: u64, invalid: u64) -> TestResult {
    // Reuse a reflected descriptor proto and change only its scalar field kind.
    let mut file = descriptor("Inner")?.parent_file().file_descriptor_proto().clone();
    let owner = file
        .message_type
        .iter_mut()
        .find(|m| m.name.as_deref() == Some("Inner"))
        .ok_or("Inner absent")?;
    let field = owner.field.iter_mut().find(|f| f.number == Some(1)).ok_or("layer absent")?;
    // FieldDescriptorProto::Type numeric values from descriptor.proto.
    field.r#type = Some(if ty == "int32" { 5 } else { 17 });
    let mut pool = prost_reflect::DescriptorPool::new();
    pool.add_file_descriptor_proto(file)?;
    let descriptor = pool.get_message_by_name("ramflux.message.v1.Inner").ok_or("Inner missing")?;
    assert_eq!(
        super::scanner::scan(&descriptor, &scalar(1, valid), 2, 0),
        Ok(ScanOutcome::Supported)
    );
    assert_eq!(
        super::scanner::scan(&descriptor, &scalar(1, invalid), 2, 0),
        Err(ValidationError::Malformed)
    );
    if ty == "int32" {
        assert_eq!(
            super::scanner::scan(&descriptor, &scalar(1, u64::MAX), 2, 0),
            Ok(ScanOutcome::Supported)
        );
        assert_eq!(
            super::scanner::scan(&descriptor, &scalar(1, 0xffff_ffff), 2, 0),
            Err(ValidationError::Malformed)
        );
    }
    Ok(())
}

#[test]
fn sealed_content_and_entity_ranges_have_exact_errors() {
    let sealed =
        Message { sealed_group: Some(GroupSealedContent::default()), ..Default::default() };
    assert_eq!(validate_message(&sealed), Ok(()));
    for part in 0..5 {
        let mut message = sealed.clone();
        match part {
            0 => message.text = "x".into(),
            1 => message.entities.push(Entity { length: 1, kind: 1, ..Default::default() }),
            2 => message.media.push(MediaRef::default()),
            3 => message.reply_to = Some(MessageRef::default()),
            _ => message.forward = Some(Forward::default()),
        }
        assert_eq!(validate_message(&message), Err(ValidationError::Content));
    }
    for (offset, length) in [(0, 0), (1, 1), (u32::MAX, 1), (1, u32::MAX)] {
        let message = Message {
            text: "x".into(),
            entities: vec![Entity { offset, length, kind: 1, value: None }],
            ..Default::default()
        };
        assert_eq!(validate_message(&message), Err(ValidationError::Content));
    }
    assert_eq!(validate_content(&Content::default()), Err(ValidationError::MissingChoice));
    assert_eq!(
        validate_content(&Content { value: Some(content::Value::Edit(Edit::default())) }),
        Err(ValidationError::Content)
    );
}

#[test]
fn collection_and_recursion_caps_have_exact_errors() -> TestResult {
    for count in [MAX_ENTITIES, MAX_ENTITIES + 1] {
        let message = Message {
            text: "x".into(),
            entities: vec![Entity { length: 1, kind: 1, ..Default::default() }; count],
            ..Default::default()
        };
        assert_eq!(
            validate_message(&message),
            if count == MAX_ENTITIES { Ok(()) } else { Err(ValidationError::Limit) }
        );
        assert_eq!(
            scan_message("Message", &message.encode_to_vec(), 2),
            if count == MAX_ENTITIES {
                Ok(ScanOutcome::Supported)
            } else {
                Err(ValidationError::Limit)
            }
        );
    }
    for count in [MAX_MEDIA, MAX_MEDIA + 1] {
        let message = Message { media: vec![MediaRef::default(); count], ..Default::default() };
        assert_eq!(
            validate_message(&message),
            if count == MAX_MEDIA { Ok(()) } else { Err(ValidationError::Limit) }
        );
        assert_eq!(
            scan_message("Message", &message.encode_to_vec(), 2),
            if count == MAX_MEDIA {
                Ok(ScanOutcome::Supported)
            } else {
                Err(ValidationError::Limit)
            }
        );
    }
    let mut nested = JsonValue { value: Some(json_value::Value::Null(JsonNull {})) };
    // Each array traverses JsonArray and JsonValue; the leaf JsonNull adds one.
    for _ in 0..(MAX_DEPTH / 2 - 1) {
        nested =
            JsonValue { value: Some(json_value::Value::Array(JsonArray { values: vec![nested] })) };
    }
    assert_eq!(scan_message("JsonValue", &nested.encode_to_vec(), 2), Ok(ScanOutcome::Supported));
    let descriptor = descriptor("JsonValue")?;
    let leaf = JsonValue { value: Some(json_value::Value::Null(JsonNull {})) }.encode_to_vec();
    assert_eq!(
        super::scanner::scan(&descriptor, &leaf, 2, MAX_DEPTH - 1),
        Ok(ScanOutcome::Supported)
    );
    assert_eq!(super::scanner::scan(&descriptor, &leaf, 2, MAX_DEPTH), Err(ValidationError::Limit));
    let nested =
        JsonValue { value: Some(json_value::Value::Array(JsonArray { values: vec![nested] })) };
    assert_eq!(scan_message("JsonValue", &nested.encode_to_vec(), 2), Err(ValidationError::Limit));
    Ok(())
}

#[test]
fn every_closed_choice_requires_an_arm() -> TestResult {
    for message in descriptors()?.all_messages() {
        if message.oneofs().any(|oneof| !oneof.is_synthetic()) {
            assert_eq!(
                scan_message(message.name(), &[], 2),
                Err(ValidationError::MissingChoice),
                "{}",
                message.name()
            );
        }
    }
    Ok(())
}

#[test]
fn own_message_copy_uses_tag_order_for_both_arms() -> TestResult {
    for payload in [
        own_message_copy::Payload::Sent(OwnSentMessage {
            envelope_id: "e".into(),
            ..Default::default()
        }),
        own_message_copy::Payload::Item(HistoryItem::default()),
    ] {
        let mut copy =
            OwnMessageCopy { created_at: 7, payload: Some(payload), ..Default::default() };
        let bytes = copy.encode_to_vec();
        let expected = if matches!(copy.payload, Some(own_message_copy::Payload::Sent(_))) {
            vec![0x20, 7, 0x32, 3, 0x0a, 1, b'e']
        } else {
            vec![0x0a, 0, 0x20, 7]
        };
        assert_eq!(bytes, expected);
        assert_eq!(copy.encoded_len(), bytes.len());
        assert_eq!(scan_message("OwnMessageCopy", &bytes, 2), Ok(ScanOutcome::Supported));
        assert_eq!(OwnMessageCopy::decode(bytes.as_slice())?, copy);
        copy.clear();
        assert_eq!(copy, OwnMessageCopy::default());
    }
    Ok(())
}

#[test]
fn every_implicit_scalar_default_and_wrong_wire_type_is_rejected() -> TestResult {
    use prost_reflect::Kind;
    for message in descriptors()?.all_messages() {
        for field in
            message.fields().filter(|f| !f.supports_presence() && !f.is_list() && !f.is_map())
        {
            let expected = match field.kind() {
                Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => 1,
                Kind::String | Kind::Bytes => 2,
                Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => 5,
                Kind::Message(_) => continue,
                _ => 0,
            };
            let mut bytes = varint(u64::from(field.number()) * 8 + expected);
            match expected {
                1 => bytes.extend([0; 8]),
                5 => bytes.extend([0; 4]),
                _ => bytes.push(0),
            }
            assert_eq!(
                super::scanner::scan(&message, &bytes, 4, 0),
                Err(ValidationError::NonCanonical),
                "{}.{} default",
                message.name(),
                field.name()
            );
            let wrong =
                if expected == 0 { blob(field.number(), &[1]) } else { scalar(field.number(), 1) };
            assert_eq!(
                super::scanner::scan(&message, &wrong, 4, 0),
                Err(ValidationError::Malformed),
                "{}.{} wire",
                message.name(),
                field.name()
            );
        }
    }
    Ok(())
}
