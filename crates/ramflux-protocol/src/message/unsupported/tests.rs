// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::message as g;

fn diagnose(layer: u32, kind: u32, body: Vec<u8>) -> Result<&'static str, ValidationError> {
    let bytes = g::Inner {
        layer,
        kind,
        identity: Some(g::EventIdentity {
            id: vec![1; 32],
            conversation_id: "c".into(),
            ..Default::default()
        }),
        body,
    }
    .encode_to_vec();
    Ok(reason(&validation::scan_inner(&bytes)?))
}
#[test]
fn unsupported_reasons_use_adopted_priority_without_exposing_bytes() -> Result<(), ValidationError>
{
    assert_eq!(diagnose(registry::COMPILED_LAYER + 1, 900, vec![0xff])?, "layer_above_supported");
    assert_eq!(diagnose(registry::COMPILED_LAYER, 900, vec![0xff])?, "unknown_kind");
    let mut body =
        g::Message { text: "hello".into(), erasure_nonce: vec![42; 32], ..Default::default() }
            .encode_to_vec();
    body.extend_from_slice(&[0xa0, 0x06, 1]); // unknown tag 100, canonical order
    assert_eq!(diagnose(registry::COMPILED_LAYER, 1, body)?, "unknown_field");
    let body = g::Receipt { state: 999, ..Default::default() }.encode_to_vec();
    assert_eq!(diagnose(registry::COMPILED_LAYER, 6, body.clone())?, "unknown_enum");
    let mut combined = body;
    combined.extend_from_slice(&[0xa0, 0x06, 1]);
    assert_eq!(diagnose(registry::COMPILED_LAYER, 6, combined)?, "unknown_field");
    let body = g::Message {
        text: "hello".into(),
        erasure_nonce: vec![42; 32],
        entities: vec![g::Entity { offset: 0, length: 1, kind: 999, value: None }],
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(diagnose(registry::COMPILED_LAYER, 1, body)?, "unknown_entity");
    Ok(())
}
#[test]
fn body_and_missing_identity_have_distinct_non_authoritative_reasons() -> Result<(), ValidationError>
{
    let bytes = g::Inner {
        layer: registry::COMPILED_LAYER,
        kind: 1,
        identity: None,
        body: g::Message {
            text: "hello".into(),
            erasure_nonce: vec![42; 32],
            ..Default::default()
        }
        .encode_to_vec(),
    }
    .encode_to_vec();
    assert_eq!(reason(&validation::scan_inner(&bytes)?), "identity_undecodable");
    // A formerly opaque body's new decoder may fail. Reason classification does not
    // admit it or relax scan_inner's malformed-wire refusal.
    let body = [0xff];
    let scanned = ScannedInner {
        exact_inner: &bytes,
        layer: registry::COMPILED_LAYER,
        kind: 1,
        body: &body,
        outcome: validation::ScanOutcome::Unsupported,
    };
    assert_eq!(reason(&scanned), "body_undecodable");
    Ok(())
}
