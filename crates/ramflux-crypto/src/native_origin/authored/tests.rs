// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-account data bindings are distinct from original peer signature evidence.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn capture() -> Result<OwnAuthoredCapture, Box<dyn std::error::Error>> {
    let author = g::QualifiedDevice {
        account_anchor: ramflux_protocol::encode_base64url([31; 32]),
        device_id: "original-device".into(),
        device_epoch: 1,
    };
    let identity = g::EventIdentity {
        id: g::identity::derive(&author, "thread", 1)?.to_vec(),
        author: Some(author),
        conversation_id: "thread".into(),
        device_sequence: 1,
        hlc: 1000,
        ..Default::default()
    };
    let inner = g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 1,
        identity: Some(identity.clone()),
        body: g::Message {
            text: "original own content".into(),
            erasure_nonce: vec![8; 32],
            ..Default::default()
        }
        .encode_to_vec(),
    };
    Ok(OwnAuthoredCapture {
        target: identity.id.clone(),
        current: identity.id.clone(),
        original: identity.clone(),
        sent: g::OwnSentMessage {
            message_id: ramflux_protocol::encode_base64url(&identity.id),
            exact_inner: inner.encode_to_vec(),
            context: Some(g::OwnContext { conversation_id: "thread".into(), ..Default::default() }),
            ..Default::default()
        },
    })
}
#[test]
fn own_capture_direct_data_preserves_original_order_and_refuses_foreign_root() -> TestResult {
    let capture = capture()?;
    let own = ramflux_protocol::encode_base64url([31; 32]);
    assert_eq!(capture.check_direct(&own)?, capture.original);
    assert_eq!(
        g::identity::order_key(&capture.check_direct(&own)?)?,
        g::identity::order_key(&capture.original)?
    );
    assert!(capture.check_direct(&ramflux_protocol::encode_base64url([32; 32])).is_err());
    Ok(())
}
#[test]
fn own_capture_direct_data_refuses_mixed_revision_and_original_coordinates() -> TestResult {
    let own = ramflux_protocol::encode_base64url([31; 32]);
    for change in ["target", "current", "original-clock", "context", "digest"] {
        let mut value = capture()?;
        match change {
            "target" => value.target = vec![1; 32],
            "current" => value.current = vec![2; 32],
            "original-clock" => value.original.hlc += 1,
            "context" => {
                value.sent.context.as_mut().ok_or("context")?.conversation_id =
                    "other-thread".into();
            }
            "digest" => value.sent.ciphertext_digest = Some(vec![3; 32]),
            _ => return Err("unknown fixture change".into()),
        }
        assert!(value.check_direct(&own).is_err(), "accepted {change}");
    }
    Ok(())
}

#[test]
fn own_capture_edit_keeps_original_order_and_binds_the_replacement_target() -> TestResult {
    let own = ramflux_protocol::encode_base64url([31; 32]);
    let mut value = capture()?;
    let mut revision = value.original.clone();
    revision.device_sequence = 2;
    revision.hlc += 1;
    revision.id = g::identity::derive(
        revision.author.as_ref().ok_or("revision author")?,
        &revision.conversation_id,
        revision.device_sequence,
    )?
    .to_vec();
    let mut edit = g::Edit {
        target: Some(g::MessageRef {
            id: value.target.clone(),
            conversation_id: "thread".into(),
            author_anchor: own.clone(),
        }),
        revision: 1,
        previous_content_digest: vec![7; 32],
        replacement: Some(g::Message {
            text: "replacement".into(),
            erasure_nonce: vec![9; 32],
            ..Default::default()
        }),
    };
    let mut inner = g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 3,
        identity: Some(revision.clone()),
        body: edit.encode_to_vec(),
    };
    value.current = revision.id.clone();
    value.sent.message_id = ramflux_protocol::encode_base64url(&revision.id);
    value.sent.exact_inner = inner.encode_to_vec();
    assert_eq!(value.check_direct(&own)?, revision, "current edit identity lost");
    assert_eq!(value.original.device_sequence, 1, "original order was replaced");
    edit.target.as_mut().ok_or("target")?.author_anchor =
        ramflux_protocol::encode_base64url([32; 32]);
    inner.body = edit.encode_to_vec();
    value.sent.exact_inner = inner.encode_to_vec();
    assert!(value.check_direct(&own).is_err(), "foreign edit target accepted");
    Ok(())
}
