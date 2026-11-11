// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::message as g;
use ramflux_protocol::message::{DeleteScope, Message, MessageRef, content};
use serde_json::json;
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn named_ref() -> MessageRef {
    MessageRef { id: b"msg-1".to_vec(), conversation_id: "c1".into(), author_anchor: "a".into() }
}

fn field_set(
    surface: AdapterSurface,
    message: &str,
) -> Result<BTreeSet<(u32, String, bool)>, SdkError> {
    Ok(adapter_binding_vector(surface, message)?
        .fields
        .into_iter()
        .map(|field| (field.tag, field.json_name, field.optional))
        .collect())
}

fn all_surfaces() -> [AdapterSurface; 4] {
    [AdapterSurface::Cli, AdapterSurface::CAbi, AdapterSurface::Uniffi, AdapterSurface::Wasm]
}

fn round_trip_all_surfaces(request: &g::MessageRequest) -> Result<g::MessageRequest, SdkError> {
    let json = encode_message_request(request)?;
    let via_cli = decode_message_request(&json)?;
    let via_c_abi = crate::bindings::decode_message_request(&json)?;
    let via_uniffi = uniffi::decode_message_request(&json)?;
    let via_wasm = wasm::decode_message_request(&json)?;
    assert_eq!(via_cli, via_c_abi);
    assert_eq!(via_cli, via_uniffi);
    assert_eq!(via_cli, via_wasm);
    Ok(via_cli)
}

fn sample_send() -> Result<g::MessageRequest, SdkError> {
    cli::send_text("req-1", "acct-1", "c1", "hello", b"op-1")
}

fn sample_edit() -> g::MessageRequest {
    g::MessageRequest {
        request_id: "req-edit".into(),
        account_id: "acct-1".into(),
        action: Some(g::message_request::Action::Edit(g::Edit {
            target: Some(named_ref()),
            revision: 2,
            previous_content_digest: vec![7; 32],
            replacement: Some(Message { text: "edited".into(), ..Default::default() }),
        })),
    }
}

fn sample_delete() -> Result<g::MessageRequest, SdkError> {
    cli::delete_message("req-del", "acct-1", "c1", b"msg-1", false, Some(b"tomb"))
}

fn sample_reaction() -> g::MessageRequest {
    g::MessageRequest {
        request_id: "req-react".into(),
        account_id: "acct-1".into(),
        action: Some(g::message_request::Action::Reaction(g::Reaction {
            target: Some(named_ref()),
            token: "👍".into(),
            remove: false,
            operation_id: b"op-r".to_vec(),
        })),
    }
}

fn sample_typing() -> g::MessageRequest {
    g::MessageRequest {
        request_id: "req-type".into(),
        account_id: "acct-1".into(),
        action: Some(g::message_request::Action::Typing(g::Typing { active: true, expires_at: 5 })),
    }
}

fn assert_shared_vectors() -> TestResult {
    for message in PRODUCT_MESSAGES {
        let core = field_set(AdapterSurface::Cli, message)?;
        assert!(!core.is_empty(), "{message} descriptor fields");
        for surface in all_surfaces() {
            assert_eq!(field_set(surface, message)?, core, "{surface:?} {message}");
        }
        assert_eq!(uniffi::exported_fields(message)?, wasm::exported_fields(message)?);
        for field in binding_vector(message)?.fields {
            let bound = bind_adapter_field(message, &field.json_name)?;
            assert_eq!(bound.tag, field.tag);
            assert_eq!(bound.optional, field.optional);
        }
    }
    Ok(())
}

fn assert_hand_maintained_name_fails() -> TestResult {
    let core: BTreeSet<String> =
        binding_vector("MessageRequest")?.fields.into_iter().map(|field| field.json_name).collect();
    let handwritten = BTreeSet::from([
        "requestId".into(),
        "accountId".into(),
        "send".into(),
        "edit".into(),
        "delete".into(),
        "reaction".into(),
        "typing".into(),
        "messageBody".into(),
    ]);
    assert_ne!(handwritten, core, "hand-maintained adapter field name");
    match bind_adapter_field("MessageRequest", "messageBody") {
        Err(SdkError::LocalBus(message)) => {
            assert!(message.contains("unknown adapter field MessageRequest.messageBody"));
        }
        other => return Err(format!("expected unknown field, got {other:?}").into()),
    }
    let forged = json!({
        "requestId": "req-1",
        "accountId": "acct-1",
        "send": {"conversationId": "c1", "content": {"message": {"text": "hello"}}},
        "messageBody": "hand-maintained",
    });
    match decode_message_request(&forged) {
        Err(error) => {
            let mapped = AdapterError::from_sdk(&error);
            assert_eq!(mapped.code, AdapterError::INVALID_JSON);
            assert_eq!(mapped.name, "InvalidCanonicalJson");
        }
        Ok(_) => return Err("hand-maintained field must fail decode".into()),
    }
    Ok(())
}

fn assert_request_actions_round_trip() -> TestResult {
    let send = round_trip_all_surfaces(&sample_send()?)?;
    let (conversation, text) = cli::send_payload(&send)?;
    assert_eq!(conversation, "c1");
    assert_eq!(text, "hello");
    assert!(matches!(
        send.action,
        Some(g::message_request::Action::Send(ref payload)) if payload.reply_to.is_none()
    ));

    let edit = round_trip_all_surfaces(&sample_edit())?;
    assert!(matches!(edit.action, Some(g::message_request::Action::Edit(_))));

    let delete = round_trip_all_surfaces(&sample_delete()?)?;
    let (conversation, message_id) = cli::delete_payload(&delete)?;
    assert_eq!(conversation, "c1");
    assert_eq!(message_id, b"msg-1");
    assert!(matches!(
        delete.action,
        Some(g::message_request::Action::Delete(ref payload))
            if payload.scope == DeleteScope::Local as i32
    ));

    let reaction = round_trip_all_surfaces(&sample_reaction())?;
    assert!(matches!(reaction.action, Some(g::message_request::Action::Reaction(_))));

    let typing = round_trip_all_surfaces(&sample_typing())?;
    assert!(matches!(typing.action, Some(g::message_request::Action::Typing(_))));
    Ok(())
}

fn assert_updates_and_optional_presence() -> TestResult {
    let content = g::MessageUpdate {
        account_id: "acct-1".into(),
        journal_sequence: 9,
        identity: None,
        state: Some(g::message_update::State::Content(g::Content {
            value: Some(content::Value::Message(Message {
                text: "hi".into(),
                ..Default::default()
            })),
        })),
    };
    let decoded = round_trip_update(&content)?;
    assert!(decoded.identity.is_none());
    assert!(matches!(decoded.state, Some(g::message_update::State::Content(_))));

    let unsupported = cli::identity_update("acct-1", 3, b"evt-1")?;
    assert_eq!(cli::identity_event_id(&unsupported)?, b"evt-1");
    assert!(matches!(unsupported.state, Some(g::message_update::State::Unsupported(_))));

    let tombstone = g::MessageUpdate {
        account_id: "acct-1".into(),
        journal_sequence: 4,
        identity: None,
        state: Some(g::message_update::State::Tombstone(g::Delete {
            targets: vec![named_ref()],
            scope: DeleteScope::Everyone as i32,
            tombstone_id: b"t".to_vec(),
            native_group_authorization: Vec::new(),
        })),
    };
    let decoded = uniffi::round_trip_update(&tombstone)?;
    assert_eq!(wasm::round_trip_update(&tombstone)?, decoded);
    assert!(matches!(decoded.state, Some(g::message_update::State::Tombstone(_))));
    Ok(())
}

#[test]
fn generated_requests_updates_share_core_across_product_adapters() -> TestResult {
    assert_shared_vectors()?;
    assert_request_actions_round_trip()?;
    assert_updates_and_optional_presence()?;
    assert_hand_maintained_name_fails()?;
    Ok(())
}
