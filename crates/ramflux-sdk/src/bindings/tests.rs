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
    cli::send_text("req-1", "acct-1", "c1", "hello", b"operation-id-0001")
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
        action: Some(g::message_request::Action::Send(g::SendMessage {
            conversation_id: "c1".into(),
            operation_id: vec![1; 16],
            content: Some(g::Content {
                value: Some(g::content::Value::Typing(g::Typing { active: true, expires_at: 0 })),
            }),
            ..Default::default()
        })),
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
        Err(SdkError::GeneratedApi(error)) => {
            assert!(error.message.contains("unknown adapter field MessageRequest.messageBody"));
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
            assert_eq!(mapped.name, "invalid_json");
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
    assert!(matches!(
        typing.action,
        Some(g::message_request::Action::Send(g::SendMessage {
            content: Some(g::Content { value: Some(g::content::Value::Typing(_)) }),
            ..
        }))
    ));
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
    assert_generated_error_vectors()?;
    assert_shared_vectors()?;
    assert_request_actions_round_trip()?;
    assert_updates_and_optional_presence()?;
    assert_hand_maintained_name_fails()?;
    Ok(())
}

#[test]
fn request_typing_uses_send_and_zero_deadline() -> TestResult {
    assert!(round_trip_all_surfaces(&sample_typing())?.action.is_some());
    let mut request = sample_typing();
    request.action =
        Some(g::message_request::Action::Typing(g::Typing { active: true, expires_at: 0 }));
    let error =
        encode_message_request(&request).err().ok_or("target-free typing must be refused")?;
    assert!(error.to_string().contains("use send.content.typing"));
    request = sample_typing();
    if let Some(g::message_request::Action::Send(send)) = request.action.as_mut() {
        send.content = Some(g::Content {
            value: Some(g::content::Value::Typing(g::Typing { active: true, expires_at: 5 })),
        });
    }
    assert!(encode_message_request(&request).is_err());
    Ok(())
}

#[test]
fn send_reply_to_is_copied_or_compared_and_refused_for_other_content() -> TestResult {
    let mut request = sample_send()?;
    if let Some(g::message_request::Action::Send(send)) = request.action.as_mut() {
        send.reply_to = Some(named_ref());
    }
    let normalized = round_trip_all_surfaces(&request)?;
    let Some(g::message_request::Action::Send(mut send)) = normalized.action else {
        return Err("send".into());
    };
    let Some(g::content::Value::Message(message)) =
        send.content.as_mut().and_then(|content| content.value.as_mut())
    else {
        return Err("message".into());
    };
    assert_eq!(message.reply_to, Some(named_ref()));
    message.reply_to.as_mut().ok_or("reply")?.id = vec![9; 32];
    assert!(encode_send_message(&send).is_err());
    send.content =
        Some(g::Content { value: Some(g::content::Value::Typing(g::Typing::default())) });
    assert!(encode_send_message(&send).is_err());
    Ok(())
}

#[test]
fn send_content_allowlist_and_operation_id_bounds_are_shared() -> TestResult {
    let Some(g::message_request::Action::Send(mut send)) = sample_send()?.action else {
        return Err("send".into());
    };
    for size in [0, 15, 65] {
        send.operation_id = vec![1; size];
        assert!(encode_send_message(&send).is_err());
    }
    for size in [16, 64] {
        send.operation_id = vec![1; size];
        assert!(encode_send_message(&send).is_ok());
    }
    for value in [
        g::content::Value::Service(g::Service::default()),
        g::content::Value::Receipt(g::Receipt::default()),
        g::content::Value::Control(g::Control::default()),
        g::content::Value::Edit(g::Edit::default()),
        g::content::Value::Delete(g::Delete::default()),
        g::content::Value::Reaction(g::Reaction::default()),
    ] {
        send.content = Some(g::Content { value: Some(value) });
        assert!(encode_send_message(&send).is_err());
    }
    Ok(())
}

fn assert_generated_error_vectors() -> TestResult {
    use GeneratedErrorCode as C;
    let codes = [
        C::InvalidArgument,
        C::InvalidJson,
        C::PeerUpgradeRequired,
        C::StorageCapacity,
        C::SchemaResetRequired,
        C::ResyncRequired,
        C::EditConflict,
        C::NotAuthorized,
        C::TargetNotFound,
        C::TargetDeleted,
        C::PayloadTooLarge,
        C::RateLimited,
        C::EphemeralUnavailable,
        C::CryptoFailure,
        C::NotConnected,
        C::Internal,
    ];
    let names = [
        "invalid_argument",
        "invalid_json",
        "peer_upgrade_required",
        "storage_capacity",
        "schema_reset_required",
        "resync_required",
        "edit_conflict",
        "not_authorized",
        "target_not_found",
        "target_deleted",
        "payload_too_large",
        "rate_limited",
        "ephemeral_unavailable",
        "crypto_failure",
        "not_connected",
        "internal",
    ];
    for (index, code) in codes.into_iter().enumerate() {
        let expected = test_error_vector(code);
        let error = SdkError::from(expected.clone());
        let values = [
            AdapterError::from_sdk(&error),
            cli::AdapterError::from_sdk(&error),
            uniffi::AdapterError::from_sdk(&error),
            wasm::AdapterError::from_sdk(&error),
        ];
        for mapped in values {
            assert_eq!(mapped.code, i32::try_from(index + 1)?);
            assert_eq!(mapped.name, names[index]);
            let details = match index + 1 {
                4 => json!({"scope":"source","source":"peer"}),
                6 => json!({"cursor":2,"floor":4,"head":8}),
                7 => json!({"target":"m","expected":2,"received":3}),
                _ => json!({}),
            };
            let encoded = serde_json::to_value(&mapped)?;
            assert_eq!(
                encoded,
                json!({"code":index+1,"name":names[index],"message":"vector","details":details})
            );
            assert_eq!(serde_json::from_value::<AdapterError>(encoded.clone())?, mapped);
            let remote = SdkError::LocalBusRefused {
                code: mapped.name.into(),
                message: mapped.message.clone(),
                body: Box::new(encoded),
            };
            assert_eq!(AdapterError::from_sdk(&remote), mapped);
        }
    }
    assert_error_details()
}

fn assert_error_details() -> TestResult {
    let edit = AdapterError::from_sdk(&SdkError::EditConflict {
        target: "m".into(),
        expected: 2,
        received: 3,
    });
    assert_eq!(
        serde_json::to_value(edit)?.get("details"),
        Some(&json!({"target":"m","expected":2,"received":3}))
    );
    let resync = AdapterError::resync(7, 9, 12);
    assert_eq!(
        serde_json::to_value(resync)?.get("details"),
        Some(&json!({"cursor":7,"floor":9,"head":12}))
    );
    let storage = AdapterError::from_sdk(&SdkError::StorageCapacity {
        source_anchor: "peer".into(),
        scope: ramflux_storage::RawInnerQuotaScope::Source,
    });
    assert_eq!(storage.code, 4);
    assert_eq!(serde_json::to_value(storage)?["details"]["source"], "peer");
    Ok(())
}

#[test]
fn generated_error_decode_refuses_code_name_and_detail_mismatches() -> TestResult {
    let valid = serde_json::to_value(AdapterError::resync(2, 4, 8))?;
    for patch in [
        json!({"code":17}),
        json!({"name":"ResyncRequired"}),
        json!({"details":{}}),
        json!({"details":{"cursor":2,"floor":4,"head":8,"body":"payload"}}),
        json!({"details":{"scope":"source","source":"peer"}}),
        json!({"extra":"payload"}),
    ] {
        let mut forged = valid.clone();
        for (key, value) in patch.as_object().ok_or("object patch")? {
            forged[key] = value.clone();
        }
        assert!(serde_json::from_value::<AdapterError>(forged).is_err());
    }
    Ok(())
}

#[test]
fn public_bindings_strip_private_revision_nonce_and_refuse_selected_input()
-> Result<(), Box<dyn std::error::Error>> {
    let message = g::Message {
        text: "public body".into(),
        erasure_nonce: vec![203; 32],
        ..Default::default()
    };
    let mut send = g::SendMessage {
        conversation_id: "conversation".into(),
        operation_id: vec![1; 16],
        content: Some(g::Content { value: Some(g::content::Value::Message(message.clone())) }),
        ..Default::default()
    };
    assert!(encode_send_message(&send).is_err());
    let update = g::MessageUpdate {
        account_id: "account".into(),
        journal_sequence: 1,
        identity: None,
        state: Some(g::message_update::State::Content(send.content.clone().ok_or("content")?)),
    };
    let mut cached = update.clone();
    cached.identity = Some(g::EventIdentity {
        id: vec![2; 32],
        conversation_id: "conversation".into(),
        ..Default::default()
    });
    let mut cache = crate::client::typed_messages::MessageCache::default();
    cache.apply(cached);
    let cached =
        serde_json::to_string(cache.get("conversation", &[2; 32]).ok_or("cached public update")?)?;
    assert!(!cached.contains("erasureNonce") && !cached.contains("erasure_nonce"));
    let encoded = encode_message_update(&update)?;
    let wire = serde_json::to_string(&encoded)?;
    assert!(!wire.contains("erasureNonce") && !wire.contains("erasure_nonce"));
    assert!(!wire.contains(&ramflux_protocol::encode_base64url([203; 32])));
    let public = decode_message_update(&encoded)?;
    let Some(g::message_update::State::Content(g::Content {
        value: Some(g::content::Value::Message(public)),
    })) = public.state
    else {
        return Err("public content".into());
    };
    assert_eq!(public.erasure_nonce, [] as [u8; 0]);
    assert_eq!(public.text, message.text);
    if let Some(g::Content { value: Some(g::content::Value::Message(message)) }) =
        send.content.as_mut()
    {
        message.erasure_nonce.clear();
    }
    assert!(encode_send_message(&send).is_ok());
    Ok(())
}

#[test]
fn gateway_writer_busy_preserves_typed_backpressure_across_adapters() {
    let error = SdkError::GatewayWriterBusy;
    for mapped in [
        AdapterError::from_sdk(&error),
        cli::AdapterError::from_sdk(&error),
        uniffi::AdapterError::from_sdk(&error),
        wasm::AdapterError::from_sdk(&error),
    ] {
        assert_eq!(mapped.code, GeneratedErrorCode::RateLimited as i32);
        assert_eq!(mapped.name, "rate_limited");
        assert_eq!(mapped.message, "gateway_writer_busy: retryable");
    }
    assert!(error.gateway_writer_busy());
    assert!(crate::error_policy::approval_retryable(&error));
}

#[test]
fn signature_failures_preserve_crypto_classification_across_adapters() {
    for error in [
        SdkError::SignatureVerificationFailed("test signature".into()),
        SdkError::Protocol(ramflux_protocol::ProtocolError::SignatureVerificationFailed),
    ] {
        for mapped in [
            AdapterError::from_sdk(&error),
            cli::AdapterError::from_sdk(&error),
            uniffi::AdapterError::from_sdk(&error),
            wasm::AdapterError::from_sdk(&error),
        ] {
            assert_eq!(mapped.code, GeneratedErrorCode::CryptoFailure as i32);
            assert_eq!(mapped.name, "crypto_failure");
        }
    }
}
