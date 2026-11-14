// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::message::{self as g, content, surface, surface_carrier};
use serde_json::Value;
use std::io::Read as _;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn stream() -> GeneratedEventStream {
    GeneratedEventStream::new(
        "conversation",
        g::QualifiedDevice {
            account_anchor: "anchor".into(),
            device_id: "device".into(),
            device_epoch: 1,
        },
    )
}
fn object(value: &Value) -> TestResult<g::JsonObject> {
    Ok(g::JsonObject {
        members: value
            .as_object()
            .ok_or("JSON object")?
            .iter()
            .map(|(key, value)| Ok(g::JsonMember { key: key.clone(), value: Some(json(value)?) }))
            .collect::<TestResult<_>>()?,
    })
}
fn json(value: &Value) -> TestResult<g::JsonValue> {
    use g::json_value::Value as V;
    Ok(g::JsonValue {
        value: Some(match value {
            Value::Null => V::Null(g::JsonNull {}),
            Value::Bool(v) => V::Boolean(*v),
            Value::Number(v) => V::Number(v.to_string()),
            Value::String(v) => V::Text(v.clone()),
            Value::Array(v) => {
                V::Array(g::JsonArray { values: v.iter().map(json).collect::<TestResult<_>>()? })
            }
            Value::Object(_) => V::Object(object(value)?),
        }),
    })
}
fn fixture(name: &str) -> TestResult<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ramflux-protocol/fixtures/protocol/v1/a2ui_surface")
        .join(name);
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    assert!(bytes.len() <= 16 * 1024, "surface fixture must remain bounded");
    Ok(serde_json::from_slice(&bytes)?)
}
fn create() -> TestResult<g::SurfaceEvent> {
    let value = fixture("create.event.json")?;
    Ok(g::SurfaceEvent {
        schema: ramflux_protocol::EVENT_SCHEMA.into(),
        conversation_id: "conversation".into(),
        surface_version: 1,
        new_surface_hash: value
            .get("newSurfaceHash")
            .and_then(Value::as_str)
            .ok_or("fixture hash")?
            .into(),
        fallback_text: Some("Save note".into()),
        operation: Some(g::surface_event::Operation::A2ui(object(
            value.get("a2ui").ok_or("fixture message")?,
        )?)),
        ..Default::default()
    })
}
fn action() -> TestResult<g::SurfaceAction> {
    let value = fixture("submit.action.json")?;
    Ok(g::SurfaceAction {
        schema: ramflux_protocol::ACTION_SCHEMA.into(),
        conversation_id: "conversation".into(),
        surface_version: 1,
        surface_hash: value
            .get("surfaceHash")
            .and_then(Value::as_str)
            .ok_or("surface hash")?
            .into(),
        source_instance: Vec::new(),
        args_hash: value.get("argsHash").and_then(Value::as_str).ok_or("args hash")?.into(),
        a2ui: Some(object(value.get("a2ui").ok_or("action message")?)?),
        ..Default::default()
    })
}
fn carrier(payload: surface_carrier::Payload) -> g::SurfaceCarrier {
    g::SurfaceCarrier {
        conversation_id: "conversation".into(),
        surface_id: "surface".into(),
        sender_principal_id: "alice".into(),
        author_principal_id: "alice".into(),
        signature: "signature".into(),
        payload: Some(payload),
        ..Default::default()
    }
}
fn delivery(payload: surface_carrier::Payload) -> g::Surface {
    g::Surface {
        payload: Some(surface::Payload::Delivery(g::SurfaceDelivery {
            kind: Some(g::SurfaceControlKind {
                value: Some(g::surface_control_kind::Value::Peer(g::SurfaceControlKindPeer {})),
            }),
            carrier: Some(carrier(payload)),
            ..Default::default()
        })),
    }
}
fn round_trip(surface: g::Surface, id: &[u8]) -> TestResult {
    RamfluxClient::validate_generated_surface(&surface)?;
    let bytes = RamfluxClient::encode_generated_surface(&mut stream(), id.to_vec(), surface)?;
    let (_, decoded) = RamfluxClient::decode_generated_inner(&bytes)?;
    assert!(
        matches!(decoded.value, Some(content::Value::Surface(_))),
        "generated Inner must preserve the surface payload"
    );
    Ok(())
}
#[test]
fn v3_mutations_append_and_resync_round_trip_without_legacy_shapes() -> TestResult {
    let create = create()?;
    round_trip(delivery(surface_carrier::Payload::Event(create.clone())), b"create")?;
    for (id, operation) in [
        (
            b"components".as_slice(),
            g::surface_event::Operation::A2ui(object(
                &serde_json::json!({"version":"1.0","updateComponents":{"surfaceId":"surface","components":[]}}),
            )?),
        ),
        (
            b"model".as_slice(),
            g::surface_event::Operation::A2ui(object(
                &serde_json::json!({"version":"1.0","updateDataModel":{"surfaceId":"surface","path":"/text","value":"changed"}}),
            )?),
        ),
        (
            b"delete".as_slice(),
            g::surface_event::Operation::A2ui(object(
                &serde_json::json!({"version":"1.0","deleteSurface":{"surfaceId":"surface"}}),
            )?),
        ),
        (
            b"append".as_slice(),
            g::surface_event::Operation::AppendText(g::SurfaceAppendText {
                surface_id: "surface".into(),
                path: "/text".into(),
                delta: "!".into(),
                r#final: true,
            }),
        ),
    ] {
        let event = g::SurfaceEvent {
            surface_version: 2,
            base_surface_hash: Some(create.new_surface_hash.clone()),
            new_surface_hash: "unapplied-delta-commitment".into(),
            operation: Some(operation),
            fallback_text: None,
            ..create.clone()
        };
        round_trip(delivery(surface_carrier::Payload::Event(event)), id)?;
    }
    let native = ramflux_protocol::SurfaceEvent::from_wire_bytes(
        &ramflux_protocol::canonical_json_bytes(&fixture("create.event.json")?)?,
    )?;
    let state = ramflux_protocol::SurfaceState::validate_proof(&native)?;
    let frame = state.resync_frame()?;
    let event = g::SurfaceEvent {
        schema: frame.schema,
        conversation_id: frame.conversation_id,
        surface_version: frame.surface_version,
        base_surface_hash: frame.base_surface_hash,
        new_surface_hash: frame.new_surface_hash,
        fallback_text: frame.fallback_text,
        close_reason: frame.close_reason,
        closed: frame.closed,
        metadata: frame
            .metadata
            .as_ref()
            .map(|value| object(&serde_json::to_value(value)?))
            .transpose()?,
        r#final: frame
            .final_
            .unwrap_or_default()
            .into_iter()
            .map(|entry| g::SurfaceFinalEntry {
                pointer: entry.pointer,
                text_hash: entry.text_hash,
            })
            .collect(),
        operation: Some(g::surface_event::Operation::Resync(g::SurfaceResync {
            a2ui: Some(object(&serde_json::to_value(frame.resync.ok_or("resync")?.a2ui)?)?),
        })),
    };
    round_trip(delivery(surface_carrier::Payload::Event(event)), b"resync")?;
    Ok(())
}
#[test]
fn actions_receipts_resync_requests_and_history_preserve_original_signer() -> TestResult {
    let action = action()?;
    let signed = carrier(surface_carrier::Payload::Action(action.clone()));
    RamfluxClient::authorize_generated_surface_action_signer("alice", &signed)?;
    round_trip(delivery(surface_carrier::Payload::Action(action)), b"action")?;
    round_trip(
        delivery(surface_carrier::Payload::ActionReceipt(Box::new(signed.clone()))),
        b"receipt",
    )?;
    round_trip(
        g::Surface {
            payload: Some(surface::Payload::ResyncRequest(g::SurfaceResyncRequest {
                kind: "full".into(),
                conversation_id: "conversation".into(),
                surface_ref: "reference".into(),
                author: "alice".into(),
                surface_id: "surface".into(),
                ..Default::default()
            })),
        },
        b"request",
    )?;
    round_trip(
        g::Surface {
            payload: Some(surface::Payload::OwnHistory(g::SurfaceHistoryExport {
                controls: vec![g::SurfaceDelivery {
                    kind: Some(g::SurfaceControlKind {
                        value: Some(g::surface_control_kind::Value::Peer(
                            g::SurfaceControlKindPeer {},
                        )),
                    }),
                    carrier: Some(signed.clone()),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        },
        b"history",
    )?;
    let mut forged = signed;
    forged.signature.clear();
    assert!(
        RamfluxClient::authorize_generated_surface_action_signer("alice", &forged).is_err(),
        "receipt signer cannot be fabricated"
    );
    assert!(
        RamfluxClient::validate_generated_surface(&delivery(
            surface_carrier::Payload::ActionReceipt(Box::new(forged))
        ))
        .is_err(),
        "a receipt must validate its wrapped original signature"
    );
    Ok(())
}
#[test]
fn duplicate_json_members_and_legacy_generated_wire_are_refused() -> TestResult {
    let mut event = create()?;
    let Some(g::surface_event::Operation::A2ui(message)) = &mut event.operation else {
        return Err("create operation".into());
    };
    let first = message.members.first().ok_or("fixture member")?.clone();
    message.members.push(first);
    assert!(
        RamfluxClient::validate_generated_surface(&delivery(surface_carrier::Payload::Event(
            event
        )))
        .is_err(),
        "duplicate keys cannot cross the generated/native conversion"
    );
    assert!(
        serde_json::from_value::<g::SurfaceEvent>(
            serde_json::json!({"schema":"surface.v1","command":{}})
        )
        .is_err(),
        "deleted command shapes must have no generated decoder"
    );
    Ok(())
}
