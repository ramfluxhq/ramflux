// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated Surface Inner conversion (S10a P16).
//! This module neither sends a carrier nor admits a stored event.
use super::generated_content::GeneratedEventStream;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

/// Encode a generated Surface Inner. Additive candidate API; does not send or persist.
/// # Errors
/// Rejects a missing payload, a failed native check, or invalid Inner.
pub fn validate_generated_surface(surface: &g::Surface) -> Result<(), SdkError> {
    match surface.payload.as_ref() {
        Some(g::surface::Payload::Delivery(delivery)) => validate_delivery(delivery),
        Some(g::surface::Payload::ResyncRequest(request)) => validate_resync(request),
        Some(g::surface::Payload::OwnHistory(export)) => {
            if export.controls.is_empty() && export.checkpoints.is_empty() {
                Err(refused("surface own-history requires controls or checkpoints"))
            } else {
                Ok(())
            }
        }
        None => Err(refused("surface requires delivery, resync or own-history")),
    }
}

/// Original action signer must remain bound on the action carrier and its receipt.
/// # Errors
/// Refuses a missing signature or a sender that is not the original signer.
pub fn authorize_surface_action_signer(
    original_signer: &str,
    carrier: &g::SurfaceCarrier,
) -> Result<(), SdkError> {
    if original_signer.is_empty()
        || carrier.signature.is_empty()
        || carrier.sender_principal_id != original_signer
    {
        return Err(refused("surface action requires the original signer binding"));
    }
    match carrier.payload.as_ref() {
        Some(g::surface_carrier::Payload::Action(_)) => Ok(()),
        Some(g::surface_carrier::Payload::ActionReceipt(inner)) => {
            if !matches!(inner.payload, Some(g::surface_carrier::Payload::Action(_))) {
                return Err(refused("surface action receipt must wrap the original action"));
            }
            authorize_surface_action_signer(original_signer, inner)
        }
        _ => Err(refused("surface action signer applies to action or action receipt")),
    }
}

fn validate_delivery(delivery: &g::SurfaceDelivery) -> Result<(), SdkError> {
    match delivery.kind.as_ref().and_then(|kind| kind.value.as_ref()) {
        Some(g::surface_control_kind::Value::Peer(_) | g::surface_control_kind::Value::Own(_)) => {}
        None => return Err(refused("surface delivery requires peer or own kind")),
    }
    let Some(carrier) = delivery.carrier.as_ref() else {
        return Err(refused("surface delivery requires a carrier"));
    };
    validate_carrier(carrier)
}

fn validate_carrier(carrier: &g::SurfaceCarrier) -> Result<(), SdkError> {
    if carrier.conversation_id.is_empty()
        || carrier.surface_id.is_empty()
        || carrier.sender_principal_id.is_empty()
        || carrier.author_principal_id.is_empty()
        || carrier.signature.is_empty()
    {
        return Err(refused("surface carrier requires ids, sender, author and signature"));
    }
    match carrier.payload.as_ref() {
        Some(g::surface_carrier::Payload::Event(event)) => validate_event(event),
        Some(g::surface_carrier::Payload::Action(action)) => validate_action(action),
        Some(g::surface_carrier::Payload::ActionReceipt(inner)) => {
            if matches!(inner.payload, Some(g::surface_carrier::Payload::ActionReceipt(_))) {
                return Err(refused("surface action receipt is one level only"));
            }
            validate_carrier(inner)?;
            authorize_surface_action_signer(&carrier.sender_principal_id, inner)
        }
        Some(g::surface_carrier::Payload::FunctionCall(frame)) => {
            validate_rpc(frame, ramflux_protocol::RpcKind::FunctionCall)
        }
        Some(g::surface_carrier::Payload::FunctionResponse(frame)) => {
            validate_rpc(frame, ramflux_protocol::RpcKind::FunctionResponse)
        }
        Some(g::surface_carrier::Payload::Error(frame)) => {
            validate_rpc(frame, ramflux_protocol::RpcKind::Error)
        }
        None => Err(refused("surface carrier requires event, action or action receipt")),
    }
}

fn validate_event(event: &g::SurfaceEvent) -> Result<(), SdkError> {
    let mut value = serde_json::json!({"schema":event.schema,"conversationId":event.conversation_id,"surfaceVersion":event.surface_version,"newSurfaceHash":event.new_surface_hash});
    let object = value.as_object_mut().ok_or_else(|| refused("event object missing"))?;
    for (key, field) in [
        ("baseSurfaceHash", &event.base_surface_hash),
        ("fallbackText", &event.fallback_text),
        ("closeReason", &event.close_reason),
    ] {
        if let Some(field) = field {
            object.insert(key.into(), serde_json::json!(field));
        }
    }
    if let Some(metadata) = &event.metadata {
        object.insert("metadata".into(), json_object(metadata, 0)?);
    }
    if let Some(closed) = event.closed {
        object.insert("closed".into(), serde_json::json!(closed));
    }
    match event.operation.as_ref() {
        Some(g::surface_event::Operation::A2ui(message)) => {
            object.insert("a2ui".into(), json_object(message, 0)?);
        }
        Some(g::surface_event::Operation::AppendText(append)) => {
            object.insert("appendText".into(),serde_json::json!({"surfaceId":append.surface_id,"path":append.path,"delta":append.delta,"final":append.r#final}));
        }
        Some(g::surface_event::Operation::Resync(resync)) => {
            let message =
                resync.a2ui.as_ref().ok_or_else(|| refused("resync A2UI message missing"))?;
            object.insert("resync".into(), serde_json::json!({"a2ui":json_object(message,0)?}));
            object.insert("final".into(),serde_json::json!(event.r#final.iter().map(|entry| serde_json::json!({"pointer":entry.pointer,"textHash":entry.text_hash})).collect::<Vec<_>>()));
        }
        None => return Err(refused("surface event requires exactly one operation")),
    }
    let bytes = ramflux_protocol::canonical_json_bytes(&value)?;
    let native = ramflux_protocol::SurfaceEvent::from_wire_bytes(&bytes)?;
    if native.is_create() || native.is_resync() {
        ramflux_protocol::SurfaceState::validate_proof(&native)?;
    }
    Ok(())
}
fn validate_action(action: &g::SurfaceAction) -> Result<(), SdkError> {
    let mut value = serde_json::json!({"schema":action.schema,"conversationId":action.conversation_id,"surfaceVersion":action.surface_version,"surfaceHash":action.surface_hash,"sourceInstance":action.source_instance,"argsHash":action.args_hash,"a2ui":json_object(action.a2ui.as_ref().ok_or_else(|| refused("action A2UI message missing"))?,0)?});
    if let Some(binding) = &action.task_binding {
        let object = value.as_object_mut().ok_or_else(|| refused("action object missing"))?;
        object.insert(
            "taskBinding".into(),
            serde_json::json!({"task_id":binding.task_id,"step_id":binding.step_id}),
        );
    }
    ramflux_protocol::SurfaceAction::from_wire_bytes(&ramflux_protocol::canonical_json_bytes(
        &value,
    )?)?;
    Ok(())
}
fn json_object(object: &g::JsonObject, depth: usize) -> Result<serde_json::Value, SdkError> {
    if depth > 16 || object.members.len() > ramflux_protocol::MAX_STATE_BYTES {
        return Err(refused("surface JSON limit"));
    }
    let mut map = serde_json::Map::new();
    for member in &object.members {
        if member.key.len() > ramflux_protocol::MAX_STATE_BYTES || map.contains_key(&member.key) {
            return Err(refused("duplicate or oversized surface JSON key"));
        }
        map.insert(
            member.key.clone(),
            json_value(
                member.value.as_ref().ok_or_else(|| refused("JSON member value missing"))?,
                depth + 1,
            )?,
        );
    }
    Ok(serde_json::Value::Object(map))
}
fn json_value(value: &g::JsonValue, depth: usize) -> Result<serde_json::Value, SdkError> {
    use g::json_value::Value as V;
    if depth > 16 {
        return Err(refused("surface JSON depth"));
    }
    Ok(match value.value.as_ref().ok_or_else(|| refused("surface JSON kind missing"))? {
        V::Null(_) => serde_json::Value::Null,
        V::Boolean(v) => serde_json::Value::Bool(*v),
        V::Number(v) => {
            serde_json::Value::Number(v.parse().map_err(|_| refused("surface JSON number"))?)
        }
        V::Text(v) => {
            if v.len() > ramflux_protocol::MAX_STATE_BYTES {
                return Err(refused("surface JSON text limit"));
            }
            serde_json::Value::String(v.clone())
        }
        V::Array(v) => {
            if v.values.len() > ramflux_protocol::MAX_STATE_BYTES {
                return Err(refused("surface JSON array limit"));
            }
            serde_json::Value::Array(
                v.values.iter().map(|v| json_value(v, depth + 1)).collect::<Result<_, _>>()?,
            )
        }
        V::Object(v) => json_object(v, depth + 1)?,
    })
}

fn validate_rpc(
    frame: &g::SurfaceRpcFrame,
    kind: ramflux_protocol::RpcKind,
) -> Result<(), SdkError> {
    let native = ramflux_protocol::RpcFrame {
        schema: frame.schema.clone(),
        conversation_id: frame.conversation_id.clone(),
        surface_id: frame.surface_id.clone(),
        known_version: frame.known_version,
        known_hash: frame.known_hash.clone(),
        function_call_id: frame.function_call_id.clone(),
        rejected_version: frame.rejected_version,
        a2ui: json_object(
            frame.a2ui.as_ref().ok_or_else(|| refused("RPC A2UI message missing"))?,
            0,
        )?,
    };
    native.wire_bytes(kind)?;
    Ok(())
}

fn validate_resync(request: &g::SurfaceResyncRequest) -> Result<(), SdkError> {
    if request.conversation_id.is_empty()
        || request.surface_id.is_empty()
        || request.surface_ref.is_empty()
        || request.author.is_empty()
    {
        return Err(refused("surface resync requires conversation, surface, ref and author"));
    }
    Ok(())
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

impl RamfluxClient {
    /// Encode a generated Surface Inner. Does not send or persist.
    /// # Errors
    /// Same as [`validate_generated_surface`].
    pub fn encode_generated_surface(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        surface: g::Surface,
    ) -> Result<Vec<u8>, SdkError> {
        validate_generated_surface(&surface)?;
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Surface(surface)) },
        )
    }

    /// Candidate Surface native checks. Does not send or persist.
    /// # Errors
    /// Same as [`validate_generated_surface`].
    pub fn validate_generated_surface(surface: &g::Surface) -> Result<(), SdkError> {
        validate_generated_surface(surface)
    }

    /// Candidate original-signer binding for a Surface action or receipt.
    /// # Errors
    /// Same as [`authorize_surface_action_signer`].
    pub fn authorize_generated_surface_action_signer(
        original_signer: &str,
        carrier: &g::SurfaceCarrier,
    ) -> Result<(), SdkError> {
        authorize_surface_action_signer(original_signer, carrier)
    }
}

#[cfg(test)]
mod tests;
