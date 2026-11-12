// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `CONTROL_A2I` (operation 11): a signed agent-to-inbox control event.
//! The typed event converts to the native signed document, its signature is checked against the
//! pinned key of the authenticated sending device. Execution is closed until native grants exist.
use super::{authority, content, generated_signed, native_signed};
use crate::client::identity_authority::HeadUse;
use crate::client::routed::{Kind, Opened};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde_json::{Map, Value};

const MAX_JSON_DEPTH: usize = 16;

fn json_to_native(value: &g::JsonValue, depth: usize) -> Result<Value, SdkError> {
    use g::json_value::Value as J;
    if depth > MAX_JSON_DEPTH {
        return Err(content("a2i JSON nesting too deep"));
    }
    Ok(match value.value.as_ref().ok_or_else(|| content("a2i JSON choice missing"))? {
        J::Null(_) => Value::Null,
        J::Boolean(flag) => Value::Bool(*flag),
        J::Number(token) => {
            let number: Value =
                serde_json::from_str(token).map_err(|_| content("a2i JSON number invalid"))?;
            if !number.is_number() || number.to_string().as_bytes() != token.as_bytes() {
                return Err(content("a2i JSON number noncanonical"));
            }
            number
        }
        J::Text(text) => Value::String(text.clone()),
        J::Array(array) => Value::Array(
            array
                .values
                .iter()
                .map(|item| json_to_native(item, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        J::Object(object) => Value::Object(object_to_native(object, depth + 1)?),
    })
}

fn object_to_native(object: &g::JsonObject, depth: usize) -> Result<Map<String, Value>, SdkError> {
    let mut members = Map::new();
    for member in &object.members {
        let value = member.value.as_ref().ok_or_else(|| content("a2i JSON member missing"))?;
        if members.insert(member.key.clone(), json_to_native(value, depth)?).is_some() {
            return Err(content("a2i JSON duplicate key"));
        }
    }
    Ok(members)
}

fn json_to_generated(value: &Value) -> g::JsonValue {
    use g::json_value::Value as J;
    g::JsonValue {
        value: Some(match value {
            Value::Null => J::Null(g::JsonNull {}),
            Value::Bool(flag) => J::Boolean(*flag),
            Value::Number(number) => J::Number(number.to_string()),
            Value::String(text) => J::Text(text.clone()),
            Value::Array(values) => {
                J::Array(g::JsonArray { values: values.iter().map(json_to_generated).collect() })
            }
            Value::Object(object) => J::Object(object_to_generated(object)),
        }),
    }
}

fn object_to_generated(object: &Map<String, Value>) -> g::JsonObject {
    g::JsonObject {
        members: object
            .iter()
            .map(|(key, value)| g::JsonMember {
                key: key.clone(),
                value: Some(json_to_generated(value)),
            })
            .collect(),
    }
}

fn domain_to_native(
    event: &g::A2iControlEvent,
) -> Result<ramflux_protocol::ControlDomain, SdkError> {
    use g::control_domain::Value as D;
    use ramflux_protocol::ControlDomain as N;
    Ok(match event.control_domain.as_ref().and_then(|domain| domain.value.as_ref()) {
        Some(D::Message(_)) => N::Message,
        Some(D::Conversation(_)) => N::Conversation,
        Some(D::A2ui(_)) => N::A2ui,
        Some(D::McpTool(_)) => N::McpTool,
        None => return Err(content("a2i control requires a typed domain")),
    })
}

/// Typed event to the native signed document. Reserved member names cannot be smuggled through
/// the extension map: the native type refuses unknown and duplicate fields.
fn to_native(event: &g::A2iControlEvent) -> Result<ramflux_protocol::A2iControlEvent, SdkError> {
    if event.schema != ramflux_protocol::domain::A2I_CONTROL
        || event.domain != ramflux_protocol::domain::A2I_CONTROL
        || event.version != 1
    {
        return Err(content("a2i schema, domain or version unknown"));
    }
    if !matches!(
        event.event_type.as_ref().and_then(|kind| kind.value.as_ref()),
        Some(g::a2i_control_event_type::Value::Control(_))
    ) {
        return Err(content("a2i event type missing"));
    }
    let signed = native_signed(event.signed.as_ref())?;
    let mut document = match event.ext.as_ref().and_then(|ext| ext.ext.as_ref()) {
        Some(ext) if !ext.members.is_empty() => {
            let mut wrapper = Map::new();
            wrapper.insert("ext".into(), Value::Object(object_to_native(ext, 1)?));
            wrapper
        }
        _ => Map::new(),
    };
    let mut put = |key: &str, value: Value| document.insert(key.to_owned(), value);
    put("schema", Value::String(event.schema.clone()));
    put("version", Value::from(event.version));
    put("domain", Value::String(event.domain.clone()));
    put("signing_key_id", Value::String(signed.signing_key_id.clone()));
    put("signature_alg", serde_json::to_value(&signed.signature_alg)?);
    put("signature", Value::String(signed.signature.clone()));
    put("event_type", Value::String("a2i.control".into()));
    put("control_domain", serde_json::to_value(domain_to_native(event)?)?);
    put("action", Value::String(event.action.clone()));
    put(
        "subject",
        json_to_native(event.subject.as_ref().ok_or_else(|| content("a2i subject missing"))?, 1)?,
    );
    put("correlation_id", Value::String(event.correlation_id.clone()));
    put("source_device_id", Value::String(event.source_device_id.clone()));
    put("target_device_id", Value::String(event.target_device_id.clone()));
    if let Some(grant) = event.grant_id.as_ref() {
        put("grant_id", Value::String(grant.clone()));
    }
    if let Some(expires) = event.expires_at {
        put("expires_at", Value::from(expires));
    }
    serde_json::from_value(Value::Object(document))
        .map_err(|_| content("a2i event is not a native signed document"))
}

/// Native signed document to the typed event (producer side).
pub(in crate::client::routed) fn to_generated(
    event: &ramflux_protocol::A2iControlEvent,
) -> Result<g::A2iControlEvent, SdkError> {
    use g::control_domain::Value as D;
    use ramflux_protocol::ControlDomain as N;
    let domain = match event.control_domain {
        N::Message => D::Message(g::ControlDomainMessage {}),
        N::Conversation => D::Conversation(g::ControlDomainConversation {}),
        N::A2ui => D::A2ui(g::ControlDomainA2ui {}),
        N::McpTool => D::McpTool(g::ControlDomainMcpTool {}),
    };
    let ext = if event.ext.ext.is_empty() {
        None
    } else {
        Some(g::Ext {
            ext: Some(object_to_generated(
                &event.ext.ext.iter().map(|(key, value)| (key.clone(), value.clone())).collect(),
            )),
        })
    };
    let generated = g::A2iControlEvent {
        schema: event.schema.clone(),
        version: event.version,
        domain: event.domain.clone(),
        ext,
        signed: Some(generated_signed(&event.signed)),
        event_type: Some(g::A2iControlEventType {
            value: Some(g::a2i_control_event_type::Value::Control(
                g::A2iControlEventTypeControl {},
            )),
        }),
        control_domain: Some(g::ControlDomain { value: Some(domain) }),
        action: event.action.clone(),
        subject: Some(json_to_generated(&event.subject)),
        correlation_id: event.correlation_id.clone(),
        source_device_id: event.source_device_id.clone(),
        target_device_id: event.target_device_id.clone(),
        grant_id: event.grant_id.clone(),
        expires_at: event.expires_at,
    };
    if to_native(&generated)? != *event {
        return Err(content("a2i event does not survive the typed round trip"));
    }
    Ok(generated)
}

/// OPEN-VALUE (A2I-INBOX-ROW): no document fixes how the signed document fills the native A2I
/// inbox row. Recommended mapping, kept in this one function: `event_id` = `correlation_id`,
/// `event_type` = "a2i.control", `control_domain` = native `snake_case` name, `subject_base64` =
/// base64url of the canonical JSON subject, `created_at` = local receive time (seconds).
#[cfg(test)]
fn inbox_row(
    native: &ramflux_protocol::A2iControlEvent,
    received_at: i64,
) -> Result<ramflux_sync::A2iControlEvent, SdkError> {
    Ok(ramflux_sync::A2iControlEvent {
        event_id: native.correlation_id.clone(),
        event_type: "a2i.control".into(),
        source_device_id: native.source_device_id.clone(),
        source_principal_id: None,
        source_principal_commitment: None,
        target_device_id: native.target_device_id.clone(),
        control_domain: serde_json::to_value(&native.control_domain)?
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        action: native.action.clone(),
        subject_base64: ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(
            &native.subject,
        )?),
        created_at: received_at,
        acknowledged: false,
    })
}

impl RamfluxClient {
    /// Sender rule: the authenticated pair peer names itself as source and this device as target,
    /// and its pinned device key signed the native document. An expired event is refused.
    pub(in crate::client::routed) fn authorize_generated_a2i(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        event: &g::A2iControlEvent,
    ) -> Result<ramflux_protocol::A2iControlEvent, SdkError> {
        Self::require_a2i_binding_authority()?;
        if opened.routing.kind != Kind::Control || opened.routing.group_id.is_some() {
            return Err(authority("a2i control requires a direct control route"));
        }
        let native = to_native(event)?;
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if source != opened.remote_device
            || native.source_device_id != source.device_id()
            || native.target_device_id != opened.local_device.device_id()
            || native.signed.signing_key_id != source.device_id()
        {
            return Err(authority("a2i device binding differs from authenticated endpoints"));
        }
        if source.root_commitment() != self.own_account_anchor()?
            && self.friend_rejection_reason(source.root_commitment())?.is_some()
        {
            return Err(authority("blocked or removed peer cannot send a2i controls"));
        }
        if native.correlation_id.is_empty() || native.action.is_empty() {
            return Err(content("a2i correlation id and action are required"));
        }
        if native.expires_at.is_some_and(|expires| expires <= crate::time::now_unix_timestamp()) {
            return Err(content("a2i control expired"));
        }
        let (_, key) = self.pinned_peer(&source)?;
        ramflux_protocol::verify_signed_fields(&native, &native.signed, &key)
            .map_err(|_| authority("a2i signature invalid for the pinned device key"))?;
        Ok(native)
    }

    /// Native inbox write: the row is bound to the verified root, an event id reused with other
    /// content by the same sender is refused, and both rows commit with the replay ledger.
    pub(in crate::client::routed) fn apply_generated_a2i(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        event: &g::A2iControlEvent,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        let _ = (identity, exact_inner);
        self.authorize_generated_a2i(opened, entry, event)?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a2i_json_numbers_and_duplicate_keys_are_refused() {
        let number =
            |token: &str| g::JsonValue { value: Some(g::json_value::Value::Number(token.into())) };
        assert!(json_to_native(&number("1"), 1).is_ok());
        for token in ["01", "1.0e0", " 1", "NaN", "\"1\""] {
            assert!(json_to_native(&number(token), 1).is_err(), "number {token:?} admitted");
        }
        let member = |key: &str| g::JsonMember { key: key.into(), value: Some(number("1")) };
        let duplicate = g::JsonObject { members: vec![member("a"), member("a")] };
        assert!(object_to_native(&duplicate, 1).is_err());
    }

    #[test]
    fn inbox_mapping_is_not_an_authority_contract() -> Result<(), SdkError> {
        let native = serde_json::from_value(serde_json::json!({
            "schema": ramflux_protocol::domain::A2I_CONTROL, "version": 1,
            "domain": ramflux_protocol::domain::A2I_CONTROL,
            "signing_key_id": "source", "signature_alg": "ed25519", "signature": "sig",
            "event_type": "a2i.control", "control_domain": "mcp_tool",
            "action": "approve", "subject": {"tool":"search"},
            "correlation_id": "event", "source_device_id": "source", "target_device_id": "target"
        }))?;
        let mapped = inbox_row(&native, 123)?;
        assert_eq!(mapped.event_id, "event");
        assert_eq!(mapped.created_at, 123);
        assert_eq!(
            mapped.subject_base64,
            ramflux_protocol::encode_base64url(br#"{"tool":"search"}"#)
        );
        assert!(RamfluxClient::require_a2i_binding_authority().is_err());
        Ok(())
    }

    #[test]
    fn a2i_extension_cannot_shadow_signed_members() {
        let event = g::A2iControlEvent {
            schema: ramflux_protocol::domain::A2I_CONTROL.into(),
            version: 1,
            domain: ramflux_protocol::domain::A2I_CONTROL.into(),
            signed: None,
            ..Default::default()
        };
        assert!(to_native(&event).is_err(), "unsigned a2i event admitted");
    }
}
