// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! List-row facts that the directory already has locally: a bounded preview and an avatar kind.
//! Preview text is plain stored text. Attachment and system rows carry a kind and no text.

use crate::prelude::*;
use ramflux_protocol::PrincipalKind;
use ramflux_protocol::message as g;
use serde_json::{Map, Value, json};

/// Byte cap for one preview. Truncation keeps a char boundary and adds no ellipsis.
const PREVIEW_MAX_BYTES: usize = 256;

pub(super) fn attach_conversation(
    client: &RamfluxClient,
    conversation_id: &str,
    row: &mut Value,
) -> Result<(), SdkError> {
    row["peer_kind"] = json!(peer_kind(client, row)?);
    row["preview"] = preview(client, conversation_id)?;
    Ok(())
}

pub(super) fn attach_group(client: &RamfluxClient, group: &mut Value) -> Result<(), SdkError> {
    let members = group.get("members").and_then(Value::as_array).map_or(0, Vec::len);
    group["member_count"] = json!(u64::try_from(members).unwrap_or(u64::MAX));
    let title = group.get("name").filter(|name| name.is_string()).cloned().unwrap_or(Value::Null);
    let conversation = group.get("conversation_id").and_then(Value::as_str);
    let (last_activity, row_preview) = match conversation {
        Some(conversation) => group_activity(client, conversation)?,
        None => (Value::Null, Value::Null),
    };
    group["summary"] = json!({
        "title": title,
        "last_activity": last_activity,
        "preview": row_preview,
    });
    Ok(())
}

fn group_activity(client: &RamfluxClient, conversation: &str) -> Result<(Value, Value), SdkError> {
    let viewer = client.read_device_identity()?;
    let meta = client.account_db()?.client_conversation_metadata(conversation, viewer.as_ref())?;
    let activity = meta.get("last_activity").cloned().unwrap_or(Value::Null);
    Ok((activity, preview(client, conversation)?))
}

/// Avatar kind. Closed values are `person`, `group` and `agent`.
/// The stored `kind` field stays `direct` or `group`.
fn peer_kind(client: &RamfluxClient, row: &Value) -> Result<String, SdkError> {
    if is_group(row) {
        return Ok("group".to_owned());
    }
    let Some(peer) = other_principal(row) else {
        return Ok("person".to_owned());
    };
    Ok(avatar_kind(client, &peer)?.to_owned())
}

fn is_group(row: &Value) -> bool {
    row.get("group_id").and_then(Value::as_str).is_some_and(|id| !id.is_empty())
        || row.get("kind").and_then(Value::as_str) == Some("group")
}

fn other_principal(row: &Value) -> Option<String> {
    if let Some(peer) = row.get("peer_principal_id").and_then(Value::as_str)
        && !peer.is_empty()
    {
        return Some(peer.to_owned());
    }
    let own = row.get("self_principal_id").and_then(Value::as_str);
    row.get("participants").and_then(Value::as_array).and_then(|participants| {
        participants
            .iter()
            .filter_map(Value::as_str)
            .find(|participant| Some(*participant) != own)
            .map(str::to_owned)
    })
}

fn avatar_kind(client: &RamfluxClient, principal: &str) -> Result<&'static str, SdkError> {
    if let Some(facts) = client.read_profile_facts(principal) {
        return Ok(kind_name(facts.profile.kind));
    }
    let stored = client.account_db()?.client_record("identity", principal)?;
    Ok(match stored.as_ref().and_then(|row| row.get("kind")).and_then(Value::as_str) {
        Some("headless_ai" | "bot" | "workflow" | "agent") => "agent",
        _ => "person",
    })
}

fn kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "person",
        PrincipalKind::HeadlessAi | PrincipalKind::Bot | PrincipalKind::Workflow => "agent",
    }
}

fn preview(client: &RamfluxClient, conversation: &str) -> Result<Value, SdkError> {
    let db = client.account_db()?;
    let Some((message_id, at)) = db.latest_visible_message(conversation)? else {
        return Ok(Value::Null);
    };
    if db
        .load_actor_state::<g::UnsupportedView>(&format!("routed/unsupported/{message_id}"))?
        .is_some()
    {
        return Ok(preview_value("unsupported", None, at));
    }
    let class = classify_body(client, &message_id)?;
    Ok(preview_value(class.kind(), class.text(), at))
}

fn classify_body(client: &RamfluxClient, message_id: &str) -> Result<PreviewClass, SdkError> {
    let db = client.account_db()?;
    if let Some(projected) =
        db.load_actor_state::<g::Message>(&format!("routed/group-projection/{message_id}"))?
    {
        return Ok(classify_message(&projected));
    }
    let Some(bytes) = db.message_content_within(
        message_id,
        ramflux_protocol::message::validation::MAX_INNER_BYTES,
    )?
    else {
        return Ok(PreviewClass::Unsupported);
    };
    let Ok((_, mut content)) = RamfluxClient::decode_generated_inner(&bytes) else {
        return Ok(PreviewClass::Unsupported);
    };
    if let Some(g::content::Value::Edit(edit)) = content.value.as_ref() {
        match edit.replacement.clone() {
            Some(message) => content.value = Some(g::content::Value::Message(message)),
            None => return Ok(PreviewClass::System),
        }
    }
    g::private_revision::redact_content(&mut content);
    Ok(classify_content(&content))
}

fn classify_content(content: &g::Content) -> PreviewClass {
    match content.value.as_ref() {
        Some(g::content::Value::Message(message)) => classify_message(message),
        Some(
            g::content::Value::Service(_)
            | g::content::Value::Edit(_)
            | g::content::Value::Delete(_)
            | g::content::Value::Reaction(_)
            | g::content::Value::Receipt(_)
            | g::content::Value::Typing(_)
            | g::content::Value::Control(_)
            | g::content::Value::Surface(_)
            | g::content::Value::Task(_)
            | g::content::Value::Call(_)
            | g::content::Value::SelfSync(_),
        ) => PreviewClass::System,
        None => PreviewClass::Unsupported,
    }
}

fn classify_message(message: &g::Message) -> PreviewClass {
    if message.sealed_group.is_some() {
        return PreviewClass::Unsupported;
    }
    if !message.media.is_empty() {
        return PreviewClass::Attachment;
    }
    PreviewClass::Text(bound_text(&message.text))
}

enum PreviewClass {
    Text(String),
    Attachment,
    System,
    Unsupported,
}

impl PreviewClass {
    fn kind(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Attachment => "attachment",
            Self::System => "system",
            Self::Unsupported => "unsupported",
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Attachment | Self::System | Self::Unsupported => None,
        }
    }
}

fn preview_value(kind: &str, text: Option<&str>, at: i64) -> Value {
    let mut value = Map::new();
    value.insert("kind".to_owned(), json!(kind));
    if let Some(text) = text {
        value.insert("text".to_owned(), json!(text));
    }
    value.insert("at".to_owned(), json!(at));
    Value::Object(value)
}

fn bound_text(text: &str) -> String {
    if text.len() <= PREVIEW_MAX_BYTES {
        return text.to_owned();
    }
    let mut end = PREVIEW_MAX_BYTES;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or("").to_owned()
}
