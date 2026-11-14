// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reconstruct only current, locally admitted display text; no transport or receipt reads.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use ramflux_storage::local_search::{
    MAX_NORMALIZED_BYTES, MAX_SOURCE_BYTES, SearchActivation, SearchControl, SearchDependency,
    SearchError, SearchKind, SearchSource,
};
use serde_json::Value;

struct PrivateJson(Value);
impl std::ops::Deref for PrivateJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl Drop for PrivateJson {
    fn drop(&mut self) {
        crate::bus::secrets::wipe(&mut self.0);
    }
}
fn check_json_budget(bytes: &[u8]) -> Result<(), SdkError> {
    if bytes.len() > MAX_NORMALIZED_BYTES
        || bytes
            .iter()
            .filter(|byte| matches!(**byte, b'{' | b'[' | b',' | b':'))
            .take(1025)
            .count()
            > 1024
    {
        return Err(SearchError::Capacity.into());
    }
    Ok(())
}
fn json(bytes: &[u8]) -> Result<PrivateJson, SdkError> {
    check_json_budget(bytes)?;
    serde_json::from_slice(bytes).map(PrivateJson).map_err(|_| SearchError::IndexUnavailable.into())
}
fn dependency(table: &str, key: impl Into<String>) -> SearchDependency {
    SearchDependency { table: table.into(), key: key.into() }
}
fn append(text: &mut String, value: &str) -> bool {
    if text.len().saturating_add(value.len()).saturating_add(1) > MAX_SOURCE_BYTES {
        return false;
    }
    if !text.is_empty() {
        text.push(' ');
    }
    text.push_str(value);
    true
}

pub(super) fn sources(
    client: &RamfluxClient,
    activation: &SearchActivation,
    kind: SearchKind,
    key: &str,
    control: &SearchControl,
) -> Result<Vec<SearchSource>, SdkError> {
    let db = client.account_db()?;
    // Only the native admitted owner can authorize generated records; no inert-format indexing.
    if client.born_v3_account.is_none() {
        return Err(SearchError::IndexUnavailable.into());
    }
    if kind == SearchKind::Conversation {
        return conversation(client, activation, key, control);
    }
    let Some(input) = db.search_message_input(activation, key, control)? else {
        return Ok(Vec::new());
    };
    let identity: g::EventIdentity =
        serde_json::from_slice(&input.identity).map_err(|_| SearchError::IndexUnavailable)?;
    g::identity::verify(&identity).map_err(|_| SearchError::IndexUnavailable)?;
    if identity.conversation_id != input.conversation_id
        || ramflux_protocol::encode_base64url(&identity.id) != key
    {
        return Err(SearchError::IndexUnavailable.into());
    }
    if let Some(group) = identity.group_id.as_deref() {
        let viewer = client.read_device_identity()?.ok_or(SearchError::PermissionDenied)?;
        if !db.search_group_member(activation, group, &viewer, control)? {
            return Ok(Vec::new());
        }
    }
    let message = if let Some(projection) = input.group_projection.as_ref() {
        check_json_budget(projection)?;
        serde_json::from_slice::<super::projection::DisplayMessage>(projection)
            .map_err(|_| SearchError::IndexUnavailable)?
    } else {
        let Some(display) = super::projection::decode(&input.body)? else {
            return Ok(Vec::new());
        };
        display
    };
    if message.sealed_group.is_some() {
        return Ok(Vec::new());
    }
    let mut dependencies = vec![
        dependency("runtime_message_content", key),
        dependency("direct_message_projection", key),
        dependency("conversation_list_state", &input.conversation_id),
        dependency("conversation_projection", &input.conversation_id),
        dependency("conversation_disappearing_policy", &input.conversation_id),
        dependency("runtime_actor_state", format!("routed/generated-identity/{key}")),
        dependency("runtime_actor_state", format!("routed/unsupported/{key}")),
        dependency("runtime_actor_state", format!("routed/group-projection/{key}")),
        dependency("runtime_actor_state", format!("routed/edit-revision/{key}")),
        dependency("object_message_reference", key),
    ];
    if let Some(group) = identity.group_id.as_ref() {
        dependencies.push(dependency("shared_group_member_projection", group));
        dependencies.push(dependency("group_projection", group));
    }
    if message.entities.len() > 1024 {
        return Err(SearchError::Capacity.into());
    }
    let concealed = message
        .entities
        .iter()
        .filter(|entity| entity.kind == g::EntityKind::EntitySpoiler as i32)
        .map(|entity| {
            entity
                .offset
                .checked_add(entity.length)
                .map(|end| (entity.offset, end))
                .ok_or(SearchError::IndexUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let visible =
        ramflux_storage::local_search::visible_source_text(&message.text, &concealed, control)?;
    let mut output = Vec::new();
    if !visible.expose().trim().is_empty() {
        output.push(SearchSource {
            kind: SearchKind::Message,
            source_ref: key.into(),
            source_key: key.into(),
            conversation_id: input.conversation_id.clone(),
            message_id: Some(key.into()),
            revision: input.revision,
            timestamp: input.created_at,
            expires_at: input.expires_at,
            text: visible,
            dependencies: dependencies.clone(),
        });
    }
    output.extend(attachment_sources(db, activation, &input, &message, &dependencies, control)?);
    Ok(output)
}

fn attachment_sources(
    db: &ramflux_storage::AccountDb,
    activation: &SearchActivation,
    input: &ramflux_storage::local_search::SearchMessageInput,
    message: &super::projection::DisplayMessage,
    dependencies: &[SearchDependency],
    control: &SearchControl,
) -> Result<Vec<SearchSource>, SdkError> {
    let key = input.message_id.as_str();
    let mut output = Vec::new();
    let mut bytes = 0usize;
    for (ordinal, media) in message.media.iter().take(32).enumerate() {
        control.check()?;
        let Some(name) = media.file_name.as_ref() else { continue };
        let basename = name.rsplit(['/', '\\']).next().unwrap_or("");
        if basename.is_empty() || media.manifest_digest.len() != 32 {
            continue;
        }
        let manifest = ramflux_protocol::encode_base64url(&media.manifest_digest);
        let Some(admitted) = db.search_attachment_dependencies(
            activation,
            key,
            &media.object_id,
            &manifest,
            control,
        )?
        else {
            continue;
        };
        let mut dependencies = dependencies.to_vec();
        dependencies.extend(admitted);
        dependencies.push(dependency("object_index", &media.object_id));
        let source = SearchSource {
            kind: SearchKind::Attachment,
            source_ref: format!("{key}/{}/{ordinal}", media.object_id),
            source_key: key.into(),
            conversation_id: input.conversation_id.clone(),
            message_id: Some(key.into()),
            revision: input.revision,
            timestamp: input.created_at,
            expires_at: input.expires_at,
            text: basename.into(),
            dependencies,
        };
        source.validate()?;
        let strings = source
            .text
            .expose()
            .len()
            .saturating_add(source.source_ref.len())
            .saturating_add(source.source_key.len())
            .saturating_add(source.conversation_id.len())
            .saturating_add(source.message_id.as_ref().map_or(0, String::len))
            .saturating_add(source.dependencies.iter().fold(0usize, |total, dependency| {
                total.saturating_add(dependency.table.len()).saturating_add(dependency.key.len())
            }));
        bytes = bytes
            .saturating_add(strings.saturating_mul(2))
            .saturating_add(
                source
                    .dependencies
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SearchDependency>()),
            )
            .saturating_add(std::mem::size_of::<SearchSource>());
        if bytes > ramflux_storage::local_search::MAX_REBUILD_BYTES {
            return Err(SearchError::Capacity.into());
        }
        output.push(source);
    }
    Ok(output)
}

fn conversation(
    client: &RamfluxClient,
    activation: &SearchActivation,
    key: &str,
    control: &SearchControl,
) -> Result<Vec<SearchSource>, SdkError> {
    let db = client.account_db()?;
    if !db.search_conversation_visible(activation, key, control)? {
        return Ok(Vec::new());
    }
    let actor = format!("directory/conversation/{key}");
    let Some(bytes) = db.search_actor_bytes(activation, &actor, control)? else {
        return Ok(Vec::new());
    };
    let metadata = json(&bytes)?;
    let mut dependencies = vec![
        dependency("runtime_actor_state", actor),
        dependency("conversation_list_state", key),
        dependency("conversation_projection", key),
    ];
    if let Some(group) = metadata.get("group_id").and_then(Value::as_str) {
        let viewer = client.read_device_identity()?.ok_or(SearchError::PermissionDenied)?;
        if !db.search_group_member(activation, group, &viewer, control)? {
            return Ok(Vec::new());
        }
        dependencies.push(dependency("shared_group_member_projection", group));
        dependencies.push(dependency("group_projection", group));
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    if let Some(title) = metadata.get("title").and_then(Value::as_str)
        && !append(&mut text, title)
    {
        return Err(SearchError::Capacity.into());
    }
    if let Some(participants) = metadata.get("participants").and_then(Value::as_array) {
        if participants.len() > 1024 {
            return Err(SearchError::Capacity.into());
        }
        for participant in participants.iter().take(1024).filter_map(Value::as_str) {
            control.check()?;
            if participant.len() > 256 || !append(&mut text, participant) {
                return Err(SearchError::Capacity.into());
            }
            let actor = format!("directory/identity/{participant}");
            if let Some(bytes) = db.search_actor_bytes(activation, &actor, control)? {
                let metadata = json(&bytes)?;
                if let Some(name) = metadata.get("display_name").and_then(Value::as_str)
                    && !append(&mut text, name)
                {
                    return Err(SearchError::Capacity.into());
                }
            }
            dependencies.push(dependency("runtime_actor_state", actor));
        }
    }
    if text.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![SearchSource {
        kind: SearchKind::Conversation,
        source_ref: key.into(),
        source_key: key.into(),
        conversation_id: key.into(),
        message_id: None,
        revision: metadata.get("revision").and_then(Value::as_u64).unwrap_or(0),
        timestamp: 0,
        expires_at: None,
        text: std::mem::take(&mut *text).into(),
        dependencies,
    }])
}
