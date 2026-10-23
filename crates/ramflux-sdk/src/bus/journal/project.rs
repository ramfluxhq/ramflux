// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit topic mapping and K11 metadata row construction; no arbitrary payload serialization.
use super::{A2iControlEvent, RamfluxClient, SdkError, Value, field, json, metadata};
use ramflux_storage::AccountOutboxEntry;
type Projection = (String, Value, Option<String>);

pub(crate) fn project(
    client: &RamfluxClient,
    entry: &AccountOutboxEntry,
) -> Result<Vec<Projection>, SdkError> {
    let db = client.account_db()?;
    let keys = &entry.keys;
    let mut events = Vec::new();
    if let Some(conversation) = field(keys, "conversation_id") {
        if let Some(message) = field(keys, "message_id") {
            if entry.table_name == "direct_message_projection" {
                let row = db.client_message_metadata(message)?.unwrap_or_else(
                    || json!({"id":message,"conversation_id":conversation,"removed":true}),
                );
                let route = db.load_actor_state::<crate::client::routed::Routing>(&format!(
                    "routed/committed/{message}"
                ))?;
                let topic = if entry.change_kind == "insert" && route.is_some() {
                    if route.as_ref().is_some_and(|route| {
                        route.kind == crate::client::routed::Kind::GroupMessage
                    }) {
                        "group.message.received"
                    } else {
                        "message.received"
                    }
                } else {
                    "message.updated"
                };
                events.push((topic.to_owned(),json!({"message":row,"conversation":super::super::read_model::row(client,"conversation",conversation)?}),None));
            } else if matches!(
                entry.table_name.as_str(),
                "message_tombstone_projection" | "receipt_projection"
            ) {
                events.push((
                    "message.updated".to_owned(),
                    json!({"message_id":message,"conversation_id":conversation}),
                    None,
                ));
            }
        }
        if entry.table_name.starts_with("conversation_")
            || entry.table_name == "direct_message_projection"
        {
            events.push((
                "conversation.changed".to_owned(),
                super::super::read_model::row(client, "conversation", conversation)?,
                None,
            ));
        }
    }
    project_object(client, entry, &mut events);
    if let Some(group) = field(keys, "group_id")
        && matches!(
            entry.table_name.as_str(),
            "group_projection" | "group_member_projection" | "group_ban_projection"
        )
    {
        events.push((
            "group.changed".to_owned(),
            super::super::read_model::row(client, "group", group)
                .unwrap_or_else(|_| json!({"id":group,"removed":true})),
            None,
        ));
    }
    project_contact(client, entry, &mut events)?;
    if entry.table_name == "runtime_actor_state"
        && let Some(kind) = field(keys, "state_kind")
    {
        state(client, kind, &mut events)?;
    }
    if entry.table_name == "audit_log"
        && let Some(audit) = db.client_audit_metadata(entry.row_id)?
        && let Some(topic) = field(&audit, "event_type")
        && topic.starts_with("mcp.tool.")
    {
        events.push((
            topic.to_owned(),
            metadata(
                &audit,
                &[
                    "server_id",
                    "tool_name",
                    "operation_origin",
                    "approval_id",
                    "grant_id",
                    "capability",
                    "risk_level",
                    "tool_scope",
                    "outcome",
                    "registry_hash",
                    "tool_manifest_set_hash",
                ],
            ),
            None,
        ));
    }
    Ok(events)
}

fn state(client: &RamfluxClient, key: &str, events: &mut Vec<Projection>) -> Result<(), SdkError> {
    let db = client.account_db()?;
    for (prefix, directory, topic) in [
        ("directory/conversation/", "conversation", "conversation.changed"),
        ("directory/identity/", "identity", "contact.changed"),
        ("directory/object/", "object", "object.changed"),
        ("directory/group/", "group", "group.changed"),
    ] {
        if let Some(id) = key.strip_prefix(prefix) {
            let row = super::super::read_model::row(client, directory, id)
                .unwrap_or_else(|_| json!({"id":id,"removed":true}));
            events.push((topic.to_owned(), row, None));
            return Ok(());
        }
    }
    if let Some(id) = key.strip_prefix("attachment/fetch/") {
        let row = super::super::read_model::row(client, "object", id)
            .unwrap_or_else(|_| json!({"id":id,"removed":true}));
        events.push(("object.transfer.progress".to_owned(), row.clone(), None));
        events.push(("object.changed".to_owned(), row, None));
    }
    if key.starts_with("stream/a2ui/")
        && let Some(value) = db.load_actor_state::<Value>(key)?
        && let Some(topic) = field(&value, "topic")
    {
        events.push((topic.to_owned(), value["body"].clone(), None));
    }
    if let Some(id) = key.strip_prefix("directory/approval/")
        && let Some(value) = db.client_record("approval", id)?
    {
        let topic = field(&value, "event_type").unwrap_or("mcp.approval.request").to_owned();
        let row = metadata(
            &value,
            &[
                "id",
                "approval_id",
                "server_id",
                "tool_name",
                "capability",
                "risk_level",
                "tool_scope",
                "confirmation_mode",
                "expires_at",
                "status",
                "registry_hash",
                "tool_manifest_set_hash",
                "conversation_id",
                "context_id",
            ],
        );
        events.push((topic, row, Some(id.to_owned())));
    }
    if let Some(value) = key
        .strip_prefix("a2i/")
        .map(|_| db.load_actor_state::<A2iControlEvent>(key))
        .transpose()?
        .flatten()
    {
        events.push((value.event_type.clone(),json!({"event_id":value.event_id,"source_device_id":value.source_device_id,"target_device_id":value.target_device_id,"action":value.action,"acknowledged":value.acknowledged}),None));
    }
    Ok(())
}

fn project_object(
    client: &RamfluxClient,
    entry: &AccountOutboxEntry,
    events: &mut Vec<Projection>,
) {
    if let Some(object) = field(&entry.keys, "object_id")
        && matches!(
            entry.table_name.as_str(),
            "object_index" | "object_operation" | "object_transfer_state" | "object_tombstone"
        )
    {
        let row = super::super::read_model::row(client, "object", object)
            .unwrap_or_else(|_| json!({"id":object,"removed":true}));
        let topic = if entry.table_name == "object_transfer_state" {
            "object.transfer.progress"
        } else {
            "object.changed"
        };
        events.push((topic.to_owned(), row, None));
    }
}

fn project_contact(
    client: &RamfluxClient,
    entry: &AccountOutboxEntry,
    events: &mut Vec<Projection>,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let keys = &entry.keys;
    if entry.table_name == "contact_verification_projection"
        && let Some(commitment) = field(keys, "contact_identity_commitment")
    {
        let peer = db.client_record("commitment", commitment)?;
        let identity = peer
            .as_ref()
            .and_then(|peer| field(peer, "principal_id"))
            .map(|id| super::super::read_model::row(client, "identity", id))
            .transpose()?
            .unwrap_or_else(|| json!({"contact_identity_commitment":commitment}));
        events.push(("safety.changed".to_owned(), identity, Some(commitment.to_owned())));
    }
    if entry.table_name == "friend_link_projection" {
        events.push((
            "contact.changed".to_owned(),
            metadata(keys, &["link_id", "requester_id", "target_id"]),
            None,
        ));
    }
    Ok(())
}
