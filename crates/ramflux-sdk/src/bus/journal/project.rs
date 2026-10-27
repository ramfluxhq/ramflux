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
    if entry.table_name == "backup_restore" {
        let pending = db.load_actor_state::<bool>("backup/reestablishing")?.unwrap_or(false);
        events.push(("account.restored".into(),json!({"local_account_id":keys["local_account_id"],"job_id":keys["job_id"],"secure_sessions":if pending{"reestablishing"}else{"ready"}}),None));
        return Ok(events);
    }
    if let Some(conversation) = field(keys, "conversation_id") {
        if let Some(message) = field(keys, "message_id") {
            if entry.table_name == "direct_message_projection" {
                let mut row = db.client_message_metadata(message)?.unwrap_or_else(
                    || json!({"id":message,"conversation_id":conversation,"removed":true}),
                );
                enrich_message_origin(client, conversation, message, &mut row)?;
                let route = client.routed_message_metadata(message)?;
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

fn enrich_message_origin(
    client: &RamfluxClient,
    conversation: &str,
    message: &str,
    row: &mut Value,
) -> Result<(), SdkError> {
    if row.get("deleted").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    let origin = client.message_origin(conversation, message)?.unwrap_or(Value::Null);
    for field in ["sender_device_id", "sender_root_commitment", "sender_device_display"] {
        row[field] = origin[field].clone();
    }
    Ok(())
}

fn state(client: &RamfluxClient, key: &str, events: &mut Vec<Projection>) -> Result<(), SdkError> {
    let db = client.account_db()?;
    for prefix in ["directory/surface/", "directory/surface_error/"] {
        if let Some(id) = key.strip_prefix(prefix) {
            let directory =
                if prefix == "directory/surface/" { "surface" } else { "surface_error" };
            let view = db
                .client_record(directory, id)?
                .unwrap_or_else(|| json!({"surface_id":id,"surface_ref":id,"removed":true}));
            events.push((
                if directory == "surface" { "surface.changed" } else { "surface.rejected" }
                    .to_owned(),
                crate::client::surface::surface_metadata(&view),
                None,
            ));
            return Ok(());
        }
    }
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
    if matches!(entry.table_name.as_str(), "contact_request_projection" | "contact_message_request")
        && let Some(root) = field(keys, "contact_identity_commitment")
    {
        for direction in ["inbound", "outbound"] {
            if let Some(request) = db.contact_request(root, direction)? {
                if entry.table_name == "contact_message_request"
                    && (direction != "inbound" || request.state != "pending")
                {
                    continue;
                }
                let topic = match (request.state.as_str(), direction) {
                    ("pending", "inbound") => "contact.requested",
                    ("accepted", _) => "contact.accepted",
                    ("declined", _) => "contact.declined",
                    ("blocked", _) => "contact.blocked",
                    ("expired", _) => "contact.request.expired",
                    _ => continue,
                };
                let body = json!({"request_id":request.request_id,"principal_id":request.principal_id,
                    "root_commitment":root,"state":request.state,"direction":direction,
                    "message_count":if direction=="inbound" && request.state=="pending" {
                        db.contact_message_count(root)?
                    } else { 0 }});
                events.push((topic.into(), body, Some(root.into())));
            }
        }
    }
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
        events.push(("contact.changed".to_owned(), identity.clone(), Some(commitment.to_owned())));
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

#[cfg(test)]
mod removal_tests {
    use super::*;
    #[test]
    fn surface_removal_includes_the_scoped_reference_without_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-surface-removal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("a", "root")?;
        client.unlock_account("a", b"test")?;
        let reference = "opaque-conversation-author-surface-reference";
        let entry = AccountOutboxEntry {
            sequence: 1,
            table_name: "runtime_actor_state".into(),
            change_kind: "delete".into(),
            row_id: 0,
            keys: json!({"state_kind":format!("directory/surface/{reference}")}),
        };
        let events = project(&client, &entry)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "surface.changed");
        assert_eq!(events[0].1["surface_ref"], reference);
        assert_eq!(events[0].1["removed"], true);
        assert!(events[0].1.get("snapshot").is_none());
        assert!(events[0].1.get("fallback_text").is_none());
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
