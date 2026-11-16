// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generic all-column inspection of message-copy stores, independent of erasure implementation.
use super::*;
use ramflux_storage::{FileVaultSecretSource, VaultSecretSource};
use rusqlite::{Connection, types::ValueRef};
use std::fmt::Write;
pub(super) type IdentitySnapshot = Vec<(String, Vec<Vec<u8>>)>;
const IDENTITY_TABLES: &[&str] = &[
    "device_directory",
    "device_identity",
    "local_event_counter",
    "friend_link_projection",
    "contact_request_projection",
    "contact_request_decision",
    "contact_link_decision",
    "contact_root_binding",
    "shared_group_member_projection",
    "group_member_projection",
    "group_member_device_key",
    "runtime_account_identity",
    "runtime_inbox_changes",
    "root_group_control_event_seen",
];
const IDENTITY_ACTOR_FILTER: &str = "state_kind GLOB 'directory/identity/*' OR state_kind GLOB 'directory/device/*' OR state_kind GLOB 'directory/contact/*' OR state_kind GLOB 'directory/commitment/*' OR state_kind GLOB 'directory/conversation/*' OR state_kind GLOB 'directory/group/*' OR state_kind GLOB 'directory/group-local/*' OR state_kind GLOB 'directory/group-name/*' OR state_kind GLOB 'group-state/*' OR state_kind GLOB 'task/verified_roster_v2/*' OR state_kind GLOB 'identity/*' OR state_kind GLOB 'authority/*'";
const IDENTITY_EVENT_FILTER: &str = "event_type GLOB 'identity.*' OR event_type GLOB 'device.*' OR event_type GLOB 'prekey.*' OR event_type GLOB 'x3dh.prekey.*' OR event_type IN ('dm.ratchet_session','group.sender_key.state','group.member.route')";
// Static migration descriptions are schema metadata, never account or message copies.
const STRUCTURAL_TABLES: &[&str] = &["schema_migration"];

pub(super) fn open(
    spec: &Spec,
    client: &RamfluxClient,
) -> Result<Connection, Box<dyn std::error::Error>> {
    client.account_db()?.checkpoint_retired_secrets()?;
    let vault = FileVaultSecretSource::new(&spec.root).vault_secret(&spec.principal)?;
    let wrapped = client.account_index()?.load_wrapped_db_key(&spec.principal)?.ok_or("key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(&vault, b"receipt-test"),
        &wrapped,
    )?;
    let db = Connection::open_with_flags(
        &client.account_db()?.path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut hex = String::with_capacity(64);
    for byte in key.bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    db.execute_batch(&format!("PRAGMA key=\"x'{hex}'\"; PRAGMA query_only=ON;"))?;
    Ok(db)
}

pub(super) fn identities(db: &Connection) -> Result<IdentitySnapshot, rusqlite::Error> {
    let mut result = Vec::new();
    for table in IDENTITY_TABLES {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |r| r.get(0),
        )?;
        if exists {
            result.push((
                (*table).into(),
                dump(db, &format!("SELECT * FROM {table} ORDER BY rowid"))?,
            ));
        }
    }
    result.push(("identity actor records".into(),dump(db,&format!("SELECT * FROM runtime_actor_state WHERE {IDENTITY_ACTOR_FILTER} ORDER BY state_kind"))?));
    result.push((
        "independent key authority events".into(),
        dump(
            db,
            &format!(
                "SELECT * FROM local_event_log WHERE {IDENTITY_EVENT_FILTER} ORDER BY event_id"
            ),
        )?,
    ));
    result.push(("identity notifications".into(),dump(db,"SELECT * FROM runtime_journal WHERE topic IN ('safety.changed','account.state') ORDER BY seq")?));
    result.push(("identity outbox records".into(),dump(db,&format!("SELECT o.sequence,o.table_name,o.change_kind,o.row_id,o.keys_json FROM runtime_outbox o WHERE o.table_name IN ({}) OR (o.table_name='runtime_actor_state' AND EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.rowid=o.row_id AND ({IDENTITY_ACTOR_FILTER}))) OR (o.table_name='local_event_log' AND EXISTS(SELECT 1 FROM local_event_log e WHERE e.rowid=o.row_id AND ({IDENTITY_EVENT_FILTER}))) ORDER BY o.sequence",IDENTITY_TABLES.iter().map(|table|format!("'{table}'")).collect::<Vec<_>>().join(",")))?));
    Ok(result)
}

fn dump(db: &Connection, sql: &str) -> Result<Vec<Vec<u8>>, rusqlite::Error> {
    let mut q = db.prepare(sql)?;
    let columns = q.column_count();
    q.query_map([], |row| {
        let mut bytes = Vec::new();
        for column in 0..columns {
            let value = row.get_ref(column)?;
            bytes.extend_from_slice(format!("{value:?}\0").as_bytes());
        }
        Ok(bytes)
    })?
    .collect()
}

pub(super) fn dictionary(
    db: &Connection,
    envelope: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut q=db.prepare("SELECT principal_commitment,device_id,COALESCE(raw_device_id,device_id) FROM device_directory")?;
    let rows = q
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let roots = rows.iter().map(|(root, _, _)| root).collect::<BTreeSet<_>>();
    let devices =
        rows.iter().flat_map(|(_, qualified, raw)| [qualified, raw]).collect::<BTreeSet<_>>();
    let mut probes = Vec::new();
    for root in roots {
        for device in &devices {
            probes.push(ramflux_crypto::blake3_256_base64url(
                "ramflux.sdk.receipt.v3",
                &ramflux_protocol::canonical_json_bytes(&(root, device, envelope))?,
            ));
        }
    }
    Ok(probes)
}

pub(super) fn forbidden(
    db: &Connection,
    entry: &GatewayInboxEntry,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut values = dictionary(db, &entry.envelope.envelope_id)?;
    values.extend([
        source.root_commitment().to_owned(),
        entry.envelope.source_principal_id.clone(),
        entry.envelope.source_device_id.clone(),
        entry.envelope.envelope_id.clone(),
    ]);
    Ok(values)
}

pub(super) fn assert_erased(db: &Connection, forbidden: &[String], message: &str) -> TestResult {
    let services = service_identities(db)?;
    let mut tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let tables = tables.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    let mut checked = 0;
    for table in tables {
        // These tables are independent account authority, contact, or group-membership state.
        // Their outbox invalidations are exempt below by the same named sources or actor keys.
        if IDENTITY_TABLES.contains(&table.as_str()) || STRUCTURAL_TABLES.contains(&table.as_str())
        {
            continue;
        }
        let filter = inspection_filter(&table);
        let quoted = table.replace('"', "\"\"");
        let mut q = db.prepare(&format!("SELECT * FROM \"{quoted}\"{filter}"))?;
        let names = q.column_names().map(ToString::to_string).collect::<Vec<_>>();
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            let source_table = names
                .iter()
                .position(|name| name == "table_name")
                .and_then(|i| row.get::<_, String>(i).ok());
            let directory = names
                .iter()
                .position(|name| name == "state_kind")
                .and_then(|i| row.get::<_, String>(i).ok())
                .is_some_and(|key| key == format!("directory/message/{message}"));
            let retained_identity = names
                .iter()
                .position(|name| name == "state_kind")
                .and_then(|i| row.get::<_, String>(i).ok())
                .is_some_and(|key| key == format!("routed/generated-identity/{message}"));
            let notice = table == "runtime_outbox"
                && source_table.as_deref().is_some_and(|name| {
                    matches!(
                        name,
                        "direct_message_projection"
                            | "message_tombstone_projection"
                            | "group_message_tombstone_projection"
                            | "runtime_actor_state"
                    )
                });
            let service_author = service_author_exempt(row, &names, &services, message)?;
            for (column, name) in names.iter().enumerate() {
                let value = row.get_ref(column)?;
                let (ValueRef::Text(bytes) | ValueRef::Blob(bytes)) = value else { continue };
                let text = String::from_utf8_lossy(bytes);
                if retained_identity && name == "state_kind" {
                    continue;
                }
                if retained_identity && name == "state_json" {
                    check_tombstone_identity(&serde_json::from_slice(bytes)?, message)?;
                    checked += 1;
                    continue;
                }
                // The retained projection ID is explicitly part of the deletion contract.
                if name == "message_id" && text == message || directory && name == "state_kind" {
                    continue;
                }
                let rendered =
                    if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(bytes) {
                        if table == "runtime_journal" && name == "body_json" {
                            strip_generated_tombstone(&mut value, message)?;
                        }
                        strip_deleted_id(&mut value, message);
                        if notice {
                            strip_projection_notice(&mut value, message);
                        }

                        serde_json::to_string(&value)?
                    } else {
                        text.into_owned()
                    };
                for secret in forbidden {
                    if service_author.iter().any(|author| author == secret) {
                        continue;
                    }
                    assert!(
                        !rendered.contains(secret),
                        "residual in {table}.{name}: {secret}; row={:?}",
                        row_context(row, names.len())
                    );
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
    Ok(())
}
struct ServiceIdentity {
    message_id: String,
    exempt: Vec<String>,
}

fn service_identities(db: &Connection) -> Result<Vec<ServiceIdentity>, Box<dyn std::error::Error>> {
    let mut found = Vec::new();
    let mut stmt =
        db.prepare("SELECT message_id, sender_id, encrypted_body FROM direct_message_projection")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let message_id: String = row.get(0)?;
        let sender_id: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        let body = row.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default();
        let Ok((identity, content)) = crate::RamfluxClient::decode_generated_inner(&body) else {
            continue;
        };
        if !matches!(content.value, Some(crate::message::content::Value::Service(_))) {
            continue;
        }
        let Some(author) = identity.author else { continue };
        let mut exempt = vec![sender_id, author.account_anchor, author.device_id];
        exempt.retain(|value| !value.is_empty());
        exempt.sort();
        exempt.dedup();
        found.push(ServiceIdentity { message_id, exempt });
    }
    Ok(found)
}

/// Author principal, root, and device on a service-event row are group history, not a copy of
/// a different erased chat message. The erased id, its body, and its envelope stay forbidden.
fn service_author_exempt(
    row: &rusqlite::Row<'_>,
    names: &[String],
    services: &[ServiceIdentity],
    erased: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if services.is_empty() {
        return Ok(Vec::new());
    }
    let mut texts = Vec::new();
    for index in 0..names.len() {
        if let ValueRef::Text(bytes) | ValueRef::Blob(bytes) = row.get_ref(index)? {
            texts.push(String::from_utf8_lossy(bytes).into_owned());
        }
    }
    if texts.iter().any(|text| text.contains(erased)) {
        return Ok(Vec::new());
    }
    let mut exempt = Vec::new();
    for service in services {
        if texts.iter().any(|text| text.contains(&service.message_id)) {
            exempt.extend(service.exempt.iter().cloned());
        }
    }
    Ok(exempt)
}

fn strip_deleted_id(value: &mut serde_json::Value, message: &str) {
    match value {
        serde_json::Value::Object(fields) => {
            if fields.get("deleted").and_then(serde_json::Value::as_bool) == Some(true)
                && fields.get("message_id").and_then(serde_json::Value::as_str) == Some(message)
            {
                fields.remove("message_id");
            }
            for value in fields.values_mut() {
                strip_deleted_id(value, message);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                strip_deleted_id(value, message);
            }
        }
        _ => {}
    }
}

fn strip_projection_notice(value: &mut serde_json::Value, message: &str) {
    if let Some(fields) = value.as_object_mut() {
        if fields.get("message_id").and_then(serde_json::Value::as_str) == Some(message)
            && fields.get("sender_id").is_none_or(|sender| sender == "")
        {
            fields.remove("message_id");
        }
        if fields.get("state_kind").and_then(serde_json::Value::as_str)
            == Some(&format!("directory/message/{message}"))
        {
            fields.remove("state_kind");
        }
    }
}

fn row_context(row: &rusqlite::Row<'_>, columns: usize) -> Vec<String> {
    (0..columns)
        .map(|i| match row.get_ref(i) {
            Ok(ValueRef::Text(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
            Ok(ValueRef::Blob(bytes)) => format!("BLOB({} bytes)", bytes.len()),
            value => format!("{value:?}"),
        })
        .collect()
}

fn check_tombstone_identity(value: &serde_json::Value, message: &str) -> TestResult {
    assert!(value.as_object().ok_or("tombstone identity object")?.keys().all(|key| matches!(
        key.as_str(),
        "id" | "conversationId" | "author" | "deviceSequence" | "hlc" | "groupId" | "groupEpoch"
    )));
    assert!(
        value["author"]
            .as_object()
            .ok_or("tombstone author")?
            .keys()
            .all(|key| matches!(key.as_str(), "accountAnchor" | "deviceId" | "deviceEpoch"))
    );
    let identity: ramflux_protocol::message::EventIdentity = serde_json::from_value(value.clone())?;
    assert_eq!(ramflux_protocol::encode_base64url(identity.id), message);
    Ok(())
}
fn strip_generated_tombstone(value: &mut serde_json::Value, message: &str) -> TestResult {
    if value.get("update").is_none() {
        return Ok(());
    }
    let update: ramflux_protocol::message::MessageUpdate =
        serde_json::from_value(value["update"].clone())?;
    let journal_id = update
        .identity
        .as_ref()
        .map(|identity| ramflux_protocol::encode_base64url(&identity.id))
        .ok_or("journal identity")?;
    // A service-event journal is group history. Only the erased chat message must be a tombstone.
    if journal_id != message {
        return Ok(());
    }
    assert!(
        matches!(
            update.state,
            Some(ramflux_protocol::message::message_update::State::Tombstone(_))
        ),
        "erased generated journal must be a tombstone"
    );
    assert!(value["update"].as_object().ok_or("typed tombstone update")?.keys().all(
        |key| matches!(key.as_str(), "accountId" | "journalSequence" | "identity" | "tombstone")
    ));
    check_tombstone_identity(&value["update"]["identity"], message)?;
    let identity = update.identity.as_ref().ok_or("tombstone identity")?;
    let Some(ramflux_protocol::message::message_update::State::Tombstone(tombstone)) =
        &update.state
    else {
        return Err("typed tombstone state".into());
    };
    assert!(
        value["update"]["tombstone"]
            .as_object()
            .ok_or("tombstone object")?
            .keys()
            .all(|key| matches!(key.as_str(), "scope" | "targets" | "tombstoneId"))
    );
    let targets = value["update"]["tombstone"]["targets"].as_array().ok_or("qualified targets")?;
    for target in targets {
        assert!(
            target
                .as_object()
                .ok_or("qualified target object")?
                .keys()
                .all(|key| matches!(key.as_str(), "id" | "authorAnchor" | "conversationId"))
        );
    }
    assert_eq!(tombstone.targets.len(), 1, "local erasure retains one qualified target");
    let target = tombstone.targets.first().ok_or("tombstone target")?;
    assert_eq!(target.id, identity.id, "tombstone target matches its immutable identity");
    assert_eq!(target.conversation_id, identity.conversation_id);
    assert_eq!(
        target.author_anchor,
        identity.author.as_ref().ok_or("tombstone author")?.account_anchor
    );
    value["update"]["tombstone"]["targets"] = serde_json::Value::Null;
    value["update"]["identity"] = serde_json::Value::Null;
    assert_eq!(value["message_id"].as_str(), Some(message));
    value.as_object_mut().ok_or("typed tombstone envelope")?.remove("message_id");
    Ok(())
}

fn inspection_filter(table: &str) -> String {
    if matches!(table, "runtime_actor_state" | "backup_archived_actor_state") {
        format!(" WHERE NOT ({IDENTITY_ACTOR_FILTER})")
    } else if table == "runtime_outbox" {
        let actor_key =
            IDENTITY_ACTOR_FILTER.replace("state_kind", "json_extract(keys_json,'$.state_kind')");
        format!(
            " WHERE table_name NOT IN ({})
                  AND NOT (table_name='runtime_actor_state' AND (({actor_key}) OR EXISTS(
                   SELECT 1 FROM runtime_actor_state a WHERE a.rowid=runtime_outbox.row_id
                    AND ({IDENTITY_ACTOR_FILTER}))))
                  AND NOT (table_name='local_event_log' AND EXISTS(
                   SELECT 1 FROM local_event_log e WHERE e.rowid=runtime_outbox.row_id
                    AND ({IDENTITY_EVENT_FILTER})))",
            IDENTITY_TABLES.iter().map(|table| format!("'{table}'")).collect::<Vec<_>>().join(",")
        )
    } else if matches!(table, "local_event_log" | "backup_archived_local_event") {
        format!(" WHERE NOT ({IDENTITY_EVENT_FILTER})")
    } else if table == "runtime_journal" {
        " WHERE topic NOT IN ('safety.changed','account.state')".to_owned()
    } else {
        String::new()
    }
}
