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
            for (column, name) in names.iter().enumerate() {
                let owned = {
                    let value = row.get_ref(column)?;
                    let (ValueRef::Text(bytes) | ValueRef::Blob(bytes)) = value else { continue };
                    bytes.to_vec()
                };
                let text = String::from_utf8_lossy(&owned);
                if retained_identity && name == "state_kind" {
                    continue;
                }
                if retained_identity && name == "state_json" {
                    check_tombstone_identity(&serde_json::from_slice(&owned)?, message)?;
                    checked += 1;
                    continue;
                }
                // The retained projection ID is explicitly part of the deletion contract.
                if name == "message_id" && text == message || directory && name == "state_kind" {
                    continue;
                }
                let rendered =
                    if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&owned) {
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
                let cell = ServiceCell {
                    table: &table,
                    column: name,
                    names: &names,
                    row,
                    bytes: &owned,
                    erased: message,
                };
                let rendered = designated_service_text(&cell, &rendered, &services)?;
                reject_residual(&table, name, &rendered, forbidden, row, names.len())?;
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
    Ok(())
}
struct ServiceIdentity {
    message_id: String,
}

struct ServiceCell<'a> {
    table: &'a str,
    column: &'a str,
    names: &'a [String],
    row: &'a rusqlite::Row<'a>,
    bytes: &'a [u8],
    erased: &'a str,
}

fn service_identities(db: &Connection) -> Result<Vec<ServiceIdentity>, Box<dyn std::error::Error>> {
    if !sqlite_table(db, "direct_message_projection")? {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    let mut stmt =
        db.prepare("SELECT message_id, sender_id, encrypted_body FROM direct_message_projection")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let message_id: String = row.get(0)?;
        let body = row.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default();
        let Ok((_, content)) = crate::RamfluxClient::decode_generated_inner(&body) else {
            continue;
        };
        if matches!(content.value, Some(crate::message::content::Value::Service(_))) {
            found.push(ServiceIdentity { message_id });
        }
    }
    Ok(found)
}

fn sqlite_table(db: &Connection, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get(0),
    )?)
}

/// Exempt only designated author fields on the exact service row.
///
/// `sender_id`, `author.account_anchor`, and `author.device_id` are group history. A copied
/// author in any other column or payload still fails. The erased id stays visible in the cell.
fn designated_service_text(
    cell: &ServiceCell<'_>,
    rendered: &str,
    services: &[ServiceIdentity],
) -> Result<String, Box<dyn std::error::Error>> {
    if services.is_empty() || rendered.contains(cell.erased) {
        return Ok(rendered.to_owned());
    }
    if let Some(text) = redact_service_column(cell, rendered, services)? {
        return Ok(text);
    }
    Ok(rendered.to_owned())
}

fn redact_service_column(
    cell: &ServiceCell<'_>,
    rendered: &str,
    services: &[ServiceIdentity],
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let message_id = column_text(cell.row, cell.names, "message_id")?;
    let exact = message_id.as_deref().is_some_and(|id| service_id(services, id));
    Ok(match (cell.table, cell.column) {
        ("direct_message_projection", "sender_id") if exact => Some(String::new()),
        ("direct_message_projection", "encrypted_body") | ("runtime_message_content", "body")
            if exact =>
        {
            message_id.as_deref().and_then(|id| redact_service_body(cell.bytes, id))
        }
        ("runtime_actor_state", "state_json") => {
            let kind = column_text(cell.row, cell.names, "state_kind")?;
            kind.as_deref().and_then(|kind| redact_identity_author(rendered, services, kind))
        }
        ("runtime_journal", "body_json") => redact_journal_author(rendered, services),
        ("runtime_outbox", "keys_json")
            if column_text(cell.row, cell.names, "table_name")?.as_deref()
                == Some("direct_message_projection") =>
        {
            redact_outbox_sender(rendered, services)
        }
        _ => None,
    })
}

fn reject_residual(
    table: &str,
    column: &str,
    rendered: &str,
    forbidden: &[String],
    row: &rusqlite::Row<'_>,
    width: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for secret in forbidden {
        if rendered.contains(secret) {
            return Err(format!(
                "residual in {table}.{column}: {secret}; row={:?}",
                row_context(row, width)
            )
            .into());
        }
    }
    Ok(())
}

fn service_id(services: &[ServiceIdentity], message_id: &str) -> bool {
    services.iter().any(|service| service.message_id == message_id)
}

fn column_text(
    row: &rusqlite::Row<'_>,
    names: &[String],
    column: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(index) = names.iter().position(|name| name == column) else {
        return Ok(None);
    };
    Ok(match row.get_ref(index)? {
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        _ => None,
    })
}

fn redact_service_body(bytes: &[u8], message_id: &str) -> Option<String> {
    let (mut identity, content) = crate::RamfluxClient::decode_generated_inner(bytes).ok()?;
    if ramflux_protocol::encode_base64url(&identity.id) != message_id {
        return None;
    }
    if !matches!(content.value, Some(crate::message::content::Value::Service(_))) {
        return None;
    }
    if let Some(author) = identity.author.as_mut() {
        author.account_anchor.clear();
        author.device_id.clear();
    }
    serde_json::to_string(&serde_json::json!({"identity": identity, "content": content})).ok()
}

fn redact_identity_author(
    rendered: &str,
    services: &[ServiceIdentity],
    kind: &str,
) -> Option<String> {
    let id = kind.strip_prefix("routed/generated-identity/")?;
    if !service_id(services, id) {
        return None;
    }
    clear_author_object(rendered, &["author"])
}

fn redact_journal_author(rendered: &str, services: &[ServiceIdentity]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(rendered).ok()?;
    let update: ramflux_protocol::message::MessageUpdate =
        serde_json::from_value(value.get("update")?.clone()).ok()?;
    let identity = update.identity.as_ref()?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let service = matches!(
        update.state,
        Some(ramflux_protocol::message::message_update::State::Content(ref content))
            if matches!(content.value, Some(crate::message::content::Value::Service(_)))
    );
    if !service || !service_id(services, &id) {
        return None;
    }
    clear_author_object(rendered, &["update", "identity", "author"])
}

fn redact_outbox_sender(rendered: &str, services: &[ServiceIdentity]) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(rendered).ok()?;
    let message_id = value.get("message_id")?.as_str()?.to_owned();
    if !service_id(services, &message_id) {
        return None;
    }
    value.as_object_mut()?.remove("sender_id");
    serde_json::to_string(&value).ok()
}

fn clear_author_object(rendered: &str, path: &[&str]) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(rendered).ok()?;
    let mut cursor = &mut value;
    for (index, key) in path.iter().enumerate() {
        if index + 1 == path.len() {
            let author = cursor.get_mut(*key)?.as_object_mut()?;
            author.remove("accountAnchor");
            author.remove("account_anchor");
            author.remove("deviceId");
            author.remove("device_id");
            return serde_json::to_string(&value).ok();
        }
        cursor = cursor.get_mut(*key)?;
    }
    None
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

#[cfg(test)]
mod exemption_tests {
    use super::assert_erased;

    struct Fixture {
        db: rusqlite::Connection,
        forbidden: Vec<String>,
        leak: Vec<u8>,
    }

    #[test]
    fn copied_author_outside_designated_fields_still_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = service_fixture()?;
        assert_erased(&fixture.db, &fixture.forbidden, "erased-chat-id")?;
        let column = service_fixture()?;
        column.db.execute(
            "UPDATE direct_message_projection SET metadata_json=?1",
            [br#"{"note":"erased-root"}"#.as_slice()],
        )?;
        assert!(
            assert_erased(&column.db, &column.forbidden, "erased-chat-id").is_err(),
            "a service row's unrelated column must not inherit the author exemption"
        );
        fixture.db.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES('routed/unrelated-leak',?1)",
            [&fixture.leak],
        )?;
        assert!(
            assert_erased(&fixture.db, &fixture.forbidden, "erased-chat-id").is_err(),
            "an unrelated payload that copies the service id and the author must fail"
        );
        Ok(())
    }

    fn service_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        use ramflux_protocol::message as g;
        let author = g::QualifiedDevice {
            account_anchor: "erased-root".into(),
            device_id: "erased-device".into(),
            device_epoch: 1,
        };
        let id = g::identity::derive(&author, "thread", 1)?;
        let identity = g::EventIdentity {
            id: id.to_vec(),
            conversation_id: "thread".into(),
            author: Some(author),
            device_sequence: 1,
            hlc: 1,
            group_id: None,
            group_epoch: None,
        };
        let content = g::Content {
            value: Some(g::content::Value::Service(g::Service {
                action: g::ServiceAction::ServiceNameChanged as i32,
                subjects: Vec::new(),
                text: Some("Renamed".into()),
                target: None,
                native_authority_proof: Vec::new(),
            })),
        };
        let body = crate::RamfluxClient::encode_generated_inner(identity.clone(), &content)?;
        let service_id = ramflux_protocol::encode_base64url(&identity.id);
        let db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE direct_message_projection(message_id TEXT, sender_id TEXT, encrypted_body BLOB, metadata_json BLOB);
             CREATE TABLE runtime_message_content(message_id TEXT, conversation_id TEXT, body BLOB);
             CREATE TABLE runtime_actor_state(state_kind TEXT, state_json BLOB);
             CREATE TABLE runtime_journal(topic TEXT, body_json BLOB);
             CREATE TABLE local_event_log(event_type TEXT);
             CREATE TABLE runtime_outbox(table_name TEXT, keys_json TEXT, row_id INTEGER);",
        )?;
        db.execute(
            "INSERT INTO direct_message_projection(message_id,sender_id,encrypted_body,metadata_json) VALUES(?1,'erased-root',?2,x'7b7d')",
            rusqlite::params![service_id, body],
        )?;
        db.execute(
            "INSERT INTO runtime_message_content(message_id,conversation_id,body) VALUES(?1,'thread',?2)",
            rusqlite::params![service_id, body],
        )?;
        db.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            rusqlite::params![
                format!("routed/generated-identity/{service_id}"),
                serde_json::to_vec(&identity)?
            ],
        )?;
        let update = g::MessageUpdate {
            account_id: "account".into(),
            journal_sequence: 1,
            identity: Some(identity),
            state: Some(g::message_update::State::Content(content)),
        };
        let journal =
            serde_json::to_vec(&serde_json::json!({"message_id": service_id, "update": update}))?;
        db.execute(
            "INSERT INTO runtime_journal(topic,body_json) VALUES('message.updated',?1)",
            [journal],
        )?;
        let keys = serde_json::json!({
            "conversation_id": "thread",
            "message_id": service_id,
            "sender_id": "erased-root"
        });
        db.execute(
            "INSERT INTO runtime_outbox(table_name,keys_json) VALUES('direct_message_projection',?1)",
            [keys.to_string()],
        )?;
        Ok(Fixture {
            db,
            forbidden: vec![
                "erased-root".into(),
                "erased-device".into(),
                "erased-chat-id".into(),
                "envelope-id".into(),
            ],
            leak: serde_json::to_vec(&serde_json::json!({
                "service_ref": service_id,
                "leaked_author": "erased-root"
            }))?,
        })
    }
}
