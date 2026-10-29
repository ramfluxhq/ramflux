// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transaction-local registration of message copies and aliases.
use rusqlite::Connection;

pub(super) fn install(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    install_copy_triggers(db)?;
    super::erasure::install(db)?;
    Ok(())
}
// Explicit UPSERT clauses survive conflict handling inherited from an enclosing actor UPSERT.
const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS message_footprint(
 message_id TEXT NOT NULL,kind TEXT NOT NULL,locator TEXT NOT NULL,
 PRIMARY KEY(message_id,kind,locator));
CREATE INDEX IF NOT EXISTS message_footprint_message ON message_footprint(message_id);
CREATE INDEX IF NOT EXISTS message_footprint_locator ON message_footprint(kind,locator,message_id);
CREATE TABLE IF NOT EXISTS message_copy_binding(copy_id TEXT NOT NULL,message_id TEXT NOT NULL,
 PRIMARY KEY(copy_id,message_id));
CREATE INDEX IF NOT EXISTS message_copy_binding_message ON message_copy_binding(message_id);
CREATE TRIGGER IF NOT EXISTS footprint_binding AFTER INSERT ON message_copy_binding BEGIN
 INSERT INTO message_footprint SELECT NEW.message_id,kind,locator FROM message_footprint WHERE message_id='copy:'||NEW.copy_id ON CONFLICT DO NOTHING;
 DELETE FROM message_footprint WHERE message_id='copy:'||NEW.copy_id;
 INSERT INTO message_footprint SELECT NEW.message_id,kind,locator FROM message_footprint WHERE message_id IN (SELECT 'copy:event:'||locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='event') ON CONFLICT DO NOTHING;
 DELETE FROM message_footprint WHERE message_id IN (SELECT 'copy:event:'||locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='event');
 INSERT INTO message_copy_binding SELECT 'event:'||locator,NEW.message_id FROM message_footprint WHERE message_id=NEW.message_id AND kind='event' ON CONFLICT DO NOTHING;
END;
";

pub(super) fn exists(db: &Connection, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )
}

fn install_copy_triggers(db: &Connection) -> rusqlite::Result<()> {
    for (table, kind, key, column, guard, extra) in [
        ("runtime_actor_state", "actor", "NEW.state_kind", "state_json", ACTOR_GUARD, ACTOR_LINKS),
        (
            "backup_archived_actor_state",
            "archived_actor",
            "CAST(NEW.rowid AS TEXT)",
            "state_json",
            ACTOR_GUARD,
            ACTOR_LINKS,
        ),
        ("runtime_journal", "journal", "CAST(NEW.seq AS TEXT)", "body_json", "1", ""),
        ("local_event_log", "event", "NEW.event_id", "event_body", "1", ""),
        (
            "backup_archived_local_event",
            "archived_event",
            "CAST(NEW.rowid AS TEXT)",
            "event_body",
            "1",
            "",
        ),
        ("runtime_unrouted", "unrouted", "NEW.envelope_id", "entry_json", "1", ""),
        ("runtime_inbox_retry", "retry", "NEW.envelope_key", "entry_json", "1", ""),
        ("runtime_inbox_dead_letter", "dead_letter", "NEW.envelope_key", "entry_json", "1", ""),
        (
            "runtime_outbox",
            "outbox",
            "CAST(NEW.sequence AS TEXT)",
            "keys_json",
            "NEW.table_name NOT IN ('message_tombstone_projection','group_message_tombstone_projection') AND NOT (NEW.table_name='direct_message_projection' AND COALESCE(json_extract(NEW.keys_json,'$.sender_id'),'')='')",
            OUTBOX_LINKS,
        ),
    ] {
        json_copy(db, CopyStore { table, kind, locator: key, column, guard, extra })?;
    }
    for (table, column) in [
        ("runtime_message_content", "message_id"),
        ("rejected_inbox_projection", "message_id"),
        ("conversation_unread_marker", "message_id"),
        ("group_message_tombstone_projection", "message_id"),
        ("message_projection", "message_id"),
        ("receipt_projection", "message_id"),
        ("group_pending_undecrypted", "message_id"),
        ("contact_message_request", "message_id"),
        ("conversation_read_state", "read_through_message_id"),
        ("conversation_delivery_state", "delivered_through_message_id"),
    ] {
        column_copy(db, table, column)?;
    }
    for (table, column, namespace) in [
        ("raw_envelope_log", "envelope_id", "envelope"),
        ("outbox_queue", "envelope_id", "envelope"),
        ("ack_state", "envelope_id", "envelope"),
        ("nack_state", "envelope_id", "envelope"),
        ("cursor_checkpoint", "last_envelope_id", "envelope"),
        ("device_inbox_cursor", "last_envelope_id", "envelope"),
        ("event_causal_dependency", "event_id", "event"),
        ("event_causal_dependency", "depends_on_event_id", "event"),
        ("projection_checkpoint", "last_event_id", "event"),
    ] {
        alias_copy(db, table, column, namespace)?;
    }
    Ok(())
}
const ACTOR_GUARD: &str = "NEW.state_kind NOT GLOB 'routed/seen/*' AND (NEW.state_kind GLOB 'routed/*' OR NEW.state_kind GLOB 'directory/message/*' OR NEW.state_kind GLOB 'directory/object/*' OR NEW.state_kind GLOB 'message/origin/*' OR NEW.state_kind GLOB 'delivery-receipt/*' OR NEW.state_kind GLOB 'attachment/*' OR NEW.state_kind GLOB 'sync/attachment/*' OR NEW.state_kind GLOB 'surface/origin/*' OR NEW.state_kind GLOB 'surface/message/*' OR NEW.state_kind GLOB 'surface/pending/*' OR NEW.state_kind GLOB 'surface/history/*' OR NEW.state_kind GLOB 'directory/surface_error/*' OR NEW.state_kind GLOB 'task/message/*' OR NEW.state_kind GLOB 'group-message/alias/*' OR NEW.state_kind GLOB 'own-copy/*' OR NEW.state_kind GLOB 'own-device/*' OR NEW.state_kind GLOB 'inbox/*' OR NEW.state_kind GLOB 'backup/staging/*')";
const ACTOR_LINKS: &str = r"
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:object:'||substr(substr(NEW.state_kind,18),1,instr(substr(NEW.state_kind,18),'/')-1)),'{kind}',{locator} FROM (SELECT 1) LEFT JOIN message_copy_binding b ON b.copy_id='object:'||substr(substr(NEW.state_kind,18),1,instr(substr(NEW.state_kind,18),'/')-1) WHERE NEW.state_kind GLOB 'attachment/chunk/*/*' ON CONFLICT DO NOTHING;

 INSERT INTO message_footprint SELECT message_id,'{kind}',{locator} FROM message_copy_binding WHERE copy_id='actor:'||NEW.state_kind ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT substr(NEW.state_kind,21),'{kind}',{locator} WHERE NEW.state_kind GLOB 'group-message/alias/*' ON CONFLICT DO NOTHING;
 INSERT INTO message_copy_binding SELECT 'actor:delivery-receipt/status/'||json_extract(CAST(NEW.state_json AS TEXT),'$.status_id'),json_extract(CAST(NEW.state_json AS TEXT),'$.message') WHERE NEW.state_kind GLOB 'delivery-receipt/pending/*' AND json_type(CAST(NEW.state_json AS TEXT),'$.status_id')='text' AND json_type(CAST(NEW.state_json AS TEXT),'$.message')='text' ON CONFLICT DO NOTHING;

 INSERT INTO message_copy_binding SELECT 'object:'||substr(NEW.state_kind,18),json_extract(CAST(NEW.state_json AS TEXT),'$.message_id') WHERE NEW.state_kind GLOB 'directory/object/*' AND json_type(CAST(NEW.state_json AS TEXT),'$.message_id')='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_copy_binding SELECT 'payload:'||json_extract(CAST(NEW.state_json AS TEXT),'$.entry.envelope.payload_hash'),json_extract(CAST(NEW.state_json AS TEXT),'$.routing.message_id') WHERE NEW.state_kind GLOB 'routed/committed/*' AND json_type(CAST(NEW.state_json AS TEXT),'$.routing.message_id')='text' AND json_type(CAST(NEW.state_json AS TEXT),'$.entry.envelope.payload_hash')='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_copy_binding SELECT 'envelope:'||json_extract(CAST(NEW.state_json AS TEXT),'$.entry.envelope.envelope_id'),json_extract(CAST(NEW.state_json AS TEXT),'$.routing.message_id') WHERE NEW.state_kind GLOB 'routed/committed/*' AND json_type(CAST(NEW.state_json AS TEXT),'$.routing.message_id')='text' AND json_type(CAST(NEW.state_json AS TEXT),'$.entry.envelope.envelope_id')='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_copy_binding SELECT 'group:'||json_extract(CAST(NEW.state_json AS TEXT),'$.group_id')||':'||json_extract(CAST(NEW.state_json AS TEXT),'$.group_message_id'),json_extract(CAST(NEW.state_json AS TEXT),'$.message_id') WHERE NEW.state_kind GLOB 'routed/message-metadata/*' AND json_type(CAST(NEW.state_json AS TEXT),'$.group_message_id')='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT t.value,'{kind}',{locator} FROM json_tree(CAST(NEW.state_json AS TEXT)) t WHERE t.type='text' AND t.key='message' AND NEW.state_kind GLOB 'delivery-receipt/*' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT json_extract(CAST(NEW.state_json AS TEXT),'$.intent.id'),'{kind}',{locator} WHERE NEW.state_kind GLOB 'own-device/send/*' AND json_type(CAST(NEW.state_json AS TEXT),'$.intent.id')='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT CAST(json_extract(CAST(NEW.state_json AS TEXT),'$') AS TEXT),'{kind}',{locator} WHERE (NEW.state_kind GLOB 'routed/projection/*' OR NEW.state_kind GLOB 'directory/message/*') AND json_type(CAST(NEW.state_json AS TEXT),'$')='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT substr(NEW.state_kind,22),'{kind}',{locator} WHERE NEW.state_kind GLOB 'routed/message-owner/*' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT substr(NEW.state_kind,25),'{kind}',{locator} WHERE NEW.state_kind GLOB 'routed/message-metadata/*' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:object:'||json_extract(CAST(NEW.state_json AS TEXT),'$')),'{kind}',{locator} FROM (SELECT 1) LEFT JOIN message_copy_binding b ON b.copy_id='object:'||json_extract(CAST(NEW.state_json AS TEXT),'$') WHERE json_type(CAST(NEW.state_json AS TEXT),'$')='text' AND (NEW.state_kind GLOB 'attachment/reference-by-sender/*' OR NEW.state_kind GLOB 'attachment/reference-by-slot/*') ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:object:'||substr(NEW.state_kind,22)),'{kind}',{locator} FROM (SELECT 1) LEFT JOIN message_copy_binding b ON b.copy_id='object:'||substr(NEW.state_kind,22) WHERE NEW.state_kind GLOB 'attachment/reference/*' ON CONFLICT DO NOTHING;
";
const OUTBOX_LINKS: &str = r"
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:envelope:'||json_extract(NEW.keys_json,'$.envelope_id')),'{kind}',{locator} FROM (SELECT 1) LEFT JOIN message_copy_binding b ON b.copy_id='envelope:'||json_extract(NEW.keys_json,'$.envelope_id') WHERE NEW.table_name IN ('raw_envelope_log','outbox_queue','ack_state','nack_state') AND json_type(NEW.keys_json,'$.envelope_id')='text' ON CONFLICT DO NOTHING;

 INSERT INTO message_footprint SELECT message_id,'{kind}',{locator} FROM message_footprint WHERE kind='actor' AND locator=json_extract(NEW.keys_json,'$.state_kind') ON CONFLICT DO NOTHING;
";

#[derive(Clone, Copy)]
struct CopyStore<'a> {
    table: &'a str,
    kind: &'a str,
    locator: &'a str,
    column: &'a str,
    guard: &'a str,
    extra: &'a str,
}
fn json_copy(db: &Connection, store: CopyStore<'_>) -> rusqlite::Result<()> {
    let CopyStore { table, kind, locator, column, guard, extra } = store;
    if !exists(db, table)? {
        return Ok(());
    }
    if matches!(
        table,
        "runtime_journal"
            | "runtime_unrouted"
            | "runtime_inbox_retry"
            | "runtime_inbox_dead_letter"
            | "local_event_log"
            | "backup_archived_actor_state"
            | "backup_archived_local_event"
    ) {
        let old_locator = locator.replace("NEW.", "OLD.");
        db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS footprint_{table}_removed AFTER DELETE ON {table} BEGIN DELETE FROM message_footprint WHERE kind='{kind}' AND locator={old_locator}; END;"))?;
    }
    let extra = extra.replace("{kind}", kind).replace("{locator}", locator);
    for operation in ["INSERT", "UPDATE"] {
        // BEFORE registration makes ownership available to every AFTER invalidation trigger,
        // regardless of installation/reopen order. Erasure itself waits until the row exists.
        let phase = if table == "runtime_actor_state" { "BEFORE" } else { "AFTER" };
        let insert_guard = if table == "runtime_actor_state" && operation == "INSERT" {
            "AND NOT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=NEW.state_kind)"
        } else {
            ""
        };
        let event_link = if table == "local_event_log" {
            "INSERT INTO message_copy_binding SELECT 'event:'||NEW.event_id,message_id FROM message_footprint WHERE kind='event' AND locator=NEW.event_id AND message_id NOT GLOB 'copy:*' ON CONFLICT DO NOTHING;"
        } else {
            ""
        };
        let erase = if table == "runtime_actor_state" {
            String::new()
        } else {
            format!(
                "UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id IN (SELECT message_id FROM message_footprint WHERE kind='{kind}' AND locator={locator});"
            )
        };
        if table == "runtime_actor_state" {
            db.execute_batch(&format!("DROP TRIGGER IF EXISTS footprint_{table}_{operation}; CREATE TRIGGER IF NOT EXISTS footprint_actor_fence_{operation} AFTER {operation} ON {table} BEGIN UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id IN (SELECT message_id FROM message_footprint WHERE kind='actor' AND locator=NEW.state_kind); END;"))?;
        }
        let reset = if operation == "UPDATE" {
            format!("DELETE FROM message_footprint WHERE kind='{kind}' AND locator={locator};")
        } else {
            String::new()
        };
        db.execute_batch(&format!(r"
CREATE TRIGGER IF NOT EXISTS footprint_{table}_{operation} {phase} {operation} ON {table}
WHEN json_valid(CAST(NEW.{column} AS TEXT)) AND ({guard}) {insert_guard}
 AND COALESCE(json_extract(CAST(NEW.{column} AS TEXT),'$.deleted'),0)!=1
 AND COALESCE(json_extract(CAST(NEW.{column} AS TEXT),'$.message.deleted'),0)!=1 BEGIN
 {reset}
 {extra}
 INSERT INTO message_footprint SELECT t.value,'{kind}',{locator} FROM json_tree(CAST(NEW.{column} AS TEXT)) t WHERE t.type='text' AND t.key IN ('message_id','own_copy_message_id','target_message_id') ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT t.value,'{kind}',{locator} FROM json_tree(CAST(NEW.{column} AS TEXT)) t WHERE t.type='text' AND t.key='id' AND t.path='$.message' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:payload:'||t.value),'{kind}',{locator} FROM json_tree(CAST(NEW.{column} AS TEXT)) t LEFT JOIN message_copy_binding b ON b.copy_id='payload:'||t.value WHERE t.key='payload_hash' AND t.type='text' ON CONFLICT DO NOTHING;
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:object:'||t.value),'{kind}',{locator} FROM json_tree(CAST(NEW.{column} AS TEXT)) t LEFT JOIN message_copy_binding b ON b.copy_id='object:'||t.value WHERE t.type='text' AND t.key='object_id' ON CONFLICT DO NOTHING;
 {event_link}
 {erase}
END;
"))?;
    }
    Ok(())
}
fn column_copy(db: &Connection, table: &str, column: &str) -> rusqlite::Result<()> {
    if !exists(db, table)? {
        return Ok(());
    }
    for operation in ["INSERT", "UPDATE"] {
        db.execute_batch(&format!(
            r"
CREATE TRIGGER IF NOT EXISTS footprint_{table}_{operation} AFTER {operation} ON {table}
WHEN NEW.{column} IS NOT NULL BEGIN
 DELETE FROM message_footprint WHERE kind='{table}' AND locator=CAST(NEW.rowid AS TEXT);
 INSERT INTO message_footprint VALUES(NEW.{column},'{table}',CAST(NEW.rowid AS TEXT)) ON CONFLICT DO NOTHING;
 UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id=NEW.{column};
END;
"
        ))?;
    }
    Ok(())
}

fn alias_copy(db: &Connection, table: &str, column: &str, namespace: &str) -> rusqlite::Result<()> {
    let kind = format!("{table}:{column}");
    for operation in ["INSERT", "UPDATE"] {
        db.execute_batch(&format!(r"
CREATE TRIGGER IF NOT EXISTS footprint_{table}_{column}_{operation} AFTER {operation} ON {table} BEGIN
 DELETE FROM message_footprint WHERE kind='{kind}' AND locator=CAST(NEW.rowid AS TEXT);
 INSERT INTO message_footprint SELECT COALESCE(b.message_id,'copy:{namespace}:'||NEW.{column}),'{kind}',CAST(NEW.rowid AS TEXT) FROM (SELECT 1) LEFT JOIN message_copy_binding b ON b.copy_id='{namespace}:'||NEW.{column} WHERE NEW.{column} IS NOT NULL AND NEW.{column}<>'' ON CONFLICT DO NOTHING;
 UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id IN (SELECT message_id FROM message_footprint WHERE kind='{kind}' AND locator=CAST(NEW.rowid AS TEXT));
END;
"))?;
    }
    Ok(())
}
