// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed erasure drivers shared by live and private backup generations.
use rusqlite::Connection;

pub(super) fn install(db: &Connection) -> rusqlite::Result<()> {
    let mut body = String::from(BODY);
    for (table, kind) in [
        ("backup_archived_actor_state", "archived_actor"),
        ("backup_archived_local_event", "archived_event"),
    ] {
        if super::schema::exists(db, table)? {
            body.insert_str(0,&format!("DELETE FROM {table} WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='{kind}');"));
        }
    }
    db.execute_batch(&format!("DROP TRIGGER IF EXISTS footprint_erase_message; CREATE TRIGGER footprint_erase_message AFTER UPDATE OF deleted ON direct_message_projection WHEN NEW.deleted=1 BEGIN {body} END;"))?;
    Ok(())
}
const BODY: &str = r"
 UPDATE runtime_actor_state SET state_json=CAST(json_object('message_id',NEW.message_id,'deleted',json('true'),'created_at',NEW.created_at,'conversation_id',NEW.conversation_id,'is_own',json(CASE WHEN NEW.is_own=1 THEN 'true' ELSE 'false' END)) AS BLOB)
 WHERE state_kind='directory/message/'||NEW.message_id;
 DELETE FROM runtime_receipt_retention WHERE state_kind IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='actor');
 DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='actor') AND state_kind<>'directory/message/'||NEW.message_id;
 DELETE FROM event_causal_dependency WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind IN ('event_causal_dependency:event_id','event_causal_dependency:depends_on_event_id'));
 DELETE FROM projection_checkpoint WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='projection_checkpoint:last_event_id');
 DELETE FROM raw_envelope_log WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='raw_envelope_log:envelope_id');
 DELETE FROM outbox_queue WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='outbox_queue:envelope_id');
 DELETE FROM ack_state WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='ack_state:envelope_id');
 DELETE FROM nack_state WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='nack_state:envelope_id');
 UPDATE cursor_checkpoint SET last_envelope_id=NULL WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='cursor_checkpoint:last_envelope_id');
 UPDATE device_inbox_cursor SET last_envelope_id=NULL WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='device_inbox_cursor:last_envelope_id');
 DELETE FROM local_event_log WHERE event_id IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='event');
 UPDATE runtime_journal SET body_json=CAST(json_object('message',json_object('message_id',NEW.message_id,'deleted',json('true'),'created_at',NEW.created_at,'conversation_id',NEW.conversation_id,'is_own',json(CASE WHEN NEW.is_own=1 THEN 'true' ELSE 'false' END))) AS BLOB),source_key='privacy:'||seq,subject=NULL WHERE seq IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='journal');
 DELETE FROM runtime_inbox_policy WHERE envelope_key IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind IN ('retry','dead_letter','policy'));
 DELETE FROM runtime_unrouted WHERE envelope_id IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='unrouted');
 DELETE FROM runtime_inbox_retry WHERE envelope_key IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='retry');
 DELETE FROM runtime_inbox_dead_letter WHERE envelope_key IN (SELECT locator FROM message_footprint WHERE message_id=NEW.message_id AND kind='dead_letter');
 DELETE FROM runtime_message_content WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='runtime_message_content');
 DELETE FROM message_projection WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='message_projection');
 DELETE FROM receipt_projection WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='receipt_projection');
 DELETE FROM group_pending_undecrypted WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='group_pending_undecrypted');
 DELETE FROM contact_message_request WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='contact_message_request');
 DELETE FROM conversation_read_state WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='conversation_read_state');
 DELETE FROM conversation_delivery_state WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='conversation_delivery_state');
 DELETE FROM rejected_inbox_projection WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='rejected_inbox_projection');
 DELETE FROM conversation_unread_marker WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='conversation_unread_marker');
 UPDATE group_message_tombstone_projection SET actor_device_id='',reason='' WHERE rowid IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='group_message_tombstone_projection');
 DELETE FROM runtime_outbox WHERE sequence IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id=NEW.message_id AND kind='outbox');
 DELETE FROM message_copy_binding WHERE message_id=NEW.message_id;
 DELETE FROM message_footprint WHERE message_id=NEW.message_id;
";
