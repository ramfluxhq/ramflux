// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SQL ownership changes share the message deletion transaction, including backup generations.
use rusqlite::Connection;
use std::fmt::Write as _;

pub(crate) fn install(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    // Projection retirement probes selector keys after object_index deletion;
    // row_id can no longer resolve them, so index the retained outbox key.
    db.execute_batch("CREATE INDEX IF NOT EXISTS runtime_outbox_object_selector ON runtime_outbox(CAST(json_extract(keys_json,'$.object_id') AS TEXT)) WHERE table_name='object_index';")?;
    db.execute_batch("CREATE INDEX IF NOT EXISTS object_key_slot_wire ON object_key_slot(object_id); CREATE INDEX IF NOT EXISTS object_transfer_wire ON object_transfer_state(object_id); CREATE INDEX IF NOT EXISTS object_tombstone_target ON object_tombstone(target_kind,target_id);")
}

pub(crate) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS account_erasure_generation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL);
INSERT INTO account_erasure_generation SELECT 1,0 WHERE NOT EXISTS(SELECT 1 FROM account_erasure_generation);
CREATE TABLE IF NOT EXISTS object_retention_upgrade(singleton INTEGER PRIMARY KEY CHECK(singleton=1),format_version INTEGER NOT NULL,phase INTEGER NOT NULL,cursor INTEGER NOT NULL,rows_scanned INTEGER NOT NULL,decoded_bytes INTEGER NOT NULL,unsafe_references INTEGER NOT NULL);
INSERT INTO object_retention_upgrade SELECT 1,1,0,0,0,0,0 WHERE NOT EXISTS(SELECT 1 FROM object_retention_upgrade WHERE singleton=1);
CREATE TABLE IF NOT EXISTS object_legacy_reference_context(selector TEXT PRIMARY KEY,message_id TEXT NOT NULL,manifest_hash TEXT NOT NULL,metadata_json BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS object_legacy_context_message ON object_legacy_reference_context(message_id);
CREATE TABLE IF NOT EXISTS object_retention_payload(
 commitment TEXT PRIMARY KEY,wire_id TEXT NOT NULL,manifest_hash TEXT NOT NULL,
 wire_lookup TEXT NOT NULL,retention_class TEXT NOT NULL,
 hold_expires_at INTEGER,owner_count INTEGER NOT NULL DEFAULT 0 CHECK(owner_count>=0),UNIQUE(wire_id,manifest_hash));
CREATE INDEX IF NOT EXISTS object_retention_expiry ON object_retention_payload(retention_class,owner_count,hold_expires_at,commitment);
CREATE INDEX IF NOT EXISTS object_retention_wire ON object_retention_payload(wire_id);
CREATE TABLE IF NOT EXISTS object_retention_reference(
 reference_hash TEXT PRIMARY KEY,commitment TEXT NOT NULL,selector TEXT NOT NULL,
 selector_lookup TEXT NOT NULL,reference_json BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS object_reference_payload ON object_retention_reference(commitment);
CREATE INDEX IF NOT EXISTS object_reference_selector ON object_retention_reference(selector);
CREATE TABLE IF NOT EXISTS object_message_reference(
 message_id TEXT NOT NULL,reference_hash TEXT NOT NULL,metadata_json BLOB NOT NULL,
 PRIMARY KEY(message_id,reference_hash));
CREATE INDEX IF NOT EXISTS object_reference_message ON object_message_reference(reference_hash,message_id);
CREATE TRIGGER IF NOT EXISTS object_message_owner_added AFTER INSERT ON object_message_reference BEGIN UPDATE object_retention_payload SET owner_count=owner_count+1 WHERE commitment=(SELECT commitment FROM object_retention_reference WHERE reference_hash=NEW.reference_hash); END;
CREATE TRIGGER IF NOT EXISTS object_message_owner_removed AFTER DELETE ON object_message_reference BEGIN UPDATE object_retention_payload SET owner_count=owner_count-1 WHERE commitment=(SELECT commitment FROM object_retention_reference WHERE reference_hash=OLD.reference_hash); END;
CREATE TABLE IF NOT EXISTS object_transport_actor(commitment TEXT NOT NULL,state_kind TEXT NOT NULL,PRIMARY KEY(commitment,state_kind));
CREATE TABLE IF NOT EXISTS object_payload_dependency(parent_commitment TEXT NOT NULL,child_commitment TEXT NOT NULL,PRIMARY KEY(parent_commitment,child_commitment));
CREATE INDEX IF NOT EXISTS object_dependency_child ON object_payload_dependency(child_commitment,parent_commitment);
CREATE TABLE IF NOT EXISTS object_payload_actor(commitment TEXT NOT NULL,state_kind TEXT NOT NULL,PRIMARY KEY(commitment,state_kind));
CREATE INDEX IF NOT EXISTS object_payload_actor_kind ON object_payload_actor(state_kind);
CREATE TABLE IF NOT EXISTS object_reference_actor(reference_hash TEXT NOT NULL,state_kind TEXT NOT NULL,PRIMARY KEY(reference_hash,state_kind));
CREATE INDEX IF NOT EXISTS object_reference_actor_kind ON object_reference_actor(state_kind);
CREATE TABLE IF NOT EXISTS object_runtime_response(commitment TEXT NOT NULL,operation_id TEXT NOT NULL,PRIMARY KEY(commitment,operation_id));
CREATE TABLE IF NOT EXISTS object_identity_replacement(commitment TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS object_erasure_fence(commitment TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS object_erasure_lookup(lookup TEXT PRIMARY KEY,commitment TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS object_erasure_work(commitment TEXT PRIMARY KEY,wire_id TEXT NOT NULL,manifest_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS object_erasure_work_wire ON object_erasure_work(wire_id,manifest_hash);
CREATE TABLE IF NOT EXISTS object_projection_erasure_work(selector TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS object_reference_erasure_work(reference_hash TEXT PRIMARY KEY,selector TEXT NOT NULL,selector_lookup TEXT NOT NULL,commitment TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS object_fence_no_update BEFORE UPDATE ON object_erasure_fence BEGIN SELECT RAISE(ABORT,'object erasure fences are append-only'); END;
CREATE TRIGGER IF NOT EXISTS object_fence_no_delete BEFORE DELETE ON object_erasure_fence BEGIN SELECT RAISE(ABORT,'object erasure fences are append-only'); END;
";

pub(crate) fn erasure_body(db: &Connection) -> rusqlite::Result<String> {
    let mut body = String::from(ERASE);
    body.push_str(PAYLOAD_ERASE);
    body.push_str(super::selector_erasure::RETIRE);
    body.push_str(super::selector_erasure::PROJECT);
    body.push_str(&payload_cleanup(db)?);
    body.push_str(super::selector_erasure::DRAIN);
    body.push_str(
        "DELETE FROM object_reference_erasure_work; DELETE FROM object_projection_erasure_work;",
    );
    Ok(body)
}

pub(crate) fn payload_erasure_body(db: &Connection) -> rusqlite::Result<String> {
    let mut body = String::from(
        "UPDATE account_erasure_generation SET generation=generation+1 WHERE singleton=1 AND EXISTS(SELECT 1 FROM object_erasure_work w JOIN object_retention_payload p USING(commitment));",
    );
    body.push_str(PAYLOAD_ERASE);
    body.push_str(super::selector_erasure::RETIRE);
    body.push_str(super::selector_erasure::PROJECT);
    body.push_str(&payload_cleanup(db)?);
    body.push_str(super::selector_erasure::DRAIN);
    body.push_str(
        "DELETE FROM object_reference_erasure_work; DELETE FROM object_projection_erasure_work;",
    );
    Ok(body)
}

pub(super) fn payload_cleanup(db: &Connection) -> rusqlite::Result<String> {
    let mut body = String::new();
    let wires = "SELECT w.wire_id FROM object_erasure_work w WHERE EXISTS(SELECT 1 FROM object_index o WHERE o.object_id=w.wire_id AND CAST(o.manifest_hash AS TEXT)=w.manifest_hash) OR NOT EXISTS(SELECT 1 FROM object_retention_payload p WHERE p.wire_id=w.wire_id AND p.commitment NOT IN (SELECT commitment FROM object_erasure_work))";
    for table in [
        "object_key_slot",
        "object_chunk",
        "object_manifest",
        "object_transfer_state",
        "object_operation",
        "object_share_grant_projection",
    ] {
        if super::super::message_footprint::table_exists(db, table)? {
            let exact=match table {
                "object_transfer_state"|"object_operation"=>format!("EXISTS(SELECT 1 FROM object_erasure_work w WHERE w.wire_id={table}.object_id AND w.manifest_hash=CAST({table}.manifest_hash AS TEXT))"),
                "object_manifest"=>"EXISTS(SELECT 1 FROM object_erasure_work w WHERE w.wire_id=object_manifest.object_id AND (w.manifest_hash=CAST(object_manifest.manifest_hash AS TEXT) OR w.manifest_hash=CAST(object_manifest.chunk_manifest_hash AS TEXT)))".into(),
                "object_key_slot"|"object_chunk"=>format!("EXISTS(SELECT 1 FROM object_manifest m JOIN object_erasure_work w ON w.wire_id=m.object_id WHERE m.object_id={table}.object_id AND (w.manifest_hash=CAST(m.manifest_hash AS TEXT) OR w.manifest_hash=CAST(m.chunk_manifest_hash AS TEXT)))"),
                _=>"0".into(),
            };
            write!(&mut body, "DELETE FROM {table} WHERE object_id IN (SELECT wire_id FROM object_erasure_work) AND (object_id IN ({wires}) OR {exact});")
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
        }
    }
    write!(
        &mut body,
        "DELETE FROM object_tombstone WHERE target_kind='object' AND target_id IN ({wires});"
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    body.push_str("DELETE FROM object_index WHERE object_id IN (SELECT wire_id FROM object_erasure_work) AND EXISTS(SELECT 1 FROM object_erasure_work w WHERE w.wire_id=object_index.object_id AND w.manifest_hash=CAST(object_index.manifest_hash AS TEXT)); DELETE FROM object_retention_payload WHERE commitment IN (SELECT commitment FROM object_erasure_work); DELETE FROM object_erasure_work;");
    Ok(body)
}

const ERASE: &str = r"
 DELETE FROM object_reference_erasure_work;
 DELETE FROM object_projection_erasure_work;
 DELETE FROM object_erasure_work;
 INSERT INTO object_reference_erasure_work
 SELECT DISTINCT r.reference_hash,r.selector,r.selector_lookup,r.commitment
 FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash)
 WHERE m.message_id=NEW.message_id;
 INSERT INTO object_projection_erasure_work SELECT DISTINCT selector FROM object_reference_erasure_work;
 DELETE FROM object_message_reference WHERE message_id=NEW.message_id;
 UPDATE account_erasure_generation SET generation=generation+1 WHERE singleton=1 AND changes()>0;
 DELETE FROM object_legacy_reference_context WHERE message_id=NEW.message_id;
 DELETE FROM object_reference_erasure_work WHERE EXISTS(SELECT 1 FROM object_message_reference m WHERE m.reference_hash=object_reference_erasure_work.reference_hash);
 DELETE FROM object_retention_reference WHERE reference_hash IN (SELECT reference_hash FROM object_reference_erasure_work);
 INSERT INTO object_erasure_work SELECT p.commitment,p.wire_id,p.manifest_hash
 FROM object_retention_payload p WHERE p.commitment IN (SELECT commitment FROM object_reference_erasure_work)
 AND (p.retention_class='transport' OR (p.retention_class='imported' AND NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.commitment=p.commitment)));

";

const PAYLOAD_ERASE: &str = r#"
 INSERT INTO object_erasure_work WITH RECURSIVE retired(commitment) AS (SELECT commitment FROM object_erasure_work UNION SELECT d.parent_commitment FROM object_payload_dependency d JOIN retired r ON r.commitment=d.child_commitment) SELECT p.commitment,p.wire_id,p.manifest_hash FROM object_retention_payload p JOIN retired r USING(commitment) WHERE p.retention_class='transport' ON CONFLICT DO NOTHING;
 INSERT INTO object_reference_erasure_work SELECT reference_hash,selector,selector_lookup,commitment FROM object_retention_reference WHERE commitment IN (SELECT commitment FROM object_erasure_work) ON CONFLICT DO NOTHING;
 INSERT INTO object_projection_erasure_work SELECT selector FROM object_reference_erasure_work WHERE 1 ON CONFLICT DO NOTHING;
 DELETE FROM object_message_reference WHERE reference_hash IN (SELECT reference_hash FROM object_retention_reference WHERE commitment IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM object_retention_reference WHERE commitment IN (SELECT commitment FROM object_erasure_work);
 DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM object_transport_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM runtime_outbox WHERE actor_state_kind IN (SELECT state_kind FROM object_transport_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM object_transport_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work);
 DELETE FROM object_payload_dependency WHERE parent_commitment IN (SELECT commitment FROM object_erasure_work) OR child_commitment IN (SELECT commitment FROM object_erasure_work);
 UPDATE runtime_operation SET response_json='{"object_erased":true}' WHERE operation_id IN (SELECT operation_id FROM object_runtime_response WHERE commitment IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM object_runtime_response WHERE commitment IN (SELECT commitment FROM object_erasure_work);
 DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM object_payload_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work)) AND NOT EXISTS(SELECT 1 FROM object_payload_actor a WHERE a.state_kind=runtime_actor_state.state_kind AND a.commitment NOT IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM runtime_outbox WHERE actor_state_kind IN (SELECT state_kind FROM object_payload_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM message_footprint WHERE kind='actor' AND locator IN (SELECT state_kind FROM object_payload_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work));
 DELETE FROM object_payload_actor WHERE commitment IN (SELECT commitment FROM object_erasure_work);
 DELETE FROM message_copy_binding WHERE copy_id IN (SELECT 'object:'||wire_id FROM object_erasure_work);
 DELETE FROM message_footprint WHERE message_id IN (SELECT 'copy:object:'||wire_id FROM object_erasure_work);
 INSERT INTO object_erasure_fence SELECT commitment FROM object_erasure_work WHERE 1 ON CONFLICT DO NOTHING;
 INSERT INTO object_erasure_lookup SELECT wire_lookup,commitment FROM object_retention_payload WHERE commitment IN (SELECT commitment FROM object_erasure_work) ON CONFLICT DO NOTHING;
 INSERT INTO runtime_privacy_maintenance SELECT 1,1 WHERE EXISTS(SELECT 1 FROM object_erasure_work) ON CONFLICT(singleton) DO UPDATE SET erasure_pending=1;
"#;
