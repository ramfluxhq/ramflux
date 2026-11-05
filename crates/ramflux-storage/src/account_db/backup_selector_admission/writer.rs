// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Import the classified graph without transiently creating unowned references.
use crate::StorageError;
use rusqlite::Connection;

pub(in crate::account_db) fn merge(db: &Connection) -> Result<(), StorageError> {
    db.execute_batch(r"
INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class,hold_expires_at)
SELECT p.commitment,p.wire_id,p.manifest_hash,p.wire_lookup,p.retention_class,p.hold_expires_at FROM incoming.object_retention_payload p
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=p.commitment)
ON CONFLICT DO NOTHING;
INSERT INTO object_retention_reference
SELECT r.* FROM incoming.object_retention_reference r
WHERE EXISTS(SELECT 1 FROM backup_reference_admission a
 WHERE a.side='incoming' AND a.reference_hash=r.reference_hash
 AND a.selector=r.selector AND a.commitment=r.commitment)
ON CONFLICT DO NOTHING;
INSERT INTO object_message_reference
SELECT m.* FROM incoming.object_message_reference m
WHERE EXISTS(SELECT 1 FROM backup_reference_admission a
 WHERE a.side='incoming' AND a.reference_hash=m.reference_hash AND a.message_id=m.message_id)
ON CONFLICT DO NOTHING;
INSERT INTO object_reference_actor
SELECT a.* FROM incoming.object_reference_actor a
WHERE EXISTS(SELECT 1 FROM backup_reference_admission r
 WHERE r.side='incoming' AND r.reference_hash=a.reference_hash)
ON CONFLICT DO NOTHING;
INSERT INTO object_payload_actor
SELECT a.* FROM incoming.object_payload_actor a
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment)
ON CONFLICT DO NOTHING;
INSERT INTO object_payload_dependency
SELECT d.* FROM incoming.object_payload_dependency d
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment IN (d.parent_commitment,d.child_commitment))
ON CONFLICT DO NOTHING;
INSERT INTO object_transport_actor
SELECT a.* FROM incoming.object_transport_actor a
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment)
ON CONFLICT DO NOTHING;
INSERT INTO object_identity_replacement
SELECT * FROM incoming.object_identity_replacement WHERE 1 ON CONFLICT DO NOTHING;

INSERT INTO message_copy_binding
SELECT 'object:'||a.selector,a.message_id FROM backup_reference_admission a
WHERE a.side='incoming' ON CONFLICT DO NOTHING;
INSERT INTO message_copy_binding
SELECT 'object:'||p.wire_id,a.message_id FROM backup_reference_admission a
JOIN incoming.object_retention_payload p ON p.commitment=a.commitment
WHERE a.side='incoming' ON CONFLICT DO NOTHING;
INSERT INTO message_footprint
SELECT a.message_id,'actor',r.state_kind FROM backup_reference_admission a
JOIN incoming.object_reference_actor r USING(reference_hash)
WHERE a.side='incoming' ON CONFLICT DO NOTHING;
INSERT INTO message_footprint
SELECT a.message_id,'revocation_selector',json_object(
 'selector',a.selector,'wire',p.wire_id,'manifest',p.manifest_hash,
 'commitment',a.commitment,'selector_lookup',r.selector_lookup)
FROM backup_reference_admission a
JOIN incoming.object_retention_reference r USING(reference_hash)
JOIN incoming.object_retention_payload p ON p.commitment=a.commitment
WHERE a.side='incoming' ON CONFLICT DO NOTHING;
")?;
    Ok(())
}
