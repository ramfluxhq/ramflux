// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retire captured selectors while their authenticated payload identities still exist.

pub(super) const RETIRE: &str = r"
 DELETE FROM object_index WHERE object_id IN (SELECT selector FROM object_reference_erasure_work)
 AND tombstoned=1 AND chunk_count=0 AND length(ciphertext)=0
 AND NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.selector=object_index.object_id)
 AND EXISTS(SELECT 1 FROM object_reference_erasure_work w JOIN object_retention_payload p USING(commitment) WHERE w.selector=object_index.object_id AND p.manifest_hash=CAST(object_index.manifest_hash AS TEXT));
 INSERT INTO object_erasure_lookup SELECT w.selector_lookup,w.commitment FROM object_reference_erasure_work w
 WHERE NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.selector=w.selector) ON CONFLICT DO NOTHING;
 DELETE FROM runtime_outbox WHERE actor_state_kind IN (SELECT a.state_kind FROM object_reference_actor a JOIN object_reference_erasure_work w USING(reference_hash))
 AND NOT EXISTS(SELECT 1 FROM object_reference_actor a JOIN object_retention_reference r USING(reference_hash) JOIN object_message_reference m USING(reference_hash) WHERE a.state_kind=runtime_outbox.actor_state_kind);
 DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT a.state_kind FROM object_reference_actor a JOIN object_reference_erasure_work w USING(reference_hash))
 AND NOT EXISTS(SELECT 1 FROM object_reference_actor a JOIN object_retention_reference r USING(reference_hash) JOIN object_message_reference m USING(reference_hash) WHERE a.state_kind=runtime_actor_state.state_kind);
 DELETE FROM message_footprint WHERE kind='actor' AND locator IN (SELECT a.state_kind FROM object_reference_actor a JOIN object_reference_erasure_work w USING(reference_hash))
 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind=message_footprint.locator);
 DELETE FROM object_payload_actor WHERE state_kind IN (SELECT a.state_kind FROM object_reference_actor a JOIN object_reference_erasure_work w USING(reference_hash))
 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind=object_payload_actor.state_kind);
 DELETE FROM runtime_outbox WHERE actor_state_kind IN (SELECT a.state_kind FROM object_reference_actor a JOIN object_reference_erasure_work w USING(reference_hash))
 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind=runtime_outbox.actor_state_kind);
 DELETE FROM object_reference_actor WHERE reference_hash IN (SELECT reference_hash FROM object_reference_erasure_work);
 DELETE FROM message_copy_binding WHERE copy_id IN (SELECT 'object:'||selector FROM object_reference_erasure_work)
 AND NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE ('object:'||r.selector=message_copy_binding.copy_id OR 'object:'||(SELECT p.wire_id FROM object_retention_payload p WHERE p.commitment=r.commitment)=message_copy_binding.copy_id) AND m.message_id=message_copy_binding.message_id);
 DELETE FROM message_footprint WHERE message_id IN (SELECT 'copy:object:'||selector FROM object_reference_erasure_work)
 AND NOT EXISTS(SELECT 1 FROM message_copy_binding b WHERE 'copy:'||b.copy_id=message_footprint.message_id);
";

pub(super) const PROJECT: &str = r"
 INSERT INTO runtime_actor_state(state_kind,state_json) SELECT 'attachment/reference/'||w.selector,(SELECT r.reference_json FROM object_retention_reference r WHERE r.selector=w.selector ORDER BY r.reference_hash LIMIT 1) FROM object_projection_erasure_work w WHERE EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.selector=w.selector) ON CONFLICT(state_kind) DO NOTHING;
 INSERT INTO runtime_actor_state(state_kind,state_json) SELECT 'directory/object/'||w.selector,(SELECT m.metadata_json FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) WHERE r.selector=w.selector ORDER BY m.message_id,r.reference_hash LIMIT 1) FROM object_projection_erasure_work w WHERE EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.selector=w.selector) ON CONFLICT(state_kind) DO NOTHING;
 UPDATE runtime_actor_state SET state_json=(SELECT r.reference_json FROM object_retention_reference r WHERE r.selector=substr(runtime_actor_state.state_kind,22) ORDER BY r.reference_hash LIMIT 1)
 WHERE state_kind IN (SELECT 'attachment/reference/'||selector FROM object_projection_erasure_work)
 AND EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.selector=substr(runtime_actor_state.state_kind,22));
 UPDATE runtime_actor_state SET state_json=(SELECT m.metadata_json FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) WHERE r.selector=substr(runtime_actor_state.state_kind,18) ORDER BY m.message_id,r.reference_hash LIMIT 1)
 WHERE state_kind IN (SELECT 'directory/object/'||selector FROM object_projection_erasure_work)
 AND EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.selector=substr(runtime_actor_state.state_kind,18));
 DELETE FROM runtime_actor_state WHERE state_kind IN (
 SELECT 'attachment/reference/'||w.selector FROM object_reference_erasure_work w WHERE NOT EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.selector=w.selector)
 UNION ALL SELECT 'directory/object/'||w.selector FROM object_reference_erasure_work w WHERE NOT EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.selector=w.selector));
";

// Projection DELETEs also emit invalidation keys; retire those within the same transaction.
// Drive outbox probes from the captured closure; matching TEXT affinity keeps
// the expression index searchable rather than scanning unrelated object keys.
pub(super) const DRAIN: &str = r"
 DELETE FROM object_payload_actor WHERE state_kind IN (
 SELECT 'attachment/reference/'||selector FROM object_projection_erasure_work
 UNION ALL SELECT 'directory/object/'||selector FROM object_projection_erasure_work)
 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind=object_payload_actor.state_kind);
 DELETE FROM runtime_outbox WHERE actor_state_kind IN (
 SELECT 'attachment/reference/'||selector FROM object_projection_erasure_work
 UNION ALL SELECT 'directory/object/'||selector FROM object_projection_erasure_work)
 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind=runtime_outbox.actor_state_kind);
 DELETE FROM message_footprint WHERE kind='actor' AND locator IN (
 SELECT 'attachment/reference/'||selector FROM object_projection_erasure_work
 UNION ALL SELECT 'directory/object/'||selector FROM object_projection_erasure_work)
 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind=message_footprint.locator);
 DELETE FROM runtime_outbox WHERE sequence IN (
 SELECT pending.sequence FROM object_projection_erasure_work w
 CROSS JOIN runtime_outbox pending INDEXED BY runtime_outbox_object_selector
 ON CAST(json_extract(pending.keys_json,'$.object_id') AS TEXT)=w.selector
 WHERE pending.table_name='object_index'
 AND NOT EXISTS(SELECT 1 FROM object_index o WHERE o.object_id=json_extract(pending.keys_json,'$.object_id')));
";
