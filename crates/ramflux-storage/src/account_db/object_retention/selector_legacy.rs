// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Message-owned retirement identities for authenticated, undiscovered references.
// The exact locator is the survivor key, so the existing (kind,locator,message)
// index bounds work to this identity. Neither discovery context nor trigger
// ordering participates in retirement.
pub(crate) fn erasure_body() -> String {
    let retired = r"SELECT f.locator FROM message_footprint f
        WHERE f.message_id=NEW.message_id AND f.kind='revocation_selector'
        AND NOT EXISTS(SELECT 1 FROM message_footprint other
          WHERE other.kind='revocation_selector' AND other.locator=f.locator
          AND other.message_id<>NEW.message_id
          AND NOT EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=other.message_id AND d.deleted=1))
        AND NOT EXISTS(SELECT 1 FROM object_retention_reference r
          JOIN object_message_reference m USING(reference_hash)
          WHERE r.selector=json_extract(f.locator,'$.selector')
          AND m.message_id<>NEW.message_id
          AND NOT EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=m.message_id AND d.deleted=1))";
    format!(
        r"
        UPDATE account_erasure_generation SET generation=generation+1
        WHERE EXISTS({retired});
        DELETE FROM object_index WHERE object_id IN (SELECT json_extract(locator,'$.selector') FROM ({retired}))
        AND tombstoned=1 AND chunk_count=0 AND length(ciphertext)=0
        AND (manifest_hash=zeroblob(32) OR EXISTS(SELECT 1 FROM ({retired}) f
          WHERE json_extract(f.locator,'$.selector')=object_index.object_id
          AND json_extract(f.locator,'$.manifest')=CAST(object_index.manifest_hash AS TEXT)));
        DELETE FROM message_footprint WHERE kind='actor' AND locator IN (
          SELECT actor.locator FROM message_footprint actor
          WHERE actor.message_id=NEW.message_id AND actor.kind='actor'
          AND EXISTS({retired}))
        AND message_id GLOB 'copy:*'
        AND NOT EXISTS(SELECT 1 FROM message_copy_binding b WHERE b.copy_id=substr(message_footprint.message_id,6));
        DELETE FROM object_payload_actor WHERE state_kind IN (
          SELECT actor.locator FROM message_footprint actor
          WHERE actor.message_id=NEW.message_id AND actor.kind='actor'
          AND EXISTS({retired}))
        AND NOT EXISTS(SELECT 1 FROM message_footprint shared
          WHERE shared.kind='actor' AND shared.locator=object_payload_actor.state_kind
          AND shared.message_id<>NEW.message_id AND shared.message_id NOT GLOB 'copy:*');
        DELETE FROM runtime_outbox WHERE sequence IN (
          SELECT outbox.sequence FROM ({retired}) f
          CROSS JOIN runtime_outbox outbox INDEXED BY runtime_outbox_object_selector
          ON CAST(json_extract(outbox.keys_json,'$.object_id') AS TEXT)=json_extract(f.locator,'$.selector')
          WHERE outbox.table_name='object_index'
          AND NOT EXISTS(SELECT 1 FROM object_index o WHERE o.object_id=json_extract(f.locator,'$.selector')));
        INSERT INTO object_erasure_lookup SELECT json_extract(locator,'$.selector_lookup'),json_extract(locator,'$.commitment')
        FROM ({retired}) WHERE 1 ON CONFLICT DO NOTHING;
    "
    )
}
