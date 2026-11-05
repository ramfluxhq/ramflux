// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consume the captured incoming deletion restrictions while target owner links remain intact.
use crate::StorageError;
use rusqlite::Connection;

pub(in crate::account_db) fn apply(db: &Connection) -> Result<(), StorageError> {
    // Decisions were captured before union using authenticated deletion authority.
    // In particular a marker-only deletion need not win projection arbitration.
    // Updating deleted fires the existing live erasure triggers, which preserve
    // independent owners and retire selectors without fencing their shared payload.
    db.execute_batch(
        "UPDATE direct_message_projection SET sender_id='',encrypted_body=x'',metadata_json=x'7b7d',deleted=1 WHERE message_id IN (SELECT message_id FROM backup_target_delete);",
    )?;
    Ok(())
}

pub(in crate::account_db) fn verify(db: &Connection) -> Result<(), StorageError> {
    // Drive the bounded postcondition from this operation's pending edge set;
    // never scan unrelated message history or trust incoming survivor rows.
    let invalid: bool = db.query_row(
        r"SELECT EXISTS(SELECT 1 FROM backup_target_delete t WHERE
        EXISTS(SELECT 1 FROM object_message_reference m WHERE m.reference_hash=t.reference_hash AND m.message_id=t.message_id)
        OR NOT EXISTS(SELECT 1 FROM direct_message_projection p WHERE p.message_id=t.message_id AND p.deleted=1)
        OR EXISTS(SELECT 1 FROM message_copy_binding b WHERE b.copy_id='object:'||t.selector AND b.message_id=t.message_id)
        OR (NOT EXISTS(SELECT 1 FROM object_message_reference m WHERE m.reference_hash=t.reference_hash)
            AND (EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.reference_hash=t.reference_hash)
                OR EXISTS(SELECT 1 FROM object_reference_actor a WHERE a.reference_hash=t.reference_hash)))
        OR (NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.selector=t.selector)
            AND NOT EXISTS(SELECT 1 FROM message_footprint f INDEXED BY message_footprint_revocation_selector WHERE f.kind='revocation_selector' AND CAST(json_extract(f.locator,'$.selector') AS TEXT)=t.selector AND NOT EXISTS(SELECT 1 FROM object_erasure_fence e WHERE e.commitment=json_extract(f.locator,'$.commitment')) AND NOT EXISTS(SELECT 1 FROM direct_message_projection p WHERE p.message_id=f.message_id AND p.deleted=1))
            AND EXISTS(SELECT 1 FROM object_index o WHERE o.object_id=t.selector AND o.tombstoned=1 AND length(o.ciphertext)=0 AND o.chunk_count=0)))",
        [],
        |r| r.get(0),
    )?;
    if invalid {
        return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
    }
    let root: String = db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let mut retired = db.prepare(r"SELECT DISTINCT t.selector,t.commitment FROM backup_target_delete t
        WHERE NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.selector=t.selector)
        AND NOT EXISTS(SELECT 1 FROM message_footprint f INDEXED BY message_footprint_revocation_selector WHERE f.kind='revocation_selector' AND CAST(json_extract(f.locator,'$.selector') AS TEXT)=t.selector AND NOT EXISTS(SELECT 1 FROM object_erasure_fence e WHERE e.commitment=json_extract(f.locator,'$.commitment')) AND NOT EXISTS(SELECT 1 FROM direct_message_projection p WHERE p.message_id=f.message_id AND p.deleted=1))")?;
    for row in retired.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (selector, commitment) = row?;
        let lookup = ramflux_crypto::object_erasure_lookup(&root, &selector);
        let recorded: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1 AND commitment=?2)",
            rusqlite::params![lookup, commitment],
            |r| r.get(0),
        )?;
        if !recorded {
            return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
        }
    }
    Ok(())
}

#[cfg(test)]
type Observer = fn(&Connection) -> Result<(), StorageError>;
#[cfg(test)]
thread_local! {
    pub(super) static BEFORE: std::cell::Cell<Option<Observer>> = const { std::cell::Cell::new(None) };
    pub(super) static AFTER: std::cell::Cell<Option<Observer>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(in crate::account_db) fn checkpoint(db: &Connection, after: bool) -> Result<(), StorageError> {
    if let Some(observe) = if after { AFTER.get() } else { BEFORE.get() } {
        observe(db)?;
    }
    Ok(())
}
