// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retire private register publications and their fingerprint-bearing outbox keys atomically.
use super::AccountDb;
use crate::StorageError;

impl AccountDb {
    /// Retire one disposable `SelfSync` actor and its indexed/outbox copies.
    /// Revision and conversation erase floors are deliberately outside this allowlist.
    /// # Errors
    /// Requires the caller's writer transaction; rejects other namespaces and SQL failures.
    pub fn retire_self_sync_actor(&self, key: &str) -> Result<(), StorageError> {
        let key = key.to_owned();
        self.connection.call(move |db| Ok(retire_actor(db, &key))).map_err(StorageError::from)?
    }
}

pub(super) fn retire_actor(db: &rusqlite::Connection, key: &str) -> Result<(), StorageError> {
    if db.is_autocommit()
        || ![
            "self-sync/state/",
            "self-sync/pending/",
            "self-sync/repair/",
            "self-sync/repair-sent/",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
    {
        return Err(StorageError::AuthorizationRejected);
    }
    db.execute(
        "DELETE FROM runtime_outbox WHERE table_name='runtime_actor_state' AND actor_state_kind=?1",
        [key],
    )?;
    db.execute("DELETE FROM runtime_actor_state WHERE state_kind=?1", [key])?;
    // The delete trigger may enqueue the fingerprint-bearing actor key again.
    db.execute(
        "DELETE FROM runtime_outbox WHERE table_name='runtime_actor_state' AND actor_state_kind=?1",
        [key],
    )?;
    db.execute("DELETE FROM message_footprint WHERE locator=?1", [key])?;
    db.execute("DELETE FROM message_copy_binding WHERE copy_id IN (?1,'actor:'||?1)", [key])?;
    db.execute("INSERT INTO runtime_privacy_maintenance VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET erasure_pending=1", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    #[test]
    fn self_sync_retirement_purges_fingerprint_outbox_and_releases_old_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("self-sync-retire-outbox")?;
        let key = "self-sync/repair-sent/old-draft-fingerprint-canary";
        db.send_direct_message("c", "old-target", "peer", b"old target")?;
        db.send_direct_message("c", "new-target", "peer", b"new target")?;
        db.write_transaction(|| {
            db.persist_message_actor_state("old-target", key, &json!({"conversation_id":"c"}))
        })?;
        assert!(db.pending_outbox(256)?.iter().any(|entry| entry.keys.to_string().contains(key)));
        assert!(db.retire_self_sync_actor(key).is_err(), "retirement needs the enclosing writer");
        assert!(
            db.write_transaction(|| db.retire_self_sync_actor("self-sync/revision/floor")).is_err()
        );
        db.write_transaction(|| db.retire_self_sync_actor(key))?;
        assert!(!db.actor_state_exists(key)?);
        assert!(!db.pending_outbox(256)?.iter().any(|entry| entry.keys.to_string().contains(key)));
        db.write_transaction(|| {
            db.persist_message_actor_state("new-target", key, &json!({"conversation_id":"c"}))
        })?;
        db.delete_direct_message("c", "old-target", "local", "erase-old-target")?;
        assert!(
            db.actor_state_exists(key)?,
            "a retired ownership edge must not erase a later unrelated register"
        );
        db.delete_direct_message("c", "new-target", "local", "erase-new-target")?;
        assert!(!db.actor_state_exists(key)?);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
