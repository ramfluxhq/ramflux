// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-isolated admission and original-lifetime bounds for retained ciphertext.
use super::*;
/// Authenticated identity scope and dependency for a retained inbox failure.
#[derive(Clone, Copy)]
pub struct InboxFailurePolicy<'a> {
    /// An independently verified source scope; absent for unauthenticated claims.
    pub verified_source: Option<&'a str>,
    /// True only for an authenticated source with an existing local relationship.
    pub trusted: bool,
    /// Dependency class and subject used for selective redrive.
    pub dependency: (&'a str, &'a str),
    /// Receiver time at admission.
    pub at: i64,
}
impl AccountDb {
    /// Records a bounded failure policy. Only authenticated, locally related peers get longer holds.
    /// # Errors
    /// Returns SQLite or serialization errors.
    pub fn set_inbox_failure_policy(
        &self,
        key: &str,
        entry: &[u8],
        trusted: bool,
        dependency: (&str, &str),
        at: i64,
    ) -> Result<bool, StorageError> {
        let value: serde_json::Value = serde_json::from_slice(entry).unwrap_or_default();
        let source = value["envelope"]["source_device_id"].as_str().unwrap_or(key);
        self.set_verified_inbox_failure_policy(
            key,
            entry,
            InboxFailurePolicy {
                verified_source: trusted.then_some(source),
                trusted,
                dependency,
                at,
            },
        )
    }
    /// Sets failure policy with a verified identity scope independent of claimed device IDs.
    /// # Errors
    /// Returns SQLite or serialization errors.
    pub fn set_verified_inbox_failure_policy(
        &self,
        key: &str,
        entry: &[u8],
        policy: InboxFailurePolicy<'_>,
    ) -> Result<bool, StorageError> {
        let InboxFailurePolicy { verified_source, trusted, dependency: (class, subject), at } =
            policy;
        let trusted = trusted && verified_source.is_some();
        let source = verified_source
            .map_or_else(|| format!("unverified:{key}"), |source| format!("verified:{source}"));
        let value: serde_json::Value = serde_json::from_slice(entry).unwrap_or_default();
        self.write_transaction(|| {
            let exists: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM runtime_inbox_policy WHERE envelope_key=?1)",
                params![key],
                |r| r.get(0),
            )?;
            if exists {
                if verified_source.is_some() {
                    let count: i64 = self.connection.query_row("SELECT count(*) FROM runtime_inbox_policy WHERE source=?1 AND envelope_key!=?2",params![source,key],|r|r.get(0))?;
                    if count >= if trusted { 8 } else { 2 } { return Ok(false); }
                    if trusted {
                        self.connection.execute("UPDATE runtime_inbox_retry SET next_at=?2 WHERE envelope_key=?1 AND EXISTS(SELECT 1 FROM runtime_inbox_policy WHERE envelope_key=?1 AND trusted=0)",params![key,at])?;
                    }
                    self.connection.execute("UPDATE runtime_inbox_policy SET source=?2 WHERE envelope_key=?1",params![key,source])?;
                }
                if trusted {
                    self.connection.execute("UPDATE runtime_inbox_policy SET source=?2,trusted=1,expires_at=min(first_seen+600,?3) WHERE envelope_key=?1 AND trusted=0",params![key,source,value["envelope"]["created_at"].as_i64().zip(value["envelope"]["ttl"].as_i64()).map_or(i64::MAX, |(created, ttl)| created.saturating_add(ttl))])?;
                }
                if class != "none" { self.connection.execute("UPDATE runtime_inbox_policy SET failure_class=?2,subject=?3,last_revision=coalesce((SELECT revision FROM runtime_inbox_changes WHERE kind=?2 AND subject=?3),0) WHERE envelope_key=?1",params![key,class,subject])?; }
                return Ok(true);
            }
            let count: i64 = self.connection.query_row(
                "SELECT count(*) FROM runtime_inbox_policy WHERE source=?1",
                params![source],
                |r| r.get(0),
            )?;
            let total: i64 = self.connection.query_row(
                "SELECT count(*) FROM runtime_inbox_policy",
                [],
                |r| r.get(0),
            )?;
            let strangers: i64 = self.connection.query_row(
                "SELECT count(*) FROM runtime_inbox_policy WHERE trusted=0",
                [],
                |r| r.get(0),
            )?;
            if count >= if trusted { 8 } else { 2 } || total >= 128 || (!trusted && strangers >= 16)
            {
                return Ok(false);
            }
            let window = if trusted { 600 } else { 30 };
            let wire_expiry = value["envelope"]["created_at"]
                .as_i64()
                .zip(value["envelope"]["ttl"].as_i64())
                .map_or(i64::MAX, |(created, ttl)| created.saturating_add(ttl));
            self.connection.execute(
                "INSERT INTO runtime_inbox_policy VALUES(?1,?2,?3,?4,?5,0,?6,?7,0,coalesce((SELECT revision FROM runtime_inbox_changes WHERE kind=?6 AND subject=?7),0))",
                params![
                    key,
                    source,
                    trusted,
                    at,
                    at.saturating_add(window).min(wire_expiry),
                    class,
                    subject
                ],
            )?;
            Ok(true)
        })
    }
    pub(super) fn ensure_inbox_policy(
        &self,
        key: &str,
        entry: &[u8],
        at: i64,
    ) -> Result<bool, StorageError> {
        self.set_inbox_failure_policy(key, entry, false, ("none", ""), at)
    }
    pub(super) fn cleanup_inbox_policy(&self) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM runtime_inbox_policy WHERE envelope_key NOT IN (SELECT envelope_key FROM runtime_inbox_retry UNION SELECT envelope_key FROM runtime_inbox_dead_letter)",[])?;
        Ok(())
    }
    /// Selectively wakes work affected by actual group/manifest changes. Each entry can be woken
    /// at most once per minute, without extending its first-seen lifetime or attempt budget.
    /// # Errors
    /// Returns SQLite errors.
    pub fn redrive_inbox_changes(&self, at: i64) -> Result<usize, StorageError> {
        self.write_transaction(|| {
            if self.load_actor_state::<i64>("inbox/redrive-at")?.is_some_and(|last| at<=last) { return Ok(0); }
            let mut q=self.connection.prepare("SELECT p.envelope_key FROM runtime_inbox_policy p JOIN runtime_inbox_retry r USING(envelope_key) WHERE p.failure_class IN ('group','manifest') AND p.expires_at>?1 AND p.attempts < CASE WHEN p.trusted=1 THEN 8 ELSE 3 END AND (p.last_redrive=0 OR p.last_redrive<=?1-60) AND EXISTS(SELECT 1 FROM runtime_inbox_changes c WHERE c.kind=p.failure_class AND c.subject=p.subject AND c.revision>p.last_revision) ORDER BY p.first_seen LIMIT 8")?;
            let keys=q.query_map(params![at],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(q);
            let mut changed=0;
            for key in keys {
                let woke=self.connection.execute("UPDATE runtime_inbox_retry SET next_at=?2 WHERE envelope_key=?1",params![key,at])?;
                changed+=woke;
                if woke>0 { self.connection.execute("UPDATE runtime_inbox_policy SET last_redrive=?2,last_revision=coalesce((SELECT max(revision) FROM runtime_inbox_changes WHERE kind=failure_class AND runtime_inbox_changes.subject=runtime_inbox_policy.subject),last_revision) WHERE envelope_key=?1",params![key,at])?; }
            }
            if changed>0 { self.persist_actor_state("inbox/redrive-at",&at)?; }
            Ok(changed)
        })
    }
}
