// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Paged unavailable-reference diagnostics and the authenticated source-omission manifest.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::StorageError;
use rusqlite::{Connection, params};
pub(super) const MISSING: &str = "r.state_kind LIKE 'attachment/reference/%' AND NOT EXISTS(SELECT 1 FROM object_index o WHERE o.manifest_hash IN (CAST(json_extract(CAST(r.state_json AS TEXT),'$.reference.manifest_hash') AS BLOB),json_extract(CAST(r.state_json AS TEXT),'$.reference.manifest_hash')) AND o.plaintext_hash=json_extract(CAST(r.state_json AS TEXT),'$.reference.plaintext_hash'))";
fn page(db: &Connection, after: &str) -> rusqlite::Result<Vec<String>> {
    let mut q=db.prepare(&format!("SELECT substr(r.state_kind,length('attachment/reference/')+1) FROM runtime_actor_state r WHERE {MISSING} AND r.state_kind>?1 ORDER BY r.state_kind LIMIT 64"))?;
    q.query_map(params![format!("attachment/reference/{after}")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()
}
impl AccountDb {
    /// Enumerates unavailable references with one hash-set build and one ordered reference scan.
    /// Run on a reader worker, inside a short read transaction when concurrent writes are possible.
    /// # Errors
    /// Returns SQLite or malformed JSON errors; there is no count-based truncation.
    pub fn backup_missing_selectors(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.connection.call(|db| {
            let mut keys = std::collections::HashSet::new();
            let mut objects = db.prepare("SELECT CAST(manifest_hash AS BLOB),plaintext_hash FROM object_index WHERE manifest_hash IS NOT NULL AND plaintext_hash IS NOT NULL")?;
            for row in objects.query_map([], |r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?)))? {
                keys.insert(row?);
            }
            let mut refs = db.prepare("SELECT substr(state_kind,length('attachment/reference/')+1),CASE WHEN json_type(CAST(state_json AS TEXT),'$.reference.manifest_hash')='text' THEN json_extract(CAST(state_json AS TEXT),'$.reference.manifest_hash') END,CASE WHEN json_type(CAST(state_json AS TEXT),'$.reference.plaintext_hash')='text' THEN json_extract(CAST(state_json AS TEXT),'$.reference.plaintext_hash') END FROM runtime_actor_state WHERE state_kind LIKE 'attachment/reference/%' ORDER BY state_kind")?;
            let mut missing=Vec::new();
            for row in refs.query_map([], |r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Option<String>>(2)?)))? {
                let (selector, manifest, plaintext)=row?;
                if !manifest.zip(plaintext).is_some_and(|(m,p)|keys.contains(&(m.into_bytes(),p))) {
                    missing.push(selector);
                }
            }
            Ok(missing)
        })?)
    }
    /// Counts unavailable references without a per-reference correlated object scan.
    /// # Errors
    /// Returns SQLite errors.
    pub fn backup_missing_count(&self) -> Result<u64, StorageError> {
        Ok(self.backup_missing_selectors()?.len() as u64)
    }
    /// Lists the next 64 unavailable selectors. Fetch preparation uses a single full enumeration.
    /// # Errors
    /// Returns SQLite errors. Continue after the last selector until an empty page.
    pub fn backup_missing_page(&self, after: &str) -> Result<Vec<String>, StorageError> {
        Ok(self
            .backup_missing_selectors()?
            .into_iter()
            .filter(|s| s.as_str() > after)
            .take(64)
            .collect())
    }
}
impl BackupDatabase {
    pub(super) fn ensure_missing_manifest(&self) -> Result<(), StorageError> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS backup_missing_attachment(selector TEXT PRIMARY KEY,manifest_hash TEXT NOT NULL,plaintext_hash TEXT NOT NULL); CREATE INDEX IF NOT EXISTS backup_object_reference_hashes ON object_index(manifest_hash,plaintext_hash);")?;
        Ok(())
    }
    /// Lists a bounded page of unavailable payload selectors in the private snapshot.
    /// # Errors
    /// Returns SQLite errors; callers must continue rather than truncate.
    pub fn missing_attachment_page(&self, after: &str) -> Result<Vec<String>, StorageError> {
        Ok(page(&self.db, after)?)
    }
    /// Counts every missing payload reference in the private snapshot.
    /// # Errors
    /// Returns SQLite errors.
    pub fn missing_attachment_count(&self) -> Result<u64, StorageError> {
        Ok(self.db.query_row(
            &format!("SELECT count(*) FROM runtime_actor_state r WHERE {MISSING}"),
            [],
            |r| r.get(0),
        )?)
    }
    /// Clears approvals from earlier archives before a new explicit create decision.
    /// # Errors
    /// Returns SQLite errors.
    pub fn clear_missing_manifest(&self) -> Result<(), StorageError> {
        self.db.execute("DELETE FROM backup_missing_attachment", [])?;
        Ok(())
    }
    /// Records explicit source unavailability in the authenticated database manifest.
    /// Malformed references and corrupt stored files are never approved by this option.
    /// # Errors
    /// Returns SQLite errors.
    pub fn allow_missing_attachments(&self) -> Result<(), StorageError> {
        self.db.execute(&format!("INSERT OR REPLACE INTO backup_missing_attachment SELECT substr(r.state_kind,length('attachment/reference/')+1),json_extract(CAST(r.state_json AS TEXT),'$.reference.manifest_hash'),json_extract(CAST(r.state_json AS TEXT),'$.reference.plaintext_hash') FROM runtime_actor_state r WHERE {MISSING} AND json_type(CAST(r.state_json AS TEXT),'$.reference.manifest_hash')='text' AND json_type(CAST(r.state_json AS TEXT),'$.reference.plaintext_hash')='text' AND length(json_extract(CAST(r.state_json AS TEXT),'$.reference.manifest_hash'))>0 AND length(json_extract(CAST(r.state_json AS TEXT),'$.reference.plaintext_hash'))>0"),[])?;
        Ok(())
    }
    /// Counts still-missing references exactly bound to their approved hashes and selector.
    /// # Errors
    /// Returns SQLite errors; unrelated or subsequently available records do not grant an omission.
    pub fn approved_missing_count(&self) -> Result<u64, StorageError> {
        Ok(self.db.query_row(&format!("SELECT count(*) FROM runtime_actor_state r JOIN backup_missing_attachment m ON m.selector=substr(r.state_kind,length('attachment/reference/')+1) AND m.manifest_hash=json_extract(CAST(r.state_json AS TEXT),'$.reference.manifest_hash') AND m.plaintext_hash=json_extract(CAST(r.state_json AS TEXT),'$.reference.plaintext_hash') WHERE {MISSING}"),[],|r|r.get(0))?)
    }
}

impl BackupDatabase {
    pub(super) fn install_missing_counts(&self) -> Result<(u64, u64), StorageError> {
        let supplied = "EXISTS(SELECT 1 FROM incoming.runtime_actor_state source WHERE source.state_kind=r.state_kind AND source.state_json=r.state_json)";
        let missing = self.db.query_row(
            &format!("SELECT count(*) FROM runtime_actor_state r WHERE {MISSING} AND {supplied}"),
            [],
            |r| r.get::<_, u64>(0),
        )?;
        let approved=self.db.query_row(&format!("SELECT count(*) FROM runtime_actor_state r JOIN incoming.backup_missing_attachment m ON m.selector=substr(r.state_kind,length('attachment/reference/')+1) AND m.manifest_hash=json_extract(CAST(r.state_json AS TEXT),'$.reference.manifest_hash') AND m.plaintext_hash=json_extract(CAST(r.state_json AS TEXT),'$.reference.plaintext_hash') WHERE {MISSING} AND {supplied}"),[],|r|r.get::<_,u64>(0))?;
        Ok((missing, approved))
    }
}
