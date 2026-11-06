// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Portable generation restrictions and local, lease-drained physical cleanup debt.
use super::{
    AccountDb, SegmentDirection, SegmentStore, StorageError, VerifiedContentManifest, files,
    integer, lease,
};
use crate::database::Connection;
use rusqlite::{OptionalExtension, params};
use std::path::{Path, PathBuf};
pub(super) const RESOURCE_LIMIT: usize = 4096;
type ResourceBinding = (String, String, Option<String>, Option<String>, Option<String>, bool);
type ResourceState = (String, String, Option<String>, Option<String>, Option<String>, bool, bool);
pub struct SegmentReference<'a> {
    pub selector: &'a str,
    pub reference_hash: &'a str,
    pub message_id: &'a str,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SegmentCleanupPage {
    pub deleted: usize,
    pub busy: usize,
    pub more: bool,
}
pub(super) struct ResourceLease {
    held: Option<lease::Lease>,
    db: Connection,
    path: PathBuf,
}
impl ResourceLease {
    pub(super) fn new(held: lease::Lease, db: Connection, path: PathBuf) -> Self {
        Self { held: Some(held), db, path }
    }
}
impl Drop for ResourceLease {
    fn drop(&mut self) {
        drop(self.held.take());
        if let Err(error) =
            drain(&self.db, self.path.parent().unwrap_or(&self.path), Some(&self.path), 32)
        {
            tracing::warn!(%error,"segment cleanup debt retained");
        }
    }
}
fn directory(id: &str) -> String {
    ramflux_protocol::encode_base64url(blake3::hash(id.as_bytes()).as_bytes())
}
impl SegmentStore<'_> {
    /// Admits only an exact, currently owned local message reference. Remote grant
    /// authority remains with the source; this cannot settle its retirement outbox.
    /// # Errors
    /// Refuses erased selectors, deleted owners, stale generations and identity changes.
    pub fn admit_reference(
        &mut self,
        id: &str,
        generation: u64,
        direction: SegmentDirection,
        native: &VerifiedContentManifest,
        reference: &SegmentReference<'_>,
    ) -> Result<(), StorageError> {
        self.admit_inner(id, generation, direction, native, Some(reference))
    }
    /// Admits an owned upload under the account's existing provisional retention token.
    /// # Errors
    /// Refuses foreign ownership, expired/released holds, fences and stale generations.
    pub fn admit_pre_send(
        &mut self,
        id: &str,
        generation: u64,
        native: &VerifiedContentManifest,
        hold: &crate::PreSendObjectHold,
    ) -> Result<(), StorageError> {
        let m = native.manifest();
        let wire = ramflux_protocol::encode_base64url(m.object_id);
        let manifest = ramflux_protocol::encode_base64url(
            m.hash().map_err(|_| StorageError::Integrity("segment manifest"))?,
        );
        if m.owner.account_anchor != self.db.principal_commitment
            || !hold.admits_segment_payload(self.db, &wire, &manifest)
        {
            return Err(StorageError::AuthorizationRejected);
        }
        self.check_provisional(&wire, &manifest)?;
        self.admit_inner(id, generation, SegmentDirection::Upload, native, None)
    }
    pub(super) fn check_provisional(&self, wire: &str, manifest: &str) -> Result<(), StorageError> {
        let authority = self.db.erasure_authority.as_ref().unwrap_or(&self.db.connection);
        let live:bool=authority.query_row("SELECT EXISTS(SELECT 1 FROM object_retention_payload WHERE commitment=?1 AND retention_class='pre_send' AND hold_expires_at>?2)",params![ramflux_crypto::object_erasure_commitment(&self.db.principal_commitment,wire,manifest),self.db.now_unix()],|r|r.get(0))?;
        if !live {
            return Err(StorageError::ObjectErased);
        }
        self.db.check_object_identity(wire, manifest)
    }
    #[cfg(test)]
    pub(super) fn admit(
        &mut self,
        id: &str,
        generation: u64,
        direction: SegmentDirection,
        native: &VerifiedContentManifest,
    ) -> Result<(), StorageError> {
        let m = native.manifest();
        self.db.retain_object(
            &ramflux_protocol::encode_base64url(m.object_id),
            &ramflux_protocol::encode_base64url(
                m.hash().map_err(|_| StorageError::Integrity("segment manifest"))?,
            ),
            crate::ObjectRetention::PreSend { expires_at: self.db.now_unix().saturating_add(600) },
        )?;
        self.admit_inner(id, generation, direction, native, None)
    }
    pub(super) fn check_reference(
        &self,
        r: &SegmentReference<'_>,
        wire: &str,
        manifest: &str,
    ) -> Result<(), StorageError> {
        self.db.check_object_access(r.selector)?;
        self.db.check_object_identity(wire, manifest)?;
        let db = self.db.erasure_authority.as_ref().unwrap_or(&self.db.connection);
        let present:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) JOIN object_retention_payload p USING(commitment) WHERE m.message_id=?1 AND m.reference_hash=?2 AND r.selector=?3 AND p.wire_id=?4 AND p.manifest_hash=?5)",params![r.message_id,r.reference_hash,r.selector,wire,manifest],|row|row.get(0))?;
        if !present || self.db.message_is_deleted(r.message_id)? {
            return Err(StorageError::ObjectErased);
        }
        Ok(())
    }
    pub(super) fn record_resource(
        &self,
        id: &str,
        generation: i64,
        wire: &str,
        manifest: &str,
        reference: Option<&SegmentReference<'_>>,
    ) -> Result<bool, StorageError> {
        let dir = directory(id);
        let floor: Option<i64> = self
            .db
            .connection
            .query_row(
                "SELECT generation FROM object_segment_floor WHERE directory=?1",
                params![dir],
                |r| r.get(0),
            )
            .optional()?;
        if floor.is_some_and(|f| generation <= f) {
            return Err(StorageError::ObjectErased);
        }
        let binding = reference.map(|r| (r.selector, r.reference_hash, r.message_id));
        let old:Option<ResourceBinding>=self.db.connection.query_row("SELECT wire,manifest,selector,reference_hash,message_id,retired FROM object_segment_resource WHERE directory=?1 AND generation=?2",params![dir,generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        let fresh = old.is_none();
        if fresh {
            check_capacity(&self.db.connection)?;
        }
        if let Some((w, m, s, r, msg, retired)) = old
            && (retired
                || w != wire
                || m != manifest
                || s.as_deref() != binding.map(|b| b.0)
                || r.as_deref() != binding.map(|b| b.1)
                || msg.as_deref() != binding.map(|b| b.2))
        {
            return Err(StorageError::ObjectIdentityConflict);
        }
        self.db.connection.execute("UPDATE object_segment_resource SET retired=1 WHERE directory=?1 AND generation<?2 AND retired=0",params![dir,generation])?;
        self.db.connection.execute(
            "INSERT OR IGNORE INTO object_segment_resource VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
            params![
                dir,
                generation,
                id,
                wire,
                manifest,
                ramflux_crypto::object_erasure_commitment(
                    &self.db.principal_commitment,
                    wire,
                    manifest
                ),
                binding.map(|b| b.0),
                binding.map(|b| b.1),
                binding.map(|b| b.2)
            ],
        )?;
        Ok(fresh)
    }
    pub(super) fn check_resource(&self, id: &str, generation: u64) -> Result<(), StorageError> {
        let dir = directory(id);
        let authority = self.db.erasure_authority.as_ref().unwrap_or(&self.db.connection);
        let row:Option<ResourceState>=authority.query_row("SELECT wire,manifest,selector,reference_hash,message_id,retired,EXISTS(SELECT 1 FROM object_segment_floor f WHERE f.directory=r.directory AND f.generation>=r.generation) FROM object_segment_resource r WHERE directory=?1 AND generation=?2",params![dir,integer(generation)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        let Some((wire, manifest, selector, reference, message, retired, fenced)) = row else {
            return Err(StorageError::ObjectErased);
        };
        if retired || fenced {
            return Err(StorageError::ObjectErased);
        }
        match (selector, reference, message) {
            (Some(selector), Some(reference_hash), Some(message_id)) => self.check_reference(
                &SegmentReference {
                    selector: &selector,
                    reference_hash: &reference_hash,
                    message_id: &message_id,
                },
                &wire,
                &manifest,
            ),
            (None, None, None) => self.check_provisional(&wire, &manifest),
            _ => Err(StorageError::ObjectErased),
        }
    }
    /// Recounts the retained local rows, including cleanup debt. No snapshot counter is trusted.
    /// # Errors
    /// Returns database errors.
    pub fn resource_count(&self) -> Result<usize, StorageError> {
        Ok(self.db.connection.query_row(
            "SELECT count(*) FROM object_segment_resource",
            [],
            |r| r.get(0),
        )?)
    }
    /// Retired files remain debt until their real lease drains and directory fsync succeeds.
    /// # Errors
    /// Refuses unbounded work or filesystem/database failures; failed rows remain queued.
    pub fn cleanup_retired(&self, limit: usize) -> Result<SegmentCleanupPage, StorageError> {
        drain(&self.db.connection, &self.root, None, limit)
    }
}
pub(in crate::account_db) fn drain_account(
    db: &AccountDb,
    limit: usize,
) -> Result<(), StorageError> {
    drain_connection(&db.connection, &db.path.with_extension("segments"), limit)
}
pub(in crate::account_db) fn drain_connection(
    db: &Connection,
    root: &Path,
    limit: usize,
) -> Result<(), StorageError> {
    if root.try_exists()? {
        files::private_dir(root)?;
        let root = std::fs::canonicalize(root)?;
        let _ = drain(db, &root, None, limit)?;
    }
    Ok(())
}

fn drain(
    db: &Connection,
    root: &Path,
    only: Option<&Path>,
    limit: usize,
) -> Result<SegmentCleanupPage, StorageError> {
    if limit == 0 || limit > 32 {
        return Err(StorageError::Integrity("segment cleanup limit"));
    }
    let mut q=db.prepare("SELECT directory,generation FROM object_segment_resource WHERE retired=1 AND directory>=?1 ORDER BY directory,generation LIMIT ?2")?;
    let start = only.and_then(Path::file_name).and_then(|s| s.to_str()).unwrap_or("");
    let rows = q
        .query_map(params![start, limit + 1], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut result = SegmentCleanupPage { more: rows.len() > limit, ..Default::default() };
    for (dir, generation) in rows.into_iter().take(limit) {
        let parent = root.join(&dir);
        if only.is_some_and(|p| p != parent) {
            break;
        }
        if !ramflux_protocol::decode_base64url(&dir).is_ok_and(|b| b.len() == 32)
            || dir.contains('/')
            || dir.contains('\\')
            || generation <= 0
        {
            return Err(StorageError::Integrity("segment cleanup identity"));
        }
        let _held = match lease::Lease::acquire(parent.clone()) {
            Ok(v) => v,
            Err(StorageError::AccountWriterBusy(_)) => {
                result.busy += 1;
                continue;
            }
            Err(e) => return Err(e),
        };
        let path = parent.join(generation.to_string());
        if path.try_exists()? {
            if !std::fs::symlink_metadata(&parent)?.is_dir()
                || !std::fs::symlink_metadata(&path)?.is_dir()
            {
                return Err(StorageError::Integrity("segment cleanup directory"));
            }
            std::fs::remove_dir_all(&path)?;
        }
        files::sync_dir(if parent.try_exists()? { &parent } else { root })?;
        let tx = db.immediate_transaction()?;
        db.execute("DELETE FROM object_segment_resource WHERE directory=?1 AND generation=?2 AND retired=1",params![dir,generation])?;
        tx.commit()?;
        result.deleted += 1;
    }
    Ok(result)
}
/// Both inputs' restriction rows survive, independently of resource/progress rows.
pub(in crate::account_db) fn merge_floors(db: &rusqlite::Connection) -> Result<(), StorageError> {
    for schema in ["main", "incoming"] {
        let exists:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.sqlite_master WHERE name='runtime_attachment_reference')"),[],|r|r.get(0))?;
        if exists {
            db.execute_batch(&format!("INSERT OR IGNORE INTO main.object_segment_reference_veto SELECT reference_id FROM {schema}.runtime_attachment_reference WHERE sealed=1;"))?;
        }
    }
    db.execute_batch("INSERT OR IGNORE INTO main.object_segment_reference_veto SELECT reference_id FROM incoming.object_segment_reference_veto;
INSERT INTO main.object_segment_floor SELECT directory,generation FROM incoming.object_segment_floor WHERE 1 ON CONFLICT(directory) DO UPDATE SET generation=max(generation,excluded.generation); UPDATE main.object_segment_resource SET retired=1 WHERE EXISTS(SELECT 1 FROM main.object_segment_floor f WHERE f.directory=object_segment_resource.directory AND f.generation>=object_segment_resource.generation);")?;
    Ok(())
}

pub(super) fn check_capacity(db: &Connection) -> Result<(), StorageError> {
    let count: usize =
        db.query_row("SELECT count(*) FROM object_segment_resource", [], |r| r.get(0))?;
    if count >= RESOURCE_LIMIT {
        return Err(StorageError::SegmentResourceCapacity { limit: RESOURCE_LIMIT });
    }
    Ok(())
}
