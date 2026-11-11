// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fair, bounded reparse snapshots. A snapshot never grants permission to write.
use super::RawInnerCopy;
use crate::{AccountDb, StorageError};
use rusqlite::{OptionalExtension, params};

const PAGE_ROWS: usize = 32;
const PAGE_BYTES: usize = 4 * 1024 * 1024;
type CurrentRawCopy = (Vec<u8>, Vec<u8>, String, Vec<u8>, String);

/// Exact retained copy and its receive-time authenticated provenance.
#[derive(Clone, Debug)]
pub struct RawInnerReparseRow {
    pub copy: RawInnerCopy,
    pub source_anchor: String,
    pub metadata: Vec<u8>,
    pub erasure_generation: i64,
    pub attempted_decoder: String,
}

impl AccountDb {
    /// Reads at most 32 rows / 4 MiB, interleaving verified source roots.
    /// Copies attempted by this decoder are durably excluded, including after restart.
    /// No network request or raw reconstruction is performed.
    /// # Errors
    /// Refuses an invalid decoder marker and returns storage errors.
    pub fn raw_inner_reparse_page(
        &self,
        decoder: &str,
    ) -> Result<Vec<RawInnerReparseRow>, StorageError> {
        super::writer::validate_id(decoder)?;
        let erasure_generation = self.privacy_erasure_generation()?;
        let decoder = decoder.to_owned();
        let handles = self.connection.call(move |db| {
            let mut query = db.prepare(
                "SELECT copy_id FROM (
                    SELECT c.copy_id,o.source_anchor,
                      row_number() OVER (PARTITION BY o.source_anchor ORDER BY c.copy_id) AS position
                    FROM raw_inner_copy c JOIN raw_inner_owner o USING(owner_id)
                    WHERE c.attempted_decoder<>?1
                 ) ORDER BY position,source_anchor,copy_id LIMIT 32",
            )?;
            query.query_map([decoder], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        let mut bytes = 0_usize;
        let mut page = Vec::with_capacity(PAGE_ROWS);
        for handle in handles {
            let Some(copy) = self.raw_inner_copy(&handle)? else { continue };
            let next =
                bytes.checked_add(copy.bytes.len()).ok_or(StorageError::AuthorizationRejected)?;
            if next > PAGE_BYTES {
                break;
            }
            let owner = copy.owner_id.clone();
            let copy_id = copy.copy_id.clone();
            let provenance = self.connection.call(move |db| {
                db.query_row(
                    "SELECT o.source_anchor,c.copy_metadata,c.attempted_decoder FROM raw_inner_owner o JOIN raw_inner_copy c USING(owner_id) WHERE o.owner_id=?1 AND c.copy_id=?2",
                    params![owner,copy_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?,row.get::<_,String>(2)?)),
                )
                .optional()
            })?;
            if let Some((source_anchor, metadata, attempted_decoder)) = provenance {
                bytes = next;
                page.push(RawInnerReparseRow {
                    copy,
                    source_anchor,
                    metadata,
                    erasure_generation,
                    attempted_decoder,
                });
            }
        }
        Ok(page)
    }

    /// Rechecks the snapshot and both sticky deletion fences on the open writer.
    /// Must be called with projection/linkage updates in the same caller transaction.
    /// # Errors
    /// Refuses a missing transaction or changed provenance; returns SQL errors.
    pub fn raw_inner_reparse_is_current(
        &self,
        snapshot: &RawInnerReparseRow,
        message_id: &str,
    ) -> Result<bool, StorageError> {
        let copy = snapshot.copy.clone();
        let source = snapshot.source_anchor.clone();
        let metadata = snapshot.metadata.clone();
        let message = message_id.to_owned();
        let generation = snapshot.erasure_generation;
        let attempted_decoder = snapshot.attempted_decoder.clone();
        self.connection
            .call(move |db| {
                let check = || {
                    if db.is_autocommit() {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    let current_generation: i64 = db.query_row(
                        "SELECT generation FROM account_erasure_generation WHERE singleton=1",
                        [],
                        |row| row.get(0),
                    )?;
                    if generation != current_generation {
                        return Ok(false);
                    }
                    if super::writer::raw_copy_deleted(db, &copy.copy_id)?
                        || super::super::deleted_messages::message_is_deleted_on(
                            db,
                            &copy.owner_id,
                        )?
                        || super::super::deleted_messages::message_is_deleted_on(db, &message)?
                    {
                        return Ok(false);
                    }
                    let current: Option<CurrentRawCopy> = db
                        .query_row(
                            "SELECT c.raw_digest,c.raw_bytes,o.source_anchor,c.copy_metadata,c.attempted_decoder
                     FROM raw_inner_copy c JOIN raw_inner_owner o USING(owner_id)
                     WHERE c.copy_id=?1 AND c.owner_id=?2",
                            params![copy.copy_id, copy.owner_id],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,row.get(4)?)),
                        )
                        .optional()?;
                    Ok(current.is_some_and(|(digest, bytes, anchor, provenance, attempted)| {
                        digest == copy.digest
                            && bytes == copy.bytes
                            && anchor == source
                            && provenance == metadata
                            && attempted == attempted_decoder
                    }))
                };
                Ok(check())
            })
            .map_err(StorageError::from)?
    }

    /// Persist a decoder attempt in the same writer transaction as its outcome.
    /// # Errors
    /// Refuses a missing transaction or invalid marker; returns storage errors.
    pub fn mark_raw_inner_reparse_attempted(
        &self,
        snapshot: &RawInnerReparseRow,
        decoder: &str,
    ) -> Result<bool, StorageError> {
        super::writer::validate_id(decoder)?;
        if !self.raw_inner_reparse_is_current(snapshot, &snapshot.copy.owner_id)? {
            return Ok(false);
        }
        Ok(self.connection.execute("UPDATE raw_inner_copy SET attempted_decoder=?1 WHERE copy_id=?2 AND attempted_decoder=?3",params![decoder,snapshot.copy.copy_id,snapshot.attempted_decoder])?==1)
    }

    /// Whether this decoder still has unexamined retained copies.
    /// # Errors
    /// Returns invalid marker or storage errors.
    pub fn raw_inner_reparse_pending(&self, decoder: &str) -> Result<bool, StorageError> {
        super::writer::validate_id(decoder)?;
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM raw_inner_copy WHERE attempted_decoder<>?1)",
            params![decoder],
            |row| row.get(0),
        )?)
    }

    /// Releases raw quota after the caller has bound and projected the known message.
    /// Keeps the copy locator/binding as an erasure fence for delayed writers.
    /// # Errors
    /// Refuses a missing transaction or returns SQL errors.
    pub fn finish_raw_inner_reparse(&self, copy_id: &str) -> Result<(), StorageError> {
        let copy = copy_id.to_owned();
        self.connection
            .call(move |db| {
                if db.is_autocommit() {
                    return Ok(Err(StorageError::AuthorizationRejected));
                }
                db.execute("DELETE FROM raw_inner_copy WHERE copy_id=?1", [copy])?;
                Ok(Ok(()))
            })
            .map_err(StorageError::from)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawInnerCopyKind, RawInnerCopyWrite, tests::test_db};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn reparse_pages_are_source_fair_and_bounded_by_rows_and_bytes() -> TestResult {
        let (_root, db) = test_db("reparse-pages")?;
        let bytes = vec![0x41; 128 * 1024];
        for source in ["a", "b", "c"] {
            for index in 0..16 {
                let id = format!("{source}-{index:02}");
                db.write_transaction(|| {
                    db.put_unsupported_raw_copy(RawInnerCopyWrite {
                        owner_id: &id,
                        verified_source_anchor: source,
                        copy_id: &id,
                        kind: RawInnerCopyKind::OuterInner,
                        bytes: &bytes,
                        bounded_metadata: b"{}",
                    })
                })?;
            }
        }
        let first = db.raw_inner_reparse_page("decoder-2")?;
        assert_eq!(first.len(), 32);
        assert_eq!(first.iter().map(|row| row.copy.bytes.len()).sum::<usize>(), PAGE_BYTES);
        for source in ["a", "b", "c"] {
            assert!(first.iter().filter(|row| row.source_anchor == source).count() >= 10);
        }
        let visited = first.iter().map(|row| row.copy.copy_id.clone()).collect::<Vec<_>>();
        db.write_transaction(|| -> Result<(), StorageError> {
            for row in &first {
                assert!(db.mark_raw_inner_reparse_attempted(row, "decoder-2")?);
            }
            Ok(())
        })?;
        let second = db.raw_inner_reparse_page("decoder-2")?;
        assert_eq!(second.len(), 16);
        assert!(second.iter().all(|row| !visited.contains(&row.copy.copy_id)));
        Ok(())
    }

    #[test]
    fn reparse_commit_rechecks_provenance_digest_and_deletion_generation() -> TestResult {
        let (_root, db) = test_db("reparse-commit-fences")?;
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: "owner",
                verified_source_anchor: "root",
                copy_id: "copy",
                kind: RawInnerCopyKind::OuterInner,
                bytes: b"exact",
                bounded_metadata: b"provenance",
            })
        })?;
        let row = db.raw_inner_reparse_page("decoder-2")?.pop().ok_or("snapshot")?;
        assert!(db.raw_inner_reparse_is_current(&row, "target").is_err());
        assert!(db.write_transaction(|| db.raw_inner_reparse_is_current(&row, "target"))?);
        let mut wrong = row.clone();
        wrong.copy.digest[0] ^= 1;
        assert!(!db.write_transaction(|| db.raw_inner_reparse_is_current(&wrong, "target"))?);
        let mut wrong = row.clone();
        wrong.metadata.push(0);
        assert!(!db.write_transaction(|| db.raw_inner_reparse_is_current(&wrong, "target"))?);
        let mut wrong = row.clone();
        wrong.erasure_generation -= 1;
        assert!(!db.write_transaction(|| db.raw_inner_reparse_is_current(&wrong, "target"))?);
        db.import_deleted_message_projection("c", "target", false, 1)?;
        assert!(!db.write_transaction(|| db.raw_inner_reparse_is_current(&row, "target"))?);
        let rejected: Result<(), StorageError> = db.write_transaction(|| {
            db.finish_raw_inner_reparse("copy")?;
            Err(StorageError::AuthorizationRejected)
        });
        assert!(rejected.is_err());
        assert!(db.raw_inner_copy("copy")?.is_some());
        db.write_transaction(|| db.finish_raw_inner_reparse("copy"))?;
        assert_eq!(db.unsupported_raw_quota(None)?.raw_bytes, 0);
        Ok(())
    }
    #[test]
    fn reparse_attempts_survive_reopen_and_progress_past_sixty_four_copies() -> TestResult {
        let (root, db) = test_db("reparse-persistent-attempts")?;
        let mut charged = 0;
        for source in ["a", "b", "c"] {
            for owner in 0..16 {
                let owner_id = format!("{source}-{owner}");
                for version in 0..2 {
                    let copy_id = format!("{owner_id}-{version}");
                    let metadata = serde_json::to_vec(&serde_json::json!({"copy":copy_id}))?;
                    charged += 1 + metadata.len();
                    db.write_transaction(|| {
                        db.put_unsupported_raw_copy(RawInnerCopyWrite {
                            owner_id: &owner_id,
                            verified_source_anchor: source,
                            copy_id: &copy_id,
                            kind: RawInnerCopyKind::OuterInner,
                            bytes: b"x",
                            bounded_metadata: &metadata,
                        })
                    })?;
                }
            }
        }
        assert_eq!(db.unsupported_raw_quota(None)?.raw_bytes, u64::try_from(charged)?);
        let first = db.raw_inner_reparse_page("decoder-2")?;
        assert_eq!(first.len(), 32);
        for row in &first {
            let metadata: serde_json::Value = serde_json::from_slice(&row.metadata)?;
            assert_eq!(
                metadata["copy"], row.copy.copy_id,
                "each received copy owns its provenance"
            );
        }
        db.write_transaction(|| -> Result<(), StorageError> {
            for row in &first {
                assert!(db.mark_raw_inner_reparse_attempted(row, "decoder-2")?);
            }
            Ok(())
        })?;
        drop(db);
        let index = crate::AccountIndex::open(&root)?;
        let db = AccountDb::open(
            &index,
            "acct",
            &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
        )?;
        let mut seen = first
            .iter()
            .map(|row| row.copy.copy_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for _ in 0..2 {
            let page = db.raw_inner_reparse_page("decoder-2")?;
            assert_eq!(page.len(), 32);
            db.write_transaction(|| -> Result<(), StorageError> {
                for row in &page {
                    assert!(
                        seen.insert(row.copy.copy_id.clone()),
                        "decoder revisited an attempted copy"
                    );
                    assert!(db.mark_raw_inner_reparse_attempted(row, "decoder-2")?);
                }
                Ok(())
            })?;
        }
        assert_eq!(seen.len(), 96);
        assert!(!db.raw_inner_reparse_pending("decoder-2")?);
        assert!(db.raw_inner_reparse_page("decoder-2")?.is_empty());
        assert_eq!(db.raw_inner_reparse_page("decoder-3")?.len(), 32);
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn reparse_attempt_and_outcome_rollback_together() -> TestResult {
        let (_root, db) = test_db("reparse-attempt-rollback")?;
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: "owner",
                verified_source_anchor: "root",
                copy_id: "copy",
                kind: RawInnerCopyKind::OuterInner,
                bytes: b"exact",
                bounded_metadata: b"copy provenance",
            })
        })?;
        let row = db.raw_inner_reparse_page("decoder-2")?.pop().ok_or("snapshot")?;
        let failure: Result<(), StorageError> = db.write_transaction(|| {
            assert!(db.mark_raw_inner_reparse_attempted(&row, "decoder-2")?);
            db.persist_actor_state("test/projection", &true)?;
            Err(StorageError::AuthorizationRejected)
        });
        assert!(failure.is_err());
        assert!(!db.actor_state_exists("test/projection")?);
        assert_eq!(db.raw_inner_reparse_page("decoder-2")?.len(), 1);
        assert!(db.write_transaction(|| db.mark_raw_inner_reparse_attempted(&row, "decoder-2"))?);
        assert!(!db.write_transaction(|| db.raw_inner_reparse_is_current(&row, "owner"))?);
        assert!(db.raw_inner_reparse_page("decoder-2")?.is_empty());
        Ok(())
    }
}
