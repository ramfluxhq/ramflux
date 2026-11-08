// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private report-opening and provenance evidence for already-known content.

use crate::{StorageError, account_db::AccountDb};
use rusqlite::{OptionalExtension, params};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownContentEvidence {
    pub provenance: Vec<u8>,
    pub report_opening: Vec<u8>,
}

impl AccountDb {
    /// Stores exact known Inner content and private evidence in the caller's transaction.
    ///
    /// The regular local-history policy owns content bytes; this API adds only the private
    /// opening/provenance record and its explicit erase locator. Callers must include this in
    /// their existing `write_transaction` and commit it with the content/projection changes.
    ///
    /// # Errors
    /// Rejects invalid or already-deleted messages, oversized evidence, and SQL failures.
    pub fn put_known_content_evidence(
        &self,
        message_id: &str,
        conversation_id: &str,
        exact_inner: &[u8],
        provenance: &[u8],
        report_opening: &[u8],
    ) -> Result<(), StorageError> {
        super::writer::validate_id(message_id)?;
        super::writer::validate_id(conversation_id)?;
        if exact_inner.is_empty()
            || exact_inner.len() > super::writer::MAX_INNER_BYTES
            || provenance.len() > 4096
            || report_opening.len() > super::writer::MAX_INNER_BYTES
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let message = message_id.to_owned();
        let conversation = conversation_id.to_owned();
        let inner = exact_inner.to_vec();
        let provenance = provenance.to_vec();
        let opening = report_opening.to_vec();
        self.connection
            .call(move |db| {
                let result = (|| {
                    if db.is_autocommit() {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    if super::writer::message_deleted(db, &message)? {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    let existing: Option<Vec<u8>> = db
                        .query_row(
                            "SELECT body FROM runtime_message_content WHERE message_id=?1",
                            [&message],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if existing.as_deref().is_some_and(|body| body != inner.as_slice()) {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    if existing.is_none() {
                        db.execute(
                            "INSERT INTO runtime_message_content(message_id,conversation_id,body) VALUES(?1,?2,?3)",
                            params![message, conversation, inner],
                        )?;
                    }
                    db.execute(
                        "INSERT INTO raw_inner_evidence(message_id,provenance,report_opening) VALUES(?1,?2,?3)
                         ON CONFLICT(message_id) DO UPDATE SET provenance=excluded.provenance,report_opening=excluded.report_opening",
                        params![message, provenance, opening],
                    )?;
                    db.execute(
                        "INSERT OR IGNORE INTO message_footprint(message_id,kind,locator) VALUES(?1,'raw_inner_evidence',?1)",
                        [&message],
                    )?;
                    Ok(())
                })();
                Ok(result)
            })
            .map_err(StorageError::from)?
    }

    /// Reads private evidence for a known message; ordinary event/bus APIs never expose it.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn known_content_evidence(
        &self,
        message_id: &str,
    ) -> Result<Option<KnownContentEvidence>, StorageError> {
        let message = message_id.to_owned();
        self.connection
            .call(move |db| {
                db.query_row(
                    "SELECT provenance,report_opening FROM raw_inner_evidence WHERE message_id=?1",
                    [message],
                    |row| {
                        Ok(KnownContentEvidence {
                            provenance: row.get(0)?,
                            report_opening: row.get(1)?,
                        })
                    },
                )
                .optional()
            })
            .map_err(StorageError::from)
    }
}
