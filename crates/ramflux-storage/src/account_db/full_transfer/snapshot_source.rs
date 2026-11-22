// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A-side encoder of the snapshot family. Each cut is sanitized once; its file and key stay
//! in A's encrypted stage so a re-encode yields the exact bytes the source signed.
use super::{
    FullBaseSourceEncoding, full_transfer_catalog, snapshot, source_base::Rooted,
    source_owner::SourceContext,
};
use crate::{AccountDbKey, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{U64, chunk_layout};
use std::{io::Write, path::PathBuf};
use zeroize::Zeroizing;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS snapshot_file(cut INTEGER NOT NULL CHECK(cut BETWEEN 0 AND 9),snapshot_id TEXT NOT NULL,filename TEXT NOT NULL UNIQUE,snapshot_key BLOB NOT NULL CHECK(length(snapshot_key)=32),PRIMARY KEY(cut,snapshot_id));";

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

impl SourceContext<'_> {
    /// The sanitized copy of one saved cut, created on first use and reused afterwards.
    fn sanitized_cut(
        &self,
        cut: u64,
        snapshot_id: &str,
    ) -> Result<(PathBuf, AccountDbKey), StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        let id = snapshot_id.to_owned();
        let saved = self.connection.call(move |db| {
            use rusqlite::OptionalExtension as _;
            db.query_row(
                "SELECT filename,snapshot_key FROM snapshot_file WHERE cut=?1 AND snapshot_id=?2",
                rusqlite::params![cut, id],
                |row| Ok((row.get::<_, String>(0)?, Zeroizing::new(row.get::<_, Vec<u8>>(1)?))),
            )
            .optional()
        })?;
        if let Some((filename, bytes)) = saved {
            let raw = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid())?;
            return Ok((self.directory.join(filename), AccountDbKey::from_bytes(raw)));
        }
        super::stage::raw32(snapshot_id)?;
        let filename = format!("snapshot-{cut}-{snapshot_id}.db");
        let path = self.directory.join(&filename);
        if std::fs::symlink_metadata(&path).is_ok() {
            // An unrecorded file is an interrupted earlier attempt; never reuse it.
            std::fs::remove_file(&path)?;
        }
        let destination = path.clone();
        let written = self.with_source_cut(cut, snapshot_id, move |input| {
            input.call(move |db| Ok(snapshot::write_sanitized(db, &destination)))?
        });
        let key = match written {
            Ok(key) => key,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(error);
            }
        };
        let raw = Zeroizing::new(*key.bytes());
        let id = snapshot_id.to_owned();
        self.connection.call(move |db| {
            db.execute(
                "INSERT INTO snapshot_file(cut,snapshot_id,filename,snapshot_key) VALUES(?1,?2,?3,?4)",
                rusqlite::params![cut, id, filename, raw.as_slice()],
            )
        })?;
        crate::sync_path::sync_path(self.directory)?;
        Ok((path, key))
    }

    /// Encode one cut as the framed sanitized snapshot. The root covers every output byte.
    /// # Errors
    /// Refuses unclassified data, a self-scan hit, a changed cut, quota or output failure.
    pub(super) fn encode_snapshot_cut<W: Write + Send + 'static>(
        &mut self,
        cut: u64,
        snapshot_id: &str,
        writer: W,
        wire: bool,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        let mut schema = self.source_cut_schema(cut, snapshot_id, full_transfer_catalog())?;
        let (storage_generation, source_erasure_generation) =
            self.with_source_cut(cut, snapshot_id, |input| {
                Ok((
                    input.query_row(
                        "SELECT max(schema_version) FROM schema_migration",
                        [],
                        |row| row.get::<_, u64>(0),
                    )?,
                    input.query_row(
                        "SELECT generation FROM account_erasure_generation WHERE singleton=1",
                        [],
                        |row| row.get::<_, u64>(0),
                    )?,
                ))
            })?;
        let (path, key) = self.sanitized_cut(cut, snapshot_id)?;
        let length = std::fs::metadata(&path)?.len();
        let total = snapshot::FRAME_HEADER.checked_add(length).ok_or_else(invalid)?;
        let [family] = schema.families.as_mut_slice() else {
            return Err(invalid());
        };
        family.portable_records = U64(1);
        family.encoded_bytes = U64(total);
        let mut output = Rooted::new(writer, total)?;
        if wire {
            output = output.with_wire(self.wire_spool(cut, snapshot_id)?);
        }
        if snapshot::write_frame(&mut output, &key, &path)? != total {
            return Err(invalid());
        }
        let (writer, root) = output.finish(total)?;
        self.require_source_live()?;
        Ok((
            writer,
            FullBaseSourceEncoding {
                schema,
                storage_generation,
                source_erasure_generation,
                total_bytes: total,
                chunk_count: chunk_layout(total).map_err(|_| invalid())?.0,
                chunks_root: root,
            },
        ))
    }
}
