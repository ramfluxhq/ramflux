// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A bounded view of authenticated encrypted slots; no plaintext staging file.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{
    CHUNK_BYTES, SourceManifest, chunk_digest,
};
use rusqlite::params;
use std::io::{self, Read, Seek, SeekFrom};
use zeroize::{Zeroize as _, Zeroizing};

/// Reads at most one decrypted chunk at a time from this stage's forward stream.
/// Root verification is necessary for opening, but does not certify logical records,
/// application, `DataVerified`, publication or endpoint tail admission.
pub struct FullForwardReader<'stage, 'db> {
    stage: &'stage FullTransferStage<'db>,
    manifest: SourceManifest,
    hash: String,
    position: u64,
    cached_index: Option<u64>,
    cache: Zeroizing<Vec<u8>>,
    failed: bool,
}
impl<'db> FullTransferStage<'db> {
    /// Recompute the retained root and open a guarded, seekable logical input stream.
    /// # Errors
    /// Refuses incomplete/corrupt slots, a stale unlock or a mismatched root.
    pub fn forward_reader(&self, hash: &str) -> Result<FullForwardReader<'_, 'db>, StorageError> {
        self.verify_forward_root(hash)?;
        Ok(FullForwardReader {
            stage: self,
            manifest: self.forward_manifest(hash)?,
            hash: hash.into(),
            position: 0,
            cached_index: None,
            cache: Zeroizing::new(Vec::new()),
            failed: false,
        })
    }
}
impl FullForwardReader<'_, '_> {
    fn guard(&mut self) -> io::Result<()> {
        if self.failed || self.stage.db.require_full_stage_unlock().is_err() {
            return self.fail();
        }
        Ok(())
    }
    fn fail<T>(&mut self) -> io::Result<T> {
        self.cache.zeroize();
        self.cached_index = None;
        self.failed = true;
        Err(io::Error::new(io::ErrorKind::InvalidData, "full-transfer stage input refused"))
    }
    fn load(&mut self, index: u64) -> io::Result<()> {
        if self.cached_index == Some(index) {
            return Ok(());
        }
        self.cache.zeroize();
        self.cached_index = None;
        let retained = self.stage.connection.query_row(
            "SELECT length,digest FROM chunk WHERE direction=0 AND manifest_hash=?1 AND idx=?2",
            params![self.hash, index],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, [u8; 32]>(1)?)),
        );
        let Ok((length, digest)) = retained else { return self.fail() };
        let chunk = self.stage.read_forward_chunk(&self.manifest, &self.hash, index, length);
        let Ok(chunk) = chunk else { return self.fail() };
        if !chunk_digest(index, &chunk).is_ok_and(|actual| actual == digest) {
            return self.fail();
        }
        self.cache = chunk;
        self.cached_index = Some(index);
        Ok(())
    }
}
impl Read for FullForwardReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.guard()?;
        if output.is_empty() || self.position == self.manifest.manifest.total_bytes.0 {
            return Ok(0);
        }
        self.load(self.position / u64::from(CHUNK_BYTES))?;
        let offset = usize::try_from(self.position % u64::from(CHUNK_BYTES))
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let Some(available) = self.cache.get(offset..) else { return self.fail() };
        let amount = available.len().min(output.len());
        if amount == 0 {
            return self.fail();
        }
        output[..amount].copy_from_slice(&available[..amount]);
        self.position += amount as u64;
        Ok(amount)
    }
}
impl Seek for FullForwardReader<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.guard()?;
        let length = self.manifest.manifest.total_bytes.0;
        let target = match from {
            SeekFrom::Start(value) => Some(value),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => length.checked_add_signed(delta),
        };
        let Some(target) = target.filter(|value| *value <= length) else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        self.position = target;
        Ok(target)
    }
}
