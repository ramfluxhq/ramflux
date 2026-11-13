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

/// Reads at most one decrypted chunk at a time from an authenticated directional stream.
/// Root verification is necessary for opening, but does not certify logical records,
/// application, `DataVerified`, publication or endpoint tail admission.
pub struct FullForwardReader<'stage, 'db> {
    stage: &'stage FullTransferStage<'db>,
    manifest: SourceManifest,
    hash: String,
    direction: u8,
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
            direction: 0,
            position: 0,
            cached_index: None,
            cache: Zeroizing::new(Vec::new()),
            failed: false,
        })
    }
}
impl<'db> FullTransferStage<'db> {
    pub(super) fn validated_tail_reader(
        &self,
        hash: &str,
    ) -> Result<FullForwardReader<'_, 'db>, StorageError> {
        self.require_validated_tail_input(hash)?;
        Ok(FullForwardReader {
            stage: self,
            manifest: self.forward_manifest(hash)?,
            hash: hash.into(),
            direction: 0,
            position: 0,
            cached_index: None,
            cache: Zeroizing::new(Vec::new()),
            failed: false,
        })
    }
    pub(super) fn validated_reverse_reader(
        &self,
        hash: &str,
    ) -> Result<FullForwardReader<'_, 'db>, StorageError> {
        self.require_validated_reverse_input(hash)?;
        Ok(FullForwardReader {
            stage: self,
            manifest: self.reverse_manifest(hash)?,
            hash: hash.into(),
            direction: 1,
            position: 0,
            cached_index: None,
            cache: Zeroizing::new(Vec::new()),
            failed: false,
        })
    }
    /// Read the independently authenticated reverse stream with one bounded plaintext chunk.
    /// This verifies bytes/root only; actual A union commit must precede any signed DV.
    /// # Errors
    /// Refuses incomplete/torn reverse slots, a changed local unlock or a foreign manifest.
    pub fn reverse_reader(&self, hash: &str) -> Result<FullForwardReader<'_, 'db>, StorageError> {
        self.verify_reverse_root(hash)?;
        Ok(FullForwardReader {
            stage: self,
            manifest: self.reverse_manifest(hash)?,
            hash: hash.into(),
            direction: 1,
            position: 0,
            cached_index: None,
            cache: Zeroizing::new(Vec::new()),
            failed: false,
        })
    }
}
impl FullForwardReader<'_, '_> {
    fn guard(&mut self) -> io::Result<()> {
        if self.failed || self.stage.require_io().is_err() {
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
            "SELECT length,digest FROM chunk WHERE direction=?3 AND manifest_hash=?1 AND idx=?2",
            params![self.hash, index, self.direction],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, [u8; 32]>(1)?)),
        );
        let Ok((length, digest)) = retained else { return self.fail() };
        let chunk = if self.direction == 0 {
            self.stage.read_forward_chunk(&self.manifest, &self.hash, index, length)
        } else {
            self.stage.read_reverse_chunk(&self.manifest, &self.hash, index, length)
        };
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
