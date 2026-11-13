// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded decrypt-only reverse reader, independent of the ordinary account DB owner.
use super::{SourceGuard, SourceManifest, StorageError, mismatch};
use crate::{
    account_db::full_transfer::{
        EncryptedStageChunk,
        keys::FullChunkReadKey,
        stage::{open_regular, raw32},
    },
    database::Connection,
};
use ramflux_protocol::custody::pairing::full_transfer::{CHUNK_BYTES, RootHasher, chunk_digest};
use std::{
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
};
use zeroize::{Zeroize as _, Zeroizing};
pub(super) struct Reader {
    connection: Connection,
    _lock: std::fs::File,
    directory: PathBuf,
    key: FullChunkReadKey,
    manifest: SourceManifest,
    hash: String,
    guard: SourceGuard,
    position: u64,
    cached: Option<u64>,
    cache: Zeroizing<Vec<u8>>,
}
pub(super) struct Inputs {
    pub(super) connection: Connection,
    pub(super) lock: std::fs::File,
    pub(super) directory: PathBuf,
    pub(super) key: FullChunkReadKey,
}
impl Reader {
    pub(super) fn new(
        inputs: Inputs,
        manifest: SourceManifest,
        hash: String,
        guard: SourceGuard,
    ) -> Self {
        let Inputs { connection, lock, directory, key } = inputs;
        Self {
            connection,
            _lock: lock,
            directory,
            key,
            manifest,
            hash,
            guard,
            position: 0,
            cached: None,
            cache: Zeroizing::new(Vec::new()),
        }
    }
    fn load(&mut self, index: u64) -> Result<(), StorageError> {
        self.guard.require()?;
        if self.cached == Some(index) {
            return Ok(());
        }
        self.cache.zeroize();
        self.cached = None;
        if index >= self.manifest.manifest.chunk_count.0 {
            return Err(mismatch());
        }
        let (length, digest): (u32, [u8; 32]) = self.connection.query_row(
            "SELECT length,digest FROM chunk WHERE direction=1 AND manifest_hash=?1 AND idx=?2",
            rusqlite::params![self.hash, index],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if length == 0 || length > CHUNK_BYTES {
            return Err(mismatch());
        }
        let path = self.directory.join(format!("seg-r-0-{}.bin", index / 256));
        let mut file = open_regular(&path, false)?;
        file.seek(SeekFrom::Start((index % 256) * 262_172))?;
        let mut bytes = Zeroizing::new(vec![0; length as usize + 28]);
        file.read_exact(&mut bytes)?;
        self.cache = self.key.open(index, length, &EncryptedStageChunk::from_file_bytes(bytes)?)?;
        if chunk_digest(index, &self.cache).map_err(|_| mismatch())? != digest {
            self.cache.zeroize();
            return Err(mismatch());
        }
        self.cached = Some(index);
        self.guard.require()
    }
    pub(super) fn verify_root(&mut self) -> Result<(), StorageError> {
        let mut root =
            RootHasher::new(self.manifest.manifest.total_bytes.0).map_err(|_| mismatch())?;
        for index in 0..self.manifest.manifest.chunk_count.0 {
            self.load(index)?;
            root.push(index, &self.cache).map_err(|_| mismatch())?;
        }
        if root.finish().map_err(|_| mismatch())? != raw32(&self.manifest.manifest.chunks_root)? {
            return Err(mismatch());
        }
        self.position = 0;
        self.cache.zeroize();
        self.cached = None;
        self.guard.require()
    }
}
fn io_error(_: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "full reverse input refused")
}
impl Read for Reader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.guard.require().map_err(io_error)?;
        if output.is_empty() || self.position == self.manifest.manifest.total_bytes.0 {
            return Ok(0);
        }
        let index = self.position / u64::from(CHUNK_BYTES);
        let offset = usize::try_from(self.position % u64::from(CHUNK_BYTES)).map_err(io_error)?;
        self.load(index).map_err(io_error)?;
        let available = self.cache.get(offset..).ok_or_else(|| io_error("offset"))?;
        let length = output.len().min(available.len());
        if length == 0 {
            return Err(io_error("empty slot"));
        }
        output
            .get_mut(..length)
            .ok_or_else(|| io_error("output"))?
            .copy_from_slice(available.get(..length).ok_or_else(|| io_error("input"))?);
        self.position += length as u64;
        Ok(length)
    }
}
impl Seek for Reader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.guard.require().map_err(io_error)?;
        let total = self.manifest.manifest.total_bytes.0;
        let position = match from {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => total.checked_add_signed(delta),
        };
        let position =
            position.filter(|position| *position <= total).ok_or_else(|| io_error("seek"))?;
        self.position = position;
        Ok(position)
    }
}
