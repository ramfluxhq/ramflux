// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable ciphertext cache of one download. Each encrypted segment is written to its own file
//! (temp file, fsync, rename, directory fsync) before the journal sets its bit. A cached segment
//! is trusted only after its digest matches the manifest; a mismatch means refetch.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use ramflux_protocol::large_attachment::{SEGMENT_BYTES, SegmentLayout};

use super::codes::{CODE_LAYOUT_INVALID, CODE_SEAL_FAILED, Refusal};

/// Largest encrypted segment the cache accepts (plaintext segment plus AEAD tag).
const MAX_CIPHER_BYTES: u64 = SEGMENT_BYTES as u64;

fn file_name(index: u32) -> String {
    format!("seg-{index:06}.bin")
}

/// Number of encrypted segments for a plaintext length.
/// # Errors
/// Returns `layout_invalid` when the length has no valid layout.
pub(crate) fn segment_count(plaintext_length: u64) -> Result<u32, Refusal> {
    let layout =
        SegmentLayout { plaintext_length, network_chunk_bytes: super::import_job::NETWORK_CHUNK };
    layout.dimensions().map(|(count, _)| count).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

/// Writes one ciphertext segment durably under its final name.
/// # Errors
/// Returns `seal_failed` when any step of the durable write fails.
pub(crate) fn write(dir: &Path, index: u32, cipher: &[u8]) -> Result<(), Refusal> {
    let final_path = dir.join(file_name(index));
    let temp_path = dir.join(format!("{}.tmp", file_name(index)));
    let mut file = File::create(&temp_path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    file.write_all(cipher).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    file.sync_all().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    drop(file);
    fs::rename(&temp_path, &final_path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}

/// Reads a cached segment back, returning it only when its digest equals `expected`. A missing,
/// oversized or mismatched file returns `None`, so the caller refetches it.
pub(crate) fn read(dir: &Path, index: u32, expected: [u8; 32]) -> Option<Vec<u8>> {
    let path = dir.join(file_name(index));
    let meta = fs::metadata(&path).ok()?;
    if meta.len() > MAX_CIPHER_BYTES {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    let digest = ramflux_crypto::large_attachment::segment_digest(&bytes).ok()?;
    (digest == expected).then_some(bytes)
}
