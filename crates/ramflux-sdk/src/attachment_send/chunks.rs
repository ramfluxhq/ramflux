// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Idempotent plaintext log. A lost reply retries the same offset.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use super::codes::{CODE_FILE_TOO_LARGE, CODE_STREAM_CLOSED, CODE_STREAM_OFFSET, Refusal};
use super::meta::{CHUNK, MAX_PLAINTEXT, Phase, Row};

/// # Errors
/// Returns `stream_offset` for a gap or a different overlap, and `file_too_large` past 4 GiB.
pub(crate) fn accept(dir: &Path, row: &mut Row, offset: u64, bytes: &[u8]) -> Result<(), Refusal> {
    if row.phase != Phase::Accepting {
        return Err(Refusal::new(CODE_STREAM_CLOSED));
    }
    let len = u64::try_from(bytes.len()).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    if len > CHUNK || bytes.is_empty() && offset != row.accepted_through {
        return Err(Refusal::new(CODE_STREAM_OFFSET));
    }
    let end = offset.checked_add(len).ok_or(Refusal::new(CODE_STREAM_OFFSET))?;
    if end > MAX_PLAINTEXT {
        return Err(Refusal::new(CODE_FILE_TOO_LARGE));
    }
    let path = dir.join("plain.bin");
    if offset == row.accepted_through {
        append(&path, bytes)?;
        row.accepted_through = end;
        return Ok(());
    }
    if end <= row.accepted_through {
        let stored = read_range(&path, offset, bytes.len())?;
        if stored == bytes {
            return Ok(());
        }
        return Err(Refusal::new(CODE_STREAM_OFFSET));
    }
    Err(Refusal::new(CODE_STREAM_OFFSET))
}

pub(crate) fn read_range(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, Refusal> {
    let mut file = File::open(path).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    file.seek(SeekFrom::Start(offset)).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    let mut out = vec![0_u8; len];
    file.read_exact(&mut out).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    Ok(out)
}

fn append(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    let created = !path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    file.write_all(bytes).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    file.sync_all().map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    if created {
        super::store::sync_parent(path)?;
    }
    Ok(())
}

pub(crate) fn truncate(path: &Path, len: u64) -> Result<(), Refusal> {
    let file =
        OpenOptions::new().write(true).open(path).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    file.set_len(len).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    file.sync_all().map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    Ok(())
}

pub(crate) fn digest(path: &Path, len: u64) -> Result<[u8; 32], Refusal> {
    let mut file = File::open(path).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    let mut hasher = blake3::Hasher::new();
    let mut left = len;
    let mut buf = vec![0_u8; 64 * 1024];
    while left > 0 {
        let take = buf.len().min(usize::try_from(left).unwrap_or(buf.len()));
        let n = file.read(&mut buf[..take]).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
        if n == 0 {
            return Err(Refusal::new(CODE_STREAM_OFFSET));
        }
        hasher.update(&buf[..n]);
        let read = u64::try_from(n).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
        left -= read;
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn remove_plain(dir: &Path) {
    let _ = fs::remove_file(dir.join("plain.bin"));
}
