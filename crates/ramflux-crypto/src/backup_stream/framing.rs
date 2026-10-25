// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sequential AEAD frames with a nonce-bound final marker and strict physical EOF.

use super::{BackupStreamError, CHUNK_SIZE, TAG_SIZE};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

fn nonce(prefix: &[u8], counter: u64, last: bool) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..15].copy_from_slice(prefix);
    nonce[15..23].copy_from_slice(&counter.to_be_bytes());
    nonce[23] = u8::from(last);
    nonce
}

fn fill(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut used = 0;
    while used < buffer.len() {
        match input.read(&mut buffer[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(used)
}

pub(super) fn encrypt_chunks(
    input: &mut impl Read,
    output: &mut impl Write,
    key: &[u8; 32],
    prefix: &[u8],
    aad: &[u8],
) -> Result<u64, BackupStreamError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut counter = 0_u64;
    let mut total = 0_u64;
    let mut buffer = Zeroizing::new(vec![0; CHUNK_SIZE + TAG_SIZE]);
    loop {
        buffer.resize(CHUNK_SIZE, 0);
        let count = fill(input, &mut buffer)?;
        buffer.truncate(count);
        let last = count < CHUNK_SIZE;
        cipher
            .encrypt_in_place(XNonce::from_slice(&nonce(prefix, counter, last)), aad, &mut *buffer)
            .map_err(|_| BackupStreamError::Authentication)?;
        let length = u32::try_from(buffer.len())
            .map_err(|_| BackupStreamError::Invalid("chunk length overflow"))?;
        output.write_all(&length.to_be_bytes())?;
        output.write_all(&[u8::from(last)])?;
        output.write_all(&buffer)?;
        total = total
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| BackupStreamError::Invalid("chunk length overflow"))?,
            )
            .ok_or(BackupStreamError::Invalid("archive length overflow"))?;
        if last {
            return Ok(total);
        }
        counter =
            counter.checked_add(1).ok_or(BackupStreamError::Invalid("chunk counter exhausted"))?;
    }
}

pub(super) fn decrypt_chunks(
    input: &mut impl Read,
    output: &mut impl Write,
    key: &[u8; 32],
    prefix: &[u8],
    aad: &[u8],
) -> Result<u64, BackupStreamError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut counter = 0_u64;
    let mut total = 0_u64;
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE));
    loop {
        let mut framing = [0; 5];
        input.read_exact(&mut framing)?;
        let size = u32::from_be_bytes([framing[0], framing[1], framing[2], framing[3]]) as usize;
        let last = match framing[4] {
            0 => false,
            1 => true,
            _ => return Err(BackupStreamError::Invalid("final marker")),
        };
        if !(TAG_SIZE..=CHUNK_SIZE + TAG_SIZE).contains(&size)
            || (!last && size != CHUNK_SIZE + TAG_SIZE)
            || (last && size == CHUNK_SIZE + TAG_SIZE)
        {
            return Err(BackupStreamError::Invalid("chunk length"));
        }
        // Erase the previous plaintext before a shorter final frame shrinks the Vec.
        buffer.as_mut_slice().zeroize();
        buffer.resize(size, 0);
        input.read_exact(&mut buffer)?;
        cipher
            .decrypt_in_place(XNonce::from_slice(&nonce(prefix, counter, last)), aad, &mut *buffer)
            .map_err(|_| BackupStreamError::Authentication)?;
        output.write_all(&buffer)?;
        total = total
            .checked_add(
                u64::try_from(buffer.len())
                    .map_err(|_| BackupStreamError::Invalid("chunk length overflow"))?,
            )
            .ok_or(BackupStreamError::Invalid("archive length overflow"))?;
        if last {
            let mut trailing = [0];
            if fill(input, &mut trailing)? != 0 {
                return Err(BackupStreamError::Invalid("trailing bytes"));
            }
            return Ok(total);
        }
        counter =
            counter.checked_add(1).ok_or(BackupStreamError::Invalid("chunk counter exhausted"))?;
    }
}
