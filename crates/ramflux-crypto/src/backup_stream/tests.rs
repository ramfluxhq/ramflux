// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::io::{Cursor, ErrorKind};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const TEST_KEY: [u8; 32] = [37; 32];

fn context() -> BackupContext {
    BackupContext { account_id: "backup-account".into(), created_at: 1_761_350_400 }
}
fn seal(plaintext: &[u8]) -> Result<Vec<u8>, BackupStreamError> {
    let mut archive = Vec::new();
    encrypt_with_key(
        &mut Cursor::new(plaintext),
        &mut archive,
        &Header::fresh(context())?,
        &TEST_KEY,
    )?;
    Ok(archive)
}
fn open(archive: &[u8]) -> Result<Vec<u8>, BackupStreamError> {
    let mut input = Cursor::new(archive);
    let (header, aad, wrapped) = read_header(&mut input)?;
    let mut plaintext = Vec::new();
    decrypt_with_key(&mut input, &mut plaintext, header, aad, &wrapped, &TEST_KEY)?;
    Ok(plaintext)
}
fn first_frame(archive: &[u8]) -> Result<usize, BackupStreamError> {
    let mut input = Cursor::new(archive);
    read_header(&mut input)?;
    usize::try_from(input.position()).map_err(|_| BackupStreamError::Invalid("test position"))
}

#[test]
fn stream_round_trips_empty_partial_exact_and_multiple_chunks() -> TestResult {
    for size in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 3] {
        let bytes = vec![93; size];
        assert_eq!(open(&seal(&bytes)?)?, bytes);
    }
    Ok(())
}

#[test]
fn passphrase_kdf_and_random_file_key_round_trip_without_reusing_an_archive() -> TestResult {
    let mut archive = Vec::new();
    let plaintext = b"private root, contacts, history and attachment data";
    let passphrase = b"generated recovery material has at least sixteen bytes";
    let summary =
        encrypt_backup_stream(&mut Cursor::new(plaintext), &mut archive, passphrase, context())?;
    let mut restored = Vec::new();
    assert_eq!(
        decrypt_backup_stream(&mut Cursor::new(&archive), &mut restored, passphrase)?,
        summary
    );
    assert_eq!(restored, plaintext);
    let first = seal(plaintext)?;
    let second = seal(plaintext)?;
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn truncation_before_any_boundary_or_inside_final_tag_never_verifies() -> TestResult {
    let archive = seal(&vec![42; CHUNK_SIZE + 19])?;
    let first = first_frame(&archive)?;
    for length in [
        0,
        7,
        11,
        first - 1,
        first,
        first + 4,
        first + CHUNK_SIZE,
        archive.len() - 16,
        archive.len() - 1,
    ] {
        assert!(open(&archive[..length]).is_err(), "accepted truncation at {length}");
    }
    Ok(())
}

#[test]
fn reordered_duplicated_deleted_or_cross_archive_chunks_fail_authentication() -> TestResult {
    let source = vec![17; CHUNK_SIZE * 3 + 20];
    let archive = seal(&source)?;
    let other = seal(&source)?;
    let start = first_frame(&archive)?;
    let size = CHUNK_SIZE + TAG_SIZE + 5;
    let (first, second) = (&archive[start..start + size], &archive[start + size..start + 2 * size]);
    let mut reordered = archive[..start].to_vec();
    reordered.extend_from_slice(second);
    reordered.extend_from_slice(first);
    reordered.extend_from_slice(&archive[start + 2 * size..]);
    assert!(open(&reordered).is_err());
    let mut duplicate = archive[..start + size].to_vec();
    duplicate.extend_from_slice(&archive[start..]);
    assert!(open(&duplicate).is_err());
    let mut deleted = archive[..start].to_vec();
    deleted.extend_from_slice(&archive[start + size..]);
    assert!(open(&deleted).is_err());
    let other_start = first_frame(&other)?;
    let mut spliced = archive.clone();
    spliced[start..start + size].copy_from_slice(&other[other_start..other_start + size]);
    assert!(open(&spliced).is_err());
    Ok(())
}

#[test]
fn header_wrapped_key_ciphertext_and_final_marker_are_authenticated() -> TestResult {
    let archive = seal(b"private data")?;
    let first = first_frame(&archive)?;
    for offset in [12, first - 1, first + 4, first + 5, archive.len() - 1] {
        let mut altered = archive.clone();
        altered[offset] ^= 1;
        assert!(open(&altered).is_err(), "accepted altered byte at {offset}");
    }
    let mut appended = archive.clone();
    appended.push(0);
    assert!(open(&appended).is_err());
    let mut input = Cursor::new(&archive);
    let (header, aad, wrapped) = read_header(&mut input)?;
    assert!(matches!(
        decrypt_with_key(&mut input, &mut Vec::new(), header, aad, &wrapped, &[38; 32]),
        Err(BackupStreamError::Authentication)
    ));
    Ok(())
}

struct FailedWriter;
impl Write for FailedWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(ErrorKind::StorageFull.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn disk_failure_is_a_typed_error_and_never_a_successful_partial_archive() -> TestResult {
    let result = encrypt_with_key(
        &mut Cursor::new(b"data"),
        &mut FailedWriter,
        &Header::fresh(context())?,
        &TEST_KEY,
    );
    assert!(
        matches!(result, Err(BackupStreamError::Io(error)) if error.kind() == ErrorKind::StorageFull)
    );
    let archive = seal(b"data")?;
    let mut input = Cursor::new(&archive);
    let (header, aad, wrapped) = read_header(&mut input)?;
    assert!(
        matches!(decrypt_with_key(&mut input, &mut FailedWriter, header, aad, &wrapped, &TEST_KEY), Err(BackupStreamError::Io(error)) if error.kind() == ErrorKind::StorageFull)
    );
    Ok(())
}

struct BoundedRead {
    remaining: u64,
    largest_request: usize,
}
impl Read for BoundedRead {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.largest_request = self.largest_request.max(buffer.len());
        let count = buffer.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        buffer[..count].fill(71);
        self.remaining -= count as u64;
        Ok(count)
    }
}
#[test]
fn archive_size_does_not_increase_the_stream_read_buffer() -> TestResult {
    let size = (CHUNK_SIZE * 33 + 7) as u64;
    let mut input = BoundedRead { remaining: size, largest_request: 0 };
    let summary =
        encrypt_with_key(&mut input, &mut std::io::sink(), &Header::fresh(context())?, &TEST_KEY)?;
    assert_eq!(summary.plaintext_bytes, size);
    assert_eq!(input.remaining, 0);
    assert_eq!(input.largest_request, CHUNK_SIZE);
    Ok(())
}

#[test]
fn a_stale_outbound_snapshot_reuses_its_counter_and_cannot_resume_a_live_peer() -> TestResult {
    let mut sender = crate::DmSession::initiator([1; 32], [2; 32], [3; 32], [4; 32])?;
    let mut receiver = crate::DmSession::recipient([1; 32], [3; 32], [2; 32], [4; 32])?;
    let backup = sender.snapshot();
    let sent = sender.encrypt(b"sent after the backup", b"old envelope context")?;
    assert_eq!(receiver.decrypt(&sent, b"old envelope context")?, b"sent after the backup");
    let mut restored = crate::DmSession::from_snapshot(backup.clone())?;
    let replacement = restored.encrypt(b"new message after restore", b"fresh envelope context")?;
    assert_eq!(replacement.counter, sent.counter);
    assert!(receiver.decrypt(&replacement, b"fresh envelope context").is_err());
    // Fresh envelope associated data changes the derived key/nonce. Replaying the
    // old context reproduces the old encryption, so counter rollback is not a safe
    // generic restore policy even though distinct envelopes derive distinct keys.
    let mut same_context = crate::DmSession::from_snapshot(backup)?;
    let repeated = same_context.encrypt(b"sent after the backup", b"old envelope context")?;
    assert_eq!(repeated.nonce, sent.nonce);
    assert_eq!(repeated.ciphertext, sent.ciphertext);
    assert_ne!(replacement.nonce, sent.nonce);
    Ok(())
}
