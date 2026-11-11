// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::pairing::full_transfer::{CellType, U64};
use std::io::Cursor;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn header(family: &str, key: &str, length: u64) -> RecordHeader {
    RecordHeader {
        family: family.into(),
        codec_version: U64(1),
        key: key.into(),
        op: RecordOp::Put,
        cell_types: vec![CellType::Bytes],
        cell_lengths: vec![U64(length)],
    }
}
fn record(out: &mut Vec<u8>, family: &str, key: &str, body: &[u8]) -> Result<(), StreamError> {
    write_record_header(
        out,
        &header(family, key, u64::try_from(body.len()).map_err(|_| WireError::Size)?),
    )?;
    out.extend_from_slice(body);
    Ok(())
}
fn classify(header: &RecordHeader) -> Result<bool, StreamError> {
    if header.codec_version.0 != 1 || header.cell_types != [CellType::Bytes] {
        return Err(WireError::Field("SchemaMismatch").into());
    }
    match header.family.as_str() {
        "content" => Ok(false),
        "restriction" => Ok(true),
        _ => Err(WireError::Field("UnsupportedRecord").into()),
    }
}
#[test]
fn full_snapshot_diff_emits_changed_new_and_absent_but_never_lifts_restrictions() -> TestResult {
    let mut previous = Vec::new();
    let mut current = Vec::new();
    for (key, body) in
        [("a", b"old".as_slice()), ("b", b"same".as_slice()), ("c", b"deleted".as_slice())]
    {
        record(&mut previous, "content", key, body)?;
    }
    record(&mut previous, "restriction", "veto", b"retained denial")?;
    for (key, body) in
        [("a", b"changed".as_slice()), ("b", b"same".as_slice()), ("d", b"new".as_slice())]
    {
        record(&mut current, "content", key, body)?;
    }
    let mut delta = Vec::new();
    let stats = diff_snapshots(Cursor::new(previous), Cursor::new(current), &mut delta, classify)?;
    assert_eq!((stats.puts, stats.absent), (2, 1));
    assert_eq!(stats.encoded_bytes, u64::try_from(delta.len())?);
    let mut reader = delta.as_slice();
    let mut seen = Vec::new();
    while let Some(header) = read_record_header(&mut reader)? {
        let mut body = Vec::new();
        copy_record_cells(&mut reader, &mut body, &header)?;
        seen.push((header.family, header.key, header.op, body));
    }
    assert_eq!(
        seen,
        vec![
            ("content".into(), "a".into(), RecordOp::Put, b"changed".to_vec()),
            ("content".into(), "c".into(), RecordOp::Absent, Vec::new()),
            ("content".into(), "d".into(), RecordOp::Put, b"new".to_vec())
        ]
    );
    Ok(())
}
#[test]
fn full_snapshot_diff_refuses_unknown_or_duplicate_keys_and_truncated_cells() -> TestResult {
    let mut known = Vec::new();
    record(&mut known, "content", "key", b"exact")?;
    let mut output = Vec::new();
    assert_eq!(
        diff_snapshots(Cursor::new(&known), Cursor::new(&known), &mut output, classify)?,
        DiffStats::default()
    );
    let mut unknown = Vec::new();
    record(&mut unknown, "unclassified", "key", b"data")?;
    assert!(diff_snapshots(Cursor::new([]), Cursor::new(unknown), &mut output, classify).is_err());
    let mut duplicate = known.clone();
    duplicate.extend_from_slice(&known);
    assert!(
        diff_snapshots(Cursor::new([]), Cursor::new(duplicate), &mut output, classify).is_err()
    );
    known.pop();
    assert!(diff_snapshots(Cursor::new([]), Cursor::new(known), &mut output, classify).is_err());
    Ok(())
}
struct VirtualRecord {
    header: Vec<u8>,
    length: u64,
    position: u64,
}
impl Read for VirtualRecord {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let total = u64::try_from(self.header.len())
            .map_err(|_| std::io::ErrorKind::InvalidData)?
            + self.length;
        let amount = usize::try_from(
            (total - self.position)
                .min(u64::try_from(out.len()).map_err(|_| std::io::ErrorKind::InvalidData)?),
        )
        .map_err(|_| std::io::ErrorKind::InvalidData)?;
        for byte in &mut out[..amount] {
            *byte = usize::try_from(self.position)
                .ok()
                .and_then(|pos| self.header.get(pos))
                .copied()
                .unwrap_or(7);
            self.position += 1;
        }
        Ok(amount)
    }
}
impl Seek for VirtualRecord {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let total = u64::try_from(self.header.len())
            .map_err(|_| std::io::ErrorKind::InvalidData)?
            + self.length;
        let offset = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(total) + i128::from(value),
        };
        if offset < 0 || offset > i128::from(total) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.position = u64::try_from(offset).map_err(|_| std::io::ErrorKind::InvalidData)?;
        Ok(self.position)
    }
}
#[derive(Default)]
struct Count {
    total: u64,
    largest: usize,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.total += u64::try_from(bytes.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
        self.largest = self.largest.max(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn full_snapshot_diff_rereads_huge_cells_without_row_sized_memory() -> TestResult {
    let mut prefix = Vec::new();
    write_record_header(&mut prefix, &header("content", "large", 5_242_883))?;
    let expected = 5_242_883 + u64::try_from(prefix.len())?;
    let input = VirtualRecord { header: prefix, length: 5_242_883, position: 0 };
    let mut output = Count::default();
    let stats = diff_snapshots(Cursor::new([]), input, &mut output, classify)?;
    assert_eq!(stats.puts, 1);
    assert_eq!(stats.encoded_bytes, expected);
    assert_eq!(output.total, expected);
    assert!(output.largest <= 16_384);
    Ok(())
}
