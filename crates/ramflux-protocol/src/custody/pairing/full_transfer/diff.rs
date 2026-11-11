// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministic merge-join of immutable typed logical cuts. No event-counter mutation feed.
use super::{
    RecordHeader, RecordOp, StreamError, WireError, copy_record_cells, read_record_header,
    write_record_header,
};
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct DiffStats {
    pub puts: u64,
    pub absent: u64,
    pub encoded_bytes: u64,
}
struct Record {
    header: RecordHeader,
    body_offset: u64,
    digest: [u8; 32],
    restrictive: bool,
}
struct Cut<R> {
    reader: R,
    previous: Option<(String, String)>,
    record: Option<Record>,
}
struct Digest(zeroize::Zeroizing<blake3::Hasher>);
impl Write for Digest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<R: Read + Seek> Cut<R> {
    fn next(
        &mut self,
        classify: &impl Fn(&RecordHeader) -> Result<bool, StreamError>,
    ) -> Result<(), StreamError> {
        let Some(header) = read_record_header(&mut self.reader)? else {
            self.record = None;
            return Ok(());
        };
        if header.op != RecordOp::Put {
            return Err(WireError::Field("snapshot_record").into());
        }
        let key = (header.family.clone(), header.key.clone());
        if self.previous.as_ref().is_some_and(|old| *old >= key) {
            return Err(WireError::Field("record_order").into());
        }
        let restrictive = classify(&header)?;
        let body_offset = self.reader.stream_position()?;
        if header
            .cell_lengths
            .iter()
            .try_fold(body_offset, |offset, length| offset.checked_add(length.0))
            .is_none_or(|end| end > i64::MAX.cast_unsigned())
        {
            return Err(WireError::Size.into());
        }
        let mut hash = Digest(super::integrity::framed("ramflux.pairing.full.logical_record.v1"));
        write_record_header(&mut hash, &header)?;
        copy_record_cells(&mut self.reader, &mut hash, &header)?;
        self.record = Some(Record {
            header,
            body_offset,
            digest: *hash.0.finalize().as_bytes(),
            restrictive,
        });
        self.previous = Some(key);
        Ok(())
    }
    fn emit(&mut self, output: &mut impl Write) -> Result<(), StreamError> {
        let record = self.record.as_ref().ok_or(WireError::Field("snapshot_record"))?;
        self.reader.seek(SeekFrom::Start(record.body_offset))?;
        write_record_header(output, &record.header)?;
        copy_record_cells(&mut self.reader, output, &record.header)
    }
}
struct Counted<'a, W> {
    inner: &'a mut W,
    total: u64,
}
impl<W: Write> Write for Counted<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let amount = u64::try_from(bytes.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
        if self.total.checked_add(amount).is_none_or(|total| total > i64::MAX.cast_unsigned()) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let written = self.inner.write(bytes)?;
        self.total += u64::try_from(written).map_err(|_| std::io::ErrorKind::InvalidData)?;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
fn key(record: &Record) -> (&str, &str) {
    (&record.header.family, &record.header.key)
}

/// Diff two immutable encrypted-snapshot logical views into an encrypted private-stage writer.
/// `classify` must check the compiled codec/column shape and return its restrictive flag.
/// Stable keys identify source contributions; native semantic duplicate IDs merge later.
/// Source views may seek/re-read cells, but never materialize a whole cell/row in memory.
/// # Errors
/// Refuses unknown/malformed/unordered input, nonfinite floats, invalid UTF-8, truncation,
/// signed-offset overflow and I/O errors. Partial private output must be discarded by its owner.
pub fn diff_snapshots<P: Read + Seek, C: Read + Seek, W: Write>(
    previous: P,
    current: C,
    output: &mut W,
    classify: impl Fn(&RecordHeader) -> Result<bool, StreamError>,
) -> Result<DiffStats, StreamError> {
    let mut previous = Cut { reader: previous, previous: None, record: None };
    let mut current = Cut { reader: current, previous: None, record: None };
    let mut output = Counted { inner: output, total: 0 };
    let mut stats = DiffStats::default();
    previous.next(&classify)?;
    current.next(&classify)?;
    while previous.record.is_some() || current.record.is_some() {
        let order = match (&previous.record, &current.record) {
            (Some(a), Some(b)) => key(a).cmp(&key(b)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => break,
        };
        match order {
            std::cmp::Ordering::Less => {
                let record = previous.record.as_ref().ok_or(WireError::Field("snapshot_record"))?;
                if !record.restrictive {
                    let mut absent = record.header.clone();
                    absent.op = RecordOp::Absent;
                    absent.cell_types.clear();
                    absent.cell_lengths.clear();
                    write_record_header(&mut output, &absent)?;
                    stats.absent += 1;
                }
                previous.next(&classify)?;
            }
            std::cmp::Ordering::Greater => {
                current.emit(&mut output)?;
                stats.puts += 1;
                current.next(&classify)?;
            }
            std::cmp::Ordering::Equal => {
                if previous.record.as_ref().map(|r| r.digest)
                    != current.record.as_ref().map(|r| r.digest)
                {
                    current.emit(&mut output)?;
                    stats.puts += 1;
                }
                previous.next(&classify)?;
                current.next(&classify)?;
            }
        }
    }
    stats.encoded_bytes = output.total;
    Ok(stats)
}

#[cfg(test)]
mod tests;
