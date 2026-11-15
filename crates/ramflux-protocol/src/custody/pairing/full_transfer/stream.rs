// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact logical framing with bounded, wiped cell scratch. No serde tree holds cell contents.
use super::{CellType, PairingWire, RecordHeader, WireError};
use std::io::{Read, Write};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("invalid full-transfer record")]
    Format(#[from] WireError),
    #[error("full-transfer stream I/O failure")]
    Io(#[from] std::io::Error),
    #[error("invalid full-transfer cell")]
    Cell,
}

/// Read one original canonical bounded header, leaving all cell bytes in the input stream.
/// # Errors
/// Rejects truncated/oversized headers, duplicate/unknown fields and noncanonical encoding.
pub fn read_record_header(reader: &mut impl Read) -> Result<Option<RecordHeader>, StreamError> {
    let mut prefix = [0_u8; 4];
    if reader.read(&mut prefix[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| WireError::Size)?;
    if length == 0 || length > RecordHeader::LIMIT {
        return Err(WireError::Size.into());
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    Ok(Some(RecordHeader::from_wire_bytes(&bytes)?))
}

/// Write only a canonical header; the typed catalog owner streams its exact cells separately.
/// # Errors
/// Rejects invalid headers and output I/O failures.
pub fn write_record_header(
    writer: &mut impl Write,
    header: &RecordHeader,
) -> Result<(), StreamError> {
    let bytes = Zeroizing::new(header.to_wire_bytes()?);
    writer.write_all(&u32::try_from(bytes.len()).map_err(|_| WireError::Size)?.to_be_bytes())?;
    writer.write_all(&bytes)?;
    Ok(())
}

/// Copy precisely this record's cells into a private encrypted owner, using 16 KiB scratch.
/// This validates physical cell grammar; semantic column/secret admission remains mandatory.
/// No cell reaches application readers until the complete staged stream is verified.
/// # Errors
/// Refuses truncation, malformed UTF-8, nonfinite floats, invalid lengths or I/O errors.
pub fn copy_record_cells(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: &RecordHeader,
) -> Result<(), StreamError> {
    header.validate()?;
    let mut scratch = Zeroizing::new([0_u8; 16_384]);
    for (kind, length) in header.cell_types.iter().zip(&header.cell_lengths) {
        if *kind == CellType::F64 {
            let mut value = Zeroizing::new([0_u8; 8]);
            reader.read_exact(value.as_mut())?;
            if !f64::from_be_bytes(*value).is_finite() {
                return Err(StreamError::Cell);
            }
            writer.write_all(value.as_ref())?;
            continue;
        }
        let mut text = Utf8Tail { bytes: Zeroizing::new([0; 4]), len: 0 };
        let mut remaining = length.0;
        while remaining > 0 {
            let amount = usize::try_from(remaining.min(16_384)).map_err(|_| WireError::Size)?;
            reader.read_exact(&mut scratch[..amount])?;
            if *kind == CellType::Utf8 {
                text.update(&scratch[..amount])?;
            }
            writer.write_all(&scratch[..amount])?;
            remaining -= u64::try_from(amount).map_err(|_| WireError::Size)?;
        }
        if text.len != 0 {
            return Err(StreamError::Cell);
        }
    }
    Ok(())
}

struct Utf8Tail {
    bytes: Zeroizing<[u8; 4]>,
    len: usize,
}
impl Utf8Tail {
    fn update(&mut self, mut bytes: &[u8]) -> Result<(), StreamError> {
        if self.len != 0 {
            let width = match self.bytes[0] {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Err(StreamError::Cell),
            };
            let amount = (width - self.len).min(bytes.len());
            self.bytes[self.len..self.len + amount].copy_from_slice(&bytes[..amount]);
            self.len += amount;
            bytes = &bytes[amount..];
            if self.len != width {
                return Ok(());
            }
            std::str::from_utf8(&self.bytes[..width]).map_err(|_| StreamError::Cell)?;
            self.len = 0;
        }
        match std::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_none() => {
                let tail = &bytes[error.valid_up_to()..];
                if tail.len() > 3 {
                    return Err(StreamError::Cell);
                }
                self.bytes[..tail.len()].copy_from_slice(tail);
                self.len = tail.len();
                Ok(())
            }
            Err(_) => Err(StreamError::Cell),
        }
    }
}
