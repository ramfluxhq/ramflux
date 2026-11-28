// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The bounded outer header of an MLS `PrivateMessage` (RFC 9420 6 and 6.3), read without any key.
//!
//! One shared function for every node-side check that needs `{wire_format, group_id, epoch,
//! content_type}` of an `MLSMessage` (the `dm_order` table and the group host). It reads at most
//! [`MAX_OUTER_HEADER_BYTES`] bytes, allocates only the group id, never indexes with an untrusted
//! bound, and refuses every wire format except the pure-ciphertext `PrivateMessage` (ramflux
//! refuses public messages). [`parse_private_message`] also returns the cleartext
//! `authenticated_data` that follows the content type (bounded to [`MAX_AUTHENTICATED_DATA_BYTES`]);
//! variable-length integers must be minimally encoded (RFC 9420 section 2.1.2).

/// Most bytes the parser reads: version, wire format, group id (length prefix and bytes), epoch,
/// content type.
pub(crate) const MAX_OUTER_HEADER_BYTES: usize = 64;

/// Largest `authenticated_data` the parser returns.
pub(crate) const MAX_AUTHENTICATED_DATA_BYTES: usize = 16 * 1024;

const MLS10: u16 = 1;
const WIRE_FORMAT_PRIVATE_MESSAGE: u16 = 2;

/// Content type of a `PrivateMessage` (RFC 9420 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlsContentType {
    /// Application data.
    Application,
    /// A proposal.
    Proposal,
    /// A commit.
    Commit,
}

/// The parsed outer header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MlsOuterHeader {
    /// Wire format code point (always 2, `PrivateMessage`).
    pub(crate) wire_format: u16,
    /// Group id.
    pub(crate) group_id: Vec<u8>,
    /// Epoch the message was protected at.
    pub(crate) epoch: u64,
    /// Content type.
    pub(crate) content_type: MlsContentType,
}

/// Why a header was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MlsHeaderError {
    /// The message ends inside the header, or the header does not fit the 64 byte bound.
    #[error("truncated or oversized mls header")]
    Truncated,
    /// Not MLS 1.0.
    #[error("unsupported mls protocol version")]
    Version,
    /// Not a `PrivateMessage`.
    #[error("mls wire format is not private_message")]
    WireFormat,
    /// Unknown content type.
    #[error("unknown mls content type")]
    ContentType,
    /// A variable-length integer is not in its shortest form.
    #[error("non-minimal mls varint")]
    NonMinimal,
    /// The `authenticated_data` is longer than the bound.
    #[error("authenticated data too large")]
    AuthenticatedDataTooLarge,
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], MlsHeaderError> {
        let (head, rest) = self.rest.split_at_checked(count).ok_or(MlsHeaderError::Truncated)?;
        self.rest = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, MlsHeaderError> {
        match self.take(1)? {
            [byte] => Ok(*byte),
            _ => Err(MlsHeaderError::Truncated),
        }
    }

    fn u16(&mut self) -> Result<u16, MlsHeaderError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| MlsHeaderError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, MlsHeaderError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| MlsHeaderError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// An RFC 9420 variable-length integer in its shortest form (one, two or four bytes).
    fn varint(&mut self) -> Result<usize, MlsHeaderError> {
        let first = self.u8()?;
        let width = match first >> 6 {
            0 => return Ok(usize::from(first)),
            1 => 2_usize,
            2 => 4,
            _ => return Err(MlsHeaderError::Truncated),
        };
        let mut value = usize::from(first & 0x3f);
        for _ in 1..width {
            value = (value << 8) | usize::from(self.u8()?);
        }
        let minimal = if width == 2 { value >= 64 } else { value >= 16_384 };
        if minimal { Ok(value) } else { Err(MlsHeaderError::NonMinimal) }
    }
}

fn parse_header(message: &[u8]) -> Result<(MlsOuterHeader, usize), MlsHeaderError> {
    let bounded = message.get(..MAX_OUTER_HEADER_BYTES).unwrap_or(message);
    let mut cursor = Cursor { rest: bounded };
    if cursor.u16()? != MLS10 {
        return Err(MlsHeaderError::Version);
    }
    let wire_format = cursor.u16()?;
    if wire_format != WIRE_FORMAT_PRIVATE_MESSAGE {
        return Err(MlsHeaderError::WireFormat);
    }
    let group_id_len = cursor.varint()?;
    let group_id = cursor.take(group_id_len)?.to_vec();
    let epoch = cursor.u64()?;
    let content_type = match cursor.u8()? {
        1 => MlsContentType::Application,
        2 => MlsContentType::Proposal,
        3 => MlsContentType::Commit,
        _ => return Err(MlsHeaderError::ContentType),
    };
    let consumed = bounded.len().saturating_sub(cursor.rest.len());
    Ok((MlsOuterHeader { wire_format, group_id, epoch, content_type }, consumed))
}

/// Parse the outer header of an `MLSMessage` carrying a `PrivateMessage`.
///
/// Only the first [`MAX_OUTER_HEADER_BYTES`] bytes of `message` are looked at.
///
/// # Errors
/// [`MlsHeaderError`] when the header is truncated, does not fit the bound, or is not an MLS 1.0
/// `PrivateMessage` with a known content type.
pub(crate) fn parse_outer_header(message: &[u8]) -> Result<MlsOuterHeader, MlsHeaderError> {
    parse_header(message).map(|(header, _)| header)
}

/// Parse the outer header and the cleartext `authenticated_data` that follows the content type.
///
/// # Errors
/// [`MlsHeaderError`] as [`parse_outer_header`]; also when the field is missing, runs past the
/// message, is longer than [`MAX_AUTHENTICATED_DATA_BYTES`], or its length is not minimally encoded.
pub(crate) fn parse_private_message(
    message: &[u8],
) -> Result<(MlsOuterHeader, &[u8]), MlsHeaderError> {
    let (header, consumed) = parse_header(message)?;
    let mut cursor = Cursor { rest: message.get(consumed..).ok_or(MlsHeaderError::Truncated)? };
    let len = cursor.varint()?;
    if len > MAX_AUTHENTICATED_DATA_BYTES {
        return Err(MlsHeaderError::AuthenticatedDataTooLarge);
    }
    Ok((header, cursor.take(len)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(aad_prefix: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 1, 0, 2, 4, 9, 9, 9, 9];
        out.extend_from_slice(&7_u64.to_be_bytes());
        out.push(3);
        out.extend_from_slice(aad_prefix);
        out.extend_from_slice(aad);
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn returns_the_authenticated_data_after_the_header() {
        let short = message(&[3], b"abc");
        let (header, aad) = parse_private_message(&short).expect("test: message parses");
        assert_eq!(header.epoch, 7, "epoch");
        assert_eq!(header.content_type, MlsContentType::Commit, "content type");
        assert_eq!(aad, b"abc", "authenticated data");
        let long = vec![5_u8; 300];
        let wide = message(&[0x41, 0x2c], &long);
        let (_, aad) = parse_private_message(&wide).expect("test: two-byte length parses");
        assert_eq!(aad, long.as_slice(), "two-byte length form");
    }

    #[test]
    fn refuses_non_minimal_missing_and_oversized_data() {
        assert_eq!(
            parse_private_message(&message(&[0x40, 0x03], b"abc")),
            Err(MlsHeaderError::NonMinimal),
            "a two-byte form of 3 is not minimal"
        );
        assert_eq!(
            parse_private_message(&message(&[0x80, 0, 0x40, 0], b"")),
            Err(MlsHeaderError::Truncated),
            "a length past the message"
        );
        let mut huge = vec![0x80, 0, 0x40, 0x01];
        huge.extend_from_slice(&vec![0_u8; 16_385]);
        assert_eq!(
            parse_private_message(&message(&huge[..4], &huge[4..])),
            Err(MlsHeaderError::AuthenticatedDataTooLarge),
            "over 16 KiB"
        );
        assert!(parse_private_message(&message(&[], b"")[..18]).is_err(), "no field at all");
        assert_eq!(
            parse_outer_header(&[0, 1, 0, 2, 0x40, 0x04, 1, 2, 3, 4]),
            Err(MlsHeaderError::NonMinimal),
            "the group id length is checked too"
        );
    }
}
