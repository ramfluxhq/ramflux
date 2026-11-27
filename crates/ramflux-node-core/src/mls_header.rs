// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The bounded outer header of an MLS `PrivateMessage` (RFC 9420 6 and 6.3), read without any key.
//!
//! One shared function for every node-side check that needs `{wire_format, group_id, epoch,
//! content_type}` of an `MLSMessage` (the `dm_order` table and the group host). It reads at most
//! [`MAX_OUTER_HEADER_BYTES`] bytes, allocates only the group id, never indexes with an untrusted
//! bound, and refuses every wire format except the pure-ciphertext `PrivateMessage` (ramflux
//! refuses public messages).

/// Most bytes the parser reads: version, wire format, group id (length prefix and bytes), epoch,
/// content type.
pub(crate) const MAX_OUTER_HEADER_BYTES: usize = 64;

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

    /// An RFC 9420 variable-length integer; the four-byte form cannot fit the header bound.
    fn varint(&mut self) -> Result<usize, MlsHeaderError> {
        let first = self.u8()?;
        match first >> 6 {
            0 => Ok(usize::from(first)),
            1 => {
                let second = self.u8()?;
                Ok((usize::from(first & 0x3f) << 8) | usize::from(second))
            }
            _ => Err(MlsHeaderError::Truncated),
        }
    }
}

/// Parse the outer header of an `MLSMessage` carrying a `PrivateMessage`.
///
/// Only the first [`MAX_OUTER_HEADER_BYTES`] bytes of `message` are looked at.
///
/// # Errors
/// [`MlsHeaderError`] when the header is truncated, does not fit the bound, or is not an MLS 1.0
/// `PrivateMessage` with a known content type.
pub(crate) fn parse_outer_header(message: &[u8]) -> Result<MlsOuterHeader, MlsHeaderError> {
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
    Ok(MlsOuterHeader { wire_format, group_id, epoch, content_type })
}
