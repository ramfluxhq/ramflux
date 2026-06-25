use crate::{ProtocolError, domain, encode_base64url};

const MAGIC: &[u8; 4] = b"RFH1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderKind {
    DmMessage = 0x01,
    GroupMessage = 0x02,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderFieldValue {
    U64(u64),
    Bytes32([u8; 32]),
    String(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderField {
    pub field_id: u16,
    pub value: HeaderFieldValue,
}

impl HeaderField {
    #[must_use]
    pub const fn u64(field_id: u16, value: u64) -> Self {
        Self { field_id, value: HeaderFieldValue::U64(value) }
    }

    #[must_use]
    pub const fn bytes32(field_id: u16, value: [u8; 32]) -> Self {
        Self { field_id, value: HeaderFieldValue::Bytes32(value) }
    }

    #[must_use]
    pub fn string(field_id: u16, value: impl Into<String>) -> Self {
        Self { field_id, value: HeaderFieldValue::String(value.into()) }
    }
}

/// Encodes M1.1 RFH1 canonical header bytes.
///
/// # Errors
/// Returns an error if there are too many fields or an encoded value is too large.
pub fn canonical_header_bytes(
    kind: HeaderKind,
    fields: &[HeaderField],
) -> Result<Vec<u8>, ProtocolError> {
    let field_count =
        u16::try_from(fields.len()).map_err(|_err| ProtocolError::HeaderFieldCountOverflow)?;
    let mut out = Vec::with_capacity(8 + fields.len() * 16);
    out.extend_from_slice(MAGIC);
    out.push(kind as u8);
    out.push(1);
    out.extend_from_slice(&field_count.to_be_bytes());
    for field in fields {
        out.extend_from_slice(&field.field_id.to_be_bytes());
        let value = field_value_bytes(&field.value);
        let value_len =
            u32::try_from(value.len()).map_err(|_err| ProtocolError::HeaderFieldValueTooLong)?;
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(&value);
    }
    Ok(out)
}

/// Computes `header_hash` for RFH1 canonical header bytes.
///
/// # Errors
/// Returns an error if canonical header encoding fails.
pub fn header_hash_base64url(
    kind: HeaderKind,
    fields: &[HeaderField],
) -> Result<String, ProtocolError> {
    Ok(encode_base64url(crate::blake3_hash_bytes(
        domain::COMMITTING_AEAD_HEADER,
        &canonical_header_bytes(kind, fields)?,
    )))
}

fn field_value_bytes(value: &HeaderFieldValue) -> Vec<u8> {
    match value {
        HeaderFieldValue::U64(value) => value.to_be_bytes().to_vec(),
        HeaderFieldValue::Bytes32(value) => value.to_vec(),
        HeaderFieldValue::String(value) => value.as_bytes().to_vec(),
    }
}
