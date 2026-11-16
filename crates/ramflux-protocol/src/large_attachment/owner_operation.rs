// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner reserve, bind, upload, commit and pending-retire transcripts.
//! Reader [`super::AttachmentOperation`] does not accept these kinds.

use super::native::{Cursor, identity};
use super::{FormatError, SEGMENT_BYTES, body_digest};

const RESERVE: u32 = 9;
const BIND: u32 = 10;
const PUT: u32 = 4;
const COMMIT: u32 = 5;
const RETIRE: u32 = 7;

/// One owner operation. `grant_id` and `grant_epoch` are zero and are not fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAttachmentOperation {
    pub op: u32,
    pub audience: String,
    pub object_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub authority_generation: u64,
    pub operation_id: [u8; 32],
    pub payload_generation: u64,
    pub segment_index: u64,
    pub offset: u64,
    pub length: u64,
    pub body_digest: [u8; 32],
}

impl OwnerAttachmentOperation {
    /// Reserve body and the operation that names those identities.
    /// # Errors
    /// Refuses a zero authority generation, an illegal chunk size, or an oversized length.
    pub fn reserve(input: &OwnerReserve<'_>) -> Result<(Self, Vec<u8>), FormatError> {
        if !matches!(input.network_chunk_bytes, 524_288 | 1_048_576)
            || input.plaintext_length > 4_u64 << 30
        {
            return Err(FormatError("operation range"));
        }
        let mut body = Vec::with_capacity(84);
        body.extend(input.upload_id);
        body.extend(input.object_id);
        body.extend(input.plaintext_length.to_be_bytes());
        body.extend(input.network_chunk_bytes.to_be_bytes());
        body.extend(input.lease_hard_until.to_be_bytes());
        let op = Self {
            op: RESERVE,
            audience: input.audience.to_owned(),
            object_id: input.object_id,
            manifest_hash: [0; 32],
            authority_generation: input.authority_generation,
            operation_id: input.upload_id,
            payload_generation: 1,
            segment_index: 0,
            offset: 0,
            length: 0,
            body_digest: body_digest(&body),
        };
        op.canonical_bytes()?;
        Ok((op, body))
    }

    /// Bind operation over the exact signed manifest container.
    /// # Errors
    /// Refuses a zero authority or payload generation, or an empty body.
    pub fn bind(input: &OwnerBind<'_>) -> Result<Self, FormatError> {
        if input.body.is_empty() || input.payload_generation == 0 {
            return Err(FormatError("operation generation"));
        }
        let op = Self {
            op: BIND,
            audience: input.audience.to_owned(),
            object_id: input.object_id,
            manifest_hash: input.manifest_hash,
            authority_generation: input.authority_generation,
            operation_id: input.operation_id,
            payload_generation: input.payload_generation,
            segment_index: 0,
            offset: 0,
            length: 0,
            body_digest: body_digest(input.body),
        };
        op.canonical_bytes()?;
        Ok(op)
    }

    /// PUT one chunk. `length` is the body length.
    /// # Errors
    /// Refuses a range outside one segment or a zero payload generation.
    pub fn put(input: &OwnerPut<'_>) -> Result<Self, FormatError> {
        let length = u64::try_from(input.body.len()).map_err(|_| FormatError("operation range"))?;
        if input.payload_generation == 0 {
            return Err(FormatError("operation generation"));
        }
        let op = Self {
            op: PUT,
            audience: input.audience.to_owned(),
            object_id: input.object_id,
            manifest_hash: input.manifest_hash,
            authority_generation: input.authority_generation,
            operation_id: input.operation_id,
            payload_generation: input.payload_generation,
            segment_index: input.segment_index,
            offset: input.offset,
            length,
            body_digest: body_digest(input.body),
        };
        op.canonical_bytes()?;
        Ok(op)
    }

    /// Commit with an empty body.
    /// # Errors
    /// Refuses a zero authority or payload generation.
    pub fn commit(
        audience: &str,
        object_id: [u8; 32],
        manifest_hash: [u8; 32],
        authority_generation: u64,
        operation_id: [u8; 32],
        payload_generation: u64,
    ) -> Result<Self, FormatError> {
        if payload_generation == 0 {
            return Err(FormatError("operation generation"));
        }
        let op = Self {
            op: COMMIT,
            audience: audience.to_owned(),
            object_id,
            manifest_hash,
            authority_generation,
            operation_id,
            payload_generation,
            segment_index: 0,
            offset: 0,
            length: 0,
            body_digest: body_digest(&[]),
        };
        op.canonical_bytes()?;
        Ok(op)
    }

    /// Pending retire. The manifest hash and payload generation stay zero.
    /// # Errors
    /// Refuses a zero authority generation.
    pub fn retire(
        audience: &str,
        object_id: [u8; 32],
        authority_generation: u64,
        operation_id: [u8; 32],
    ) -> Result<Self, FormatError> {
        let op = Self {
            op: RETIRE,
            audience: audience.to_owned(),
            object_id,
            manifest_hash: [0; 32],
            authority_generation,
            operation_id,
            payload_generation: 0,
            segment_index: 0,
            offset: 0,
            length: 0,
            body_digest: body_digest(&[]),
        };
        op.canonical_bytes()?;
        Ok(op)
    }

    /// # Errors
    /// Refuses a reader kind, a non-zero grant, a zero authority generation, or a bad range.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.authority_generation == 0 {
            return Err(FormatError("operation generation"));
        }
        let (method, path) = endpoint(self)?;
        let mut out = b"RFO1".to_vec();
        out.extend(1_u32.to_be_bytes());
        out.extend(self.op.to_be_bytes());
        for value in [method, path.as_str(), self.audience.as_str()] {
            identity(&mut out, value)?;
        }
        out.extend(self.object_id);
        out.extend(self.manifest_hash);
        out.extend([0; 32]);
        out.extend(0_u64.to_be_bytes());
        out.extend(self.authority_generation.to_be_bytes());
        out.extend(self.operation_id);
        for value in [self.payload_generation, self.segment_index, self.offset, self.length] {
            out.extend(value.to_be_bytes());
        }
        out.extend(self.body_digest);
        Ok(out)
    }

    /// Domain-separated operation hash. An owner proof binds this value.
    /// # Errors
    /// Refuses a transcript this operation cannot encode.
    pub fn hash(&self) -> Result<[u8; 32], FormatError> {
        super::digest("ramflux.attachment.operation.v1", &self.canonical_bytes()?)
    }

    /// # Errors
    /// Refuses a reader operation, a non-zero grant, or bytes that are not this transcript.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > 4096 {
            return Err(FormatError("operation cap"));
        }
        let mut cursor = Cursor(bytes);
        if cursor.take(4)? != b"RFO1" || cursor.u32()? != 1 {
            return Err(FormatError("operation version"));
        }
        let op_kind = cursor.u32()?;
        if !matches!(op_kind, RESERVE | BIND | PUT | COMMIT | RETIRE) {
            return Err(FormatError("operation kind"));
        }
        let method = cursor.identity()?;
        let path = cursor.identity()?;
        let audience = cursor.identity()?;
        let object_id = cursor.array()?;
        let manifest_hash = cursor.array()?;
        let grant_id: [u8; 32] = cursor.array()?;
        let grant_epoch = cursor.u64()?;
        if grant_id != [0; 32] || grant_epoch != 0 {
            return Err(FormatError("operation generation"));
        }
        let decoded = Self {
            op: op_kind,
            audience,
            object_id,
            manifest_hash,
            authority_generation: cursor.u64()?,
            operation_id: cursor.array()?,
            payload_generation: cursor.u64()?,
            segment_index: cursor.u64()?,
            offset: cursor.u64()?,
            length: cursor.u64()?,
            body_digest: cursor.array()?,
        };
        let (expected_method, expected_path) = endpoint(&decoded)?;
        if method != expected_method || path != expected_path || !cursor.0.is_empty() {
            return Err(FormatError("operation endpoint"));
        }
        if decoded.canonical_bytes()? != bytes {
            return Err(FormatError("operation framing"));
        }
        Ok(decoded)
    }
}

/// Arguments for one owner Reserve.
pub struct OwnerReserve<'a> {
    pub audience: &'a str,
    pub object_id: [u8; 32],
    pub authority_generation: u64,
    pub upload_id: [u8; 32],
    pub plaintext_length: u64,
    pub network_chunk_bytes: u32,
    pub lease_hard_until: u64,
}

/// Arguments for one owner Bind.
pub struct OwnerBind<'a> {
    pub audience: &'a str,
    pub object_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub authority_generation: u64,
    pub operation_id: [u8; 32],
    pub payload_generation: u64,
    pub body: &'a [u8],
}

/// Arguments for one segment PUT.
pub struct OwnerPut<'a> {
    pub audience: &'a str,
    pub object_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub authority_generation: u64,
    pub operation_id: [u8; 32],
    pub payload_generation: u64,
    pub segment_index: u64,
    pub offset: u64,
    pub body: &'a [u8],
}

fn endpoint(op: &OwnerAttachmentOperation) -> Result<(&'static str, String), FormatError> {
    let object = hex(&op.object_id);
    let hash = hex(&op.manifest_hash);
    let (method, path, range_clear, payload_rule) = match op.op {
        RESERVE => ("POST", "/attachments/reserve".to_owned(), true, PayloadRule::ExactlyOne),
        BIND => ("POST", format!("/attachments/{object}/{hash}/bind"), true, PayloadRule::NonZero),
        PUT => (
            "PUT",
            format!("/attachments/{object}/{hash}/segments/{}", op.segment_index),
            false,
            PayloadRule::NonZero,
        ),
        COMMIT => {
            ("POST", format!("/attachments/{object}/{hash}/commit"), true, PayloadRule::NonZero)
        }
        RETIRE => ("POST", format!("/attachments/{object}/abandon"), true, PayloadRule::Zero),
        _ => return Err(FormatError("operation kind")),
    };
    if op.op == RESERVE && op.manifest_hash != [0; 32] {
        return Err(FormatError("operation unused range"));
    }
    if op.op == RETIRE && op.manifest_hash != [0; 32] {
        return Err(FormatError("operation unused range"));
    }
    let clear = op.segment_index == 0 && op.offset == 0 && op.length == 0;
    if range_clear != clear {
        return Err(FormatError("operation unused range"));
    }
    match payload_rule {
        PayloadRule::ExactlyOne if op.payload_generation != 1 => {
            return Err(FormatError("operation generation"));
        }
        PayloadRule::NonZero if op.payload_generation == 0 => {
            return Err(FormatError("operation generation"));
        }
        PayloadRule::Zero if op.payload_generation != 0 => {
            return Err(FormatError("operation generation"));
        }
        _ => {}
    }
    if op.op == PUT {
        let end = op.offset.checked_add(op.length).ok_or(FormatError("operation range"))?;
        if op.length == 0 || op.length > 1_048_576 || end > u64::from(SEGMENT_BYTES) {
            return Err(FormatError("operation range"));
        }
    }
    if op.op == COMMIT && op.body_digest != body_digest(&[]) {
        return Err(FormatError("read body"));
    }
    if op.op == RETIRE && op.body_digest != body_digest(&[]) {
        return Err(FormatError("read body"));
    }
    Ok((method, path))
}

enum PayloadRule {
    ExactlyOne,
    NonZero,
    Zero,
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [char::from(HEX[usize::from(byte >> 4)]), char::from(HEX[usize::from(byte & 15)])]
        })
        .collect()
}

#[cfg(test)]
mod tests;
