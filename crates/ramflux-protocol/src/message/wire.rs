// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Borrowed canonical wire traversal; never allocate from a peer-provided length.
use super::validation::ValidationError;

pub(crate) fn varint(input: &mut &[u8]) -> Result<u64, ValidationError> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = input.split_first().ok_or(ValidationError::Malformed)?;
        *input = rest;
        if shift == 63 && byte > 1 {
            return Err(ValidationError::Malformed);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if shift > 0 && byte == 0 {
                return Err(ValidationError::NonCanonical);
            }
            return Ok(value);
        }
    }
    Err(ValidationError::Malformed)
}

pub(crate) fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], ValidationError> {
    let (value, rest) = input.split_at_checked(length).ok_or(ValidationError::Malformed)?;
    *input = rest;
    Ok(value)
}

pub(crate) struct Field<'a> {
    pub tag: u32,
    pub wire: u8,
    pub scalar: u64,
    pub bytes: &'a [u8],
}

pub(crate) fn field<'a>(input: &mut &'a [u8]) -> Result<Field<'a>, ValidationError> {
    let key = varint(input)?;
    let tag = u32::try_from(key >> 3).map_err(|_| ValidationError::Malformed)?;
    if tag == 0 || tag > 536_870_911 || (19_000..20_000).contains(&tag) {
        return Err(ValidationError::Malformed);
    }
    let wire = u8::try_from(key & 7).map_err(|_| ValidationError::Malformed)?;
    let mut result = Field { tag, wire, scalar: 0, bytes: &[] };
    match wire {
        0 => result.scalar = varint(input)?,
        1 => result.bytes = take(input, 8)?,
        2 => {
            let length = usize::try_from(varint(input)?).map_err(|_| ValidationError::Limit)?;
            result.bytes = take(input, length)?;
        }
        5 => result.bytes = take(input, 4)?,
        _ => return Err(ValidationError::Malformed),
    }
    Ok(result)
}
