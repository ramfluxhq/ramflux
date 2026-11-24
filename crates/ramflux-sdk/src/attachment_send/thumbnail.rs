// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded poster admission. Inspect containers, never decode peer-controlled pixels.

use ramflux_protocol::{large_attachment, message::Thumbnail};
use serde::Deserialize;

use super::codes::{CODE_LAYOUT_INVALID, Refusal};

const MAX_BYTES: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    mime_type: String,
    width: u32,
    height: u32,
    encoded_image_base64: String,
}

pub(crate) struct Finished {
    pub digest: [u8; 32],
    pub thumbnail: Option<Thumbnail>,
}

impl Input {
    pub(super) fn decode(self) -> Result<Thumbnail, Refusal> {
        // Bound allocation before decoding; unpadded base64url needs ceil(4*n/3) bytes.
        if self.encoded_image_base64.len() > (MAX_BYTES * 4).div_ceil(3) {
            return Err(invalid());
        }
        let thumbnail = Thumbnail {
            mime_type: self.mime_type,
            width: self.width,
            height: self.height,
            encoded_image: ramflux_protocol::decode_base64url(&self.encoded_image_base64)
                .map_err(|_| invalid())?,
        };
        validate(Some(&thumbnail))?;
        Ok(thumbnail)
    }
}

pub(super) fn validate(thumbnail: Option<&Thumbnail>) -> Result<(), Refusal> {
    let Some(t) = thumbnail else { return Ok(()) };
    if t.encoded_image.is_empty()
        || t.encoded_image.len() > MAX_BYTES
        || !(1..=320).contains(&t.width)
        || !(1..=320).contains(&t.height)
    {
        return Err(invalid());
    }
    let dimensions = match t.mime_type.as_str() {
        "image/jpeg" => jpeg(&t.encoded_image),
        "image/webp" => webp(&t.encoded_image),
        _ => None,
    };
    if dimensions == Some((t.width, t.height)) { Ok(()) } else { Err(invalid()) }
}

pub(super) fn to_canonical(t: &Thumbnail) -> large_attachment::Thumbnail {
    large_attachment::Thumbnail {
        mime_type: t.mime_type.clone(),
        width: t.width,
        height: t.height,
        encoded_image: t.encoded_image.clone(),
    }
}

pub(super) fn to_prost(t: &large_attachment::Thumbnail) -> Thumbnail {
    Thumbnail {
        mime_type: t.mime_type.clone(),
        width: t.width,
        height: t.height,
        encoded_image: t.encoded_image.clone(),
    }
}

fn invalid() -> Refusal {
    Refusal::because_of(CODE_LAYOUT_INVALID, "thumbnail")
}

fn be16(bytes: &[u8]) -> Option<u32> {
    let pair: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
    Some(u32::from(u16::from_be_bytes(pair)))
}

// Walk every marker, including progressive scan boundaries, with bounded slice reads.
fn jpeg(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..2)? != [0xff, 0xd8] {
        return None;
    }
    let mut rest = bytes.get(2..)?;
    let mut dimensions = None;
    let mut scanned = false;
    while !rest.is_empty() {
        if *rest.first()? != 0xff {
            return None;
        }
        rest = rest.get(1..)?;
        while rest.first() == Some(&0xff) {
            rest = rest.get(1..)?;
        }
        let marker = *rest.first()?;
        rest = rest.get(1..)?;
        if marker == 0xd9 {
            return if scanned && rest.is_empty() { dimensions } else { None };
        }
        if matches!(marker, 0x00 | 0x01 | 0xd0..=0xd8) {
            return None;
        }
        let length = usize::try_from(be16(rest)?).ok()?;
        let body = rest.get(2..length)?;
        rest = rest.get(length..)?;
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if dimensions.is_some() || !matches!(marker, 0xc0..=0xc2) || body.first() != Some(&8) {
                return None;
            }
            let components = usize::from(*body.get(5)?);
            if components == 0 || components > 4 || body.len() != 6 + 3 * components {
                return None;
            }
            dimensions = Some((be16(body.get(3..)?)?, be16(body.get(1..)?)?));
        }
        if marker == 0xda {
            dimensions?;
            let components = usize::from(*body.first()?);
            if components == 0 || components > 4 || body.len() != 4 + 2 * components {
                return None;
            }
            let used = scan_length(rest)?;
            if used == 0 {
                return None;
            }
            rest = rest.get(used..)?;
            scanned = true;
        }
    }
    None
}

fn scan_length(bytes: &[u8]) -> Option<usize> {
    let mut at = 0;
    while at < bytes.len() {
        if *bytes.get(at)? == 0xff {
            let mut next = at + 1;
            while bytes.get(next) == Some(&0xff) {
                next += 1;
            }
            match *bytes.get(next)? {
                0x00 | 0xd0..=0xd7 => at = next + 1,
                _ => return Some(at),
            }
        } else {
            at += 1;
        }
    }
    None
}

fn le32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn le24(bytes: &[u8]) -> Option<u32> {
    let [a, b, c]: [u8; 3] = bytes.get(..3)?.try_into().ok()?;
    Some(u32::from(a) | u32::from(b) << 8 | u32::from(c) << 16)
}

fn webp(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..4)? != b"RIFF"
        || bytes.get(8..12)? != b"WEBP"
        || usize::try_from(le32(bytes.get(4..)?)?).ok()?.checked_add(8)? != bytes.len()
    {
        return None;
    }
    let mut rest = bytes.get(12..)?;
    let mut canvas = None;
    let mut dimensions = None;
    while !rest.is_empty() {
        let kind = rest.get(..4)?;
        let length = usize::try_from(le32(rest.get(4..)?)?).ok()?;
        let body = rest.get(8..8_usize.checked_add(length)?)?;
        match kind {
            b"VP8X" if canvas.is_none() && dimensions.is_none() && body.len() == 10 => {
                // Static posters only; reserved bits and animation are refused.
                if *body.first()? & 0xc3 != 0 || body.get(1..4)? != [0, 0, 0] {
                    return None;
                }
                canvas = Some((le24(body.get(4..)?)? + 1, le24(body.get(7..)?)? + 1));
            }
            b"VP8 " | b"VP8L" if dimensions.is_none() => {
                dimensions = Some(webp_frame(kind, body)?);
            }
            b"ALPH" | b"ICCP" | b"EXIF" | b"XMP " => {}
            _ => return None,
        }
        let padded = length.checked_add(length % 2)?;
        if padded != length && *rest.get(8 + length)? != 0 {
            return None;
        }
        rest = rest.get(8_usize.checked_add(padded)?..)?;
    }
    let dimensions = dimensions?;
    if canvas.is_some_and(|size| size != dimensions) { None } else { Some(dimensions) }
}

fn webp_frame(kind: &[u8], body: &[u8]) -> Option<(u32, u32)> {
    if kind == b"VP8L" {
        if body.len() <= 5 || body.first() != Some(&0x2f) {
            return None;
        }
        let bits = le32(body.get(1..)?)?;
        if bits >> 29 != 0 {
            return None;
        }
        return Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1));
    }
    if body.len() <= 10 || body.get(3..6)? != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let tag = le24(body)?;
    if tag & 1 != 0
        || tag & 0x10 == 0
        || (tag >> 1) & 7 > 3
        || usize::try_from(tag >> 5).ok()? > body.len().checked_sub(10)?
    {
        return None;
    }
    let width = u16::from_le_bytes(body.get(6..8)?.try_into().ok()?);
    let height = u16::from_le_bytes(body.get(8..10)?.try_into().ok()?);
    Some((u32::from(width & 0x3fff), u32::from(height & 0x3fff)))
}
