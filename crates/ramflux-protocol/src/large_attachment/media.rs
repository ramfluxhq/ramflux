// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    ContentManifest, FormatError, MAX_MANIFEST_BYTES, SEGMENT_BYTES, SegmentLayout, digest,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QualifiedDevice {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MediaKeySlot {
    pub recipient: QualifiedDevice,
    pub encrypted_key: Vec<u8>,
    pub format: u32,
}

/// The S0 `MediaManifest` fields 1 through 12, in their original schema.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MediaManifest {
    pub manifest_id: [u8; 32],
    pub plaintext_digest: [u8; 32],
    pub plaintext_length: u64,
    pub ciphertext_length: u64,
    pub encrypted_segment_bytes: u32,
    pub network_chunk_bytes: u32,
    pub segment_digests: Vec<[u8; 32]>,
    pub key_slots: Vec<MediaKeySlot>,
    pub relay_origin: String,
    pub read_capability: Vec<u8>,
    pub expires_at: u64,
    pub retention_class: String,
}

impl MediaManifest {
    /// # Errors
    /// Rejects inconsistent dimensions, unsupported retention or oversized bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let (n, cipher) = self.layout().dimensions()?;
        if self.encrypted_segment_bytes != SEGMENT_BYTES
            || self.ciphertext_length != cipher
            || self.segment_digests.len() != n as usize
        {
            return Err(FormatError("inner segment dimensions"));
        }
        if self.retention_class != "relay_retained.v1" {
            return Err(FormatError("unsupported retention"));
        }
        let variable = self.relay_origin.len().saturating_add(self.read_capability.len());
        let slots = self.key_slots.iter().try_fold(variable, |size, slot| {
            if slot.recipient.account_anchor.is_empty()
                || slot.recipient.account_anchor.len() > 256
                || slot.recipient.device_id.is_empty()
                || slot.recipient.device_id.len() > 256
                || slot.recipient.device_epoch == 0
                || slot.format == 0
                || slot.encrypted_key.is_empty()
            {
                return Err(FormatError("key slot"));
            }
            Ok(size.saturating_add(slot.encrypted_key.len()).saturating_add(600))
        })?;
        if slots > MAX_MANIFEST_BYTES {
            return Err(FormatError("inner manifest cap"));
        }
        let mut out = Vec::new();
        bytes(&mut out, 1, &self.manifest_id);
        bytes(&mut out, 2, &self.plaintext_digest);
        for (tag, value) in [
            (3, self.plaintext_length),
            (4, self.ciphertext_length),
            (5, u64::from(self.encrypted_segment_bytes)),
            (6, u64::from(self.network_chunk_bytes)),
        ] {
            scalar(&mut out, tag, value);
        }
        for h in &self.segment_digests {
            bytes(&mut out, 7, h);
        }
        for slot in &self.key_slots {
            bytes(&mut out, 8, &slot.encode());
        }
        bytes(&mut out, 9, self.relay_origin.as_bytes());
        bytes(&mut out, 10, &self.read_capability);
        scalar(&mut out, 11, self.expires_at);
        bytes(&mut out, 12, self.retention_class.as_bytes());
        if out.len() > MAX_MANIFEST_BYTES {
            return Err(FormatError("inner manifest cap"));
        }
        Ok(out)
    }

    #[must_use]
    pub fn layout(&self) -> SegmentLayout {
        SegmentLayout {
            plaintext_length: self.plaintext_length,
            network_chunk_bytes: self.network_chunk_bytes,
        }
    }

    /// # Errors
    /// Rejects invalid manifest fields.
    pub fn hash(&self) -> Result<[u8; 32], FormatError> {
        digest("ramflux.message.media_manifest.v1", &self.canonical_bytes()?)
    }

    /// Strict canonical S0 decoder; rejects unknowns, duplicates and defaults.
    /// # Errors
    /// Rejects malformed, noncanonical, oversized or inconsistent manifests.
    pub fn decode(input: &[u8]) -> Result<Self, FormatError> {
        let mut m = Self::default();
        for f in fields(input)? {
            match f.tag {
                1 => m.manifest_id = hash(f.data()?)?,
                2 => m.plaintext_digest = hash(f.data()?)?,
                3 => m.plaintext_length = f.number()?,
                4 => m.ciphertext_length = f.number()?,
                5 => m.encrypted_segment_bytes = narrow(f.number()?)?,
                6 => m.network_chunk_bytes = narrow(f.number()?)?,
                7 => m.segment_digests.push(hash(f.data()?)?),
                8 => m.key_slots.push(MediaKeySlot::decode(f.data()?)?),
                9 => m.relay_origin = string(f.data()?)?,
                10 => m.read_capability = f.data()?.to_vec(),
                11 => m.expires_at = f.number()?,
                12 => m.retention_class = string(f.data()?)?,
                _ => return Err(FormatError("unknown inner field")),
            }
        }
        if m.canonical_bytes()? != input {
            return Err(FormatError("noncanonical inner"));
        }
        Ok(m)
    }
}

impl MediaKeySlot {
    fn encode(&self) -> Vec<u8> {
        let mut q = Vec::new();
        bytes(&mut q, 1, self.recipient.account_anchor.as_bytes());
        bytes(&mut q, 2, self.recipient.device_id.as_bytes());
        scalar(&mut q, 3, self.recipient.device_epoch);
        let mut out = Vec::new();
        bytes(&mut out, 1, &q);
        bytes(&mut out, 2, &self.encrypted_key);
        scalar(&mut out, 3, u64::from(self.format));
        out
    }
    fn decode(input: &[u8]) -> Result<Self, FormatError> {
        let mut s = Self::default();
        for f in fields(input)? {
            match f.tag {
                1 => {
                    for q in fields(f.data()?)? {
                        match q.tag {
                            1 => s.recipient.account_anchor = string(q.data()?)?,
                            2 => s.recipient.device_id = string(q.data()?)?,
                            3 => s.recipient.device_epoch = q.number()?,
                            _ => return Err(FormatError("unknown qualified field")),
                        }
                    }
                }
                2 => s.encrypted_key = f.data()?.to_vec(),
                3 => s.format = narrow(f.number()?)?,
                _ => return Err(FormatError("unknown slot field")),
            }
        }
        if s.encode() != input {
            return Err(FormatError("noncanonical slot"));
        }
        Ok(s)
    }
}

/// S0 Thumbnail fields. Parsing validates the encoded bounds before any decoder.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Thumbnail {
    pub mime_type: String,
    pub width: u32,
    pub height: u32,
    pub encoded_image: Vec<u8>,
}
impl Thumbnail {
    fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if !matches!(self.mime_type.as_str(), "image/jpeg" | "image/webp")
            || self.width == 0
            || self.width > 320
            || self.height == 0
            || self.height > 320
            || self.encoded_image.is_empty()
            || self.encoded_image.len() > 16384
        {
            return Err(FormatError("thumbnail bounds"));
        }
        let mut out = Vec::new();
        bytes(&mut out, 1, self.mime_type.as_bytes());
        scalar(&mut out, 2, u64::from(self.width));
        scalar(&mut out, 3, u64::from(self.height));
        bytes(&mut out, 4, &self.encoded_image);
        Ok(out)
    }
    fn decode(input: &[u8]) -> Result<Self, FormatError> {
        let mut t = Self::default();
        for f in fields(input)? {
            match f.tag {
                1 => t.mime_type = string(f.data()?)?,
                2 => t.width = narrow(f.number()?)?,
                3 => t.height = narrow(f.number()?)?,
                4 => t.encoded_image = f.data()?.to_vec(),
                _ => return Err(FormatError("unknown thumbnail field")),
            }
        }
        if t.encode()? != input {
            return Err(FormatError("noncanonical thumbnail"));
        }
        Ok(t)
    }
}

/// Authenticated S0 reference binding, checked before a large payload is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    pub mime_type: String,
    pub file_name: Option<String>,
    pub inline_thumbnail: Option<Thumbnail>,
    pub object_id: String,
    pub manifest_digest: [u8; 32],
    pub size: u64,
    pub key_slots: Vec<MediaKeySlot>,
    pub large_manifest: MediaManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMedia<'a> {
    Large(&'a MediaRef),
    CaptionWithUpgradeRequired { caption: &'a str, required_layer: u32 },
}

impl MediaRef {
    /// Canonical S0 `MediaRef` fields 1 through 8 for a large attachment.
    /// # Errors
    /// Rejects invalid inner/thumbnail fields or encoded length above the cap.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.size != self.large_manifest.plaintext_length
            || self.key_slots != self.large_manifest.key_slots
            || self.manifest_digest != self.large_manifest.hash()?
        {
            return Err(FormatError("reference inner binding"));
        }
        let text_size = self
            .object_id
            .len()
            .saturating_add(self.mime_type.len())
            .saturating_add(self.file_name.as_ref().map_or(0, String::len));
        if text_size > MAX_MANIFEST_BYTES {
            return Err(FormatError("reference text cap"));
        }
        let mut out = Vec::new();
        bytes(&mut out, 1, self.object_id.as_bytes());
        bytes(&mut out, 2, &self.manifest_digest);
        bytes(&mut out, 3, self.mime_type.as_bytes());
        scalar(&mut out, 4, self.size);
        for slot in &self.key_slots {
            bytes(&mut out, 5, &slot.encode());
        }
        if let Some(name) = &self.file_name {
            varint(&mut out, 6 << 3 | 2);
            varint(&mut out, name.len() as u64);
            out.extend_from_slice(name.as_bytes());
        }
        if let Some(t) = &self.inline_thumbnail {
            bytes(&mut out, 7, &t.encode()?);
        }
        bytes(&mut out, 8, &self.large_manifest.canonical_bytes()?);
        if out.len() > MAX_MANIFEST_BYTES {
            return Err(FormatError("reference cap"));
        }
        Ok(out)
    }

    /// # Errors
    /// Rejects malformed or noncanonical S0 large references.
    pub fn decode(input: &[u8]) -> Result<Self, FormatError> {
        let mut r = Self {
            object_id: String::new(),
            manifest_digest: [0; 32],
            mime_type: String::new(),
            size: 0,
            key_slots: Vec::new(),
            file_name: None,
            inline_thumbnail: None,
            large_manifest: MediaManifest::default(),
        };
        for f in fields(input)? {
            match f.tag {
                1 => r.object_id = string(f.data()?)?,
                2 => r.manifest_digest = hash(f.data()?)?,
                3 => r.mime_type = string(f.data()?)?,
                4 => r.size = f.number()?,
                5 => r.key_slots.push(MediaKeySlot::decode(f.data()?)?),
                6 => r.file_name = Some(string(f.data()?)?),
                7 => r.inline_thumbnail = Some(Thumbnail::decode(f.data()?)?),
                8 => r.large_manifest = MediaManifest::decode(f.data()?)?,
                _ => return Err(FormatError("unknown reference field")),
            }
        }
        if r.canonical_bytes()? != input {
            return Err(FormatError("noncanonical reference"));
        }
        Ok(r)
    }

    /// # Errors
    /// Rejects inner/native/reference identity, dimensions or key-slot mismatch.
    pub fn validate_binding(&self, native: &ContentManifest) -> Result<(), FormatError> {
        let m = &self.large_manifest;
        if self.object_id != crate::encode_base64url(native.object_id)
            || self.manifest_digest != m.hash()?
            || self.size != m.plaintext_length
            || self.key_slots != m.key_slots
            || m.manifest_id != native.hash()?
            || m.layout() != native.layout
            || m.segment_digests != native.segment_digests
        {
            return Err(FormatError("reference binding"));
        }
        Ok(())
    }

    /// Pure representation policy; no capability or partial manifest in fallback.
    #[must_use]
    pub fn for_peer<'a>(&'a self, layer: u32, caption: &'a str) -> PeerMedia<'a> {
        if layer >= 4 {
            PeerMedia::Large(self)
        } else {
            PeerMedia::CaptionWithUpgradeRequired { caption, required_layer: 4 }
        }
    }
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 128 {
        out.push((v.to_le_bytes()[0] & 127) | 128);
        v >>= 7;
    }
    out.push(v.to_le_bytes()[0]);
}
fn bytes(out: &mut Vec<u8>, tag: u64, value: &[u8]) {
    if !value.is_empty() {
        varint(out, tag << 3 | 2);
        varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }
}
fn scalar(out: &mut Vec<u8>, tag: u64, value: u64) {
    if value != 0 {
        varint(out, tag << 3);
        varint(out, value);
    }
}
fn hash(b: &[u8]) -> Result<[u8; 32], FormatError> {
    b.try_into().map_err(|_| FormatError("hash length"))
}
fn narrow(v: u64) -> Result<u32, FormatError> {
    u32::try_from(v).map_err(|_| FormatError("u32 overflow"))
}
fn string(b: &[u8]) -> Result<String, FormatError> {
    String::from_utf8(b.to_vec()).map_err(|_| FormatError("UTF8"))
}

struct Field<'a> {
    tag: u64,
    value: Value<'a>,
}
enum Value<'a> {
    Number(u64),
    Data(&'a [u8]),
}
impl<'a> Field<'a> {
    fn number(&self) -> Result<u64, FormatError> {
        if let Value::Number(n) = self.value { Ok(n) } else { Err(FormatError("wire type")) }
    }
    fn data(&self) -> Result<&'a [u8], FormatError> {
        if let Value::Data(b) = self.value { Ok(b) } else { Err(FormatError("wire type")) }
    }
}
fn take_varint(input: &mut &[u8]) -> Result<u64, FormatError> {
    let mut n = 0;
    for shift in (0..70).step_by(7) {
        let (&b, rest) = input.split_first().ok_or(FormatError("truncated varint"))?;
        *input = rest;
        if shift == 63 && b > 1 {
            return Err(FormatError("varint overflow"));
        }
        n |= u64::from(b & 127) << shift;
        if b < 128 {
            return Ok(n);
        }
    }
    Err(FormatError("varint overflow"))
}
fn fields(mut input: &[u8]) -> Result<Vec<Field<'_>>, FormatError> {
    if input.len() > MAX_MANIFEST_BYTES {
        return Err(FormatError("protobuf cap"));
    }
    let mut out = Vec::new();
    while !input.is_empty() {
        let key = take_varint(&mut input)?;
        let value = match key & 7 {
            0 => Value::Number(take_varint(&mut input)?),
            2 => {
                let n = usize::try_from(take_varint(&mut input)?)
                    .map_err(|_| FormatError("field length"))?;
                let b = input.get(..n).ok_or(FormatError("truncated field"))?;
                input = &input[n..];
                Value::Data(b)
            }
            _ => return Err(FormatError("wire type")),
        };
        out.push(Field { tag: key >> 3, value });
    }
    Ok(out)
}
