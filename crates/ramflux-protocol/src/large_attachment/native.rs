// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{FormatError, MAX_MANIFEST_BYTES, SEGMENT_BYTES, SegmentLayout, digest, lp};

/// Claimed signer identity; registration must independently authenticate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedOwner {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_public_key: [u8; 32],
    pub home_node_id: String,
}

/// Ciphertext-only native relay manifest. No plaintext fingerprint is exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentManifest {
    pub object_id: [u8; 32],
    pub owner: QualifiedOwner,
    pub layout: SegmentLayout,
    pub segment_digests: Vec<[u8; 32]>,
}

impl ContentManifest {
    /// Encodes the native signed container. This verifies possession of the
    /// claimed key; owner authority still requires authenticated registration.
    /// # Errors
    /// Rejects malformed fields or an invalid signature.
    pub fn signed_bytes(&self, signature: &[u8; 64]) -> Result<Vec<u8>, FormatError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.owner.signing_public_key)
            .map_err(|_| FormatError("manifest signing key"))?;
        key.verify_strict(&self.signing_bytes()?, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| FormatError("manifest signature"))?;
        let mut out = Vec::new();
        lp(&mut out, &self.canonical_bytes()?)?;
        lp(&mut out, signature)?;
        Ok(out)
    }

    /// # Errors
    /// Rejects invalid framing, trailing bytes or a bad signature. Registration
    /// must additionally verify the claimed owner's current authority.
    pub fn decode_signed(input: &[u8]) -> Result<(Self, [u8; 64]), FormatError> {
        if input.len() > MAX_MANIFEST_BYTES + 72 {
            return Err(FormatError("signed manifest cap"));
        }
        let mut c = Cursor(input);
        let len = c.u32()? as usize;
        let manifest = Self::decode(c.take(len)?)?;
        if c.u32()? != 64 {
            return Err(FormatError("signature length"));
        }
        let signature = c.array()?;
        if !c.0.is_empty() || manifest.signed_bytes(&signature)? != input {
            return Err(FormatError("signed manifest framing"));
        }
        Ok((manifest, signature))
    }

    /// Strict native MC decoder, bounded before any segment-list allocation.
    /// # Errors
    /// Rejects wrong versions, dimensions, UTF-8, trailing bytes and oversized input.
    pub fn decode(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() > MAX_MANIFEST_BYTES {
            return Err(FormatError("native manifest cap"));
        }
        let mut c = Cursor(input);
        if c.take(4)? != b"RFA1" || c.u32()? != 1 {
            return Err(FormatError("native version"));
        }
        let object_id = c.array()?;
        let owner = QualifiedOwner {
            account_anchor: c.identity()?,
            device_id: c.identity()?,
            device_epoch: c.u64()?,
            signing_public_key: c.array()?,
            home_node_id: c.identity()?,
        };
        let plaintext_length = c.u64()?;
        let ciphertext_length = c.u64()?;
        if c.u32()? != SEGMENT_BYTES {
            return Err(FormatError("native segment size"));
        }
        let layout = SegmentLayout { plaintext_length, network_chunk_bytes: c.u32()? };
        let (n, cipher) = layout.dimensions()?;
        if ciphertext_length != cipher || c.u32()? != n || c.0.len() != n as usize * 32 {
            return Err(FormatError("native dimensions"));
        }
        let segment_digests = (0..n).map(|_| c.array()).collect::<Result<Vec<_>, _>>()?;
        let result = Self { object_id, owner, layout, segment_digests };
        if result.canonical_bytes()? != input {
            return Err(FormatError("native canonical bytes"));
        }
        Ok(result)
    }

    /// # Errors
    /// Rejects inconsistent lengths, oversized identities or an oversized manifest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let (n, cipher) = self.layout.dimensions()?;
        if self.segment_digests.len() != n as usize {
            return Err(FormatError("native segment count"));
        }
        let mut out = b"RFA1".to_vec();
        out.extend_from_slice(&1_u32.to_be_bytes());
        out.extend_from_slice(&self.object_id);
        for id in [&self.owner.account_anchor, &self.owner.device_id] {
            identity(&mut out, id)?;
        }
        out.extend_from_slice(&self.owner.device_epoch.to_be_bytes());
        out.extend_from_slice(&self.owner.signing_public_key);
        identity(&mut out, &self.owner.home_node_id)?;
        out.extend_from_slice(&self.layout.plaintext_length.to_be_bytes());
        out.extend_from_slice(&cipher.to_be_bytes());
        for v in [SEGMENT_BYTES, self.layout.network_chunk_bytes, n] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for h in &self.segment_digests {
            out.extend_from_slice(h);
        }
        if out.len() > MAX_MANIFEST_BYTES {
            return Err(FormatError("native manifest cap"));
        }
        Ok(out)
    }

    /// Hrelay excludes the signature and all inner secret metadata.
    /// # Errors
    /// Rejects invalid manifest fields.
    pub fn hash(&self) -> Result<[u8; 32], FormatError> {
        digest("ramflux.attachment.content_manifest.v1", &self.canonical_bytes()?)
    }

    /// # Errors
    /// Rejects invalid manifest fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut out = Vec::new();
        lp(&mut out, b"ramflux.attachment.content_manifest.sign.v1")?;
        lp(&mut out, &self.canonical_bytes()?)?;
        Ok(out)
    }
}

fn identity(out: &mut Vec<u8>, id: &str) -> Result<(), FormatError> {
    if id.is_empty() || id.len() > 256 {
        return Err(FormatError("native identity length"));
    }
    lp(out, id.as_bytes())
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        let b = self.0.get(..n).ok_or(FormatError("truncated native"))?;
        self.0 = &self.0[n..];
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        self.take(N)?.try_into().map_err(|_| FormatError("native array"))
    }
    fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn identity(&mut self) -> Result<String, FormatError> {
        let n = self.u32()? as usize;
        if n == 0 || n > 256 {
            return Err(FormatError("native identity length"));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| FormatError("native UTF8"))
    }
}
