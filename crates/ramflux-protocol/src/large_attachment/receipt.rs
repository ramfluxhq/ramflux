// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::grant::{signing, verify};
use super::native::{Cursor, identity};
use super::{FormatError, ScopedAttachmentGrant, VerifiedScopedGrant, lp};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRegistrationReceipt {
    pub grant_hash: [u8; 32],
    pub grant_epoch: u64,
    pub source_authority: String,
    pub authority_generation: u64,
    pub expires_at: u64,
}
impl AttachmentRegistrationReceipt {
    /// # Errors
    /// Refuses invalid identity or zero epochs/generations.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.grant_epoch == 0 || self.authority_generation == 0 {
            return Err(FormatError("receipt generation"));
        }
        let mut out = b"RFAK".to_vec();
        out.extend(1_u32.to_be_bytes());
        out.extend(self.grant_hash);
        out.extend(self.grant_epoch.to_be_bytes());
        identity(&mut out, &self.source_authority)?;
        out.extend(self.authority_generation.to_be_bytes());
        out.extend(self.expires_at.to_be_bytes());
        Ok(out)
    }
    /// # Errors
    /// Refuses invalid fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        signing("ramflux.attachment.registration.sign.v1", &self.canonical_bytes()?)
    }
    /// Appends a source-signed receipt to the RFC1 capability. Source key is pinned separately.
    /// # Errors
    /// Refuses grant/epoch/expiry mismatch, invalid fields or a bad source signature.
    pub fn capability(
        &self,
        grant: &VerifiedScopedGrant,
        signature: &[u8; 64],
        source_key: &[u8; 32],
    ) -> Result<Vec<u8>, FormatError> {
        self.matches(grant)?;
        verify(source_key, &self.signing_bytes()?, signature)?;
        let mut receipt = Vec::new();
        lp(&mut receipt, &self.canonical_bytes()?)?;
        lp(&mut receipt, signature)?;
        let mut out = grant.signed_bytes()?;
        lp(&mut out, &receipt)?;
        Ok(out)
    }
    fn matches(&self, grant: &VerifiedScopedGrant) -> Result<(), FormatError> {
        if self.grant_hash != grant.grant().hash()?
            || self.grant_epoch != grant.grant().epoch
            || self.expires_at > grant.grant().expires_at
        {
            return Err(FormatError("receipt grant binding"));
        }
        Ok(())
    }
    /// Reads which source authority and generation a capability names, **without verifying
    /// anything**. It only selects the candidate peer and pin to verify against; the
    /// result must never be trusted until [`Self::decode_capability`] accepts the bytes.
    /// # Errors
    /// Refuses a capability with no receipt, trailing bytes or a malformed receipt body.
    pub fn peek_source(input: &[u8]) -> Result<(String, u64), FormatError> {
        if input.len() > 8192 {
            return Err(FormatError("capability cap"));
        }
        let mut c = Cursor(input);
        if c.take(4)? != b"RFC1" {
            return Err(FormatError("capability version"));
        }
        let n = usize::try_from(c.u32()?).map_err(|_| FormatError("grant length"))?;
        c.take(n)?;
        if c.u32()? != 64 {
            return Err(FormatError("grant signature length"));
        }
        c.take(64)?;
        let n = usize::try_from(c.u32()?).map_err(|_| FormatError("receipt length"))?;
        let bytes = c.take(n)?;
        if !c.0.is_empty() {
            return Err(FormatError("capability trailing"));
        }
        let mut r = Cursor(bytes);
        let n = usize::try_from(r.u32()?).map_err(|_| FormatError("receipt length"))?;
        let mut b = Cursor(r.take(n)?);
        if b.take(4)? != b"RFAK" || b.u32()? != 1 {
            return Err(FormatError("receipt version"));
        }
        b.array::<32>()?;
        b.u64()?;
        let source = b.identity()?;
        Ok((source, b.u64()?))
    }

    /// Verifies a registered capability, never live grant state or operation admission.
    /// # Errors
    /// Refuses missing receipts, substitutions, stale authority and expiry.
    pub fn decode_capability(
        input: &[u8],
        source: &str,
        generation: u64,
        key: &[u8; 32],
        now: u64,
    ) -> Result<(VerifiedScopedGrant, Self), FormatError> {
        if input.len() > 8192 {
            return Err(FormatError("capability cap"));
        }
        let mut c = Cursor(input);
        if c.take(4)? != b"RFC1" {
            return Err(FormatError("capability version"));
        }
        let n = usize::try_from(c.u32()?).map_err(|_| FormatError("grant length"))?;
        c.take(n)?;
        if c.u32()? != 64 {
            return Err(FormatError("grant signature length"));
        }
        c.take(64)?;
        let prefix = input.len() - c.0.len();
        let grant = ScopedAttachmentGrant::decode_signed(&input[..prefix])?;
        let n = usize::try_from(c.u32()?).map_err(|_| FormatError("receipt length"))?;
        let bytes = c.take(n)?;
        if !c.0.is_empty() {
            return Err(FormatError("capability trailing"));
        }
        let mut r = Cursor(bytes);
        let n = usize::try_from(r.u32()?).map_err(|_| FormatError("receipt length"))?;
        let body = r.take(n)?;
        if r.u32()? != 64 {
            return Err(FormatError("receipt signature length"));
        }
        let signature = r.array()?;
        if !r.0.is_empty() {
            return Err(FormatError("receipt trailing"));
        }
        verify(key, &signing("ramflux.attachment.registration.sign.v1", body)?, &signature)?;
        let mut b = Cursor(body);
        if b.take(4)? != b"RFAK" || b.u32()? != 1 {
            return Err(FormatError("receipt version"));
        }
        let receipt = Self {
            grant_hash: b.array()?,
            grant_epoch: b.u64()?,
            source_authority: b.identity()?,
            authority_generation: b.u64()?,
            expires_at: b.u64()?,
        };
        if !b.0.is_empty()
            || receipt.canonical_bytes()?.as_slice() != body
            || receipt.source_authority != source
            || receipt.authority_generation != generation
            || now >= receipt.expires_at
            || now.saturating_add(5) < grant.grant().issued_at
            || now >= grant.grant().expires_at
        {
            return Err(FormatError("receipt authority/expiry"));
        }
        receipt.matches(&grant)?;
        Ok((grant, receipt))
    }
}
