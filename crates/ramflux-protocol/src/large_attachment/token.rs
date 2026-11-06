// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native source-issued token transcript (RFT1). A verified signature proves
//! issuer possession only; it never replaces live grant, retirement or replay checks.
use super::grant::{signing, verify};
use super::native::{Cursor, identity};
use super::{FormatError, lp};

const MAX_TOKEN: usize = 1024;
const MAX_LIFETIME_SECONDS: u64 = 300;
const SIGNATURE_BYTES: u32 = 64;

/// Unsigned token T. `target_hash` is Htarget, never the renewal operation hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentToken {
    pub target_hash: [u8; 32],
    pub grant_hash: [u8; 32],
    pub grant_epoch: u64,
    pub source_authority: String,
    pub authority_generation: u64,
    pub requester_digest: [u8; 32],
    pub rights: u32,
    pub token_issuer: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// A token whose issuer signature has been checked against a caller-pinned key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttachmentToken {
    token: AttachmentToken,
    signature: [u8; 64],
}

impl VerifiedAttachmentToken {
    #[must_use]
    pub fn token(&self) -> &AttachmentToken {
        &self.token
    }

    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// # Errors
    /// Refuses invalid canonical fields.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.token.container(&self.signature)
    }
}

impl AttachmentToken {
    /// Exact native T bytes. Rights 1..31 use the grant right bits.
    /// # Errors
    /// Refuses zero epochs or generations, reserved rights, invalid lifetime or identities.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.grant_epoch == 0
            || self.authority_generation == 0
            || self.rights == 0
            || self.rights & !31 != 0
        {
            return Err(FormatError("token bounds"));
        }
        if self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > MAX_LIFETIME_SECONDS
        {
            return Err(FormatError("token lifetime"));
        }
        let mut out = b"RFT1".to_vec();
        out.extend(1_u32.to_be_bytes());
        out.extend(self.target_hash);
        out.extend(self.grant_hash);
        out.extend(self.grant_epoch.to_be_bytes());
        identity(&mut out, &self.source_authority)?;
        out.extend(self.authority_generation.to_be_bytes());
        out.extend(self.requester_digest);
        out.extend(self.rights.to_be_bytes());
        identity(&mut out, &self.token_issuer)?;
        out.extend(self.issued_at.to_be_bytes());
        out.extend(self.expires_at.to_be_bytes());
        Ok(out)
    }

    /// # Errors
    /// Refuses malformed fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        signing("ramflux.attachment.token.sign.v1", &self.canonical_bytes()?)
    }

    /// Container `LP(T) || LP(signature)` after verifying the signature.
    /// # Errors
    /// Refuses malformed fields and a signature from a different key.
    pub fn signed_bytes(
        &self,
        issuer_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<Vec<u8>, FormatError> {
        verify(issuer_key, &self.signing_bytes()?, signature)?;
        self.container(signature)
    }

    fn container(&self, signature: &[u8; 64]) -> Result<Vec<u8>, FormatError> {
        let mut out = Vec::new();
        lp(&mut out, &self.canonical_bytes()?)?;
        lp(&mut out, signature)?;
        Ok(out)
    }

    /// Decodes unsigned T bytes; decode then encode is byte-identical.
    /// # Errors
    /// Refuses oversized, wrong-version, noncanonical or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_TOKEN {
            return Err(FormatError("token cap"));
        }
        let mut c = Cursor(bytes);
        if c.take(4)? != b"RFT1" || c.u32()? != 1 {
            return Err(FormatError("token version"));
        }
        let token = Self {
            target_hash: c.array()?,
            grant_hash: c.array()?,
            grant_epoch: c.u64()?,
            source_authority: c.identity()?,
            authority_generation: c.u64()?,
            requester_digest: c.array()?,
            rights: c.u32()?,
            token_issuer: c.identity()?,
            issued_at: c.u64()?,
            expires_at: c.u64()?,
        };
        if !c.0.is_empty() || token.canonical_bytes()? != bytes {
            return Err(FormatError("token framing"));
        }
        Ok(token)
    }

    /// Decodes `LP(T) || LP(signature)` and verifies the pinned issuer signature.
    /// # Errors
    /// Refuses trailing bytes, noncanonical fields and invalid signatures.
    pub fn decode_signed(
        input: &[u8],
        issuer_key: &[u8; 32],
    ) -> Result<VerifiedAttachmentToken, FormatError> {
        if input.len() > MAX_TOKEN + 128 {
            return Err(FormatError("token container cap"));
        }
        let mut c = Cursor(input);
        let n = usize::try_from(c.u32()?).map_err(|_| FormatError("token length"))?;
        let token = Self::decode(c.take(n)?)?;
        if c.u32()? != SIGNATURE_BYTES {
            return Err(FormatError("token container"));
        }
        let signature = c.array()?;
        if !c.0.is_empty() {
            return Err(FormatError("token container"));
        }
        verify(issuer_key, &token.signing_bytes()?, &signature)?;
        Ok(VerifiedAttachmentToken { token, signature })
    }
}
