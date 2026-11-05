// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native scoped grants. Verified signatures alone never authorize relay access.
use super::native::{Cursor, identity};
use super::{FormatError, QualifiedOwner, digest, lp};
const MAX_GRANT: usize = 4096;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAttachmentGrant {
    pub grant_id: [u8; 32],
    pub reference_id: [u8; 32],
    pub object_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub owner: QualifiedOwner,
    pub grantee: QualifiedOwner,
    pub epoch: u64,
    pub rights: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedScopedGrant {
    grant: ScopedAttachmentGrant,
    signature: [u8; 64],
}
impl VerifiedScopedGrant {
    #[must_use]
    pub fn grant(&self) -> &ScopedAttachmentGrant {
        &self.grant
    }
    /// # Errors
    /// Refuses invalid canonical fields.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.grant.signed_bytes(&self.signature)
    }
}
fn qualified(out: &mut Vec<u8>, q: &QualifiedOwner) -> Result<(), FormatError> {
    identity(out, &q.account_anchor)?;
    identity(out, &q.device_id)?;
    if q.device_epoch == 0 {
        return Err(FormatError("device epoch"));
    }
    out.extend(q.device_epoch.to_be_bytes());
    out.extend(q.signing_public_key);
    identity(out, &q.home_node_id)
}
fn read_qualified(c: &mut Cursor<'_>) -> Result<QualifiedOwner, FormatError> {
    Ok(QualifiedOwner {
        account_anchor: c.identity()?,
        device_id: c.identity()?,
        device_epoch: c.u64()?,
        signing_public_key: c.array()?,
        home_node_id: c.identity()?,
    })
}
impl ScopedAttachmentGrant {
    /// Exact native G bytes. Rights1..16 are GET, HEAD, Missing, Renew and Ack.
    /// # Errors
    /// Refuses reserved rights, zero epochs, invalid expiry or identities.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.epoch == 0
            || self.rights == 0
            || self.rights & !31 != 0
            || self.issued_at >= self.expires_at
        {
            return Err(FormatError("grant bounds"));
        }
        let mut out = b"RFG1".to_vec();
        out.extend(1_u32.to_be_bytes());
        for id in [&self.grant_id, &self.reference_id, &self.object_id, &self.manifest_hash] {
            out.extend(id);
        }
        qualified(&mut out, &self.owner)?;
        qualified(&mut out, &self.grantee)?;
        out.extend(self.epoch.to_be_bytes());
        out.extend(self.rights.to_be_bytes());
        out.extend(self.issued_at.to_be_bytes());
        out.extend(self.expires_at.to_be_bytes());
        Ok(out)
    }
    /// # Errors
    /// Refuses malformed fields.
    pub fn hash(&self) -> Result<[u8; 32], FormatError> {
        digest("ramflux.attachment.grant.v1", &self.canonical_bytes()?)
    }
    /// # Errors
    /// Refuses malformed fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        signing("ramflux.attachment.grant.sign.v1", &self.canonical_bytes()?)
    }
    /// RFC1 prefix without a registration receipt: signature evidence only.
    /// # Errors
    /// Refuses malformed fields and invalid owner signatures.
    pub fn signed_bytes(&self, signature: &[u8; 64]) -> Result<Vec<u8>, FormatError> {
        verify(&self.owner.signing_public_key, &self.signing_bytes()?, signature)?;
        let mut out = b"RFC1".to_vec();
        lp(&mut out, &self.canonical_bytes()?)?;
        lp(&mut out, signature)?;
        Ok(out)
    }
    /// Decodes only an unregistered signed grant. It confers no serving authority.
    /// # Errors
    /// Refuses trailing bytes, noncanonical fields and invalid owner signatures.
    pub fn decode_signed(input: &[u8]) -> Result<VerifiedScopedGrant, FormatError> {
        if input.len() > MAX_GRANT {
            return Err(FormatError("grant cap"));
        }
        let mut c = Cursor(input);
        if c.take(4)? != b"RFC1" {
            return Err(FormatError("grant container"));
        }
        let n = usize::try_from(c.u32()?).map_err(|_| FormatError("grant length"))?;
        let body = c.take(n)?;
        let mut g = Cursor(body);
        if g.take(4)? != b"RFG1" || g.u32()? != 1 {
            return Err(FormatError("grant version"));
        }
        let grant = Self {
            grant_id: g.array()?,
            reference_id: g.array()?,
            object_id: g.array()?,
            manifest_hash: g.array()?,
            owner: read_qualified(&mut g)?,
            grantee: read_qualified(&mut g)?,
            epoch: g.u64()?,
            rights: g.u32()?,
            issued_at: g.u64()?,
            expires_at: g.u64()?,
        };
        if !g.0.is_empty() || c.u32()? != 64 {
            return Err(FormatError("grant framing"));
        }
        let signature = c.array()?;
        if !c.0.is_empty() || grant.canonical_bytes()?.as_slice() != body {
            return Err(FormatError("grant canonical"));
        }
        verify(&grant.owner.signing_public_key, &grant.signing_bytes()?, &signature)?;
        Ok(VerifiedScopedGrant { grant, signature })
    }
}
pub(super) fn signing(domain: &str, body: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    lp(&mut out, domain.as_bytes())?;
    lp(&mut out, body)?;
    Ok(out)
}
pub(super) fn verify(key: &[u8; 32], body: &[u8], signature: &[u8; 64]) -> Result<(), FormatError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| FormatError("grant key"))?;
    key.verify_strict(body, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| FormatError("grant signature"))
}
