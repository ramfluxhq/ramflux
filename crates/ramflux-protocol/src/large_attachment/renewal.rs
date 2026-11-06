// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant native renewal transcripts. Signatures prove possession, not current authority.
use super::grant::{signing, verify};
use super::native::{Cursor, identity};
use super::{FormatError, QualifiedOwner, digest, lp};

/// Only recipient read targets and the renewal operation are accepted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentOperation {
    pub op: u32,
    pub method: String,
    pub path: String,
    pub audience: String,
    pub object_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub grant_id: [u8; 32],
    pub grant_epoch: u64,
    pub authority_generation: u64,
    pub operation_id: [u8; 32],
    pub payload_generation: u64,
    pub segment_index: u64,
    pub offset: u64,
    pub length: u64,
    pub body_digest: [u8; 32],
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [char::from(HEX[usize::from(b >> 4)]), char::from(HEX[usize::from(b & 15)])])
        .collect()
}
impl AttachmentOperation {
    /// # Errors
    /// Refuses unsupported methods, paths, generations, ranges or operation kinds.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.grant_epoch == 0 || self.authority_generation == 0 || self.payload_generation == 0 {
            return Err(FormatError("operation generation"));
        }
        let object_path =
            format!("/attachments/{}/{}", hex(&self.object_id), hex(&self.manifest_hash));
        let (method, path) = match self.op {
            1 => ("GET", format!("{object_path}/segments/{}", self.segment_index)),
            2 => ("HEAD", format!("{object_path}/segments/0")),
            3 => ("POST", format!("{object_path}/missing")),
            8 => ("POST", "/s9/attachments/renew".into()),
            _ => return Err(FormatError("operation kind")),
        };
        if self.method != method || self.path != path {
            return Err(FormatError("operation endpoint"));
        }
        if matches!(self.op, 2 | 8)
            && (self.segment_index != 0 || self.offset != 0 || self.length != 0)
        {
            return Err(FormatError("operation unused range"));
        }
        if self.op == 1
            && (self.length == 0
                || self.length > 1_048_576
                || self.offset.checked_add(self.length).is_none_or(|end| end > u64::from(super::SEGMENT_BYTES)))
        {
            return Err(FormatError("operation range"));
        }
        if self.op == 3
            && (self.segment_index != 0
                || self.length == 0
                || self.length > 256
                || self.offset.checked_add(self.length).is_none())
        {
            return Err(FormatError("operation page"));
        }
        if matches!(self.op, 1 | 2) && self.body_digest != body_digest(&[]) {
            return Err(FormatError("read body"));
        }
        let mut out = b"RFO1".to_vec();
        out.extend(1_u32.to_be_bytes());
        out.extend(self.op.to_be_bytes());
        for s in [&self.method, &self.path, &self.audience] {
            identity(&mut out, s)?;
        }
        for id in [&self.object_id, &self.manifest_hash, &self.grant_id] {
            out.extend(id);
        }
        out.extend(self.grant_epoch.to_be_bytes());
        out.extend(self.authority_generation.to_be_bytes());
        out.extend(self.operation_id);
        for v in [self.payload_generation, self.segment_index, self.offset, self.length] {
            out.extend(v.to_be_bytes());
        }
        out.extend(self.body_digest);
        Ok(out)
    }
    /// # Errors
    /// Refuses oversized, malformed, noncanonical or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > 4096 {
            return Err(FormatError("operation cap"));
        }
        let mut c = Cursor(bytes);
        if c.take(4)? != b"RFO1" || c.u32()? != 1 {
            return Err(FormatError("operation version"));
        }
        let op = Self {
            op: c.u32()?,
            method: c.identity()?,
            path: c.identity()?,
            audience: c.identity()?,
            object_id: c.array()?,
            manifest_hash: c.array()?,
            grant_id: c.array()?,
            grant_epoch: c.u64()?,
            authority_generation: c.u64()?,
            operation_id: c.array()?,
            payload_generation: c.u64()?,
            segment_index: c.u64()?,
            offset: c.u64()?,
            length: c.u64()?,
            body_digest: c.array()?,
        };
        if !c.0.is_empty() || op.canonical_bytes()? != bytes {
            return Err(FormatError("operation framing"));
        }
        Ok(op)
    }
    /// # Errors
    /// Refuses invalid operation fields.
    pub fn hash(&self) -> Result<[u8; 32], FormatError> {
        digest("ramflux.attachment.operation.v1", &self.canonical_bytes()?)
    }
}
/// Streaming body hash, including the empty body.
#[must_use]
pub fn body_digest(bytes: &[u8]) -> [u8; 32] {
    let tag = b"ramflux.attachment.request.body.v1";
    let mut h = blake3::Hasher::new();
    h.update(&34_u32.to_be_bytes());
    h.update(tag);
    h.update(&(bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    *h.finalize().as_bytes()
}
fn qualified(out: &mut Vec<u8>, q: &QualifiedOwner, home: bool) -> Result<(), FormatError> {
    identity(out, &q.account_anchor)?;
    identity(out, &q.device_id)?;
    if q.device_epoch == 0 {
        return Err(FormatError("device epoch"));
    }
    out.extend(q.device_epoch.to_be_bytes());
    out.extend(q.signing_public_key);
    if home { identity(out, &q.home_node_id) } else { lp(out, &[]) }
}
/// Stable requester digest excludes routing home only.
/// # Errors
/// Refuses malformed requester identities.
pub fn requester_digest(q: &QualifiedOwner) -> Result<[u8; 32], FormatError> {
    let mut bytes = Vec::new();
    qualified(&mut bytes, q, false)?;
    digest("ramflux.attachment.requester.v1", &bytes)
}
/// Exact request bytes are retained across home forwarding and transport retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalRequest {
    pub operation: Vec<u8>,
    pub body: Vec<u8>,
}
impl RenewalRequest {
    /// # Errors
    /// Refuses invalid target/renewal combinations or body substitution.
    pub fn target(&self) -> Result<(AttachmentOperation, AttachmentOperation), FormatError> {
        if self.body.len() > 8192 {
            return Err(FormatError("renewal body cap"));
        }
        let renew = AttachmentOperation::decode(&self.operation)?;
        let mut c = Cursor(&self.body);
        if c.take(4)? != b"RFRQ" || c.u32()? != 1 {
            return Err(FormatError("renewal body version"));
        }
        let n = c.u32()? as usize;
        let target = AttachmentOperation::decode(c.take(n)?)?;
        if !c.0.is_empty() {
            return Err(FormatError("renewal body framing"));
        }
        if renew.op != 8 || !matches!(target.op, 1..=3) {
            return Err(FormatError("renewal target kind"));
        }
        if renew.body_digest != body_digest(&self.body) {
            return Err(FormatError("renewal body digest"));
        }
        if renew.object_id != target.object_id
            || renew.manifest_hash != target.manifest_hash
            || renew.grant_id != target.grant_id
            || renew.grant_epoch != target.grant_epoch
            || renew.authority_generation != target.authority_generation
            || renew.payload_generation != target.payload_generation
            || renew.operation_id == target.operation_id
        {
            return Err(FormatError("renewal target binding"));
        }
        Ok((renew, target))
    }
    /// # Errors
    /// Refuses malformed targets; the caller supplies a fresh distinct operation id.
    pub fn new(
        target: &AttachmentOperation,
        source: &str,
        operation_id: [u8; 32],
    ) -> Result<Self, FormatError> {
        let mut body = b"RFRQ".to_vec();
        body.extend(1_u32.to_be_bytes());
        lp(&mut body, &target.canonical_bytes()?)?;
        let renew = AttachmentOperation {
            op: 8,
            method: "POST".into(),
            path: "/s9/attachments/renew".into(),
            audience: source.into(),
            operation_id,
            segment_index: 0,
            offset: 0,
            length: 0,
            body_digest: body_digest(&body),
            ..target.clone()
        };
        let result = Self { operation: renew.canonical_bytes()?, body };
        result.target()?;
        Ok(result)
    }
}
/// Home-signed W. The home key must be pinned by authoritative node trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAttestation {
    pub requester: QualifiedOwner,
    pub grant_hash: [u8; 32],
    pub grant_id: [u8; 32],
    pub grant_epoch: u64,
    pub source_issuer: String,
    pub home_issuer: String,
    pub challenge: [u8; 32],
    pub operation_hash: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}
fn lifetime(issued: u64, expires: u64) -> Result<(), FormatError> {
    if issued >= expires || expires - issued > 30 {
        return Err(FormatError("proof lifetime"));
    }
    Ok(())
}
impl ForwardAttestation {
    /// # Errors
    /// Refuses invalid identity, epoch, home or lifetime fields.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        lifetime(self.issued_at, self.expires_at)?;
        if self.grant_epoch == 0 || self.requester.home_node_id != self.home_issuer {
            return Err(FormatError("forward home binding"));
        }
        let mut out = b"RFW1".to_vec();
        out.extend(1_u32.to_be_bytes());
        qualified(&mut out, &self.requester, true)?;
        out.extend(self.grant_hash);
        out.extend(self.grant_id);
        out.extend(self.grant_epoch.to_be_bytes());
        identity(&mut out, &self.source_issuer)?;
        identity(&mut out, &self.home_issuer)?;
        out.extend(self.challenge);
        out.extend(self.operation_hash);
        out.extend(self.issued_at.to_be_bytes());
        out.extend(self.expires_at.to_be_bytes());
        Ok(out)
    }
    /// # Errors
    /// Refuses malformed fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        signing("ramflux.attachment.forward.sign.v1", &self.canonical_bytes()?)
    }
    /// # Errors
    /// Refuses malformed fields or a signature from a different home key.
    pub fn verify(&self, key: &[u8; 32], signature: &[u8; 64]) -> Result<(), FormatError> {
        verify(key, &self.signing_bytes()?, signature)
    }
    /// # Errors
    /// Refuses malformed fields.
    pub fn hash(&self) -> Result<[u8; 32], FormatError> {
        digest("ramflux.attachment.forward.v1", &self.canonical_bytes()?)
    }
}
/// Fresh requester proof; nonce consumption belongs to the receiving authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterPop {
    pub operation_hash: [u8; 32],
    pub requester_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub forward_digest: [u8; 32],
}
impl RequesterPop {
    /// # Errors
    /// Refuses invalid proof lifetime.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        lifetime(self.issued_at, self.expires_at)?;
        let mut out = b"RFP1".to_vec();
        out.extend(1_u32.to_be_bytes());
        out.extend(self.operation_hash);
        out.extend(self.requester_digest);
        out.extend(self.nonce);
        out.extend(self.issued_at.to_be_bytes());
        out.extend(self.expires_at.to_be_bytes());
        out.extend(self.forward_digest);
        Ok(out)
    }
    /// # Errors
    /// Refuses invalid proof fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        signing("ramflux.attachment.pop.sign.v1", &self.canonical_bytes()?)
    }
    /// # Errors
    /// Refuses an invalid signature or malformed fields.
    pub fn verify(&self, key: &[u8; 32], signature: &[u8; 64]) -> Result<(), FormatError> {
        verify(key, &self.signing_bytes()?, signature)
    }
}
impl RenewalRequest {
    /// Checks the grant and pinned routing before any home attestation is signed.
    /// This is not source registration, retention or replay admission.
    /// # Errors
    /// Refuses requester/routing/rights/time or object/generation substitution.
    pub fn validate(
        &self,
        grant: &super::VerifiedScopedGrant,
        requester: &QualifiedOwner,
        source: &str,
        relay: &str,
        now: u64,
    ) -> Result<(), FormatError> {
        let (renew, target) = self.target()?;
        let g = grant.grant();
        if &g.grantee != requester {
            return Err(FormatError("renewal requester"));
        }
        if renew.audience != source || target.audience != relay {
            return Err(FormatError("renewal audience"));
        }
        if target.object_id != g.object_id
            || target.manifest_hash != g.manifest_hash
            || target.grant_id != g.grant_id
            || target.grant_epoch != g.epoch
        {
            return Err(FormatError("renewal grant binding"));
        }
        let right = 1 << (target.op - 1);
        if g.rights & (8 | right) != (8 | right) {
            return Err(FormatError("renewal rights"));
        }
        if now < g.issued_at || now >= g.expires_at {
            return Err(FormatError("renewal grant time"));
        }
        Ok(())
    }
}
impl ForwardAttestation {
    /// # Errors
    /// Refuses a substituted attestation, stale challenge or expired proof.
    pub fn validate(
        &self,
        request: &RenewalRequest,
        grant: &super::VerifiedScopedGrant,
        requester: &QualifiedOwner,
        challenge: &[u8; 32],
        now: u64,
    ) -> Result<(), FormatError> {
        if &self.requester != requester
            || &self.challenge != challenge
            || self.grant_hash != grant.grant().hash()?
            || self.grant_id != grant.grant().grant_id
            || self.grant_epoch != grant.grant().epoch
            || self.source_issuer != request.target()?.0.audience
            || self.operation_hash != request.target()?.0.hash()?
        {
            return Err(FormatError("forward request binding"));
        }
        self.canonical_bytes()?;
        if self.issued_at > now.saturating_add(5)
            || self.expires_at <= now
            || self.expires_at > grant.grant().expires_at
        {
            return Err(FormatError("forward time"));
        }
        Ok(())
    }
}
impl RequesterPop {
    /// # Errors
    /// Refuses changed requester, operation, attestation or stale timestamps.
    pub fn validate(&self, w: &ForwardAttestation, now: u64) -> Result<(), FormatError> {
        self.canonical_bytes()?;
        if self.operation_hash != w.operation_hash
            || self.requester_digest != requester_digest(&w.requester)?
            || self.forward_digest != w.hash()?
        {
            return Err(FormatError("pop binding"));
        }
        if self.issued_at < w.issued_at
            || self.expires_at > w.expires_at
            || self.issued_at > now.saturating_add(5)
            || self.expires_at <= now
        {
            return Err(FormatError("pop time"));
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "renewal_tests.rs"]
mod tests;
impl ForwardAttestation {
    /// # Errors
    /// Refuses oversized/noncanonical native W bytes before any unbounded allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > 2048 {
            return Err(FormatError("forward cap"));
        }
        let mut c = Cursor(bytes);
        if c.take(4)? != b"RFW1" || c.u32()? != 1 {
            return Err(FormatError("forward version"));
        }
        let requester = QualifiedOwner {
            account_anchor: c.identity()?,
            device_id: c.identity()?,
            device_epoch: c.u64()?,
            signing_public_key: c.array()?,
            home_node_id: c.identity()?,
        };
        let w = Self {
            requester,
            grant_hash: c.array()?,
            grant_id: c.array()?,
            grant_epoch: c.u64()?,
            source_issuer: c.identity()?,
            home_issuer: c.identity()?,
            challenge: c.array()?,
            operation_hash: c.array()?,
            issued_at: c.u64()?,
            expires_at: c.u64()?,
        };
        if !c.0.is_empty() || w.canonical_bytes()? != bytes {
            return Err(FormatError("forward framing"));
        }
        Ok(w)
    }
}
impl RequesterPop {
    /// # Errors
    /// Refuses noncanonical native P bytes, wrong version or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() != 152 {
            return Err(FormatError("pop length"));
        }
        let mut c = Cursor(bytes);
        if c.take(4)? != b"RFP1" || c.u32()? != 1 {
            return Err(FormatError("pop version"));
        }
        let p = Self {
            operation_hash: c.array()?,
            requester_digest: c.array()?,
            nonce: c.array()?,
            issued_at: c.u64()?,
            expires_at: c.u64()?,
            forward_digest: c.array()?,
        };
        if p.canonical_bytes()? != bytes {
            return Err(FormatError("pop framing"));
        }
        Ok(p)
    }
}
