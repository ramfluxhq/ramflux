// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded dormant HTTP relay codecs; no account or publication authority.
use super::{
    Commit, Deserialize, PairingWire, Result, Serialize, WireError, b32, budget, decode_base64url,
    domain, encode_base64url, header, integer, require,
};
fn role(v: &str) -> Result<()> {
    require(matches!(v, "initiator" | "responder"), "role")
}
fn reason(v: &str) -> Result<()> {
    require(matches!(v, "cancel" | "mismatch" | "expired" | "done" | "protocol"), "reason")
}
fn seq(v: u64) -> Result<()> {
    integer(v, "seq")
}
fn issuer(v: u64) -> Result<()> {
    integer(v, "issuer_seq")?;
    require(v >= 1, "issuer_seq")
}
fn raw(v: &str, min: usize, max: usize, field: &'static str) -> Result<usize> {
    let b = decode_base64url(v).map_err(|_| WireError::Field(field))?;
    require(b.len() >= min && b.len() <= max && encode_base64url(&b) == v, field)?;
    Ok(b.len())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayFrame {
    Commit { value: Commit },
    RevealChunk { object_id: String, index: u64, count: u64, total_bytes: u64, bytes: String },
    OfferChunk { object_id: String, index: u64, count: u64, total_bytes: u64, bytes: String },
    Confirm { role: String, transcript_hash: String, mac: String },
    Channel { counter: u64, ciphertext: String },
}
impl RelayFrame {
    /// Validate a single bounded frame, before any assembly or queue allocation.
    /// # Errors
    /// Rejects unknown fields/kinds, invalid sizes, counters or chunk geometry.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Commit { value } => value.validate(),
            Self::RevealChunk { object_id, index, count, total_bytes, bytes } => {
                chunk(object_id, *index, *count, *total_bytes, bytes, 24576)
            }
            Self::OfferChunk { object_id, index, count, total_bytes, bytes } => {
                chunk(object_id, *index, *count, *total_bytes, bytes, 16384)
            }
            Self::Confirm { role: r, transcript_hash, mac } => {
                role(r)?;
                b32(transcript_hash, "transcript_hash")?;
                b32(mac, "mac")
            }
            Self::Channel { counter, ciphertext } => {
                integer(*counter, "counter")?;
                raw(ciphertext, 16, 11716, "ciphertext")?;
                Ok(())
            }
        }
    }
    fn sender(&self) -> Option<&str> {
        match self {
            Self::Commit { value } => Some(&value.role),
            Self::Confirm { role, .. } => Some(role),
            _ => None,
        }
    }
}
fn chunk(id: &str, index: u64, count: u64, total: u64, encoded: &str, max: u64) -> Result<()> {
    b32(id, "object_id")?;
    integer(index, "index")?;
    integer(count, "count")?;
    integer(total, "total_bytes")?;
    require(total > 0 && total <= max, "total_bytes")?;
    require(count == total.div_ceil(8192) && count <= 3, "count")?;
    require(index < count, "index")?;
    let n = raw(encoded, 1, 8192, "bytes")?;
    require(
        n as u64 == if index + 1 == count { total - index * 8192 } else { 8192 },
        "chunk_length",
    )
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub recipient_token: String,
    pub claim_nonce: String,
}
impl PairingWire for Claim {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Claim")?;
        b32(&self.invitation_id, "invitation_id")?;
        issuer(self.issuer_seq)?;
        b32(&self.recipient_token, "recipient_token")?;
        b32(&self.claim_nonce, "claim_nonce")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claimed {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub claim_nonce: String,
    pub role: String,
    pub expires_at: u64,
}
impl PairingWire for Claimed {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Claimed")?;
        b32(&self.invitation_id, "invitation_id")?;
        issuer(self.issuer_seq)?;
        b32(&self.claim_nonce, "claim_nonce")?;
        require(self.role == "responder", "role")?;
        integer(self.expires_at, "expires_at")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Send {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub role: String,
    pub token: String,
    pub seq: u64,
    pub frame: RelayFrame,
}
impl PairingWire for Send {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Send")?;
        b32(&self.invitation_id, "invitation_id")?;
        issuer(self.issuer_seq)?;
        role(&self.role)?;
        b32(&self.token, "token")?;
        seq(self.seq)?;
        self.frame.validate()?;
        if let RelayFrame::Commit { value } = &self.frame {
            require(value.invitation_id == self.invitation_id, "frame_invitation")?;
        }
        if let Some(r) = self.frame.sender() {
            require(r == self.role, "frame_role")?;
        }
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sent {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub role: String,
    pub seq: u64,
}
impl PairingWire for Sent {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Sent")?;
        b32(&self.invitation_id, "invitation_id")?;
        role(&self.role)?;
        seq(self.seq)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub role: String,
    pub token: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub after_seq: Option<u64>,
}
impl PairingWire for Poll {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Poll")?;
        b32(&self.invitation_id, "invitation_id")?;
        issuer(self.issuer_seq)?;
        role(&self.role)?;
        b32(&self.token, "token")?;
        if let Some(v) = self.after_seq {
            seq(v)?;
        }
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedFrame {
    pub seq: u64,
    pub frame: RelayFrame,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Polled {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub frames: Vec<QueuedFrame>,
    pub closed: bool,
}
impl PairingWire for Polled {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Polled")?;
        b32(&self.invitation_id, "invitation_id")?;
        require(self.frames.len() <= 2, "frames")?;
        for v in &self.frames {
            seq(v.seq)?;
            v.frame.validate()?;
        }
        require(
            self.frames.windows(2).all(|v| v[0].seq.checked_add(1) == Some(v[1].seq)),
            "frame_sequence",
        )?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Close {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub role: String,
    pub token: String,
    pub reason: String,
}
impl PairingWire for Close {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Close")?;
        b32(&self.invitation_id, "invitation_id")?;
        issuer(self.issuer_seq)?;
        role(&self.role)?;
        b32(&self.token, "token")?;
        reason(&self.reason)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closed {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub reason: String,
}
impl PairingWire for Closed {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Closed")?;
        b32(&self.invitation_id, "invitation_id")?;
        reason(&self.reason)?;
        budget(self, Self::LIMIT)
    }
}
/// Borrowed allocator evidence. The server owns this binding, never caller JSON.
pub struct TokenBinding<'a> {
    pub invitation_id: &'a str,
    pub issuer_seq: u64,
    pub role: &'a str,
    pub token: &'a str,
    pub expires_at: u64,
}
impl TokenBinding<'_> {
    fn check(&self, id: &str, issuer: u64, r: &str, token: &str, now: u64) -> Result<()> {
        require(self.invitation_id == id && self.issuer_seq == issuer, "token_context")?;
        require(self.role == r, "token_role")?;
        require(self.token == token, "token")?;
        require(now < self.expires_at, "expired")
    }
}
impl Send {
    /// Match validated bytes to server-owned bearer and role before queue access.
    /// # Errors
    /// Rejects wrong invitation, issuer, role, token or deadline.
    pub fn validate_token(&self, binding: &TokenBinding<'_>, now: u64) -> Result<()> {
        self.validate()?;
        binding.check(&self.invitation_id, self.issuer_seq, &self.role, &self.token, now)
    }
    /// Existing custody object hash over the exact canonical Send frame.
    /// # Errors
    /// Rejects malformed input, never normalizing received frames.
    pub fn frame_digest(&self) -> Result<String> {
        self.validate()?;
        super::super::framed_hash(domain::CUSTODY_OBJECT_HASH, self).map_err(|_| WireError::Json)
    }
}
impl Poll {
    /// Validate server-owned role and capability before reading/acknowledging a queue.
    /// # Errors
    /// Rejects wrong context, role, token or deadline.
    pub fn validate_token(&self, binding: &TokenBinding<'_>, now: u64) -> Result<()> {
        self.validate()?;
        binding.check(&self.invitation_id, self.issuer_seq, &self.role, &self.token, now)
    }
}
impl Close {
    /// Validate server-owned role and capability before closing a slot.
    /// # Errors
    /// Rejects wrong context, role, token or deadline.
    pub fn validate_token(&self, binding: &TokenBinding<'_>, now: u64) -> Result<()> {
        self.validate()?;
        binding.check(&self.invitation_id, self.issuer_seq, &self.role, &self.token, now)
    }
}
impl Claim {
    /// Only the allocated recipient token may claim this invitation.
    /// # Errors
    /// Rejects wrong context, role, token or deadline.
    pub fn validate_token(&self, binding: &TokenBinding<'_>, now: u64) -> Result<()> {
        self.validate()?;
        binding.check(&self.invitation_id, self.issuer_seq, "responder", &self.recipient_token, now)
    }
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Claim { redacted }")
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.recipient_token);
    }
}

impl std::fmt::Debug for Send {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Send { redacted }")
    }
}
impl Drop for Send {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

impl std::fmt::Debug for Poll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Poll { redacted }")
    }
}
impl Drop for Poll {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

impl std::fmt::Debug for Close {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Close { redacted }")
    }
}
impl Drop for Close {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}
