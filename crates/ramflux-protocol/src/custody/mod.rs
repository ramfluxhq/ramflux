// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 custody wire primitives. These do not reinterpret legacy flat records.
mod contact;
pub use contact::*;
mod contact_card;
pub use contact_card::*;
mod network;
mod node;
pub use network::*;
mod proof;
mod types;
use crate::{MAX_SAFE_JSON_INTEGER, ProtocolError, canonical_json_bytes, domain, encode_base64url};
pub use node::*;
pub use proof::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use types::*;

pub const MAX_RECORD_BYTES: usize = 512 * 1024;
pub const MAX_ROSTER: usize = 1024;
pub const REVOCATION_RESERVE: usize = 64;
pub const MAX_ENROLLMENT_ROSTER: usize = MAX_ROSTER - REVOCATION_RESERVE;
pub const MAX_REVOKED_IDS: usize = 65_536;
pub const MAX_REVOKED_LIST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RANGE: u64 = (1 << 21) - 1;
pub const MAX_REVISION: u64 = (1 << 32) - 1;
pub const MAX_BRANCH_LEASE_SECONDS: u64 = 2_592_000;
pub const CLOCK_SKEW_SECONDS: u64 = 300;
pub const MASTER_SCOPES: [&str; 5] =
    ["branch_certify", "contact_consent", "delegate", "device_set", "profile"];

pub(crate) fn invalid(reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidIdentityRecord(reason)
}
/// Encode the one 53-bit epoch without wrapping or accepting revision zero.
/// # Errors
/// Rejects zero or exhausted ranges/revisions.
pub fn encode_epoch(range: u64, revision: u64) -> Result<u64, ProtocolError> {
    if range == 0 || range > MAX_RANGE || revision == 0 || revision > MAX_REVISION {
        return Err(invalid("custody epoch outside certified range"));
    }
    Ok((range << 32) | revision)
}
/// Decode the one epoch into its certified range and within-range revision.
/// # Errors
/// Rejects unsafe JSON integers and zero range/revision components.
pub fn decode_epoch(epoch: u64) -> Result<(u64, u64), ProtocolError> {
    if epoch > MAX_SAFE_JSON_INTEGER {
        return Err(invalid("unsafe custody epoch"));
    }
    let pair = (epoch >> 32, epoch & MAX_REVISION);
    encode_epoch(pair.0, pair.1)?;
    Ok(pair)
}
/// Exact custody signing transcript; nested signatures are deliberately retained.
/// # Errors
/// Returns canonical serialization failures.
pub fn signing_bytes<T: Serialize>(tag: &str, body: &T) -> Result<Vec<u8>, ProtocolError> {
    #[derive(Serialize)]
    struct Transcript<'a, T> {
        domain: &'a str,
        body: &'a T,
    }
    canonical_json_bytes(&Transcript { domain: tag, body })
}
/// Hash an explicitly NUL-framed custody object.
/// # Errors
/// Returns canonical serialization failures.
pub fn framed_hash<T: Serialize>(tag: &str, value: &T) -> Result<String, ProtocolError> {
    let mut hash = blake3::Hasher::new();
    hash.update(tag.as_bytes());
    hash.update(&[0]);
    hash.update(&canonical_json_bytes(value)?);
    Ok(encode_base64url(hash.finalize().as_bytes()))
}
/// Hash the entire envelope, including its signature.
/// # Errors
/// Returns canonical serialization failures.
pub fn object_hash<T: Serialize>(envelope: &Envelope<T>) -> Result<String, ProtocolError> {
    framed_hash(domain::CUSTODY_OBJECT_HASH, envelope)
}
/// Compute all six section hashes without removing nulls or nested signatures.
/// # Errors
/// Returns canonical serialization failures.
pub fn section_hashes(record: &DeviceSet) -> Result<SectionHashes, ProtocolError> {
    fn section<T: Serialize>(name: &str, value: &T) -> Result<String, ProtocolError> {
        #[derive(Serialize)]
        struct Section<'a, T> {
            section: &'a str,
            value: &'a T,
        }
        framed_hash(domain::CUSTODY_SECTION_HASH, &Section { section: name, value })
    }
    Ok(SectionHashes {
        profile: section("profile", &record.profile)?,
        devices: section("devices", &record.devices)?,
        delegations: section("delegations", &record.delegations)?,
        revoked_delegation_ids: section("revoked_delegation_ids", &record.revoked_delegation_ids)?,
        migration: section("migration", &record.migration)?,
        revoked_device_checkpoint: section(
            "revoked_device_checkpoint",
            &record.revoked_device_checkpoint,
        )?,
    })
}
/// Decode an exact custody schema from original bounded I-JSON bytes.
/// # Errors
/// Rejects excessive bytes/depth, duplicate keys, unknown/missing fields and noncanonical types.
pub fn decode<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, ProtocolError> {
    if bytes.len() > limit {
        return Err(invalid("custody wire byte budget exceeded"));
    }
    let mut depth = 0_u32;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 16 {
                        return Err(invalid("custody wire nesting exceeds 16"));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    let raw: Value = crate::parse_i_json(bytes)?;
    let typed: T = serde_json::from_value(raw.clone())?;
    // Round-tripping catches absent nullable fields which serde normally fills with None.
    if serde_json::to_value(&typed)? != raw {
        return Err(invalid("custody wire fields must be explicit and exact"));
    }
    Ok(typed)
}
impl Envelope<DeviceSet> {
    /// Decode a bounded complete record, preserving original duplicate-key evidence.
    /// # Errors
    /// Rejects malformed or oversized wire objects; signature verification remains mandatory.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode(bytes, MAX_RECORD_BYTES)
    }
}

#[cfg(test)]
mod tests;
