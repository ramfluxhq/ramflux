// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-account logical transfer contract. Data verification never grants publication authority.
//! Catalog comparison, signature verification and encrypted staging belong to their owners.
use super::{DeviceRef, PairingWire, Result, WireError, b32, budget, reference, require};
use serde::{Deserialize, Serialize};

mod binding;
mod diff;
mod integrity;
mod keys;
pub use keys::{MAX_STABLE_KEY_BYTES, encode_keyless_row_key, encode_stable_key};
pub mod lease;
mod packet;
mod preservation;
mod record;
pub mod relay;
mod stream;
pub use binding::DataBinding;
pub use diff::{DiffStats, diff_snapshots};
pub use integrity::{ChainHasher, RootHasher, chunk_digest, chunk_layout, manifest_hash};
pub use packet::{DataPacket, FullError, SecretBase64};
pub use preservation::PreservationFull;
pub use record::{CellType, RecordHeader, RecordOp};
pub use stream::{StreamError, copy_record_cells, read_record_header, write_record_header};

pub const PROFILE: &str = "primary_transfer_full_v1";
pub const SELECTION: &str = "full_account_data_v1";
pub const CHUNK_BYTES: u32 = 262_144;
pub const MANIFEST_BYTES: usize = 1_048_576;
pub const PACKET_BYTES: usize = 524_288;
/// Conservative inner base64 chunk plus the approved 1-KiB plaintext framing reserve.
pub const PACKET_PLAINTEXT_BYTES: usize = 349_528 + 1024;
pub const PACKET_CIPHERTEXT_BYTES: usize = PACKET_PLAINTEXT_BYTES + 16;
pub const LEASE_SECONDS: u64 = 604_800;
/// Controller-confirmed reserve required by both endpoints before constructing J3.
pub const MIN_J3_LEASE_SECONDS: u64 = 86_400;
/// Controller-confirmed endpoint tail limit; the relay cannot inspect encrypted manifests.
pub const MAX_TAIL_BYTES: u64 = 1_073_741_824;
pub const PACKETS_PER_KEY: u64 = 65_536;

/// Full-profile counts are exact decimal strings, including values above JSON's safe integer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U64(pub u64);
impl Serialize for U64 {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct Decimal;
        impl serde::de::Visitor<'_> for Decimal {
            type Value = U64;
            fn expecting(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                output.write_str("canonical unsigned decimal string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<U64, E> {
                if value.is_empty()
                    || value.len() > 20
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(E::custom("invalid unsigned decimal"));
                }
                value.parse().map(U64).map_err(|_| E::custom("unsigned decimal overflow"))
            }
        }
        decoder.deserialize_str(Decimal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Transfer,
    Exclude,
    Rebuild,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    pub id: String,
    pub codec_version: U64,
    pub restrictive: bool,
    pub disposition: Disposition,
    pub source_rows: U64,
    pub portable_records: U64,
    pub encoded_bytes: U64,
    pub rule_hash: String,
}
impl Family {
    fn validate(&self) -> Result<()> {
        identifier(&self.id)?;
        require(self.codec_version.0 > 0, "codec_version")?;
        b32(&self.rule_hash, "rule_hash")?;
        require(self.encoded_bytes.0 <= i64::MAX.cast_unsigned(), "encoded_bytes")?;
        if self.disposition != Disposition::Transfer {
            require(self.portable_records.0 == 0 && self.encoded_bytes.0 == 0, "disposition")?;
        }
        Ok(())
    }
}
fn identifier(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'-' | b'.' | b'/')),
        "family",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    Base,
    Delta,
    Tail,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub account_anchor: String,
    pub source_ref: DeviceRef,
    pub destination_ref: DeviceRef,
    pub base_record_hash: String,
    pub snapshot_id: String,
    pub snapshot_cut: U64,
    #[serde(deserialize_with = "super::required_nullable")]
    pub previous_cut: Option<U64>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub parent_manifest_hash: Option<String>,
    pub kind: ManifestKind,
    pub source_erasure_generation: U64,
    pub storage_generation: U64,
    pub census_hash: String,
    pub families: Vec<Family>,
    pub total_bytes: U64,
    pub chunk_bytes: U64,
    pub chunk_count: U64,
    pub chunks_root: String,
    pub attachment_policy: String,
}
impl PairingWire for Manifest {
    const LIMIT: usize = MANIFEST_BYTES;
    fn validate(&self) -> Result<()> {
        require(
            self.schema == "ramflux.pairing.full_transfer.manifest.v1" && self.version == 1,
            "schema",
        )?;
        for value in [
            &self.transfer_id,
            &self.account_anchor,
            &self.base_record_hash,
            &self.snapshot_id,
            &self.census_hash,
            &self.chunks_root,
        ] {
            b32(value, "manifest_hash")?;
        }
        reference(&self.source_ref)?;
        reference(&self.destination_ref)?;
        require(
            self.source_ref.account_anchor == self.account_anchor
                && self.destination_ref.account_anchor == self.account_anchor
                && self.source_ref != self.destination_ref,
            "manifest_context",
        )?;
        match self.kind {
            ManifestKind::Base => require(
                self.snapshot_cut.0 == 0
                    && self.previous_cut.is_none()
                    && self.parent_manifest_hash.is_none(),
                "manifest_chain",
            )?,
            ManifestKind::Delta | ManifestKind::Tail => {
                let previous = self.previous_cut.ok_or(WireError::Field("previous_cut"))?;
                require(previous.0.checked_add(1) == Some(self.snapshot_cut.0), "snapshot_cut")?;
                b32(
                    self.parent_manifest_hash
                        .as_deref()
                        .ok_or(WireError::Field("parent_manifest_hash"))?,
                    "parent_manifest_hash",
                )?;
            }
        }
        require(
            self.kind != ManifestKind::Tail || self.total_bytes.0 <= MAX_TAIL_BYTES,
            "NoSpace",
        )?;
        require(
            self.chunk_bytes.0 == u64::from(CHUNK_BYTES)
                && self.chunk_count.0 == chunk_layout(self.total_bytes.0)?.0,
            "chunk_count",
        )?;
        require(self.attachment_policy == "remote_ciphertext", "attachment_policy")?;
        require(
            !self.families.is_empty() && self.families.windows(2).all(|w| w[0].id < w[1].id),
            "families",
        )?;
        let mut bytes = 0_u64;
        for family in &self.families {
            family.validate()?;
            bytes = bytes.checked_add(family.encoded_bytes.0).ok_or(WireError::Size)?;
        }
        require(bytes == self.total_bytes.0, "family_bytes")?;
        budget(self, Self::LIMIT)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    pub manifest: Manifest,
    pub source_signature: String,
}
impl Manifest {
    /// Compare every projection against the local compiled catalog, including zero-row entries.
    /// Reverse streams select only locally declared restrictive projections.
    /// # Errors
    /// Refuses omitted/extra/reordered families or a peer-chosen codec, rule or restrictive flag.
    pub fn validate_catalog(&self, catalog: &[Family], reverse: bool) -> Result<()> {
        self.validate()?;
        let mut expected = catalog.iter().filter(|family| !reverse || family.restrictive);
        for family in &self.families {
            let entry = expected.next().ok_or(WireError::Field("SchemaMismatch"))?;
            require(
                family.id == entry.id
                    && family.codec_version == entry.codec_version
                    && family.restrictive == entry.restrictive
                    && family.disposition == entry.disposition
                    && family.rule_hash == entry.rule_hash,
                "SchemaMismatch",
            )?;
        }
        require(expected.next().is_none(), "SchemaMismatch")
    }

    /// # Errors
    /// Rejects invalid manifest fields before its source branch signs the snapshot commitment.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        crate::custody::signing_bytes("ramflux.identity.transfer.manifest.full.v1", self)
            .map_err(|_| WireError::Json)
    }
}
impl PairingWire for SourceManifest {
    const LIMIT: usize = MANIFEST_BYTES;
    fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        let signature = crate::decode_base64url(&self.source_signature)
            .map_err(|_| WireError::Field("source_signature"))?;
        require(
            signature.len() == 64 && crate::encode_base64url(&signature) == self.source_signature,
            "source_signature",
        )?;
        budget(self, Self::LIMIT)
    }
}

impl SourceManifest {
    /// Check the exact predecessor and frozen catalog/context before accepting a later cut.
    /// Signature and current-head admission must also be checked by the local owner.
    /// # Errors
    /// Rejects missing/reordered cuts, changed bindings/catalog or children of a tail.
    pub fn verify_predecessor(&self, previous: &Self) -> Result<()> {
        self.validate()?;
        previous.validate()?;
        let current = &self.manifest;
        let parent = &previous.manifest;
        require(
            current.kind != ManifestKind::Base
                && parent.kind != ManifestKind::Tail
                && current.previous_cut == Some(parent.snapshot_cut)
                && current.parent_manifest_hash.as_deref()
                    == Some(crate::encode_base64url(manifest_hash(previous)?).as_str())
                && current.transfer_id == parent.transfer_id
                && current.account_anchor == parent.account_anchor
                && current.source_ref == parent.source_ref
                && current.destination_ref == parent.destination_ref
                && current.base_record_hash == parent.base_record_hash
                && current.census_hash == parent.census_hash
                && current.storage_generation == parent.storage_generation
                && current.families.len() == parent.families.len()
                && current.families.iter().zip(&parent.families).all(|(a, b)| {
                    a.id == b.id
                        && a.codec_version == b.codec_version
                        && a.restrictive == b.restrictive
                        && a.disposition == b.disposition
                        && a.rule_hash == b.rule_hash
                }),
            "manifest_predecessor",
        )
    }
}

#[cfg(test)]
mod tests;
