// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted full-profile packets. Secret cell bytes never enter a serde Value or Debug output.
use super::{DeviceRef, PairingWire, Result, U64, WireError, b32, budget, reference, require};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretBase64(#[serde(with = "secret_string")] Zeroizing<String>);
mod secret_string {
    use super::{Deserialize, Zeroizing};
    pub fn serialize<S: serde::Serializer>(
        value: &Zeroizing<String>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        decoder: D,
    ) -> std::result::Result<Zeroizing<String>, D::Error> {
        String::deserialize(decoder).map(Zeroizing::new)
    }
}
impl SecretBase64 {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(crate::encode_base64url(bytes)))
    }
    /// # Errors
    /// Refuses oversized, padded or noncanonical base64 before use by a staging owner.
    pub fn decode(&self, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let encoded_max = max.div_ceil(3).checked_mul(4).ok_or(WireError::Size)?;
        require(self.0.len() <= encoded_max, "packet_bytes")?;
        let decoded = Zeroizing::new(
            crate::decode_base64url(&self.0).map_err(|_| WireError::Field("packet_bytes"))?,
        );
        require(
            decoded.len() <= max
                && Zeroizing::new(crate::encode_base64url(decoded.as_slice())).as_str()
                    == self.0.as_str(),
            "packet_bytes",
        )?;
        Ok(decoded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FullError {
    UnsupportedRecord,
    SchemaMismatch,
    SnapshotBusy,
    SnapshotInvalidated,
    NoSpace,
    AttachmentNotRemote,
    ChunkMismatch,
    ManifestMismatch,
    TransferConflict,
    ResumeRequired,
    LeaseExpired,
    InstallPending,
    Busy,
    InvalidInput,
    WrongRole,
    WrongContext,
    Replay,
    HeadChanged,
    PrimaryRequired,
    PublicationPending,
    UpdateRequired,
    VaultUnavailable,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DataPacket {
    Manifest {
        manifest_hash: String,
        offset: U64,
        total: U64,
        bytes: SecretBase64,
    },
    Chunk {
        manifest_hash: String,
        index: U64,
        length: U64,
        digest: String,
        bytes: SecretBase64,
    },
    Receipt {
        manifest_hash: String,
        #[serde(deserialize_with = "super::super::required_nullable")]
        durable_through: Option<U64>,
        credit: u8,
    },
    DataVerified {
        manifest_hash: String,
        chunks_root: String,
        total_bytes: U64,
        census_hash: String,
        destination_ref: DeviceRef,
        manifest_chain_hash: String,
        signature: String,
    },
    Rebind {
        manifest_hash: String,
        new_base_record_hash: String,
        source_signature: String,
    },
    Stop {
        code: FullError,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PacketKind {
    Manifest,
    Chunk,
    Receipt,
    DataVerified,
    Rebind,
    Stop,
}
#[derive(Deserialize)]
struct KindHeader {
    kind: PacketKind,
}

fn signature(value: &str) -> Result<()> {
    let bytes = crate::decode_base64url(value).map_err(|_| WireError::Field("signature"))?;
    require(bytes.len() == 64 && crate::encode_base64url(bytes) == value, "signature")
}
impl PairingWire for DataPacket {
    const LIMIT: usize = 349_528 + 1024;
    fn received_limit(&self) -> usize {
        if matches!(self, Self::Manifest { .. } | Self::Chunk { .. }) { Self::LIMIT } else { 8192 }
    }
    fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = self.encode_secret()?;
        Ok(std::mem::take(&mut *encoded))
    }
    fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        if input.len() > Self::LIMIT {
            return Err(WireError::Size);
        }
        let header: KindHeader = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
        let limit = if matches!(header.kind, PacketKind::Manifest | PacketKind::Chunk) {
            Self::LIMIT
        } else {
            8192
        };
        if input.len() > limit {
            return Err(WireError::Size);
        }
        let packet: Self = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
        packet.validate()?;
        if packet.encode_secret()?.as_slice() != input {
            return Err(WireError::NonCanonical);
        }
        Ok(packet)
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Manifest { manifest_hash, offset, total, bytes } => {
                b32(manifest_hash, "manifest_hash")?;
                let bytes = bytes.decode(super::CHUNK_BYTES as usize)?;
                require(
                    !bytes.is_empty()
                        && total.0 <= super::MANIFEST_BYTES as u64
                        && offset
                            .0
                            .checked_add(u64::try_from(bytes.len()).map_err(|_| WireError::Size)?)
                            .is_some_and(|end| end <= total.0),
                    "manifest_part",
                )?;
            }
            Self::Chunk { manifest_hash, index, length, digest, bytes } => {
                b32(manifest_hash, "manifest_hash")?;
                b32(digest, "chunk_digest")?;
                let bytes = bytes.decode(super::CHUNK_BYTES as usize)?;
                require(
                    length.0 == u64::try_from(bytes.len()).map_err(|_| WireError::Size)?
                        && crate::encode_base64url(super::chunk_digest(index.0, &bytes)?)
                            == *digest,
                    "ChunkMismatch",
                )?;
            }
            Self::Receipt { manifest_hash, credit, .. } => {
                b32(manifest_hash, "manifest_hash")?;
                require(*credit <= 2, "credit")?;
            }
            Self::DataVerified {
                manifest_hash,
                chunks_root,
                total_bytes,
                census_hash,
                destination_ref,
                manifest_chain_hash,
                signature: sig,
            } => {
                for hash in [manifest_hash, chunks_root, census_hash, manifest_chain_hash] {
                    b32(hash, "data_verified")?;
                }
                super::chunk_layout(total_bytes.0)?;
                reference(destination_ref)?;
                signature(sig)?;
            }
            Self::Rebind { manifest_hash, new_base_record_hash, source_signature } => {
                b32(manifest_hash, "manifest_hash")?;
                b32(new_base_record_hash, "new_base_record_hash")?;
                signature(source_signature)?;
            }
            Self::Stop { code, retry_after_ms } => {
                require(
                    if *code == FullError::Busy {
                        retry_after_ms.is_some_and(|ms| (1000..=30000).contains(&ms))
                    } else {
                        retry_after_ms.is_none()
                    },
                    "retry_after_ms",
                )?;
            }
        }
        budget(self, self.received_limit())
    }
}

// All field names below are ASCII and emitted in JCS order. No sorting serializer holds values.
impl Serialize for DataPacket {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        macro_rules! fields {
            ($map:ident, $($name:literal => $value:expr),+ $(,)?) => { $( $map.serialize_entry($name, $value)?; )+ };
        }
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::Manifest { manifest_hash, offset, total, bytes } => {
                fields!(map, "bytes" => bytes, "kind" => "manifest", "manifest_hash" => manifest_hash, "offset" => offset, "total" => total);
            }
            Self::Chunk { manifest_hash, index, length, digest, bytes } => {
                fields!(map, "bytes" => bytes, "digest" => digest, "index" => index, "kind" => "chunk", "length" => length, "manifest_hash" => manifest_hash);
            }
            Self::Receipt { manifest_hash, durable_through, credit } => {
                fields!(map, "credit" => credit, "durable_through" => durable_through, "kind" => "receipt", "manifest_hash" => manifest_hash);
            }
            Self::DataVerified {
                manifest_hash,
                chunks_root,
                total_bytes,
                census_hash,
                destination_ref,
                manifest_chain_hash,
                signature,
            } => {
                fields!(map, "census_hash" => census_hash, "chunks_root" => chunks_root, "destination_ref" => &CanonicalRef(destination_ref), "kind" => "data_verified", "manifest_chain_hash" => manifest_chain_hash, "manifest_hash" => manifest_hash, "signature" => signature, "total_bytes" => total_bytes);
            }
            Self::Rebind { manifest_hash, new_base_record_hash, source_signature } => {
                fields!(map, "kind" => "rebind", "manifest_hash" => manifest_hash, "new_base_record_hash" => new_base_record_hash, "source_signature" => source_signature);
            }
            Self::Stop { code, retry_after_ms } => {
                fields!(map, "code" => code, "kind" => "stop");
                if let Some(retry) = retry_after_ms {
                    map.serialize_entry("retry_after_ms", retry)?;
                }
            }
        }
        map.end()
    }
}
struct CanonicalRef<'a>(&'a DeviceRef);
impl Serialize for CanonicalRef<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("account_anchor", &self.0.account_anchor)?;
        map.serialize_entry("device_epoch", &self.0.device_epoch)?;
        map.serialize_entry("device_id", &self.0.device_id)?;
        map.end()
    }
}
impl DataPacket {
    /// Direct canonical encoding into one bounded zeroizing allocation.
    /// # Errors
    /// Refuses invalid/oversized packets without an unzeroized intermediate value tree.
    pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        struct Output {
            bytes: Zeroizing<Vec<u8>>,
            limit: usize,
        }
        impl std::io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.bytes.len().checked_add(bytes.len()).is_none_or(|size| size > self.limit) {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        self.validate()?;
        let limit = self.received_limit();
        let mut output = Output { bytes: Zeroizing::new(Vec::with_capacity(limit)), limit };
        serde_json::to_writer(&mut output, self).map_err(|_| WireError::Size)?;
        Ok(output.bytes)
    }
}

impl DataPacket {
    /// Native custody signing grammar over the flat `DataVerified` body without its signature.
    /// The local storage owner must prove durable verification before asking its branch signer.
    /// # Errors
    /// Refuses a different packet arm or invalid verification fields.
    pub fn data_verified_signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Body<'a> {
            kind: &'static str,
            manifest_hash: &'a str,
            chunks_root: &'a str,
            total_bytes: U64,
            census_hash: &'a str,
            destination_ref: &'a DeviceRef,
            manifest_chain_hash: &'a str,
        }
        self.validate()?;
        let Self::DataVerified {
            manifest_hash,
            chunks_root,
            total_bytes,
            census_hash,
            destination_ref,
            manifest_chain_hash,
            ..
        } = self
        else {
            return Err(WireError::Field("data_verified"));
        };
        crate::custody::signing_bytes(
            "ramflux.identity.transfer.data_verified.v1",
            &Body {
                kind: "data_verified",
                manifest_hash,
                chunks_root,
                total_bytes: *total_bytes,
                census_hash,
                destination_ref,
                manifest_chain_hash,
            },
        )
        .map_err(|_| WireError::Json)
    }
    /// Exact source-branch Rebind body. A receiver still fetches and verifies the new head.
    /// # Errors
    /// Refuses a different arm or malformed context.
    pub fn rebind_signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Body<'a> {
            kind: &'static str,
            manifest_hash: &'a str,
            new_base_record_hash: &'a str,
        }
        self.validate()?;
        let Self::Rebind { manifest_hash, new_base_record_hash, .. } = self else {
            return Err(WireError::Field("rebind"));
        };
        crate::custody::signing_bytes(
            "ramflux.identity.transfer.rebind.full.v1",
            &Body { kind: "rebind", manifest_hash, new_base_record_hash },
        )
        .map_err(|_| WireError::Json)
    }
    /// Commit the complete signed `DataVerified` object for the full preservation body.
    /// # Errors
    /// Refuses a different packet arm or invalid signed-object shape.
    pub fn data_verified_hash(&self) -> Result<[u8; 32]> {
        require(matches!(self, Self::DataVerified { .. }), "data_verified")?;
        let tag = b"ramflux.pairing.full.data_verified.v1";
        let mut hash = blake3::Hasher::new();
        hash.update(&u32::try_from(tag.len()).map_err(|_| WireError::Size)?.to_be_bytes());
        hash.update(tag);
        hash.update(&self.encode_secret()?);
        Ok(*hash.finalize().as_bytes())
    }
}
