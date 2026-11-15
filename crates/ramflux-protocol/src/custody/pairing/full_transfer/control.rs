// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Audit-r2 M3 full-channel carriers. Native approvals are checked by the separate publication owner.
use super::{DeviceRef, PairingWire, PreservationFull, Result, b32, budget, reference, require};
use crate::custody::Envelope;
use serde::{Deserialize, Serialize};

/// Annex-D's encrypted-control bound. Relay discovery/HPKE control requests retain 8KiB;
/// this opaque DATA packet must fit the existing 8192-raw-byte candidate `ArtifactChunk`.
pub const CONTROL_PACKET_BYTES: usize = <super::super::channel::Channel as PairingWire>::LIMIT;
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FullControlPayload {
    CandidateReady {
        transfer_id: String,
        record_hash: String,
        #[serde(deserialize_with = "super::super::required_nullable")]
        compacted_ids_hash: Option<String>,
    },
    ArtifactChunk {
        object_kind: String,
        object_id: String,
        index: u64,
        count: u64,
        total_bytes: u64,
        bytes: super::SecretBase64,
    },
    TransferReadyFull {
        transfer_id: String,
        record_hash: String,
        #[serde(deserialize_with = "super::super::required_nullable")]
        compacted_ids_hash: Option<String>,
        preservation: Box<Envelope<PreservationFull>>,
    },
    Published {
        operation_id: String,
        record_hash: String,
        device_set_epoch: u64,
        recipient_ref: DeviceRef,
    },
    Installed {
        operation_id: String,
        record_hash: String,
        recipient_ref: DeviceRef,
    },
    Completed {
        operation_id: String,
        record_hash: String,
        cleanup: String,
    },
    Abort {
        reason: String,
    },
}
impl FullControlPayload {
    /// Annex-D roles only. The durable stage owner independently checks phase/order,
    /// duplex `DataVerified`, candidate scope and the exact native acknowledgement.
    /// # Errors
    /// Refuses another sender or an invalid closed control.
    pub fn require_sender(&self, sender: &str) -> Result<()> {
        self.validate()?;
        require(matches!(sender, "initiator" | "responder"), "sender")?;
        let expected = match self {
            Self::CandidateReady { .. } | Self::Installed { .. } => "responder",
            Self::TransferReadyFull { .. } | Self::Published { .. } | Self::Completed { .. } => {
                "initiator"
            }
            Self::ArtifactChunk { .. } | Self::Abort { .. } => "",
        };
        require(expected.is_empty() || expected == sender, "channel_role")
    }
}
impl PairingWire for FullControlPayload {
    const LIMIT: usize = CONTROL_PACKET_BYTES;
    fn validate(&self) -> Result<()> {
        match self {
            Self::CandidateReady { transfer_id, record_hash, compacted_ids_hash }
            | Self::TransferReadyFull { transfer_id, record_hash, compacted_ids_hash, .. } => {
                b32(transfer_id, "transfer_id")?;
                b32(record_hash, "record_hash")?;
                if let Some(hash) = compacted_ids_hash {
                    b32(hash, "compacted_ids_hash")?;
                }
                if let Self::TransferReadyFull { preservation, .. } = self {
                    preservation.body.validate()?;
                    super::packet::signature(&preservation.signature)?;
                    require(
                        preservation.body.transfer_id == *transfer_id
                            && preservation.body.new_record_hash == *record_hash,
                        "preservation_binding",
                    )?;
                }
            }
            Self::ArtifactChunk { object_kind, object_id, index, count, total_bytes, bytes } => {
                require(object_kind == "candidate", "object_kind")?;
                b32(object_id, "object_id")?;
                require(*total_bytes > 0 && *total_bytes <= 524_288, "total_bytes")?;
                require(*count == total_bytes.div_ceil(8192) && *index < *count, "count")?;
                let raw = bytes.decode(8192)?;
                require(
                    raw.len() as u64
                        == if index + 1 == *count { total_bytes - index * 8192 } else { 8192 },
                    "chunk_length",
                )?;
            }
            Self::Published { operation_id, record_hash, device_set_epoch, recipient_ref } => {
                b32(operation_id, "operation_id")?;
                b32(record_hash, "record_hash")?;
                super::super::integer(*device_set_epoch, "device_set_epoch")?;
                reference(recipient_ref)?;
            }
            Self::Installed { operation_id, record_hash, recipient_ref } => {
                b32(operation_id, "operation_id")?;
                b32(record_hash, "record_hash")?;
                reference(recipient_ref)?;
            }
            Self::Completed { operation_id, record_hash, cleanup } => {
                b32(operation_id, "operation_id")?;
                b32(record_hash, "record_hash")?;
                require(matches!(cleanup.as_str(), "done" | "pending"), "cleanup")?;
            }
            Self::Abort { reason } => super::super::channel::error_code(reason)?,
        }
        budget(self, Self::LIMIT)
    }
}
impl Serialize for FullControlPayload {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use super::packet::CanonicalRef;
        use serde::ser::SerializeMap as _;
        macro_rules! fields {($map:ident,$($name:literal=>$value:expr),+ $(,)?)=>{$($map.serialize_entry($name,$value)?;)+};}
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::CandidateReady { transfer_id, record_hash, compacted_ids_hash } => {
                fields!(map,"compacted_ids_hash"=>compacted_ids_hash,"kind"=>"candidate_ready","record_hash"=>record_hash,"transfer_id"=>transfer_id);
            }
            Self::TransferReadyFull {
                transfer_id,
                record_hash,
                compacted_ids_hash,
                preservation,
            } => {
                fields!(map,"compacted_ids_hash"=>compacted_ids_hash,"kind"=>"transfer_ready_full","preservation"=>&CanonicalPreservation(preservation),"record_hash"=>record_hash,"transfer_id"=>transfer_id);
            }
            Self::ArtifactChunk { object_kind, object_id, index, count, total_bytes, bytes } => {
                fields!(map,"bytes"=>bytes,"count"=>count,"index"=>index,"kind"=>"artifact_chunk","object_id"=>object_id,"object_kind"=>object_kind,"total_bytes"=>total_bytes);
            }
            Self::Published { operation_id, record_hash, device_set_epoch, recipient_ref } => {
                fields!(map,"device_set_epoch"=>device_set_epoch,"kind"=>"published","operation_id"=>operation_id,"recipient_ref"=>&CanonicalRef(recipient_ref),"record_hash"=>record_hash);
            }
            Self::Installed { operation_id, record_hash, recipient_ref } => {
                fields!(map,"kind"=>"installed","operation_id"=>operation_id,"recipient_ref"=>&CanonicalRef(recipient_ref),"record_hash"=>record_hash);
            }
            Self::Completed { operation_id, record_hash, cleanup } => {
                fields!(map,"cleanup"=>cleanup,"kind"=>"completed","operation_id"=>operation_id,"record_hash"=>record_hash);
            }
            Self::Abort { reason } => {
                fields!(map,"kind"=>"abort","reason"=>reason);
            }
        }
        map.end()
    }
}
struct CanonicalPreservation<'a>(&'a Envelope<PreservationFull>);
impl Serialize for CanonicalPreservation<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("body", &CanonicalBody(&self.0.body))?;
        map.serialize_entry("signature", &self.0.signature)?;
        map.end()
    }
}
struct CanonicalBody<'a>(&'a PreservationFull);
impl Serialize for CanonicalBody<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let body = self.0;
        let mut map = serializer.serialize_map(Some(13))?;
        map.serialize_entry("data_verified_hash", &body.data_verified_hash)?;
        map.serialize_entry(
            "destination_ref",
            &super::packet::CanonicalRef(&body.destination_ref),
        )?;
        map.serialize_entry("expires_at", &body.expires_at)?;
        map.serialize_entry("manifest_chain_hash", &body.manifest_chain_hash)?;
        map.serialize_entry("new_record_hash", &body.new_record_hash)?;
        map.serialize_entry("old_record_hash", &body.old_record_hash)?;
        map.serialize_entry("policy", &body.policy)?;
        map.serialize_entry("recipient_mode", &body.recipient_mode)?;
        map.serialize_entry("schema", &body.schema)?;
        map.serialize_entry("target_restrictions_root", &body.target_restrictions_root)?;
        map.serialize_entry("transcript_hash", &body.transcript_hash)?;
        map.serialize_entry("transfer_id", &body.transfer_id)?;
        map.serialize_entry("version", &body.version)?;
        map.end()
    }
}

/// Locally established scope/phase, never deserialized from a peer control or relay reply.
/// The coordinator obtains native acknowledgements and durable duplex/install proofs first.
pub struct FullControlContext<'a> {
    pub sender: &'a str,
    pub phase: &'a str,
    pub transfer_id: &'a str,
    pub operation_id: &'a str,
    pub transcript_hash: &'a str,
    pub base_record_hash: &'a str,
    pub manifest_chain_hash: &'a str,
    pub data_verified_hash: &'a str,
    pub target_restrictions_root: &'a str,
    pub recipient_mode: &'a str,
    pub destination_ref: &'a DeviceRef,
    pub candidate_hash: Option<&'a str>,
    pub candidate_object_id: Option<&'a str>,
    pub compacted_ids_hash: Option<&'a str>,
    pub record_epoch: Option<u64>,
    pub lease_expires_at: u64,
    pub now: u64,
}
impl FullControlPayload {
    /// Validate the closed control against the endpoint's own established scope. This
    /// does not fetch/reconcile native state or certify a stage/installation by itself.
    /// # Errors
    /// Refuses reflection, foreign operation/candidate/context, expiry or wrong phase.
    pub fn validate_context(&self, c: &FullControlContext<'_>) -> Result<()> {
        self.require_sender(c.sender)?;
        require(c.now < c.lease_expires_at, "LeaseExpired")?;
        let phases: &[&str] = match self {
            Self::ArtifactChunk { .. } | Self::Abort { .. } => {
                &["mutually_confirmed", "proposal_pending", "prepared"]
            }
            Self::CandidateReady { .. } | Self::TransferReadyFull { .. } => &["prepared"],
            Self::Published { .. } => &["acknowledged"],
            Self::Installed { .. } => &["locally_installed"],
            Self::Completed { .. } => &["completed"],
        };
        require(phases.contains(&c.phase), "channel_phase")?;
        match self {
            Self::CandidateReady { transfer_id, record_hash, compacted_ids_hash }
            | Self::TransferReadyFull { transfer_id, record_hash, compacted_ids_hash, .. } => {
                require(
                    transfer_id == c.transfer_id
                        && Some(record_hash.as_str()) == c.candidate_hash
                        && compacted_ids_hash.as_deref() == c.compacted_ids_hash,
                    "candidate_context",
                )?;
                if let Self::TransferReadyFull { preservation, .. } = self {
                    let body = &preservation.body;
                    require(
                        body.transcript_hash == c.transcript_hash
                            && body.old_record_hash == c.base_record_hash
                            && body.manifest_chain_hash == c.manifest_chain_hash
                            && body.data_verified_hash == c.data_verified_hash
                            && body.target_restrictions_root == c.target_restrictions_root
                            && body.recipient_mode == c.recipient_mode
                            && &body.destination_ref == c.destination_ref
                            && body.expires_at > c.now
                            && body.expires_at <= c.lease_expires_at,
                        "preservation_context",
                    )?;
                }
            }
            Self::ArtifactChunk { object_id, .. } => {
                require(Some(object_id.as_str()) == c.candidate_object_id, "candidate_object")?;
            }
            Self::Published { operation_id, record_hash, device_set_epoch, recipient_ref } => {
                require(
                    operation_id == c.operation_id
                        && Some(record_hash.as_str()) == c.candidate_hash
                        && Some(*device_set_epoch) == c.record_epoch
                        && recipient_ref == c.destination_ref,
                    "published_context",
                )?;
            }
            Self::Installed { operation_id, record_hash, recipient_ref } => {
                require(
                    operation_id == c.operation_id
                        && Some(record_hash.as_str()) == c.candidate_hash
                        && recipient_ref == c.destination_ref,
                    "installed_context",
                )?;
            }
            Self::Completed { operation_id, record_hash, .. } => {
                require(
                    operation_id == c.operation_id
                        && Some(record_hash.as_str()) == c.candidate_hash,
                    "completed_context",
                )?;
            }
            Self::Abort { .. } => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
