// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant confirmed-channel and transfer codecs; no publication authority.
use super::super::Envelope;
use super::{
    Deserialize, DeviceRef, PairingWire, Result, Serialize, Transcript, WireError, b32, budget,
    decode_base64url, encode_base64url, header, integer, reference, require,
};

pub(super) fn error_code(v: &str) -> Result<()> {
    require(
        matches!(
            v,
            "Busy"
                | "InvalidInput"
                | "Expired"
                | "Retired"
                | "WrongRole"
                | "WrongContext"
                | "Replay"
                | "HeadChanged"
                | "PrimaryRequired"
                | "SasMismatch"
                | "PublicationPending"
                | "TransferCapacity"
                | "UpdateRequired"
                | "VaultUnavailable"
                | "NotFound"
        ),
        "code",
    )
}
fn sig<T: Serialize>(v: &Envelope<T>) -> Result<()> {
    let b = decode_base64url(&v.signature).map_err(|_| WireError::Field("signature"))?;
    require(b.len() == 64 && encode_base64url(&b) == v.signature, "signature")
}
fn legacy(schema: &str, version: u32, name: &str) -> Result<()> {
    require(schema == name, "schema")?;
    require(version == 1, "version")
}
fn caps(v: &[String]) -> Result<()> {
    require(
        !v.is_empty()
            && v.len() <= 5
            && v.windows(2).all(|w| w[0] < w[1])
            && v.iter()
                .all(|c| matches!(c.as_str(), "call" | "group" | "message" | "register" | "sync")),
        "capabilities",
    )
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBody {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub transcript_hash: String,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub recipient_ref: DeviceRef,
    pub branch_signing_key: String,
    pub agreement_key: String,
    pub requested_role: String,
    pub capabilities: Vec<String>,
    pub lease_expires_at: u64,
    pub display_name: String,
}
impl PairingWire for EnrollmentBody {
    const LIMIT: usize = 11_700;
    fn validate(&self) -> Result<()> {
        legacy(&self.schema, self.version, "ramflux.identity.pairing.enrollment.v1")?;
        for (v, f) in [
            (&self.invitation_id, "invitation_id"),
            (&self.transcript_hash, "transcript_hash"),
            (&self.base_record_hash, "base_record_hash"),
            (&self.branch_signing_key, "branch_signing_key"),
            (&self.agreement_key, "agreement_key"),
        ] {
            b32(v, f)?;
        }
        integer(self.base_epoch, "base_epoch")?;
        integer(self.lease_expires_at, "lease_expires_at")?;
        reference(&self.recipient_ref)?;
        require(self.requested_role == "secondary", "requested_role")?;
        caps(&self.capabilities)?;
        require(
            self.display_name.len() <= 128
                && crate::text_safety::free_text_is_safe(&self.display_name),
            "display_name",
        )?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservationBody {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub old_record_hash: String,
    pub new_record_hash: String,
    pub destination_ref: DeviceRef,
    pub recipient_mode: String,
    pub policy: String,
    pub expires_at: u64,
}
impl PairingWire for PreservationBody {
    const LIMIT: usize = 11_700;
    fn validate(&self) -> Result<()> {
        legacy(&self.schema, self.version, "ramflux.identity.transfer.preserve.v1")?;
        for (v, f) in [
            (&self.transfer_id, "transfer_id"),
            (&self.transcript_hash, "transcript_hash"),
            (&self.old_record_hash, "old_record_hash"),
            (&self.new_record_hash, "new_record_hash"),
        ] {
            b32(v, f)?;
        }
        reference(&self.destination_ref)?;
        require(matches!(self.recipient_mode.as_str(), "new" | "existing"), "recipient_mode")?;
        require(self.policy == "preserve_all_existing", "policy")?;
        integer(self.expires_at, "expires_at")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Enrollment {
        proposal: Envelope<EnrollmentBody>,
    },
    Approval {
        proposal_hash: String,
        base_record_hash: String,
        base_epoch: u64,
        approved: bool,
    },
    ArtifactChunk {
        object_kind: String,
        object_id: String,
        index: u64,
        count: u64,
        total_bytes: u64,
        bytes: String,
    },
    CandidateReady {
        transfer_id: String,
        record_hash: String,
        compacted_ids_hash: Option<String>,
    },
    TransferReady {
        transfer_id: String,
        record_hash: String,
        compacted_ids_hash: Option<String>,
        preservation: Envelope<PreservationBody>,
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
impl Payload {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Enrollment { proposal } => {
                proposal.body.validate()?;
                sig(proposal)?;
            }
            Self::Approval { proposal_hash, base_record_hash, base_epoch, .. } => {
                b32(proposal_hash, "proposal_hash")?;
                b32(base_record_hash, "base_record_hash")?;
                integer(*base_epoch, "base_epoch")?;
            }
            Self::ArtifactChunk { object_kind, object_id, index, count, total_bytes, bytes } => {
                b32(object_id, "object_id")?;
                let max = match object_kind.as_str() {
                    "hpke" => 819_200,
                    "candidate" => 524_288,
                    _ => return Err(WireError::Field("object_kind")),
                };
                require(*total_bytes > 0 && *total_bytes <= max, "total_bytes")?;
                require(*count == total_bytes.div_ceil(8192), "count")?;
                require(*index < *count, "index")?;
                let raw = decode_base64url(bytes).map_err(|_| WireError::Field("bytes"))?;
                require(
                    !raw.is_empty() && raw.len() <= 8192 && encode_base64url(&raw) == *bytes,
                    "bytes",
                )?;
                require(
                    raw.len() as u64
                        == if index + 1 == *count { total_bytes - index * 8192 } else { 8192 },
                    "chunk_length",
                )?;
            }
            Self::CandidateReady { transfer_id, record_hash, compacted_ids_hash }
            | Self::TransferReady { transfer_id, record_hash, compacted_ids_hash, .. } => {
                b32(transfer_id, "transfer_id")?;
                b32(record_hash, "record_hash")?;
                if let Some(v) = compacted_ids_hash {
                    b32(v, "compacted_ids_hash")?;
                }
                if let Self::TransferReady { preservation, .. } = self {
                    preservation.body.validate()?;
                    sig(preservation)?;
                    require(
                        preservation.body.transfer_id == *transfer_id
                            && preservation.body.new_record_hash == *record_hash,
                        "preservation_binding",
                    )?;
                }
            }
            Self::Published { operation_id, record_hash, device_set_epoch, recipient_ref } => {
                b32(operation_id, "operation_id")?;
                b32(record_hash, "record_hash")?;
                integer(*device_set_epoch, "device_set_epoch")?;
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
            Self::Abort { reason } => error_code(reason)?,
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub transcript_hash: String,
    pub payload: Payload,
}
impl PairingWire for Channel {
    const LIMIT: usize = 11_700;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Channel")?;
        b32(&self.invitation_id, "invitation_id")?;
        b32(&self.transcript_hash, "transcript_hash")?;
        self.payload.validate()?;
        if let Payload::Enrollment { proposal } = &self.payload {
            require(
                proposal.body.invitation_id == self.invitation_id
                    && proposal.body.transcript_hash == self.transcript_hash,
                "proposal_binding",
            )?;
        }
        if let Payload::TransferReady { preservation, .. } = &self.payload {
            require(
                preservation.body.transcript_hash == self.transcript_hash,
                "preservation_transcript",
            )?;
        }
        budget(self, Self::LIMIT)
    }
}
/// Saved local evidence, never populated from peer-supplied phase or role fields.
pub struct ChannelContext<'a> {
    pub transcript: &'a Transcript,
    pub transcript_hash: &'a str,
    pub sender: &'a str,
    pub phase: &'a str,
    pub operation_id: &'a str,
    pub proposal_hash: Option<&'a str>,
    pub record_hash: Option<&'a str>,
    pub record_epoch: Option<u64>,
    pub compacted_ids_hash: Option<&'a str>,
}
impl Channel {
    /// Match decoded controls against frozen context and locally established phase.
    /// # Errors
    /// Rejects wrong role, phase, invitation, transcript, proposal, head or destination.
    pub fn validate_context(&self, c: &ChannelContext<'_>) -> Result<()> {
        self.validate()?;
        c.transcript.validate()?;
        require(matches!(c.sender, "initiator" | "responder"), "sender")?;
        let common = &c.transcript.initiator.common;
        let dest = &c.transcript.responder;
        require(self.invitation_id == common.invitation_id, "channel_invitation")?;
        require(self.transcript_hash == c.transcript_hash, "channel_transcript")?;
        let (sender, phases): (&str, &[&str]) = match &self.payload {
            Payload::Enrollment { .. } => ("responder", &["mutually_confirmed"]),
            Payload::Approval { .. } => ("initiator", &["proposal_pending"]),
            Payload::ArtifactChunk { .. } | Payload::Abort { .. } => {
                ("", &["mutually_confirmed", "proposal_pending", "prepared"])
            }
            Payload::CandidateReady { .. } => ("responder", &["prepared"]),
            Payload::TransferReady { .. } => ("initiator", &["prepared"]),
            Payload::Published { .. } => ("initiator", &["acknowledged"]),
            Payload::Installed { .. } => ("responder", &["locally_installed"]),
            Payload::Completed { .. } => ("initiator", &["completed"]),
        };
        require(sender.is_empty() || c.sender == sender, "channel_role")?;
        require(phases.contains(&c.phase), "channel_phase")?;
        if let Payload::Published { device_set_epoch, .. } = &self.payload {
            require(Some(*device_set_epoch) == c.record_epoch, "published_epoch")?;
        }
        match &self.payload {
            Payload::Enrollment { proposal } => {
                let p = &proposal.body;
                require(common.purpose == "enroll", "channel_purpose")?;
                require(
                    p.base_record_hash == common.record_hash
                        && p.base_epoch == common.device_set_epoch,
                    "proposal_head",
                )?;
                require(
                    p.recipient_ref == dest.device_ref
                        && p.branch_signing_key == dest.branch_key
                        && p.agreement_key == dest.agreement_key
                        && p.capabilities == common.capabilities
                        && p.lease_expires_at == common.lease_expires_at
                        && p.display_name == dest.display_name,
                    "proposal_context",
                )?;
            }
            Payload::Approval { proposal_hash, base_record_hash, base_epoch, .. } => {
                require(Some(proposal_hash.as_str()) == c.proposal_hash, "proposal_hash")?;
                require(
                    *base_record_hash == common.record_hash
                        && *base_epoch == common.device_set_epoch,
                    "approval_head",
                )?;
            }
            Payload::ArtifactChunk { object_kind, object_id, .. } => {
                require(common.purpose == "primary_transfer", "channel_purpose")?;
                require(
                    if object_kind == "hpke" {
                        common.transfer_id.as_ref() == Some(object_id) && c.sender == "initiator"
                    } else {
                        *object_id == self.invitation_id && c.sender == "responder"
                    },
                    "artifact_context",
                )?;
            }
            Payload::CandidateReady { transfer_id, record_hash, compacted_ids_hash }
            | Payload::TransferReady { transfer_id, record_hash, compacted_ids_hash, .. } => {
                require(
                    compacted_ids_hash.as_deref() == c.compacted_ids_hash,
                    "compacted_ids_hash",
                )?;
                require(common.transfer_id.as_ref() == Some(transfer_id), "transfer_id")?;
                require(Some(record_hash.as_str()) == c.record_hash, "record_hash")?;
                if let Payload::TransferReady { preservation, .. } = &self.payload {
                    let p = &preservation.body;
                    require(
                        p.old_record_hash == common.record_hash
                            && p.destination_ref == dest.device_ref
                            && p.recipient_mode == common.recipient_mode
                            && p.expires_at <= common.expires_at,
                        "preservation_context",
                    )?;
                }
            }
            Payload::Published { operation_id, record_hash, recipient_ref, .. }
            | Payload::Installed { operation_id, record_hash, recipient_ref } => {
                require(*operation_id == c.operation_id, "operation_binding")?;
                require(Some(record_hash.as_str()) == c.record_hash, "record_hash")?;
                require(*recipient_ref == dest.device_ref, "recipient_ref")?;
            }
            Payload::Completed { operation_id, record_hash, .. } => {
                require(*operation_id == c.operation_id, "operation_binding")?;
                require(Some(record_hash.as_str()) == c.record_hash, "record_hash")?;
            }
            Payload::Abort { .. } => {}
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInvitation {
    pub invitation_id: String,
    pub expires_at: u64,
    pub proposal_hash: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub operation_id: String,
    pub intent_hash: String,
    pub state: String,
    pub acknowledgement_hash: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRestriction {
    pub group_id: String,
    pub group_genesis_hash: String,
    pub control_head_hash: String,
    pub restriction_hashes: Vec<String>,
    pub revocation_hashes: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataKey {
    pub key_id: String,
    pub purpose: String,
    pub key: String,
}
impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey { redacted }")
    }
}
impl Drop for DataKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
fn payload_id(v: &str, field: &'static str) -> Result<()> {
    require(!v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control), field)
}
fn hashes(v: &[String]) -> Result<()> {
    require(v.len() <= 8 && v.windows(2).all(|w| w[0] < w[1]), "hashes")?;
    for h in v {
        b32(h, "hash")?;
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPayload {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub current_record_hash: String,
    pub device_set_epoch: u64,
    pub pending_invitations: Vec<PendingInvitation>,
    pub journal: Vec<JournalEntry>,
    pub delegation_state: Vec<serde_json::Value>,
    pub group_restriction_summary: Vec<GroupRestriction>,
    pub pending_erasure: Vec<DeviceRef>,
    pub optional_data_keys: Vec<DataKey>,
}
impl std::fmt::Debug for TransferPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferPayload { redacted }")
    }
}
impl PairingWire for TransferPayload {
    const LIMIT: usize = 1_048_576;
    fn validate(&self) -> Result<()> {
        legacy(&self.schema, self.version, "ramflux.identity.transfer.payload.v1")?;
        for (v, f) in [
            (&self.transfer_id, "transfer_id"),
            (&self.transcript_hash, "transcript_hash"),
            (&self.current_record_hash, "current_record_hash"),
        ] {
            b32(v, f)?;
        }
        integer(self.device_set_epoch, "device_set_epoch")?;
        require(self.pending_invitations.len() <= 3, "pending_invitations")?;
        for v in &self.pending_invitations {
            b32(&v.invitation_id, "invitation_id")?;
            integer(v.expires_at, "expires_at")?;
            if let Some(h) = &v.proposal_hash {
                b32(h, "proposal_hash")?;
            }
            budget(v, 512)?;
        }
        require(self.journal.len() <= 64, "journal")?;
        for v in &self.journal {
            b32(&v.operation_id, "operation_id")?;
            b32(&v.intent_hash, "intent_hash")?;
            require(matches!(v.state.as_str(), "pending" | "acknowledged"), "state")?;
            require(
                v.acknowledgement_hash.is_some() == (v.state == "acknowledged"),
                "acknowledgement_hash",
            )?;
            if let Some(h) = &v.acknowledgement_hash {
                b32(h, "acknowledgement_hash")?;
            }
            budget(v, 512)?;
        }
        require(self.delegation_state.is_empty(), "UpdateRequired")?;
        require(
            self.group_restriction_summary.len() <= 64
                && self.group_restriction_summary.windows(2).all(|w| w[0].group_id < w[1].group_id),
            "group_restriction_summary",
        )?;
        for v in &self.group_restriction_summary {
            payload_id(&v.group_id, "group_id")?;
            b32(&v.group_genesis_hash, "group_genesis_hash")?;
            b32(&v.control_head_hash, "control_head_hash")?;
            hashes(&v.restriction_hashes)?;
            hashes(&v.revocation_hashes)?;
            budget(v, 2048)?;
        }
        require(
            self.pending_erasure.len() <= 256
                && self.pending_erasure.windows(2).all(|w| {
                    (&w[0].account_anchor, &w[0].device_id, w[0].device_epoch)
                        < (&w[1].account_anchor, &w[1].device_id, w[1].device_epoch)
                }),
            "pending_erasure",
        )?;
        for v in &self.pending_erasure {
            reference(v)?;
            budget(v, 1024)?;
        }
        require(
            self.optional_data_keys.len() <= 32
                && self
                    .optional_data_keys
                    .windows(2)
                    .all(|w| (&w[0].key_id, &w[0].purpose) < (&w[1].key_id, &w[1].purpose)),
            "optional_data_keys",
        )?;
        for v in &self.optional_data_keys {
            payload_id(&v.key_id, "key_id")?;
            require(matches!(v.purpose.as_str(), "history" | "attachment"), "key.purpose")?;
            b32(&v.key, "key")?;
            budget(v, 1024)?;
        }
        budget(self, Self::LIMIT)
    }
}
impl TransferPayload {
    /// Bind decrypted transfer metadata and every opt-in key to the committed selection.
    /// # Errors
    /// Rejects changed transfer context or missing, extra or differently purposed keys.
    pub fn validate_context(&self, t: &Transcript, th: &str) -> Result<()> {
        self.validate()?;
        t.validate()?;
        let c = &t.initiator.common;
        require(
            c.transfer_id.as_ref() == Some(&self.transfer_id)
                && self.transcript_hash == th
                && self.current_record_hash == c.record_hash
                && self.device_set_epoch == c.device_set_epoch,
            "transfer_context",
        )?;
        require(
            self.optional_data_keys.len() == c.data_selection.len()
                && self
                    .optional_data_keys
                    .iter()
                    .zip(&c.data_selection)
                    .all(|(k, s)| k.key_id == s.key_id && k.purpose == s.purpose),
            "data_consent",
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferBinding {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub current_record_hash: String,
    pub device_set_epoch: u64,
    pub sender_device_ref: DeviceRef,
    pub sender_hpke_key: String,
    pub recipient_hpke_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl PairingWire for TransferBinding {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        legacy(&self.schema, self.version, "ramflux.identity.transfer_binding.v1")?;
        for (v, f) in [
            (&self.transfer_id, "transfer_id"),
            (&self.transcript_hash, "transcript_hash"),
            (&self.current_record_hash, "current_record_hash"),
            (&self.sender_hpke_key, "sender_hpke_key"),
            (&self.recipient_hpke_key, "recipient_hpke_key"),
        ] {
            b32(v, f)?;
        }
        integer(self.device_set_epoch, "device_set_epoch")?;
        reference(&self.sender_device_ref)?;
        integer(self.issued_at, "issued_at")?;
        integer(self.expires_at, "expires_at")?;
        require(
            self.expires_at >= self.issued_at && self.expires_at - self.issued_at <= 300,
            "binding_lifetime",
        )?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HpkeEnvelope {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub current_record_hash: String,
    pub device_set_epoch: u64,
    pub sender_binding: Envelope<TransferBinding>,
    pub enc: String,
    pub ciphertext: String,
}
impl PairingWire for HpkeEnvelope {
    const LIMIT: usize = 819_200;
    fn validate(&self) -> Result<()> {
        legacy(&self.schema, self.version, "ramflux.identity.transfer.hpke.v1")?;
        for (v, f) in [
            (&self.transfer_id, "transfer_id"),
            (&self.transcript_hash, "transcript_hash"),
            (&self.current_record_hash, "current_record_hash"),
            (&self.enc, "enc"),
        ] {
            b32(v, f)?;
        }
        integer(self.device_set_epoch, "device_set_epoch")?;
        self.sender_binding.body.validate()?;
        sig(&self.sender_binding)?;
        let b = &self.sender_binding.body;
        require(
            b.transfer_id == self.transfer_id
                && b.transcript_hash == self.transcript_hash
                && b.current_record_hash == self.current_record_hash
                && b.device_set_epoch == self.device_set_epoch,
            "hpke_binding",
        )?;
        let raw = decode_base64url(&self.ciphertext).map_err(|_| WireError::Field("ciphertext"))?;
        require(
            raw.len() >= 16 && raw.len() <= 1_048_592 && encode_base64url(&raw) == self.ciphertext,
            "ciphertext",
        )?;
        budget(self, Self::LIMIT)
    }
}
impl HpkeEnvelope {
    /// Bind the authenticated sender profile to both frozen transfer role contexts.
    /// # Errors
    /// Rejects altered context, keys, sender or lifetime before opening ciphertext.
    pub fn validate_context(&self, transcript: &Transcript, transcript_hash: &str) -> Result<()> {
        self.validate()?;
        transcript.validate()?;
        let common = &transcript.initiator.common;
        require(
            common.transfer_id.as_ref() == Some(&self.transfer_id)
                && self.transcript_hash == transcript_hash
                && self.current_record_hash == common.record_hash
                && self.device_set_epoch == common.device_set_epoch,
            "hpke_context",
        )?;
        let binding = &self.sender_binding.body;
        require(
            binding.sender_device_ref == transcript.initiator.device_ref
                && Some(&binding.sender_hpke_key) == transcript.initiator.hpke_key.as_ref()
                && Some(&binding.recipient_hpke_key) == transcript.responder.hpke_key.as_ref(),
            "hpke_keys",
        )?;
        require(binding.expires_at <= common.expires_at, "hpke_expiry")
    }
}
