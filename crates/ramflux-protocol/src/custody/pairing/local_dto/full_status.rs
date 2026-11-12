// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! OVP-33's closed, bounded local progress value. Counters and errors confer no
//! receipt, semantic verification, native publication or installation authority.
use super::{Deserialize, PairingWire, Result, Serialize, budget, integer, local_base, require};
use crate::custody::pairing::full_transfer::{FullError, U64};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FullStatusStage {
    Snapshot,
    Streaming,
    AwaitingReverse,
    AwaitingPrepare,
    Candidate,
    Publishing,
    Installing,
    Installed,
    Conflict,
    Cancelled,
    Expired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FullTailStatus {
    None,
    Pending,
    Merged,
    Abandoned,
}
/// Exact OVP-33 value layout for `ramflux.pairing.FullStatus.v3`; its containing
/// LocalResult/Event identifies the full-status arm. No family names, object ids or keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullStatus {
    pub attachment_absent: U64,
    pub bytes_durable: U64,
    pub bytes_total: U64,
    pub cut: U64,
    pub generation: u64,
    pub lease_expires_at: u64,
    pub operation_id: String,
    #[serde(deserialize_with = "super::super::required_nullable")]
    pub result: Option<FullError>,
    pub role: String,
    pub stage: FullStatusStage,
    pub tail_status: FullTailStatus,
}
impl PairingWire for FullStatus {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        local_base(&self.operation_id, self.generation)?;
        integer(self.lease_expires_at, "lease_expires_at")?;
        require(matches!(self.role.as_str(), "initiator" | "responder"), "role")?;
        require(self.cut.0 <= 9, "cut")?;
        require(
            i64::try_from(self.bytes_total.0).is_ok() && self.bytes_durable.0 <= self.bytes_total.0,
            "progress",
        )?;
        budget(self, Self::LIMIT)
    }
}
impl FullError {
    /// Parse one closed full-profile code without retaining diagnostic text.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "UnsupportedRecord" => Self::UnsupportedRecord,
            "SchemaMismatch" => Self::SchemaMismatch,
            "SnapshotBusy" => Self::SnapshotBusy,
            "SnapshotInvalidated" => Self::SnapshotInvalidated,
            "NoSpace" => Self::NoSpace,
            "AttachmentNotRemote" => Self::AttachmentNotRemote,
            "ChunkMismatch" => Self::ChunkMismatch,
            "ManifestMismatch" => Self::ManifestMismatch,
            "TransferConflict" => Self::TransferConflict,
            "ResumeRequired" => Self::ResumeRequired,
            "LeaseExpired" => Self::LeaseExpired,
            "InstallPending" => Self::InstallPending,
            "Busy" => Self::Busy,
            "InvalidInput" => Self::InvalidInput,
            "WrongRole" => Self::WrongRole,
            "WrongContext" => Self::WrongContext,
            "Replay" => Self::Replay,
            "HeadChanged" => Self::HeadChanged,
            "PrimaryRequired" => Self::PrimaryRequired,
            "PublicationPending" => Self::PublicationPending,
            "UpdateRequired" => Self::UpdateRequired,
            "VaultUnavailable" => Self::VaultUnavailable,
            _ => return None,
        })
    }
    /// OVP-33 compatibility category only. The full status retains the exact error;
    /// a legacy category never changes a phase or authorizes a retry/publication.
    #[must_use]
    pub const fn legacy_update_result(self) -> &'static str {
        match self {
            Self::UnsupportedRecord | Self::SchemaMismatch | Self::UpdateRequired => {
                "UpdateRequired"
            }
            Self::SnapshotBusy | Self::NoSpace | Self::ResumeRequired | Self::Busy => "Busy",
            Self::LeaseExpired => "Expired",
            Self::InstallPending | Self::PublicationPending => "PublicationPending",
            Self::WrongRole => "WrongRole",
            Self::WrongContext => "WrongContext",
            Self::Replay => "Replay",
            Self::HeadChanged => "HeadChanged",
            Self::PrimaryRequired => "PrimaryRequired",
            Self::VaultUnavailable => "VaultUnavailable",
            Self::SnapshotInvalidated
            | Self::AttachmentNotRemote
            | Self::ChunkMismatch
            | Self::ManifestMismatch
            | Self::TransferConflict
            | Self::InvalidInput => "InvalidInput",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const VECTOR: &[u8] = br#"{"attachment_absent":"0","bytes_durable":"262144","bytes_total":"262145","cut":"0","generation":1,"lease_expires_at":1900000000,"operation_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","result":null,"role":"responder","stage":"streaming","tail_status":"none"}"#;
    #[test]
    fn pairing_full_status_exact_vector_and_pending_tail_expiry_round_trip()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut status = FullStatus::from_wire_bytes(VECTOR)?;
        assert_eq!(status.to_wire_bytes()?, VECTOR);
        status.stage = FullStatusStage::Installed;
        status.tail_status = FullTailStatus::Pending;
        status.result = Some(FullError::LeaseExpired);
        assert_eq!(FullStatus::from_wire_bytes(&status.to_wire_bytes()?)?, status);
        assert_eq!(status.tail_status, FullTailStatus::Pending, "expiry completed the tail");
        Ok(())
    }
    #[test]
    fn pairing_full_status_refuses_missing_result_unknown_fields_and_invalid_progress()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let base: serde_json::Value = serde_json::from_slice(VECTOR)?;
        for (field, operand) in [
            ("bytes_durable", serde_json::json!("262146")),
            ("bytes_total", serde_json::json!("18446744073709551615")),
            ("cut", serde_json::json!("10")),
            ("generation", serde_json::json!(0)),
            ("role", serde_json::json!("primary")),
            ("stage", serde_json::json!("verified")),
            ("tail_status", serde_json::json!("complete")),
            ("family_name", serde_json::json!("not allowed")),
            ("result", serde_json::json!("UnknownError")),
        ] {
            let mut value = base.clone();
            value.as_object_mut().ok_or("status object")?.insert(field.into(), operand);
            assert!(
                FullStatus::from_wire_bytes(&crate::canonical_json_bytes(&value)?).is_err(),
                "accepted {field}"
            );
        }
        let mut missing = base;
        missing.as_object_mut().ok_or("status object")?.remove("result");
        assert!(FullStatus::from_wire_bytes(&crate::canonical_json_bytes(&missing)?).is_err());
        assert!(FullStatus::from_wire_bytes(&vec![b' '; FullStatus::LIMIT + 1]).is_err());
        Ok(())
    }
    #[test]
    fn pairing_full_status_legacy_categories_keep_exact_full_errors() {
        assert_eq!(FullError::from_code("NoSpace"), Some(FullError::NoSpace));
        assert_eq!(FullError::from_code("nospace"), None);
        assert_eq!(FullError::from_code("UnknownError"), None);
        for (error, expected) in [
            (FullError::UnsupportedRecord, "UpdateRequired"),
            (FullError::SchemaMismatch, "UpdateRequired"),
            (FullError::NoSpace, "Busy"),
            (FullError::ResumeRequired, "Busy"),
            (FullError::LeaseExpired, "Expired"),
            (FullError::InstallPending, "PublicationPending"),
            (FullError::TransferConflict, "InvalidInput"),
            (FullError::HeadChanged, "HeadChanged"),
        ] {
            assert_eq!(error.legacy_update_result(), expected);
        }
    }
}
