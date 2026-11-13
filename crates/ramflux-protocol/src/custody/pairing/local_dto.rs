// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant closed local DTOs. Secret credential buffers are never JSON.
use super::native::{Failure, InviteToken};
use super::{
    DataSelection, Deserialize, DeviceRef, MAX_BRANCH_LEASE_SECONDS, PairingWire, Result,
    Serialize, WireError, b32, budget, header, integer, reference, require, text,
};

fn local_base(id: &str, generation: u64) -> Result<()> {
    b32(id, "operation_id")?;
    integer(generation, "generation")?;
    require(generation >= 1, "generation")
}
mod full;
pub use full::FullTransferBegin;
mod full_status;
pub use full_status::{FullStatus, FullStatusStage, FullTailStatus};

fn name(v: &str) -> Result<()> {
    require(v.len() <= 128 && crate::text_safety::free_text_is_safe(v), "display_name")
}
fn rights(caps: &[String], start: u64, end: u64) -> Result<()> {
    require(
        !caps.is_empty()
            && caps.len() <= 5
            && caps.windows(2).all(|w| w[0] < w[1])
            && caps
                .iter()
                .all(|c| matches!(c.as_str(), "call" | "group" | "message" | "register" | "sync")),
        "capabilities",
    )?;
    integer(start, "lease_not_before")?;
    integer(end, "lease_expires_at")?;
    require(end > start && end - start <= MAX_BRANCH_LEASE_SECONDS, "lease")
}
pub(super) fn selection(v: &[DataSelection]) -> Result<()> {
    require(v.len() <= 32 && v.windows(2).all(|w| w[0] < w[1]), "data_selection")?;
    for x in v {
        text(&x.key_id, true, "selection.key_id")?;
        require(matches!(x.purpose.as_str(), "history" | "attachment"), "selection.purpose")?;
        budget(x, 384)?;
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Begin {
    pub schema: String,
    pub version: u32,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub display_name: String,
}
impl PairingWire for Begin {
    fn normalize(&mut self) {
        self.capabilities.sort();
    }
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Begin")?;
        rights(&self.capabilities, self.lease_not_before, self.lease_expires_at)?;
        name(&self.display_name)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferBegin {
    pub schema: String,
    pub version: u32,
    pub recipient_mode: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub destination_ref: Option<DeviceRef>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub data_selection: Vec<DataSelection>,
    pub display_name: String,
}
impl PairingWire for TransferBegin {
    fn normalize(&mut self) {
        self.capabilities.sort();
        self.data_selection.sort();
    }
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "TransferBegin")?;
        rights(&self.capabilities, self.lease_not_before, self.lease_expires_at)?;
        name(&self.display_name)?;
        require(matches!(self.recipient_mode.as_str(), "new" | "existing"), "recipient_mode")?;
        require(
            self.destination_ref.is_some() == (self.recipient_mode == "existing"),
            "destination_ref",
        )?;
        if let Some(v) = &self.destination_ref {
            reference(v)?;
        }
        selection(&self.data_selection)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Join {
    pub schema: String,
    pub version: u32,
    pub token: InviteToken,
    pub display_name: String,
}
impl PairingWire for Join {
    const LIMIT: usize = 32_768;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Join")?;
        self.token.validate()?;
        name(&self.display_name)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
    pub transcript_hash: String,
    pub r#match: bool,
}
impl PairingWire for Confirm {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Confirm")?;
        local_base(&self.operation_id, self.generation)?;
        b32(&self.transcript_hash, "transcript_hash")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approve {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
    pub transcript_hash: String,
    pub proposal_hash: String,
    pub approved: bool,
}
impl PairingWire for Approve {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Approve")?;
        local_base(&self.operation_id, self.generation)?;
        b32(&self.transcript_hash, "transcript_hash")?;
        b32(&self.proposal_hash, "proposal_hash")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
    pub transcript_hash: String,
}
impl PairingWire for Prepare {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Prepare")?;
        local_base(&self.operation_id, self.generation)?;
        b32(&self.transcript_hash, "transcript_hash")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
}
impl PairingWire for Cancel {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Cancel")?;
        local_base(&self.operation_id, self.generation)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
}
impl PairingWire for StatusRequest {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "StatusRequest")?;
        local_base(&self.operation_id, self.generation)?;
        budget(self, Self::LIMIT)
    }
}
pub const PHASES: [&str; 14] = [
    "invited",
    "commitments",
    "revealed",
    "sas_pending",
    "mutually_confirmed",
    "proposal_pending",
    "prepared",
    "submitted",
    "acknowledged",
    "locally_installed",
    "completed",
    "cancelled",
    "expired",
    "rejected",
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
    pub phase: String,
    pub expires_at: u64,
    #[serde(deserialize_with = "super::required_nullable")]
    pub transcript_hash: Option<String>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub emoji_indices: Option<Vec<u64>>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub peer_ref: Option<DeviceRef>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub peer_name: Option<String>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    #[serde(deserialize_with = "super::required_nullable")]
    pub proposal_hash: Option<String>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub record_hash: Option<String>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub result: Option<String>,
    pub cleanup: String,
}
impl PairingWire for Update {
    fn normalize(&mut self) {
        self.capabilities.sort();
    }
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Update")?;
        local_base(&self.operation_id, self.generation)?;
        integer(self.expires_at, "expires_at")?;
        rights(&self.capabilities, self.lease_not_before, self.lease_expires_at)?;
        let p = PHASES.iter().position(|v| *v == self.phase).ok_or(WireError::Field("phase"))?;
        for (v, f) in [
            (&self.transcript_hash, "transcript_hash"),
            (&self.proposal_hash, "proposal_hash"),
            (&self.record_hash, "record_hash"),
        ] {
            if let Some(v) = v {
                b32(v, f)?;
            }
        }
        let terminal = p >= 10;
        require(
            if terminal { true } else { self.transcript_hash.is_some() == (p >= 2) },
            "phase_transcript",
        )?;
        require(self.peer_ref.is_some() == self.peer_name.is_some(), "peer_fields")?;
        require(if terminal { true } else { self.peer_ref.is_some() == (p >= 2) }, "phase_peer")?;
        if let Some(v) = &self.peer_ref {
            reference(v)?;
        }
        if let Some(v) = &self.peer_name {
            name(v)?;
        }
        if let Some(v) = &self.emoji_indices {
            require(
                matches!(self.phase.as_str(), "sas_pending" | "mutually_confirmed"),
                "phase_emoji",
            )?;
            require(v.len() == 7 && v.iter().all(|i| *i <= 63), "emoji_indices")?;
        }
        require(self.proposal_hash.is_none() || p >= 5, "phase_proposal")?;
        require(self.record_hash.is_none() || p >= 6, "phase_record")?;
        if let Some(v) = &self.result {
            super::channel::error_code(v)?;
            require(p >= 11 || v == "PublicationPending", "phase_result")?;
        }
        require(p < 11 || self.result.is_some(), "terminal_result")?;
        require(matches!(self.cleanup.as_str(), "none" | "pending" | "done"), "cleanup")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginResult {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
    pub expires_at: u64,
    pub invite_token: InviteToken,
}
impl PairingWire for BeginResult {
    const LIMIT: usize = 17_408;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "BeginResult")?;
        local_base(&self.operation_id, self.generation)?;
        integer(self.expires_at, "expires_at")?;
        self.invite_token.validate()?;
        require(
            self.operation_id == self.invite_token.invitation.body.request_id,
            "operation_binding",
        )?;
        require(self.expires_at == self.invite_token.invitation.body.expires_at, "expiry_binding")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Begin { value: Box<BeginResult> },
    Update { value: Box<Update> },
    FullStatus { value: Box<FullStatus> },
    Error { error: Failure },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResult {
    pub schema: String,
    pub version: u32,
    pub outcome: Outcome,
}
impl PairingWire for LocalResult {
    fn received_limit(&self) -> usize {
        match self.outcome {
            Outcome::Begin { .. } => 18_432,
            Outcome::Update { .. } | Outcome::FullStatus { .. } => 4608,
            Outcome::Error { .. } => 1024,
        }
    }
    const LIMIT: usize = 18_432;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "LocalResult")?;
        match &self.outcome {
            Outcome::Begin { value } => {
                value.validate()?;
            }
            Outcome::Update { value } => {
                value.validate()?;
                budget(self, 4608)?;
            }
            Outcome::FullStatus { value } => {
                value.validate()?;
                budget(self, 4608)?;
            }
            Outcome::Error { error } => {
                error.validate()?;
                budget(self, 1024)?;
            }
        }
        budget(self, Self::LIMIT)
    }
}
impl LocalResult {
    /// Bind a decoded result to its requested method.
    /// # Errors
    /// Rejects unknown methods and inappropriate success arms.
    pub fn validate_method(&self, method: &str) -> Result<()> {
        self.validate()?;
        let begin = matches!(method, "pair.begin" | "transfer.begin");
        require(
            begin
                || matches!(
                    method,
                    "pair.join"
                        | "pair.confirm"
                        | "pair.approve"
                        | "pair.cancel"
                        | "pair.status"
                        | "transfer.prepare"
                        | "transfer.confirm"
                        | "transfer.cancel"
                        | "transfer.status"
                ),
            "method",
        )?;
        require(
            !matches!(self.outcome, Outcome::FullStatus { .. }) || method == "transfer.status",
            "full_status_method",
        )?;
        require(
            matches!(self.outcome, Outcome::Error { .. })
                || begin == matches!(self.outcome, Outcome::Begin { .. }),
            "result_method",
        )
    }
}
/// The v2 update event is byte-compatible. Full progress uses the same tagged
/// success arm as `LocalResult`, with no optional fields or mixed alternatives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum LocalEvent {
    Update { schema: String, version: u32, update: Box<Update> },
    FullStatus { schema: String, version: u32, outcome: FullStatusEvent },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", rename_all = "snake_case", deny_unknown_fields)]
pub enum FullStatusEvent {
    FullStatus { value: Box<FullStatus> },
}
impl PairingWire for LocalEvent {
    const LIMIT: usize = 4608;
    fn validate(&self) -> Result<()> {
        match self {
            Self::Update { schema, version, update } => {
                header(schema, *version, "LocalEvent")?;
                update.validate()?;
            }
            Self::FullStatus { schema, version, outcome } => {
                header(schema, *version, "LocalEvent")?;
                let FullStatusEvent::FullStatus { value } = outcome;
                value.validate()?;
            }
        }
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub local_account_id: String,
    pub reservation_id: String,
    pub frontend_generation: u64,
    pub action: String,
}
impl PairingWire for CredentialRequest {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<()> {
        text(&self.local_account_id, true, "local_account_id")?;
        b32(&self.reservation_id, "reservation_id")?;
        integer(self.frontend_generation, "frontend_generation")?;
        require(self.frontend_generation >= 1, "frontend_generation")?;
        require(matches!(self.action.as_str(), "setup" | "unlock" | "phrase"), "action")?;
        budget(self, Self::LIMIT)
    }
}
/// Private borrowed provider inputs; no Serialize, Clone or Debug implementation.
/// Owned zeroizing buffers remain with the private SDK provider adapter.
#[derive(Clone, Copy)]
pub struct CredentialInput<'a> {
    pub passphrase: &'a [u8],
    pub confirmation: Option<&'a [u8]>,
}
impl CredentialRequest {
    /// Validate exact frontend-owned request binding and private byte inputs.
    /// # Errors
    /// Rejects stale or foreign requests, invalid UTF-8, lengths and confirmation arms.
    pub fn validate_input(&self, expected: &Self, input: CredentialInput<'_>) -> Result<()> {
        self.validate()?;
        expected.validate()?;
        require(self.local_account_id == expected.local_account_id, "credential_account")?;
        require(self.reservation_id == expected.reservation_id, "credential_reservation")?;
        require(self.frontend_generation == expected.frontend_generation, "credential_generation")?;
        require(self.action == expected.action, "credential_action")?;
        let total = input
            .passphrase
            .len()
            .checked_add(input.confirmation.map_or(0, <[u8]>::len))
            .ok_or(WireError::Size)?;
        require(total <= 2048, "credential_total")?;
        for v in std::iter::once(input.passphrase).chain(input.confirmation) {
            require(!v.is_empty() && v.len() <= 1024, "credential_length")?;
            require(std::str::from_utf8(v).is_ok(), "credential_utf8")?;
        }
        if self.action == "setup" {
            require(input.confirmation == Some(input.passphrase), "credential_confirmation")
        } else {
            require(input.confirmation.is_none(), "credential_confirmation")
        }
    }
}
impl std::fmt::Debug for Join {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Join { redacted }")
    }
}
impl std::fmt::Debug for BeginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BeginResult { redacted }")
    }
}
impl std::fmt::Debug for LocalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalResult { redacted }")
    }
}
impl CredentialRequest {
    /// Existing recipients may unlock their data store but never set up a replacement.
    /// # Errors
    /// Rejects unknown modes and setup for an already enrolled recipient.
    pub fn validate_recipient_mode(&self, mode: &str) -> Result<()> {
        self.validate()?;
        require(matches!(mode, "new" | "existing"), "recipient_mode")?;
        require(mode != "existing" || self.action == "unlock", "credential_mode")
    }
}
