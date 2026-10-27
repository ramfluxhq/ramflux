// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable migration metadata. Debug and progress never disclose admission evidence.
use ramflux_protocol::{custody::DeviceRef, home_migration as wire};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Intent,
    PrepareSent,
    AwaitingCustodyUnlock,
    SealSent,
    Sealed,
    CommitPending,
    ActivateSent,
    BacklogTransferring,
    Reconnecting,
    ManifestSwitchPending,
    Forwarding,
    Complete,
    Expired,
    Aborted,
    Refused,
    NeedsAttention,
}
impl MigrationPhase {
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Expired | Self::Aborted | Self::Refused)
    }
}
/// Bus input. The operation identifier is a canonical base64url 32-byte random value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationIntent {
    pub operation_id: String,
    pub target_discovery_url: String,
    pub expected_node_fingerprint: String,
}
/// This is the complete public event body; its sequence is local to this operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationProgress {
    pub operation_id: String,
    pub seq: u64,
    pub phase: MigrationPhase,
    pub source: String,
    pub target: Option<String>,
    pub home_epoch: Option<u64>,
    pub home_hash: Option<String>,
    pub commit_deadline: Option<u64>,
    pub forward_until: Option<u64>,
    pub backlog: wire::BacklogProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<wire::Refusal>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub version: u32,
    pub intent: MigrationIntent,
    pub intent_hash: String,
    pub anchor: String,
    pub authority_hash: String,
    pub actor: DeviceRef,
    pub source_key: String,
    pub progress: MigrationProgress,
    pub recovery_blocked: bool,
    pub cancel_requested: bool,
    pub clock_floor: u64,
    pub attempts: u32,
    pub next_attempt_at: u64,
    pub target: Option<ramflux_protocol::WellKnownClientRecord>,
    pub prepare: Option<wire::Signed<wire::Prepare>>,
    pub offer: Option<wire::Signed<wire::Offer>>,
    pub draft: Option<wire::Authorization>,
    pub proposal_digest: Option<String>,
    pub authorization: Option<wire::Signed<wire::Authorization>>,
    pub seal: Option<wire::Signed<wire::Receipt>>,
    pub commit: Option<wire::Signed<wire::CommitProof>>,
    pub fence: Option<wire::Signed<wire::NoncommitFence>>,
    pub new_home: Option<wire::RecordEvidence>,
}
impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationJob").field("progress", &self.progress).finish_non_exhaustive()
    }
}
