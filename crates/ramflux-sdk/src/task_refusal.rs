// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable task refusal codes; internal quota scope is retained without parsing messages.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRefusalCode {
    RateLimited,
    InvalidRequest,
    InvalidEvent,
    NotRequester,
    NotAssignee,
    NotMember,
    NotEligibleAcceptor,
    HumanRequired,
    StaleRevision,
    Terminal,
    TaskStalled,
    NotFound,
    AlreadyExists,
    NoLocalRole,
    SignerQuotaExhausted,
    TaskQuotaExhausted,
    DecisionConsumed,
    DecisionMismatch,
}
impl TaskRefusalCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidEvent => "invalid_event",
            Self::NotRequester => "not_requester",
            Self::NotAssignee => "not_assignee",
            Self::NotMember => "not_member",
            Self::NotEligibleAcceptor => "not_eligible_acceptor",
            Self::HumanRequired => "human_required",
            Self::StaleRevision => "stale_revision",
            Self::Terminal => "terminal",
            Self::TaskStalled => "task_stalled",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::NoLocalRole => "no_local_role",
            Self::SignerQuotaExhausted | Self::TaskQuotaExhausted => "quota_exhausted",
            Self::DecisionConsumed => "decision_consumed",
            Self::DecisionMismatch => "decision_mismatch",
        }
    }
}
pub(crate) fn refused(reason: TaskRefusalCode, message: impl Into<String>) -> crate::SdkError {
    crate::SdkError::TaskRefused { reason, message: message.into() }
}
pub(crate) fn protocol(error: &ramflux_protocol::TaskReject) -> crate::SdkError {
    use ramflux_protocol::TaskReject as E;
    let reason = match error {
        E::StaleVersion { .. } | E::StaleDecision { .. } | E::InvalidVersion => {
            TaskRefusalCode::StaleRevision
        }
        E::Terminal => TaskRefusalCode::Terminal,
        E::HumanRequired => TaskRefusalCode::HumanRequired,
        E::NotFound => TaskRefusalCode::NotFound,
        E::AlreadyExists => TaskRefusalCode::AlreadyExists,
        E::DecisionReplay => TaskRefusalCode::DecisionConsumed,
        E::DecisionMismatch | E::HumanDecisionPending => TaskRefusalCode::DecisionMismatch,
        _ => TaskRefusalCode::InvalidEvent,
    };
    refused(reason, error.to_string())
}
