// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent creation on the desktop: the request state machine and its durable record. Transport,
//! node admission and publication are separate stages; this module takes and returns bytes.
mod capability;
mod commit;
mod machine;
mod publish;
mod receive_checks;
mod receive_decision;
mod state;
mod store;

#[cfg(test)]
mod tests;

pub use capability::require_agent_custody_authorization;
pub use commit::commit_approved;
pub use machine::{
    BeginInput, BeginOutcome, PrimarySigning, apply_decision, begin, cancel, primary_sign_decision,
    receive_plan, resume_request,
};
pub(crate) use publish::{AgentPublishing, first_action, load_publishing};
pub use receive_checks::{
    check_plan_endpoints, check_received_request, check_scope, check_sender, expected_scope,
};
pub use receive_decision::{check_received_decision, primary_branch_public_key, receive_decision};
pub use state::{AgentCreationState, AgentFailure};
pub use store::{AgentCreationRecord, AgentCreationStore};
