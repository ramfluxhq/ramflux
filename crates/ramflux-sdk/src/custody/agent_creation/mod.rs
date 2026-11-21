// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent creation on the desktop: the request state machine and its durable record. Transport,
//! node admission and publication are separate stages; this module takes and returns bytes.
mod advance;
mod capability;
mod commit;
mod machine;
mod publish;
mod rebind;
mod rebind_commit;
mod rebind_observe;
mod rebind_plan;
mod rebind_send;
mod receive_checks;
mod receive_decision;
mod state;
mod store;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod rebind_commit_tests;
#[cfg(test)]
mod rebind_plan_tests;
#[cfg(test)]
mod rebind_tests;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
pub(crate) mod tests;

pub use advance::{AgentStep, AgentSteps, advance_all, advance_one};
pub use capability::require_agent_custody_authorization;
pub use commit::commit_approved;
pub(crate) use commit::desktop_is_enrolled;
pub use machine::{
    BeginInput, BeginOutcome, PrimarySigning, apply_decision, begin, cancel, primary_sign_decision,
    receive_plan, resume_request,
};
pub(crate) use publish::complete_with_receipt;
pub(crate) use publish::{AgentPublishing, first_action, load_publishing};
pub use rebind::{RebindBinding, RebindEntry};
pub use rebind_commit::commit_rebind;
pub use rebind_observe::observe_primary;
pub(crate) use rebind_plan::check_decision_context;
pub use rebind_plan::{RebindInput, begin_rebind, stored_profile};
pub use rebind_send::{PreparedRebind, prepare_rebind_request};
pub use receive_checks::{
    check_plan_endpoints, check_received_request, check_scope, check_sender, expected_scope,
};
pub use receive_decision::{check_received_decision, primary_branch_public_key, receive_decision};
pub use state::{AgentCreationState, AgentFailure};
pub use store::{AgentCreationRecord, AgentCreationStore};
