// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent creation on the desktop: the request state machine and its durable record. Transport,
//! node admission and publication are separate stages; this module takes and returns bytes.
mod machine;
mod receive_checks;
mod state;
mod store;

#[cfg(test)]
mod tests;

pub use machine::{
    BeginInput, BeginOutcome, PrimarySigning, apply_decision, begin, cancel, primary_sign_decision,
    receive_plan, resume_request,
};
pub use receive_checks::{
    check_plan_endpoints, check_received_request, check_scope, check_sender, expected_scope,
};
pub use state::{AgentCreationState, AgentFailure};
pub use store::{AgentCreationRecord, AgentCreationStore};
