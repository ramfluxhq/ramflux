// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Advances the pending agent creations of one human account (controller decision r10 item 1).
//! The human account's runtime performs the store steps, the caller activates the agent account.
//! Every step is idempotent: a request already past a step skips it, and a failed step leaves the
//! request in the state it had, so the next advance (unlock, or an operation read) repeats it.

use super::rebind::RebindBinding;
use super::rebind_plan::is_rebind;
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use std::future::Future;

/// Whether the agent of this record has a paused binding (rebind pending or committed) in the
/// inventory. Such an agent is neither activated nor connected by an advance.
fn binding_is_paused(
    store: &AgentCreationStore,
    record: &AgentCreationRecord,
) -> Result<bool, SdkError> {
    let Some(account_id) = record.account_id.as_deref() else {
        return Ok(false);
    };
    Ok(store.load_rebind(account_id)?.is_some_and(|entry| {
        matches!(entry.binding, RebindBinding::RebindPending | RebindBinding::Committed)
    }))
}

/// One store step that the human account's runtime performs for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStep {
    /// Commit an approved request (`commit_approved`), with the capabilities of the selected node.
    Commit { request_id: String, capabilities: Vec<String>, now: u64 },
    /// Mark a request complete once its receipt is saved (no-op before the receipt).
    Complete { request_id: String },
}

/// The effects an advance needs. The human runtime implements the store steps; the supervisor
/// implements activation. Tests implement them with the real store steps and a fake connection.
pub trait AgentSteps {
    /// Commit the approved request; returns the record after the commit.
    fn commit(
        &mut self,
        request_id: &str,
        now: u64,
    ) -> impl Future<Output = Result<AgentCreationRecord, SdkError>>;
    /// Whether the agent account is already open (live), so activation can be skipped.
    fn is_live(&self, account_id: &str) -> bool;
    /// Activate the agent account; its ordinary connection runs the registration.
    fn activate(
        &mut self,
        record: &AgentCreationRecord,
    ) -> impl Future<Output = Result<(), SdkError>>;
    /// Complete the request; returns the record after the step.
    fn complete(
        &mut self,
        request_id: &str,
    ) -> impl Future<Output = Result<AgentCreationRecord, SdkError>>;
}

/// Advances one request as far as it can go and returns its state afterwards.
///
/// # Errors
/// Returns the first step failure; the record keeps the state it had before that step.
pub async fn advance_one<S: AgentSteps>(
    steps: &mut S,
    store: &AgentCreationStore,
    request_id: &str,
    now: u64,
) -> Result<AgentCreationState, SdkError> {
    let mut record = store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    // Stage D3: a rebind request is not a creation (stage D4 commits it), and an agent whose
    // binding is paused (rebind pending) or committed-but-unpublished is never activated here.
    if is_rebind(&record) || binding_is_paused(store, &record)? {
        return Ok(record.state);
    }
    if record.state == AgentCreationState::Authorized {
        record = steps.commit(request_id, now).await?;
    }
    if record.state == AgentCreationState::Complete {
        return Ok(record.state);
    }
    if !matches!(
        record.state,
        AgentCreationState::PublicationPending | AgentCreationState::PublicationUnknown
    ) {
        return Ok(record.state);
    }
    let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
    if !steps.is_live(&account_id) {
        steps.activate(&record).await?;
    }
    record = steps.complete(request_id).await?;
    Ok(record.state)
}

/// Advances every pending request of the human account, oldest id first. A failure on one request
/// does not stop the others; each outcome is returned with its request id.
///
/// # Errors
/// Refuses a record directory that cannot be read.
pub async fn advance_all<S: AgentSteps>(
    steps: &mut S,
    store: &AgentCreationStore,
    now: u64,
) -> Result<Vec<(String, Result<AgentCreationState, SdkError>)>, SdkError> {
    let mut outcomes = Vec::new();
    for record in store.pending()? {
        let outcome = advance_one(steps, store, &record.request_id, now).await;
        outcomes.push((record.request_id, outcome));
    }
    Ok(outcomes)
}
