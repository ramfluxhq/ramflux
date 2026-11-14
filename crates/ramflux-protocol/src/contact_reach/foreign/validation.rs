// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Correlation and closed error/result grammar shared by native and gateway consumers.
use super::super::{digest, invalid, safe, text};
use super::{Operation, OperationResult, Reason, Request, Response, SubmitOutcome, directory};
impl Request {
    /// Check account/session framing before dispatch; no body claims grant a session.
    /// # Errors
    /// Refuses invalid correlation ids, generation or hop budgets.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        digest(&self.request_id)?;
        text(&self.session_id)?;
        safe(self.session_generation)?;
        if self.session_generation == 0 || !(1..=10_000).contains(&self.remaining_ms) {
            return Err(invalid("reach session generation or budget"));
        }
        if let Operation::GroupRoster { operation_id, roster } = &self.operation {
            digest(operation_id)?;
            roster.header.body.validate()?;
            if crate::canonical_json_bytes(roster)?.len() > 16 * 1024 {
                return Err(invalid("group roster operation byte budget"));
            }
        }
        if let Operation::Query { query } = &self.operation {
            query.validate()?;
            if query.nonce != self.request_id {
                return Err(invalid("query nonce/request id mismatch"));
            }
        }
        Ok(())
    }
    /// Validate the exact stream/session generation and operation-specific reply.
    /// # Errors
    /// Refuses response substitution, unsafe error metadata and mismatched result variants.
    pub fn validate_response(&self, response: &Response) -> Result<(), crate::ProtocolError> {
        if self.request_id != response.request_id
            || self.session_id != response.session_id
            || self.session_generation != response.session_generation
        {
            return Err(invalid("reach response/session correlation mismatch"));
        }
        self.operation.validate_result(&response.result)
    }
}

impl Operation {
    /// Match the exact result arm and immutable request identity before exposing an owner result.
    /// # Errors
    /// Refuses substituted envelope/profile ids, mismatched revisions and recursive composite results.
    pub fn validate_result(&self, result: &OperationResult) -> Result<(), crate::ProtocolError> {
        if let OperationResult::Error { reason, retry_after_ms, current_revision } = result {
            return validate_error(*reason, *retry_after_ms, *current_revision);
        }
        let valid = match (self, result) {
            (Self::Query { query }, OperationResult::Query { reply }) => {
                let body = &reply.snapshot.body;
                body.source_node == query.target_node
                    && body.target_node == query.source_node
                    && body.account_anchor == query.account_anchor
                    && body.request_nonce == query.nonce
                    && body.request_hash
                        == crate::custody::framed_hash(super::QUERY_HASH_DOMAIN, query)?
            }
            (Self::Cost { request, target_node_id }, OperationResult::Challenge { challenge }) => {
                challenge.body.validate()?;
                challenge.body.issuer == *target_node_id
                    && challenge.body.purpose == request.purpose
                    && challenge.body.source_root == request.source_root
                    && challenge.body.recipient_root == request.recipient_root
                    && challenge.body.operation_hash == request.operation_hash
            }
            (
                Self::Submit { submission, .. },
                OperationResult::Submit { envelope_id, outcome, reason },
            ) => {
                envelope_id == &submission.envelope.envelope_id
                    && (*outcome == SubmitOutcome::Refused) == reason.is_some()
            }
            (Self::Policy { update }, OperationResult::Policy { revision, .. }) => {
                *revision == update.body.revision
            }
            (Self::Admission { update, .. }, OperationResult::Admission { revision, outcome }) => {
                if *outcome == super::Applied::Duplicate {
                    *revision >= update.body.expected_revision
                } else {
                    update.body.expected_revision.checked_add(1) == Some(*revision)
                }
            }
            (Self::GroupRoster { .. }, OperationResult::Admission { revision, .. }) => {
                *revision <= crate::MAX_SAFE_JSON_INTEGER
            }
            (
                Self::Start { update, submission, .. },
                OperationResult::Start { revision, submission: result, .. },
            )
            | (
                Self::Reply { update, submission, .. },
                OperationResult::Reply { revision, submission: result, .. },
            ) => {
                update.body.expected_revision.checked_add(1) == Some(*revision)
                    && matches!(result.as_ref(),OperationResult::Submit {
                    envelope_id,outcome:SubmitOutcome::Spooled,reason:None } if envelope_id==&submission.envelope.envelope_id)
            }
            (
                Self::ReachState { snapshot_id, page, .. },
                OperationResult::ReachState { manifest, page: result },
            ) => {
                result.page == *page
                    && snapshot_id.as_ref().is_none_or(|id| id == &manifest.body.snapshot_id)
                    && result.snapshot_id == manifest.body.snapshot_id
            }
            (
                Self::Strangers { after_seq, limit, .. },
                OperationResult::Strangers { entries, next_seq },
            ) => {
                let mut previous = *after_seq;
                let mut ordered = true;
                for entry in entries {
                    if entry.seq <= previous {
                        ordered = false;
                    }
                    previous = entry.seq;
                }
                ordered
                    && u64::try_from(entries.len()).is_ok_and(|n| n <= *limit && n <= 16)
                    && *next_seq == previous
                    && crate::canonical_json_bytes(entries)?.len() <= 2 * 1024 * 1024
            }
            _ => directory_result(self, result)?,
        };
        if !valid {
            return Err(invalid("reach operation/result mismatch"));
        }
        Ok(())
    }
}

fn validate_error(
    reason: Reason,
    retry_after_ms: Option<u64>,
    current_revision: Option<u64>,
) -> Result<(), crate::ProtocolError> {
    let revision =
        matches!(reason, Reason::ReachRevisionConflict | Reason::AdmissionRevisionConflict);
    if revision != current_revision.is_some() {
        return Err(invalid("reach error revision metadata"));
    }
    if let Some(value) = current_revision {
        safe(value)?;
    }
    let rate = matches!(reason, Reason::ForeignRateLimited | Reason::ForeignSpamLimited);
    if retry_after_ms != if rate { Some(1000) } else { None } {
        return Err(invalid("reach error retry metadata"));
    }
    Ok(())
}

fn directory_result(
    operation: &Operation,
    result: &OperationResult,
) -> Result<bool, crate::ProtocolError> {
    Ok(match (operation, result) {
        (
            Operation::ProfilePublish { update, .. },
            OperationResult::ProfilePublish { epoch, profile_hash, .. },
        ) => {
            *epoch == update.body.epoch
                && profile_hash
                    == &crate::custody::framed_hash(directory::PROFILE_HASH_DOMAIN, update)?
        }
        (
            Operation::UsernameMutate { operation, .. },
            OperationResult::UsernameMutate { receipt },
        ) => {
            receipt.body.operation_id == operation.body.operation_id
                && receipt.body.operation_hash
                    == crate::custody::framed_hash(directory::OPERATION_HASH_DOMAIN, operation)?
        }
        (
            Operation::UsernameStatus { operation_id, operation_hash, .. },
            OperationResult::UsernameStatus { receipt },
        ) => {
            receipt.body.operation_id == *operation_id
                && receipt.body.operation_hash == *operation_hash
        }
        (
            Operation::UsernameResolve { name, nonce },
            OperationResult::UsernameResolve { resolve },
        ) => resolve.body.name == *name && resolve.body.request_nonce == *nonce,
        _ => false,
    })
}
