// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One action-selected payload transcript is shared by clients and custody dispatch.
use super::{
    Action, ActionPayload, Authorization, Request, Response, Signed, invalid, message_hash,
};
use crate::{ProtocolError, custody::framed_hash, domain};
/// Hash the immutable action payload, including authorization-only cancellation after a lost seal.
/// # Errors
/// Rejects an action/payload mismatch, missing cancellation binding or serialization failure.
pub fn control_payload_hash(
    action: Action,
    payload: &ActionPayload,
    cancellation: Option<&Signed<Authorization>>,
) -> Result<String, ProtocolError> {
    match (action, payload) {
        (Action::Attest, ActionPayload::Attest(value)) => {
            framed_hash(domain::HOME_ATTEST_REQUEST, value)
        }
        (Action::Prepare, ActionPayload::Prepare(value)) => message_hash(value),
        (Action::Seal, ActionPayload::Seal(value)) => framed_hash(domain::HOME_CONTROL, value),
        (Action::Commit, ActionPayload::Commit(value)) => framed_hash(domain::HOME_CONTROL, value),
        (Action::Activate, ActionPayload::Activate(value)) => {
            framed_hash(domain::HOME_CONTROL, value)
        }
        (Action::Status, ActionPayload::Operation(value)) => {
            framed_hash(domain::HOME_CONTROL, value)
        }
        (Action::Abort, ActionPayload::Operation(value)) => {
            cancellation.map_or_else(|| framed_hash(domain::HOME_CONTROL, value), message_hash)
        }
        (Action::Resolve, ActionPayload::Resolve(value)) => {
            framed_hash(domain::HOME_CONTROL, value)
        }
        (Action::Fence, ActionPayload::Fence(value)) => framed_hash(domain::HOME_CONTROL, value),
        _ => Err(invalid("migration action does not match payload")),
    }
}
impl Request {
    /// Check action-selected payload integrity and every duplicated owner/operation identifier.
    /// Signatures and current authority remain the receiving service's responsibility.
    /// # Errors
    /// Rejects substituted payloads or evidence that changes an authorization-only cancellation.
    pub fn validate_payload_binding(&self) -> Result<(), ProtocolError> {
        let c = &self.control.body;
        if c.payload_hash
            != control_payload_hash(c.action, &self.payload, self.evidence.authorization.as_ref())?
        {
            return Err(invalid("migration payload hash mismatch"));
        }
        let own = &c.requester.account_anchor;
        match &self.payload {
            ActionPayload::Attest(p) if p.account_anchor != *own || p.nonce != c.nonce => {
                return Err(invalid("migration attest owner mismatch"));
            }
            ActionPayload::Prepare(p)
                if p.body.account_anchor != *own
                    || p.body.migration_id != c.migration_id
                    || p.body.actor != c.requester =>
            {
                return Err(invalid("migration prepare owner mismatch"));
            }
            ActionPayload::Operation(p)
                if p.account_anchor != *own || p.migration_id != c.migration_id =>
            {
                return Err(invalid("migration operation owner mismatch"));
            }
            _ => {}
        }
        if c.action == Action::Abort
            && let Some(auth) = &self.evidence.authorization
            && (auth.body.account_anchor != *own || auth.body.migration_id != c.migration_id)
        {
            return Err(invalid("migration cancellation authorization mismatch"));
        }
        Ok(())
    }
}
impl Response {
    /// Bind all six response members independently of the fresh receipt signature.
    /// # Errors
    /// Returns canonical encoding or hashing errors.
    pub fn payload_hash(&self) -> Result<String, ProtocolError> {
        framed_hash(
            domain::HOME_RECEIPT,
            &serde_json::json!({
                "offer": self.offer,
                "commit_proof": self.commit_proof,
                "noncommit_fence": self.noncommit_fence,
                "resolve_result": self.resolve_result,
                "backlog_progress": self.backlog_progress,
                "attestation": self.attestation,
            }),
        )
    }
}
