// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore exact committed public bytes without reserving, retrying or extending an operation.
use super::{
    HomeDirectory, HomeIntent, HomeProfileView, LiveHomeRevalidation, ensure, matches_intent,
    observe, verify_candidate,
};
use crate::username_directory::{CheckpointError, Result};
use ed25519_dalek::VerifyingKey;
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};

impl HomeDirectory {
    /// Requires current native master authority and a newly authenticated centre response.
    /// Historical signatures and archive bytes alone grant no publication authority.
    /// # Errors
    /// Refuses a noncurrent tuple, invalid signatures, substituted home, or floor regression.
    pub fn recover_committed(
        &self,
        master: &VerifyingKey,
        candidate: HomeIntent,
        live: LiveHomeRevalidation,
        now: u64,
    ) -> Result<HomeProfileView> {
        ramflux_crypto::username_directory::verify_operation(master, &candidate.operation)?;
        verify_candidate(master, &candidate.operation, &candidate.profile)?;
        let op = &candidate.operation.body;
        ensure(
            op.binding.as_ref().is_none_or(|binding| binding.body.node == self.home),
            Code::OwnershipMismatch,
        )?;
        let live = live.into_result();
        ensure(
            live.root == op.principal_commitment && live.issued_at <= now && now < live.expires_at,
            Code::DirectoryUnavailable,
        )?;
        let receipt =
            live.current_receipt.as_ref().ok_or(CheckpointError::Directory(Code::NotFound))?;
        ensure(
            receipt.body.state == w::ReceiptState::Committed
                && op.issued_at <= receipt.body.committed_at
                && receipt.body.committed_at < op.expires_at,
            Code::Replay,
        )?;
        matches_intent(&candidate, receipt)?;
        ensure(live.current_binding == op.binding, Code::StaleEpoch)?;
        let view = HomeProfileView {
            operation: candidate.operation.clone(),
            binding: live.current_binding.clone(),
            profile: candidate.profile,
            receipt: receipt.clone(),
        };
        self.update(&op.principal_commitment, |state| {
            ensure(!state.deleted || op.action == w::Action::Delete, Code::AccountDeleted)?;
            observe(state, &live)?;
            let same =
                state.intent.as_ref().is_some_and(|intent| intent.operation == candidate.operation);
            if same || op.action == w::Action::Delete {
                state.intent = None;
            }
            state.deleted |= op.action == w::Action::Delete;
            // A different restrictive local intent keeps its suppression while the older
            // committed bytes repair the base. It never becomes an implicit cancellation.
            state.suppressed = !live.lookup_allowed
                || state
                    .intent
                    .as_ref()
                    .is_some_and(|intent| super::restrictive(&intent.operation));
            state.committed = Some(view.clone());
            Ok(())
        })?;
        Ok(view)
    }
}
