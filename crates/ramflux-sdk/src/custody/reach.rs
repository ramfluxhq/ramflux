// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native, session-correlated reach operations; retries preserve the caller's sealed operation.
use super::{CustodyConnection, network};
use crate::{
    SdkError,
    contact_reach::{ReachReadContext, VerifiedReachState},
};
use ramflux_protocol::{
    contact_reach::*,
    custody::{CustodyServerFrame, CustodySessionAction},
};

fn refused(reason: Reason) -> SdkError {
    SdkError::ReachRefused(reason)
}
impl<S: ramflux_transport::GatewaySessionTransport + Send> CustodyConnection<S> {
    /// Execute an already prepared operation on the current authenticated native session.
    /// No signing credential crosses this boundary. Start/reply retries reuse exact bytes/ids.
    /// # Errors
    /// Refuses expired/missing sessions, mismatched correlation and typed remote errors.
    pub async fn reach_operation(
        &mut self,
        operation: Operation,
    ) -> Result<OperationResult, SdkError> {
        let session = self.session.as_ref().ok_or_else(|| refused(Reason::ForeignUnavailable))?;
        let request = Request {
            request_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            session_id: session.session_id.clone(),
            session_generation: 1,
            remaining_ms: u64::try_from(self.timeout.as_millis().min(10_000))
                .map_err(|_| refused(Reason::ForeignUnavailable))?,
            operation,
        };
        request.validate()?;
        let frame = self
            .request(CustodySessionAction::ContactForeign { request: Box::new(request.clone()) })
            .await?;
        let CustodyServerFrame::ContactForeignResult { response } = frame else {
            return Err(refused(Reason::ForeignInvalidFrame));
        };
        if response.request_id != request.request_id
            || response.session_id != request.session_id
            || response.session_generation != request.session_generation
        {
            return Err(refused(Reason::ForeignInvalidFrame));
        }
        if let OperationResult::Error { reason, .. } = response.result {
            return Err(refused(reason));
        }
        Ok(response.result)
    }

    /// Fetch a complete immutable reach mirror before projecting any page.
    /// The independently verified home head is supplied by the account's home resolver.
    /// # Errors
    /// Refuses partial/expired pages, changed manifests, bad signatures and retained rollback.
    pub async fn refresh_reach_state(
        &mut self,
        minimum_revision: u64,
        home_head_hash: &str,
    ) -> Result<VerifiedReachState, SdkError> {
        let result = self
            .reach_operation(Operation::ReachState {
                known_revision: minimum_revision,
                snapshot_id: None,
                page: 0,
            })
            .await?;
        let OperationResult::ReachState { manifest, page } = result else {
            return Err(refused(Reason::ForeignInvalidFrame));
        };
        manifest.body.validate()?;
        let mut pages = vec![page];
        for index in 1..manifest.body.page_count {
            let result = self
                .reach_operation(Operation::ReachState {
                    known_revision: minimum_revision,
                    snapshot_id: Some(manifest.body.snapshot_id.clone()),
                    page: index,
                })
                .await?;
            let OperationResult::ReachState { manifest: next, page } = result else {
                return Err(refused(Reason::ForeignInvalidFrame));
            };
            if next != manifest {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            }
            pages.push(page);
        }
        VerifiedReachState::verify(
            &manifest,
            &pages,
            ReachReadContext {
                authority: self.account.verified(),
                device: &self.device,
                home_head_hash,
                home_node_key: self.pins.public_key(),
                minimum_revision,
                now: network::now()?,
            },
        )
    }

    /// Read/ACK the bounded per-device Strangers transfer queue without accepting a peer.
    /// # Errors
    /// Returns authentication, cursor, capacity and transport refusals.
    pub async fn strangers(
        &mut self,
        after_seq: u64,
        limit: u64,
        ack_seqs: Vec<u64>,
    ) -> Result<OperationResult, SdkError> {
        self.reach_operation(Operation::Strangers { after_seq, limit, ack_seqs }).await
    }
}
