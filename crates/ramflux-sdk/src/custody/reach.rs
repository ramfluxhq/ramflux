// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native, session-correlated reach operations; retries preserve the caller's sealed operation.
use super::{CustodyConnection, network};
use crate::{
    SdkError,
    contact_reach::{ReachReadContext, VerifiedReachState},
};
use ramflux_protocol::{
    contact_reach::{Operation, OperationResult, Reason, Request},
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
        if !ramflux_protocol::contact_reach::enabled() {
            return Err(refused(Reason::ForeignCapabilityMissing));
        }
        let session = self.session.as_ref().ok_or_else(|| refused(Reason::ForeignUnavailable))?;
        let request = Request {
            request_id: match &operation {
                Operation::Query { query } => query.nonce.clone(),
                _ => ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            },
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
        request.validate_response(&response)?;
        crate::contact_reach::remote_result(response.result)
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
        let mut authorities = std::collections::BTreeMap::new();
        let signers = ramflux_protocol::contact_reach::page_signers(&pages)?;
        let mut staging_bytes = ramflux_protocol::canonical_json_bytes(&pages)?.len();
        for reference in &signers {
            if authorities.contains_key(&reference.proof_hash) {
                continue;
            }
            let result = self
                .reach_operation(Operation::ReachProvenance {
                    snapshot_id: manifest.body.snapshot_id.clone(),
                    proof_hash: reference.proof_hash.clone(),
                })
                .await?;
            staging_bytes = staging_bytes
                .checked_add(ramflux_protocol::canonical_json_bytes(&result)?.len())
                .ok_or_else(|| refused(Reason::ForeignCapacity))?;
            if staging_bytes > ramflux_protocol::contact_reach::MAX_REACH_STAGING_BYTES {
                return Err(refused(Reason::ForeignCapacity));
            }
            let OperationResult::ReachProvenance {
                manifest: returned,
                proof_hash,
                authority,
                custodian_history,
            } = result
            else {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            };
            if returned != manifest || proof_hash != reference.proof_hash {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            }
            authorities.insert(
                proof_hash.clone(),
                ramflux_protocol::contact_reach::ProvenanceAuthority {
                    proof_hash,
                    authority: *authority,
                    custodian_history,
                },
            );
        }
        let provenance = ramflux_protocol::contact_reach::Provenance {
            kind: ramflux_protocol::contact_reach::ProvenanceKind::ReachProvenance,
            version: 1,
            account_anchor: manifest.body.account_anchor.clone(),
            revision: manifest.body.revision,
            state_hash: manifest.body.state_hash.clone(),
            signers,
            authorities: authorities.into_values().collect(),
        };
        VerifiedReachState::verify(
            &manifest,
            &pages,
            provenance,
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
