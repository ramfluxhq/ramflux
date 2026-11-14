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
        home: &ramflux_crypto::home_migration::VerifiedHome,
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
        ramflux_protocol::contact_reach::check_submission_time(
            manifest.body.issued_at,
            manifest.body.expires_at,
            network::now()?,
        )?;
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(60))
            .ok_or_else(|| refused(Reason::ForeignSnapshotExpired))?;
        let mut pages = Vec::new();
        let mut page_bytes = 2_usize;
        append_state_page(&mut pages, page, &manifest.body, 0, &mut page_bytes)?;
        for index in 1..manifest.body.page_count {
            check_read_deadline(deadline)?;
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
            check_read_deadline(deadline)?;
            append_state_page(&mut pages, page, &manifest.body, index, &mut page_bytes)?;
        }
        drop(ramflux_protocol::contact_reach::verify_pages(&manifest.body, &pages)?);
        let provenance = self.read_reach_provenance(&manifest, &pages, deadline).await?;
        if page_bytes
            .checked_add(provenance.staged_bytes())
            .is_none_or(|total| total > ramflux_protocol::contact_reach::MAX_REACH_STAGING_BYTES)
        {
            return Err(refused(Reason::ForeignCapacity));
        }
        VerifiedReachState::verify(
            &manifest,
            &pages,
            provenance,
            ReachReadContext {
                authority: self.account.verified(),
                device: &self.device,
                home_head_hash: home.hash(),
                home: Some(home),
                home_node_key: self.pins.public_key(),
                minimum_revision,
                now: network::now()?,
            },
        )
    }

    async fn read_reach_provenance(
        &mut self,
        manifest: &ramflux_protocol::custody::Envelope<
            ramflux_protocol::contact_reach::StateManifest,
        >,
        pages: &[ramflux_protocol::contact_reach::StatePage],
        deadline: std::time::Instant,
    ) -> Result<ramflux_crypto::contact_reach::EncryptedProvenanceStage, SdkError> {
        let signers = ramflux_protocol::contact_reach::page_signers(pages)?;
        let required: std::collections::BTreeSet<_> =
            signers.iter().map(|reference| reference.proof_hash.clone()).collect();
        let mut stage = ramflux_crypto::contact_reach::ProvenanceStageBuilder::new(
            &manifest.body.account_anchor,
            manifest.body.revision,
            &manifest.body.state_hash,
            signers,
        )?;
        for expected_hash in required {
            check_read_deadline(deadline)?;
            let result = self
                .reach_operation(Operation::ReachProvenance {
                    snapshot_id: manifest.body.snapshot_id.clone(),
                    proof_hash: expected_hash.clone(),
                })
                .await?;
            let OperationResult::ReachProvenance {
                manifest: returned,
                proof_hash,
                authority,
                custodian_history,
            } = result
            else {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            };
            if &returned != manifest || proof_hash != expected_hash {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            }
            check_read_deadline(deadline)?;
            stage.push(&ramflux_protocol::contact_reach::ProvenanceAuthority {
                proof_hash,
                authority: *authority,
                custodian_history,
            })?;
        }
        check_read_deadline(deadline)?;
        Ok(stage.finish()?)
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

fn append_state_page(
    pages: &mut Vec<ramflux_protocol::contact_reach::StatePage>,
    page: ramflux_protocol::contact_reach::StatePage,
    manifest: &ramflux_protocol::contact_reach::StateManifest,
    index: u64,
    bytes: &mut usize,
) -> Result<(), SdkError> {
    let size = ramflux_protocol::canonical_json_bytes(&page)?.len();
    if page.version != 1
        || page.page != index
        || page.snapshot_id != manifest.snapshot_id
        || page.records.is_empty()
        || page.records.len() > 32
        || page.signers.len() > 128
        || size > 1024 * 1024
    {
        return Err(refused(Reason::ForeignSnapshotInvalid));
    }
    *bytes = bytes
        .checked_add(size + usize::from(!pages.is_empty()))
        .filter(|total| *total <= ramflux_protocol::contact_reach::MAX_STATE_BYTES)
        .ok_or_else(|| refused(Reason::ForeignCapacity))?;
    pages.push(page);
    Ok(())
}

fn check_read_deadline(deadline: std::time::Instant) -> Result<(), SdkError> {
    if std::time::Instant::now() >= deadline {
        return Err(refused(Reason::ForeignSnapshotExpired));
    }
    Ok(())
}
