// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private federation ingress preserves sender bytes and the source retention deadline.
use crate::{
    CustodyPublication, InboxEntry, MigrationNode, NodeCoreError, RouterCore, RouterRedbStore,
    RouterSubmitOutcome,
};
use ramflux_protocol::home_migration::{CommitProof, Refusal, Signed};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedMigrationEvidence {
    pub commit_proof: Option<Signed<CommitProof>>,
    pub retain_until: i64,
    #[serde(default)]
    pub floors: Vec<CustodyPublication>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedEnvelopeRequest {
    pub envelope: ramflux_protocol::Envelope,
    pub migration_evidence: Option<ForwardedMigrationEvidence>,
}
impl RouterCore {
    /// Accept an envelope from an authenticated federation peer without rewriting it.
    /// # Errors
    /// Refuses stale sender authority, dormant homes, invalid seals and persistence failures.
    pub fn submit_forwarded_envelope(
        &self,
        store: &RouterRedbStore,
        node: Option<&MigrationNode>,
        request: ForwardedEnvelopeRequest,
        now: u64,
    ) -> Result<RouterSubmitOutcome, NodeCoreError> {
        let ForwardedEnvelopeRequest { envelope, migration_evidence } = request;
        // Verify sender bytes without persistence, then the complete sealed proof, before pins.
        crate::DeviceAuthKeyResponse::forwarded_envelope_source(&envelope)?;
        let proof = migration_evidence.as_ref().and_then(|e| e.commit_proof.as_ref());
        if proof.is_some() {
            let node = node.ok_or(NodeCoreError::HomeMigration(Refusal::PeeringUnavailable))?;
            store.check_forwarded_target(node, &envelope.target_delivery_id, proof, now, false)?;
        } else if !store.home_migration_target_active(&envelope.target_delivery_id)? {
            return Err(NodeCoreError::HomeMigration(Refusal::DormantInbox));
        }
        let floors = migration_evidence.as_ref().map_or(&[][..], |e| e.floors.as_slice());
        let native = envelope
            .ext
            .ext
            .get("source_device_authority")
            .and_then(|v| v.get("custody_authority"))
            .is_some_and(|v| !v.is_null());
        let source = if native {
            self.authenticated_native_forwarded_source_with_floors(
                &envelope,
                floors,
                store,
                crate::RouterEnvelopeOrigin::Federation,
            )?
        } else {
            if !floors.is_empty() {
                return Err(NodeCoreError::Unauthorized(
                    "native floors require native sender".into(),
                ));
            }
            self.authenticated_envelope_source_from(
                &envelope,
                Some(store),
                crate::RouterEnvelopeOrigin::Federation,
            )?
        };
        let proof = migration_evidence.as_ref().and_then(|e| e.commit_proof.as_ref());
        if let Some(proof) = proof {
            let node = node.ok_or(NodeCoreError::HomeMigration(Refusal::PeeringUnavailable))?;
            store.activate_forwarded_target(
                node,
                &envelope.target_delivery_id,
                Some(proof),
                now,
            )?;
        } else if !store.home_migration_target_active(&envelope.target_delivery_id)? {
            return Err(NodeCoreError::HomeMigration(Refusal::DormantInbox));
        }
        let lease = store.acquire_submission(&envelope.target_delivery_id)?;
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        let deadline = crate::inbox_retain_until(&envelope, now);
        let deadline =
            migration_evidence.as_ref().map_or(deadline, |e| deadline.min(e.retain_until));
        if deadline <= now {
            return Err(NodeCoreError::Unauthorized("forwarded entry expired".into()));
        }
        if store.has_local_delivery_envelope(
            source.root_commitment(),
            &envelope.envelope_id,
            &envelope.target_delivery_id,
            now,
        )? {
            return Ok(RouterSubmitOutcome::DuplicateFederatedForward {
                target_delivery_id: envelope.target_delivery_id,
            });
        }
        let replay = crate::envelope_replay_tuple_key(&source, &envelope);
        let outcome = self.submit_envelope_at(&source, envelope, now);
        let entry = match &outcome {
            RouterSubmitOutcome::Online(d) => Some(InboxEntry {
                inbox_seq: d.inbox_seq,
                target_delivery_id: d.target_delivery_id.clone(),
                envelope: d.envelope.clone(),
            }),
            RouterSubmitOutcome::OfflineQueued(d) => Some(d.entry.clone()),
            _ => None,
        };
        if let Some(entry) = entry {
            self.constrain_forwarded_retention(&entry, deadline);
            if let Err(error) = store.record_forwarded_submission(
                &replay,
                &entry,
                source.root_commitment(),
                deadline,
                lease,
            ) {
                tracing::error!(%error, "forwarded inbox persistence failed after acceptance; terminating to avoid a state fork");
                std::process::abort();
            }
        }
        Ok(outcome)
    }
}
