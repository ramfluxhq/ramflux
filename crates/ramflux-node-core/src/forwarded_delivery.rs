// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private federation ingress preserves sender bytes and the source retention deadline.
use crate::{
    CustodyPublication, InboxEntry, MigrationNode, NodeCoreError, RouterCore, RouterRedbStore,
    RouterSubmitOutcome,
};
use ramflux_protocol::home_migration::{CommitProof, Refusal, Signed};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub peer_node_id: String,
    pub envelope: ramflux_protocol::Envelope,
    pub migration_evidence: Option<ForwardedMigrationEvidence>,
}
// Serialize pin eviction with inbox acceptance so a newly verified pin cannot be
// evicted between its authority transaction and its durable inbox receipt.
pub(crate) static FOREIGN_PIN_ADMISSION: std::sync::Mutex<()> = std::sync::Mutex::new(());
static PIN_REFERENCES: std::sync::Mutex<std::collections::BTreeMap<String, usize>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
struct PinReferences(Vec<String>);
impl PinReferences {
    fn new(envelope: &ramflux_protocol::Envelope) -> Result<Self, NodeCoreError> {
        let (authority, source) =
            crate::DeviceAuthKeyResponse::forwarded_envelope_source(envelope)?;
        let mut anchors = vec![source.root_commitment().to_owned()];
        if let Some(evidence) = authority.custody_authority
            && let Some(custodian) = evidence.custodian_publication
        {
            anchors.push(custodian.record.body.account_anchor);
        }
        let mut references =
            PIN_REFERENCES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for anchor in &anchors {
            *references.entry(anchor.clone()).or_default() += 1;
        }
        Ok(Self(anchors))
    }
}
impl Drop for PinReferences {
    fn drop(&mut self) {
        let mut references =
            PIN_REFERENCES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for anchor in &self.0 {
            if let Some(count) = references.get_mut(anchor) {
                *count -= 1;
                if *count == 0 {
                    references.remove(anchor);
                }
            }
        }
    }
}
pub(crate) fn pin_referenced(anchor: &str) -> bool {
    PIN_REFERENCES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key(anchor)
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
        crate::router_store::publication::capture(|| {
            self.submit_forwarded_envelope_inner(store, node, request, now)
        })?
        .published_blocking()?
    }

    fn authenticated_forwarded_source(
        &self,
        store: &RouterRedbStore,
        peer_node_id: &str,
        envelope: &ramflux_protocol::Envelope,
        floors: &[CustodyPublication],
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let native = envelope
            .ext
            .ext
            .get("source_device_authority")
            .and_then(|v| v.get("custody_authority"))
            .is_some_and(|v| !v.is_null());
        let source = if native {
            self.authenticated_native_forwarded_source_from_peer(
                peer_node_id,
                envelope,
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
                envelope,
                Some(store),
                crate::RouterEnvelopeOrigin::Federation,
            )?
        };
        Ok(source)
    }

    fn submit_forwarded_envelope_inner(
        &self,
        store: &RouterRedbStore,
        node: Option<&MigrationNode>,
        request: ForwardedEnvelopeRequest,
        now: u64,
    ) -> Result<RouterSubmitOutcome, NodeCoreError> {
        let pin_admission =
            FOREIGN_PIN_ADMISSION.lock().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        let ForwardedEnvelopeRequest { envelope, migration_evidence, peer_node_id } = request;
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
        let source =
            self.authenticated_forwarded_source(store, &peer_node_id, &envelope, floors)?;
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
        // Transfer eviction protection from the global authentication lock to
        // bounded live references before persistence or waiting on an original.
        let _pins = PinReferences::new(&envelope)?;
        let admission = store.admit_sender_retry(&source, &envelope, now)?;
        drop(pin_admission);
        let retry_owner = match admission {
            crate::sender_retry::RetryAdmission::Owner(owner) => owner,
            retry => {
                drop(lease);
                let assignment = match retry {
                    crate::sender_retry::RetryAdmission::Accepted(assignment) => assignment,
                    crate::sender_retry::RetryAdmission::Waiting(waiter) => {
                        waiter.resolved_blocking()?
                    }
                    crate::sender_retry::RetryAdmission::Owner(_) => unreachable!(),
                };
                let assignment =
                    crate::publication::await_sender_retry(&store.publication_core()?, assignment)?;
                return Ok(crate::sender_retry::accepted_outcome(&assignment, envelope));
            }
        };
        retry_owner.bind(&envelope.target_delivery_id)?;
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
        self.prepare_publication_target(store, &envelope.target_delivery_id)?;
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
                if crate::publication::proved_non_write() {
                    return Err(crate::sender_retry::SenderRetryRefusal::AbortedRetrySafe.into());
                }
                tracing::error!(%error, "forwarded inbox persistence failed after acceptance; terminating to avoid a state fork");
                std::process::abort();
            }
            let assignment = store
                .sender_assignment(source.root_commitment(), &entry.envelope, now)?
                .ok_or_else(|| NodeCoreError::Redb("accepted sender index missing".into()))?;
            retry_owner.accepted(assignment);
        }
        Ok(outcome)
    }
}
