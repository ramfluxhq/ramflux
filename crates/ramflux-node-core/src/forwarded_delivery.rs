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
/// Metadata captured by forwarded acceptance, never reconstructed by authenticating a reply.
pub struct ForwardedSubmission {
    pub outcome: RouterSubmitOutcome,
    pub incarnation_id: Option<String>,
    pub retain_until: Option<i64>,
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
    /// Run on a blocking/store thread; async ingress must prepare there and await publication.
    /// # Errors
    /// Refuses stale sender authority, dormant homes, invalid seals and persistence failures.
    pub fn submit_forwarded_envelope(
        &self,
        store: &RouterRedbStore,
        node: Option<&MigrationNode>,
        request: ForwardedEnvelopeRequest,
        now: u64,
    ) -> Result<RouterSubmitOutcome, NodeCoreError> {
        ramflux_protocol::ephemeral::require_durable(&request.envelope)?;
        self.prepare_forwarded_envelope(store, node, request, now)?.published_blocking()?
    }

    /// Prepare forwarded acceptance on a blocking/store thread, then await
    /// [`crate::publication::PublishedOperation::published`] from async ingress.
    /// # Errors
    /// Refuses nested publication scopes; the operation carries validation/storage errors.
    pub fn prepare_forwarded_envelope(
        &self,
        store: &RouterRedbStore,
        node: Option<&MigrationNode>,
        request: ForwardedEnvelopeRequest,
        now: u64,
    ) -> Result<
        crate::publication::PublishedOperation<Result<RouterSubmitOutcome, NodeCoreError>>,
        NodeCoreError,
    > {
        ramflux_protocol::ephemeral::require_durable(&request.envelope)?;
        crate::router_store::publication::capture(|| {
            self.submit_forwarded_envelope_inner(store, node, request, now)
                .map(|result| result.outcome)
        })
    }

    /// Prepare a forwarded result with its original acceptance metadata.
    /// # Errors
    /// Refuses nested preparation and propagates the existing storage/admission errors.
    pub fn prepare_forwarded_envelope_with_metadata(
        &self,
        store: &RouterRedbStore,
        node: Option<&MigrationNode>,
        request: ForwardedEnvelopeRequest,
        now: u64,
    ) -> Result<
        crate::publication::PublishedOperation<Result<ForwardedSubmission, NodeCoreError>>,
        NodeCoreError,
    > {
        ramflux_protocol::ephemeral::require_durable(&request.envelope)?;
        crate::router_store::publication::capture(|| {
            self.submit_forwarded_envelope_inner(store, node, request, now)
        })
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
    ) -> Result<ForwardedSubmission, NodeCoreError> {
        ramflux_protocol::ephemeral::require_durable(&request.envelope)?;
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
                return Ok(ForwardedSubmission {
                    outcome: crate::sender_retry::accepted_outcome(&assignment, envelope),
                    incarnation_id: Some(assignment.inbox_incarnation_id),
                    retain_until: Some(assignment.retain_until),
                });
            }
        };
        retry_owner.bind(&envelope.target_delivery_id)?;
        if store.has_local_delivery_envelope(
            source.root_commitment(),
            &envelope.envelope_id,
            &envelope.target_delivery_id,
            now,
        )? {
            return Ok(ForwardedSubmission {
                outcome: RouterSubmitOutcome::DuplicateFederatedForward {
                    target_delivery_id: envelope.target_delivery_id,
                },
                incarnation_id: None,
                retain_until: None,
            });
        }
        self.prepare_publication_target(store, &envelope.target_delivery_id)?;
        let replay = crate::envelope_replay_tuple_key(&source, &envelope);
        let outcome = self.submit_envelope_at(&source, envelope, now);
        let entry = accepted_entry(&outcome);
        let mut metadata = (None, None);
        if let Some(entry) = entry {
            self.constrain_forwarded_retention(&entry, deadline);
            metadata = self.session_delivery_metadata(&entry.target_delivery_id, entry.inbox_seq);
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
            retry_owner.accepted_entry(store, source.root_commitment(), &entry, now);
        }
        Ok(ForwardedSubmission { outcome, incarnation_id: metadata.0, retain_until: metadata.1 })
    }
}

fn accepted_entry(outcome: &RouterSubmitOutcome) -> Option<InboxEntry> {
    match outcome {
        RouterSubmitOutcome::Online(d) => Some(InboxEntry {
            inbox_seq: d.inbox_seq,
            target_delivery_id: d.target_delivery_id.clone(),
            envelope: d.envelope.clone(),
        }),
        RouterSubmitOutcome::OfflineQueued(d) => Some(d.entry.clone()),
        _ => None,
    }
}
