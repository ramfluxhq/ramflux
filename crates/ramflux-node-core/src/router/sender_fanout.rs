// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Child-qualified sender retry ownership across own-device fanout.
use super::{
    Arc, InboxEntry, ItestMvp10OwnDeviceFanoutDelivery, ItestMvp10OwnDeviceFanoutRequest,
    ItestMvp10OwnDeviceFanoutResponse, NodeCoreError, ReplayAcceptedFanoutDelivery, RouterCore,
    envelope_replay_tuple_key, lock_unpoisoned, mvp10_fanout_envelope_id, replay_guard_shard_index,
};
use crate::sender_retry::{RetryAdmission, RetryOwner, RetryWaiter};

struct Candidate {
    device: String,
    envelope: ramflux_protocol::Envelope,
    admission: RetryAdmission,
}
enum Child {
    Complete(ItestMvp10OwnDeviceFanoutDelivery),
    Waiting { device: String, target: String, waiter: RetryWaiter },
}
/// Stored fanout response, with original-child retry waiters still outside all locks.
pub struct PreparedFanout {
    principal_id: String,
    source_device_id: String,
    children: Vec<Child>,
    core: Arc<crate::publication::PublicationCore>,
}
impl PreparedFanout {
    /// Await attached children and their original publication gates.
    /// # Errors
    /// Returns a store/runtime error; typed child refusals remain delivery outcomes.
    pub async fn resolved(self) -> Result<ItestMvp10OwnDeviceFanoutResponse, NodeCoreError> {
        let mut delivered = Vec::with_capacity(self.children.len());
        for child in self.children {
            delivered.push(match child {
                Child::Complete(delivery) => delivery,
                Child::Waiting { device, target, waiter } => match waiter.resolved().await {
                    Ok(assignment) => {
                        self.core.wait_sender_assignment(&assignment).await;
                        delivery(device, target, "offline_queued", Some(assignment.inbox_seq))
                    }
                    Err(error) => delivery(device, target, &error.to_string(), None),
                },
            });
        }
        Ok(ItestMvp10OwnDeviceFanoutResponse {
            principal_id: self.principal_id,
            source_device_id: self.source_device_id,
            delivered,
        })
    }
    /// Blocking compatibility for TCP mesh/store threads.
    /// # Errors
    /// Returns runtime creation and persistence errors.
    pub fn resolved_blocking(self) -> Result<ItestMvp10OwnDeviceFanoutResponse, NodeCoreError> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .block_on(self.resolved())
    }
}
fn delivery(
    device_id: String,
    target_delivery_id: String,
    outcome: &str,
    inbox_seq: Option<u64>,
) -> ItestMvp10OwnDeviceFanoutDelivery {
    ItestMvp10OwnDeviceFanoutDelivery {
        device_id,
        target_delivery_id,
        outcome: outcome.into(),
        inbox_seq,
    }
}

impl RouterCore {
    /// Freeze authenticated children, register retry ownership before tentative
    /// replay acceptance, and persist only newly allocated children.
    /// # Errors
    /// Returns authority, typed admission, replay or persistence errors.
    pub fn prepare_sender_fanout(
        &self,
        store: &crate::RouterRedbStore,
        request: &ItestMvp10OwnDeviceFanoutRequest,
        now: i64,
    ) -> Result<PreparedFanout, NodeCoreError> {
        match self.prepare_sender_fanout_inner(store, request, now) {
            Ok(prepared) => Ok(prepared),
            Err(
                error @ (NodeCoreError::SenderRetry(_)
                | NodeCoreError::Publication(_)
                | NodeCoreError::PayloadTooLarge),
            ) => {
                let outcome = if matches!(
                    error,
                    NodeCoreError::Publication(
                        crate::publication::PublicationRefusal::CapacityRetryAfter { .. }
                    )
                ) {
                    "capacity_retry_after".into()
                } else {
                    error.to_string()
                };
                Ok(PreparedFanout {
                    principal_id: request.principal_id.clone(),
                    source_device_id: request.source_device_id.clone(),
                    children: self
                        .mvp10_own_device_targets(request)?
                        .into_iter()
                        .map(|(device, target)| {
                            Child::Complete(delivery(device, target, &outcome, None))
                        })
                        .collect(),
                    core: store.publication_core()?,
                })
            }
            Err(error) => Err(error),
        }
    }
    fn prepare_sender_fanout_inner(
        &self,
        store: &crate::RouterRedbStore,
        request: &ItestMvp10OwnDeviceFanoutRequest,
        now: i64,
    ) -> Result<PreparedFanout, NodeCoreError> {
        let source = self.authenticated_envelope_source_durable(&request.envelope, store)?;
        let targets = self.mvp10_own_device_targets(request)?;
        let leases = targets
            .iter()
            .map(|(_, target)| store.acquire_submission(target))
            .collect::<Result<Vec<_>, _>>()?;
        let mut normalized = request.envelope.clone();
        self.refresh_registered_envelope_authority(&mut normalized)?;
        let mut checked = Vec::with_capacity(targets.len());
        for (device, target) in targets {
            let mut envelope = normalized.clone();
            envelope.target_delivery_id = target;
            envelope.envelope_id = mvp10_fanout_envelope_id(&request.envelope.envelope_id, &device);
            crate::check_entry_bound(&envelope)?;
            checked.push((device, envelope));
        }
        let mut candidates = Vec::with_capacity(checked.len());
        for (device, envelope) in checked {
            candidates.push(Candidate {
                device,
                admission: store.admit_sender_retry(&source, &envelope, now)?,
                envelope,
            });
        }
        let core = store.publication_core()?;
        let has_retry =
            candidates.iter().any(|child| !matches!(child.admission, RetryAdmission::Owner(_)));
        let replay = envelope_replay_tuple_key(&source, &request.envelope);
        let has_owners =
            candidates.iter().any(|child| matches!(child.admission, RetryAdmission::Owner(_)));
        let identities = if has_owners {
            self.prepare_sender_fanout_targets(store, &core, &candidates, &replay, now)?
        } else {
            Vec::new()
        };
        if has_owners
            && !self.accept_envelope_replay_once(&source, &request.envelope, now)?
            && !has_retry
        {
            return Err(NodeCoreError::ReplayGuard(format!("replay: {replay}")));
        }
        if has_owners {
            crate::router_store::publication::operation::reserve_targets(&core, &identities)?;
        }
        let (children, entries, owners) = self.assign_sender_fanout(store, candidates, now)?;
        if !entries.is_empty() {
            let expiry =
                request
                    .envelope
                    .created_at
                    .checked_add(i64::from(request.envelope.ttl))
                    .ok_or_else(|| NodeCoreError::ReplayGuard("fanout expiry overflow".into()))?;
            if let Err(error) = store.record_leased_fanout(
                &replay,
                expiry,
                source.root_commitment(),
                &entries,
                leases,
            ) {
                if crate::publication::proved_non_write() {
                    return Err(crate::sender_retry::SenderRetryRefusal::AbortedRetrySafe.into());
                }
                tracing::error!(%error, "fanout persistence failed after hand-off");
                std::process::abort();
            }
            for (owner, entry) in owners {
                owner.accepted_entry(store, source.root_commitment(), &entry, now);
            }
        }
        Ok(PreparedFanout {
            principal_id: request.principal_id.clone(),
            source_device_id: request.source_device_id.clone(),
            children,
            core,
        })
    }

    fn prepare_sender_fanout_targets(
        &self,
        store: &crate::RouterRedbStore,
        core: &Arc<crate::publication::PublicationCore>,
        candidates: &[Candidate],
        replay: &str,
        now: i64,
    ) -> Result<Vec<(String, String)>, NodeCoreError> {
        let mut identities = Vec::new();
        for child in candidates {
            if let RetryAdmission::Owner(owner) = &child.admission {
                self.prepare_publication_target(store, &child.envelope.target_delivery_id)?;
                owner.bind(&child.envelope.target_delivery_id)?;
                identities.push((
                    child.envelope.target_delivery_id.clone(),
                    store.provisional_inbox_incarnation(&child.envelope.target_delivery_id)?,
                ));
            }
        }
        // A durable sibling is authoritative visibility evidence for a reused
        // parent replay key; an aborted new child must not remove that evidence.
        crate::router_store::publication::operation::reference_replay(core, replay, || {
            lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(replay)])
                .accepted_entries()
                .any(|(key, expiry)| key == replay && *expiry >= now)
        })?;
        Ok(identities)
    }

    fn assign_sender_fanout(
        &self,
        store: &crate::RouterRedbStore,
        candidates: Vec<Candidate>,
        now: i64,
    ) -> Result<FanoutAssignments, NodeCoreError> {
        let mut children = Vec::with_capacity(candidates.len());
        let mut entries = Vec::new();
        let mut owners = Vec::new();
        for child in candidates {
            let target = child.envelope.target_delivery_id.clone();
            match child.admission {
                RetryAdmission::Accepted(assignment) => {
                    let assignment = crate::publication::await_sender_retry(
                        &store.publication_core()?,
                        assignment,
                    )?;
                    children.push(Child::Complete(delivery(
                        child.device,
                        target,
                        "offline_queued",
                        Some(assignment.inbox_seq),
                    )));
                }
                RetryAdmission::Waiting(waiter) => {
                    children.push(Child::Waiting { device: child.device, target, waiter });
                }
                RetryAdmission::Owner(owner) => {
                    let (result, entry) = self.submit_replay_accepted_fanout_delivery(
                        ReplayAcceptedFanoutDelivery {
                            device_id: child.device,
                            target_delivery_id: target,
                            envelope: child.envelope,
                        },
                        now,
                    );
                    if let Some(entry) = entry {
                        owners.push((owner, entry.clone()));
                        entries.push(entry);
                    }
                    children.push(Child::Complete(result));
                }
            }
        }
        Ok((children, entries, owners))
    }
}
type FanoutAssignments = (Vec<Child>, Vec<InboxEntry>, Vec<(RetryOwner, InboxEntry)>);
