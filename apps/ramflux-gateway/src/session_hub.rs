// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable hub snapshots and registration lifecycle.
use crate::GatewaySendHandle;
use crate::hub_index::Index;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GatewayRegistrationToken(u64);

pub(crate) struct GatewayRegistration {
    pub(crate) token: GatewayRegistrationToken,
    pub(crate) closed: tokio::sync::watch::Receiver<bool>,
}

struct BindSpec {
    target_delivery_id: String,
    session_id: String,
    sender: GatewaySendHandle,
    incarnation: Option<String>,
    limit: usize,
    ephemeral: bool,
}

#[derive(Clone)]
pub(crate) struct GatewayHubEntry {
    session_id: String,
    pub(crate) token: GatewayRegistrationToken,
    pub(crate) queue: crate::push_queue::PushQueue,
    pub(crate) incarnation: Option<String>,
    pub(crate) ephemeral: bool,
    /// Boot id this live ephemeral entry was last re-asserted against.
    asserted_boot: Option<String>,
    sender: GatewaySendHandle,
}

#[derive(Default)]
pub(crate) struct GatewaySessionHub {
    senders_by_target: AsyncMutex<Arc<Index<GatewayHubEntry>>>,
    next_registration: std::sync::atomic::AtomicU64,
    pub(crate) probe_started: std::sync::atomic::AtomicBool,
    pub(crate) probe_requests: crate::issued_probe::Requests,
    pub(crate) readiness: Arc<crate::session_push::Readiness>,
    pub(crate) ephemeral_rates: crate::ephemeral::EphemeralRateRegistry,
    /// Test-only observer for hub-path wake calls; each hub fixture owns its counter.
    #[cfg(test)]
    wake_calls: std::sync::atomic::AtomicU64,
    /// Per-hub C4 clock override; production builds always use wall clock.
    #[cfg(test)]
    ephemeral_clock_ms: std::sync::atomic::AtomicU64,
    /// Per-hub enqueue barrier; tests park one forward without a process-global hold.
    #[cfg(test)]
    enqueue_hold: std::sync::Mutex<
        Option<(std::sync::Arc<tokio::sync::Notify>, std::sync::Arc<tokio::sync::Semaphore>)>,
    >,
}

impl GatewaySessionHub {
    pub(crate) fn active_session_ids(&self) -> std::collections::BTreeSet<String> {
        let snapshot = self.senders_by_target.blocking_lock().clone();
        snapshot.values().map(|entry| entry.session_id.clone()).collect()
    }
    pub(crate) async fn snapshot(&self) -> Arc<Index<GatewayHubEntry>> {
        self.senders_by_target.lock().await.clone()
    }
    pub(crate) async fn ephemeral_registrations(
        &self,
        gateway_id: &str,
        boot: &str,
    ) -> Vec<ramflux_node_core::EphemeralRegistrationItem> {
        self.snapshot()
            .await
            .iter()
            .filter(|(_, entry)| {
                entry.ephemeral
                    && !entry.queue.is_closed()
                    && entry.asserted_boot.as_deref() != Some(boot)
            })
            .map(|(target, entry)| ramflux_node_core::EphemeralRegistrationItem {
                target: target.to_owned(),
                session_id: entry.session_id.clone(),
                gateway_id: gateway_id.to_owned(),
            })
            .collect()
    }
    pub(crate) async fn stamp_ephemeral_boot(
        &self,
        boot: &str,
        items: &[ramflux_node_core::EphemeralRegistrationItem],
    ) {
        let _ = self
            .update(|index| {
                for item in items {
                    if let Some(entry) = index.get_mut(&item.target)
                        && entry.ephemeral
                        && entry.session_id == item.session_id
                        && !entry.queue.is_closed()
                    {
                        entry.asserted_boot = Some(boot.to_owned());
                    }
                }
                None
            })
            .await;
    }
    #[cfg(test)]
    pub(crate) async fn ephemeral_flag(&self, target: &str) -> Option<bool> {
        self.snapshot().await.get(target).map(|entry| entry.ephemeral)
    }

    #[cfg(test)]
    pub(crate) fn wake_count(&self) -> u64 {
        self.wake_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn update<F>(&self, edit: F) -> anyhow::Result<Option<GatewayHubEntry>>
    where
        F: Fn(&mut Index<GatewayHubEntry>) -> Option<GatewayHubEntry>,
    {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let snapshot = self.snapshot().await;
                let mut next = (*snapshot).clone();
                let result = edit(&mut next);
                let mut current = self.senders_by_target.lock().await;
                if Arc::ptr_eq(&snapshot, &current) {
                    if let Some(old) = &result {
                        old.queue.prevent_admission();
                    }
                    let old = std::mem::replace(&mut *current, Arc::new(next));
                    drop(current);
                    drop(old);
                    return result;
                }
                drop(current);
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) async fn register(
        self: &Arc<Self>,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
    ) -> anyhow::Result<GatewayRegistration> {
        self.register_session(target_delivery_id, session_id, sender, None).await
    }
    #[cfg(test)]
    pub(crate) async fn register_session(
        self: &Arc<Self>,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
        incarnation: Option<String>,
    ) -> anyhow::Result<GatewayRegistration> {
        self.register_with_limit(target_delivery_id, session_id, sender, incarnation, 256).await
    }
    #[cfg(test)]
    pub(crate) async fn register_with_limit(
        self: &Arc<Self>,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
        incarnation: Option<String>,
        limit: usize,
    ) -> anyhow::Result<GatewayRegistration> {
        self.bind_registration(BindSpec {
            target_delivery_id,
            session_id,
            sender,
            incarnation,
            limit,
            ephemeral: false,
        })
        .await
    }
    pub(crate) async fn register_runtime(
        self: &Arc<Self>,
        runtime: &crate::GatewaySessionRuntime,
        sender: GatewaySendHandle,
    ) -> anyhow::Result<GatewayRegistration> {
        self.bind_registration(BindSpec {
            target_delivery_id: runtime.target_delivery_id.clone(),
            session_id: runtime.session_id.clone(),
            sender,
            incarnation: runtime.session_push.clone(),
            limit: runtime.push_limit,
            ephemeral: runtime.ephemeral,
        })
        .await
    }
    #[cfg(test)]
    pub(crate) async fn register_ephemeral(
        self: &Arc<Self>,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
        incarnation: Option<String>,
        limit: usize,
    ) -> anyhow::Result<GatewayRegistration> {
        self.bind_registration(BindSpec {
            target_delivery_id,
            session_id,
            sender,
            incarnation,
            limit,
            ephemeral: true,
        })
        .await
    }
    async fn bind_registration(
        self: &Arc<Self>,
        spec: BindSpec,
    ) -> anyhow::Result<GatewayRegistration> {
        use std::sync::atomic::Ordering;
        let BindSpec { target_delivery_id, session_id, sender, incarnation, limit, ephemeral } =
            spec;
        let sequence = self
            .next_registration
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| anyhow::anyhow!("gateway registration counter exhausted"))?;
        let token = GatewayRegistrationToken(sequence);
        let (closed, receiver) = tokio::sync::watch::channel(false);
        let queue = crate::push_queue::PushQueue::new(limit, closed);
        queue.install(&sender, incarnation.clone()).await?;
        let old = self
            .update(|index| {
                index.insert(
                    target_delivery_id.clone(),
                    GatewayHubEntry {
                        session_id: session_id.clone(),
                        token,
                        queue: queue.clone(),
                        incarnation: incarnation.clone(),
                        ephemeral,
                        asserted_boot: None,
                        sender: sender.clone(),
                    },
                )
            })
            .await?;
        if let Some(old) = old {
            old.queue.retire();
        }
        let hub = Arc::downgrade(self);
        tokio::spawn(async move {
            queue.run(sender, target_delivery_id.clone(), incarnation).await;
            if let Some(hub) = hub.upgrade() {
                hub.unregister(&target_delivery_id, token).await;
            }
        });
        Ok(GatewayRegistration { token, closed: receiver })
    }

    #[cfg(test)]
    pub(crate) async fn population_fixture(&self, n: usize, id: &str, sender: &GatewaySendHandle) {
        let mut index = Index::default();
        for n in 0..n {
            let (closed, _) = tokio::sync::watch::channel(false);
            index.insert(
                format!("target-{n:08}"),
                GatewayHubEntry {
                    session_id: format!("session-{n}"),
                    token: GatewayRegistrationToken(n as u64),
                    queue: crate::push_queue::PushQueue::new(16, closed),
                    incarnation: Some(id.into()),
                    ephemeral: false,
                    asserted_boot: None,
                    sender: sender.clone(),
                },
            );
        }
        *self.senders_by_target.lock().await = Arc::new(index);
    }
    pub(crate) async fn probe_observation(
        &self,
        target: &str,
        token: GatewayRegistrationToken,
        observation: Option<&crate::issued_probe::IssuedSeq>,
    ) {
        let entry = self.snapshot().await.get(target).cloned();
        if let Some(entry) = entry.filter(|e| e.token == token && !e.queue.is_closed()) {
            if let Some(row) = observation
                && row.incarnation_id.as_deref() != entry.incarnation.as_deref()
                && entry.incarnation.is_some()
            {
                entry.queue.request_retirement(entry.sender.clone());
                return;
            }
            if entry.incarnation.is_some() {
                entry.queue.observe_issued(observation.map(|r| r.inbox_seq));
            }
        }
    }
    pub(crate) async fn unregister(
        &self,
        target_delivery_id: &str,
        token: GatewayRegistrationToken,
    ) {
        let removed = self
            .update(|index| {
                if index.get(target_delivery_id).is_some_and(|entry| entry.token == token) {
                    index.remove(target_delivery_id)
                } else {
                    None
                }
            })
            .await
            .ok()
            .flatten();
        if let Some(entry) = removed {
            entry.queue.retire();
        }
    }
    #[cfg(test)]
    pub(crate) async fn flushed(&self, target: &str) -> anyhow::Result<()> {
        let queue = self.snapshot().await.get(target).map(|e| e.queue.clone());
        if let Some(queue) = queue {
            queue.flushed().await?;
        }
        Ok(())
    }

    pub(crate) async fn retire_incarnation(
        &self,
        target: &str,
        expected: &str,
        sender: &GatewaySendHandle,
    ) {
        if let Some(entry) = self.snapshot().await.get(target).cloned()
            && entry.incarnation.as_deref() == Some(expected)
            && Arc::ptr_eq(&entry.sender, sender)
        {
            entry.queue.retire_with_sink(&entry.sender).await;
            self.unregister(target, entry.token).await;
        }
    }
    /// A peer sink failure is a delivery miss, never a failure of the calling session.
    #[cfg(test)]
    pub(crate) async fn send_to(
        &self,
        target_delivery_id: &str,
        frame: &ramflux_node_core::GatewayServerFrame,
    ) -> bool {
        self.send_delivery(target_delivery_id, frame, None).await
    }
    pub(crate) async fn send_delivery(
        &self,
        target: &str,
        frame: &ramflux_node_core::GatewayServerFrame,
        metadata: Option<(&str, i64)>,
    ) -> bool {
        matches!(
            self.send_delivery_result(target, frame, metadata).await,
            ramflux_node_core::SessionPushForwardOutcome::Queued
                | ramflux_node_core::SessionPushForwardOutcome::Overflowed
        )
    }
    pub(crate) async fn send_delivery_result(
        &self,
        target_delivery_id: &str,
        frame: &ramflux_node_core::GatewayServerFrame,
        metadata: Option<(&str, i64)>,
    ) -> ramflux_node_core::SessionPushForwardOutcome {
        use ramflux_node_core::SessionPushForwardOutcome as Outcome;
        let entry = self.snapshot().await.get(target_delivery_id).cloned();
        let Some(entry) = entry else {
            return Outcome::NoSession;
        };
        let wire = match (&entry.incarnation, frame) {
            (Some(expected), ramflux_node_core::GatewayServerFrame::Deliver { entry: row }) => {
                let Some((id, deadline)) = metadata else {
                    return if entry.queue.not_pushed(row.inbox_seq) {
                        Outcome::Overflowed
                    } else {
                        Outcome::NoSession
                    };
                };
                if id != expected {
                    entry.queue.request_retirement(entry.sender.clone());
                    return Outcome::Overflowed;
                }
                serde_json::to_vec(&ramflux_node_core::SessionPushServerFrame::Deliver {
                    entry: row.clone(),
                    incarnation_id: id.into(),
                    retain_until: deadline,
                })
            }
            _ => serde_json::to_vec(frame),
        };
        let Ok(wire) = wire else {
            return Outcome::NoSession;
        };
        if wire.len() > crate::push_queue::BYTE_CAP
            || (entry.incarnation.is_some() && wire.len() > ramflux_node_core::ENTRY_FRAME_BYTE_CAP)
        {
            return Outcome::NoSession;
        }
        let seq = match frame {
            ramflux_node_core::GatewayServerFrame::Deliver { entry } => entry.inbox_seq,
            _ => 0,
        };
        let admission = if entry.incarnation.is_some() {
            entry.queue.try_push_versioned(wire, seq, entry.incarnation.clone())
        } else {
            entry.queue.try_push(wire, seq)
        };
        match admission {
            crate::push_queue::Admission::Queued => Outcome::Queued,
            crate::push_queue::Admission::Overflowed => Outcome::Overflowed,
            crate::push_queue::Admission::Closed => Outcome::NoSession,
        }
    }
    /// Enqueue a transient frame on the live registration for `target_delivery_id`.
    /// Transients never touch the Resync slot or durable coverage (D4).
    pub(crate) async fn try_push_transient(
        &self,
        target_delivery_id: &str,
        bytes: Vec<u8>,
        expires_at_ms: u64,
    ) -> crate::push_queue::TransientAdmission {
        let Some(entry) = self.snapshot().await.get(target_delivery_id).cloned() else {
            return crate::push_queue::TransientAdmission::Closed;
        };
        entry.queue.try_push_transient(bytes, expires_at_ms)
    }
    /// C4: recheck the live hub entry at final enqueue.
    ///
    /// The registration at `registration_target` must exist with an open token and
    /// `ephemeral == true`, and that key must equal `forward_target`, which must
    /// equal `envelope_target`. Capability replacement is refused here, not at C1.
    pub(crate) async fn try_enqueue_ephemeral(
        &self,
        registration_target: &str,
        forward_target: &str,
        envelope_target: &str,
        bytes: Vec<u8>,
        expires_at_ms: u64,
    ) -> crate::ephemeral_forward::EphemeralEnqueueOutcome {
        use crate::ephemeral_forward::EphemeralEnqueueOutcome as Outcome;
        self.await_enqueue_hold().await;
        let Some(entry) = self.snapshot().await.get(registration_target).cloned() else {
            return crate::ephemeral_forward::finish_without_wake(Outcome::Offline);
        };
        if entry.queue.is_closed() {
            return crate::ephemeral_forward::finish_without_wake(Outcome::Offline);
        }
        if !entry.ephemeral {
            return crate::ephemeral_forward::finish_without_wake(Outcome::RecipientUnsupported);
        }
        if registration_target != forward_target || forward_target != envelope_target {
            return crate::ephemeral_forward::finish_without_wake(Outcome::RecipientUnsupported);
        }
        // Final admission: the hub lookup above is awaited, so re-read the injected clock here.
        // A forward validated at D-1 that resumes at D is refused without charging occupancy.
        if entry.queue.clock_ms() >= expires_at_ms {
            return crate::ephemeral_forward::finish_without_wake(Outcome::Expired);
        }
        let admission = entry.queue.try_push_transient(bytes, expires_at_ms);
        let outcome = match admission {
            crate::push_queue::TransientAdmission::Queued => Outcome::Queued,
            crate::push_queue::TransientAdmission::QueueFull => Outcome::QueueFull,
            crate::push_queue::TransientAdmission::Closed => Outcome::Offline,
        };
        crate::ephemeral_forward::finish_without_wake(outcome)
    }
    #[cfg(test)]
    pub(crate) fn park_next_enqueue(
        &self,
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Semaphore>,
    ) {
        *self.enqueue_hold.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((entered, release));
    }

    #[cfg(test)]
    #[allow(clippy::panic, reason = "test hold must fail the test on timeout")]
    async fn await_enqueue_hold(&self) {
        let barrier = self.enqueue_hold.lock().ok().and_then(|mut hold| hold.take());
        if let Some((entered, release)) = barrier {
            entered.notify_one();
            match tokio::time::timeout(std::time::Duration::from_secs(10), release.acquire()).await
            {
                Ok(Ok(permit)) => permit.forget(),
                Ok(Err(closed)) => panic!("enqueue hold closed: {closed}"),
                Err(elapsed) => panic!("enqueue hold timed out: {elapsed}"),
            }
        }
    }

    #[cfg(not(test))]
    async fn await_enqueue_hold(&self) {
        std::future::ready(()).await;
    }

    #[cfg(test)]
    pub(crate) async fn ephemeral_queued(&self, target: &str) -> usize {
        self.snapshot().await.get(target).map_or(0, |entry| entry.queue.ephemeral_len())
    }
    #[cfg(test)]
    pub(crate) async fn set_queue_clock(&self, target: &str, now_ms: u64) {
        if let Some(entry) = self.snapshot().await.get(target) {
            entry.queue.set_clock_ms(now_ms);
        }
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_now_ms(&self) -> Option<u64> {
        let now_ms = self.ephemeral_clock_ms.load(std::sync::atomic::Ordering::Acquire);
        (now_ms != 0).then_some(now_ms)
    }

    #[cfg(test)]
    pub(crate) fn set_ephemeral_clock_ms(&self, now_ms: u64) {
        self.ephemeral_clock_ms.store(now_ms, std::sync::atomic::Ordering::Release);
    }
}

impl Drop for GatewaySessionHub {
    fn drop(&mut self) {
        for entry in self.senders_by_target.get_mut().values() {
            entry.queue.retire();
        }
    }
}

#[cfg(test)]
mod tests;
