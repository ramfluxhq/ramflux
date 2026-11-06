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

#[derive(Clone)]
pub(crate) struct GatewayHubEntry {
    session_id: String,
    pub(crate) token: GatewayRegistrationToken,
    pub(crate) queue: crate::push_queue::PushQueue,
    pub(crate) incarnation: Option<String>,
    sender: GatewaySendHandle,
}

#[derive(Default)]
pub(crate) struct GatewaySessionHub {
    senders_by_target: AsyncMutex<Arc<Index<GatewayHubEntry>>>,
    next_registration: std::sync::atomic::AtomicU64,
    pub(crate) probe_started: std::sync::atomic::AtomicBool,
    pub(crate) readiness: Arc<crate::session_push::Readiness>,
}

impl GatewaySessionHub {
    pub(crate) fn active_session_ids(&self) -> std::collections::BTreeSet<String> {
        let snapshot = self.senders_by_target.blocking_lock().clone();
        snapshot.values().map(|entry| entry.session_id.clone()).collect()
    }
    pub(crate) async fn snapshot(&self) -> Arc<Index<GatewayHubEntry>> {
        self.senders_by_target.lock().await.clone()
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
    pub(crate) async fn register_with_limit(
        self: &Arc<Self>,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
        incarnation: Option<String>,
        limit: usize,
    ) -> anyhow::Result<GatewayRegistration> {
        use std::sync::atomic::Ordering;
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
