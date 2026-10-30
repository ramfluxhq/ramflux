// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable surface deferrals and poll errors independent of event-stream progress.
use crate::checkpoint::DeferredSurface;
use crate::{AgentBus, AgentHost, EngineProvider, Error, OutputRefusal, Result, participant};
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::json;
const MAX_DEFERRED: usize = 64;
// Reserve eight slots for already persisted work while bounding new admissions.
const MAX_NEW_DEFERRED: usize = 56;
const MAX_DEFERRED_BYTES: usize = 32 * 1024;
// Per-conversation limits constrain monopolization. The global admission cap still applies;
// the eight reserved slots preserve legacy entries and updates, not new conversations.
const MAX_PER_CONVERSATION: usize = 4;
const MAX_CONVERSATION_BYTES: usize = MAX_DEFERRED_BYTES / 16;
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) fn defer_surface(
        &mut self,
        event: &LocalBusFrame,
        seq: u64,
        ready_at: u64,
    ) -> Result<()> {
        let conversation = participant::field(&event.body, "conversation_id")?.to_owned();
        let reference = participant::field(&event.body, "surface_ref")?.to_owned();
        let action = event
            .body
            .get("last_action_id")
            .filter(|v| !v.is_null())
            .map(|_| participant::field(&event.body, "last_action_id").map(str::to_owned))
            .transpose()?;
        let key = ramflux_protocol::hash_base64url(
            "ramflux.agent.deferred_surface.v1",
            &ramflux_protocol::canonical_json_bytes(&(&conversation, &reference, &action))
                .map_err(|_| Error::State)?,
        );
        let mut queued = self.state.deferred_surfaces.clone();
        let conversation_id = conversation.clone();
        let is_new = !queued.contains_key(&key);
        queued.entry(key).and_modify(|old| old.ready_at = ready_at).or_insert(DeferredSurface {
            seq,
            conversation,
            reference,
            action,
            ready_at,
        });
        if is_new
            && (queued.len() > MAX_NEW_DEFERRED || !conversation_fits(&queued, &conversation_id))
        {
            return Err(Error::Limit);
        }
        if queued.len() > MAX_DEFERRED
            || serde_json::to_vec(&queued).map_err(|_| Error::State)?.len() > MAX_DEFERRED_BYTES
        {
            return Err(Error::Limit);
        }
        let mut next = self.state.clone();
        next.deferred_surfaces = queued;
        // Leave room for the refusal/cursor that may be recorded by a subsequent event.
        if serde_json::to_vec(&next).map_err(|_| Error::State)?.len()
            > usize::try_from(crate::checkpoint::MAX_STATE_BYTES)
                .map_err(|_| Error::Limit)?
                .saturating_sub(8192)
        {
            return Err(Error::Limit);
        }
        self.state = next;
        self.store.save(&self.state)
    }
    /// Poll the authenticated inbox and recheck due surface actions without sleeping per conversation.
    ///
    /// # Errors
    /// Returns only identity/storage loss or a transport/stream failure requiring reconnect.
    pub(crate) async fn poll(&mut self, bus: &mut impl AgentBus, now_ms: u64) -> Result<()> {
        self.prune_rate_history(now_ms);
        if let Err(error) = bus
            .request("message.receive", json!({"limit":32,"auto_fetch_attachments":false}), None)
            .await
        {
            if error.stops_host() || matches!(error, Error::Bus | Error::Resync) {
                return Err(error);
            }
            let refusal = OutputRefusal {
                group_reason: None,
                conversation_id: String::new(),
                surface_id: None,
                reason: crate::runner_policy::refusal(&error),
            };
            if self.state.last_refusal.as_ref() != Some(&refusal) {
                self.state.last_refusal = Some(refusal);
                self.store.save(&self.state)?;
            }
        }
        self.recover_pending(bus).await?;
        let mut due = self
            .state
            .deferred_surfaces
            .iter()
            .filter(|(_, work)| work.ready_at <= now_ms)
            .map(|(key, work)| (key.clone(), work.clone()))
            .collect::<Vec<_>>();
        due.sort_by_key(|(_, work)| work.seq);
        for (key, work) in due {
            let mut event = LocalBusFrame::request(
                "deferred-surface",
                Some(self.config.account_id.clone()),
                "stream",
                "surface.changed",
                json!({
                    "conversation_id":work.conversation,"surface_ref":work.reference,"last_action_id":work.action,
                    "author_principal_id":self.state.principal_id,"executor_device_id":self.state.device_id,
                    "is_action_executor":true,"out_of_sync":work.action.is_none(),
                }),
            );
            event.kind = LocalBusFrameKind::Event;
            event.seq = Some(work.seq);
            let result = self.surface_action(bus, &event, work.seq, now_ms).await;
            self.finish_event(result, &event, work.seq)?;
            // Keep the durable entry through reads/sends. Recovery or rfd's consumed-action
            // guard handles a crash after send but before retiring this entry.
            if self
                .state
                .deferred_surfaces
                .get(&key)
                .is_some_and(|queued| queued.ready_at <= now_ms)
            {
                self.state.deferred_surfaces.remove(&key);
                self.store.save(&self.state)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn valid(state: &crate::Checkpoint) -> bool {
    state.deferred_surfaces.len() <= MAX_DEFERRED
        && serde_json::to_vec(&state.deferred_surfaces)
            .is_ok_and(|bytes| bytes.len() <= MAX_DEFERRED_BYTES)
        && state.deferred_surfaces.values().all(|work| {
            [work.conversation.as_str(), work.reference.as_str()]
                .into_iter()
                .chain(work.action.as_deref())
                .all(|id| !id.is_empty() && id.len() <= 1024)
        })
}

fn conversation_fits(
    rows: &std::collections::BTreeMap<String, DeferredSurface>,
    conversation: &str,
) -> bool {
    let owned = rows
        .iter()
        .filter(|(_, work)| work.conversation == conversation)
        .collect::<std::collections::BTreeMap<_, _>>();
    owned.len() <= MAX_PER_CONVERSATION
        && serde_json::to_vec(&owned).is_ok_and(|bytes| bytes.len() <= MAX_CONVERSATION_BYTES)
}
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) fn normalize_deferred(&mut self) -> Result<()> {
        let mut ordered = self
            .state
            .deferred_surfaces
            .iter()
            .map(|(key, work)| (key.clone(), work.clone()))
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(_, work)| work.seq);
        let mut kept = std::collections::BTreeMap::new();
        let mut rejected = None;
        for (key, work) in ordered {
            kept.insert(key.clone(), work.clone());
            if !conversation_fits(&kept, &work.conversation) {
                kept.remove(&key);
                rejected = Some(OutputRefusal {
                    group_reason: None,
                    conversation_id: work.conversation,
                    surface_id: Some(work.reference),
                    reason: ramflux_sdk::SurfaceRefusalCode::TooLarge,
                });
            }
        }
        if let Some(refusal) = rejected {
            eprintln!("agent host refused newest deferred work above its conversation share");
            self.state.deferred_surfaces = kept;
            self.state.last_refusal = Some(refusal);
            self.store.save(&self.state)?;
        }
        Ok(())
    }
}
