// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Periodic durable queue selection, outside the socket-frame path.
use super::{Call, PrxBridgeEngine};
impl PrxBridgeEngine {
    pub(super) fn queue(&mut self, tag: String) {
        if self.send_queue.len() < 256 && self.scheduled.insert(tag.clone()) {
            self.send_queue.push_back(tag);
        }
    }
    pub(super) fn queued_call(&mut self, tag: &str) -> Option<Call> {
        if let Some(id) = tag.strip_prefix("in:") {
            let input = self.state.inbound.get(id)?;
            let turn = self.state.turns.get(id)?;
            if self.active.get(&turn.conversation).map(String::as_str) != Some(id) {
                return None;
            }
            return Some(Call { method: "inbound.message".into(), params: input.params.clone() });
        }
        if let Some(key) = tag.strip_prefix("erase:") {
            let erase = self.state.erases.get(key)?;
            if erase.wait_hello
                || erase.wait_input.as_ref().is_some_and(|t| self.inflight.contains_key(t))
            {
                return None;
            }
            return Some(Call {
                method: "inbound.message_deleted".into(),
                params: erase.params.clone(),
            });
        }
        self.state.controls.get(tag).or_else(|| self.state.decisions.get(tag)).cloned()
    }
    pub(super) fn schedule(&mut self, now: u64) {
        let stale = self
            .state
            .inbound
            .iter()
            .filter(|(id, i)| {
                now >= i.queued_at.saturating_add(600_000)
                    && self.state.turns.get(*id).is_none_or(|t| t.submitted_at.is_none())
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in stale {
            self.state.inbound.remove(&id);
            if let Some(turn) = self.state.turns.remove(&id)
                && self.active.get(&turn.conversation) == Some(&id)
            {
                self.active.remove(&turn.conversation);
            }
            self.count(&["inbound_dropped_stale"]);
            eprintln!("agent host bridge dropped stale inbound");
        }
        if !self.connected {
            return;
        }
        let controls = self
            .state
            .controls
            .keys()
            .chain(self.state.decisions.keys())
            .cloned()
            .collect::<Vec<_>>();
        for tag in controls {
            self.queue(tag);
        }
        let erases = self
            .state
            .erases
            .iter()
            .filter(|(_, e)| !e.wait_hello && now >= e.next_at)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        for key in erases {
            self.queue(format!("erase:{key}"));
        }
        if self.state.erases.len() >= 1024 {
            return;
        }
        let mut queued = self.state.inbound.values().cloned().collect::<Vec<_>>();
        queued.sort_by_key(|i| (i.order, i.turn_id.clone()));
        for input in queued {
            let Some(turn) = self.state.turns.get_mut(&input.turn_id) else {
                continue;
            };
            // An erase barrier prevents a later turn from recalling rows awaiting erasure.
            if self.state.erases.values().any(|e| e.params["conversation_id"] == turn.conversation)
            {
                continue;
            }
            if !self.active.contains_key(&turn.conversation) && self.active.len() < self.maximum {
                turn.submitted_at = Some(now);
                self.active.insert(turn.conversation.clone(), input.turn_id.clone());
            }
            if self.active.get(&turn.conversation) == Some(&input.turn_id) {
                let resent = turn.was_sent;
                let tag = format!("in:{}", input.turn_id);
                if !self.inflight.contains_key(&tag) && !self.scheduled.contains(&tag) {
                    self.count(&[if resent { "inbound_resent" } else { "inbound_sent" }]);
                    if let Some(turn) = self.state.turns.get_mut(&input.turn_id) {
                        turn.was_sent = true;
                    }
                    self.queue(tag);
                }
            }
        }
    }
}
