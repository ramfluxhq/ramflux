// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile generated Typing reception with receiver-local wall and monotonic clocks.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{Envelope, ephemeral::{self, EphemeralDropReason}};
use ramflux_protocol::message as g;
use std::{collections::BTreeMap, time::{Duration, Instant}};

const MAX_ROWS: usize = 64;
const MAX_BYTES: usize = 256 * 1024;

/// A memory-only update; it has no journal sequence or transport ACK.
#[derive(Clone, Debug)]
pub struct TypingUpdate {
    pub identity: g::EventIdentity,
    pub typing: g::Typing,
    pub expires_at_ms: u64,
}

/// Local receive result, independent of the gateway's acceptance result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypingOutcome {
    Held,
    Visible,
    Duplicate,
    Dropped(EphemeralDropReason),
}

struct Indicator {
    update: TypingUpdate,
    starts_at_ms: u64,
    hold_until: Instant,
    expires: Instant,
    visible: bool,
    bytes: usize,
}

/// One account's bounded volatile receiver. Dropping it forgets all indicators and dedupe state.
#[derive(Default)]
pub struct TypingReceiver {
    indicators: BTreeMap<(String, String, String), Indicator>,
    seen: BTreeMap<(String, String), (u64, Instant)>,
    updates: Vec<TypingUpdate>,
}

impl TypingReceiver {
    /// Accept a live frame using this receiver's clocks, never the gateway's `expires_at_ms`.
    /// # Errors
    /// Returns source/crypto/protocol errors. Invalid lifetime or saturation is a typed drop.
    pub fn receive(
        &mut self,
        client: &RamfluxClient,
        envelope: &Envelope,
        local_device: &str,
        now_ms: u64,
        monotonic: Instant,
    ) -> Result<TypingOutcome, SdkError> {
        self.poll(now_ms, monotonic);
        let deadline = match ephemeral::deadline(envelope, now_ms) {
            Ok(deadline) => deadline,
            Err(ephemeral::EphemeralModeError::Expired) => return Ok(TypingOutcome::Dropped(EphemeralDropReason::Expired)),
            Err(_) => return Ok(TypingOutcome::Dropped(EphemeralDropReason::Invalid)),
        };
        let wire_bytes = ramflux_protocol::canonical_json_bytes(envelope)?.len();
        if wire_bytes > 32_768 { return Ok(TypingOutcome::Dropped(EphemeralDropReason::Invalid)); }
        let root = envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            .ok_or_else(|| SdkError::InboundRejected("typing source root missing".into()))?;
        let source_key = (format!("{root}/{}", envelope.source_device_id), envelope.envelope_id.clone());
        if self.seen.contains_key(&source_key) { return Ok(TypingOutcome::Duplicate); }
        if self.seen.len() >= MAX_ROWS
            || self.indicators.values().map(|state| state.bytes).sum::<usize>().saturating_add(wire_bytes) > MAX_BYTES
        { return Ok(TypingOutcome::Dropped(EphemeralDropReason::QueueFull)); }
        let (identity, typing) = client.open_typing_delivery(envelope, local_device)?;
        let author = identity.author.as_ref().ok_or_else(|| SdkError::InboundRejected("typing author missing".into()))?;
        let key = (author.account_anchor.clone(), author.device_id.clone(), identity.conversation_id.clone());
        let starts = u64::try_from(envelope.created_at).ok().and_then(|value| value.checked_mul(1000))
            .ok_or_else(|| SdkError::InboundRejected("typing start overflow".into()))?;
        let expires_at_ms = typing.expires_at.checked_mul(1000)
            .ok_or_else(|| SdkError::InboundRejected("typing expiry overflow".into()))?.min(deadline);
        if now_ms >= expires_at_ms { return Ok(TypingOutcome::Dropped(EphemeralDropReason::Expired)); }
        let hold_until = monotonic.checked_add(Duration::from_secs(2))
            .ok_or_else(|| SdkError::InboundRejected("typing monotonic overflow".into()))?;
        let expires = monotonic.checked_add(Duration::from_millis(expires_at_ms - now_ms))
            .ok_or_else(|| SdkError::InboundRejected("typing monotonic overflow".into()))?;
        let visible = now_ms >= starts;
        let update = TypingUpdate { identity, typing, expires_at_ms };
        if visible { self.push_update(update.clone()); }
        self.indicators.insert(key, Indicator { update, starts_at_ms: starts, hold_until, expires, visible, bytes: wire_bytes });
        self.seen.insert(source_key, (deadline, expires));
        Ok(if visible { TypingOutcome::Visible } else { TypingOutcome::Held })
    }

    /// Advance held/displayed state. The caller supplies clocks; no sleep or durable task exists.
    pub fn poll(&mut self, now_ms: u64, monotonic: Instant) {
        self.seen.retain(|_, (deadline, until)| now_ms < *deadline && monotonic < *until);
        let mut updates = Vec::new();
        self.indicators.retain(|_, indicator| {
            let expired = now_ms >= indicator.update.expires_at_ms || monotonic >= indicator.expires;
            if expired || (!indicator.visible && monotonic >= indicator.hold_until && now_ms < indicator.starts_at_ms) {
                if indicator.visible {
                    let mut clear = indicator.update.clone();
                    clear.typing.active = false;
                    updates.push(clear);
                }
                return false;
            }
            if !indicator.visible && now_ms >= indicator.starts_at_ms {
                indicator.visible = true;
                if let Some(display_cap) = monotonic.checked_add(Duration::from_secs(5)) {
                    indicator.expires = indicator.expires.min(display_cap);
                }
                updates.push(indicator.update.clone());
            }
            true
        });
        for update in updates { self.push_update(update); }
    }

    /// Drain only volatile typed updates. No history is reconstructed on reconnect.
    pub fn drain_updates(&mut self) -> Vec<TypingUpdate> {
        std::mem::take(&mut self.updates)
    }

    fn push_update(&mut self, update: TypingUpdate) {
        if self.updates.len() == MAX_ROWS { self.updates.remove(0); }
        self.updates.push(update);
    }
}
