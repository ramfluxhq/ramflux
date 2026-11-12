// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile generated Typing reception with receiver-local wall and monotonic clocks.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use ramflux_protocol::{
    Envelope,
    ephemeral::{self, EphemeralDropReason},
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

mod rate;

const MAX_ROWS: usize = 64;
const MAX_DEDUP: usize = 256;
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
    RetainedUnsupported,
    Dropped(EphemeralDropReason),
}

#[derive(Clone, Copy)]
struct Admission {
    deadline: u64,
    wire_bytes: usize,
    now_ms: u64,
    monotonic: Instant,
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
    seen: BTreeMap<(String, String), (u64, Instant, String)>,
    pending_clears: BTreeMap<(String, String, String), Indicator>,
    newest: BTreeMap<(String, String, String), (i64, Instant)>,
    updates: Vec<TypingUpdate>,
    rates: rate::ReceiverRates,
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
            Err(ephemeral::EphemeralModeError::Expired) => {
                return Ok(TypingOutcome::Dropped(EphemeralDropReason::Expired));
            }
            Err(_) => return Ok(TypingOutcome::Dropped(EphemeralDropReason::Invalid)),
        };
        let wire_bytes = ramflux_protocol::canonical_json_bytes(envelope)?.len();
        if wire_bytes > 32_768 {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::Invalid));
        }
        let entry = crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 0,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope: envelope.clone(),
        };
        client.authenticated_envelope_sender(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            &entry,
        )?;
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SdkError::InboundRejected("typing source root missing".into()))?;
        let source_key =
            (format!("{root}/{}", envelope.source_device_id), envelope.envelope_id.clone());
        if let Some((_, _, hash)) = self.seen.get(&source_key) {
            return Ok(if hash == &envelope.payload_hash {
                TypingOutcome::Duplicate
            } else {
                TypingOutcome::Dropped(EphemeralDropReason::Invalid)
            });
        }
        if self.seen.len() >= MAX_DEDUP
            || self
                .indicators
                .values()
                .chain(self.pending_clears.values())
                .map(|state| state.bytes)
                .sum::<usize>()
                .saturating_add(wire_bytes)
                > MAX_BYTES
        {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::QueueFull));
        }
        let Some(conversation) = client.typing_conversation_before_decrypt(envelope)? else {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::Invalid));
        };
        if !self.rates.admit(root, &conversation, monotonic) {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::RateLimited));
        }
        match client.open_ephemeral_delivery(envelope, local_device)? {
            crate::client::routed::EphemeralContent::Typing(identity, typing) => self.install(
                envelope,
                (identity, typing),
                Admission { deadline, wire_bytes, now_ms, monotonic },
            ),
            other => {
                let until = monotonic
                    .checked_add(Duration::from_millis(deadline.saturating_sub(now_ms)))
                    .ok_or_else(|| {
                        SdkError::InboundRejected("ephemeral dedupe deadline overflow".into())
                    })?;
                self.seen.insert(source_key, (deadline, until, envelope.payload_hash.clone()));
                Ok(match other {
                    crate::client::routed::EphemeralContent::Unsupported => {
                        TypingOutcome::RetainedUnsupported
                    }
                    _ => TypingOutcome::Dropped(EphemeralDropReason::Invalid),
                })
            }
        }
    }

    fn install(
        &mut self,
        envelope: &Envelope,
        (identity, typing): (g::EventIdentity, g::Typing),
        admission: Admission,
    ) -> Result<TypingOutcome, SdkError> {
        let Admission { deadline, wire_bytes, now_ms, monotonic } = admission;
        let author = identity
            .author
            .as_ref()
            .ok_or_else(|| SdkError::InboundRejected("typing author missing".into()))?;
        let source_key = (
            format!("{}/{}", author.account_anchor, author.device_id),
            envelope.envelope_id.clone(),
        );
        let key = (
            author.account_anchor.clone(),
            author.device_id.clone(),
            identity.conversation_id.clone(),
        );
        if self.newest.get(&key).is_some_and(|(created, _)| {
            (typing.active && envelope.created_at <= *created)
                || (!typing.active && envelope.created_at < *created)
        }) {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::Invalid));
        }
        let starts = u64::try_from(envelope.created_at)
            .ok()
            .and_then(|value| value.checked_mul(1000))
            .ok_or_else(|| SdkError::InboundRejected("typing start overflow".into()))?;
        let future_clear = !typing.active && now_ms < starts;
        let allocates = if future_clear {
            !self.pending_clears.contains_key(&key)
        } else {
            !self.indicators.contains_key(&key)
        };
        if allocates && self.indicators.len() + self.pending_clears.len() >= MAX_ROWS {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::QueueFull));
        }
        let expires_at_ms = typing
            .expires_at
            .checked_mul(1000)
            .ok_or_else(|| SdkError::InboundRejected("typing expiry overflow".into()))?
            .min(deadline);
        if now_ms >= expires_at_ms {
            return Ok(TypingOutcome::Dropped(EphemeralDropReason::Expired));
        }
        let hold_until = monotonic
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| SdkError::InboundRejected("typing monotonic overflow".into()))?;
        let expires = monotonic
            .checked_add(Duration::from_millis(expires_at_ms - now_ms))
            .ok_or_else(|| SdkError::InboundRejected("typing monotonic overflow".into()))?;
        let supersede_until = monotonic
            .checked_add(Duration::from_millis(starts.saturating_add(5000).saturating_sub(now_ms)))
            .ok_or_else(|| {
                SdkError::InboundRejected("typing supersede deadline overflow".into())
            })?;
        if future_clear {
            self.seen.insert(source_key, (deadline, expires, envelope.payload_hash.clone()));
            self.pending_clears.insert(
                key,
                Indicator {
                    update: TypingUpdate { identity, typing, expires_at_ms },
                    starts_at_ms: starts,
                    hold_until,
                    expires,
                    visible: false,
                    bytes: wire_bytes,
                },
            );
            return Ok(TypingOutcome::Held);
        }
        self.pending_clears.remove(&key);
        self.newest.insert(key.clone(), (envelope.created_at, supersede_until));
        self.seen.insert(source_key, (deadline, expires, envelope.payload_hash.clone()));
        let visible = now_ms >= starts;
        let update = TypingUpdate { identity, typing, expires_at_ms };
        if !update.typing.active {
            self.indicators.remove(&key);
            self.push_update(update);
            return Ok(TypingOutcome::Visible);
        }
        if visible {
            self.push_update(update.clone());
        }
        self.indicators.insert(
            key,
            Indicator {
                update,
                starts_at_ms: starts,
                hold_until,
                expires,
                visible,
                bytes: wire_bytes,
            },
        );
        Ok(if visible { TypingOutcome::Visible } else { TypingOutcome::Held })
    }

    /// Advance held/displayed state. The caller supplies clocks; no sleep or durable task exists.
    pub fn poll(&mut self, now_ms: u64, monotonic: Instant) {
        self.seen.retain(|_, (deadline, until, _)| now_ms < *deadline && monotonic < *until);
        self.newest.retain(|_, (_, until)| monotonic < *until);
        let mut updates = Vec::new();
        let mut clears = Vec::new();
        self.pending_clears.retain(|key, pending| {
            if now_ms >= pending.update.expires_at_ms
                || monotonic >= pending.expires
                || (now_ms < pending.starts_at_ms && monotonic >= pending.hold_until)
            {
                return false;
            }
            if now_ms >= pending.starts_at_ms {
                clears.push((key.clone(), pending.update.clone(), pending.starts_at_ms));
                return false;
            }
            true
        });
        for (key, update, starts) in clears {
            let created = i64::try_from(starts / 1000).unwrap_or(i64::MAX);
            if self.newest.get(&key).is_none_or(|(newest, _)| created >= *newest) {
                self.indicators.remove(&key);
                if let Some(until) = monotonic.checked_add(Duration::from_secs(5)) {
                    self.newest.insert(key, (created, until));
                }
                updates.push(update);
            }
        }
        self.indicators.retain(|_, indicator| {
            let expired =
                now_ms >= indicator.update.expires_at_ms || monotonic >= indicator.expires;
            if expired
                || (!indicator.visible
                    && monotonic >= indicator.hold_until
                    && now_ms < indicator.starts_at_ms)
            {
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
        for update in updates {
            self.push_update(update);
        }
    }

    /// Clear this author's indicators when its durable Message is projected.
    pub fn clear_author(&mut self, root: &str, conversation: &str) {
        self.pending_clears.retain(|(author, _, scope), _| author != root || scope != conversation);
        let keys: Vec<_> = self
            .indicators
            .keys()
            .filter(|(author, _, scope)| author == root && scope == conversation)
            .cloned()
            .collect();
        for key in keys {
            if let Some(indicator) = self.indicators.remove(&key) {
                let mut update = indicator.update;
                update.typing.active = false;
                self.push_update(update);
            }
        }
    }

    /// Drain only volatile typed updates. No history is reconstructed on reconnect.
    pub fn drain_updates(&mut self) -> Vec<TypingUpdate> {
        std::mem::take(&mut self.updates)
    }

    fn push_update(&mut self, update: TypingUpdate) {
        if self.updates.len() == MAX_ROWS {
            self.updates.remove(0);
        }
        self.updates.push(update);
    }
}
