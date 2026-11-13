// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RAM-only call secrets, endpoint selection and authenticated transition rules.
use crate::SdkError;
use ramflux_protocol::{
    CallAction, CallControl, CallEndpoint, CallRow, VoiceAllocation, VoiceCallFailureReason,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq)]
pub(crate) struct LiveCall {
    pub row: CallRow,
    pub caller: CallEndpoint,
    pub callee: CallEndpoint,
    pub invited: Vec<CallEndpoint>,
    pub local: CallEndpoint,
    pub send_key: Zeroizing<[u8; 32]>,
    pub receive_key: Option<Zeroizing<[u8; 32]>>,
    pub allocation: Option<VoiceAllocation>,
    pub lease_offer: Option<ramflux_protocol::VoicePeerAllocation>,
    pub lease_consent: Option<ramflux_protocol::VoiceLeaseConsent>,
    pub next_lease_refresh: i64,
    pub retry_at: i64,
    pub retry_attempts: u32,
    pub release_until: u64,
    pub media_taken: bool,
    pub pending: Vec<CallControl>,
    media_loss: Option<(VoiceCallFailureReason, u64)>,
    offer_keys: BTreeMap<CallEndpoint, Zeroizing<[u8; 32]>>,
    peer_keys: BTreeMap<CallEndpoint, String>,
    next_seq: u64,
    ring_deadline: i64,
    seen: BTreeMap<CallEndpoint, u64>,
    /// Bound before the encrypted control is signed. Copied onto later controls.
    pub(crate) call_ref: Option<String>,
    pub(crate) call_start: Option<ramflux_protocol::SignedCallIntentV1>,
    pub(crate) local_generation: u64,
    pub(crate) gateway_generation: Option<String>,
    pub(crate) gateway_answered: bool,
    /// Set when an incoming invite carries `call_ref`. Media stays blocked until the
    /// gateway accepts a resolve of that reference.
    pub(crate) media_held: bool,
    #[cfg(feature = "test-support")]
    pub(crate) last_control_error: Option<String>,
}

pub(super) fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(format!("voice call: {message}"))
}
pub(super) fn decode_key(text: &str) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let bytes = Zeroizing::new(
        ramflux_protocol::decode_base64url(text).map_err(|_| invalid("invalid media key"))?,
    );
    Ok(Zeroizing::new(bytes.as_slice().try_into().map_err(|_| invalid("media key length"))?))
}
impl LiveCall {
    pub(crate) fn pin_peer(&mut self, peer: CallEndpoint, key: String) -> Result<(), SdkError> {
        if !ramflux_protocol::decode_base64url(&key).is_ok_and(|k| k.len() == 32)
            || self.peer_keys.get(&peer).is_some_and(|old| *old != key)
        {
            return Err(invalid("call device key changed; start a fresh call"));
        }
        self.peer_keys.insert(peer, key);
        Ok(())
    }
    pub(crate) fn peer_key_matches(&self, peer: &CallEndpoint, key: &str) -> bool {
        self.peer_keys.get(peer).is_some_and(|old| old == key)
    }
    pub(super) fn has_seen(&self, sender: &CallEndpoint, seq: u64) -> bool {
        self.seen.get(sender).is_some_and(|old| seq <= *old)
    }
    pub fn outgoing(
        id: String,
        conversation: String,
        local: CallEndpoint,
        invited: Vec<CallEndpoint>,
        now: i64,
    ) -> Result<Self, SdkError> {
        if invited.len() > 96 {
            return Err(invalid("too many callee devices"));
        }
        let callee = invited.first().cloned().ok_or_else(|| invalid("no callable peer device"))?;
        let key = Zeroizing::new(ramflux_crypto::random_32()?);
        let mut call = Self::new(id, conversation, (local.clone(), callee), local, key, now);
        call.invited = invited;
        for peer in call.invited.clone() {
            let key = Zeroizing::new(ramflux_crypto::random_32()?);
            let body =
                CallAction::Invite { base_key: ramflux_protocol::encode_base64url(key.as_ref()) };
            call.offer_keys.insert(peer.clone(), key);
            let mut control = call.control(body, now)?;
            control.callee = peer;
            call.pending.push(control);
        }
        Ok(call)
    }
    pub fn incoming(
        control: &CallControl,
        local: CallEndpoint,
        now: i64,
    ) -> Result<Self, SdkError> {
        let CallAction::Invite { base_key } = &control.body else {
            return Err(invalid("unknown call"));
        };
        if control.sender != control.caller
            || control.callee != local
            || control.seq == 0
            || control.created_at > now.saturating_add(60)
            || now.saturating_sub(control.created_at) >= 45
        {
            return Err(invalid("invalid or expired invite"));
        }
        let key = Zeroizing::new(ramflux_crypto::random_32()?);
        let mut call = Self::new(
            control.call_id.clone(),
            control.conversation_id.clone(),
            (control.caller.clone(), control.callee.clone()),
            local,
            key,
            control.created_at,
        );
        call.ring_deadline = now.min(control.created_at).saturating_add(45);
        call.receive_key = Some(decode_key(base_key)?);
        call.seen.insert(control.sender.clone(), control.seq);
        call.call_ref.clone_from(&control.call_ref);
        call.call_start.clone_from(&control.call_start);
        let ringing = call.control(CallAction::Ringing, now)?;
        call.pending.push(ringing);
        Ok(call)
    }
    fn new(
        id: String,
        conversation: String,
        endpoints: (CallEndpoint, CallEndpoint),
        local: CallEndpoint,
        key: Zeroizing<[u8; 32]>,
        now: i64,
    ) -> Self {
        let (origin, target) = endpoints;
        let outgoing = local == origin;
        Self {
            row: CallRow {
                call_id: id,
                conversation_id: conversation,
                peer_id: if outgoing {
                    target.principal_id.clone()
                } else {
                    origin.principal_id.clone()
                },
                direction: if outgoing { "outgoing" } else { "incoming" }.into(),
                state: if outgoing { "outgoing_ringing" } else { "incoming_ringing" }.into(),
                end_reason: None,
                failure_reason: None,
                peer_reason: None,
                seq: 1,
                created_at: now,
                answered_at: None,
                ended_at: None,
                media_generation: 0,
            },
            caller: origin,
            callee: target,
            local,
            invited: Vec::new(),
            send_key: key,
            receive_key: None,
            allocation: None,
            lease_offer: None,
            lease_consent: None,
            next_lease_refresh: 0,
            retry_at: 0,
            retry_attempts: 0,
            release_until: 0,
            media_taken: false,
            pending: Vec::new(),
            media_loss: None,
            offer_keys: BTreeMap::new(),
            peer_keys: BTreeMap::new(),
            next_seq: 1,
            ring_deadline: now.saturating_add(45),
            seen: BTreeMap::new(),
            call_ref: None,
            call_start: None,
            local_generation: 1,
            gateway_generation: None,
            gateway_answered: false,
            media_held: true,
            #[cfg(feature = "test-support")]
            last_control_error: None,
        }
    }
    pub(crate) fn bind_gateway_generation(
        &mut self,
        generation: Option<&str>,
    ) -> Result<(), SdkError> {
        if self.gateway_generation.as_deref() != generation {
            self.local_generation = self
                .local_generation
                .checked_add(1)
                .ok_or_else(|| invalid("local call generation exhausted"))?;
            self.gateway_generation = generation.map(str::to_owned);
            self.media_held = true;
        }
        Ok(())
    }

    /// Release media after the gateway accepts the owner's resolve.
    pub(crate) fn allow_media(&mut self) {
        self.apply_gateway_resolution(true);
    }

    /// Apply an authenticated decision after the caller has checked its complete context.
    pub(crate) fn apply_gateway_resolution(&mut self, media_allowed: bool) {
        self.media_held = !media_allowed;
    }
    pub fn control(&mut self, body: CallAction, now: i64) -> Result<CallControl, SdkError> {
        if self.call_ref.is_some() {
            self.media_held = true;
        }
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?;
        Ok(CallControl {
            call_start: None,
            schema: "ramflux.call.control.v1".into(),
            call_id: self.row.call_id.clone(),
            conversation_id: self.row.conversation_id.clone(),
            caller: self.caller.clone(),
            callee: self.callee.clone(),
            sender: self.local.clone(),
            seq,
            created_at: now,
            body,
            call_ref: self.call_ref.clone(),
            signature: String::new(),
        })
    }
    pub fn answer(&mut self, now: i64) -> Result<(), SdkError> {
        if self.media_held {
            return Err(invalid("call resolution missing"));
        }
        if self.local != self.callee || self.row.state != "incoming_ringing" || self.expired(now) {
            return Err(invalid("call cannot be answered"));
        }
        let answer = self.control(
            CallAction::Answer {
                base_key: ramflux_protocol::encode_base64url(self.send_key.as_ref()),
            },
            now,
        )?;
        self.pending.push(answer);
        self.set_state("connecting", now)?;
        Ok(())
    }
    pub fn apply(&mut self, c: &CallControl, now: i64) -> Result<bool, SdkError> {
        if c.call_id != self.row.call_id
            || c.conversation_id != self.row.conversation_id
            || c.caller != self.caller
            || c.sender == self.local
            || c.seq == 0
            || self.seen.get(&c.sender).is_some_and(|seq| c.seq <= *seq)
            || c.created_at > now.saturating_add(60)
        {
            return Err(invalid("control binding or replay"));
        }
        let peer = if self.local == self.caller { &c.callee } else { &self.caller };
        if &c.sender != peer
            || (self.local == self.caller && !self.invited.contains(&c.callee))
            || (self.local != self.caller && c.callee != self.local)
        {
            return Err(invalid("control endpoint not invited"));
        }
        if self.row.state == "ended" {
            return Err(invalid("call already ended"));
        }
        self.seen.insert(c.sender.clone(), c.seq);
        match &c.body {
            CallAction::Ringing if self.row.state == "outgoing_ringing" => {}
            CallAction::Answer { base_key } if self.local == self.caller => {
                if self.expired(now) {
                    self.expire(now)?;
                    return Ok(false);
                }
                if self.row.state != "outgoing_ringing" {
                    if c.callee == self.callee {
                        return Err(invalid("answer cannot replace an active key"));
                    }
                    // The first answer already queued an authenticated terminal notice for siblings.
                    return Ok(false);
                }
                self.receive_key = Some(decode_key(base_key)?);
                self.send_key = self
                    .offer_keys
                    .remove(&c.callee)
                    .ok_or_else(|| invalid("answer has no fresh offer key"))?;
                self.offer_keys.clear();
                self.callee = c.callee.clone();
                self.set_state("connecting", now)?;
                for loser in self
                    .invited
                    .clone()
                    .into_iter()
                    .filter(|peer| peer != &self.callee)
                    .collect::<Vec<_>>()
                {
                    let mut other = self.control(CallAction::AnsweredElsewhere, now)?;
                    other.callee = loser;
                    self.pending.push(other);
                }
                return Ok(true);
            }
            CallAction::Ack { allocation }
                if self.local == self.callee
                    && matches!(self.row.state.as_str(), "connecting" | "active") =>
            {
                self.acknowledge_offer(allocation, now)?;
            }
            CallAction::Ready { consent }
                if self.local == self.caller && self.row.state == "active" =>
            {
                self.remember_consent(consent)?;
            }
            CallAction::AnsweredElsewhere if self.local == self.callee => {
                self.finish("answered_elsewhere", now)?;
            }
            CallAction::Reject | CallAction::Busy if self.row.state == "outgoing_ringing" => {
                // One device refusing does not suppress another ringing sibling.
                self.invited.retain(|peer| peer != &c.callee);
                if self.invited.is_empty() {
                    self.finish(
                        if matches!(c.body, CallAction::Busy) { "busy" } else { "declined" },
                        now,
                    )?;
                }
            }
            CallAction::Failed => {
                self.finish_peer_failure(VoiceCallFailureReason::SignalingUnavailable, now)?;
            }
            CallAction::Hangup | CallAction::Timeout => {
                if self.local == self.caller && c.callee != self.callee {
                    return Ok(false);
                }
                let reason = if matches!(c.body, CallAction::Timeout) {
                    if self.local == self.caller { "timeout" } else { "missed" }
                } else if self.row.answered_at.is_some() {
                    "completed"
                } else if self.local == self.callee {
                    "missed"
                } else {
                    "declined"
                };
                self.finish(reason, now)?;
            }
            _ => return Err(invalid("control invalid for current state")),
        }
        Ok(false)
    }
    pub fn end(&mut self, reject: bool, now: i64) -> Result<(), SdkError> {
        if self.row.state == "ended" {
            return Ok(());
        }
        if reject && (self.local != self.callee || self.row.state != "incoming_ringing") {
            return Err(invalid("only a ringing callee can reject a call"));
        }
        self.pending.clear();
        self.retry_at = 0;
        self.retry_attempts = 0;
        let action = if reject { CallAction::Reject } else { CallAction::Hangup };
        if self.local == self.caller && self.row.state == "outgoing_ringing" {
            for target in self.invited.clone() {
                let mut control = self.control(action.clone(), now)?;
                control.callee = target;
                self.pending.push(control);
            }
        } else {
            let control = self.control(action, now)?;
            self.pending.push(control);
        }
        self.finish(
            if reject {
                "declined"
            } else if self.row.answered_at.is_some() {
                "completed"
            } else if self.local == self.caller {
                "cancelled"
            } else {
                "missed"
            },
            now,
        )
    }
    pub fn busy(&mut self, now: i64) -> Result<(), SdkError> {
        if self.local != self.callee || self.row.state != "incoming_ringing" {
            return Err(invalid("busy outside incoming call"));
        }
        self.pending.clear();
        let control = self.control(CallAction::Busy, now)?;
        self.pending.push(control);
        self.finish("busy", now)
    }
    pub fn expire(&mut self, now: i64) -> Result<bool, SdkError> {
        if !self.expired(now) {
            return Ok(false);
        }
        self.end(false, now)?;
        for control in &mut self.pending {
            control.body = CallAction::Timeout;
        }
        self.row.end_reason =
            Some(if self.local == self.caller { "timeout" } else { "missed" }.into());
        Ok(true)
    }
    pub fn fail(&mut self, reason: VoiceCallFailureReason, now: i64) -> Result<(), SdkError> {
        if self.row.state == "ended" {
            return Ok(());
        }
        self.end(false, now)?;
        for control in &mut self.pending {
            control.body = CallAction::Failed;
        }
        self.row.end_reason = Some("failed".into());
        self.row.failure_reason = Some(reason);
        self.row.peer_reason = None;
        Ok(())
    }
    pub fn expire_media(&mut self, now: i64) -> Result<bool, SdkError> {
        if let Some((reason, deadline)) = self.media_loss {
            if now.unsigned_abs() >= deadline {
                self.fail(reason, now)?;
                return Ok(true);
            }
            return Ok(false);
        }
        if self.row.state == "active"
            && self.allocation.as_ref().is_some_and(|a| a.expires_at <= now.unsigned_abs())
        {
            self.fail(VoiceCallFailureReason::MediaLeaseExpired, now)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(crate) fn lease_refused(
        &mut self,
        reason: VoiceCallFailureReason,
        now: i64,
    ) -> Result<(), SdkError> {
        if self.row.state == "active" && reason == VoiceCallFailureReason::RelayUnavailable {
            if self.media_loss.is_none() {
                let deadline =
                    self.allocation.as_ref().map_or(now.unsigned_abs(), |a| a.expires_at);
                self.media_loss = Some((reason, deadline));
                self.allocation = None;
                self.send_key = Zeroizing::new([0; 32]);
                self.receive_key = None;
                self.lease_offer = None;
                self.lease_consent = None;
                self.next_lease_refresh = i64::MAX;
            }
            self.expire_media(now)?;
            Ok(())
        } else {
            self.fail(reason, now)
        }
    }
    pub(crate) fn media_lost(&self) -> bool {
        self.media_loss.is_some()
    }
    pub(crate) fn expired(&self, now: i64) -> bool {
        matches!(self.row.state.as_str(), "outgoing_ringing" | "incoming_ringing" | "connecting")
            && self.row.answered_at.is_none()
            && !self.gateway_answered
            && now >= self.ring_deadline
    }
    pub(super) fn set_state(&mut self, state: &str, now: i64) -> Result<(), SdkError> {
        self.row.seq =
            self.row.seq.checked_add(1).ok_or_else(|| invalid("row sequence exhausted"))?;
        self.row.state = state.into();
        if state == "active" {
            self.row.answered_at = Some(now);
        }
        Ok(())
    }
    pub fn finish(&mut self, reason: &str, now: i64) -> Result<(), SdkError> {
        self.local_generation = self
            .local_generation
            .checked_add(1)
            .ok_or_else(|| invalid("local call generation exhausted"))?;
        self.media_held = true;
        self.set_state("ended", now)?;
        self.row.end_reason = Some(reason.into());
        self.row.failure_reason = None;
        self.row.peer_reason = None;
        self.row.ended_at = Some(now);
        self.pending.retain(|c| {
            matches!(
                c.body,
                CallAction::Reject
                    | CallAction::Busy
                    | CallAction::Hangup
                    | CallAction::Timeout
                    | CallAction::Failed
                    | CallAction::AnsweredElsewhere
            )
        });
        self.next_lease_refresh = 0;
        self.offer_keys.clear();
        self.send_key = Zeroizing::new([0; 32]);
        self.receive_key = None;
        self.release_until = self.allocation.as_ref().map_or(0, |a| a.expires_at);
        self.allocation = None;
        self.lease_offer = None;
        self.lease_consent = None;
        self.media_loss = None;
        Ok(())
    }
    fn finish_peer_failure(
        &mut self,
        reason: VoiceCallFailureReason,
        now: i64,
    ) -> Result<(), SdkError> {
        self.finish("failed", now)?;
        self.row.peer_reason = Some(reason);
        Ok(())
    }
}

#[cfg(test)]
mod resolution_gate {
    use super::LiveCall;

    fn endpoint(id: &str) -> ramflux_protocol::CallEndpoint {
        ramflux_protocol::CallEndpoint {
            principal_id: id.to_owned(),
            root_public_key: "key".to_owned(),
            device_id: id.to_owned(),
        }
    }

    fn invite(call_ref: Option<String>, now: i64) -> ramflux_protocol::CallControl {
        let caller = endpoint("caller");
        ramflux_protocol::CallControl {
            call_start: None,
            schema: "ramflux.call.control.v1".into(),
            call_id: "call-1".into(),
            conversation_id: "conv-1".into(),
            caller: caller.clone(),
            callee: endpoint("callee"),
            sender: caller,
            seq: 1,
            created_at: now,
            body: ramflux_protocol::CallAction::Invite {
                base_key: ramflux_protocol::encode_base64url([7_u8; 32]),
            },
            call_ref,
            signature: String::new(),
        }
    }

    #[test]
    fn incoming_calls_hold_media_with_or_without_a_reference_until_resolution()
    -> Result<(), crate::SdkError> {
        let now = 1_700_000_000;
        let plain = LiveCall::incoming(&invite(None, now), endpoint("callee"), now)?;
        assert!(plain.media_held, "a missing reference cannot grant media authority");
        let mut held =
            LiveCall::incoming(&invite(Some("ref".to_owned()), now), endpoint("callee"), now)?;
        assert!(held.media_held, "a reference alone cannot grant media authority");
        assert_eq!(
            held.pending.first().and_then(|control| control.call_ref.as_deref()),
            Some("ref")
        );
        assert!(held.answer(now).is_err());
        held.apply_gateway_resolution(false);
        assert!(held.answer(now).is_err());
        held.allow_media();
        held.answer(now)?;
        assert!(held.media_held, "a new answer control requires a new correlated decision");
        let answer = held.pending.last().ok_or_else(|| super::invalid("answer missing"))?;
        assert_eq!(super::super::resolution_terminal(answer).as_deref(), Some("answer"));
        let mut covered = invite(Some("ref".to_owned()), now);
        let with_ref = super::super::signing_bytes(&covered)?;
        covered.call_ref = None;
        let without_ref = super::super::signing_bytes(&covered)?;
        assert_ne!(with_ref.as_slice(), without_ref.as_slice());
        Ok(())
    }
}
