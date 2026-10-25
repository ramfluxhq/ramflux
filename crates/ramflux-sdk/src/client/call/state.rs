// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RAM-only call secrets, endpoint selection and authenticated transition rules.
use crate::SdkError;
use ramflux_protocol::{CallAction, CallControl, CallEndpoint, CallRow, VoiceAllocation};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct LiveCall {
    pub row: CallRow,
    pub caller: CallEndpoint,
    pub callee: CallEndpoint,
    pub invited: Vec<CallEndpoint>,
    pub local: CallEndpoint,
    pub send_key: Zeroizing<[u8; 32]>,
    pub receive_key: Option<Zeroizing<[u8; 32]>>,
    pub allocation: Option<VoiceAllocation>,
    pub next_lease_refresh: i64,
    pub media_taken: bool,
    pub media_leased: bool,
    pub media_counter: u64,
    pub pending: Vec<CallControl>,
    offer_keys: BTreeMap<CallEndpoint, Zeroizing<[u8; 32]>>,
    next_seq: u64,
    seen: BTreeMap<CallEndpoint, u64>,
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
            || now.saturating_sub(control.created_at) > 45
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
        call.receive_key = Some(decode_key(base_key)?);
        call.seen.insert(control.sender.clone(), control.seq);
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
            next_lease_refresh: 0,
            media_taken: false,
            media_leased: false,
            media_counter: 0,
            pending: Vec::new(),
            offer_keys: BTreeMap::new(),
            next_seq: 1,
            seen: BTreeMap::new(),
        }
    }
    pub fn control(&mut self, body: CallAction, now: i64) -> Result<CallControl, SdkError> {
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?;
        Ok(CallControl {
            schema: "ramflux.call.control.v1".into(),
            call_id: self.row.call_id.clone(),
            conversation_id: self.row.conversation_id.clone(),
            caller: self.caller.clone(),
            callee: self.callee.clone(),
            sender: self.local.clone(),
            seq,
            created_at: now,
            body,
            signature: String::new(),
        })
    }
    pub fn answer(&mut self, now: i64) -> Result<(), SdkError> {
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
                if self.row.state != "outgoing_ringing" || self.expired(now) {
                    let mut other = self.control(CallAction::AnsweredElsewhere, now)?;
                    other.callee = c.callee.clone();
                    self.pending.push(other);
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
                if self.local == self.callee && self.row.state == "connecting" =>
            {
                self.allocation = Some(allocation.as_ref().clone());
                self.set_state("active", now)?;
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
            CallAction::Hangup | CallAction::Timeout => {
                if self.local == self.caller && c.callee != self.callee {
                    return Ok(false);
                }
                let reason = if self.row.answered_at.is_some() {
                    "completed"
                } else if self.local == self.callee {
                    "missed"
                } else {
                    "cancelled"
                };
                self.finish(reason, now)?;
            }
            _ => return Err(invalid("control invalid for current state")),
        }
        Ok(false)
    }
    pub fn activate(&mut self, allocation: VoiceAllocation, now: i64) -> Result<(), SdkError> {
        if self.local != self.caller || self.row.state != "connecting" {
            return Err(invalid("allocation outside connecting caller"));
        }
        let ack =
            self.control(CallAction::Ack { allocation: Box::new(allocation.clone()) }, now)?;
        self.allocation = Some(allocation);
        self.next_lease_refresh = now.saturating_add(20);
        self.pending.push(ack);
        self.set_state("active", now)
    }
    pub fn end(&mut self, reject: bool, now: i64) -> Result<(), SdkError> {
        if self.row.state == "ended" {
            return Ok(());
        }
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
    pub fn expire(&mut self, now: i64) -> Result<bool, SdkError> {
        if !self.expired(now) {
            return Ok(false);
        }
        self.end(false, now)?;
        self.row.end_reason =
            Some(if self.local == self.caller { "timeout" } else { "missed" }.into());
        Ok(true)
    }
    fn expired(&self, now: i64) -> bool {
        matches!(self.row.state.as_str(), "outgoing_ringing" | "incoming_ringing" | "connecting")
            && self.row.answered_at.is_none()
            && now.saturating_sub(self.row.created_at) >= 45
    }
    fn set_state(&mut self, state: &str, now: i64) -> Result<(), SdkError> {
        self.row.seq =
            self.row.seq.checked_add(1).ok_or_else(|| invalid("row sequence exhausted"))?;
        self.row.state = state.into();
        if state == "active" {
            self.row.answered_at = Some(now);
        }
        Ok(())
    }
    pub fn finish(&mut self, reason: &str, now: i64) -> Result<(), SdkError> {
        self.set_state("ended", now)?;
        self.row.end_reason = Some(reason.into());
        self.row.ended_at = Some(now);
        self.send_key = Zeroizing::new([0; 32]);
        self.receive_key = None;
        self.allocation = None;
        Ok(())
    }
}
