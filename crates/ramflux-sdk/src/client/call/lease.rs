// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public lease offers and participant-private credentials never share a peer control message.
use super::state::{LiveCall, invalid};
use crate::SdkError;
use ramflux_protocol::{
    CallAction, VoiceAllocation, VoiceAllocationRequest, VoiceLeaseConsent, VoicePeerAllocation,
};
impl LiveCall {
    pub(crate) fn lease_scope(&self) -> VoiceAllocationRequest {
        VoiceAllocationRequest {
            call_id: self.row.call_id.clone(),
            caller: self.caller.clone(),
            callee: self.callee.clone(),
        }
    }
    pub(super) fn acknowledge_offer(
        &mut self,
        offer: &VoicePeerAllocation,
        now: i64,
    ) -> Result<(), SdkError> {
        if offer.expires_at <= now.unsigned_abs()
            || offer.expires_at > now.unsigned_abs().saturating_add(120)
            || offer.hard_expires_at < offer.expires_at
            || offer.hard_expires_at > now.unsigned_abs().saturating_add(4 * 60 * 60)
            || offer.endpoint.is_empty()
            || !ramflux_protocol::decode_base64url(&offer.lease_id).is_ok_and(|id| id.len() == 16)
        {
            return Err(invalid("invalid relay offer"));
        }
        if self.lease_offer.as_ref().is_some_and(|old| {
            old.lease_id != offer.lease_id
                || old.endpoint != offer.endpoint
                || old.hard_expires_at != offer.hard_expires_at
                || old.expires_at > offer.expires_at
        }) {
            return Err(invalid("relay offer changed"));
        }
        if self.allocation.as_ref().is_none_or(|a| a.expires_at < offer.expires_at) {
            self.next_lease_refresh = now;
        }
        self.lease_offer = Some(offer.clone());
        Ok(())
    }
    fn validate_private(
        &self,
        allocation: &VoiceAllocation,
        side: u8,
        now: i64,
    ) -> Result<(), SdkError> {
        if allocation.side != side
            || allocation.expires_at <= now.unsigned_abs()
            || allocation.expires_at > now.unsigned_abs().saturating_add(120)
            || allocation.hard_expires_at < allocation.expires_at
            || allocation.hard_expires_at > now.unsigned_abs().saturating_add(4 * 60 * 60)
            || allocation.endpoint.is_empty()
            || !ramflux_protocol::decode_base64url(&allocation.lease_id)
                .is_ok_and(|id| id.len() == 16)
            || [&allocation.token, &allocation.rebind_key].into_iter().any(|key| {
                !ramflux_protocol::decode_base64url(key).is_ok_and(|bytes| bytes.len() == 32)
            })
        {
            return Err(invalid("invalid private relay allocation"));
        }
        if self.allocation.as_ref().is_some_and(|old| {
            old.lease_id != allocation.lease_id
                || old.token != allocation.token
                || old.rebind_key != allocation.rebind_key
                || old.endpoint != allocation.endpoint
                || old.hard_expires_at != allocation.hard_expires_at
                || old.expires_at > allocation.expires_at
        }) {
            return Err(invalid("private relay allocation changed"));
        }
        Ok(())
    }
    pub(crate) fn activate(
        &mut self,
        allocation: VoiceAllocation,
        now: i64,
    ) -> Result<(), SdkError> {
        if self.local != self.caller || self.row.state != "connecting" {
            return Err(invalid("allocation outside connecting caller"));
        }
        self.validate_private(&allocation, 0, now)?;
        let offer = allocation.for_callee();
        let ack = self.control(CallAction::Ack { allocation: Box::new(offer.clone()) }, now)?;
        self.lease_offer = Some(offer);
        self.allocation = Some(allocation);
        self.pending.push(ack);
        self.next_lease_refresh = now.saturating_add(20);
        self.set_state("active", now)
    }
    pub(crate) fn accept_lease(
        &mut self,
        allocation: VoiceAllocation,
        consent: VoiceLeaseConsent,
        now: i64,
    ) -> Result<(), SdkError> {
        if self.local != self.callee || !matches!(self.row.state.as_str(), "connecting" | "active")
        {
            return Err(invalid("allocation outside consenting callee"));
        }
        self.validate_private(&allocation, 1, now)?;
        let offer = self.lease_offer.as_ref().ok_or_else(|| invalid("relay offer absent"))?;
        if offer.lease_id != allocation.lease_id
            || offer.endpoint != allocation.endpoint
            || offer.hard_expires_at != allocation.hard_expires_at
            || consent.scope != self.lease_scope()
            || consent.lease_id != offer.lease_id
            || consent.expires_at != offer.hard_expires_at
        {
            return Err(invalid("callee consent scope mismatch"));
        }
        if self.lease_consent.is_none() {
            let ready =
                self.control(CallAction::Ready { consent: Box::new(consent.clone()) }, now)?;
            self.pending.push(ready);
        }
        self.lease_consent = Some(consent);
        self.allocation = Some(allocation);
        self.next_lease_refresh = now.saturating_add(20);
        if self.row.state == "connecting" {
            self.set_state("active", now)?;
        }
        Ok(())
    }
    pub(super) fn remember_consent(&mut self, consent: &VoiceLeaseConsent) -> Result<(), SdkError> {
        let allocation = self.allocation.as_ref().ok_or_else(|| invalid("lease absent"))?;
        if consent.scope != self.lease_scope()
            || consent.lease_id != allocation.lease_id
            || consent.expires_at != allocation.hard_expires_at
        {
            return Err(invalid("peer consent scope mismatch"));
        }
        if self.lease_consent.as_ref().is_some_and(|old| old != consent) {
            return Err(invalid("peer consent changed"));
        }
        self.lease_consent = Some(consent.clone());
        Ok(())
    }
}
