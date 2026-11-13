// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lease response effects shared by background and direct call drivers.
use super::invalid;
use crate::{SdkError, client::call::state::LiveCall};
use ramflux_protocol::{CallAction, VoiceCallFailureReason, VoiceLeaseConsent, VoiceLeaseResponse};
pub(crate) fn apply_result(
    next: &mut LiveCall,
    result: Result<VoiceLeaseResponse, SdkError>,
    consent: Option<VoiceLeaseConsent>,
    now: i64,
) -> Result<(), SdkError> {
    // Retry scheduling never changes ring, media or consent deadlines. The regular
    // expiry pass remains authoritative, including while admission stays saturated.
    if result.as_ref().is_err_and(SdkError::gateway_writer_busy) {
        next.next_lease_refresh = now.saturating_add(1);
        return Ok(());
    }
    match result {
        Ok(VoiceLeaseResponse::Allocation { allocation }) if next.local == next.callee => {
            next.accept_lease(
                allocation,
                consent.ok_or_else(|| invalid("callee lease consent absent"))?,
                now,
            )?;
        }
        Ok(VoiceLeaseResponse::Allocation { allocation }) if next.row.state == "connecting" => {
            next.activate(allocation, now)?;
        }
        Ok(VoiceLeaseResponse::Status { status })
            if next.row.state == "active" && next.local == next.caller =>
        {
            if let Some(allocation) = next.allocation.as_mut() {
                allocation.expires_at = status.expires_at;
            }
            let allocation = next
                .allocation
                .as_ref()
                .ok_or_else(|| invalid("renewed lease missing"))?
                .for_callee();
            let ack = next.control(CallAction::Ack { allocation: Box::new(allocation) }, now)?;
            next.pending.push(ack);
            next.next_lease_refresh = now.saturating_add(20);
        }
        Ok(VoiceLeaseResponse::Refused { reason }) => next.lease_refused(reason, now)?,
        _ if next.row.state == "active" && next.local == next.caller => {
            next.next_lease_refresh = now.saturating_add(5);
        }
        _ => next.fail(VoiceCallFailureReason::SignalingUnavailable, now)?,
    }
    Ok(())
}

// This fixture observes the same decoder and transition function as the live drivers;
// callers supply actual wire replies, never synthesized admission success.
#[cfg(feature = "test-support")]
pub struct VoiceAdmissionProbe(LiveCall);
#[cfg(feature = "test-support")]
impl VoiceAdmissionProbe {
    /// Constructs a connecting caller/callee or an active caller with a bounded lease.
    /// # Errors
    /// Returns malformed call-control or allocation errors.
    pub fn new(
        scope: ramflux_protocol::VoiceAllocationRequest,
        active: bool,
        callee: bool,
        now: i64,
    ) -> Result<Self, SdkError> {
        let mut origin = LiveCall::outgoing(
            scope.call_id,
            "admission-probe".into(),
            scope.caller,
            vec![scope.callee.clone()],
            now,
        )?;
        let mut recipient = LiveCall::incoming(&origin.pending[0], scope.callee, now)?;
        recipient.answer(now)?;
        let answer = recipient.pending.last().ok_or_else(|| invalid("probe answer absent"))?;
        origin.apply(answer, now)?;
        let mut call = if callee { recipient } else { origin };
        if active {
            call.activate(
                ramflux_protocol::VoiceAllocation {
                    endpoint: "relay.example:17449".into(),
                    lease_id: ramflux_protocol::encode_base64url([8; 16]),
                    side: 0,
                    token: ramflux_protocol::encode_base64url([9; 32]),
                    rebind_key: ramflux_protocol::encode_base64url([10; 32]),
                    expires_at: now.unsigned_abs() + 60,
                    hard_expires_at: now.unsigned_abs() + 300,
                },
                now,
            )?;
        }
        call.pending.clear();
        Ok(Self(call))
    }
    /// Applies a wire response through the production decoder and shared driver transition.
    /// # Errors
    /// Returns invalid call transition errors.
    pub fn apply(&mut self, frame: &[u8], now: i64) -> Result<(), SdkError> {
        apply_result(
            &mut self.0,
            crate::gateway::engine::decode_voice_reply(ramflux_protocol::parse_i_json(frame)?),
            None,
            now,
        )
    }
    /// Public row, allocation, pending controls and deadlines for regression assertions.
    /// # Errors
    /// Returns serialization errors.
    pub fn snapshot(&self) -> Result<serde_json::Value, SdkError> {
        Ok(
            serde_json::json!({"row":self.0.row,"allocation":self.0.allocation,"pending":self.0.pending,"receive_key_present":self.0.receive_key.is_some(),"next_refresh":self.0.next_lease_refresh}),
        )
    }
    /// Runs the regular bounded call/media expiry rules.
    /// # Errors
    /// Returns invalid transition errors.
    pub fn expire(&mut self, now: i64) -> Result<(), SdkError> {
        self.0.expire(now)?;
        self.0.expire_media(now)?;
        Ok(())
    }
}
