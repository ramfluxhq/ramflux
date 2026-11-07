// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Submit on a negotiated session: the reply is `submit_accepted`, never the recipient deliver.

use super::frame_dispatch::ExpectedReply;
use super::host_frames::{Step, Wait};
use super::session_push::{CapableServerFrame, SessionMode};
use super::{GatewayInboxEntry, GatewayServerFrame, GatewaySessionEngine};
use crate::SdkError;

impl GatewaySessionEngine {
    /// Waits for the reply to a submit already written on a Push session.
    ///
    /// A matching `submit_accepted` is adapted to the public entry. The legacy forward
    /// acknowledgement and keyless refusal stay valid replies. A `deliver`, including one for
    /// the sender's own target, is an event and is carried, never taken as the reply.
    pub(crate) async fn read_push_submit_reply(
        &mut self,
        submitted: ramflux_protocol::Envelope,
    ) -> Result<GatewayInboxEntry, SdkError> {
        loop {
            match self.read_step("submit response", Wait::Submit).await? {
                Step::SubmitAccepted(accepted) => return self.adopt_accepted(*accepted, submitted),
                Step::Legacy(frame) => {
                    // Events (wake, push-route replies) are handled by the dispatcher; only an
                    // admitted reply comes back as `true`.
                    if !self.dispatch_frame(&frame, Some(ExpectedReply::Submit))? {
                        continue;
                    }
                    return Self::legacy_submit_result(*frame, submitted);
                }
            }
        }
    }

    fn adopt_accepted(
        &mut self,
        accepted: CapableServerFrame,
        submitted: ramflux_protocol::Envelope,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let CapableServerFrame::SubmitAccepted {
            incarnation_id,
            envelope_id,
            target_delivery_id,
            inbox_seq,
        } = accepted
        else {
            return Err(self.retire("unexpected capable reply while awaiting a submit"));
        };
        let SessionMode::Push { incarnation } = &self.mode else {
            return Err(self.retire("submit_accepted on an unnegotiated session"));
        };
        if &incarnation_id != incarnation {
            return Err(self.retire("submit_accepted with a foreign incarnation"));
        }
        if envelope_id != submitted.envelope_id {
            return Err(self.retire("submit_accepted for a different envelope"));
        }
        if target_delivery_id != submitted.target_delivery_id {
            return Err(self.retire("submit_accepted for a different target"));
        }
        if inbox_seq == 0 {
            return Err(self.retire("submit_accepted without an inbox sequence"));
        }
        Ok(GatewayInboxEntry {
            forwarded: false,
            inbox_seq,
            target_delivery_id,
            envelope: submitted,
        })
    }

    fn legacy_submit_result(
        frame: GatewayServerFrame,
        submitted: ramflux_protocol::Envelope,
    ) -> Result<GatewayInboxEntry, SdkError> {
        match frame {
            GatewayServerFrame::ForwardAck { ack }
                if ack.envelope_id == submitted.envelope_id
                    && ack.target_delivery_id == submitted.target_delivery_id =>
            {
                Ok(GatewayInboxEntry {
                    forwarded: true,
                    inbox_seq: ack.inbox_seq.unwrap_or(0),
                    target_delivery_id: ack.target_delivery_id,
                    envelope: submitted,
                })
            }
            GatewayServerFrame::ForwardAck { ack } => {
                Err(SdkError::GatewaySessionRejected(format!(
                    "forward acknowledgement mismatch for envelope {} target {}",
                    ack.envelope_id, ack.target_delivery_id
                )))
            }
            GatewayServerFrame::Nack { reason }
                if reason == ramflux_protocol::GATEWAY_FORWARDED_HOME_NODE_MIGRATED_REASON =>
            {
                Ok(GatewayInboxEntry {
                    forwarded: true,
                    inbox_seq: 0,
                    target_delivery_id: submitted.target_delivery_id.clone(),
                    envelope: submitted,
                })
            }
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected deliver after submit, got {other:?}"
            ))),
        }
    }
}
